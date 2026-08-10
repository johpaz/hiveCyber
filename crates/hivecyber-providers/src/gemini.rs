use anyhow::{Context, Result};
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::traits::*;

pub struct GeminiProvider {
    client: Client,
    api_key: String,
    model: String,
}

impl GeminiProvider {
    pub fn new(api_key: &str, model: &str) -> Self {
        GeminiProvider {
            client: Client::new(),
            api_key: api_key.to_string(),
            model: model.to_string(),
        }
    }
}

#[derive(Serialize)]
struct GeminiRequest {
    contents: Vec<GeminiContent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    system_instruction: Option<GeminiSystemInstruction>,
    generation_config: GeminiGenConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<Vec<GeminiTool>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    safety_settings: Option<Vec<GeminiSafetySetting>>,
}

#[derive(Serialize)]
struct GeminiSafetySetting {
    category: &'static str,
    threshold: &'static str,
}

#[derive(Serialize)]
struct GeminiTool {
    function_declarations: Vec<GeminiFunctionDecl>,
}

#[derive(Serialize)]
struct GeminiFunctionDecl {
    name: String,
    description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parameters: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct GeminiSystemInstruction {
    parts: Vec<GeminiPart>,
}

#[derive(Serialize)]
struct GeminiContent {
    role: String,
    parts: Vec<GeminiPart>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum GeminiPart {
    Text { text: String },
    FunctionCall { name: String, args: serde_json::Value },
    FunctionResponse { name: String, response: serde_json::Value },
}

#[derive(Serialize)]
struct GeminiGenConfig {
    max_output_tokens: u64,
}

#[derive(Deserialize)]
struct GeminiResponse {
    candidates: Vec<GeminiCandidate>,
    usage_metadata: Option<GeminiUsage>,
}

#[derive(Deserialize)]
struct GeminiCandidate {
    content: GeminiRespContent,
    finish_reason: Option<String>,
}

#[derive(Deserialize)]
struct GeminiRespContent {
    parts: Vec<GeminiRespPart>,
}

#[derive(Deserialize)]
struct GeminiRespPart {
    text: Option<String>,
    function_call: Option<GeminiFunctionCallResp>,
}

#[derive(Deserialize)]
struct GeminiFunctionCallResp {
    name: String,
    args: serde_json::Value,
}

#[derive(Deserialize)]
struct GeminiUsage {
    prompt_token_count: u64,
    candidates_token_count: u64,
}

#[async_trait]
impl LlmProvider for GeminiProvider {
    async fn call(&self, req: &CallRequest) -> Result<LlmResponse> {
        let contents: Vec<GeminiContent> = req
            .messages
            .iter()
            .map(|m| {
                let (role, parts) = match &m.content {
                    Content::Text(t) => {
                        let role = match m.role.as_str() {
                            "assistant" => "model".to_string(),
                            other => other.to_string(),
                        };
                        (role, vec![GeminiPart::Text { text: t.clone() }])
                    }
                    Content::ToolResult { tool_name, content, .. } => (
                        "user".to_string(),
                        vec![GeminiPart::FunctionResponse {
                            name: tool_name.clone(),
                            response: serde_json::json!({ "content": content }),
                        }],
                    ),
                    Content::AssistantWithTools { text, tool_calls } => {
                        let mut parts = Vec::new();
                        if !text.is_empty() {
                            parts.push(GeminiPart::Text { text: text.clone() });
                        }
                        for tc in tool_calls {
                            parts.push(GeminiPart::FunctionCall {
                                name: tc.name.clone(),
                                args: tc.arguments.clone(),
                            });
                        }
                        ("model".to_string(), parts)
                    }
                };
                GeminiContent { role, parts }
            })
            .collect();

        let system_instruction = req.system.as_ref().map(|s| GeminiSystemInstruction {
            parts: vec![GeminiPart::Text { text: s.clone() }],
        });

        let tools = if req.tools.is_empty() {
            None
        } else {
            Some(vec![GeminiTool {
                function_declarations: req
                    .tools
                    .iter()
                    .map(|t| GeminiFunctionDecl {
                        name: t.name.clone(),
                        description: t.description.clone(),
                        parameters: Some(t.parameters.clone()),
                    })
                    .collect(),
            }])
        };

        let body = GeminiRequest {
            contents,
            system_instruction,
            generation_config: GeminiGenConfig {
                max_output_tokens: req.max_tokens.unwrap_or(8192),
            },
            tools,
            safety_settings: Some(vec![
                GeminiSafetySetting {
                    category: "HARM_CATEGORY_DANGEROUS_CONTENT",
                    threshold: "BLOCK_NONE",
                },
                GeminiSafetySetting {
                    category: "HARM_CATEGORY_HARASSMENT",
                    threshold: "BLOCK_NONE",
                },
                GeminiSafetySetting {
                    category: "HARM_CATEGORY_HATE_SPEECH",
                    threshold: "BLOCK_NONE",
                },
                GeminiSafetySetting {
                    category: "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                    threshold: "BLOCK_NONE",
                },
            ]),
        };

        let url = format!(
            "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}",
            self.model, self.api_key
        );

        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .context("gemini request")?;

        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();

        if !status.is_success() {
            anyhow::bail!("gemini error {}: {}", status, text);
        }

        let api_resp: GeminiResponse = serde_json::from_str(&text)
            .context(format!("gemini parse error: {}", text.chars().take(500).collect::<String>()))?;

        let candidate = api_resp
            .candidates
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("no candidates in gemini response"))?;

        let mut content = Vec::new();
        let mut tool_calls = Vec::new();
        for (i, part) in candidate.content.parts.into_iter().enumerate() {
            if let Some(text) = part.text {
                content.push(ContentBlock::Text { text });
            }
            if let Some(fc) = part.function_call {
                let id = format!("call_{}", i);
                content.push(ContentBlock::ToolUse {
                    id: id.clone(),
                    name: fc.name.clone(),
                    input: fc.args.clone(),
                });
                tool_calls.push(ToolCall {
                    id,
                    name: fc.name,
                    arguments: fc.args,
                });
            }
        }

        let usage = api_resp.usage_metadata.unwrap_or(GeminiUsage {
            prompt_token_count: 0,
            candidates_token_count: 0,
        });

        Ok(LlmResponse {
            content,
            tool_calls,
            stop_reason: candidate.finish_reason.unwrap_or_else(|| "STOP".into()),
            input_tokens: usage.prompt_token_count,
            output_tokens: usage.candidates_token_count,
        })
    }
}