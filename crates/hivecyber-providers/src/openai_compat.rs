use anyhow::{Context, Result};
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::traits::*;

pub struct OpenAiCompatProvider {
    client: Client,
    api_key: String,
    model: String,
    base_url: String,
}

impl OpenAiCompatProvider {
    pub fn new(api_key: &str, model: &str, base_url: &str) -> Self {
        OpenAiCompatProvider {
            client: Client::new(),
            api_key: api_key.to_string(),
            model: model.to_string(),
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }
}

#[derive(Serialize)]
struct OpenAiRequest {
    model: String,
    max_tokens: u64,
    messages: Vec<OpenAiMessage>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tools: Vec<OpenAiTool>,
}

#[derive(Serialize)]
struct OpenAiMessage {
    role: String,
    content: serde_json::Value,
}

#[derive(Serialize)]
struct OpenAiTool {
    #[serde(rename = "type")]
    tool_type: String,
    function: OpenAiFunction,
}

#[derive(Serialize)]
struct OpenAiFunction {
    name: String,
    description: String,
    parameters: serde_json::Value,
}

#[derive(Deserialize)]
struct OpenAiResponse {
    choices: Vec<OpenAiChoice>,
    usage: OpenAiUsage,
}

#[derive(Deserialize)]
struct OpenAiChoice {
    message: OpenAiRespMessage,
    finish_reason: Option<String>,
}

#[derive(Deserialize)]
struct OpenAiRespMessage {
    content: Option<String>,
    tool_calls: Option<Vec<OpenAiToolCall>>,
}

#[derive(Deserialize)]
struct OpenAiToolCall {
    id: String,
    function: OpenAiToolFunction,
}

#[derive(Deserialize)]
struct OpenAiToolFunction {
    name: String,
    arguments: String,
}

#[derive(Deserialize)]
struct OpenAiUsage {
    prompt_tokens: u64,
    completion_tokens: u64,
}

#[async_trait]
impl LlmProvider for OpenAiCompatProvider {
    async fn call(&self, req: &CallRequest) -> Result<LlmResponse> {
        let mut messages: Vec<OpenAiMessage> = Vec::new();

        if let Some(ref system) = req.system {
            messages.push(OpenAiMessage {
                role: "system".into(),
                content: serde_json::json!(system),
            });
        }

        for m in &req.messages {
            let content = match &m.content {
                Content::Text(t) => serde_json::json!(t),
                Content::ToolResult { tool_call_id, content } => serde_json::json!({
                    "tool_call_id": tool_call_id,
                    "content": content,
                }),
            };
            let role = match m.role.as_str() {
                "tool" => "tool".to_string(),
                other => other.to_string(),
            };
            messages.push(OpenAiMessage { role, content });
        }

        let tools: Vec<OpenAiTool> = req
            .tools
            .iter()
            .map(|t| OpenAiTool {
                tool_type: "function".into(),
                function: OpenAiFunction {
                    name: t.name.clone(),
                    description: t.description.clone(),
                    parameters: t.parameters.clone(),
                },
            })
            .collect();

        let body = OpenAiRequest {
            model: self.model.clone(),
            max_tokens: req.max_tokens.unwrap_or(8192),
            messages,
            tools,
        };

        let resp = self
            .client
            .post(format!("{}/v1/chat/completions", self.base_url))
            .bearer_auth(&self.api_key)
            .json(&body)
            .send()
            .await
            .context("openai-compat request")?;

        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();

        if !status.is_success() {
            anyhow::bail!("openai-compat error {}: {}", status, text);
        }

        let api_resp: OpenAiResponse = serde_json::from_str(&text)
            .context(format!("openai-compat parse error: {}", text.chars().take(500).collect::<String>()))?;

        let choice = api_resp
            .choices
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("no choices in response"))?;

        let mut content = Vec::new();
        if let Some(text) = choice.message.content {
            content.push(ContentBlock::Text { text });
        }

        let mut tool_calls = Vec::new();
        if let Some(tc) = choice.message.tool_calls {
            for call in tc {
                let args = serde_json::from_str(&call.function.arguments).unwrap_or(serde_json::Value::Null);
                let tc_name = call.function.name.clone();
                let tc_id = call.id.clone();
                tool_calls.push(ToolCall {
                    id: tc_id.clone(),
                    name: tc_name.clone(),
                    arguments: args,
                });
                content.push(ContentBlock::ToolUse {
                    id: tc_id,
                    name: tc_name,
                    input: serde_json::Value::Null,
                });
            }
        }

        Ok(LlmResponse {
            content,
            tool_calls,
            stop_reason: choice.finish_reason.unwrap_or_else(|| "stop".into()),
            input_tokens: api_resp.usage.prompt_tokens,
            output_tokens: api_resp.usage.completion_tokens,
        })
    }
}