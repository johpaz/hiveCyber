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
                let text = match &m.content {
                    Content::Text(t) => t.clone(),
                    Content::ToolResult { content, .. } => content.clone(),
                };
                let role = match m.role.as_str() {
                    "assistant" => "model".to_string(),
                    other => other.to_string(),
                };
                GeminiContent {
                    role,
                    parts: vec![GeminiPart::Text { text }],
                }
            })
            .collect();

        let system_instruction = req.system.as_ref().map(|s| GeminiSystemInstruction {
            parts: vec![GeminiPart::Text { text: s.clone() }],
        });

        let body = GeminiRequest {
            contents,
            system_instruction,
            generation_config: GeminiGenConfig {
                max_output_tokens: req.max_tokens.unwrap_or(8192),
            },
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

        let text_content = candidate
            .content
            .parts
            .into_iter()
            .filter_map(|p| p.text)
            .collect::<Vec<_>>()
            .join("");

        let usage = api_resp.usage_metadata.unwrap_or(GeminiUsage {
            prompt_token_count: 0,
            candidates_token_count: 0,
        });

        Ok(LlmResponse {
            content: vec![ContentBlock::Text { text: text_content }],
            tool_calls: vec![],
            stop_reason: candidate.finish_reason.unwrap_or_else(|| "STOP".into()),
            input_tokens: usage.prompt_token_count,
            output_tokens: usage.candidates_token_count,
        })
    }
}