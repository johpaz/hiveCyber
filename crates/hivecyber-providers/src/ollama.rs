use anyhow::{Context, Result};
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::traits::*;

pub struct OllamaProvider {
    client: Client,
    model: String,
    base_url: String,
}

impl OllamaProvider {
    pub fn new(model: &str, base_url: Option<&str>) -> Self {
        OllamaProvider {
            client: Client::new(),
            model: model.to_string(),
            base_url: base_url
                .unwrap_or("http://localhost:11434")
                .trim_end_matches('/')
                .to_string(),
        }
    }
}

impl Default for OllamaProvider {
    fn default() -> Self {
        Self::new("llama3.2", None)
    }
}

#[derive(Serialize)]
struct OllamaRequest {
    model: String,
    messages: Vec<OllamaMessage>,
    stream: bool,
    options: OllamaOptions,
}

#[derive(Serialize)]
struct OllamaMessage {
    role: String,
    content: String,
}

#[derive(Serialize)]
struct OllamaOptions {
    num_ctx: u64,
}

#[derive(Deserialize)]
struct OllamaResponse {
    message: OllamaRespMessage,
    done: bool,
}

#[derive(Deserialize)]
struct OllamaRespMessage {
    role: String,
    content: String,
}

#[async_trait]
impl LlmProvider for OllamaProvider {
    async fn call(&self, req: &CallRequest) -> Result<LlmResponse> {
        let mut messages: Vec<OllamaMessage> = Vec::new();

        if let Some(ref system) = req.system {
            messages.push(OllamaMessage {
                role: "system".into(),
                content: system.clone(),
            });
        }

        for m in &req.messages {
            let content = match &m.content {
                Content::Text(t) => t.clone(),
                Content::ToolResult { content, .. } => content.clone(),
                Content::AssistantWithTools { text, tool_calls } => {
                    let mut s = text.clone();
                    for tc in tool_calls {
                        s.push_str(&format!(
                            "\n[tool_call: {}({})]",
                            tc.name,
                            serde_json::to_string(&tc.arguments).unwrap_or_default()
                        ));
                    }
                    s
                }
            };
            messages.push(OllamaMessage {
                role: m.role.clone(),
                content,
            });
        }

        let body = OllamaRequest {
            model: self.model.clone(),
            messages,
            stream: false,
            options: OllamaOptions {
                num_ctx: req.max_tokens.unwrap_or(8192),
            },
        };

        let resp = self
            .client
            .post(format!("{}/api/chat", self.base_url))
            .json(&body)
            .send()
            .await
            .context("ollama request")?;

        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();

        if !status.is_success() {
            anyhow::bail!("ollama error {}: {}", status, text);
        }

        let api_resp: OllamaResponse = serde_json::from_str(&text)
            .context(format!("ollama parse error: {}", text.chars().take(500).collect::<String>()))?;

        Ok(LlmResponse {
            content: vec![ContentBlock::Text {
                text: api_resp.message.content,
            }],
            tool_calls: vec![],
            stop_reason: "stop".into(),
            input_tokens: 0,
            output_tokens: 0,
        })
    }
}