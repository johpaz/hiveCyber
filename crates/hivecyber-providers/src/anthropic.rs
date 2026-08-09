use anyhow::{Context, Result};
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::traits::*;

pub struct AnthropicProvider {
    client: Client,
    api_key: String,
    model: String,
}

impl AnthropicProvider {
    pub fn new(api_key: &str, model: &str) -> Self {
        AnthropicProvider {
            client: Client::new(),
            api_key: api_key.to_string(),
            model: model.to_string(),
        }
    }
}

#[derive(Serialize)]
struct AnthropicRequest {
    model: String,
    max_tokens: u64,
    system: String,
    messages: Vec<AnthropicMessage>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tools: Vec<AnthropicTool>,
}

#[derive(Serialize)]
struct AnthropicMessage {
    role: String,
    content: serde_json::Value,
}

#[derive(Serialize)]
struct AnthropicTool {
    name: String,
    description: String,
    input_schema: serde_json::Value,
}

#[derive(Deserialize)]
struct AnthropicResponse {
    content: Vec<AnthropicContentBlock>,
    stop_reason: Option<String>,
    usage: AnthropicUsage,
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum AnthropicContentBlock {
    text { text: String },
    tool_use { id: String, name: String, input: serde_json::Value },
}

#[derive(Deserialize)]
struct AnthropicUsage {
    input_tokens: u64,
    output_tokens: u64,
}

#[async_trait]
impl LlmProvider for AnthropicProvider {
    async fn call(&self, req: &CallRequest) -> Result<LlmResponse> {
        let messages: Vec<AnthropicMessage> = req
            .messages
            .iter()
            .map(|m| {
                let content = match &m.content {
                    Content::Text(t) => serde_json::json!(t),
                    Content::ToolResult { tool_call_id, content } => serde_json::json!([{
                        "type": "tool_result",
                        "tool_use_id": tool_call_id,
                        "content": content,
                    }]),
                };
                AnthropicMessage {
                    role: m.role.clone(),
                    content,
                }
            })
            .collect();

        let tools: Vec<AnthropicTool> = req
            .tools
            .iter()
            .map(|t| AnthropicTool {
                name: t.name.clone(),
                description: t.description.clone(),
                input_schema: t.parameters.clone(),
            })
            .collect();

        let body = AnthropicRequest {
            model: self.model.clone(),
            max_tokens: req.max_tokens.unwrap_or(8192),
            system: req.system.clone().unwrap_or_default(),
            messages,
            tools,
        };

        let resp = self
            .client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .context("anthropic request")?;

        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();

        if !status.is_success() {
            anyhow::bail!("anthropic error {}: {}", status, text);
        }

        let api_resp: AnthropicResponse = serde_json::from_str(&text)
            .context(format!("anthropic parse error: {}", text.chars().take(500).collect::<String>()))?;

        let content: Vec<ContentBlock> = api_resp
            .content
            .into_iter()
            .map(|b| match b {
                AnthropicContentBlock::text { text } => ContentBlock::Text { text },
                AnthropicContentBlock::tool_use { id, name, input } => ContentBlock::ToolUse { id, name, input },
            })
            .collect();

        let tool_calls: Vec<ToolCall> = content
            .iter()
            .filter_map(|b| match b {
                ContentBlock::ToolUse { id, name, input } => Some(ToolCall {
                    id: id.clone(),
                    name: name.clone(),
                    arguments: input.clone(),
                }),
                _ => None,
            })
            .collect();

        Ok(LlmResponse {
            content,
            tool_calls,
            stop_reason: api_resp.stop_reason.unwrap_or_else(|| "end_turn".into()),
            input_tokens: api_resp.usage.input_tokens,
            output_tokens: api_resp.usage.output_tokens,
        })
    }
}