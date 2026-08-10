use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::store::HiveDb;
use crate::config::Config;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum StreamChunk {
    Agent {
        text: String,
    },
    Reasoning {
        text: String,
    },
    ToolCall {
        name: String,
        args: serde_json::Value,
    },
    ToolResult {
        name: String,
        result: serde_json::Value,
    },
    Usage {
        input_tokens: u64,
        output_tokens: u64,
    },
    Done {
        final_text: String,
    },
    Error {
        message: String,
    },
}

pub struct AgentLoopOptions {
    pub agent_id: String,
    pub user_message: String,
    pub thread_id: String,
    pub max_iterations: u32,
    pub security: Arc<hivecyber_tools::SecurityContext>,
    pub queue: Option<Arc<crate::harness::DurableQueue>>,
}

pub struct AgentLoop {
    db: HiveDb,
    config: Config,
}

impl AgentLoop {
    pub fn new(db: HiveDb, config: Config) -> Self {
        AgentLoop { db, config }
    }

    pub async fn run(
        &self,
        opts: AgentLoopOptions,
    ) -> Result<mpsc::Receiver<StreamChunk>> {
        let (tx, rx) = mpsc::channel(128);

        let db = self.db.clone();
        let config = self.config.clone();

        tokio::spawn(async move {
            if let Err(e) = run_loop(db, config, opts, tx.clone()).await {
                let _ = tx
                    .send(StreamChunk::Error {
                        message: e.to_string(),
                    })
                    .await;
            }
            let _ = tx
                .send(StreamChunk::Done {
                    final_text: String::new(),
                })
                .await;
        });

        Ok(rx)
    }
}

async fn run_loop(
    db: HiveDb,
    config: Config,
    opts: AgentLoopOptions,
    tx: mpsc::Sender<StreamChunk>,
) -> Result<()> {
    use hivecyber_providers::{ProviderRegistry, CallRequest, Content};

    let agent = db
        .get(crate::store::collections::COL_AGENTS, &opts.agent_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("agent not found: {}", opts.agent_id))?;

    let provider = agent
        .get("provider_id")
        .and_then(|v| v.as_str())
        .or_else(|| Some(config.models.default_provider.as_str()))
        .unwrap_or("anthropic");

    let model = agent
        .get("model_id")
        .and_then(|v| v.as_str())
        .unwrap_or(match provider {
            "anthropic" => "claude-sonnet-4-20250514",
            "gemini" => "gemini-3.6-flash",
            "openai" => "gpt-4o",
            "ollama" => "llama3.2",
            "groq" => "llama-3.3-70b-versatile",
            "opencode_go" => "kimi-k2.6",
            _ => "gpt-4o",
        });

    let api_key = match provider {
        "anthropic" => std::env::var("ANTHROPIC_API_KEY").ok(),
        "openai" => std::env::var("OPENAI_API_KEY").ok(),
        "gemini" => std::env::var("GEMINI_API_KEY")
            .ok()
            .or_else(|| std::env::var("GOOGLE_API_KEY").ok()),
        "ollama" => std::env::var("OLLAMA_API_KEY").ok().or(Some(String::new())),
        "groq" => std::env::var("GROQ_API_KEY").ok(),
        "opencode_go" => std::env::var("OPENCODE_GO_API_KEY").ok(),
        _ => std::env::var("ANTHROPIC_API_KEY").ok(),
    }
    .unwrap_or_default();

    let registry = ProviderRegistry::new();
    let client = registry
        .get(provider, model, &api_key)
        .ok_or_else(|| anyhow::anyhow!("provider not configured: {}", provider))?;

    let system_prompt = agent
        .get("system_prompt")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let mut tool_registry = hivecyber_tools::ToolRegistry::create_with_security(opts.security.clone());

    let role = agent
        .get("role")
        .and_then(|v| v.as_str())
        .unwrap_or("worker");

    if role == "coordinator" {
        if let Some(queue) = opts.queue.clone() {
            let backend = Arc::new(crate::agent::delegation_backend::TaskDelegateBackend {
                db: db.clone(),
                queue,
            });
            tool_registry.register(Arc::new(hivecyber_tools::delegation::TaskDelegate { db: backend }));
        }
    }

    let tool_defs: Vec<hivecyber_providers::ToolDef> = tool_registry
        .all()
        .iter()
        .map(|t| hivecyber_providers::ToolDef {
            name: t.name().into(),
            description: t.description().into(),
            parameters: serde_json::to_value(t.parameters()).unwrap_or_default(),
        })
        .collect();

    let max_iter = opts.max_iterations.max(1);

    let mut messages: Vec<hivecyber_providers::Message> = Vec::new();

    let user_msg = hivecyber_providers::Message {
        role: "user".into(),
        content: Content::Text(opts.user_message.clone()),
    };
    messages.push(user_msg.clone());

    let _ = db
        .insert(
            crate::store::collections::COL_MESSAGES,
            &uuid::Uuid::new_v4().to_string(),
            serde_json::to_value(&crate::store::collections::MessageDoc {
                id: uuid::Uuid::new_v4().to_string(),
                thread_id: opts.thread_id.clone(),
                role: "user".into(),
                content: serde_json::Value::String(opts.user_message),
                tool_calls: None,
                tool_call_id: None,
                created_at: chrono::Utc::now().to_rfc3339(),
            })?,
        )
        .await;

    let mut stuck = crate::agent::stuck::StuckLoopDetector::new();

    for _iteration in 0..max_iter {
        let req = CallRequest {
            system: Some(system_prompt.to_string()),
            messages: messages.clone(),
            tools: tool_defs.clone(),
            max_tokens: Some(8192),
        };

        let response = client.call(&req).await?;

        let _ = tx
            .send(StreamChunk::Agent {
                text: response.content_text().unwrap_or_default(),
            })
            .await;

        let _ = tx
            .send(StreamChunk::Usage {
                input_tokens: response.input_tokens,
                output_tokens: response.output_tokens,
            })
            .await;

        let tool_calls = response.tool_calls().to_vec();

        if tool_calls.is_empty() {
            let final_text = response.content_text().unwrap_or_default();
            let assistant_msg = hivecyber_providers::Message {
                role: "assistant".into(),
                content: Content::Text(final_text.clone()),
            };

            let _ = db
                .insert(
                    crate::store::collections::COL_MESSAGES,
                    &uuid::Uuid::new_v4().to_string(),
                    serde_json::to_value(&crate::store::collections::MessageDoc {
                        id: uuid::Uuid::new_v4().to_string(),
                        thread_id: opts.thread_id.clone(),
                        role: "assistant".into(),
                        content: serde_json::Value::String(final_text),
                        tool_calls: None,
                        tool_call_id: None,
                        created_at: chrono::Utc::now().to_rfc3339(),
                    })?,
                )
                .await;

            messages.push(assistant_msg);
            return Ok(());
        }

        let assistant_msg = hivecyber_providers::Message {
            role: "assistant".into(),
            content: response.to_content(),
        };
        messages.push(assistant_msg);

        for tool_call in &tool_calls {
            let _ = tx
                .send(StreamChunk::ToolCall {
                    name: tool_call.name.clone(),
                    args: tool_call.arguments.clone(),
                })
                .await;

            if let Some(intervention) = stuck.record_tool_call(&tool_call.name) {
                let _ = tx.send(StreamChunk::Agent { text: intervention }).await;
            }
        }

        let turn_id = uuid::Uuid::new_v4().to_string();

        let mut tool_calls_vec: Vec<(String, serde_json::Value)> = Vec::new();
        for tc in &tool_calls {
            let mut args = tc.arguments.clone();
            if tc.name == "task_delegate" {
                if let Some(obj) = args.as_object_mut() {
                    obj.insert("__turn_id".into(), serde_json::json!(turn_id));
                    obj.insert("__thread_id".into(), serde_json::json!(opts.thread_id));
                }
            }
            tool_calls_vec.push((tc.name.clone(), args));
        }

        let results = crate::tool_runtime::batch::execute_tool_batch(
            tool_calls_vec,
            &tool_registry,
            config.tools.worker_pool.tool_timeout_ms,
        )
        .await;

        for result in &results {
            let _ = tx
                .send(StreamChunk::ToolResult {
                    name: result.tool_name.clone(),
                    result: result.result.clone(),
                })
                .await;

            let _ = db
                .insert(
                    crate::store::collections::COL_TRACES,
                    &uuid::Uuid::new_v4().to_string(),
                    serde_json::to_value(&crate::store::collections::TraceDoc {
                        id: uuid::Uuid::new_v4().to_string(),
                        agent_id: opts.agent_id.clone(),
                        run_id: String::new(),
                        thread_id: opts.thread_id.clone(),
                        tool_name: result.tool_name.clone(),
                        tool_args: serde_json::Value::Null,
                        tool_result: Some(result.result.clone()),
                        success: Some(result.success),
                        duration_ms: result.duration_ms,
                        tokens_used: 0,
                        created_at: chrono::Utc::now().to_rfc3339(),
                    })?,
                )
                .await;
        }

        for (tool_call, result) in tool_calls.iter().zip(results.iter()) {
            let result_str = if result.success {
                serde_json::to_string(&result.result).unwrap_or_default()
            } else {
                format!("Error: {}", result.error.as_deref().unwrap_or("unknown"))
            };

            messages.push(hivecyber_providers::Message {
                role: "tool".into(),
                content: Content::ToolResult {
                    tool_call_id: tool_call.id.clone(),
                    tool_name: tool_call.name.clone(),
                    content: result_str,
                },
            });
        }
    }

    let _ = tx
        .send(StreamChunk::Agent {
            text: "[max iterations reached]".into(),
        })
        .await;

    Ok(())
}