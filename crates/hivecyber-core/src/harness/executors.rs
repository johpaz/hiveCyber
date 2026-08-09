use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::info;

use crate::store::HiveDb;
use crate::store::collections::{COL_TASKS, TaskDoc};
use crate::agent::acceptance::{run_acceptance_checks, verdict, CheckStatus};
use crate::config::Config;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutorResult {
    pub ok: bool,
    pub retryable: bool,
    pub result: serde_json::Value,
}

#[async_trait]
pub trait JobExecutor: Send + Sync {
    fn job_type(&self) -> &str;
    async fn execute(&self, job_id: &str, payload: &serde_json::Value) -> Result<ExecutorResult>;
}

pub struct WorkerTaskExecutor {
    db: HiveDb,
    config: Config,
    security: Arc<hivecyber_tools::SecurityContext>,
}

impl WorkerTaskExecutor {
    pub fn new(db: HiveDb, config: Config) -> Self {
        let security = Arc::new(hivecyber_tools::SecurityContext::default());
        WorkerTaskExecutor { db, config, security }
    }

    pub fn with_security(mut self, security: Arc<hivecyber_tools::SecurityContext>) -> Self {
        self.security = security;
        self
    }
}

#[async_trait]
impl JobExecutor for WorkerTaskExecutor {
    fn job_type(&self) -> &str {
        "worker_task"
    }

    async fn execute(&self, job_id: &str, payload: &serde_json::Value) -> Result<ExecutorResult> {
        let task_id = payload
            .get("taskId")
            .and_then(|t| t.as_str())
            .ok_or_else(|| anyhow::anyhow!("payload missing taskId"))?;

        let worker_id = payload
            .get("workerId")
            .and_then(|w| w.as_str())
            .ok_or_else(|| anyhow::anyhow!("payload missing workerId"))?;

        let task_description = payload
            .get("taskDescription")
            .and_then(|d| d.as_str())
            .unwrap_or("");

        let origin_thread = payload
            .get("originThreadId")
            .and_then(|t| t.as_str())
            .unwrap_or("");

        info!("worker_task executor: job={} task={} worker={}", job_id, task_id, worker_id);

        let task_val = self.db.get(COL_TASKS, task_id).await
            .ok_or_else(|| anyhow::anyhow!("task not found: {}", task_id))?;

        let agent_val = self.db.get(crate::store::collections::COL_AGENTS, worker_id).await
            .ok_or_else(|| anyhow::anyhow!("agent not found: {}", worker_id))?;

        let agent_enabled = agent_val.get("enabled").and_then(|e| e.as_bool()).unwrap_or(false);
        if !agent_enabled {
            anyhow::bail!("worker agent {} is disabled", worker_id);
        }

        let system_prompt = agent_val.get("system_prompt").and_then(|s| s.as_str()).unwrap_or("");
        let provider = agent_val.get("provider_id").and_then(|p| p.as_str())
            .unwrap_or(&self.config.models.default_provider);
        let model = agent_val.get("model_id").and_then(|m| m.as_str())
            .unwrap_or(default_model_for(provider));

        let tool_allowlist: Vec<String> = agent_val
            .get("tool_allowlist_json")
            .and_then(|t| serde_json::from_value(t.clone()).ok())
            .unwrap_or_default();

        let tool_registry = hivecyber_tools::ToolRegistry::create_with_security(self.security.clone());
        let active_tools: Vec<hivecyber_providers::ToolDef> = if tool_allowlist.is_empty() {
            tool_registry.all().iter().map(|t| hivecyber_providers::ToolDef {
                name: t.name().into(),
                description: t.description().into(),
                parameters: serde_json::to_value(t.parameters()).unwrap_or_default(),
            }).collect()
        } else {
            let names = tool_registry.filter_by_allowlist(&tool_allowlist);
            names.iter().filter_map(|n| {
                tool_registry.get(n).map(|t| hivecyber_providers::ToolDef {
                    name: t.name().into(),
                    description: t.description().into(),
                    parameters: serde_json::to_value(t.parameters()).unwrap_or_default(),
                })
            }).collect()
        };

        let api_key = hivecyber_providers::ProviderRegistry::get_default_api_key(provider)
            .unwrap_or_default();
        let registry = hivecyber_providers::ProviderRegistry::new();
        let client = registry.get(provider, model, &api_key)
            .ok_or_else(|| anyhow::anyhow!("provider not configured: {}", provider))?;

        let user_msg = hivecyber_providers::Message {
            role: "user".into(),
            content: hivecyber_providers::Content::Text(task_description.to_string()),
        };

        let max_iter = agent_val.get("max_iterations").and_then(|m| m.as_u64()).unwrap_or(20) as u32;

        let mut messages = vec![user_msg];
        let mut delivery_text = String::new();
        let mut evidence: Vec<String> = Vec::new();
        let mut tool_call_count = 0u32;

        for _iteration in 0..max_iter {
            let req = hivecyber_providers::CallRequest {
                system: Some(system_prompt.to_string()),
                messages: messages.clone(),
                tools: active_tools.clone(),
                max_tokens: Some(8192),
            };

            let response = client.call(&req).await?;

            let tool_calls = response.tool_calls().to_vec();

            if tool_calls.is_empty() {
                delivery_text = response.content_text().unwrap_or_default();
                messages.push(hivecyber_providers::Message {
                    role: "assistant".into(),
                    content: response.to_content(),
                });
                break;
            }

            messages.push(hivecyber_providers::Message {
                role: "assistant".into(),
                content: response.to_content(),
            });

            let tool_calls_vec: Vec<(String, serde_json::Value)> = tool_calls
                .iter()
                .map(|tc| (tc.name.clone(), tc.arguments.clone()))
                .collect();

            let results = crate::tool_runtime::batch::execute_tool_batch(
                tool_calls_vec,
                &tool_registry,
                self.config.tools.worker_pool.tool_timeout_ms,
            ).await;

            for (tool_call, result) in tool_calls.iter().zip(results.iter()) {
                let result_str = if result.success {
                    serde_json::to_string(&result.result).unwrap_or_default()
                } else {
                    format!("Error: {}", result.error.as_deref().unwrap_or("unknown"))
                };

                if result.success {
                    evidence.push(format!("{}: {}", tool_call.name, result_str));
                }

                messages.push(hivecyber_providers::Message {
                    role: "tool".into(),
                    content: hivecyber_providers::Content::ToolResult {
                        tool_call_id: tool_call.id.clone(),
                        content: result_str,
                    },
                });
                tool_call_count += 1;
            }
        }

        let acceptance: Vec<crate::store::collections::AcceptanceCriterion> = task_val
            .get("acceptance")
            .and_then(|a| serde_json::from_value(a.clone()).ok())
            .unwrap_or_default();

        let task_description = task_val
            .get("task_description")
            .and_then(|d| d.as_str())
            .unwrap_or("");
        let checks = run_acceptance_checks(
            &task_description,
            &acceptance,
            &delivery_text,
            &evidence,
        );

        let status = verdict(&checks);
        let checks_json = serde_json::to_value(&checks).unwrap_or_default();

        match status {
            CheckStatus::Failed => {
                crate::security::policies::increment_harmful(&self.db, worker_id).await?;
                let mut task_val = self.db.get(COL_TASKS, task_id).await.unwrap_or_default();
                if let Some(obj) = task_val.as_object_mut() {
                    obj.insert("status".into(), "blocked".into());
                    obj.insert("delivery".into(), serde_json::json!({
                        "content": delivery_text,
                        "evidence": evidence,
                        "checks": checks_json,
                    }));
                    obj.insert("updated_at".into(), chrono::Utc::now().to_rfc3339().into());
                }
                self.db.insert(COL_TASKS, task_id, task_val).await?;
                Ok(ExecutorResult {
                    ok: false,
                    retryable: false,
                    result: serde_json::json!({
                        "status": "failed",
                        "delivery": delivery_text,
                        "checks": checks_json,
                        "tool_calls": tool_call_count,
                    }),
                })
            }
            CheckStatus::Passed | CheckStatus::Unchecked => {
                crate::security::policies::increment_helpful(&self.db, worker_id).await?;
                let mut task_val = self.db.get(COL_TASKS, task_id).await.unwrap_or_default();
                if let Some(obj) = task_val.as_object_mut() {
                    obj.insert("status".into(), "completed".into());
                    obj.insert("progress".into(), serde_json::json!(100));
                    obj.insert("delivery".into(), serde_json::json!({
                        "content": delivery_text,
                        "evidence": evidence,
                        "checks": checks_json,
                    }));
                    obj.insert("updated_at".into(), chrono::Utc::now().to_rfc3339().into());
                }
                self.db.insert(COL_TASKS, task_id, task_val).await?;
                Ok(ExecutorResult {
                    ok: true,
                    retryable: false,
                    result: serde_json::json!({
                        "status": "completed",
                        "delivery": delivery_text,
                        "evidence": evidence,
                        "checks": checks_json,
                        "tool_calls": tool_call_count,
                    }),
                })
            }
        }
    }
}

fn default_model_for(provider: &str) -> &str {
    match provider {
        "anthropic" => "claude-sonnet-4-20250514",
        "openai" => "gpt-4o",
        "gemini" => "gemini-2.0-flash",
        "ollama" => "llama3.2",
        "groq" => "llama-3.3-70b-versatile",
        _ => "gpt-4o",
    }
}