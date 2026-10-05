use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::info;

use crate::store::HiveDb;
use crate::store::collections::{COL_TASKS, TaskDoc};
use crate::tool_runtime::batch::ToolBatchResult;
use crate::tool_runtime::middleware::{AuditCtx, ToolMiddleware, execute_tool_batch_audited};
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
    mcp: Option<crate::agent::mcp_integration::SharedMcp>,
}

impl WorkerTaskExecutor {
    pub fn new(db: HiveDb, config: Config) -> Self {
        let security = Arc::new(hivecyber_tools::SecurityContext::default());
        WorkerTaskExecutor { db, config, security, mcp: None }
    }

    pub fn with_security(mut self, security: Arc<hivecyber_tools::SecurityContext>) -> Self {
        self.security = security;
        self
    }

    pub fn with_mcp(mut self, mcp: Option<crate::agent::mcp_integration::SharedMcp>) -> Self {
        self.mcp = mcp;
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

        // Per-task scratch dir: gives cli_exec/fs_write/fs_edit/fs_delete a
        // default working directory scoped to this task instead of the
        // process's own cwd (or, for sandboxed-worker calls, the fresh
        // worker process's unrelated $HOME). Reaped by DispatchLoop's
        // maintenance tick once the task reaches a terminal status.
        let scratch_dir = std::path::PathBuf::from(&self.config.home_dir)
            .join("scratch")
            .join(task_id);
        tokio::fs::create_dir_all(&scratch_dir).await?;
        let task_security = Arc::new(hivecyber_tools::SecurityContext {
            task_root: Some(scratch_dir),
            ..(*self.security).clone()
        });

        let task_val = self.db.get(COL_TASKS, task_id).await
            .ok_or_else(|| anyhow::anyhow!("task not found: {}", task_id))?;

        let agent_val = self.db.get(crate::store::collections::COL_AGENTS, worker_id).await
            .ok_or_else(|| anyhow::anyhow!("agent not found: {}", worker_id))?;

        let agent_enabled = agent_val.get("enabled").and_then(|e| e.as_bool()).unwrap_or(false);
        if !agent_enabled {
            anyhow::bail!("worker agent {} is disabled", worker_id);
        }

        let mut system_prompt = agent_val
            .get("system_prompt")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string();
        // Surface the skills most relevant to this task (BM25 skill-selector),
        // so the worker gets its playbooks without shipping the whole set.
        let skills_ctx =
            crate::agent::routing_context::build_skill_context(&self.db, task_description).await;
        if !skills_ctx.is_empty() {
            system_prompt.push_str("\n\n");
            system_prompt.push_str(&skills_ctx);
        }
        let provider = agent_val.get("provider_id").and_then(|p| p.as_str())
            .unwrap_or(&self.config.models.default_provider);
        // model_id from the agent, else the global config default, else empty —
        // an empty model makes the provider registry use its own default_model,
        // so we never carry a stale hardcoded per-provider model map here.
        let model = agent_val.get("model_id").and_then(|m| m.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or(&self.config.models.default_model);

        let tool_allowlist: Vec<String> = agent_val
            .get("tool_allowlist_json")
            .and_then(|t| serde_json::from_value(t.clone()).ok())
            .unwrap_or_default();

        let mut tool_registry = hivecyber_tools::ToolRegistry::create_with_security(task_security.clone());
        // MCP tools are exposed to workers too; the allowlist below still gates
        // which ones this specific worker may call.
        if let Some(mcp) = self.mcp.as_ref() {
            crate::agent::mcp_integration::register_mcp_tools(&mut tool_registry, mcp).await;
        }
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

        let api_key = crate::security::crypto::resolve_api_key(
            &self.db,
            &self.config.home_dir,
            provider,
        )
        .await;
        let registry = crate::settings::registry_for(&self.db).await;
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

            let middleware = ToolMiddleware::new(self.db.clone(), task_security.clone());
            let audit_ctx = AuditCtx {
                worker: worker_id.to_string(),
                run_id: job_id.to_string(),
                operator_id: task_security.operator_id.clone(),
            };
            let results = execute_tool_batch_audited(
                tool_calls_vec,
                &tool_registry,
                self.config.tools.worker_pool.tool_timeout_ms,
                &middleware,
                &audit_ctx,
            )
            .await;

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
                        tool_name: tool_call.name.clone(),
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
            CheckStatus::Passed => {
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
            CheckStatus::Pending | CheckStatus::Unchecked => {
                let mut task_val = self.db.get(COL_TASKS, task_id).await.unwrap_or_default();
                let acceptance_status = match status {
                    CheckStatus::Pending => "acceptance_pending",
                    _ => "acceptance_unchecked",
                };
                if let Some(obj) = task_val.as_object_mut() {
                    obj.insert("status".into(), acceptance_status.into());
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
                        "status": acceptance_status,
                        "delivery": delivery_text,
                        "evidence": evidence,
                        "checks": checks_json,
                        "tool_calls": tool_call_count,
                        "acceptance": "no verificado — no se acredita como util",
                    }),
                })
            }
        }
    }
}

