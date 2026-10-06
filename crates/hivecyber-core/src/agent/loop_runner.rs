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
    /// Connected MCP servers, if any. Their tools are registered as normal
    /// tools so they flow through the BM25 tool-selector like everything else.
    pub mcp_manager: Option<crate::agent::mcp_integration::SharedMcp>,
    /// When true, rebuild the prior conversation from `COL_MESSAGES` (this
    /// thread) before appending `user_message` — used by `resume` so the run
    /// continues with real history instead of a cold prompt.
    #[allow(dead_code)]
    pub rehydrate: bool,
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

        // Durable run for this conversation thread: gives `resume` something to
        // find, and records status/metrics. One run per thread (reused across
        // turns). The full history lives in COL_MESSAGES.
        let run_id = crate::agent::run_store::ensure_run(
            &db,
            "chat",
            &opts.agent_id,
            &opts.thread_id,
            serde_json::json!({ "message": opts.user_message }),
        )
        .await
        .ok();

        tokio::spawn(async move {
            let result = run_loop(db.clone(), config, opts, tx.clone(), run_id.clone()).await;

            // Seal the run: completed on a clean finish, interrupted on error so
            // it shows up as resumable.
            if let Some(rid) = &run_id {
                match &result {
                    Ok(()) => {
                        let _ = crate::agent::run_store::complete_run(&db, rid).await;
                    }
                    Err(_) => {
                        let _ = crate::agent::run_store::interrupt_run(&db, rid).await;
                    }
                }
            }

            if let Err(e) = result {
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
    run_id: Option<String>,
) -> Result<()> {
    use hivecyber_providers::{CallRequest, Content};

    let agent = db
        .get(crate::store::collections::COL_AGENTS, &opts.agent_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("agent not found: {}", opts.agent_id))?;

    let provider = agent
        .get("provider_id")
        .and_then(|v| v.as_str())
        .or_else(|| Some(config.models.default_provider.as_str()))
        .unwrap_or("anthropic");

    // Model resolution: agent's own model_id, else the global config default,
    // else empty — an empty model tells ProviderRegistry::get to use that
    // provider's own default_model, so we never hardcode (and never let stale)
    // per-provider model ids drift out of date here.
    let model = agent
        .get("model_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(&config.models.default_model);

    // API key resolution: environment variable first, then the encrypted secret
    // store (so a host configured via `provider set` runs with no env vars). The
    // registry knows every provider (hiveagents, deepseek, qwen, …).
    let api_key =
        crate::security::crypto::resolve_api_key(&db, &config.home_dir, provider).await;

    let registry = crate::settings::registry_for(&db).await;
    let client = registry
        .get(provider, model, &api_key)
        .ok_or_else(|| anyhow::anyhow!("provider not configured: {}", provider))?;

    // Effective model id (agent/config, else the provider's default) → used to
    // look up the real context window for the compaction budget.
    let effective_model = if model.is_empty() {
        registry.default_model_for(provider).unwrap_or_default()
    } else {
        model.to_string()
    };
    let context_budget = crate::agent::models_catalog::resolve_context_budget(
        &db,
        provider,
        &effective_model,
        config.models.context_token_budget,
    )
    .await;

    let mut system_prompt = agent
        .get("system_prompt")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Per-session scratch dir: same rationale as the worker_task executor
    // (harness/executors.rs) — gives cli_exec/fs_write/fs_edit/fs_delete a
    // default working directory scoped to this interactive session instead of
    // the process's own cwd. Keyed by thread_id since the interactive loop has
    // no task_id of its own.
    let scratch_dir = std::path::PathBuf::from(&config.home_dir)
        .join("scratch")
        .join(&opts.thread_id);
    tokio::fs::create_dir_all(&scratch_dir).await?;
    let session_security = Arc::new(hivecyber_tools::SecurityContext {
        task_root: Some(scratch_dir),
        ..(*opts.security).clone()
    });

    let mut tool_registry = hivecyber_tools::ToolRegistry::create_with_security(session_security.clone());

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
            tool_registry.register(Arc::new(hivecyber_tools::delegation::TaskDelegate {
                db: backend.clone(),
            }));
            tool_registry.register(Arc::new(hivecyber_tools::delegation::TaskStatus {
                db: backend.clone(),
            }));
            tool_registry.register(Arc::new(hivecyber_tools::delegation::TaskList {
                db: backend.clone(),
            }));
            tool_registry.register(Arc::new(hivecyber_tools::delegation::TaskRevise {
                db: backend,
            }));
        }
    }

    // Durable agent memory (write/read/list/search) for every agent — the
    // long-running coordinator especially benefits from recalling findings
    // across turns. Surfaced by the BM25 tool-selector when relevant.
    {
        let mem = Arc::new(crate::agent::memory_backend::MemoryBackend { db: db.clone() });
        tool_registry.register(Arc::new(hivecyber_tools::memory::MemoryWrite { db: mem.clone() }));
        tool_registry.register(Arc::new(hivecyber_tools::memory::MemoryRead { db: mem.clone() }));
        tool_registry.register(Arc::new(hivecyber_tools::memory::MemoryList { db: mem.clone() }));
        tool_registry.register(Arc::new(hivecyber_tools::memory::MemorySearch { db: mem }));
    }

    // Expose the connected MCP servers' tools to this agent. Registered after
    // the native + delegation tools so a colliding MCP tool name never shadows
    // a security-gated built-in (native wins). They then flow through the BM25
    // tool-selector below like any other tool.
    if let Some(mcp) = opts.mcp_manager.as_ref() {
        let n = crate::agent::mcp_integration::register_mcp_tools(&mut tool_registry, mcp).await;
        if n > 0 {
            tracing::info!("registered {} MCP tool(s) for agent {}", n, opts.agent_id);
        }
    }

    // Live routing context (BM25): for the coordinator, append the worker roster
    // ranked against this request plus the full routing catalog with exclusions —
    // the previously-static worker table becomes a live routing aid. For every
    // agent, surface the skills most relevant to the task. Both are appended to
    // the system prompt; empty when there is nothing relevant.
    if role == "coordinator" {
        let ctx = crate::agent::routing_context::build_coordinator_context(&db, &opts.user_message).await;
        if !ctx.is_empty() {
            system_prompt.push_str("\n\n");
            system_prompt.push_str(&ctx);
        }
        // Surface the connected MCP tools in the system prompt so the
        // coordinator knows (by name) what capabilities exist even before the
        // BM25 selector picks them — critical for smaller models that may not
        // reliably inspect the tool schema.
        if let Some(mcp) = opts.mcp_manager.as_ref() {
            let mcp_ctx = crate::agent::routing_context::build_mcp_tools_context(mcp).await;
            if !mcp_ctx.is_empty() {
                system_prompt.push_str("\n\n");
                system_prompt.push_str(&mcp_ctx);
            }
        }
    }
    {
        let skills_ctx = crate::agent::routing_context::build_skill_context(&db, &opts.user_message).await;
        if !skills_ctx.is_empty() {
            system_prompt.push_str("\n\n");
            system_prompt.push_str(&skills_ctx);
        }
    }

    // Dynamic tool selection (BM25): send the model only the tools relevant to
    // this task, not the whole catalog — fewer tokens, better precision. The
    // selection is made once from the initiating message and reused for the
    // whole loop. Safety rails: delegation tools (`task_*`) are always kept,
    // and if nothing scores above the cutoff (and it is not a conversational
    // message) we fall back to the full set so the agent is never left
    // tool-less. See agent/tool_selector.rs.
    let descriptors: Vec<crate::agent::tool_selector::ToolDescriptor> = tool_registry
        .all()
        .iter()
        .map(|t| crate::agent::tool_selector::ToolDescriptor {
            name: t.name().into(),
            description: t.description().into(),
            category: format!("{:?}", t.category()).to_lowercase(),
        })
        .collect();

    let selection = crate::agent::tool_selector::select_tools(&opts.user_message, &descriptors);
    let mut active_names: std::collections::HashSet<String> =
        selection.selected.iter().cloned().collect();
    // Always keep delegation tools available to the coordinator.
    for d in &descriptors {
        if d.name.starts_with("task_") {
            active_names.insert(d.name.clone());
        }
    }
    // Fallback: real request but no strong match → keep the full catalog.
    if !selection.conversational && !selection.matched {
        for d in &descriptors {
            active_names.insert(d.name.clone());
        }
    }
    tracing::debug!(
        "tool-selector: {} of {} tools active ({})",
        active_names.len(),
        descriptors.len(),
        selection.reasoning
    );

    let tool_defs: Vec<hivecyber_providers::ToolDef> = tool_registry
        .all()
        .iter()
        .filter(|t| active_names.contains(t.name()))
        .map(|t| hivecyber_providers::ToolDef {
            name: t.name().into(),
            description: t.description().into(),
            parameters: serde_json::to_value(t.parameters()).unwrap_or_default(),
        })
        .collect();
    let mut tool_defs = tool_defs;

    let max_iter = opts.max_iterations.max(1);

    let mut messages: Vec<hivecyber_providers::Message> = Vec::new();

    // Resume: rebuild the prior conversation for this thread from COL_MESSAGES
    // (clean user/assistant turns — tool turns are not persisted, so there are no
    // orphaned tool_result blocks to worry about).
    if opts.rehydrate {
        messages = load_thread_history(&db, &opts.thread_id).await;
        if !messages.is_empty() {
            let _ = tx
                .send(StreamChunk::Agent {
                    text: format!("[sistema] Rehidratados {} mensajes del hilo.\n", messages.len()),
                })
                .await;
        }
    }

    // Append the current user turn, unless rehydration already left an
    // unanswered user turn at the tail (avoid two consecutive user messages).
    let ends_with_user = messages.last().map(|m| m.role == "user").unwrap_or(false);
    if !(opts.rehydrate && ends_with_user) {
        messages.push(hivecyber_providers::Message {
            role: "user".into(),
            content: Content::Text(opts.user_message.clone()),
        });
        let _ = db
            .insert(
                crate::store::collections::COL_MESSAGES,
                &uuid::Uuid::new_v4().to_string(),
                serde_json::to_value(&crate::store::collections::MessageDoc {
                    id: uuid::Uuid::new_v4().to_string(),
                    thread_id: opts.thread_id.clone(),
                    role: "user".into(),
                    content: serde_json::Value::String(opts.user_message.clone()),
                    tool_calls: None,
                    tool_call_id: None,
                    created_at: chrono::Utc::now().to_rfc3339(),
                })?,
            )
            .await;
    }

    let mut stuck = crate::agent::stuck::StuckLoopDetector::new();
    let mut total_tokens: u64 = 0;

    // Every tool call in the interactive/coordinator loop must go through the
    // audited middleware — same as the worker path in harness/executors.rs.
    // Otherwise Isolation::Sandbox tools (metasploit_rpc, hydra, crackmapexec,
    // mimikatz) would run in-process unsandboxed and nothing would be written to
    // the tamper-evident audit log. The interactive loop has no durable job, so
    // the conversation's thread_id is used as the run identifier.
    let middleware = crate::tool_runtime::middleware::ToolMiddleware::new(
        db.clone(),
        session_security.clone(),
    );
    let audit_ctx = crate::tool_runtime::middleware::AuditCtx {
        worker: opts.agent_id.clone(),
        run_id: opts.thread_id.clone(),
        operator_id: session_security.operator_id.clone(),
    };

    for iteration in 0..max_iter {
        // Compact the in-memory working set if it has grown past the budget.
        // Only the working set is touched — COL_MESSAGES stays the full,
        // append-only record (used for audit and resume).
        if crate::agent::compaction::maybe_compact(
            &client,
            &mut messages,
            context_budget,
        )
        .await
        {
            let _ = tx
                .send(StreamChunk::Agent {
                    text: "[sistema] Contexto compactado para continuar la operación.\n".into(),
                })
                .await;
        }

        let req = CallRequest {
            system: Some(system_prompt.to_string()),
            messages: messages.clone(),
            tools: tool_defs.clone(),
            max_tokens: Some(16384),
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

        // Checkpoint the durable run each turn (iterations + tokens + lease).
        total_tokens += response.input_tokens + response.output_tokens;
        if let Some(rid) = &run_id {
            let _ = crate::agent::run_store::checkpoint_run(
                &db,
                rid,
                iteration + 1,
                total_tokens,
                serde_json::json!({ "thread_id": opts.thread_id, "turn": iteration + 1 }),
            )
            .await;
        }

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

        let results = crate::tool_runtime::middleware::execute_tool_batch_audited(
            tool_calls_vec,
            &tool_registry,
            config.tools.worker_pool.tool_timeout_ms,
            &middleware,
            &audit_ctx,
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
                        run_id: audit_ctx.run_id.clone(),
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

            // Cap tool results so a single huge MCP response (e.g. a full brief
            // JSON) doesn't dominate the context window and starve the model.
            const MAX_TOOL_RESULT_CHARS: usize = 8000;
            let result_str = if result_str.len() > MAX_TOOL_RESULT_CHARS {
                format!("{}…[truncado: {} chars totales]", &result_str[..MAX_TOOL_RESULT_CHARS], result_str.len())
            } else {
                result_str
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

        // Per-turn tool re-injection: the coordinator can discover mid-conversation
        // that it needs a tool it didn't have at the start (e.g. an MCP tool the
        // initial BM25 missed). Re-run the selector on the latest assistant text
        // + the original request and merge any newly-relevant tools into the
        // active set. This only ever ADDS tools — the coordinator can never lose
        // a tool it already had — so mid-flight tool_use/tool_result pairs stay
        // valid and the `task_*` base is preserved.
        if role == "coordinator" {
            let last_text = response.content_text().unwrap_or_default();
            if !last_text.is_empty() {
                let requery = format!("{} {}", opts.user_message, last_text);
                let re_sel = crate::agent::tool_selector::select_tools(&requery, &descriptors);
                let before = active_names.len();
                for name in &re_sel.selected {
                    if active_names.insert(name.clone()) {
                        continue;
                    }
                }
                if active_names.len() > before {
                    tracing::debug!(
                        "tool-selector (turn {}): injected {} new tool(s) → {} of {} active",
                        iteration + 1,
                        active_names.len() - before,
                        active_names.len(),
                        descriptors.len()
                    );
                    tool_defs = tool_registry
                        .all()
                        .iter()
                        .filter(|t| active_names.contains(t.name()))
                        .map(|t| hivecyber_providers::ToolDef {
                            name: t.name().into(),
                            description: t.description().into(),
                            parameters: serde_json::to_value(t.parameters()).unwrap_or_default(),
                        })
                        .collect();
                }
            }
        }
    }

    let _ = tx
        .send(StreamChunk::Agent {
            text: "[max iterations reached]".into(),
        })
        .await;

    Ok(())
}
/// Rebuild a thread's conversation from `COL_MESSAGES` for `resume`. Returns the
/// user/assistant turns in chronological order. Tool-call turns are not persisted
/// there, so the reconstructed history is a clean alternating conversation with
/// no dangling tool_use/tool_result blocks.
async fn load_thread_history(
    db: &crate::store::HiveDb,
    thread_id: &str,
) -> Vec<hivecyber_providers::Message> {
    use hivecyber_providers::{Content, Message};

    let mut docs: Vec<serde_json::Value> = db
        .list(crate::store::collections::COL_MESSAGES)
        .await
        .into_iter()
        .map(|(_, v)| v)
        .filter(|v| v.get("thread_id").and_then(|t| t.as_str()) == Some(thread_id))
        .collect();

    docs.sort_by(|a, b| {
        let ka = a.get("created_at").and_then(|v| v.as_str()).unwrap_or("");
        let kb = b.get("created_at").and_then(|v| v.as_str()).unwrap_or("");
        ka.cmp(kb)
    });

    docs.into_iter()
        .filter_map(|v| {
            let role = v.get("role").and_then(|r| r.as_str())?;
            if role != "user" && role != "assistant" {
                return None;
            }
            let content = v.get("content").and_then(|c| c.as_str()).unwrap_or("").to_string();
            Some(Message { role: role.to_string(), content: Content::Text(content) })
        })
        .collect()
}

#[cfg(test)]
mod rehydrate_tests {
    use super::load_thread_history;
    use crate::store::HiveDb;
    use crate::store::collections::COL_MESSAGES;

    async fn tmp_db() -> HiveDb {
        let dir = std::env::temp_dir().join(format!("hc_rehy_{}", uuid::Uuid::new_v4()));
        HiveDb::open(&dir).await.unwrap()
    }

    async fn put(db: &HiveDb, thread: &str, role: &str, content: &str, ts: &str) {
        db.insert(
            COL_MESSAGES,
            &uuid::Uuid::new_v4().to_string(),
            serde_json::json!({
                "id": uuid::Uuid::new_v4().to_string(),
                "thread_id": thread,
                "role": role,
                "content": content,
                "created_at": ts,
            }),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn rehydrates_thread_in_order_and_filters() {
        let db = tmp_db().await;
        // Out-of-insert-order timestamps to prove chronological sorting.
        put(&db, "t1", "assistant", "segundo (assistant)", "2026-01-01T00:00:02Z").await;
        put(&db, "t1", "user", "primero (user)", "2026-01-01T00:00:01Z").await;
        put(&db, "t1", "tool", "no debe aparecer", "2026-01-01T00:00:03Z").await;
        put(&db, "other", "user", "otro hilo", "2026-01-01T00:00:01Z").await;

        let hist = load_thread_history(&db, "t1").await;
        assert_eq!(hist.len(), 2, "tool role skipped, other thread excluded");
        assert_eq!(hist[0].role, "user");
        assert_eq!(hist[1].role, "assistant");
        match &hist[0].content {
            hivecyber_providers::Content::Text(t) => assert!(t.contains("primero")),
            _ => panic!("expected text"),
        }
    }
}
