//! WebSocket chat: `/api/chat/:agent_id?ticket=…&thread=…`
//!
//! Client → server: `{"type":"user_message","text"}`,
//!                  `{"type":"approve","category"}`, `{"type":"deny","category"}`
//! Server → client: every `StreamChunk` (tagged by `type`) plus
//!                  `{"type":"ApprovalRequired","category","tool","args"}`
//!                  when the middleware blocked a tool pending human approval.

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use futures::{SinkExt, StreamExt};
use hivecyber_core::agent::loop_runner::{AgentLoopOptions, StreamChunk};
use hivecyber_core::agent::AgentLoop;
use hivecyber_core::store::collections::COL_AGENTS;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::mpsc;

use crate::state::Shared;

#[derive(Deserialize)]
pub struct ChatQ {
    pub ticket: String,
    pub thread: Option<String>,
    /// Resume: rebuild prior history from COL_MESSAGES for the first turn.
    pub rehydrate: Option<bool>,
}

pub async fn chat_ws(
    ws: WebSocketUpgrade,
    State(s): State<Shared>,
    Path(agent_id): Path<String>,
    Query(q): Query<ChatQ>,
) -> Response {
    if !s.redeem_ticket(&q.ticket) {
        return (StatusCode::UNAUTHORIZED, "invalid or expired ticket").into_response();
    }
    let thread = q.thread.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let rehydrate = q.rehydrate.unwrap_or(false);
    ws.on_upgrade(move |sock| handle(sock, s, agent_id, thread, rehydrate))
}

async fn handle(sock: WebSocket, s: Shared, agent_id: String, thread: String, rehydrate: bool) {
    let rehydrate = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(rehydrate));
    // category → exact blocked call (tool, args). Approvals are only honoured for a call
    // the middleware actually blocked, and the retry names that exact call.
    let pending: Pending = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    let (mut sink, mut stream) = sock.split();
    let (out_tx, mut out_rx) = mpsc::channel::<Value>(256);

    let writer = tokio::spawn(async move {
        while let Some(v) = out_rx.recv().await {
            if sink.send(Message::Text(v.to_string())).await.is_err() {
                break;
            }
        }
    });

    // Fail closed: no active policy → no chat (the `--require-policy` gate).
    if s.runtime().await.security.engagement_policy.is_none() {
        let _ = out_tx
            .send(json!({"type":"Error","message":"no active EngagementPolicy — activate one before chatting"}))
            .await;
        drop(out_tx);
        let _ = writer.await;
        return;
    }
    let _ = out_tx.send(json!({"type":"Ready","agent":agent_id,"thread":thread})).await;

    while let Some(Ok(msg)) = stream.next().await {
        let Message::Text(text) = msg else { continue };
        let Ok(v) = serde_json::from_str::<Value>(&text) else { continue };
        match v["type"].as_str().unwrap_or("") {
            "user_message" => {
                let t = v["text"].as_str().unwrap_or("").trim().to_string();
                if !t.is_empty() {
                    spawn_turn(s.clone(), agent_id.clone(), thread.clone(), t, out_tx.clone(), rehydrate.swap(false, std::sync::atomic::Ordering::SeqCst), pending.clone());
                }
            }
            "approve" => {
                let cat = v["category"].as_str().unwrap_or("").to_string();
                let Some((tool, args)) = pending.lock().unwrap().remove(&cat) else {
                    let _ = out_tx.send(json!({"type":"Error","message":format!("no pending approval for '{cat}'")})).await;
                    continue;
                };
                s.runtime().await.security.grant_human_approval(&cat);
                let _ = hivecyber_core::security::audit::append_audit(
                    &s.db, "human_approval", &format!("{cat}:{tool}"), "gateway", &thread, &s.flags.operator_id,
                ).await;
                let msg = format!(
                    "[Operador] APROBÓ la categoría '{cat}' para esta llamada exacta. Ejecútala ahora, una sola vez y sin cambiar los argumentos:\n{tool}({args})"
                );
                spawn_turn(s.clone(), agent_id.clone(), thread.clone(), msg, out_tx.clone(), false, pending.clone());
            }
            "deny" => {
                let cat = v["category"].as_str().unwrap_or("").to_string();
                pending.lock().unwrap().remove(&cat);
                let _ = hivecyber_core::security::audit::append_audit(
                    &s.db, "human_denial", &cat, "gateway", &thread, &s.flags.operator_id,
                ).await;
                let msg = format!(
                    "[Operador] DENEGÓ la categoría '{cat}'. No reintentes esa acción en este turno; propón una alternativa dentro de lo permitido."
                );
                spawn_turn(s.clone(), agent_id.clone(), thread.clone(), msg, out_tx.clone(), false, pending.clone());
            }
            _ => {}
        }
    }
    drop(out_tx);
    writer.abort();
}

type Pending = std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, (String, Value)>>>;

fn spawn_turn(s: Shared, agent_id: String, thread: String, text: String, out: mpsc::Sender<Value>, rehydrate: bool, pending: Pending) {
    tokio::spawn(async move {
        let rt = s.runtime().await;
        let max_iter = s
            .db
            .get(COL_AGENTS, &agent_id)
            .await
            .and_then(|a| a["max_iterations"].as_u64())
            .unwrap_or(20) as u32;
        let opts = AgentLoopOptions {
            agent_id: agent_id.clone(),
            user_message: text,
            thread_id: thread,
            max_iterations: max_iter.min(40),
            security: rt.security.clone(),
            queue: Some(rt.dispatch.queue()),
            mcp_manager: rt.mcp.clone(),
            rehydrate,
        };
        let loop_runner = AgentLoop::new((*s.db).clone(), s.config.clone());
        let mut rx = match loop_runner.run(opts).await {
            Ok(rx) => rx,
            Err(e) => {
                let _ = out.send(json!({"type":"Error","message":e.to_string()})).await;
                return;
            }
        };
        while let Some(chunk) = rx.recv().await {
            if let StreamChunk::ToolResult { result, .. } = &chunk {
                if result["status"] == "blocked_pending_approval" {
                    if let Some(cat) = result["category"].as_str() {
                        pending.lock().unwrap().insert(cat.to_string(), (result["tool"].as_str().unwrap_or("").to_string(), result["args"].clone()));
                    }
                    let _ = out
                        .send(json!({
                            "type": "ApprovalRequired",
                            "category": result["category"],
                            "tool": result["tool"],
                            "args": result["args"],
                        }))
                        .await;
                }
            }
            let v = serde_json::to_value(&chunk).unwrap_or(Value::Null);
            if out.send(v).await.is_err() {
                break;
            }
        }
    });
}
