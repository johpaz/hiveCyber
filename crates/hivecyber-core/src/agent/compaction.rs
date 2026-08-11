//! Context compaction for the long-running loop — Rust port of Hive's
//! `compaction.ts`, adapted to this harness's message model.
//!
//! The interactive/coordinator loop accumulates every turn in an in-memory
//! `Vec<Message>` that is re-sent to the model each iteration. Left unbounded it
//! eventually exceeds the model's context window. Compaction replaces the older
//! prefix with a single summary message, keeping the recent tail verbatim.
//!
//! Two invariants matter and are enforced here:
//!   1. **Durable history is never touched.** `COL_MESSAGES` is the append-only
//!      record used for audit/`resume`; compaction operates ONLY on the working
//!      set sent to the model. The caller must not persist the compacted vec back
//!      over `COL_MESSAGES`.
//!   2. **No orphaned tool results / broken alternation.** A `tool_result`
//!      message (role `user`) without its preceding `assistant` tool-call would
//!      be rejected by the provider. The cut boundary is therefore advanced to
//!      the next `assistant` message, which both skips leading tool-results and
//!      yields a clean `user(summary) → assistant(...)` alternation.
//!
//! There is no per-model context window stored anywhere (the provider registry
//! only knows base URL + default model), so the trigger is a configurable token
//! budget — a heuristic estimate, not a hard model limit.

use std::sync::Arc;

use hivecyber_providers::{CallRequest, Content, LlmProvider, Message};

/// Minimum recent messages always kept verbatim through a compaction.
pub const MIN_RECENT_MESSAGES: usize = 4;

/// Rough token estimate: ~4 chars/token plus a small per-message overhead for
/// role/formatting. Good enough to drive a budget; not exact tokenization.
pub fn estimate_message_tokens(m: &Message) -> usize {
    let chars = match &m.content {
        Content::Text(s) => s.len(),
        Content::ToolResult { tool_name, content, .. } => tool_name.len() + content.len(),
        Content::AssistantWithTools { text, tool_calls } => {
            let args: usize = tool_calls
                .iter()
                .map(|t| t.name.len() + t.arguments.to_string().len())
                .sum();
            text.len() + args
        }
    };
    chars / 4 + 4
}

pub fn estimate_tokens(messages: &[Message]) -> usize {
    messages.iter().map(estimate_message_tokens).sum()
}

/// Decide where to cut. Returns the index `keep_from` such that
/// `messages[..keep_from]` should be summarized and `messages[keep_from..]` kept
/// verbatim, or `None` when no compaction is needed or a safe boundary can't be
/// found.
///
/// `budget` triggers compaction; `keep_budget` bounds the kept tail (recent
/// turns); `min_recent` guarantees at least that many trailing messages survive.
pub fn plan_compaction(
    messages: &[Message],
    budget: usize,
    keep_budget: usize,
    min_recent: usize,
) -> Option<usize> {
    if estimate_tokens(messages) <= budget {
        return None;
    }

    // Walk from the end, accumulating the recent tail until it would exceed
    // keep_budget (but always keep at least `min_recent` messages).
    let mut acc = 0usize;
    let mut i = messages.len();
    while i > 0 {
        let t = estimate_message_tokens(&messages[i - 1]);
        let kept = messages.len() - i;
        if acc + t > keep_budget && kept >= min_recent {
            break;
        }
        acc += t;
        i -= 1;
    }

    // Advance the boundary to the next `assistant` message. This skips any
    // leading tool_result (role "user") — which would otherwise be orphaned —
    // and guarantees the compacted list alternates user(summary) → assistant.
    while i < messages.len() && messages[i].role != "assistant" {
        i += 1;
    }

    // Need something to summarize (i>0) and something to keep (i<len).
    if i == 0 || i >= messages.len() {
        return None;
    }
    Some(i)
}

/// Build the compacted working set: a single `user` summary message followed by
/// the kept tail. Pure — does not touch the store.
pub fn compact_messages(messages: &[Message], keep_from: usize, summary: &str) -> Vec<Message> {
    let mut out = Vec::with_capacity(1 + messages.len().saturating_sub(keep_from));
    out.push(Message {
        role: "user".into(),
        content: Content::Text(format!("[Contexto previo resumido]\n{}", summary)),
    });
    out.extend_from_slice(&messages[keep_from..]);
    out
}

/// Deterministic, LLM-free summary of the messages being dropped: keeps the very
/// first user turn (the original task) verbatim and lists a truncated trace of
/// the rest. Used as a fallback when no summarizer is provided.
pub fn extractive_summary(messages: &[Message]) -> String {
    let mut s = String::new();
    if let Some(first) = messages.first() {
        if let Content::Text(t) = &first.content {
            s.push_str("Tarea original: ");
            s.push_str(t.trim());
            s.push('\n');
        }
    }
    s.push_str("Progreso previo (resumen):\n");
    for m in messages {
        let line = match &m.content {
            Content::Text(t) => format!("- {}: {}", m.role, snippet(t, 160)),
            Content::ToolResult { tool_name, content, .. } => {
                format!("- tool[{}] → {}", tool_name, snippet(content, 160))
            }
            Content::AssistantWithTools { text, tool_calls } => {
                let names: Vec<&str> = tool_calls.iter().map(|t| t.name.as_str()).collect();
                format!("- assistant llamó [{}] {}", names.join(", "), snippet(text, 120))
            }
        };
        s.push_str(&line);
        s.push('\n');
    }
    s
}

/// Compact the in-memory working set if it exceeds `budget`. Summarizes the
/// dropped prefix with the model (falling back to a deterministic summary), then
/// rewrites `messages` in place. Returns whether compaction happened.
///
/// IMPORTANT: this mutates only the working set. The caller MUST NOT persist the
/// result back over `COL_MESSAGES` — that collection is the durable, append-only
/// record used for audit and `resume`.
pub async fn maybe_compact(
    client: &Arc<dyn LlmProvider>,
    messages: &mut Vec<Message>,
    budget: usize,
) -> bool {
    if budget == 0 {
        return false; // compaction disabled
    }
    let Some(keep_from) = plan_compaction(messages, budget, budget / 2, MIN_RECENT_MESSAGES) else {
        return false;
    };

    let summary = summarize(client, &messages[..keep_from])
        .await
        .unwrap_or_else(|| extractive_summary(&messages[..keep_from]));
    let compacted = compact_messages(messages, keep_from, &summary);
    *messages = compacted;
    true
}

/// Ask the model to condense the dropped prefix. Feeds it the deterministic
/// extractive trace (bounded) and returns the model's summary, or `None` on any
/// failure so the caller uses the extractive fallback.
async fn summarize(client: &Arc<dyn LlmProvider>, slice: &[Message]) -> Option<String> {
    let transcript = extractive_summary(slice);
    let req = CallRequest {
        system: Some(
            "Resume de forma concisa esta conversación de una operación de ciberseguridad: \
             objetivo, hallazgos, decisiones tomadas y trabajo pendiente. No inventes datos ni \
             omitas hosts/credenciales/CVEs relevantes."
                .into(),
        ),
        messages: vec![Message {
            role: "user".into(),
            content: Content::Text(format!(
                "Conversación previa a resumir para continuar la operación:\n\n{}",
                transcript
            )),
        }],
        tools: Vec::new(),
        max_tokens: Some(1024),
    };
    match client.call(&req).await {
        Ok(resp) => {
            let text = resp.content_text().unwrap_or_default();
            if text.trim().is_empty() {
                None
            } else {
                Some(text)
            }
        }
        Err(_) => None,
    }
}

fn snippet(s: &str, n: usize) -> String {
    let t = s.trim();
    if t.chars().count() <= n {
        t.to_string()
    } else {
        format!("{}…", t.chars().take(n).collect::<String>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hivecyber_providers::{Content, Message, ToolCall};

    fn user(t: &str) -> Message {
        Message { role: "user".into(), content: Content::Text(t.into()) }
    }
    fn assistant(t: &str) -> Message {
        Message { role: "assistant".into(), content: Content::Text(t.into()) }
    }
    fn assistant_tools(t: &str, tool: &str) -> Message {
        Message {
            role: "assistant".into(),
            content: Content::AssistantWithTools {
                text: t.into(),
                tool_calls: vec![ToolCall { id: "c1".into(), name: tool.into(), arguments: serde_json::json!({}) }],
            },
        }
    }
    fn tool_result(name: &str, content: &str) -> Message {
        Message {
            role: "user".into(),
            content: Content::ToolResult {
                tool_call_id: "c1".into(),
                tool_name: name.into(),
                content: content.into(),
            },
        }
    }

    #[test]
    fn no_compaction_under_budget() {
        let msgs = vec![user("hola"), assistant("qué tal")];
        assert!(plan_compaction(&msgs, 10_000, 5_000, 2).is_none());
    }

    #[test]
    fn boundary_lands_on_assistant_and_skips_orphan_tool_results() {
        // user, assistant+tools, tool_result, assistant, ... — a naive tail cut
        // could start on the tool_result (orphan). The boundary must land on an
        // assistant message.
        let big = "x".repeat(4000);
        let msgs = vec![
            user(&big),               // 0
            assistant_tools("", "nmap"), // 1
            tool_result("nmap", &big),   // 2  (role user)
            assistant(&big),          // 3
            user(&big),               // 4
            assistant(&big),          // 5
        ];
        let keep = plan_compaction(&msgs, 1000, 600, 1).expect("should compact");
        assert_eq!(msgs[keep].role, "assistant", "boundary must be an assistant msg");
        // The message right at the boundary must not be a tool_result.
        assert!(!matches!(msgs[keep].content, Content::ToolResult { .. }));
    }

    #[test]
    fn compacted_list_starts_with_user_summary_then_assistant() {
        let big = "y".repeat(4000);
        let msgs = vec![
            user(&big),
            assistant_tools("", "nmap"),
            tool_result("nmap", &big),
            assistant(&big),
        ];
        let keep = plan_compaction(&msgs, 1000, 500, 1).expect("compact");
        let out = compact_messages(&msgs, keep, "resumen");
        assert_eq!(out[0].role, "user");
        assert!(matches!(&out[0].content, Content::Text(t) if t.contains("resumido")));
        // No orphan tool_result at the head of the kept tail.
        assert!(!matches!(out[1].content, Content::ToolResult { .. }));
        assert_eq!(out[1].role, "assistant");
    }

    #[test]
    fn extractive_summary_keeps_original_task() {
        let msgs = vec![user("escanear 10.0.0.5"), assistant_tools("ok", "nmap"), tool_result("nmap", "puerto 22")];
        let s = extractive_summary(&msgs);
        assert!(s.contains("Tarea original: escanear 10.0.0.5"));
        assert!(s.contains("nmap"));
    }

    // Mock provider that returns a fixed summary, to exercise maybe_compact.
    struct MockSummarizer;
    #[async_trait::async_trait]
    impl hivecyber_providers::LlmProvider for MockSummarizer {
        async fn call(
            &self,
            _req: &hivecyber_providers::CallRequest,
        ) -> anyhow::Result<hivecyber_providers::LlmResponse> {
            Ok(hivecyber_providers::LlmResponse {
                content: vec![hivecyber_providers::traits::ContentBlock::Text {
                    text: "RESUMEN-MOCK".into(),
                }],
                tool_calls: vec![],
                stop_reason: "end_turn".into(),
                input_tokens: 0,
                output_tokens: 0,
            })
        }
    }

    #[tokio::test]
    async fn maybe_compact_shrinks_and_uses_summary() {
        let big = "z".repeat(4000);
        let mut msgs = vec![
            user(&big),
            assistant_tools("", "nmap"),
            tool_result("nmap", &big),
            assistant(&big),
            user(&big),
            assistant(&big),
        ];
        let before = msgs.len();
        let client: std::sync::Arc<dyn hivecyber_providers::LlmProvider> =
            std::sync::Arc::new(MockSummarizer);

        let did = maybe_compact(&client, &mut msgs, 1000).await;
        assert!(did, "should compact over budget");
        assert!(msgs.len() < before, "working set must shrink");
        // Head is the user summary carrying the model's summary text.
        assert_eq!(msgs[0].role, "user");
        assert!(matches!(&msgs[0].content, Content::Text(t) if t.contains("RESUMEN-MOCK")));
        // No orphan tool_result immediately after the summary.
        assert!(!matches!(msgs[1].content, Content::ToolResult { .. }));
    }

    #[tokio::test]
    async fn maybe_compact_noop_when_disabled_or_small() {
        let client: std::sync::Arc<dyn hivecyber_providers::LlmProvider> =
            std::sync::Arc::new(MockSummarizer);
        let mut small = vec![user("hola"), assistant("hey")];
        assert!(!maybe_compact(&client, &mut small, 0).await, "budget 0 disables");
        assert!(!maybe_compact(&client, &mut small, 100_000).await, "under budget");
        assert_eq!(small.len(), 2);
    }
}
