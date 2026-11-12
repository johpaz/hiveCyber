//! MCP ↔ agent integration.
//!
//! Loads MCP servers from `COL_MCP_SERVERS`, connects them, and exposes each
//! discovered MCP tool to the agents as a normal `Tool` (`McpToolProxy`). Once
//! registered in the `ToolRegistry`, MCP tools flow through the BM25
//! `tool_selector` automatically — no separate capability index step needed.
//!
//! Rust equivalent of Hive's `mcp/tool-sync.ts` (which indexes MCP tools into
//! the capability index) plus `packages/mcp/src/manager.ts` (register/connect).

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::Mutex;

use hivecyber_mcp::{McpClientManager, McpServerConfig};
use hivecyber_tools::{Tool, ToolCategory, ToolRegistry, ToolSchema};

use crate::store::HiveDb;
use crate::store::collections::COL_MCP_SERVERS;

/// A connected MCP manager shared across the agent loop. Behind a `Mutex`
/// because `call_tool`/`connect` mutate connection state; MCP calls are not
/// high-concurrency and stdio is serial per server anyway.
pub type SharedMcp = Arc<Mutex<McpClientManager>>;

/// Read the configured servers, register + connect them (best-effort), and
/// return the shared manager. A server that fails to connect is left in its
/// error state; the rest still work.
pub async fn load_and_connect(db: &HiveDb) -> SharedMcp {
    let mut manager = McpClientManager::new();

    for (name, doc) in db.list(COL_MCP_SERVERS).await {
        match serde_json::from_value::<McpServerConfig>(doc.clone()) {
            Ok(cfg) => {
                if cfg.enabled {
                    manager.register(&name, cfg);
                }
            }
            Err(e) => {
                tracing::warn!("mcp: bad config for server '{}': {}", name, e);
            }
        }
    }

    let errors = manager.connect_all().await;
    for err in &errors {
        tracing::warn!("mcp connect: {}", err);
    }

    Arc::new(Mutex::new(manager))
}

/// Register a proxy tool in `registry` for every tool the connected MCP servers
/// exposed. Native tools win on name collision (an MCP tool named like a
/// built-in is skipped) so the harness's own security-gated tools are never
/// shadowed.
pub async fn register_mcp_tools(
    registry: &mut ToolRegistry,
    mcp: &SharedMcp,
    security: Arc<hivecyber_tools::SecurityContext>,
) -> usize {
    let discovered: Vec<(String, String, String, Value)> = {
        let mgr = mcp.lock().await;
        mgr.list_tools()
            .into_iter()
            .map(|t| {
                (
                    t.server_name.clone(),
                    t.name.clone(),
                    t.description.clone(),
                    t.parameters.clone(),
                )
            })
            .collect()
    };

    let mut added = 0;
    for (server, name, description, schema) in discovered {
        if registry.get(&name).is_some() {
            tracing::debug!("mcp: skipping tool '{}' (name collides with a native tool)", name);
            continue;
        }
        registry.register(Arc::new(McpToolProxy {
            mcp: mcp.clone(),
            server,
            tool_name: name,
            description,
            input_schema: schema,
            security: security.clone(),
        }));
        added += 1;
    }
    added
}

/// A single MCP tool presented to the agents as a `Tool`. `execute` forwards
/// the call to the owning MCP server via the shared manager.
pub struct McpToolProxy {
    mcp: SharedMcp,
    server: String,
    tool_name: String,
    description: String,
    input_schema: Value,
    security: Arc<hivecyber_tools::SecurityContext>,
}

/// Scope gate for MCP tools. MCP servers (browsers in particular) make network
/// requests the harness cannot inspect, so under an EngagementPolicy:
/// - if the program mandates request headers, MCP tools are refused (they cannot
///   be attached to a browser's traffic);
/// - any URL-like argument must be in scope (and rate-limited).
/// Servers that enforce scope/headers/rate themselves on every browser request
/// (see tools/scoped-browser) are exempt from the blanket header refusal.
const SCOPE_ENFORCING_SERVERS: &[&str] = &["scoped-browser"];

fn mcp_scope_check(sec: &hivecyber_tools::SecurityContext, server: &str, params: &Value) -> Result<(), String> {
    let Some(policy) = sec.engagement_policy.as_ref() else { return Ok(()) };
    if !policy.required_headers.is_empty() && !SCOPE_ENFORCING_SERVERS.contains(&server) {
        return Err(format!(
            "MCP tools are disabled under program '{}': it requires request headers ({}) that an MCP browser cannot attach",
            policy.program,
            policy.required_headers.keys().cloned().collect::<Vec<_>>().join(", ")
        ));
    }
    if let Some(obj) = params.as_object() {
        for key in ["url", "uri", "href", "target", "host"] {
            if let Some(u) = obj.get(key).and_then(|v| v.as_str()) {
                sec.check_web_scope(u, "GET", true)?;
            }
        }
    }
    Ok(())
}

#[async_trait]
impl Tool for McpToolProxy {
    fn name(&self) -> &str {
        &self.tool_name
    }
    fn description(&self) -> &str {
        &self.description
    }
    fn category(&self) -> ToolCategory {
        ToolCategory::Base
    }
    fn parameters(&self) -> ToolSchema {
        schema_from_mcp(&self.input_schema)
    }
    async fn execute(&self, params: Value) -> Result<Value> {
        if let Err(e) = mcp_scope_check(&self.security, &self.server, &params) {
            return Ok(serde_json::json!({"error": "security_policy", "message": e}));
        }
        let mut mgr = self.mcp.lock().await;
        mgr.call_tool(&self.server, &self.tool_name, &params).await
    }
}

/// Convert an MCP `inputSchema` (JSON Schema object) into the harness's
/// `ToolSchema`. Missing/odd schemas degrade to an empty object schema.
fn schema_from_mcp(schema: &Value) -> ToolSchema {
    let obj = schema.as_object();
    let properties = obj
        .and_then(|o| o.get("properties"))
        .and_then(|p| p.as_object())
        .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default();
    let required = obj
        .and_then(|o| o.get("required"))
        .and_then(|r| r.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect());
    ToolSchema {
        schema_type: "object".into(),
        properties,
        required,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mcp_blocked_when_program_requires_headers_and_url_checked() {
        let mk = |v: serde_json::Value| hivecyber_tools::SecurityContext {
            engagement_policy: Some(Arc::new(serde_json::from_value(v).unwrap())),
            ..Default::default()
        };
        let with_headers = mk(serde_json::json!({"program":"p","targets":[{"host":"ok.com","methods":["GET"]}],"required_headers":{"X-A":"b"}}));
        assert!(mcp_scope_check(&with_headers, "obscura", &serde_json::json!({"url":"https://ok.com/"})).is_err());
        let plain = mk(serde_json::json!({"program":"p","targets":[{"host":"ok.com","methods":["GET"]}]}));
        assert!(mcp_scope_check(&with_headers, "scoped-browser", &serde_json::json!({"url":"https://ok.com/"})).is_ok());
        assert!(mcp_scope_check(&with_headers, "scoped-browser", &serde_json::json!({"url":"https://evil.com/"})).is_err());
        assert!(mcp_scope_check(&plain, "obscura", &serde_json::json!({"url":"https://ok.com/"})).is_ok());
        assert!(mcp_scope_check(&plain, "obscura", &serde_json::json!({"url":"https://evil.com/"})).is_err());
        assert!(mcp_scope_check(&hivecyber_tools::SecurityContext::default(), "obscura", &serde_json::json!({"url":"https://evil.com/"})).is_ok());
    }

    #[test]
    fn schema_from_mcp_extracts_properties_and_required() {
        let s = serde_json::json!({
            "type": "object",
            "properties": { "path": {"type": "string"}, "n": {"type": "integer"} },
            "required": ["path"]
        });
        let ts = schema_from_mcp(&s);
        assert_eq!(ts.schema_type, "object");
        assert!(ts.properties.contains_key("path"));
        assert_eq!(ts.required, Some(vec!["path".to_string()]));
    }

    #[test]
    fn schema_from_mcp_handles_missing() {
        let ts = schema_from_mcp(&serde_json::Value::Null);
        assert!(ts.properties.is_empty());
        assert!(ts.required.is_none());
    }
}
