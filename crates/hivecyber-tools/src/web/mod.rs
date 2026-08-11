// Browser automation tools (web_pentester). Portadas del enfoque de Hive:
// en vez de embeber un cliente CDP pesado (chromiumoxide), se hace shell-out a
// `agent-browser` — un CLI ligero que gestiona Chrome headless por su cuenta.
// Ventaja para agentes/LLM: menos tokens, más precisión, y Chrome corre en su
// propio subproceso (fuera del seccomp del worker), no in-process.
//
// Interfaz: `agent-browser --session <name> --json <cmd> [args]` → última línea
// de stdout es JSON `{success, data?, error?}`. El binario se resuelve por
// `AGENT_BROWSER_BIN` (default `agent-browser`).

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::registry::{Tool, ToolCategory, ToolSchema};

const SESSION: &str = "hivecyber";

fn read_params(params: &Value) -> Result<HashMap<String, Value>> {
    params
        .as_object()
        .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .ok_or_else(|| anyhow!("params must be an object"))
}

/// Invoke the `agent-browser` CLI once and parse its JSON. Missing binary is a
/// graceful result (not a hard error), matching Hive's "install agent-browser"
/// message so the operator gets a clear signal instead of a crash.
async fn run_agent_browser(args: &[String], timeout_ms: u64) -> Value {
    use tokio::process::Command;

    let bin = std::env::var("AGENT_BROWSER_BIN").unwrap_or_else(|_| "agent-browser".to_string());

    let mut full: Vec<String> = vec!["--session".into(), SESSION.into(), "--json".into()];
    full.extend_from_slice(args);

    let child = Command::new(&bin)
        .args(&full)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn();

    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            return json!({
                "ok": false,
                "error": "browser_unavailable",
                "message": format!(
                    "agent-browser no disponible ('{}': {}). Instala agent-browser o setea AGENT_BROWSER_BIN.",
                    bin, e
                ),
            });
        }
    };

    let out = tokio::time::timeout(
        std::time::Duration::from_millis(timeout_ms.max(5_000)),
        child.wait_with_output(),
    )
    .await;

    let output = match out {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => return json!({"ok": false, "error": "io_error", "message": e.to_string()}),
        Err(_) => {
            return json!({"ok": false, "error": "timeout", "message": format!("agent-browser timeout after {}ms", timeout_ms)})
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // agent-browser prints one JSON object on the last stdout line.
    let last = stdout.trim().lines().last().unwrap_or("").trim();
    if let Ok(v) = serde_json::from_str::<Value>(last) {
        return v;
    }
    json!({
        "ok": output.status.success(),
        "raw": stdout.trim().chars().take(4000).collect::<String>(),
        "stderr": stderr.trim().chars().take(1000).collect::<String>(),
    })
}

macro_rules! str_arg {
    ($p:expr, $k:expr) => {
        $p.get($k)
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!(concat!($k, " required")))?
    };
}

pub struct BrowserNavigate;

#[async_trait]
impl Tool for BrowserNavigate {
    fn name(&self) -> &str { "browser_navigate" }
    fn description(&self) -> &str { "Navega el browser headless a una URL (agent-browser)." }
    fn category(&self) -> ToolCategory { ToolCategory::Web }
    fn parameters(&self) -> ToolSchema {
        let mut props = HashMap::new();
        props.insert("url".into(), json!({"type": "string"}));
        ToolSchema { schema_type: "object".into(), properties: props, required: Some(vec!["url".into()]) }
    }
    async fn execute(&self, params: Value) -> Result<Value> {
        let p = read_params(&params)?;
        let url = str_arg!(p, "url");
        let target = if url.starts_with("http://") || url.starts_with("https://") {
            url.to_string()
        } else {
            format!("https://{}", url)
        };
        Ok(run_agent_browser(&["open".into(), target], 30_000).await)
    }
}

pub struct BrowserClick;

#[async_trait]
impl Tool for BrowserClick {
    fn name(&self) -> &str { "browser_click" }
    fn description(&self) -> &str { "Hace click en un elemento (CSS selector) del browser." }
    fn category(&self) -> ToolCategory { ToolCategory::Web }
    fn parameters(&self) -> ToolSchema {
        let mut props = HashMap::new();
        props.insert("selector".into(), json!({"type": "string", "description": "CSS selector"}));
        ToolSchema { schema_type: "object".into(), properties: props, required: Some(vec!["selector".into()]) }
    }
    async fn execute(&self, params: Value) -> Result<Value> {
        let p = read_params(&params)?;
        let selector = str_arg!(p, "selector");
        Ok(run_agent_browser(&["click".into(), selector.to_string()], 30_000).await)
    }
}

pub struct BrowserType;

#[async_trait]
impl Tool for BrowserType {
    fn name(&self) -> &str { "browser_type" }
    fn description(&self) -> &str { "Escribe texto en un campo (CSS selector) del browser." }
    fn category(&self) -> ToolCategory { ToolCategory::Web }
    fn parameters(&self) -> ToolSchema {
        let mut props = HashMap::new();
        props.insert("selector".into(), json!({"type": "string"}));
        props.insert("text".into(), json!({"type": "string"}));
        ToolSchema {
            schema_type: "object".into(),
            properties: props,
            required: Some(vec!["selector".into(), "text".into()]),
        }
    }
    async fn execute(&self, params: Value) -> Result<Value> {
        let p = read_params(&params)?;
        let selector = str_arg!(p, "selector");
        let text = str_arg!(p, "text");
        Ok(run_agent_browser(&["type".into(), selector.to_string(), text.to_string()], 30_000).await)
    }
}

pub struct BrowserScreenshot;

#[async_trait]
impl Tool for BrowserScreenshot {
    fn name(&self) -> &str { "browser_screenshot" }
    fn description(&self) -> &str { "Captura un screenshot de la página actual (retorna la ruta del archivo)." }
    fn category(&self) -> ToolCategory { ToolCategory::Web }
    fn parameters(&self) -> ToolSchema {
        let mut props = HashMap::new();
        props.insert("selector".into(), json!({"type": "string", "description": "Opcional: recortar a un elemento"}));
        ToolSchema { schema_type: "object".into(), properties: props, required: None }
    }
    async fn execute(&self, params: Value) -> Result<Value> {
        let p = read_params(&params)?;
        let mut args = vec!["screenshot".to_string()];
        if let Some(sel) = p.get("selector").and_then(|v| v.as_str()) {
            if !sel.is_empty() {
                args.push(sel.to_string());
            }
        }
        Ok(run_agent_browser(&args, 30_000).await)
    }
}

pub struct BrowserExtract;

#[async_trait]
impl Tool for BrowserExtract {
    fn name(&self) -> &str { "browser_extract" }
    fn description(&self) -> &str { "Extrae texto de la página (o de un CSS selector) del browser." }
    fn category(&self) -> ToolCategory { ToolCategory::Web }
    fn parameters(&self) -> ToolSchema {
        let mut props = HashMap::new();
        props.insert("selector".into(), json!({"type": "string", "description": "Opcional: extraer solo este elemento"}));
        ToolSchema { schema_type: "object".into(), properties: props, required: None }
    }
    async fn execute(&self, params: Value) -> Result<Value> {
        let p = read_params(&params)?;
        // Extract via `eval` — same mechanism Hive uses for content extraction.
        let selector = p.get("selector").and_then(|v| v.as_str()).unwrap_or("");
        let script = if selector.is_empty() {
            "document.body.innerText".to_string()
        } else {
            format!(
                "(document.querySelector({sel}) ? document.querySelector({sel}).innerText : document.body.innerText)",
                sel = json!(selector)
            )
        };
        Ok(run_agent_browser(&["eval".into(), script], 30_000).await)
    }
}

pub fn create_all() -> Vec<std::sync::Arc<dyn Tool>> {
    vec![
        std::sync::Arc::new(BrowserNavigate),
        std::sync::Arc::new(BrowserClick),
        std::sync::Arc::new(BrowserType),
        std::sync::Arc::new(BrowserScreenshot),
        std::sync::Arc::new(BrowserExtract),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn browser_navigate_missing_binary_is_graceful() {
        // Point at a binary that certainly does not exist; the tool must return
        // a structured "unavailable" result rather than erroring or hanging.
        std::env::set_var("AGENT_BROWSER_BIN", "/nonexistent/agent-browser-xyz");
        let out = BrowserNavigate.execute(json!({"url": "example.com"})).await.unwrap();
        assert_eq!(out["ok"], false);
        assert_eq!(out["error"], "browser_unavailable");
        std::env::remove_var("AGENT_BROWSER_BIN");
    }
}
