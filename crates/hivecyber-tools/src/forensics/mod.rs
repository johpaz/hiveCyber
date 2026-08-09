use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;

use crate::base;
use crate::registry::{self, Tool, ToolCategory, ToolSchema};

fn read_params(params: &Value) -> Result<HashMap<String, Value>> {
    params
        .as_object()
        .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .ok_or_else(|| anyhow!("params must be an object"))
}

fn get_str(params: &HashMap<String, Value>, key: &str, default: &str) -> String {
    params
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or(default)
        .to_string()
}

pub struct Volatility;

#[async_trait]
impl Tool for Volatility {
    fn name(&self) -> &str { "volatility" }
    fn description(&self) -> &str { "Analisis forense de memoria con volatility3. Cadena de custodia: hash SHA-256 + timestamp." }
    fn category(&self) -> ToolCategory { ToolCategory::Forensics }
    fn parameters(&self) -> ToolSchema {
        let mut props = HashMap::new();
        props.insert("dump".into(), json!({"type": "string", "description": "Ruta al memory dump"}));
        props.insert("plugin".into(), json!({"type": "string", "default": "windows.info", "description": "Plugin: windows.pslist, windows.netscan, windows.malfind, windows.info"}));
        props.insert("timeout_seconds".into(), json!({"type": "integer", "default": 300}));
        ToolSchema {
            schema_type: "object".into(),
            properties: props,
            required: Some(vec!["dump".into()]),
        }
    }
    async fn execute(&self, params: Value) -> Result<Value> {
        let p = read_params(&params)?;
        let dump = p.get("dump").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("dump required"))?;
        let plugin = get_str(&p, "plugin", "windows.info");
        let timeout = p.get("timeout_seconds").and_then(|v| v.as_u64()).unwrap_or(300);

        let hash = compute_file_hash(dump).await?;
        let timestamp = chrono::Utc::now().to_rfc3339();
        let cmd = format!("vol -f {} {}", dump, plugin);

        let exec_result = base::CliExec::new(Arc::new(registry::SecurityContext::default()))
            .execute(json!({
                "command": cmd,
                "timeout_seconds": timeout,
            }))
            .await;

        let chain_note = json!({
            "custody": {
                "sha256": hash,
                "timestamp_acquired": timestamp,
                "command": cmd,
            }
        });

        match exec_result {
            Ok(mut v) => {
                if let Some(obj) = v.as_object_mut() {
                    if let Some(custody) = chain_note.get("custody") {
                        obj.insert("custody".into(), custody.clone());
                    }
                }
                Ok(v)
            }
            Err(e) => Err(anyhow!("volatility failed: {} (custody: hash={} ts={})", e, hash, timestamp))
        }
    }
}

pub struct YaraScan;

#[async_trait]
impl Tool for YaraScan {
    fn name(&self) -> &str { "yara_scan" }
    fn description(&self) -> &str { "Scan de archivos/procesos con reglas YARA." }
    fn category(&self) -> ToolCategory { ToolCategory::Forensics }
    fn parameters(&self) -> ToolSchema {
        let mut props = HashMap::new();
        props.insert("rules".into(), json!({"type": "string", "description": "Archivo de reglas YARA"}));
        props.insert("target".into(), json!({"type": "string", "description": "Archivo o directorio o PID"}));
        props.insert("timeout_seconds".into(), json!({"type": "integer", "default": 120}));
        ToolSchema {
            schema_type: "object".into(),
            properties: props,
            required: Some(vec!["rules".into(), "target".into()]),
        }
    }
    async fn execute(&self, params: Value) -> Result<Value> {
        let p = read_params(&params)?;
        let rules = p.get("rules").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("rules required"))?;
        let target = p.get("target").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("target required"))?;
        let timeout = p.get("timeout_seconds").and_then(|v| v.as_u64()).unwrap_or(120);

        let cmd = format!("yara -r {} {}", rules, target);
        base::CliExec::new(Arc::new(registry::SecurityContext::default())).execute(json!({
            "command": cmd,
            "timeout_seconds": timeout,
        })).await
    }
}

pub struct ZeekParse;

#[async_trait]
impl Tool for ZeekParse {
    fn name(&self) -> &str { "zeek_parse" }
    fn description(&self) -> &str { "Parsea logs de Zeek/Bro: conn.log, dns.log, http.log, ssl.log." }
    fn category(&self) -> ToolCategory { ToolCategory::Forensics }
    fn parameters(&self) -> ToolSchema {
        let mut props = HashMap::new();
        props.insert("log".into(), json!({"type": "string", "description": "Ruta al log Zeek"}));
        props.insert("filter".into(), json!({"type": "string", "description": "jq filter (default: .)"}));
        props.insert("timeout_seconds".into(), json!({"type": "integer", "default": 60}));
        ToolSchema {
            schema_type: "object".into(),
            properties: props,
            required: Some(vec!["log".into()]),
        }
    }
    async fn execute(&self, params: Value) -> Result<Value> {
        let p = read_params(&params)?;
        let log = p.get("log").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("log required"))?;
        let filter = get_str(&p, "filter", ".");
        let timeout = p.get("timeout_seconds").and_then(|v| v.as_u64()).unwrap_or(60);

        let cmd = format!("cat {} | jq -c '{}' | head -500", log, filter);
        base::CliExec::new(Arc::new(registry::SecurityContext::default())).execute(json!({
            "command": cmd,
            "timeout_seconds": timeout,
        })).await
    }
}

pub struct Osquery;

#[async_trait]
impl Tool for Osquery {
    fn name(&self) -> &str { "osquery" }
    fn description(&self) -> &str { "Consulta live del sistema con osqueryi (modo interactivo)." }
    fn category(&self) -> ToolCategory { ToolCategory::Forensics }
    fn parameters(&self) -> ToolSchema {
        let mut props = HashMap::new();
        props.insert("query".into(), json!({"type": "string", "description": "Query SQL: SELECT * FROM processes;"}));
        props.insert("timeout_seconds".into(), json!({"type": "integer", "default": 30}));
        ToolSchema {
            schema_type: "object".into(),
            properties: props,
            required: Some(vec!["query".into()]),
        }
    }
    async fn execute(&self, params: Value) -> Result<Value> {
        let p = read_params(&params)?;
        let query = p.get("query").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("query required"))?;
        let timeout = p.get("timeout_seconds").and_then(|v| v.as_u64()).unwrap_or(30);

        let cmd = format!("osqueryi --json \"{}\"", query.replace('"', "\\\""));
        base::CliExec::new(Arc::new(registry::SecurityContext::default())).execute(json!({
            "command": cmd,
            "timeout_seconds": timeout,
        })).await
    }
}

pub struct LogParse;

#[async_trait]
impl Tool for LogParse {
    fn name(&self) -> &str { "log_parse" }
    fn description(&self) -> &str { "Parser generico de logs con regex + jq." }
    fn category(&self) -> ToolCategory { ToolCategory::Forensics }
    fn parameters(&self) -> ToolSchema {
        let mut props = HashMap::new();
        props.insert("file".into(), json!({"type": "string"}));
        props.insert("regex".into(), json!({"type": "string", "description": "Regex (PCRE)"}));
        props.insert("fields".into(), json!({"type": "array", "items": {"type": "string"}, "description": "Grupos del regex"}));
        props.insert("limit".into(), json!({"type": "integer", "default": 500}));
        props.insert("timeout_seconds".into(), json!({"type": "integer", "default": 30}));
        ToolSchema {
            schema_type: "object".into(),
            properties: props,
            required: Some(vec!["file".into()]),
        }
    }
    async fn execute(&self, params: Value) -> Result<Value> {
        let p = read_params(&params)?;
        let file = p.get("file").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("file required"))?;
        let regex = get_str(&p, "regex", "");
        let limit = p.get("limit").and_then(|v| v.as_u64()).unwrap_or(500);
        let timeout = p.get("timeout_seconds").and_then(|v| v.as_u64()).unwrap_or(30);

        if regex.is_empty() {
            let cmd = format!("head -{} '{}'", limit, file);
            return base::CliExec::new(Arc::new(registry::SecurityContext::default())).execute(json!({
                "command": cmd,
                "timeout_seconds": timeout,
            })).await;
        }

        let cmd = format!("grep -P '{}' '{}' | head -{}", regex.replace('\'', "'\\''"), file, limit);
        base::CliExec::new(Arc::new(registry::SecurityContext::default())).execute(json!({
            "command": cmd,
            "timeout_seconds": timeout,
        })).await
    }
}

async fn compute_file_hash(path: &str) -> Result<String> {
    let bytes = tokio::fs::read(path).await?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn create_all() -> Vec<Arc<dyn Tool>> {
    vec![
        Arc::new(Volatility),
        Arc::new(YaraScan),
        Arc::new(ZeekParse),
        Arc::new(Osquery),
        Arc::new(LogParse),
    ]
}