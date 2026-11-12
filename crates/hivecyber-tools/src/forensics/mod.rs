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

        let (dump, plugin) = match (base::safe_value("dump", dump), base::safe_ident("plugin", &plugin)) {
            (Ok(d), Ok(pl)) => (d, pl),
            (Err(e), _) | (_, Err(e)) => return Ok(json!({"error": "invalid_params", "message": e.to_string()})),
        };
        let hash = compute_file_hash(&dump).await?;
        let timestamp = chrono::Utc::now().to_rfc3339();
        let cmd = base::quoted_cmd("vol", &["-f".into(), dump, plugin]);

        let exec_result = base::run_fixed(&registry::SecurityContext::default(), &cmd, timeout).await;

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

        let (rules, target) = match (base::safe_value("rules", rules), base::safe_value("target", target)) {
            (Ok(r), Ok(t)) => (r, t),
            (Err(e), _) | (_, Err(e)) => return Ok(json!({"error": "invalid_params", "message": e.to_string()})),
        };
        let cmd = base::quoted_cmd("yara", &["-r".into(), rules, target]);
        base::run_fixed(&registry::SecurityContext::default(), &cmd, timeout).await
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

        let log = match base::safe_value("log", log) {
            Ok(l) => l,
            Err(e) => return Ok(json!({"error": "invalid_params", "message": e.to_string()})),
        };
        if let Err(e) = check_jq_filter(&filter) {
            return Ok(json!({"error": "invalid_params", "message": e.to_string()}));
        }
        let cmd = format!("{} | head -500", base::quoted_cmd("jq", &["-c".into(), filter, log]));
        base::run_fixed(&registry::SecurityContext::default(), &cmd, timeout).await
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

        // Sin comandos meta de osqueryi (`.…`) ni flags: solo una consulta SQL.
        let query = match base::safe_value("query", query) {
            Ok(q) if !q.starts_with('.') => q,
            Ok(_) => return Ok(json!({"error": "invalid_params", "message": "query no puede empezar por '.'"})),
            Err(e) => return Ok(json!({"error": "invalid_params", "message": e.to_string()})),
        };
        let cmd = base::quoted_cmd("osqueryi", &["--json".into(), query]);
        base::run_fixed(&registry::SecurityContext::default(), &cmd, timeout).await
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

        let file = match base::safe_value("file", file) {
            Ok(f) => f,
            Err(e) => return Ok(json!({"error": "invalid_params", "message": e.to_string()})),
        };
        let limit = limit.clamp(1, 5000).to_string();
        let sec = registry::SecurityContext::default();
        if regex.is_empty() {
            let cmd = base::quoted_cmd("head", &["-n".into(), limit, file]);
            return base::run_fixed(&sec, &cmd, timeout).await;
        }
        if regex.chars().any(|c| c.is_control()) {
            return Ok(json!({"error": "invalid_params", "message": "regex con caracteres de control"}));
        }
        // `-e` fija el patrón (aunque empiece por '-') y `--` el fin de opciones.
        let grep = base::quoted_cmd("grep", &["-P".into(), "-e".into(), regex, "--".into(), file]);
        let cmd = format!("{} | head -n {}", grep, limit);
        base::run_fixed(&sec, &cmd, timeout).await
    }
}

/// Un filtro jq es un programa: puede leer el entorno (claves API) o archivos.
/// Se rechazan esos accesos; el filtro tampoco puede empezar por `-` (flag).
fn check_jq_filter(f: &str) -> Result<()> {
    let t = f.trim();
    if t.is_empty() || t.starts_with('-') {
        return Err(anyhow!("filtro jq inválido"));
    }
    let l = t.to_lowercase();
    for bad in ["env", "input", "import", "include", "$__prog", "getpath(\"/"] {
        if l.contains(bad) {
            return Err(anyhow!("filtro jq no permitido: contiene '{}'", bad));
        }
    }
    Ok(())
}

async fn compute_file_hash(path: &str) -> Result<String> {
    // Por bloques: un volcado de memoria puede pesar varios GB.
    use tokio::io::AsyncReadExt;
    let mut f = tokio::fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
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
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jq_filter_blocks_env_and_flags() {
        assert!(check_jq_filter(".").is_ok());
        assert!(check_jq_filter(".[] | select(.id_orig_h == \"1.2.3.4\")").is_ok());
        assert!(check_jq_filter("env.ANTHROPIC_API_KEY").is_err());
        assert!(check_jq_filter("$ENV.PATH").is_err());
        assert!(check_jq_filter("input").is_err());
        assert!(check_jq_filter("-n").is_err());
    }

    #[tokio::test]
    async fn log_parse_treats_regex_and_path_as_data() {
        let dir = std::env::temp_dir().join(format!("hc-log-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("a.log");
        std::fs::write(&f, "ok line\nERROR boom\n-e trick\n").unwrap();
        let t = LogParse;
        // regex que parece inyección: se busca literal, no se ejecuta
        let r = t.execute(json!({"file": f.to_str().unwrap(), "regex": "x'; touch /tmp/hc_pwned_flag; echo '"})).await.unwrap();
        assert_eq!(r["stdout"].as_str().unwrap().trim(), "", "{r}"); // sin coincidencias
        assert!(!std::path::Path::new("/tmp/hc_pwned_flag").exists());
        // patrón que empieza por '-' se trata como patrón
        let r = t.execute(json!({"file": f.to_str().unwrap(), "regex": "-e trick"})).await.unwrap();
        assert!(r["stdout"].as_str().unwrap().contains("-e trick"), "{r}");
        // ruta que empieza por '-' se rechaza
        let r = t.execute(json!({"file": "-rf"})).await.unwrap();
        assert_eq!(r["error"], "invalid_params");
    }

    #[tokio::test]
    async fn hash_streams_and_matches_known_digest() {
        let dir = std::env::temp_dir().join(format!("hc-hash-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("x.bin");
        std::fs::write(&f, b"abc").unwrap();
        assert_eq!(
            compute_file_hash(f.to_str().unwrap()).await.unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
