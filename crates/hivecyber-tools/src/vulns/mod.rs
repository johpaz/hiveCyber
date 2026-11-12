use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde_json::{json, Value};
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

macro_rules! cli_wrapper {
    ($name:ident, $tool_name:expr, $description:expr, $bin:expr, $target_flag:expr, $deny:expr) => {
        pub struct $name {
            security: Arc<registry::SecurityContext>,
        }

        impl $name {
            pub fn new(security: Arc<registry::SecurityContext>) -> Self {
                $name { security }
            }
        }

        #[async_trait]
        impl Tool for $name {
            fn name(&self) -> &str { $tool_name }
            fn description(&self) -> &str { $description }
            fn category(&self) -> ToolCategory { ToolCategory::Vulns }
            fn parameters(&self) -> ToolSchema {
                let mut props = HashMap::new();
                props.insert("target".into(), json!({"type": "string"}));
                props.insert("flags".into(), json!({"type": "string"}));
                props.insert("timeout_seconds".into(), json!({"type": "integer", "default": 180}));
                ToolSchema {
                    schema_type: "object".into(),
                    properties: props,
                    required: Some(vec!["target".into()]),
                }
            }
            async fn execute(&self, params: Value) -> Result<Value> {
                let p = read_params(&params)?;
                let target = p.get("target").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("target required"))?;
                let flags = get_str(&p, "flags", "");
                let timeout = p.get("timeout_seconds").and_then(|v| v.as_u64()).unwrap_or(180);

                if let Err(e) = self.security.validate_target(target) {
                    return Ok(json!({
                        "error": "security_policy",
                        "message": e,
                        "target": target,
                    }));
                }

                // Sin interpolación cruda: flags validados + valores citados.
                let flag_toks = match base::safe_flags(&flags)
                    .and_then(|f| base::deny_flags($tool_name, &f, $deny).map(|_| f))
                {
                    Ok(f) => f,
                    Err(e) => return Ok(json!({"error": "invalid_params", "message": e.to_string()})),
                };
                let target_val = match base::safe_value("target", target) {
                    Ok(t) => t,
                    Err(e) => return Ok(json!({"error": "invalid_params", "message": e.to_string()})),
                };
                let mut argv = flag_toks;
                argv.push($target_flag.to_string());
                argv.push(target_val);
                let cmd = base::quoted_cmd($bin, &argv);

                base::CliExec::new(self.security.clone()).execute(json!({
                    "command": cmd,
                    "timeout_seconds": timeout,
                })).await
            }
        }
    };
}

// Flags que ejecutan código, escriben/leen archivos arbitrarios o abren shells.
const NUCLEI_DENY: &[&str] = &["-code", "-config", "-headless", "-system-resolvers"];
const NIKTO_DENY: &[&str] = &["-config"];
const SQLMAP_DENY: &[&str] = &[
    "--os-shell", "--os-cmd", "--os-pwn", "--os-smbrelay", "--os-bof", "--priv-esc",
    "--reg-read", "--reg-add", "--reg-del", "--file-read", "--file-write", "--file-dest",
    "--sql-shell", "--sql-file", "--eval", "--shell", "--udf-inject", "--shared-lib",
];

cli_wrapper!(Nuclei, "nuclei", "Escaneo de vulnerabilidades web con nuclei templates.", "nuclei", "-u", NUCLEI_DENY);
cli_wrapper!(Nikto, "nikto", "Scanner web de vulnerabilidades conocido.", "nikto", "-h", NIKTO_DENY);
cli_wrapper!(Sqlmap, "sqlmap", "Deteccion y explotacion de SQL injection.", "sqlmap", "-u", SQLMAP_DENY);

pub struct Searchsploit {
    security: Arc<registry::SecurityContext>,
}

impl Searchsploit {
    pub fn new(security: Arc<registry::SecurityContext>) -> Self {
        Searchsploit { security }
    }
}

#[async_trait]
impl Tool for Searchsploit {
    fn name(&self) -> &str { "searchsploit" }
    fn description(&self) -> &str { "Busca exploits conocidos en Exploit-DB." }
    fn category(&self) -> ToolCategory { ToolCategory::Vulns }
    fn parameters(&self) -> ToolSchema {
        let mut props = HashMap::new();
        props.insert("query".into(), json!({"type": "string"}));
        props.insert("timeout_seconds".into(), json!({"type": "integer", "default": 60}));
        ToolSchema {
            schema_type: "object".into(),
            properties: props,
            required: Some(vec!["query".into()]),
        }
    }
    async fn execute(&self, params: Value) -> Result<Value> {
        let p = read_params(&params)?;
        let query = p.get("query").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("query required"))?;
        let timeout = p.get("timeout_seconds").and_then(|v| v.as_u64()).unwrap_or(60);
        // Solo palabras sueltas, citadas; ninguna puede ser un flag.
        let words: Result<Vec<String>> = query.split_whitespace().map(|w| base::safe_value("query", w)).collect();
        let words = match words {
            Ok(w) if !w.is_empty() => w,
            Ok(_) => return Ok(json!({"error": "invalid_params", "message": "query vacío"})),
            Err(e) => return Ok(json!({"error": "invalid_params", "message": e.to_string()})),
        };
        let cmd = base::quoted_cmd("searchsploit", &words);
        base::CliExec::new(self.security.clone()).execute(json!({
            "command": cmd,
            "timeout_seconds": timeout,
        })).await
    }
}

pub struct Semgrep {
    security: Arc<registry::SecurityContext>,
}

impl Semgrep {
    pub fn new(security: Arc<registry::SecurityContext>) -> Self {
        Semgrep { security }
    }
}

#[async_trait]
impl Tool for Semgrep {
    fn name(&self) -> &str { "semgrep" }
    fn description(&self) -> &str { "SAST: scan de codigo fuente con semgrep." }
    fn category(&self) -> ToolCategory { ToolCategory::Vulns }
    fn parameters(&self) -> ToolSchema {
        let mut props = HashMap::new();
        props.insert("path".into(), json!({"type": "string"}));
        props.insert("config".into(), json!({"type": "string", "default": "auto"}));
        props.insert("timeout_seconds".into(), json!({"type": "integer", "default": 180}));
        ToolSchema {
            schema_type: "object".into(),
            properties: props,
            required: Some(vec!["path".into()]),
        }
    }
    async fn execute(&self, params: Value) -> Result<Value> {
        let p = read_params(&params)?;
        let path = p.get("path").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("path required"))?;
        let config = get_str(&p, "config", "auto");
        let timeout = p.get("timeout_seconds").and_then(|v| v.as_u64()).unwrap_or(180);
        let (config, path) = match (base::safe_value("config", &config), base::safe_value("path", path)) {
            (Ok(c), Ok(p)) => (c, p),
            (Err(e), _) | (_, Err(e)) => return Ok(json!({"error": "invalid_params", "message": e.to_string()})),
        };
        let cmd = base::quoted_cmd("semgrep", &["scan".into(), "--config".into(), config, path]);
        base::CliExec::new(self.security.clone()).execute(json!({
            "command": cmd,
            "timeout_seconds": timeout,
        })).await
    }
}

pub struct Trivy {
    security: Arc<registry::SecurityContext>,
}

impl Trivy {
    pub fn new(security: Arc<registry::SecurityContext>) -> Self {
        Trivy { security }
    }
}

#[async_trait]
impl Tool for Trivy {
    fn name(&self) -> &str { "trivy" }
    fn description(&self) -> &str { "Scan de vulnerabilidades en contenedores/FS/SBOM." }
    fn category(&self) -> ToolCategory { ToolCategory::Vulns }
    fn parameters(&self) -> ToolSchema {
        let mut props = HashMap::new();
        props.insert("target".into(), json!({"type": "string", "description": "Path o image:tag"}));
        props.insert("mode".into(), json!({"type": "string", "default": "filesystem", "enum": ["filesystem", "image"]}));
        props.insert("timeout_seconds".into(), json!({"type": "integer", "default": 180}));
        ToolSchema {
            schema_type: "object".into(),
            properties: props,
            required: Some(vec!["target".into()]),
        }
    }
    async fn execute(&self, params: Value) -> Result<Value> {
        let p = read_params(&params)?;
        let target = p.get("target").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("target required"))?;
        let mode = get_str(&p, "mode", "filesystem");
        let timeout = p.get("timeout_seconds").and_then(|v| v.as_u64()).unwrap_or(180);

        let subcmd = match mode.as_str() {
            "image" => "image",
            _ => "filesystem",
        };
        let target = match base::safe_value("target", target) {
            Ok(t) => t,
            Err(e) => return Ok(json!({"error": "invalid_params", "message": e.to_string()})),
        };
        let cmd = base::quoted_cmd("trivy", &[subcmd.to_string(), target]);

        base::CliExec::new(self.security.clone()).execute(json!({
            "command": cmd,
            "timeout_seconds": timeout,
        })).await
    }
}

pub fn create_all(security: Arc<registry::SecurityContext>) -> Vec<Arc<dyn Tool>> {
    vec![
        Arc::new(Nuclei::new(security.clone())),
        Arc::new(Nikto::new(security.clone())),
        Arc::new(Sqlmap::new(security.clone())),
        Arc::new(Searchsploit::new(security.clone())),
        Arc::new(Semgrep::new(security.clone())),
        Arc::new(Trivy::new(security.clone())),
    ]
}