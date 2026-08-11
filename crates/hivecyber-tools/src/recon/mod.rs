use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

use crate::base;

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

pub struct Nmap {
    security: Arc<crate::registry::SecurityContext>,
}

impl Nmap {
    pub fn new(security: Arc<crate::registry::SecurityContext>) -> Self {
        Nmap { security }
    }
}

#[async_trait]
impl crate::registry::Tool for Nmap {
    fn name(&self) -> &str { "nmap" }
    fn description(&self) -> &str { "Escaneo de red con nmap. Uso autorizado solamente." }
    fn category(&self) -> crate::registry::ToolCategory { crate::registry::ToolCategory::Recon }
    fn parameters(&self) -> crate::registry::ToolSchema {
        let mut props = HashMap::new();
        props.insert("target".into(), json!({"type": "string", "description": "IP/hostname o CIDR target"}));
        props.insert("flags".into(), json!({"type": "string", "default": "-sV -T4", "description": "Flags nmap: -sV -sC -T4 -p- ..."}));
        props.insert("timeout_seconds".into(), json!({"type": "integer", "default": 120}));
        crate::registry::ToolSchema {
            schema_type: "object".into(),
            properties: props,
            required: Some(vec!["target".into()]),
        }
    }
    async fn execute(&self, params: Value) -> Result<Value> {
        let p = read_params(&params)?;
        let target = p.get("target").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("target required"))?;
        let flags = get_str(&p, "flags", "-sV -T4");
        let timeout = p.get("timeout_seconds").and_then(|v| v.as_u64()).unwrap_or(120);

        if let Err(e) = self.security.validate_target(target) {
            tracing::warn!("nmap target rejected: {}", e);
            return Ok(json!({
                "error": "security_policy",
                "message": e,
                "target": target,
            }));
        }

        base::CliExec::new(self.security.clone()).execute(json!({
            "command": format!("nmap {} {}", flags, target),
            "timeout_seconds": timeout,
        })).await
    }
}

pub struct Dig;

#[async_trait]
impl crate::registry::Tool for Dig {
    fn name(&self) -> &str { "dig" }
    fn description(&self) -> &str { "Consulta DNS con dig." }
    fn category(&self) -> crate::registry::ToolCategory { crate::registry::ToolCategory::Recon }
    fn parameters(&self) -> crate::registry::ToolSchema {
        let mut props = HashMap::new();
        props.insert("domain".into(), json!({"type": "string"}));
        props.insert("record_type".into(), json!({"type": "string", "default": "A"}));
        props.insert("server".into(), json!({"type": "string"}));
        crate::registry::ToolSchema {
            schema_type: "object".into(),
            properties: props,
            required: Some(vec!["domain".into()]),
        }
    }
    async fn execute(&self, params: Value) -> Result<Value> {
        let p = read_params(&params)?;
        let domain = p.get("domain").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("domain required"))?;
        let record_type = get_str(&p, "record_type", "A");
        let server = p.get("server").and_then(|v| v.as_str()).unwrap_or("");

        let cmd = if server.is_empty() {
            format!("dig {} {}", domain, record_type)
        } else {
            format!("dig @{} {} {}", server, domain, record_type)
        };

        base::CliExec::new(Arc::new(crate::registry::SecurityContext::default())).execute(json!({
            "command": cmd,
            "timeout_seconds": 30,
        })).await
    }
}

pub struct Whois;

#[async_trait]
impl crate::registry::Tool for Whois {
    fn name(&self) -> &str { "whois" }
    fn description(&self) -> &str { "Consulta WHOIS de un dominio o IP." }
    fn category(&self) -> crate::registry::ToolCategory { crate::registry::ToolCategory::Recon }
    fn parameters(&self) -> crate::registry::ToolSchema {
        let mut props = HashMap::new();
        props.insert("query".into(), json!({"type": "string", "description": "Dominio o IP"}));
        crate::registry::ToolSchema {
            schema_type: "object".into(),
            properties: props,
            required: Some(vec!["query".into()]),
        }
    }
    async fn execute(&self, params: Value) -> Result<Value> {
        let p = read_params(&params)?;
        let query = p.get("query").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("query required"))?;

        base::CliExec::new(Arc::new(crate::registry::SecurityContext::default())).execute(json!({
            "command": format!("whois {}", query),
            "timeout_seconds": 30,
        })).await
    }
}

pub struct TheHarvester;

#[async_trait]
impl crate::registry::Tool for TheHarvester {
    fn name(&self) -> &str { "theharvester" }
    fn description(&self) -> &str { "OSINT con theHarvester: emails, subdominios, hosts." }
    fn category(&self) -> crate::registry::ToolCategory { crate::registry::ToolCategory::Recon }
    fn parameters(&self) -> crate::registry::ToolSchema {
        let mut props = HashMap::new();
        props.insert("domain".into(), json!({"type": "string"}));
        props.insert("source".into(), json!({"type": "string", "default": "all"}));
        crate::registry::ToolSchema {
            schema_type: "object".into(),
            properties: props,
            required: Some(vec!["domain".into()]),
        }
    }
    async fn execute(&self, params: Value) -> Result<Value> {
        let p = read_params(&params)?;
        let domain = p.get("domain").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("domain required"))?;
        let source = get_str(&p, "source", "all");

        let cmd = if std::path::Path::new("/usr/bin/theHarvester").exists() {
            format!("theHarvester -d {} -b {}", domain, source)
        } else {
            format!("theharvester -d {} -b {}", domain, source)
        };

        base::CliExec::new(Arc::new(crate::registry::SecurityContext::default())).execute(json!({
            "command": cmd,
            "timeout_seconds": 120,
        })).await
    }
}
pub struct Shodan;

#[async_trait]
impl crate::registry::Tool for Shodan {
    fn name(&self) -> &str { "shodan" }
    fn description(&self) -> &str {
        "Consulta pasiva a la API de Shodan sobre una IP (puertos, servicios, org, hostnames). Requiere SHODAN_API_KEY."
    }
    fn category(&self) -> crate::registry::ToolCategory { crate::registry::ToolCategory::Recon }
    fn parameters(&self) -> crate::registry::ToolSchema {
        let mut props = HashMap::new();
        props.insert("target".into(), json!({"type": "string", "description": "IP a consultar en Shodan"}));
        crate::registry::ToolSchema {
            schema_type: "object".into(),
            properties: props,
            required: Some(vec!["target".into()]),
        }
    }
    async fn execute(&self, params: Value) -> Result<Value> {
        let p = read_params(&params)?;
        let target = p.get("target").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("target required"))?;

        let api_key = match std::env::var("SHODAN_API_KEY") {
            Ok(k) if !k.is_empty() => k,
            _ => {
                return Ok(json!({
                    "error": "missing_api_key",
                    "message": "set SHODAN_API_KEY to use the shodan tool",
                }));
            }
        };

        // Passive lookup against Shodan's own DB — does not touch the target,
        // so (like whois/theharvester) it is not gated by the engagement policy.
        let url = format!("https://api.shodan.io/shodan/host/{}?key={}", target, api_key);
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(25))
            .build()?;
        let resp = client.get(&url).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Ok(json!({
                "error": "shodan_error",
                "status": status.as_u16(),
                "message": body.chars().take(300).collect::<String>(),
                "target": target,
            }));
        }
        let data: Value = resp.json().await.unwrap_or(Value::Null);

        // Surface the high-signal fields; keep the full payload under `raw`.
        let ports = data.get("ports").cloned().unwrap_or(Value::Null);
        let hostnames = data.get("hostnames").cloned().unwrap_or(Value::Null);
        let org = data.get("org").cloned().unwrap_or(Value::Null);
        let os = data.get("os").cloned().unwrap_or(Value::Null);
        Ok(json!({
            "target": target,
            "ports": ports,
            "hostnames": hostnames,
            "org": org,
            "os": os,
            "raw": data,
        }))
    }
}

pub struct ReconNg;

#[async_trait]
impl crate::registry::Tool for ReconNg {
    fn name(&self) -> &str { "recon_ng" }
    fn description(&self) -> &str {
        "Ejecuta un modulo de recon-ng de forma no interactiva (OSINT). Ej: module=recon/domains-hosts/hackertarget, source=example.com."
    }
    fn category(&self) -> crate::registry::ToolCategory { crate::registry::ToolCategory::Recon }
    fn parameters(&self) -> crate::registry::ToolSchema {
        let mut props = HashMap::new();
        props.insert("module".into(), json!({"type": "string", "description": "Modulo recon-ng, ej: recon/domains-hosts/hackertarget"}));
        props.insert("source".into(), json!({"type": "string", "description": "Valor de la opcion SOURCE (dominio/host)"}));
        props.insert("options".into(), json!({"type": "string", "description": "Opciones extra 'KEY=val' separadas por ';'", "default": ""}));
        props.insert("timeout_seconds".into(), json!({"type": "integer", "default": 180}));
        crate::registry::ToolSchema {
            schema_type: "object".into(),
            properties: props,
            required: Some(vec!["module".into(), "source".into()]),
        }
    }
    async fn execute(&self, params: Value) -> Result<Value> {
        let p = read_params(&params)?;
        let module = p.get("module").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("module required"))?;
        let source = p.get("source").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("source required"))?;
        let options = get_str(&p, "options", "");
        let timeout = p.get("timeout_seconds").and_then(|v| v.as_u64()).unwrap_or(180);

        // recon-ng is interactive; drive it non-interactively with -m/-o/-x.
        let mut opts = format!("SOURCE={}", source);
        for extra in options.split(';').map(|s| s.trim()).filter(|s| !s.is_empty()) {
            opts.push(' ');
            opts.push_str(extra);
        }
        let cmd = format!("recon-ng -m {} -o {} -x", module, opts);

        base::CliExec::new(Arc::new(crate::registry::SecurityContext::default())).execute(json!({
            "command": cmd,
            "timeout_seconds": timeout,
        })).await
    }
}
