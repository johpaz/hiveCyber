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

/// Reject flag strings carrying shell metacharacters. The command is run via
/// `bash -c`, so a stray `;`/`|`/`$(...)` in model-supplied flags would be
/// command injection. The legacy wrappers (`nmap`, `nuclei`) concatenate flags
/// unchecked; the modern recon/web tools below go through this gate.
fn safe_flags(flags: &str) -> Result<()> {
    const BAD: &[char] = &[';', '|', '&', '`', '$', '>', '<', '(', ')', '\n', '\r', '{', '}', '\\', '\''];
    if let Some(c) = flags.chars().find(|c| BAD.contains(c)) {
        return Err(anyhow!("flag con metacaracter de shell no permitido: '{}'", c));
    }
    Ok(())
}

/// A modern CLI recon/web tool: validates `target` against the engagement
/// scope, rejects unsafe flags, and runs `<prefix> <target> <flags>` through the
/// sandboxed `CliExec`. `$cat` is the `ToolCategory` (Recon for asset discovery,
/// Web for content discovery).
macro_rules! cli_scan {
    ($name:ident, $tool:expr, $desc:expr, $cat:ident, $prefix:expr, $target_desc:expr, $timeout:expr) => {
        pub struct $name {
            security: Arc<crate::registry::SecurityContext>,
        }
        impl $name {
            pub fn new(security: Arc<crate::registry::SecurityContext>) -> Self {
                $name { security }
            }
        }
        #[async_trait]
        impl crate::registry::Tool for $name {
            fn name(&self) -> &str { $tool }
            fn description(&self) -> &str { $desc }
            fn category(&self) -> crate::registry::ToolCategory { crate::registry::ToolCategory::$cat }
            fn parameters(&self) -> crate::registry::ToolSchema {
                let mut props = HashMap::new();
                props.insert("target".into(), json!({"type": "string", "description": $target_desc}));
                props.insert("flags".into(), json!({"type": "string", "default": "", "description": "Flags extra de la herramienta (sin metacaracteres de shell)."}));
                props.insert("timeout_seconds".into(), json!({"type": "integer", "default": $timeout}));
                crate::registry::ToolSchema {
                    schema_type: "object".into(),
                    properties: props,
                    required: Some(vec!["target".into()]),
                }
            }
            async fn execute(&self, params: Value) -> Result<Value> {
                let p = read_params(&params)?;
                let target = p.get("target").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("target required"))?;
                let flags = get_str(&p, "flags", "");
                let timeout = p.get("timeout_seconds").and_then(|v| v.as_u64()).unwrap_or($timeout);
                if let Err(e) = safe_flags(&flags) {
                    return Ok(json!({"error": "bad_flags", "message": e.to_string()}));
                }
                if let Err(e) = self.security.validate_target(target) {
                    return Ok(json!({"error": "security_policy", "message": e, "target": target}));
                }
                let cmd = if flags.is_empty() {
                    format!("{} {}", $prefix, target)
                } else {
                    format!("{} {} {}", $prefix, target, flags)
                };
                base::CliExec::new(self.security.clone()).execute(json!({
                    "command": cmd,
                    "timeout_seconds": timeout,
                })).await
            }
        }
    };
}

// --- Descubrimiento de activos y superficie web (recon_operator) -----------
cli_scan!(Subfinder, "subfinder", "Enumeracion pasiva de subdominios (ProjectDiscovery). target = dominio raiz.", Recon, "subfinder -silent -d", "Dominio raiz, ej: example.com", 120);
cli_scan!(Dnsx, "dnsx", "Resolucion DNS masiva y validacion de hosts (ProjectDiscovery). target = dominio o host.", Recon, "dnsx -silent -d", "Dominio o host a resolver", 120);
cli_scan!(Httpx, "httpx", "Probing HTTP: status, titulo, tech, redirecciones (ProjectDiscovery). target = URL o host.", Recon, "httpx -silent -u", "URL o host, ej: https://example.com", 120);
cli_scan!(Katana, "katana", "Crawling y extraccion de endpoints (ProjectDiscovery). target = URL semilla.", Recon, "katana -silent -u", "URL semilla, ej: https://example.com", 180);
cli_scan!(Gau, "gau", "URLs historicas de un dominio (wayback, commoncrawl, otx). target = dominio.", Recon, "gau", "Dominio, ej: example.com", 120);

// --- Descubrimiento de contenido y parametros (web_pentester) --------------
cli_scan!(Feroxbuster, "feroxbuster", "Descubrimiento de contenido recursivo sobre una URL base. Requiere --unsafe y scope.", Web, "feroxbuster --silent -u", "URL base, ej: https://example.com", 300);
cli_scan!(Arjun, "arjun", "Descubrimiento de parametros HTTP ocultos sobre un endpoint. Requiere --unsafe y scope.", Web, "arjun -u", "URL del endpoint, ej: https://example.com/api/item", 180);

/// `ffuf` needs a `FUZZ` keyword in the URL and a wordlist, so it cannot use the
/// `cli_scan!` shape. The scope check runs on the URL (with `FUZZ` stripped).
pub struct Ffuf {
    security: Arc<crate::registry::SecurityContext>,
}
impl Ffuf {
    pub fn new(security: Arc<crate::registry::SecurityContext>) -> Self {
        Ffuf { security }
    }
}
#[async_trait]
impl crate::registry::Tool for Ffuf {
    fn name(&self) -> &str { "ffuf" }
    fn description(&self) -> &str {
        "Fuzzing de rutas/parametros/vhosts. La URL debe incluir la palabra FUZZ donde iterar. Requiere --unsafe y scope."
    }
    fn category(&self) -> crate::registry::ToolCategory { crate::registry::ToolCategory::Web }
    fn parameters(&self) -> crate::registry::ToolSchema {
        let mut props = HashMap::new();
        props.insert("url".into(), json!({"type": "string", "description": "URL con FUZZ, ej: https://example.com/FUZZ"}));
        props.insert("wordlist".into(), json!({"type": "string", "description": "Ruta a la wordlist en el workspace"}));
        props.insert("flags".into(), json!({"type": "string", "default": "-mc 200,204,301,302,307,401,403", "description": "Flags extra de ffuf (sin metacaracteres)."}));
        props.insert("timeout_seconds".into(), json!({"type": "integer", "default": 300}));
        crate::registry::ToolSchema {
            schema_type: "object".into(),
            properties: props,
            required: Some(vec!["url".into(), "wordlist".into()]),
        }
    }
    async fn execute(&self, params: Value) -> Result<Value> {
        let p = read_params(&params)?;
        let url = p.get("url").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("url required"))?;
        let wordlist = p.get("wordlist").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("wordlist required"))?;
        let flags = get_str(&p, "flags", "-mc 200,204,301,302,307,401,403");
        let timeout = p.get("timeout_seconds").and_then(|v| v.as_u64()).unwrap_or(300);

        if !url.contains("FUZZ") {
            return Ok(json!({"error": "bad_url", "message": "la URL debe contener la palabra FUZZ"}));
        }
        if let Err(e) = safe_flags(&flags).and_then(|_| safe_flags(wordlist)) {
            return Ok(json!({"error": "bad_flags", "message": e.to_string()}));
        }
        // Validate the host behind the URL (strip the FUZZ placeholder first so
        // it is not mistaken for a path/host token).
        let scope_url = url.replace("FUZZ", "");
        if let Err(e) = self.security.validate_target(&scope_url) {
            return Ok(json!({"error": "security_policy", "message": e, "target": url}));
        }
        let cmd = format!("ffuf -u {} -w {} {}", url, wordlist, flags);
        base::CliExec::new(self.security.clone()).execute(json!({
            "command": cmd,
            "timeout_seconds": timeout,
        })).await
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

#[cfg(test)]
mod web_recon_tests {
    use super::*;
    use crate::registry::{SecurityContext, Tool};

    fn scoped() -> Arc<SecurityContext> {
        let mut policy = crate::engagement::EngagementPolicy::from_allowlist_hosts(&["example.com".into()]);
        policy.program = "test".into();
        Arc::new(SecurityContext {
            unsafe_mode: true,
            allow_cli_exec: true,
            allowlist_hosts: vec!["example.com".into()],
            engagement_policy: Some(Arc::new(policy)),
            ..Default::default()
        })
    }

    #[tokio::test]
    async fn out_of_scope_target_is_rejected_before_executing() {
        let t = Subfinder::new(scoped());
        let out = t.execute(json!({"target": "evil.test"})).await.unwrap();
        assert_eq!(out["error"], "security_policy", "{out}");
    }

    #[tokio::test]
    async fn shell_metacharacters_in_flags_are_refused() {
        let t = Httpx::new(scoped());
        let out = t.execute(json!({"target": "example.com", "flags": "-sc; cat /etc/passwd"})).await.unwrap();
        assert_eq!(out["error"], "bad_flags", "{out}");
        // Backticks / command substitution too.
        let out = t.execute(json!({"target": "example.com", "flags": "-x `id`"})).await.unwrap();
        assert_eq!(out["error"], "bad_flags");
    }

    #[tokio::test]
    async fn ffuf_requires_fuzz_keyword_and_validates_host() {
        let t = Ffuf::new(scoped());
        let no_fuzz = t.execute(json!({"url": "https://example.com/", "wordlist": "w.txt"})).await.unwrap();
        assert_eq!(no_fuzz["error"], "bad_url");
        let off_scope = t.execute(json!({"url": "https://evil.test/FUZZ", "wordlist": "w.txt"})).await.unwrap();
        assert_eq!(off_scope["error"], "security_policy");
    }

    #[test]
    fn categories_follow_the_discovery_split() {
        let sec = scoped();
        assert_eq!(Subfinder::new(sec.clone()).category(), crate::registry::ToolCategory::Recon);
        assert_eq!(Httpx::new(sec.clone()).category(), crate::registry::ToolCategory::Recon);
        assert_eq!(Ffuf::new(sec.clone()).category(), crate::registry::ToolCategory::Web);
        assert_eq!(Feroxbuster::new(sec.clone()).category(), crate::registry::ToolCategory::Web);
        assert_eq!(Arjun::new(sec).category(), crate::registry::ToolCategory::Web);
    }
}
