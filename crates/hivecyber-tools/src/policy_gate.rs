//! Gate único de la `EngagementPolicy` sobre llamadas a tools.
//!
//! Antes de ejecutar CUALQUIER tool, `SecurityContext::gate_tool_call`:
//!   1. rechaza actividades prohibidas por el programa (`prohibited`),
//!   2. exige aprobación humana para las categorías de `require_human_approval`,
//!   3. para tools HTTP (`web_fetch`, `web_head`, `browser_navigate`) valida
//!      host + path + método contra la `TargetRule`, la ventana horaria y el
//!      rate limit del programa.
//!
//! Sin política de engagement (modo allowlist legacy) no hace nada: ese modo lo
//! gobierna `validate_target`/`unsafe_mode`.

use crate::engagement::{ApprovalCategory, EngagementPolicy, ProhibitedActivity};
use crate::registry::SecurityContext;

/// Binarios que cuentan como escaneo automatizado (también vía `cli_exec`).
const SCANNERS: &[&str] = &[
    "nmap", "masscan", "nuclei", "nikto", "sqlmap", "ffuf", "feroxbuster", "gobuster", "dirb",
    "wfuzz", "katana", "zap-cli", "wpscan", "arjun", "httpx", "dnsx",
];

/// Binarios de explotación / ataque a credenciales.
const EXPLOIT_BINS: &[&str] = &["msfconsole", "msfvenom", "hydra", "crackmapexec", "mimikatz"];
const CRED_BINS: &[&str] = &["hydra", "medusa", "crackmapexec", "patator"];

#[derive(Debug, Default, PartialEq)]
pub struct Activities {
    pub prohibited: Vec<ProhibitedActivity>,
    pub approval: Vec<ApprovalCategory>,
}

impl Activities {
    fn push_scan(&mut self) {
        self.prohibited.push(ProhibitedActivity::AutomatedScanning);
    }
}

/// Clasifica una llamada a tool en actividades de política.
pub fn classify(tool_name: &str, args: &serde_json::Value) -> Activities {
    let mut a = Activities::default();
    match tool_name {
        "nmap" | "nuclei" | "nikto" | "httpx" | "katana" | "ffuf" => a.push_scan(),
        // Verificar un secreto = probar la credencial contra su proveedor.
        "trufflehog" => {
            if args.get("verify").and_then(|v| v.as_bool()).unwrap_or(false) {
                a.approval.push(ApprovalCategory::CredentialUse);
            }
        }
        "sqlmap" => {
            a.push_scan();
            a.approval.push(ApprovalCategory::Exploit);
        }
        "metasploit_rpc" | "mimikatz" => a.approval.push(ApprovalCategory::Exploit),
        "hydra" | "crackmapexec" => {
            a.prohibited.push(ProhibitedActivity::CredentialStuffing);
            a.approval.push(ApprovalCategory::Exploit);
            a.approval.push(ApprovalCategory::CredentialUse);
        }
        "cli_exec" => {
            if let Some(cmd) = args.get("command").and_then(|v| v.as_str()) {
                for bin in command_binaries(cmd) {
                    if SCANNERS.contains(&bin.as_str()) && !a.prohibited.contains(&ProhibitedActivity::AutomatedScanning) {
                        a.push_scan();
                    }
                    if CRED_BINS.contains(&bin.as_str()) && !a.prohibited.contains(&ProhibitedActivity::CredentialStuffing) {
                        a.prohibited.push(ProhibitedActivity::CredentialStuffing);
                        a.approval.push(ApprovalCategory::CredentialUse);
                    }
                    if (EXPLOIT_BINS.contains(&bin.as_str()) || bin == "sqlmap")
                        && !a.approval.contains(&ApprovalCategory::Exploit)
                    {
                        a.approval.push(ApprovalCategory::Exploit);
                    }
                }
            }
        }
        _ => {}
    }
    a
}

/// Primer token de cada segmento de un comando de shell (`a | b; c && d`),
/// sin ruta (`/usr/bin/nmap` → `nmap`) y sin prefijos `sudo`/`env`/`timeout`.
fn command_binaries(cmd: &str) -> Vec<String> {
    let mut out = Vec::new();
    for seg in cmd.split(|c| matches!(c, ';' | '|' | '&' | '\n' | '`' | '(' | ')')) {
        let mut toks = seg.split_whitespace().peekable();
        while let Some(t) = toks.peek() {
            if matches!(*t, "sudo" | "env" | "nohup" | "time" | "timeout" | "xargs" | "exec")
                || t.contains('=')
                || t.starts_with('-')
                || t.chars().all(|c| c.is_ascii_digit())
            {
                toks.next();
            } else {
                break;
            }
        }
        if let Some(t) = toks.next() {
            let name = t.rsplit('/').next().unwrap_or(t).trim_matches(|c| c == '"' || c == '\'');
            if !name.is_empty() {
                out.push(name.to_lowercase());
            }
        }
    }
    out
}

fn approval_key(c: &ApprovalCategory) -> &'static str {
    match c {
        ApprovalCategory::Exploit => "exploit",
        ApprovalCategory::DataAccess => "data_access",
        ApprovalCategory::DestructiveTest => "destructive_test",
        ApprovalCategory::CredentialUse => "credential_use",
    }
}

fn prohibited_key(p: &ProhibitedActivity) -> String {
    serde_json::to_value(p)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_else(|| format!("{:?}", p))
}

/// Pares (URL, método) que una llamada va a contactar. Cubre tools nativas,
/// CUALQUIER tool (incl. MCP/browser) con un argumento `url`, y las URLs
/// incrustadas en `cli_exec` (curl/wget/…).
fn http_requests(tool_name: &str, args: &serde_json::Value) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if tool_name == "cli_exec" {
        if let Some(cmd) = args.get("command").and_then(|v| v.as_str()) {
            let post = cmd.split_whitespace().any(|t| {
                matches!(t, "-d" | "--data" | "--data-raw" | "--data-binary" | "-F" | "--post-data")
                    || t.eq_ignore_ascii_case("POST")
            });
            let method = if post { "POST" } else { "GET" };
            for tok in cmd.split_whitespace() {
                let t = tok.trim_matches(|c| matches!(c, '"' | '\'' | ';' | '|' | '&' | '(' | ')'));
                if t.starts_with("http://") || t.starts_with("https://") {
                    out.push((t.to_string(), method.to_string()));
                }
            }
        }
        return out;
    }
    let url = args
        .get("url")
        .or_else(|| args.get("target_url"))
        .and_then(|v| v.as_str());
    if let Some(url) = url {
        if url.starts_with("http://") || url.starts_with("https://") {
            let method = if tool_name == "web_head" {
                "HEAD".to_string()
            } else {
                args.get("method")
                    .and_then(|v| v.as_str())
                    .unwrap_or("GET")
                    .to_uppercase()
            };
            out.push((url.to_string(), method));
        }
    }
    out
}

impl SecurityContext {
    /// Valida una llamada a tool contra la política de engagement. `Ok(())` si
    /// procede; `Err(motivo)` si debe rechazarse (y auditarse como fallo).
    pub fn gate_tool_call(&self, tool_name: &str, args: &serde_json::Value) -> Result<(), String> {
        let Some(policy) = self.engagement_policy.as_deref() else {
            return Ok(());
        };
        self.gate_with_policy(policy, tool_name, args)
    }

    fn gate_with_policy(
        &self,
        policy: &EngagementPolicy,
        tool_name: &str,
        args: &serde_json::Value,
    ) -> Result<(), String> {
        let acts = classify(tool_name, args);

        for p in &acts.prohibited {
            if policy.is_prohibited(p) {
                return Err(format!(
                    "tool '{}' bloqueada: el programa '{}' prohíbe '{}'",
                    tool_name,
                    policy.program,
                    prohibited_key(p)
                ));
            }
        }
        for c in &acts.approval {
            if policy.requires_approval(c) && !self.has_human_approval(approval_key(c)) {
                return Err(format!(
                    "tool '{}' requiere aprobación humana '{}' (--approve-human {})",
                    tool_name,
                    approval_key(c),
                    approval_key(c)
                ));
            }
        }

        for (url, method) in http_requests(tool_name, args) {
            self.gate_http(policy, &url, &method)?;
        }
        Ok(())
    }

    fn gate_http(&self, policy: &EngagementPolicy, url: &str, method: &str) -> Result<(), String> {
        let parsed = reqwest::Url::parse(url).map_err(|e| format!("URL inválida '{}': {}", url, e))?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(format!("esquema '{}' no permitido", parsed.scheme()));
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| format!("URL sin host: {}", url))?;
        let rule = policy.request_allowed(host, parsed.path(), method)?;
        if !policy.is_within_window(chrono::Utc::now()) {
            return Err(format!(
                "fuera de la ventana horaria autorizada del programa '{}'",
                policy.program
            ));
        }
        if let Some(rps) = rule.rate_limit_rps {
            self.check_rate_limit(&policy.program, host, rps)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engagement::TargetRule;
    use std::sync::Arc;

    fn ctx(policy: EngagementPolicy) -> SecurityContext {
        SecurityContext {
            unsafe_mode: false,
            allowlist_hosts: vec![],
            operator_id: "t".into(),
            engagement_policy: Some(Arc::new(policy)),
            human_approvals: Default::default(),
            allow_cli_exec: true,
            task_root: None,
        }
    }

    fn policy() -> EngagementPolicy {
        EngagementPolicy {
            program: "acme".into(),
            targets: vec![TargetRule {
                host: "*.acme.com".into(),
                paths: vec!["/app/**".into()],
                methods: vec!["GET".into(), "HEAD".into()],
                rate_limit_rps: None,
                only_own_accounts: false,
            }],
            prohibited: vec![ProhibitedActivity::AutomatedScanning],
            require_human_approval: vec![ApprovalCategory::Exploit],
            ..Default::default()
        }
    }

    #[test]
    fn blocks_prohibited_scanner_tools_and_cli_exec() {
        let c = ctx(policy());
        assert!(c.gate_tool_call("nuclei", &serde_json::json!({})).is_err());
        assert!(c.gate_tool_call("nmap", &serde_json::json!({})).is_err());
        let cmd = serde_json::json!({"command": "echo hi | sudo /usr/bin/ffuf -u https://x/FUZZ"});
        assert!(c.gate_tool_call("cli_exec", &cmd).is_err());
        let ok = serde_json::json!({"command": "echo nmap"});
        assert!(c.gate_tool_call("cli_exec", &ok).is_ok());
    }

    #[test]
    fn exploit_requires_human_approval() {
        let mut p = policy();
        p.prohibited.clear();
        let c = ctx(p);
        let err = c.gate_tool_call("metasploit_rpc", &serde_json::json!({})).unwrap_err();
        assert!(err.contains("aprobación humana"));
        c.grant_human_approval("exploit");
        assert!(c.gate_tool_call("metasploit_rpc", &serde_json::json!({})).is_ok());
    }

    #[test]
    fn http_checks_host_path_and_method() {
        let c = ctx(policy());
        let ok = serde_json::json!({"url": "https://www.acme.com/app/home"});
        assert!(c.gate_tool_call("web_fetch", &ok).is_ok());
        // host fuera de scope (sufijo sin punto)
        let evil = serde_json::json!({"url": "https://evilacme.com/app/home"});
        assert!(c.gate_tool_call("web_fetch", &evil).is_err());
        // apex no cubierto por el comodín
        let apex = serde_json::json!({"url": "https://acme.com/app/home"});
        assert!(c.gate_tool_call("web_fetch", &apex).is_err());
        // path fuera de regla
        let path = serde_json::json!({"url": "https://www.acme.com/admin"});
        assert!(c.gate_tool_call("web_fetch", &path).is_err());
        // método no permitido
        let post = serde_json::json!({"url": "https://www.acme.com/app/x", "method": "POST"});
        assert!(c.gate_tool_call("web_fetch", &post).is_err());
        assert!(c.gate_tool_call("web_head", &ok).is_ok());
    }

    #[test]
    fn gates_mcp_tools_with_url_and_cli_urls() {
        let c = ctx(policy());
        // tool MCP arbitraria con argumento url
        let out = serde_json::json!({"url": "https://evil.example.org/app/x"});
        assert!(c.gate_tool_call("obscura_navigate", &out).is_err());
        let inn = serde_json::json!({"url": "https://www.acme.com/app/x"});
        assert!(c.gate_tool_call("obscura_navigate", &inn).is_ok());
        // curl a host fuera de scope / método POST no permitido
        let curl = serde_json::json!({"command": "curl -s https://evil.example.org/"});
        assert!(c.gate_tool_call("cli_exec", &curl).is_err());
        let post = serde_json::json!({"command": "curl -d a=1 https://www.acme.com/app/x"});
        assert!(c.gate_tool_call("cli_exec", &post).is_err());
        let get = serde_json::json!({"command": "curl -s https://www.acme.com/app/x"});
        assert!(c.gate_tool_call("cli_exec", &get).is_ok());
    }

    #[test]
    fn no_policy_is_noop() {
        let mut c = ctx(policy());
        c.engagement_policy = None;
        assert!(c.gate_tool_call("nuclei", &serde_json::json!({})).is_ok());
    }

    #[test]
    fn unknown_policy_field_fails_to_load() {
        let bad = r#"{"program":"x","prohibted":["automated_scanning"]}"#;
        assert!(serde_json::from_str::<EngagementPolicy>(bad).is_err());
        let ai = r#"{"program":"x","ai_policy":{"disclosure_required":true,"autonomous_submission_allowed":false}}"#;
        assert!(serde_json::from_str::<EngagementPolicy>(ai).is_ok());
    }
}
