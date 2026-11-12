//! Recon web moderno (docs/tooling-gap.md, prioridad 1-2): subfinder, httpx,
//! katana, gau, ffuf, jsluice, trufflehog.
//!
//! Diseño seguro:
//!  * Parámetros ESTRUCTURADOS y argv directo (sin shell): no hay inyección de
//!    comandos vía `flags`/`target`, y ningún valor puede empezar por `-`.
//!  * Scope por `SecurityContext::check_scope` (política o allowlist) — no
//!    exige `--unsafe-mode`, que es demasiado grueso para recon pasivo.
//!  * El rate limit de la política se traduce a los flags de cada herramienta
//!    (`-rl`/`-rate`); sin límite en política se usa un valor conservador.
//!  * El `policy_gate` (middleware) además clasifica httpx/katana/ffuf como
//!    `automated_scanning` y valida host/path/método de la URL.
//!  * Salida normalizada: `{tool, count, results[], truncated, exit_code}`.

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

use crate::registry::{SecurityContext, Tool, ToolCategory, ToolSchema};

const DEFAULT_RPS: f64 = 2.0;
const MAX_RESULTS: usize = 500;
const MAX_STDOUT: usize = 200_000;

/// Qué parte de los parámetros debe estar en scope antes de ejecutar.
enum Scope {
    Host(String),
    Url(String),
    None,
}

struct Built {
    argv: Vec<String>,
    scope: Scope,
    jsonl: bool,
    /// cwd = task_root (herramientas que leen archivos locales).
    local_files: bool,
}

type BuildFn = fn(&Value, f64) -> Result<Built>;

pub struct WebReconTool {
    name: &'static str,
    description: &'static str,
    bin: &'static str,
    params: fn() -> ToolSchema,
    build: BuildFn,
    security: Arc<SecurityContext>,
}

// ───────────────────────── validación de argumentos ─────────────────────────

fn safe_token(label: &str, v: &str) -> Result<String> {
    let v = v.trim();
    if v.is_empty() {
        return Err(anyhow!("{} vacío", label));
    }
    if v.starts_with('-') {
        return Err(anyhow!("{} no puede empezar por '-'", label));
    }
    if v.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(anyhow!("{} contiene espacios/control", label));
    }
    Ok(v.to_string())
}

fn str_param<'a>(p: &'a Value, key: &str) -> Result<&'a str> {
    p.get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("{} requerido", key))
}

fn domain_param(p: &Value, key: &str) -> Result<String> {
    let d = safe_token(key, str_param(p, key)?)?.to_lowercase();
    let ok = d
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_');
    if !ok || !d.contains('.') {
        return Err(anyhow!("{} debe ser un dominio (p.ej. example.com)", key));
    }
    Ok(d)
}

fn url_param(p: &Value, key: &str) -> Result<(String, String)> {
    let raw = safe_token(key, str_param(p, key)?)?;
    let u = reqwest::Url::parse(&raw).map_err(|e| anyhow!("{} no es una URL válida: {}", key, e))?;
    if !matches!(u.scheme(), "http" | "https") {
        return Err(anyhow!("{}: solo http/https", key));
    }
    let host = u.host_str().ok_or_else(|| anyhow!("{} sin host", key))?.to_string();
    Ok((raw, host))
}

/// Ruta relativa dentro de task_root: sin `..`, sin absoluta.
fn rel_path_param(p: &Value, key: &str) -> Result<String> {
    let v = safe_token(key, str_param(p, key)?)?;
    if v.starts_with('/') || v.split('/').any(|s| s == "..") {
        return Err(anyhow!("{} debe ser relativa a la carpeta de la tarea (sin '..')", key));
    }
    Ok(v)
}

fn rate_str(rps: f64) -> String {
    format!("{}", rps.max(0.1).ceil() as u64)
}

fn schema(props: Vec<(&str, Value)>, required: &[&str]) -> ToolSchema {
    let mut m = HashMap::new();
    for (k, v) in props {
        m.insert(k.to_string(), v);
    }
    ToolSchema {
        schema_type: "object".into(),
        properties: m,
        required: Some(required.iter().map(|s| s.to_string()).collect()),
    }
}

// ───────────────────────────── definiciones ─────────────────────────────────

fn build_subfinder(p: &Value, rps: f64) -> Result<Built> {
    let d = domain_param(p, "domain")?;
    Ok(Built {
        argv: vec!["-d".into(), d.clone(), "-silent".into(), "-rl".into(), rate_str(rps)],
        scope: Scope::Host(d),
        jsonl: false,
        local_files: false,
    })
}

fn build_httpx(p: &Value, rps: f64) -> Result<Built> {
    let raw = safe_token("target", str_param(p, "target")?)?;
    // host pelado o URL completa
    let (arg, host) = if raw.contains("://") {
        let (u, h) = url_param(p, "target")?;
        (u, h)
    } else {
        let d = domain_param(p, "target")?;
        (d.clone(), d)
    };
    Ok(Built {
        argv: ["-u", &arg, "-silent", "-json", "-sc", "-title", "-td", "-nc", "-timeout", "10", "-retries", "1", "-rl"]
            .iter()
            .map(|s| s.to_string())
            .chain(std::iter::once(rate_str(rps)))
            .collect(),
        scope: Scope::Host(host),
        jsonl: true,
        local_files: false,
    })
}

fn build_katana(p: &Value, rps: f64) -> Result<Built> {
    let (url, _) = url_param(p, "url")?;
    let depth = p.get("depth").and_then(|v| v.as_u64()).unwrap_or(2).clamp(1, 3);
    Ok(Built {
        argv: ["-u", &url, "-d", &depth.to_string(), "-silent", "-jsonl", "-nc", "-ct", "60", "-rl"]
            .iter()
            .map(|s| s.to_string())
            .chain(std::iter::once(rate_str(rps)))
            .collect(),
        scope: Scope::Url(url),
        jsonl: true,
        local_files: false,
    })
}

fn build_gau(p: &Value, _rps: f64) -> Result<Built> {
    let d = domain_param(p, "domain")?;
    Ok(Built {
        argv: vec!["--threads".into(), "1".into(), d.clone()],
        scope: Scope::Host(d),
        jsonl: false,
        local_files: false,
    })
}

fn build_ffuf(p: &Value, rps: f64) -> Result<Built> {
    let (url, host) = url_param(p, "url")?;
    // FUZZ solo en path/query: nunca en el host (evitaría el scope check).
    if !url.contains("FUZZ") {
        return Err(anyhow!("url debe contener la palabra clave FUZZ"));
    }
    // `Url` normaliza el host a minúsculas: comparar sin distinguir mayúsculas,
    // y vigilar también userinfo (ffuf sustituye FUZZ en TODA la cadena).
    let parsed = reqwest::Url::parse(&url)?;
    let authority_has_fuzz = host.to_lowercase().contains("fuzz")
        || parsed.username().to_uppercase().contains("FUZZ")
        || parsed.password().unwrap_or("").to_uppercase().contains("FUZZ");
    if authority_has_fuzz {
        return Err(anyhow!("FUZZ no puede estar en el host (fuzzing de vhosts no soportado)"));
    }
    let wl = safe_token("wordlist", str_param(p, "wordlist")?)?;
    let meta = std::fs::metadata(&wl).map_err(|e| anyhow!("wordlist ilegible: {}", e))?;
    if !meta.is_file() {
        return Err(anyhow!("wordlist debe ser un archivo"));
    }
    Ok(Built {
        argv: ["-u", &url, "-w", &wl, "-mc", "200,204,301,302,307,401,403,405", "-s", "-t", "5", "-rate"]
            .iter()
            .map(|s| s.to_string())
            .chain(std::iter::once(rate_str(rps)))
            .collect(),
        scope: Scope::Url(url.replace("FUZZ", "x")),
        jsonl: false,
        local_files: false,
    })
}

fn build_jsluice(p: &Value, _rps: f64) -> Result<Built> {
    let mode = p.get("mode").and_then(|v| v.as_str()).unwrap_or("urls");
    if !matches!(mode, "urls" | "secrets") {
        return Err(anyhow!("mode debe ser 'urls' o 'secrets'"));
    }
    let file = rel_path_param(p, "file")?;
    Ok(Built {
        argv: vec![mode.into(), file],
        scope: Scope::None,
        jsonl: true,
        local_files: true,
    })
}

fn build_trufflehog(p: &Value, _rps: f64) -> Result<Built> {
    let path = rel_path_param(p, "path")?;
    let verify = p.get("verify").and_then(|v| v.as_bool()).unwrap_or(false);
    let mut argv: Vec<String> = vec!["filesystem".into(), path, "--json".into(), "--no-update".into()];
    if !verify {
        // Verificar = probar la credencial hallada contra su proveedor: es USO
        // de credenciales, exige aprobación humana (policy_gate).
        argv.push("--no-verification".into());
    }
    Ok(Built { argv, scope: Scope::None, jsonl: true, local_files: true })
}

fn def(
    security: &Arc<SecurityContext>,
    name: &'static str,
    description: &'static str,
    bin: &'static str,
    params: fn() -> ToolSchema,
    build: BuildFn,
) -> Arc<dyn Tool> {
    Arc::new(WebReconTool { name, description, bin, params, build, security: security.clone() })
}

pub fn create_all(sec: Arc<SecurityContext>) -> Vec<Arc<dyn Tool>> {
    vec![
        def(&sec, "subfinder", "Enumeración PASIVA de subdominios de un dominio en scope (fuentes públicas).", "subfinder",
            || schema(vec![("domain", json!({"type":"string","description":"dominio raíz, p.ej. example.com"}))], &["domain"]),
            build_subfinder),
        def(&sec, "httpx", "Probing HTTP de un host/URL en scope: status, título, tecnologías (salida JSON).", "httpx",
            || schema(vec![("target", json!({"type":"string","description":"host o URL en scope"}))], &["target"]),
            build_httpx),
        def(&sec, "katana", "Crawler: extrae endpoints y URLs de una URL en scope (profundidad 1-3, rate limit de la política).", "katana",
            || schema(vec![("url", json!({"type":"string"})), ("depth", json!({"type":"integer","default":2,"minimum":1,"maximum":3}))], &["url"]),
            build_katana),
        def(&sec, "gau", "URLs históricas (Wayback/CommonCrawl/OTX) de un dominio en scope. Pasivo: no toca el objetivo.", "gau",
            || schema(vec![("domain", json!({"type":"string"}))], &["domain"]),
            build_gau),
        def(&sec, "ffuf", "Descubrimiento de contenido: fuzzing de rutas/params con FUZZ en la URL (rate limit de la política).", "ffuf",
            || schema(vec![("url", json!({"type":"string","description":"URL con FUZZ en path o query"})), ("wordlist", json!({"type":"string","description":"ruta de la wordlist"}))], &["url", "wordlist"]),
            build_ffuf),
        def(&sec, "jsluice", "Extrae URLs/endpoints o secretos de un archivo JavaScript local (ruta relativa a la carpeta de la tarea).", "jsluice",
            || schema(vec![("file", json!({"type":"string"})), ("mode", json!({"type":"string","enum":["urls","secrets"],"default":"urls"}))], &["file"]),
            build_jsluice),
        def(&sec, "trufflehog", "Busca secretos en archivos locales de la tarea. Por defecto SIN verificar contra proveedores; verify=true exige aprobación humana.", "trufflehog",
            || schema(vec![("path", json!({"type":"string"})), ("verify", json!({"type":"boolean","default":false}))], &["path"]),
            build_trufflehog),
    ]
}

// ───────────────────────────── ejecución ────────────────────────────────────

fn cap(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut cut = max;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    s[..cut].to_string()
}

#[async_trait]
impl Tool for WebReconTool {
    fn name(&self) -> &str {
        self.name
    }
    fn description(&self) -> &str {
        self.description
    }
    fn category(&self) -> ToolCategory {
        ToolCategory::Recon
    }
    fn parameters(&self) -> ToolSchema {
        (self.params)()
    }

    async fn execute(&self, params: Value) -> Result<Value> {
        if !params.is_object() {
            return Err(anyhow!("params must be an object"));
        }
        // 1) rate efectivo: el de la regla del programa o el conservador.
        let probe_host = match (self.build)(&params, DEFAULT_RPS) {
            Ok(b) => match &b.scope {
                Scope::Host(h) => Some(h.clone()),
                Scope::Url(u) => reqwest::Url::parse(u).ok().and_then(|x| x.host_str().map(String::from)),
                Scope::None => None,
            },
            Err(e) => return Ok(json!({"error": "invalid_params", "message": e.to_string()})),
        };
        let rps = probe_host
            .as_deref()
            .and_then(|h| self.security.engagement_policy.as_ref().and_then(|p| p.rate_limit_for(h)))
            .unwrap_or(DEFAULT_RPS);
        let built = match (self.build)(&params, rps) {
            Ok(b) => b,
            Err(e) => return Ok(json!({"error": "invalid_params", "message": e.to_string()})),
        };

        // 2) scope (política o allowlist) — falla cerrado.
        if let Some(host) = probe_host.as_deref() {
            if let Err(e) = self.security.check_scope(host) {
                return Ok(json!({"error": "security_policy", "message": e, "target": host}));
            }
        }

        // 3) ejecución directa, sin shell.
        let mut cmd = tokio::process::Command::new(self.bin);
        cmd.args(&built.argv)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        if built.local_files {
            if let Some(root) = &self.security.task_root {
                cmd.current_dir(root);
            }
        }
        let child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(json!({
                    "error": "binary_not_found",
                    "message": format!("'{}' no está instalado en PATH (ver docs/tooling-gap.md)", self.bin),
                }));
            }
            Err(e) => return Err(anyhow!("no se pudo lanzar {}: {}", self.bin, e)),
        };
        let timeout = params.get("timeout_seconds").and_then(|v| v.as_u64()).unwrap_or(120).min(600);
        let out = tokio::time::timeout(std::time::Duration::from_secs(timeout), child.wait_with_output())
            .await
            .map_err(|_| anyhow!("{} excedió {}s", self.bin, timeout))??;

        let stdout = cap(&String::from_utf8_lossy(&out.stdout), MAX_STDOUT);
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        let mut results: Vec<Value> = Vec::new();
        let mut total = 0usize;
        for line in stdout.lines().map(str::trim).filter(|l| !l.is_empty()) {
            total += 1;
            if results.len() < MAX_RESULTS {
                results.push(if built.jsonl {
                    serde_json::from_str(line).unwrap_or_else(|_| Value::String(line.to_string()))
                } else {
                    Value::String(line.to_string())
                });
            }
        }
        let tail: String = stderr.chars().rev().take(1500).collect::<Vec<_>>().into_iter().rev().collect();
        Ok(json!({
            "tool": self.name,
            "exit_code": out.status.code().unwrap_or(-1),
            "count": total,
            "truncated": total > results.len(),
            "results": results,
            "stderr_tail": tail,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(v: Value) -> Value {
        v
    }

    #[test]
    fn rejects_flag_and_shell_injection() {
        assert!(build_subfinder(&p(json!({"domain": "-silent"})), 1.0).is_err());
        assert!(build_subfinder(&p(json!({"domain": "a.com; rm -rf /"})), 1.0).is_err());
        assert!(build_subfinder(&p(json!({"domain": "a.com $(id)"})), 1.0).is_err());
        assert!(build_katana(&p(json!({"url": "-u http://x"})), 1.0).is_err());
        assert!(build_katana(&p(json!({"url": "file:///etc/passwd"})), 1.0).is_err());
    }

    #[test]
    fn argv_carries_policy_rate_and_caps_depth() {
        let b = build_katana(&p(json!({"url": "https://a.acme.com/", "depth": 9})), 4.0).unwrap();
        let j = b.argv.join(" ");
        assert!(j.contains("-d 3"), "{j}");
        assert!(j.ends_with("-rl 4"), "{j}");
        let f = build_ffuf(&p(json!({"url": "https://a.acme.com/FUZZ", "wordlist": "/etc/hostname"})), 1.0).unwrap();
        assert!(f.argv.join(" ").ends_with("-rate 1"));
    }

    #[test]
    fn ffuf_requires_fuzz_in_path_not_host() {
        assert!(build_ffuf(&p(json!({"url": "https://a.acme.com/x", "wordlist": "/etc/hostname"})), 1.0).is_err());
        assert!(build_ffuf(&p(json!({"url": "https://FUZZ.acme.com/", "wordlist": "/etc/hostname"})), 1.0).is_err());
    }

    #[test]
    fn local_file_tools_stay_inside_task_dir() {
        assert!(build_jsluice(&p(json!({"file": "../../etc/passwd"})), 1.0).is_err());
        assert!(build_jsluice(&p(json!({"file": "/etc/passwd"})), 1.0).is_err());
        assert!(build_jsluice(&p(json!({"file": "app.js", "mode": "x"})), 1.0).is_err());
        assert!(build_trufflehog(&p(json!({"path": "loot"})), 1.0).unwrap().argv.contains(&"--no-verification".to_string()));
        assert!(!build_trufflehog(&p(json!({"path": "loot", "verify": true})), 1.0).unwrap().argv.contains(&"--no-verification".to_string()));
    }

    #[tokio::test]
    async fn out_of_scope_domain_is_refused_and_missing_binary_reported() {
        use crate::engagement::{EngagementPolicy, TargetRule};
        let sec = Arc::new(SecurityContext {
            unsafe_mode: false,
            allowlist_hosts: vec![],
            operator_id: "t".into(),
            engagement_policy: Some(Arc::new(EngagementPolicy {
                program: "acme".into(),
                targets: vec![TargetRule { host: "*.acme.com".into(), ..Default::default() }],
                ..Default::default()
            })),
            human_approvals: Default::default(),
            allow_cli_exec: false,
            task_root: None,
        });
        let tools = create_all(sec);
        let sub = tools.iter().find(|t| t.name() == "subfinder").unwrap();
        let r = sub.execute(json!({"domain": "evil.example.org"})).await.unwrap();
        assert_eq!(r["error"], "security_policy");
        let ok = sub.execute(json!({"domain": "dev.acme.com"})).await.unwrap();
        // en CI el binario normalmente no existe: debe reportarlo, no fallar.
        assert!(ok["error"] == "binary_not_found" || ok["tool"] == "subfinder", "{ok}");
    }
}
