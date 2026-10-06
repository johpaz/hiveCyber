use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use crate::registry::{Isolation, Tool, ToolCategory, ToolSchema};

const DANGEROUS_COMMANDS: &[&str] = &[
    "msfconsole", "msfrpc", "msfvenom",
    "hydra", "medusa",
    "crackmapexec", "cme", "nxc",
    "mimikatz", "sekurlsa", "lsadump",
    "hashcat", "john",
];

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

fn get_u64(params: &HashMap<String, Value>, key: &str, default: u64) -> u64 {
    params.get(key).and_then(|v| v.as_u64()).unwrap_or(default)
}

/// Resolve a path param against this task/session's scratch dir
/// (`SecurityContext.task_root`), same rationale as `cli_exec`'s `cwd`
/// default: a relative path (`"report.txt"`, `"."`) lands in the calling
/// task's scratch space instead of the process's own cwd (or, for a
/// sandboxed-worker call, the fresh worker process's unrelated `$HOME`).
/// Absolute paths pass through unchanged — this resolves the *default*
/// working directory, it is not a jail (an agent that asks for `/etc/passwd`
/// still gets `/etc/passwd`; containing that is the separate, not-yet-built
/// hardening pass noted in the sandbox-architecture plan).
fn resolve_path(security: &crate::registry::SecurityContext, raw: &str) -> PathBuf {
    let p = PathBuf::from(raw);
    if p.is_absolute() {
        return p;
    }
    match &security.task_root {
        Some(root) => root.join(p),
        None => p,
    }
}

pub struct FsRead {
    security: Arc<crate::registry::SecurityContext>,
}

impl FsRead {
    pub fn new(security: Arc<crate::registry::SecurityContext>) -> Self {
        FsRead { security }
    }
}

#[async_trait]
impl Tool for FsRead {
    fn name(&self) -> &str { "fs_read" }
    fn description(&self) -> &str { "Lee el contenido de un archivo." }
    fn category(&self) -> ToolCategory { ToolCategory::Base }
    fn parameters(&self) -> ToolSchema {
        let mut props = HashMap::new();
        props.insert("path".into(), json!({"type": "string", "description": "Ruta del archivo"}));
        props.insert("offset".into(), json!({"type": "integer", "default": 0}));
        props.insert("limit".into(), json!({"type": "integer", "default": 2000}));
        ToolSchema {
            schema_type: "object".into(),
            properties: props,
            required: Some(vec!["path".into()]),
        }
    }
    async fn execute(&self, params: Value) -> Result<Value> {
        let p = read_params(&params)?;
        let path = p.get("path").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("path required"))?;
        let resolved = resolve_path(&self.security, path);
        let offset = get_u64(&p, "offset", 0) as usize;
        let limit = get_u64(&p, "limit", 2000) as usize;

        let content = tokio::fs::read_to_string(&resolved)
            .await
            .with_context(|| format!("read {}", resolved.display()))?;

        let lines: Vec<&str> = content.lines().collect();
        let end = std::cmp::min(offset + limit, lines.len());
        let slice = if offset < lines.len() {
            lines[offset..end].join("\n")
        } else {
            String::new()
        };

        Ok(json!({
            "path": resolved.display().to_string(),
            "content": slice,
            "total_lines": lines.len(),
            "showed_lines": end - offset,
        }))
    }
}

pub struct FsWrite {
    security: Arc<crate::registry::SecurityContext>,
}

impl FsWrite {
    pub fn new(security: Arc<crate::registry::SecurityContext>) -> Self {
        FsWrite { security }
    }
}

#[async_trait]
impl Tool for FsWrite {
    fn name(&self) -> &str { "fs_write" }
    fn description(&self) -> &str { "Escribe contenido a un archivo (sobreescribe)." }
    fn category(&self) -> ToolCategory { ToolCategory::Base }
    fn isolation(&self) -> Isolation { Isolation::Sandbox }
    fn parameters(&self) -> ToolSchema {
        let mut props = HashMap::new();
        props.insert("path".into(), json!({"type": "string"}));
        props.insert("content".into(), json!({"type": "string"}));
        ToolSchema {
            schema_type: "object".into(),
            properties: props,
            required: Some(vec!["path".into(), "content".into()]),
        }
    }
    async fn execute(&self, params: Value) -> Result<Value> {
        let p = read_params(&params)?;
        let path = p.get("path").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("path required"))?;
        let content = p.get("content").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("content required"))?;
        let resolved = resolve_path(&self.security, path);

        if let Some(parent) = resolved.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        tokio::fs::write(&resolved, content).await?;

        Ok(json!({"path": resolved.display().to_string(), "written": content.len()}))
    }
}

pub struct FsEdit {
    security: Arc<crate::registry::SecurityContext>,
}

impl FsEdit {
    pub fn new(security: Arc<crate::registry::SecurityContext>) -> Self {
        FsEdit { security }
    }
}

#[async_trait]
impl Tool for FsEdit {
    fn name(&self) -> &str { "fs_edit" }
    fn description(&self) -> &str { "Reemplaza texto exacto en un archivo." }
    fn category(&self) -> ToolCategory { ToolCategory::Base }
    fn isolation(&self) -> Isolation { Isolation::Sandbox }
    fn parameters(&self) -> ToolSchema {
        let mut props = HashMap::new();
        props.insert("path".into(), json!({"type": "string"}));
        props.insert("old".into(), json!({"type": "string"}));
        props.insert("new".into(), json!({"type": "string"}));
        ToolSchema {
            schema_type: "object".into(),
            properties: props,
            required: Some(vec!["path".into(), "old".into(), "new".into()]),
        }
    }
    async fn execute(&self, params: Value) -> Result<Value> {
        let p = read_params(&params)?;
        let path = p.get("path").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("path required"))?;
        let old = p.get("old").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("old required"))?;
        let new = p.get("new").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("new required"))?;
        let resolved = resolve_path(&self.security, path);

        let content = tokio::fs::read_to_string(&resolved).await?;
        let new_content = content.replacen(old, new, 1);

        if new_content == content {
            return Err(anyhow!("old string not found in file"));
        }

        tokio::fs::write(&resolved, &new_content).await?;

        Ok(json!({"path": resolved.display().to_string(), "replaced": 1}))
    }
}

pub struct FsGlob {
    security: Arc<crate::registry::SecurityContext>,
}

impl FsGlob {
    pub fn new(security: Arc<crate::registry::SecurityContext>) -> Self {
        FsGlob { security }
    }
}

#[async_trait]
impl Tool for FsGlob {
    fn name(&self) -> &str { "fs_glob" }
    fn description(&self) -> &str { "Busca archivos con patron glob." }
    fn category(&self) -> ToolCategory { ToolCategory::Base }
    fn parameters(&self) -> ToolSchema {
        let mut props = HashMap::new();
        props.insert("pattern".into(), json!({"type": "string", "description": "Patron glob: **/*.rs"}));
        props.insert("path".into(), json!({"type": "string", "default": "."}));
        ToolSchema {
            schema_type: "object".into(),
            properties: props,
            required: Some(vec!["pattern".into()]),
        }
    }
    async fn execute(&self, params: Value) -> Result<Value> {
        let p = read_params(&params)?;
        let pattern = p.get("pattern").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("pattern required"))?;
        let base = resolve_path(&self.security, &get_str(&p, "path", "."));

        let mut results = Vec::new();
        for entry in walkdir::WalkDir::new(&base).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.is_file() {
                let rel = path.strip_prefix(&base).unwrap_or(path);
                if glob_matches(pattern, rel.to_string_lossy().as_ref()) {
                    results.push(path.to_string_lossy().to_string());
                }
            }
            if results.len() >= 200 {
                break;
            }
        }

        Ok(json!({"files": results, "count": results.len()}))
    }
}

fn glob_matches(pattern: &str, path: &str) -> bool {
    let parts: Vec<&str> = pattern.split('/').collect();
    let path_parts: Vec<&str> = path.split('/').collect();

    glob_match_parts(&parts, &path_parts)
}

fn glob_match_parts(pattern: &[&str], path: &[&str]) -> bool {
    if pattern.is_empty() {
        return path.is_empty();
    }

    let first = pattern[0];
    if first == "**" {
        if pattern.len() == 1 {
            return true;
        }
        for i in 0..=path.len() {
            if glob_match_parts(&pattern[1..], &path[i..]) {
                return true;
            }
        }
        false
    } else if path.is_empty() {
        false
    } else if glob_single_match(first, path[0]) {
        glob_match_parts(&pattern[1..], &path[1..])
    } else {
        false
    }
}

fn glob_single_match(pattern: &str, name: &str) -> bool {
    let pb = pattern.as_bytes();
    let nb = name.as_bytes();
    let mut pi = 0;
    let mut ni = 0;
    let mut star_pi = None;
    let mut star_ni = 0;

    while ni < nb.len() {
        if pi < pb.len() && (pb[pi] == nb[ni] || pb[pi] == b'?') {
            pi += 1;
            ni += 1;
        } else if pi < pb.len() && pb[pi] == b'*' {
            star_pi = Some(pi);
            star_ni = ni;
            pi += 1;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            star_ni += 1;
            ni = star_ni;
        } else {
            return false;
        }
    }

    while pi < pb.len() && pb[pi] == b'*' {
        pi += 1;
    }

    pi == pb.len()
}

pub struct FsExists {
    security: Arc<crate::registry::SecurityContext>,
}

impl FsExists {
    pub fn new(security: Arc<crate::registry::SecurityContext>) -> Self {
        FsExists { security }
    }
}

#[async_trait]
impl Tool for FsExists {
    fn name(&self) -> &str { "fs_exists" }
    fn description(&self) -> &str { "Verifica si un archivo o directorio existe." }
    fn category(&self) -> ToolCategory { ToolCategory::Base }
    fn parameters(&self) -> ToolSchema {
        let mut props = HashMap::new();
        props.insert("path".into(), json!({"type": "string"}));
        ToolSchema {
            schema_type: "object".into(),
            properties: props,
            required: Some(vec!["path".into()]),
        }
    }
    async fn execute(&self, params: Value) -> Result<Value> {
        let p = read_params(&params)?;
        let path = p.get("path").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("path required"))?;
        let resolved = resolve_path(&self.security, path);

        let exists = tokio::fs::metadata(&resolved).await.is_ok();
        let is_dir = tokio::fs::metadata(&resolved).await.map(|m| m.is_dir()).unwrap_or(false);

        Ok(json!({"path": resolved.display().to_string(), "exists": exists, "is_dir": is_dir}))
    }
}

pub struct FsList {
    security: Arc<crate::registry::SecurityContext>,
}

impl FsList {
    pub fn new(security: Arc<crate::registry::SecurityContext>) -> Self {
        FsList { security }
    }
}

#[async_trait]
impl Tool for FsList {
    fn name(&self) -> &str { "fs_list" }
    fn description(&self) -> &str { "Lista las entradas de un directorio (nombre, tipo, tamaño)." }
    fn category(&self) -> ToolCategory { ToolCategory::Base }
    fn parameters(&self) -> ToolSchema {
        let mut props = HashMap::new();
        props.insert("path".into(), json!({"type": "string", "default": "."}));
        ToolSchema {
            schema_type: "object".into(),
            properties: props,
            required: None,
        }
    }
    async fn execute(&self, params: Value) -> Result<Value> {
        let p = read_params(&params)?;
        let resolved = resolve_path(&self.security, &get_str(&p, "path", "."));

        let mut rd = tokio::fs::read_dir(&resolved)
            .await
            .with_context(|| format!("read_dir {}", resolved.display()))?;
        let mut entries = Vec::new();
        while let Some(entry) = rd.next_entry().await? {
            let meta = entry.metadata().await.ok();
            let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
            let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
            entries.push(json!({
                "name": entry.file_name().to_string_lossy(),
                "is_dir": is_dir,
                "size": size,
            }));
        }
        entries.sort_by(|a, b| {
            a.get("name").and_then(|v| v.as_str()).unwrap_or("")
                .cmp(b.get("name").and_then(|v| v.as_str()).unwrap_or(""))
        });

        Ok(json!({"path": resolved.display().to_string(), "count": entries.len(), "entries": entries}))
    }
}

pub struct FsDelete {
    security: Arc<crate::registry::SecurityContext>,
}

impl FsDelete {
    pub fn new(security: Arc<crate::registry::SecurityContext>) -> Self {
        FsDelete { security }
    }
}

#[async_trait]
impl Tool for FsDelete {
    fn name(&self) -> &str { "fs_delete" }
    fn description(&self) -> &str { "Elimina un archivo o directorio. Con recursive=true borra directorios no vacíos." }
    fn category(&self) -> ToolCategory { ToolCategory::Base }
    fn isolation(&self) -> Isolation { Isolation::Sandbox }
    fn parameters(&self) -> ToolSchema {
        let mut props = HashMap::new();
        props.insert("path".into(), json!({"type": "string"}));
        props.insert("recursive".into(), json!({"type": "boolean", "default": false}));
        ToolSchema {
            schema_type: "object".into(),
            properties: props,
            required: Some(vec!["path".into()]),
        }
    }
    async fn execute(&self, params: Value) -> Result<Value> {
        let p = read_params(&params)?;
        let path = p.get("path").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("path required"))?;
        let recursive = p.get("recursive").and_then(|v| v.as_bool()).unwrap_or(false);
        // Guard the *resolved* path: a relative "x" must not slip past the
        // protected-path check that only sees the raw string.
        let resolved = resolve_path(&self.security, path);
        let resolved_str = resolved.display().to_string();

        // Refuse obviously catastrophic targets outright. This is a coarse guard,
        // not a full sandbox — the real confinement for sandboxed workers is the
        // seccomp/rlimit layer; here we just stop trivially fatal mistakes.
        let trimmed = resolved_str.trim_end_matches('/');
        if trimmed.is_empty()
            || matches!(trimmed, "/" | "/bin" | "/etc" | "/usr" | "/var" | "/boot" | "/lib" | "/sys" | "/proc" | "/dev")
            || resolved_str == std::env::var("HOME").unwrap_or_default()
        {
            return Ok(json!({
                "error": "refused",
                "message": format!("refusing to delete protected path '{}'", resolved_str),
            }));
        }

        let meta = tokio::fs::symlink_metadata(&resolved)
            .await
            .with_context(|| format!("stat {}", resolved_str))?;

        if meta.is_dir() {
            if recursive {
                tokio::fs::remove_dir_all(&resolved).await.with_context(|| format!("remove_dir_all {}", resolved_str))?;
            } else {
                tokio::fs::remove_dir(&resolved).await.with_context(|| format!("remove_dir {} (use recursive=true for non-empty)", resolved_str))?;
            }
        } else {
            tokio::fs::remove_file(&resolved).await.with_context(|| format!("remove_file {}", resolved_str))?;
        }

        Ok(json!({"path": resolved_str, "deleted": true, "was_dir": meta.is_dir()}))
    }
}

pub struct WebFetch;

#[async_trait]
impl Tool for WebFetch {
    fn name(&self) -> &str { "web_fetch" }
    fn description(&self) -> &str { "Descarga contenido de una URL y lo retorna como texto." }
    fn category(&self) -> ToolCategory { ToolCategory::Base }
    fn parameters(&self) -> ToolSchema {
        let mut props = HashMap::new();
        props.insert("url".into(), json!({"type": "string"}));
        props.insert("format".into(), json!({"type": "string", "default": "text", "enum": ["text", "html"]}));
        ToolSchema {
            schema_type: "object".into(),
            properties: props,
            required: Some(vec!["url".into()]),
        }
    }
    async fn execute(&self, params: Value) -> Result<Value> {
        let p = read_params(&params)?;
        let url = p.get("url").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("url required"))?;
        let format = get_str(&p, "format", "text");

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let resp = client.get(url).send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        let content_length = text.len();

        let content = if format == "html" {
            text
        } else {
            strip_html(&text)
        };

        let truncated = if content.len() > 50000 {
            format!("{}...(truncated)", &content[..50000])
        } else {
            content
        };

        Ok(json!({
            "url": url,
            "status": status.as_u16(),
            "content": truncated,
            "content_length": content_length,
        }))
    }
}

fn strip_html(html: &str) -> String {
    let mut result = String::new();
    let mut in_tag = false;
    for ch in html.chars() {
        if ch == '<' {
            in_tag = true;
        } else if ch == '>' {
            in_tag = false;
        } else if !in_tag {
            result.push(ch);
        }
    }
    result.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub struct WebSearch;

#[async_trait]
impl Tool for WebSearch {
    fn name(&self) -> &str { "web_search" }
    fn description(&self) -> &str {
        "Busca en la web y retorna los resultados (título, url, snippet). OSINT/reconocimiento pasivo."
    }
    fn category(&self) -> ToolCategory { ToolCategory::Base }
    fn parameters(&self) -> ToolSchema {
        let mut props = HashMap::new();
        props.insert("query".into(), json!({"type": "string", "description": "Términos de búsqueda"}));
        props.insert("max_results".into(), json!({"type": "integer", "default": 10}));
        ToolSchema {
            schema_type: "object".into(),
            properties: props,
            required: Some(vec!["query".into()]),
        }
    }
    async fn execute(&self, params: Value) -> Result<Value> {
        let p = read_params(&params)?;
        let query = p.get("query").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("query required"))?;
        let max_results = get_u64(&p, "max_results", 10) as usize;

        // DuckDuckGo HTML endpoint: no API key, scrape-friendly. Same shape as
        // Hive's web-search.ts (browser User-Agent, HTML result parse).
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .user_agent(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            )
            .build()?;

        let resp = client
            .post("https://html.duckduckgo.com/html/")
            .form(&[("q", query)])
            .send()
            .await?;
        let status = resp.status();
        let html = resp.text().await?;

        let results = parse_ddg_results(&html, max_results);

        Ok(json!({
            "query": query,
            "status": status.as_u16(),
            "count": results.len(),
            "results": results,
        }))
    }
}

/// Best-effort parse of DuckDuckGo HTML result blocks. Each result exposes an
/// anchor `class="result__a" href="..."` (title) and a `class="result__snippet"`
/// block. String-scan rather than a full HTML parser to avoid a heavy dep — if
/// DDG changes markup this degrades to fewer/zero results rather than panicking.
fn parse_ddg_results(html: &str, max_results: usize) -> Vec<Value> {
    let mut out = Vec::new();
    for chunk in html.split("result__a").skip(1) {
        if out.len() >= max_results {
            break;
        }
        let href = extract_attr(chunk, "href=\"");
        let title = extract_between(chunk, ">", "</a>").map(|t| strip_html(&t));
        // The snippet lives shortly after the title anchor in the same block.
        let snippet = chunk
            .split_once("result__snippet")
            .and_then(|(_, rest)| extract_between(rest, ">", "</a>"))
            .map(|s| strip_html(&s));
        if let (Some(href), Some(title)) = (href, title) {
            let url = decode_ddg_redirect(&href);
            if title.trim().is_empty() {
                continue;
            }
            out.push(json!({
                "title": title.trim(),
                "url": url,
                "snippet": snippet.unwrap_or_default().trim(),
            }));
        }
    }
    out
}

fn extract_attr(s: &str, prefix: &str) -> Option<String> {
    let start = s.find(prefix)? + prefix.len();
    let rest = &s[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn extract_between(s: &str, open: &str, close: &str) -> Option<String> {
    let start = s.find(open)? + open.len();
    let rest = &s[start..];
    let end = rest.find(close)?;
    Some(rest[..end].to_string())
}

/// DDG wraps result links as `//duckduckgo.com/l/?uddg=<url-encoded target>`.
/// Recover the real target when present; otherwise return the href as-is.
fn decode_ddg_redirect(href: &str) -> String {
    if let Some(idx) = href.find("uddg=") {
        let enc = &href[idx + 5..];
        let enc = enc.split('&').next().unwrap_or(enc);
        return percent_decode(enc);
    }
    if let Some(stripped) = href.strip_prefix("//") {
        return format!("https://{}", stripped);
    }
    href.to_string()
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    out.push((hi * 16 + lo) as u8);
                    i += 3;
                    continue;
                }
                out.push(bytes[i]);
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

pub struct CliExec {
    security: Arc<crate::registry::SecurityContext>,
}

impl CliExec {
    pub fn new(security: Arc<crate::registry::SecurityContext>) -> Self {
        CliExec { security }
    }
}

#[async_trait]
impl Tool for CliExec {
    fn name(&self) -> &str { "cli_exec" }
    fn description(&self) -> &str { "Ejecuta un comando CLI y retorna stdout/stderr." }
    fn category(&self) -> ToolCategory { ToolCategory::Base }
    fn isolation(&self) -> Isolation { Isolation::Sandbox }
    fn parameters(&self) -> ToolSchema {
        let mut props = HashMap::new();
        props.insert("command".into(), json!({"type": "string", "description": "Comando a ejecutar"}));
        props.insert("cwd".into(), json!({"type": "string"}));
        props.insert("timeout_seconds".into(), json!({"type": "integer", "default": 30}));
        ToolSchema {
            schema_type: "object".into(),
            properties: props,
            required: Some(vec!["command".into()]),
        }
    }

    async fn execute(&self, params: Value) -> Result<Value> {
        let p = read_params(&params)?;
        let command = p.get("command").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("command required"))?;
        // No explicit `cwd` from the caller -> default to this task/session's
        // scratch dir (if one was assigned) instead of the process's own cwd,
        // which inside a sandboxed-worker invocation would otherwise resolve
        // to the fresh worker process's unrelated `$HOME`.
        let cwd = match p.get("cwd").and_then(|v| v.as_str()) {
            Some(explicit) => explicit.to_string(),
            None => self
                .security
                .task_root
                .as_ref()
                .map(|r| r.display().to_string())
                .unwrap_or_else(|| ".".to_string()),
        };
        let timeout_secs = get_u64(&p, "timeout_seconds", 30);

        // cli_exec is disabled by default. It must be explicitly enabled via
        // --allow-cli-exec on the CLI; that flag also implies --unsafe-mode +
        // an allowlist/engagement policy. Freeform shell execution is the
        // narrowest hole for scope bypass — keep it opt-in.
        if !self.security.allow_cli_exec {
            return Err(anyhow!(
                "cli_exec disabled by default — enable with --allow-cli-exec (requires --unsafe-mode and allowlist/engagement policy)"
            ));
        }
        if !self.security.unsafe_mode {
            return Err(anyhow!(
                "cli_exec requires --unsafe-mode (security.unsafe_default=false)"
            ));
        }

        let denylist = [
            "rm -rf /", "sudo", "chmod 777", "> /dev/", "mkfs",
            "dd if=/dev/zero", ":(){ :|:& };:",
            "curl ", "wget ",
            "python", "python3", "node ", "perl ", "ruby ",
            "nc ", "ncat ", "bash -i", "/dev/tcp/",
        ];
        for blocked in &denylist {
            if command.contains(blocked) {
                return Err(anyhow!("command blocked by denylist: {}", blocked));
            }
        }

        let cmd_lower = command.to_lowercase();
        let is_dangerous = DANGEROUS_COMMANDS.iter().any(|d| cmd_lower.contains(d));
        if is_dangerous {
            if self.security.allowlist_hosts.is_empty()
                && self
                    .security
                    .engagement_policy
                    .as_ref()
                    .map(|p| p.targets.is_empty())
                    .unwrap_or(true)
            {
                return Err(anyhow!(
                    "dangerous command '{}' requires --allowlist-hosts (no allowlist configured)",
                    command
                ));
            }
        }

        // Validate every argv token that looks like a host/IP against the scope.
        // This is a best-effort complement to the tool-level `target` validation:
        // it covers `nmap`, `hydra`-style invocations where the target is a
        // positional argument rather than a structured parameter.
        for tok in command.split_whitespace() {
            let candidate = tok.trim_matches(|c: char| c.is_ascii_punctuation());
            if candidate.is_empty() {
                continue;
            }
            if candidate.contains('.')
                || candidate.parse::<std::net::IpAddr>().is_ok()
                || crate::engagement::normalize_host(candidate).parse::<std::net::IpAddr>().is_ok()
            {
                if !candidate.contains('/')
                    && self.security.validate_target(candidate).is_err()
                {
                    return Err(anyhow!(
                        "token '{}' looks like a host/IP but is not in scope",
                        candidate
                    ));
                }
            }
        }

        let mut cmd = tokio::process::Command::new("bash");
        cmd.arg("-c").arg(command);
        cmd.current_dir(&cwd);
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let child = cmd.spawn()?;
        let output = tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            child.wait_with_output(),
        )
        .await
        .map_err(|_| anyhow!("command timed out after {}s", timeout_secs))??;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let code = output.status.code().unwrap_or(-1);

        let truncated_out = if stdout.len() > 50_000 {
            format!("{}...(truncated)", &stdout[..50_000])
        } else {
            stdout
        };

        let truncated_err = if stderr.len() > 20_000 {
            format!("{}...(truncated)", &stderr[..20_000])
        } else {
            stderr
        };

        Ok(json!({
            "command": command,
            "exit_code": code,
            "stdout": truncated_out,
            "stderr": truncated_err,
        }))
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ddg_parse_extracts_title_url_snippet() {
        // Minimal fixture mimicking DuckDuckGo HTML result markup.
        let html = r#"
        <div class="result">
          <a rel="nofollow" class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fa&rut=x">Example <b>Title</b> One</a>
          <a class="result__snippet" href="/l">A short snippet about the first result.</a>
        </div>
        <div class="result">
          <a rel="nofollow" class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.org%2Fb">Second Result</a>
          <a class="result__snippet" href="/l">Second snippet.</a>
        </div>
        "#;
        let results = parse_ddg_results(html, 10);
        assert_eq!(results.len(), 2, "should parse both result blocks");
        assert_eq!(results[0]["title"], "Example Title One");
        assert_eq!(results[0]["url"], "https://example.com/a");
        assert_eq!(results[0]["snippet"], "A short snippet about the first result.");
        assert_eq!(results[1]["url"], "https://example.org/b");
    }

    #[test]
    fn ddg_parse_respects_max_results() {
        let mut html = String::new();
        for i in 0..5 {
            html.push_str(&format!(
                r#"<a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fx{}.com">T{}</a>"#,
                i, i
            ));
        }
        assert_eq!(parse_ddg_results(&html, 3).len(), 3);
    }

    #[test]
    fn percent_decode_handles_encoded_and_plus() {
        assert_eq!(percent_decode("a%20b+c"), "a b c");
        assert_eq!(percent_decode("https%3A%2F%2Fx.com"), "https://x.com");
    }

    #[test]
    fn decode_ddg_redirect_recovers_target_and_protocol_relative() {
        assert_eq!(
            decode_ddg_redirect("//duckduckgo.com/l/?uddg=https%3A%2F%2Fx.com%2Fy&rut=z"),
            "https://x.com/y"
        );
        assert_eq!(decode_ddg_redirect("//example.com/path"), "https://example.com/path");
        assert_eq!(decode_ddg_redirect("https://direct.com"), "https://direct.com");
    }
}
