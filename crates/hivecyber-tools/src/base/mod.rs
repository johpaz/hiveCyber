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

pub struct FsRead;

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
        let offset = get_u64(&p, "offset", 0) as usize;
        let limit = get_u64(&p, "limit", 2000) as usize;

        let content = tokio::fs::read_to_string(path)
            .await
            .with_context(|| format!("read {}", path))?;

        let lines: Vec<&str> = content.lines().collect();
        let end = std::cmp::min(offset + limit, lines.len());
        let slice = if offset < lines.len() {
            lines[offset..end].join("\n")
        } else {
            String::new()
        };

        Ok(json!({
            "path": path,
            "content": slice,
            "total_lines": lines.len(),
            "showed_lines": end - offset,
        }))
    }
}

pub struct FsWrite;

#[async_trait]
impl Tool for FsWrite {
    fn name(&self) -> &str { "fs_write" }
    fn description(&self) -> &str { "Escribe contenido a un archivo (sobreescribe)." }
    fn category(&self) -> ToolCategory { ToolCategory::Base }
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

        if let Some(parent) = PathBuf::from(path).parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        tokio::fs::write(path, content).await?;

        Ok(json!({"path": path, "written": content.len()}))
    }
}

pub struct FsEdit;

#[async_trait]
impl Tool for FsEdit {
    fn name(&self) -> &str { "fs_edit" }
    fn description(&self) -> &str { "Reemplaza texto exacto en un archivo." }
    fn category(&self) -> ToolCategory { ToolCategory::Base }
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

        let content = tokio::fs::read_to_string(path).await?;
        let new_content = content.replacen(old, new, 1);

        if new_content == content {
            return Err(anyhow!("old string not found in file"));
        }

        tokio::fs::write(path, &new_content).await?;

        Ok(json!({"path": path, "replaced": 1}))
    }
}

pub struct FsGlob;

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
        let base = get_str(&p, "path", ".");

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

pub struct FsExists;

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

        let exists = tokio::fs::metadata(path).await.is_ok();
        let is_dir = tokio::fs::metadata(path).await.map(|m| m.is_dir()).unwrap_or(false);

        Ok(json!({"path": path, "exists": exists, "is_dir": is_dir}))
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
        let cwd = get_str(&p, "cwd", ".");
        let timeout_secs = get_u64(&p, "timeout_seconds", 30);

        let denylist = [
            "rm -rf /", "sudo", "chmod 777", "> /dev/", "mkfs",
            "dd if=/dev/zero", ":(){ :|:& };:",
        ];
        for blocked in &denylist {
            if command.contains(blocked) {
                return Err(anyhow!("command blocked by denylist: {}", blocked));
            }
        }

        let cmd_lower = command.to_lowercase();
        let is_dangerous = DANGEROUS_COMMANDS.iter().any(|d| cmd_lower.contains(d));
        if is_dangerous && !self.security.unsafe_mode {
            return Err(anyhow!(
                "dangerous command '{}' requires --unsafe flag (security.unsafe_default=false)",
                command
            ));
        }
        if is_dangerous && self.security.allowlist_hosts.is_empty() {
            return Err(anyhow!(
                "dangerous command '{}' requires --allowlist-hosts (allowlist empty)",
                command
            ));
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