# Tools

## Registro

`crates/hivecyber-tools/src/registry.rs` define:

```rust
#[async_trait]
pub trait Tool: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn category(&self) -> ToolCategory;
    fn parameters(&self) -> ToolSchema;
    fn main_thread_only(&self) -> bool { false }
    fn isolation(&self) -> Isolation { Isolation::None }
    async fn execute(&self, params: serde_json::Value) -> Result<serde_json::Value>;
}

pub struct ToolRegistry {
    tools: HashMap<String, Arc<dyn Tool>>,
}
```

API:
- `ToolRegistry::create_all()` -> registry con todas las tools (SecurityContext default)
- `ToolRegistry::create_with_security(sec)` -> registry con SecurityContext custom
- `registry.get("nmap")` -> `Option<Arc<dyn Tool>>`
- `registry.filter_by_allowlist(&["fs_*", "nmap"])` -> expands globs, return names

## Categorias

| categoria | tools | descripcion |
|---|---|---|
| Base | fs_read, fs_write, fs_edit, fs_glob, fs_exists, web_fetch, cli_exec | filesystem y web basico |
| Recon | nmap, dig, whois, theharvester | reconocimiento activo y OSINT |
| Vulns | nuclei, nikto, sqlmap, searchsploit, semgrep, trivy | deteccion de vulnerabilidades |
| Exploit | metasploit_rpc, hydra, crackmapexec, mimikatz | explotacion (Sandbox) |
| Forensics | volatility, yara_scan, zeek_parse, osquery, log_parse | forense + cadena de custodia |
| Web | (pendiente) | browser automation para web_pentester |
| Base (delegation) | task_delegate, task_status | delegacion coordinator->worker |

## SecurityContext

```rust
pub struct SecurityContext {
    pub unsafe_mode: bool,           // --unsafe-mode
    pub allowlist_hosts: Vec<String>, // --allowlist-hosts <file>
    pub operator_id: String,
}

impl SecurityContext {
    pub fn validate_target(&self, target: &str) -> Result<(), String>;
}
```

Validacion:
- Si `!unsafe_mode` -> error "requires --unsafe flag"
- Si `!validate_target_in_allowlist(target, &allowlist)` -> error "not in allowlist"
- Allowlist soporta CIDR IPv4 (`10.0.0.0/24`) e IPv6 (`fe80::/10`)

## CliExec denylist + dangerous detection

`cli_exec` tiene dos capas:

1. **Denylist hardcoded**: `rm -rf /`, `sudo`, `chmod 777`, `> /dev/`, `mkfs`, `dd if=/dev/zero`, fork bomb -> always blocked
2. **Dangerous detection**: si comando contiene `msfconsole`, `hydra`, `crackmapexec`, `mimikatz`, `hashcat`, `john`, etc -> requiere `unsafe_mode` + `allowlist_hosts` no vacia

## Tool wrappers por categoria

### Base (`tools/src/base/mod.rs`)

- `fs_read { path, offset, limit }` -> lee archivo, retorna content + total_lines
- `fs_write { path, content }` -> escribe (overwrite)
- `fs_edit { path, old, new }` -> reemplaza texto exacto (1 ocurrencia)
- `fs_glob { pattern, path }` -> walkdir + glob matching (manually impl)
- `fs_exists { path }` -> { exists, is_dir }
- `web_fetch { url, format }` -> descarga URL, strip HTML si format="text"
- `cli_exec { command, cwd, timeout_seconds }` -> ejecuta con denylist + dangerous check

### Recon (`tools/src/recon/mod.rs`)

- `nmap { target, flags, timeout_seconds }` -> valida target + cli_exec
- `dig { domain, record_type, server }` -> `dig @server domain type`
- `whois { query }` -> `whois query`
- `theharvester { domain, source }` -> OSINT

### Vulns (`tools/src/vulns/mod.rs`)

- `nuclei { target, flags }` -> `nuclei -u target`
- `nikto { target, flags }` -> `nikto -h target`
- `sqlmap { target, flags }` -> `sqlmap -u target`
- `searchsploit { query }` -> `searchsploit query` (no requiere allowlist)
- `semgrep { path, config }` -> `semgrep scan --config X path`
- `trivy { target, mode }` -> `trivy filesystem|image target`

### Exploit (`tools/src/exploit/mod.rs`)

Todas con `isolation = Sandbox` + validate_target:
- `metasploit_rpc { target, module, payload, lhost, lport, options }` -> genera .rc script + `msfconsole -r /dev/stdin`
- `hydra { target, service, users, passwords }` -> `hydra -L users -P pass target service`
- `crackmapexec { target, protocol, flags }` -> `crackmapexec proto flags target`
- `mimikatz { command }` -> `mimikatz 'command' exit` (target = localhost)

### Forensics (`tools/src/forensics/mod.rs`)

Sin sandbox, con cadena de custodia:
- `volatility { dump, plugin }` -> `vol -f dump plugin` + SHA-256 hash + timestamp
- `yara_scan { rules, target }` -> `yara -r rules target`
- `zeek_parse { log, filter }` -> `cat log | jq -c filter`
- `osquery { query }` -> `osqueryi --json "query"`
- `log_parse { file, regex, limit }` -> `grep -P regex file | head -limit`

### Delegation (`tools/src/delegation/mod.rs`)

- `task_delegate { worker_id, task_description, mode, acceptance }` -> crea TaskDoc + JobDoc en DurableQueue
- `task_status { task_id }` -> (pendiente)

## Worker bin sandboxed

`crates/hivecyber-worker/src/main.rs` es un bin separado:
- Lee JSON por stdin: `{job_id, tool_name, args}`
- Ejecuta via `ToolRegistry::create_all()` (SecurityContext default, sin unsafe)
- Aplica `caps::clear(None, CapSet::Effective)` en Linux (pendiente seccomp + landlock)
- Escribe JSON response por stdout: `{job_id, success, result, error}`

## ExecuteToolBatch (`core/src/tool_runtime/batch.rs`)

Punto de entrada desde agent loop:

```rust
pub async fn execute_tool_batch(
    tool_calls: Vec<(String, serde_json::Value)>,
    registry: &ToolRegistry,
    timeout_ms: u64,
) -> Vec<ToolBatchResult>
```

- Por cada (name, args): lookup en registry, spawn tokio::time::timeout, return ToolBatchResult
- `ToolBatchResult { tool_name, success, result, duration_ms, error }`