# Security: politicas estrictas cybersec

## Filosofia

hiveCyber aplica politicas de seguridad **mas estrictas que Hive** porque las tools de ciberseguridad *(explotacion, credential dumping, brute force)* son intrinsecamente peligrosas. Hive solo proponia acciones humanas; hiveCyber aplica automaticas.

## Modo dual default-OFF

Las tools con `isolation = Sandbox` (exploit_operator, web_pentester) Y las comandos peligrosos en `cli_exec` no ejecutan por defecto. Requieren flags explicitos:

```bash
hivecyber chat --unsafe-mode --allowlist-hosts /path/targets.txt
hivecyber run "Exploita 10.0.0.5 con EternalBlue" --unsafe-mode --allowlist-hosts targets.txt
```

### CliExec dangerous detection (`tools/src/base/mod.rs`)

```rust
const DANGEROUS_COMMANDS: &[&str] = &[
    "msfconsole", "msfrpc", "msfvenom",
    "hydra", "medusa",
    "crackmapexec", "cme", "nxc",
    "mimikatz", "sekurlsa", "lsadump",
    "hashcat", "john",
];

if is_dangerous && !self.security.unsafe_mode {
    return Err("requires --unsafe flag");
}
if is_dangerous && self.security.allowlist_hosts.is_empty() {
    return Err("requires --allowlist-hosts (allowlist empty)");
}
```

### Denylist hardcoded (always blocked)

```rust
const DENYLIST: &[&str] = &[
    "rm -rf /", "sudo", "chmod 777", "> /dev/", "mkfs",
    "dd if=/dev/zero", ":(){ :|:& };:",   // fork bomb
];
```

## Allowlist de hosts

Cargada via `--allowlist-hosts <file>` (un host o CIDR por linea):

```
# /home/op/targets.txt
10.0.0.0/24
192.168.1.0/24
fe80::/10
example.com
```

Implementacion (`tools/src/registry.rs`):

```rust
pub fn validate_target_in_allowlist(target: &str, allowlist: &[String]) -> bool {
    for entry in allowlist {
        if entry.contains('/') {                     // CIDR
            // parse + match IPv4 or IPv6
        } else if entry == target || ... {            // exact match
            return true;
        }
    }
    false
}
```

Soporta:
- IPv4 CIDR: `10.0.0.0/24` cubre `10.0.0.0` a `10.0.0.255`
- IPv6 CIDR: `fe80::/10` cubre link-local
- Hostname exacto: `example.com`
- Suffix match: `targets.txt` con `example.com` cubre `example.com`

### Propagacion

El `SecurityContext` viaja desde el CLI (`build_security_context` en `main.rs`):

```rust
fn build_security_context(cli: &Cli) -> Arc<SecurityContext> {
    let mut allowlist = Vec::new();
    if let Some(ref allowlist_path) = cli.allowlist_hosts {
        let content = std::fs::read_to_string(allowlist_path)?;
        for line in content.lines() {
            let entry = line.trim();
            if entry.is_empty() || entry.starts_with('#') { continue; }
            allowlist.push(entry.to_string());
        }
    }
    Arc::new(SecurityContext {
        unsafe_mode: cli.unsafe_mode,
        allowlist_hosts: allowlist,
        operator_id: std::env::var("USER")?,
    })
}
```

Despues se propaga a:
- `AgentLoop` (via `AgentLoopOptions.security`)
- `ToolRegistry::create_with_security(security)` para construir todas las tools con este contexto
- `WorkerTaskExecutor::with_security(security)` para que los workers respeten el mismo contexto
- `DispatchLoop::with_security(security)`

## Auto-pause / auto-disable (`core/src/security/policies.rs`)

```rust
pub async fn increment_harmful(db: &HiveDb, agent_id: &str) -> Result<()> {
    let mut agent = db.get(COL_AGENTS, agent_id).await?;
    let harmful = agent.harmful_count + 1;
    let helpful = agent.helpful_count;

    agent.harmful_count = harmful;
    agent.updated_at = now;

    // Auto-pause: 3 harmful > helpful
    if harmful >= 3 && harmful > helpful {
        agent.enabled = false;
    }

    // Auto-disable: 5 harmful
    if harmful >= 5 {
        agent.enabled = false;
        agent.status = "auto_disabled";
    }

    db.insert(COL_AGENTS, agent_id, agent).await?;
}

pub async fn increment_helpful(db: &HiveDb, agent_id: &str) -> Result<()> {
    let mut agent = db.get(COL_AGENTS, agent_id).await?;
    agent.helpful_count += 1;
    db.insert(COL_AGENTS, agent_id, agent).await?;
}
```

Llamados por `WorkerTaskExecutor`:
- `acceptance_checks.verdict == Failed` -> `increment_harmful(worker_id)`
- `acceptance_checks.verdict == Passed | Unchecked` -> `increment_helpful(worker_id)`

### Re-activacion

```bash
hivecyber agent enable exploit_operator
```

Verifica el doc en HiveDB, setea `enabled=true`, `status=active`.

## Audit log inmutable (`core/src/security/audit.rs`)

Coleccion HiveDB `audit_log` con hash chain SHA-256:

```rust
pub struct AuditLogEntry {
    pub id: String,
    pub timestamp: String,           // ISO-8601
    pub tool: String,
    pub target: String,
    pub worker: String,
    pub run_id: String,
    pub operator_id: String,
    pub hash_chain_prev: String,      // hash de la entrada anterior
}

pub async fn log_audit(db, tool, target, worker, run_id, operator_id, prev_hash) -> Result<String> {
    let entry = AuditLogEntry { ... };
    let current_hash = sha256(prev_hash + timestamp + tool + target + worker + run_id + operator_id);
    db.insert(COL_AUDIT_LOG, &id, entry).await?;
    Ok(current_hash)
}

pub async fn verify_chain(db) -> Result<(bool, Vec<String>)> {
    let mut entries = db.list(COL_AUDIT_LOG).await;
    entries.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));   // cronologico

    let mut prev_hash = "0".repeat(64);   // genesis
    for (id, val) in &entries {
        let entry: AuditLogEntry = serde_json::from_value(val)?;
        if entry.hash_chain_prev != prev_hash {
            errors.push(format!("entry {}: hash chain broken", id));
        }
        prev_hash = compute_current_hash(&entry);
    }

    Ok((errors.is_empty(), errors))
}
```

CLI:
```bash
hivecyber audit show            # lista entradas
hivecyber audit verify          # valida cadena entera
```

## Cadena de custodia forense (`tools/src/forensics/mod.rs`)

`volatility` retorna `custody` con cada ejecucion:
```json
{
  "command": "vol -f dump.raw windows.pslist",
  "exit_code": 0,
  "stdout": "...",
  "custody": {
    "sha256": "abc123...",
    "timestamp_acquired": "2024-01-15T10:23:01Z",
    "command": "vol -f dump.raw windows.pslist"
  }
}
```

Necesario para evidencia forense admisible.

## ExploitSessionTracker (`core/src/security/sessions.rs`)

```rust
pub const DEFAULT_SESSION_TIMEOUT_MINUTES: u64 = 15;

pub struct ExploitSessionTracker {
    timeout: Duration,                                 // 15 min
    inner: Arc<Mutex<HashMap<String, Session>>>,
}

impl ExploitSessionTracker {
    pub async fn record_activity(&self, worker_id, target) -> bool;  // false si paused
    pub async fn check_timeouts(&self) -> Vec<String>;                // pause las inactivas
    pub async fn resume(&self, worker_id, target) -> bool;
    pub async fn clear(&self, worker_id, target);
    pub async fn list_active(&self) -> Vec<(worker_id, target, paused)>;
}

pub async fn periodic_timeout_check(tracker: Arc<ExploitSession tracker>) {
    // cada 30s, check_timeouts (pendiente spawn en cmd_chat)
}
```

## Resumen politicas

|Politica | Umbral | Accion |
|---|---|---|
| auto-pause | `harmful_count >= 3 && harmful > helpful` | `enabled = false` inmediato |
| auto-disable | `harmful_count >= 5` | `enabled = false, status = auto_disabled` |
| Allowlist enforcement | target no en allowlist | error sin invocar binario |
| Dual mode | `!unsafe_mode` o `!allowlist` | error sin invocar |
| Audit log | toda ejecucion peligrosa | append en `audit_log` con hash chain |
| Forensic custody | volatility output | SHA-256 + timestamp + command |
| Session timeout | 15min inactivo | paused, requiere resume |