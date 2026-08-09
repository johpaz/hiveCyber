# CLI

## Binario

```bash
cargo build --release
# target/release/hivecyber
# target/release/hivecyber-worker
```

Completar install (opcional):
```bash
cp target/release/hivecyber ~/.local/bin/
cp target/release/hivecyber-worker ~/.local/bin/
```

## Subcomandos

```bash
hivecyber [OPTIONS] <COMMAND>

Commands:
  chat      REPL interactivo con el coordinador
  run       Invocacion unica (no-interactiva)
  agent     Gestion de agentes
  skills    Listar/ver skills
  mcp       Gestion de MCP servers
  config    Ver/editar config
  logs      Tail de traces
  resume    Retomar run durable interrumpido
  doctor    Verificar dependencias cybersec instaladas
  audit     Audit log inmutable
  version   Version del binario
  help      Print help

Options:
  --unsafe-mode               Activa modo inseguro (requerido para exploit)
  --allowlist-hosts <FILE>    Archivo con allowlist de hosts (CIDR o exactos)
```

### chat

```bash
hivecyber chat [--agent caelum]
hivecyber chat --unsafe-mode --allowlist-hosts targets.txt
```

Comportamiento:
1. Abre HiveDB en `~/.hivecyber/db/` (o `$HIVECYBER_HOME/db/`)
2. Si no hay agentes seedeados, crea Caelum + 8 workers (auto-seed)
3. Spawnea `DispatchLoop` en background (procesa `worker_task` jobs cada 500ms)
4. Lee de stdin en loop, por cada linea:
   - Construye `AgentLoopOptions` con `agent_id`, `user_message`, `thread_id`, `max_iter=10`, `security`
   - Llama `AgentLoop::run()`
   - Consuma stream chunks: `Agent { text }` -> stdout, `ToolCall/ToolResult/Usage` -> stderr, `Done { final_text }` -> println
5. `exit` o EOF para salir

### run

```bash
hivecyber run "<prompt>" [--agent caelum]
hivecyber run "Escanea 10.0.0.0/24" --unsafe-mode --allowlist-hosts targets.txt
```

Como `chat` pero una sola invocacion, no interactiva.

### agent

```bash
hivecyber agent list                  # tabla: id, name, role, enabled, description
hivecyber agent show <id>             # JSON completo del agente
hivecyber agent enable <id>           # re-activa agente pausado/disabled
```

Seed automatico en primer `chat` o `run`:
- 1 coordinator `caelum` (system_prompt con instrucciones de delegacion)
- 8 workers con tool_allowlist, default_acceptance, workspace_scope, model_override (algunos)

### skills

```bash
hivecyber skills list                 # tabla: name, category, version, description
hivecyber skills show <name>          # JSON completo
hivecyber skills reload               # recarga del disco
```

Carga desde `skills/bundled/` (relativo al crate CLI en dev, pendiente absoluto en release) + `~/.hivecyber/skills/` (managed).

### mcp

```bash
hivecyber mcp list                    # servers registrados + status
hivecyber mcp connect <name>          # intenta conectar
```

Pendiente: Registrar servers desde config al iniciar `chat`.

### config

```bash
hivecyber config show                 # JSON completo de la config
```

Config via env vars:
- `HIVECYBER_HOME` — directorio base (default `~/.hivecyber/` o `~/.local/share/hivecyber/`)
- `HIVECYBER_HOST` / `HIVECYBER_PORT` — pendiente de usar (no hay gateway)
- `HIVECYBER_DEFAULT_PROVIDER` — pendiente wire
- `HIVECYBER_MCP_ENABLED` — true/false
- API keys por provider: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GOOGLE_API_KEY`, etc (ver `.env.example`)

### logs

```bash
hivecyber logs
```

Lista `traces` de HiveDB (ultimas 50):
```
[id] tool_name OK|FAIL durationMs
```

### resume

```bash
hivecyber resume <run_id>
```

Retoma un run durable interrumpido:
- Lee el `RunDoc` de HiveDB
- Extrae `agent_id` y `thread_id`
- Spawnea nuevo `AgentLoop::run()` con mensaje "Continua la operacion..."
- Pendiente: reconstruir messages desde HiveDB en lugar de empezar de cero

### doctor

```bash
hivecyber doctor
```

Verifica 16 binarios cybersec:
```
hivecyber doctor — verificando dependencias:

  [MISSING] nmap (nmap)
  [MISSING] nuclei (nuclei)
  ...
  [OK] whois (whois)

X tools found, Y missing
```

Tools verificadas:
- nmap, nuclei, sqlmap, metasploit (msfconsole), searchsploit, nikto, theHarvester, shodan, volatility3 (vol), yara, zeek, osquery (osqueryi), semgrep, trivy, hydra, crackmapexec

### audit

```bash
hivecyber audit show                   # lista ultimas 100 entradas
hivecyber audit verify                 # valida hash chain SHA-256
```

Ejemplo:
```
[2024-01-15T10:23:01Z] abc123 nmap target=10.0.0.5 worker=recon_operator
[2024-01-15T10:24:05Z] def456 hydra target=10.0.0.5 worker=exploit_operator
```

`verify` retorna:
```
Audit log chain: VERIFIED (all hashes valid)
# o
Audit log chain: BROKEN (2 errors)
  - entry abc123: hash chain broken (expected xxx got yyy)
```

### version

```bash
hivecyber version
# hivecyber 0.1.0
```

## Flags de seguridad

| flag | effect |
|---|---|
| `--unsafe-mode` | Habilita tools peligrosas (hydra, msf, mimikatz, cme) — default `false` |
| `--allowlist-hosts <FILE>` | Carga hosts/CIDRs desde archivo — required para exploit |

Formato del archivo:
```
# comments allowed
10.0.0.0/24
192.168.1.0/24
fe80::/10
example.com
```

## Ejemplos completos

```bash
# Chat simple con Caelum
hivecyber chat

# Correr mision
hivecyber run "Escanea 10.0.0.0/24 con nmap y reporta servicios"

# Pentest autorizado
echo "10.0.0.0/24" > /tmp/targets.txt
hivecyber run "Explota 10.0.0.5 con EternalBlue (CVE-2017-0144)" \
  --unsafe-mode --allowlist-hosts /tmp/targets.txt

# Forense
hivecyber run "Analiza memoria del dump /tmp/memdump.raw con volatility"

# Gestion
hivecyber agent list
hivecyber agent show exploit_operator
hivecyber agent enable exploit_operator   # tras auto-pause

# Skills
hivecyber skills list
hivecyber skills show pwn_check

# Audit
hivecyber audit show
hivecyber audit verify

# Dependencias
hivecyber doctor

# Config
hivecyber config show
```