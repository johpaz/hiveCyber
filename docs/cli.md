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
  provider  Configurar providers, API keys (cifradas) y modelos
  skills    Listar/ver/instalar skills
  mcp       Gestion de MCP servers
  config    Ver/editar config
  logs      Tail de traces
  runs      Lista runs (para descubrir un run_id que reanudar)
  resume    Retomar run durable interrumpido
  doctor    Verificar dependencias cybersec instaladas
  egress-rules  Genera firewall nftables (default-deny) desde la EngagementPolicy
  audit     Audit log tamper-evident
  version   Version del binario
  help      Print help

Options:
  --unsafe-mode               Activa modo inseguro (requerido para exploit)
  --allowlist-hosts <FILE>    Archivo con allowlist de hosts (CIDR o exactos)
  --engagement-policy <FILE>  EngagementPolicy JSON (exclusiones, actividades prohibidas,
                               ventanas horarias, rate_limit_rps, aprobacion humana) —
                               si se pasa, prevalece sobre --allowlist-hosts
  --require-policy             Gate obligatorio: rechaza operar sin una EngagementPolicy
                               valida (recomendado para bug bounty)
  --allow-cli-exec             Habilita la tool cli_exec (desactivada por defecto,
                               requiere ademas --unsafe-mode)
  --approve-human <CATEGORY>   Marca una categoria de EngagementPolicy como aprobada
                               por humano (repetible)
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
hivecyber agent disable <id>          # desactiva un agente
hivecyber agent set-model <id> <model>      # fija el modelo (vacio "" → default global)
hivecyber agent set-provider <id> <provider># fija el provider del agente
```

Seed automatico en primer `chat` o `run`:
- 1 coordinator `caelum` (system_prompt con instrucciones de delegacion)
- 8 workers con tool_allowlist, default_acceptance, workspace_scope, model_override (algunos)

### provider

```bash
# Guarda la API key (cifrada AES-256-GCM) + base-url/modelo opcionales
hivecyber provider set hiveagents --api-key <KEY> --model Qwen3.6-35B-A3B-UD-Q4_K_M.gguf
hivecyber provider set openai --base-url https://proxy.local/v1

hivecyber provider list               # tabla: provider, key set?, default, modelo
hivecyber provider show <id>          # config de un provider (key enmascarada)
hivecyber provider default <id> [--model <m>]   # provider/modelo por defecto
```

Las keys se cifran con una master key en `<home>/.master.key` (0600, autogenerada)
o `HIVECYBER_MASTER_KEY`. Precedencia de resolución: variable de entorno del
provider → secret store cifrado. Una vez configurado, `run`/`chat` funcionan **sin
exportar env vars**. Los defaults (`provider default`) se guardan en la colección
`settings` y se aplican al arrancar.

### models

```bash
hivecyber models                      # catálogo completo: provider, model, ctx, costo USD/1M
hivecyber models --provider hiveagents
```

Espejo del catálogo de Hive (89 modelos LLM) sembrado en `COL_MODELS` con `context_window`
e `input/output_per_1m`. El **context window por modelo** determina el presupuesto de
compaction del loop (ver `docs/agent-loop.md`); el costo alimenta reportes de gasto.

### skills

```bash
hivecyber skills list                 # tabla: name, category, version, description
hivecyber skills show <name>          # JSON completo
hivecyber skills reload               # recarga del disco
hivecyber skills add <path>           # instala una skill (copia el dir con SKILL.md
                                       # al managed dir) y recarga
```

Carga desde `skills/bundled/` (relativo al crate CLI en dev) + `<home>/skills/` (managed).

### mcp

```bash
# stdio
hivecyber mcp add fs --transport stdio --command npx \
  --arg -y --arg @modelcontextprotocol/server-filesystem --arg /tmp
# sse / streamable-http
hivecyber mcp add remote --transport sse --url https://api.example.com/mcp \
  --header "Authorization=Bearer token123"

hivecyber mcp list                    # servers registrados + status
hivecyber mcp connect <name>          # conecta y lista sus tools
hivecyber mcp tools [name]            # tools de un server (o de todos)
hivecyber mcp call <name> <tool> '<json>'
hivecyber mcp disconnect <name>
hivecyber mcp remove <name>
```

Los servers se persisten en la colección `mcp_servers` y se conectan
automáticamente al iniciar `chat`/`run` (sus tools se exponen al agente vía
`McpToolProxy`). Ver `docs/mcp.md`.

### config

```bash
hivecyber config show                 # JSON completo de la config
```

Config via env vars (prevalecen sobre `settings` persistidos):
- `HIVECYBER_HOME` — directorio base (default `~/.hivecyber/` o `~/.local/share/hivecyber/`)
- `HIVECYBER_HOST` / `HIVECYBER_PORT` — pendiente de usar (no hay gateway)
- `HIVECYBER_DEFAULT_PROVIDER` — provider por defecto (o usa `provider default`)
- `HIVECYBER_DEFAULT_MODEL` — modelo por defecto (vacío → default del provider)
- `HIVECYBER_MASTER_KEY` — master key (base64/hex de 32 bytes) para el secret store;
  si falta, se genera `<home>/.master.key` (0600)
- `HIVECYBER_MCP_ENABLED` — true/false
- API keys por provider: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GOOGLE_API_KEY`, etc
  (o guárdalas cifradas con `provider set`; ver `.env.example`)

### logs

```bash
hivecyber logs
```

Lista `traces` de HiveDB (ultimas 50):
```
[id] tool_name OK|FAIL durationMs
```

### runs

```bash
hivecyber runs                        # RUN_ID, STATUS, AGENT, KIND, iteraciones, tokens
```

El loop del coordinador persiste un **run durable por hilo** (`ensure_run`), lo checkpointea
cada turno (iteraciones + tokens + lease de 30 min) y lo marca `completed` al terminar o
`interrupted` si el proceso/LLM falla. `runs` los lista (más recientes primero) para encontrar
un `run_id` interrumpido que reanudar.

### resume

```bash
hivecyber resume <run_id>
```

Retoma un run durable interrumpido:
- Lee el `RunDoc` de HiveDB, extrae `agent_id` y `thread_id`
- **Rehidrata el historial** del hilo desde `COL_MESSAGES` (turnos user/assistant en orden
  cronológico; los turnos con tools no se persisten, así que no hay `tool_result` huérfanos)
  y continúa con `AgentLoop::run()` (`rehydrate: true`)
- Pendiente: checkpoints/estado del run para reanudar mitad-de-turno con tools en vuelo

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
| `--engagement-policy <FILE>` | EngagementPolicy JSON (superset del allowlist: exclusiones, actividades prohibidas, aprobacion humana) — prevalece sobre `--allowlist-hosts` si ambos se pasan |
| `--allow-cli-exec` | Habilita la tool `cli_exec`, desactivada por defecto — independiente de `--unsafe-mode` |
| `--approve-human <CATEGORY>` | Registra aprobacion humana para una `ApprovalCategory` de EngagementPolicy (repetible) |

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