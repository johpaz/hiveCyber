# hiveCyber

Harness de ciberseguridad en Rust con agentes de larga duracion, inspirado en [Hive](https://github.com/johpaz/hive-agents).

## Estado: endurecido · pre-producción para bug bounty

El núcleo (harness, delegación, sandbox seccomp, auditoría tamper-evident, BM25) está
implementado y testeado. **Antes de operar contra programas reales (Bugcrowd/HackerOne)**
faltan controles de seguridad de engagement listados en el [Roadmap de seguridad](#roadmap-de-seguridad-pre-bug-bounty).

| Componente | Tests | Estado |
|---|---|---|
| Workspace Cargo (7 crates) | — | `cargo build --release` OK |
| HiveDB documental (15 collections) | 10 | insert/get/delete/list/overwrite |
| ProviderRegistry (16 providers, base URLs/modelos alineados a Hive) | 31 | Anthropic/Gemini/Ollama custom + OpenAI-compat + hiveagents |
| ToolRegistry (38 tools base) + `cli_exec` gating | 29+ | base/recon/vulns/exploit/forensics/web/office, `--allow-cli-exec` |
| SkillLoader (17 skills bundled) | 8 | YAML frontmatter + walkdir |
| DurableQueue + DispatchLoop | 2 | enqueue/claim/complete/find_pending |
| Acceptance checks + policies | 5 | auto-pause @3, auto-disable @5, audit chain |
| Agent catalog (1+8 agents) | 6 | Caelum + 8 workers seedeados |
| ToolMiddleware (audit fail-closed + sandbox routing) | 4 | audit obligatorio en loop interactivo **y** workers; E2E contra `hivecyber-worker` real |
| EngagementPolicy (`tools/src/engagement.rs`) | 18 | host matching exacto/subdominio/CIDR v4+v6, exclusiones, glob de paths |
| Worker sandbox (`hivecyber-worker/src/sandbox.rs`) | 8 | seccomp allowlist funcional (arranca y ejecuta), rlimits, namespaces best-effort |
| Búsqueda BM25 de capacidades (`agent/capability_search.rs` + tool/catalog selector) | 14 | tantivy, tokenizer ES, tool-selector (máx 12/turno) enganchado al loop, routing_exclusions |
| **Total** (`cargo test --workspace`) | **187** | todos verdes |

## Caracteristicas

- **Agent loop de larga duracion** con **run durable por hilo** (`ensure_run`/`checkpoint_run`/`interrupt_run`, discovery con `hivecyber runs`, `resume` rehidrata desde `COL_MESSAGES`), leases (30min), stuck-loop detector y **compaction de contexto** (resume el working-set en memoria por presupuesto de tokens sin tocar el historial durable `COL_MESSAGES`, con corte seguro de pares tool_use/tool_result)
- **1 coordinador (Caelum) + 8 workers especializados** en cybersec
- **Delegacion paralela** coordinator->worker con acceptance checks deterministas via `checkTool`
- **38 tools base** (ToolRegistry): filesystem (7: read/write/edit/glob/exists/list/delete), web (2: fetch/search), cli (1), recon (6: nmap/dig/whois/theharvester/shodan/recon_ng), vulns (6), exploit (4), forensics (5), browser (5: navigate/click/type/screenshot/extract vía `agent-browser`), office (2: read/write docx/xlsx/pdf). **+8 tools de agente** registradas en el loop: delegation (4: delegate/status/list/revise) y memory (4: write/read/list/search) — **más los tools MCP expuestos dinámicamente**
- **Búsqueda dinámica BM25/tantivy (trilogía completa, paridad con `capability-search` de Hive)**: `tool-selector` (máx 12 tools/turno, corto-circuito conversacional), `catalog-selector` (rutea workers, respeta `routing_exclusions` — inyectado **en vivo** al prompt del coordinador vía `routing_context`), y `skill-selector` (surface de skills relevantes a la tarea, en coordinador y workers). Menos tokens, mejor precisión y ruteo.
- **17 skills bundled**: recon_workflow, osint_correlation, vuln_scan_workflow, cve_lookup, pwn_check, post_exploit_chain, lateral_movement, poc_reproduction, memory_analysis, log_timeline, ioc_extraction, pentest_report, cvss_scoring, threat_modeling, opsec, clean_up, persistence
- **16+ proveedores LLM**: Anthropic, OpenAI, Gemini, Ollama, Groq, Mistral, OpenRouter, DeepSeek, Kimi, Nvidia, Qwen, MinMax, Zai, ModelScope, OpencodeGo, HiveAgents
- **Catálogo de modelos (espejo de Hive)**: 89 modelos LLM sembrados en `COL_MODELS` con provider, **context window** y **costo** (USD/1M in/out) — fuente única de verdad. El **budget de compaction se deriva del ctx real por modelo** (no un valor fijo); `hivecyber models` lista el catálogo.
- **MCP nativo** JSON-RPC con transportes **stdio + streamable-HTTP/SSE + WebSocket** (`wss://` vía rustls) y **reconnect con backoff** en sesiones caídas; los servers se persisten (`mcp_servers`), se conectan en boot y sus tools se exponen al agente vía `McpToolProxy` (entran al tool-selector BM25). CLI completa (`mcp add/list/connect/tools/call/disconnect/remove`).
- **Configuración persistente y segura**: `provider set/list/show/default`, `agent set-model/set-provider/disable`, `skills add`. Las API keys se guardan **cifradas (AES-256-GCM)** con master key en `<home>/.master.key` (0600); una vez configurado, corre sin env vars.
- **HiveDB-style** document store en Rust (JSON-on-files + indices en RAM)
- **Worker sandbox real** (`hivecyber-worker`): seccomp BPF allowlist + rlimits + drop de capabilities + namespaces de usuario/mount, para las tools de explotacion (`isolation = Sandbox`). El `SecurityContext` del llamador viaja al subproceso — el sandbox no usa un contexto por defecto.
- **ToolMiddleware**: audita (hash-chain SHA-256) toda ejecucion de tool, exitosa o fallida, fail-closed si el audit log no puede escribirse
- **EngagementPolicy**: allowlist/exclusiones por host o CIDR, actividades prohibidas, categorias que requieren aprobacion humana (`--engagement-policy <file.json>`)
- **Politicas de seguridad estrictas**:
  - Auto-pause @ 3 harmful strikes (`harmful > helpful`)
  - Auto-disable @ 5 harmful strikes
  - Allowlist de hosts obligatoria (CIDR IPv4/IPv6) para explotacion
  - Modo dual default-OFF: `--unsafe-mode` + `--allowlist-hosts <file>` (o `--engagement-policy <file>`)
  - `cli_exec` desactivado por defecto, requiere `--allow-cli-exec` ademas de `--unsafe-mode`
  - Session timeout exploit 15min idle
  - Audit log **tamper-evident** con SHA-256 hash chain (append atómico bajo lock global — sin bifurcaciones concurrentes)
  - Cadena de custodia forense (hash + timestamp) en volatility
  - Denylist hardcoded: `rm -rf /`, `sudo`, `chmod 777`, `mkfs`, fork bomb
- **CLI** interactivo (`hivecyber chat`) y no-interactivo (`hivecyber run`)

## Roadmap

Funcionalidad planificada, aún no implementada (el resto del harness es funcional y testeado):

- **Reanudar mitad-de-turno con tools en vuelo**: el loop del coordinador ya persiste un run durable por hilo (`ensure_run`/`checkpoint_run`/`interrupt_run`, comando `runs`) y `resume` rehidrata el historial desde `COL_MESSAGES`; falta capturar el estado de un turno interrumpido con llamadas a tools a medio ejecutar (hoy se reanuda desde el último mensaje limpio).
- **Browser dentro del sandbox**: los `browser_*` corren in-process vía `agent-browser` (Chrome en su propio subproceso); no se rutean al worker seccomp. Confinar el browser requeriría reingeniería del sandbox.
- **Sandbox real en macOS/Windows**: hoy las tools `Isolation::Sandbox` se rechazan fail-closed fuera de Linux (opt-in `HIVECYBER_ALLOW_UNSANDBOXED=1`). Un confinamiento nativo (Seatbelt en macOS, Job Objects/AppContainer en Windows) permitiría ejecutarlas confinadas sin Docker.

## Instalacion

```bash
cd hiveCyber
cargo build --release
# binarios en target/release/hivecyber y target/release/hivecyber-worker
```

## Distribución (multi-SO)

hiveCyber compila en **Linux, macOS y Windows** (los deps unix del sandbox están
target-gated a Linux). Canales:

- **Binarios precompilados** por plataforma en GitHub Releases (tag `v*` → matriz
  linux x86_64/aarch64, macOS Intel/ARM, Windows x64). Ver `.github/workflows/release.yml`.
- **Docker** (recomendado para el toolchain completo): `docker build -t hivecyber .`
  — imagen batteries-included con el subset de tools cybersec de Debian.
- **Desde fuente**: `cargo build --release` en cualquier SO.

> ⚠️ **Caveat de seguridad**: el sandbox del worker (seccomp/namespaces) es **Linux-only**.
> En macOS/Windows la CLI funciona, pero las tools `Isolation::Sandbox` (exploit) se
> **rechazan por defecto** (fail-closed) en vez de correr sin confinar — ejecútalas en la
> imagen Docker (Linux), o fuérzalas con `HIVECYBER_ALLOW_UNSANDBOXED=1` (inseguro).
> `hivecyber doctor` reporta la disponibilidad del sandbox. Detalle: [docs/distribution.md](docs/distribution.md).

## Casos de uso

Contextos **autorizados**: pentesting con alcance, defensa y educación. Detalle y
ejemplos por caso en [docs/use-cases.md](docs/use-cases.md).

- **Recon / mapeo de superficie** (`recon_operator`: nmap/dig/whois/theHarvester/shodan)
- **OSINT / threat intel** (`threat_intel_analyst`: shodan/web_search/theHarvester)
- **Escaneo de vulnerabilidades** (`vuln_scanner`: nuclei/nikto/sqlmap/semgrep/trivy)
- **Pentest web** con automatización de navegador (`web_pentester`: sqlmap/nuclei + browser_*)
- **Explotación autorizada / red team** (`exploit_operator`: metasploit/hydra/cme — sandbox)
- **Forense / DFIR** (`forensics_analyst`: volatility/yara/zeek/osquery/log_parse)
- **Blue team / detección** (reglas YARA, tráfico Zeek, osquery, timelines de IOCs)
- **SAST / supply-chain** (semgrep + trivy sobre código y dependencias)
- **CTF y educación** (metodología visible vía audit log + acceptance checks)
- **Informes ejecutivos/técnicos** (`report_writer`: docx/xlsx/pdf)
- **Extensión vía MCP** y **operaciones de larga duración** (memoria + delegación + resume)

## Uso rapido

```bash
# Chat interactivo con Caelum (coordinador)
hivecyber chat

# Ejecutar una mision
hivecyber run "Escanea 10.0.0.0/24 y reporta hallazgos"

# Modo explotacion (requiere --unsafe + allowlist)
hivecyber run "Explota 10.0.0.5 con EternalBlue" --unsafe-mode --allowlist-hosts targets.txt

# Configurar provider + API key (cifrada) y modelo por defecto
hivecyber provider set hiveagents --api-key <KEY> --model Qwen3.6-35B-A3B-UD-Q4_K_M.gguf
hivecyber provider default hiveagents
hivecyber provider list

# Gestion de agentes
hivecyber agent list
hivecyber agent show recon_operator
hivecyber agent enable exploit_operator
hivecyber agent set-model recon_operator qwen-max

# Skills
hivecyber skills list
hivecyber skills show pwn_check
hivecyber skills add ./my-skill        # instala una skill propia

# MCP
hivecyber mcp add fs --transport stdio --command npx \
  --arg -y --arg @modelcontextprotocol/server-filesystem --arg /tmp
hivecyber mcp list
hivecyber mcp tools fs

# Audit log
hivecyber audit show
hivecyber audit verify

# Doctor (verifica deps cybersec instalados)
hivecyber doctor

# Config
hivecyber config show
```

## Agentes

| id | rol | especialidad | sandbox |
|---|---|---|---|
| `caelum` | coordinador | descompone, delega, reintegra | none |
| `recon_operator` | worker | recon + OSINT | none |
| `vuln_scanner` | worker | deteccion de vulns | none |
| `exploit_operator` | worker | explotacion | seccomp (sin netns) |
| `forensics_analyst` | worker | forense + cadena de custodia | none |
| `web_pentester` | worker | pentesting web | seccomp (sin netns) |
| `threat_intel_analyst` | worker | threat intel + IoCs | none |
| `report_writer` | worker | informes | none |
| `workspace_file_operator` | worker | filesystem generico | none |

## Configuracion

Config via env vars. Directorio base: `~/.hivecyber/` (o `$HIVECYBER_HOME`).

```
HIVECYBER_HOME=~/.hivecyber
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
```

Ver `.env.example` para todas las API keys soportadas.

## Documentacion

- [docs/architecture.md](docs/architecture.md) — Arquitectura general + flujo del agent loop
- [docs/agent-loop.md](docs/agent-loop.md) — Loop de larga duracion, durable runs, stuck-loop, compaction
- [docs/tools.md](docs/tools.md) — Registro de tools, categorias, SecurityContext, worker sandbox
- [docs/skills.md](docs/skills.md) — Formato SKILL.md, categorias, loader, prioridad
- [docs/mcp.md](docs/mcp.md) — MCP JSON-RPC nativo, transportes stdio + SSE, tool-sync, lifecycle
- [docs/delegation.md](docs/delegation.md) — Coordinator->worker, DurableQueue, JobDoc, acceptance checks
- [docs/security.md](docs/security.md) — Politicas estrictas, allowlist, auto-pause/disable, audit log, sesssion timeout
- [docs/providers.md](docs/providers.md) — 16+ providers, trait LlmProvider, OpenAI-compat adapter
- [docs/cli.md](docs/cli.md) — Comandos CLI completos
- [docs/distribution.md](docs/distribution.md) — Distribución por SO, Docker, caveat del sandbox, deps externas
- [docs/use-cases.md](docs/use-cases.md) — Casos de uso: pentest, OSINT, forense, DFIR, blue team, CTF, reportes
- [docs/e2e.md](docs/e2e.md) — E2E contra apps vulnerables locales (Juice Shop/WebGoat/DVWA) con PolicyGate obligatorio
- [docs/egress.md](docs/egress.md) — Control de egreso de red (firewall nftables default-deny desde la EngagementPolicy)

## Testing

```bash
cargo test --workspace
# 187 tests, 0 failures
```

## Roadmap de seguridad (pre bug bounty)

Controles de *engagement* requeridos antes de operar agentes autónomos contra programas
reales (Bugcrowd/HackerOne). Estado actual entre corchetes:

- **Auditoría atómica** de la cadena hash. [✅ hecho — `append_audit` bajo lock global; test de concurrencia]
- **Ventanas horarias** de engagement. [✅ hecho — `EngagementPolicy::is_within_window`, aplicado en `validate_target`]
- **Rate limiting compartido** por programa y por destino. [✅ hecho — limiter process-global por `programa::host`, fail-closed; aplicado en `validate_target` para tools in-process]
- **PolicyGate obligatorio**: `--require-policy` **rechaza** operar sin una `EngagementPolicy`
  válida; el gate aplica allowlist/exclusiones/rutas/métodos/ventanas/rate y aprobaciones.
  [✅ hecho — modo obligatorio disponible]
- **Acceptance por evidencias estructuradas**: modelo tipado `EvidenceItem` (host, vulnerability,
  shell_session, credential, artifact, correlation, report_file, reproduction…); los tools/workers
  pueden emitir evidencia JSON explícita y los verificadores asertan sobre ella; el texto legado se
  deriva a items tipados (compatibilidad). [✅ hecho]
- **E2E contra apps vulnerables locales** (Juice Shop, WebGoat, DVWA): `e2e/docker-compose.yml` +
  `e2e/engagement-policy.json` + `e2e/run-e2e.sh` (ver `docs/e2e.md`). Scaffolding validado (target
  arranca y responde; harness carga política + pasa el gate); el paso con LLM requiere una key.
  [✅ hecho]
- **Control de egreso de red fuera del proceso** (firewall nftables default-deny a nivel de kernel,
  generado desde la política): `hivecyber egress-rules --engagement-policy <f>` produce el ruleset
  (solo targets + DNS + infra permitida); entrypoint Docker opt-in que lo aplica como root y baja a
  `hive` (`--cap-add=NET_ADMIN`). Protocolo-agnóstico (cubre nmap/hydra/dig/HTTP y el subproceso
  worker). [✅ hecho — ver `docs/egress.md`. Roadmap: separación agente/tools por cgroup]

## Licencia

MIT