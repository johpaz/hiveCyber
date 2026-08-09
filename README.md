# hiveCyber

Harness de ciberseguridad en Rust con agentes de larga duracion, inspirado en [Hive](https://github.com/johpaz/hive-agents).

## Estado: MVP funcional

| Componente | Tests | Estado |
|---|---|---|
| Workspace Cargo (7 crates) | — | `cargo build --release` OK |
| HiveDB documental (15 collections) | 10 | insert/get/delete/list/overwrite |
| ProviderRegistry (16+ providers) | 29 | Anthropic/Gemini/Ollama custom + 13 OpenAI-compat |
| ToolRegistry (32 tools) | 27 | base/recon/vulns/exploit/forensics |
| SkillLoader (17 skills bundled) | 8 | YAML frontmatter + walkdir |
| DurableQueue + DispatchLoop | 2 | enqueue/claim/complete/find_pending |
| Acceptance checks + policies | 5 | auto-pause @3, auto-disable @5, audit chain |
| Agent catalog (1+8 agents) | 6 | Caelum + 8 workers seedeados |
| **Total** | **86** | todos verdes |

## Caracteristicas

- **Agent loop de larga duracion** con durable runs, leases (30min renew 30s), checkpoints, stuck-loop detector
- **1 coordinador (Caelum) + 8 workers especializados** en cybersec
- **Delegacion paralela** coordinator->worker con acceptance checks deterministas via `checkTool`
- **32 tools**: filesystem (7), web (1), cli (1), recon (4), vulns (6), exploit (4), forensics (5), delegation (4)
- **17 skills bundled**: recon_workflow, osint_correlation, vuln_scan_workflow, cve_lookup, pwn_check, post_exploit_chain, lateral_movement, poc_reproduction, memory_analysis, log_timeline, ioc_extraction, pentest_report, cvss_scoring, threat_modeling, opsec, clean_up, persistence
- **16+ proveedores LLM**: Anthropic, OpenAI, Gemini, Ollama, Groq, Mistral, OpenRouter, DeepSeek, Kimi, Nvidia, Qwen, MinMax, Zai, ModelScope, OpencodeGo, HiveAgents
- **MCP nativo** JSON-RPC stdio (initialize + tools/list + tools/call + notifications)
- **HiveDB-style** document store en Rust (JSON-on-files + indices en RAM)
- **Worker sandbox** (caps drop en Linux) para tools de explotacion
- **Politicas de seguridad estrictas**:
  - Auto-pause @ 3 harmful strikes (`harmful > helpful`)
  - Auto-disable @ 5 harmful strikes
  - Allowlist de hosts obligatoria (CIDR IPv4/IPv6) para explotacion
  - Modo dual default-OFF: `--unsafe-mode` + `--allowlist-hosts <file>`
  - Session timeout exploit 15min idle
  - Audit log inmutable con SHA-256 hash chain
  - Cadena de custodia forense (hash + timestamp) en volatility
  - Denylist hardcoded: `rm -rf /`, `sudo`, `chmod 777`, `mkfs`, fork bomb
- **CLI** interactivo (`hivecyber chat`) y no-interactivo (`hivecyber run`)

## Instalacion

```bash
cd hiveCyber
cargo build --release
# binarios en target/release/hivecyber y target/release/hivecyber-worker
```

## Uso rapido

```bash
# Chat interactivo con Caelum (coordinador)
hivecyber chat

# Ejecutar una mision
hivecyber run "Escanea 10.0.0.0/24 y reporta hallazgos"

# Modo explotacion (requiere --unsafe + allowlist)
hivecyber run "Explota 10.0.0.5 con EternalBlue" --unsafe-mode --allowlist-hosts targets.txt

# Gestion de agentes
hivecyber agent list
hivecyber agent show recon_operator
hivecyber agent enable exploit_operator

# Skills
hivecyber skills list
hivecyber skills show pwn_check

# MCP
hivecyber mcp list
hivecyber mcp connect my-server

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
| `exploit_operator` | worker | explotacion | seccomp+netns |
| `forensics_analyst` | worker | forense + cadena de custodia | none |
| `web_pentester` | worker | pentesting web | seccomp+netns |
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
- [docs/mcp.md](docs/mcp.md) — MCP JSON-RPC nativo, stdio transport, lifecycle
- [docs/delegation.md](docs/delegation.md) — Coordinator->worker, DurableQueue, JobDoc, acceptance checks
- [docs/security.md](docs/security.md) — Politicas estrictas, allowlist, auto-pause/disable, audit log, sesssion timeout
- [docs/providers.md](docs/providers.md) — 16+ providers, trait LlmProvider, OpenAI-compat adapter
- [docs/cli.md](docs/cli.md) — Comandos CLI completos

## Testing

```bash
cargo test --release
# 86 tests, 0 failures
```

## Licencia

MIT