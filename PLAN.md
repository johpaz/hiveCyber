# hiveCyber — Plan Consolidado

Estado: **MVP funcional** (Fases 0-5, 7 completas; Fase 8 polishing)

## Decisiones consolidadas

| Decisión | Elección |
|---|---|
| Fidelidad | Inspirado en Hive, simplificado (sin canales, sin UI web, sin gateway HTTP pesado) |
| Almacenamiento | Document store propio en Rust (HiveDB-style: JSON-on-files + indices en RAM) |
| Proveedores LLM | 16+ ports completos como Hive |
| Herramientas cybersec | Recon, análisis de vulns, explotación+post, forense+IR (todas) |
| MCP | Native JSON-RPC + stdio (sin `rmcp` crate externo) |
| Ejecución de tools | Workers separados con sandbox (caps drop) para explotación |
| Sandbox | Modo dual: explotación requiere `--unsafe` + `--allowlist-hosts` |
| Audit log | Colección HiveDB `audit_log` con índice por timestamp + `hash_chain_prev` |
| Flags | `--unsafe-mode` + `--allowlist-hosts` separados (sin alias rápido) |
| Coordinador | id `caelum`, único que habla con el operador |

## Sistema de agentes

### Coordinador `caelum` (1)
Persona "Caelum". Descompone misión, delega `task_delegate(mode:"async")`, reintegra turno `[Sistema]`, juzga criterios no determinísticos.

### Workers cybersec (8) — todos con autocustodia estricta

| id | tools | acceptance (checkTool) | sandbox |
|---|---|---|---|
| `recon_operator` | nmap, dig, whois, theHarvester, shodan, web_search, web_fetch | `recon_coverage` | none |
| `vuln_scanner` | nuclei, nikto, sqlmap, searchsploit, semgrep, trivy, fs_read, fs_glob | `vuln_findings` | none |
| `exploit_operator` | metasploit_rpc, hydra, crackmapexec, mimikatz, cli_exec | `exploit_proof` | seccomp+netns |
| `forensics_analyst` | volatility, yara_scan, zeek_parse, osquery, log_parse, fs_read | `forensics_evidence` (hash+timestamp) | none |
| `web_pentester` | nikto, sqlmap, nuclei, browser_*, web_fetch, cli_exec | `web_exploit_reproducible` (PoC ≥2x) | seccomp+netns |
| `threat_intel_analyst` | web_search, web_fetch, shodan, whois, dig, fs_read | `intel_correlation` (≥2 fuentes) | none |
| `report_writer` | fs_read, fs_write, fs_edit, office_* | `report_complete` | none |
| `workspace_file_operator` | fs_* | `readback` | none |

### Rutinas administrativas (no-LLM, deterministas)

- **`reflector`** (cada 20 traces): patrones éxito/fracaso + hallazgos duplicados intra/inter-session.
- **`curator`**: reflections → playbook rules, poda ineficaces, genera `disable_agent`/`pause_agent`/`create_agent` proposals.

## Politicas de seguridad estrictas cybersec

1. **Auto-pause en strike malo**: `harmful_count >= 3 && harmful > helpful` → `enabled: false` inmediato.
2. **Auto-disable severo**: `harmful_count >= 5` → curator auto-aplica disable.
3. **Allowlist de hosts**: `exploit_operator` + `web_pentester` + `vuln_scanner` rechazan hosts fuera de `--allowlist-hosts`.
4. **Modo dual default-OFF**: tools con `isolation = Sandbox` no ejecutan sin `--unsafe-mode` + `--allowlist-hosts <file>`.
5. **Audit log inmutable**: colección `audit_log` con SHA-256 hash chain. `hivecyber audit verify` valida cadena.
6. **Cadena de custodia forense**: `volatility` retorna `sha256 + timestamp + command` por cada dump.
7. **Session timeout exploit**: 15 min sin uso → `paused`.
8. **Denylist hardcoded**: `rm -rf /`, `sudo`, `chmod 777`, `> /dev/`, `mkfs`, `dd if=/dev/zero`, fork bomb.

## Workspace Cargo

```
hiveCyber/
├── Cargo.toml
├── crates/
│   ├── hivecyber-core/      (agent loop, hive_db, config, security, harness)
│   ├── hivecyber-cli/       (bin `hivecyber`)
│   ├── hivecyber-mcp/       (MCP client + stdio transport)
│   ├── hivecyber-skills/    (skill loader YAML+MD)
│   ├── hivecyber-tools/     (32 tools en 7 categorias)
│   ├── hivecyber-worker/   (bin sandboxed)
│   └── hivecyber-providers/ (16+ LLM adapters)
└── skills/bundled/          (17 SKILL.md en 6 categorias)
```

## Delegación + harness

- `TaskDoc` + `AgentRun(worker)` + `JobDoc(worker_task, lane:task:<id>)` + `DelegationGroup` (turn_id).
- State machine: `pending → running (lease 30min, renew 30s) → completed | failed (retry exp backoff max 3) | interrupted | cancelled`.
- Cap global 4.
- `WorkerTaskExecutor`: expande tool allowlist + runAgentIsolated + acceptance checks + increment_helpful/harmful.
- `DispatchLoop` background: 500ms dispatch + 10s maintenance.

## Almacenamiento

Colecciones: `agents`, `runs`, `jobs`, `tasks`, `messages`, `traces`, `reflections`, `playbook`, `agent_proposals`, `delegation_groups`, `skills`, `mcp_servers`, `capability_docs`, `audit_log`, `proof_packets`.

## Skills bundled (17)

recon_workflow, osint_correlation, vuln_scan_workflow, cve_lookup, pwn_check, post_exploit_chain, lateral_movement, poc_reproduction, memory_analysis, log_timeline, ioc_extraction, pentest_report, cvss_scoring, threat_modeling, opsec, clean_up, persistence.

## CLI

| comando | descripción |
|---|---|
| `hivecyber chat` | REPL con Caelum + dispatch loop background |
| `hivecyber run "<prompt>"` | invocación única |
| `hivecyber agent {list,show,enable}` | gestión agentes |
| `hivecyber skills {list,show,reload}` | skills |
| `hivecyber mcp {list,connect}` | MCP |
| `hivecyber config show` | config JSON |
| `hivecyber logs` | tail traces |
| `hivecyber resume <run_id>` | retomar run durable |
| `hivecyber doctor` | verifica 16 binarios cybersec |
| `hivecyber audit {show,verify}` | audit log + hash chain |
| `hivecyber version` | metadata |

## Fases

| Fase | Estado | Entregable |
|---|---|---|
| 0 — Skeleton | ✅ | Workspace Cargo, 7 crates |
| 1 — Core + HiveDB | ✅ | DB documental, agent loop, seed 8 workers |
| 2 — Tools base + recon | ✅ | 11 tools reales, worker bin sandboxed |
| 3 — MCP + skills | ✅ | MCP JSON-RPC stdio, 17 skills bundled |
| 4 — Delegación + harness | ✅ | DurableQueue, WorkerTaskExecutor, DispatchLoop |
| 5 — Policies strictas | ✅ | SecurityContext, auto-pause/disable, allowlist, session timeout |
| 6 — Providers restantes | pendiente | 13 OpenAI-compat ya registrados, falta test live |
| 7 — Tools vulns/exploit/forensics | ✅ | nuclei/nikto/sqlmap/msf/hydra/cme/mimikatz/volatility/yara/zeek/osquery/log_parse |
| 8 — Polishing | ✅ | doctor, audit, PLAN.md, README final |

## Dependencias crate

`tokio`, `reqwest` (rustls), `serde` + `serde_json` + `serde_yaml`, `clap`, `tracing` + `tracing-subscriber`, `anyhow` + `thiserror`, `walkdir`, `regex`, `nix` + `caps` (Linux), `directories`, `tokio-tungstenite`, `sha2`, `uuid`, `chrono`, `async-trait`, `futures`.