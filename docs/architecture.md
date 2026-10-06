# Arquitectura de hiveCyber

## Vision general

hiveCyber es un harness de ciberseguridad en Rust inspirado en Hive (Bun/TypeScript). Mantiene el patron de agent loop de larga duracion con delegacion coordinator->worker, pero simplificado (sin canales Telegram/Discord/WhatsApp/Slack, sin UI web, sin gateway HTTP pesado). El CLI ejecuta el loop directamente en proceso.

## Workspace Cargo

```
hiveCyber/
├── Cargo.toml              (workspace root, 7 members)
├── crates/
│   ├── hivecyber-core/     (agent loop, HiveDB, config, security, harness)
│   ├── hivecyber-cli/      (bin `hivecyber`)
│   ├── hivecyber-mcp/      (MCP client JSON-RPC + stdio transport)
│   ├── hivecyber-skills/   (skill loader YAML+Markdown)
│   ├── hivecyber-tools/    (32 tools en 7 categorias)
│   ├── hivecyber-worker/   (bin sandboxed)
│   └── hivecyber-providers/ (16+ LLM adapters)
├── skills/bundled/         (17 SKILL.md en 6 categorias)
└── docs/                   (esta documentacion)
```

> Capa de conocimiento (playbooks, scope, memoria de hallazgos, dedup gate): ver [brain.md](brain.md) y [tooling-gap.md](tooling-gap.md).

## Flujo de alto nivel

```
CLI `hivecyber chat`
  └─> AgentLoop::run() (tokio async, mpsc::channel)
        ├─ ContextCompiler: select tools/skills + history (last 15) + scratchpad
        ├─ LlmClient::call() -> trait LlmProvider -> {anthropic, openai, gemini, ...}
        ├─ while iter < max_iter:
        │    if tool_calls: execute_tool_batch
        │      ├─ stateless tools (tokio tasks in-process)
        │      └─ dangerous tools (validate_target + cli_exec with SecurityContext)
        │    checkpoint durable (run_store)
        │    stuck_loop detector
        │    causal log (optional)
        └─ synthesize_final_response()

DispatchLoop (background, spawned by cmd_chat):
  while running:
    every 500ms: find_pending_by_lane -> claim_job -> executors -> complete/fail
    every 10s: check_expired_leases (reclaim interrupted)
```

## Componentes clave

### AgentLoop (`crates/hivecyber-core/src/agent/loop_runner.rs`)

- `pub async fn run(opts: AgentLoopOptions) -> Result<mpsc::Receiver<StreamChunk>>`
- Spawnea un task tokio que itera el loop y envia chunks via mpsc
- `StreamChunk` variants: `Agent`, `Reasoning`, `ToolCall`, `ToolResult`, `Usage`, `Done`, `Error`
- Max iterations: 20 (coordinator) / 10 (CLI chat) / 20 (workers)
- Persiste messages y traces en HiveDB (`messages`, `traces` collections)
- StuckLoopDetector previene loops infinitos por tool signature repetition

### HiveDB (`crates/hivecyber-core/src/store/hivedb.rs`)

Document store propio en Rust:
- Persistencia: `~/.hivecyber/db/<collection>/<id>.json` (atomic write: temp + rename)
- Indices en RAM: `HashMap<id, Value>`, `BTreeMap<field_value, Vec<id>>` por campos indexados
- Concurrencia: `RwLock<Inner>` para acceso mutable seguro
- 15 collections: `agents`, `runs`, `jobs`, `tasks`, `messages`, `traces`, `reflections`, `playbook`, `agent_proposals`, `delegation_groups`, `skills`, `mcp_servers`, `capability_docs`, `audit_log`, `proof_packets`
- API: `insert`, `get`, `delete`, `list`, `count`

### Harness durable (`crates/hivecyber-core/src/harness/`)

- `DurableQueue`: enqueue/claim/complete/fail/cancel con OCC + leases
- `DispatchLoop`: background loop que procesa jobs encolados cada 500ms + maintenance cada 10s
- `WorkerTaskExecutor`: ejecuta `worker_task` jobs expandiendo tool_allowlist + runAgentIsolated + acceptance checks + increment_helpful/harmful
- `DelegationGroupManager`: tracking de tasks por turn_id, reinyeccion de turno `[Sistema]` al coordinador

### SecurityContext (`crates/hivecyber-tools/src/registry.rs`)

Viaja desde el CLI hasta cada tool:
- `unsafe_mode: bool` (seteado por `--unsafe-mode`)
- `allowlist_hosts: Vec<String>` (cargado de `--allowlist-hosts <file>`, soporta CIDR IPv4/IPv6)
- `operator_id: String`
- `validate_target(target)` -> Result (check unsafe + allowlist)

### Worker bin (`crates/hivecyber-worker/src/main.rs`)

Binario dedicado sandboxed:
- Lee JSON requests por stdin, escribe JSON responses por stdout
- Aplica caps drop en Linux (seccomp pendiente de integrar con landlock)
- Ejecuta tools via `ToolRegistry::create_all()` (sin SecurityContext peligrosa por defecto)

## Invariantes de diseno

1. **Local-first**: MCP servers lazy-connect (no spawn al registrar), config via env + defaults
2. **Per-operation timeouts, not aggregate**: LLM call (3min), tool execution (per-tool timeoutMs), MCP lazy connect (8s)
3. **Context engineering**: minimal tool loadout (7 base tools), selective history (last 15), compaction (0.80 threshold), TOON encoding (pendiente)
4. **Delegation model**: `task_delegate` produce sibling jobs que comparten `turn_id`; coordinator finaliza su turno mientras workers corren en paralelo; fan-in al cerrar grupo
5. **Politicas estrictas cybersec**: auto-pause @ 3 harmful > helpful; auto-disable @ 5; allowlist obligatoria para exploit; audit log tamper-evident; sesion timeout 15min