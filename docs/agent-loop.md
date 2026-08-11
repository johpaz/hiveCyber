# Agent Loop de larga duracion

## Diseno

El agent loop es `async fn run() -> mpsc::Receiver<StreamChunk>` en `crates/hivecyber-core/src/agent/loop_runner.rs`. Spawnea un task tokio que itera y envia chunks via canal mpsc (buffer 128).

## Flujo del loop

```
1. Load agent config from HiveDB (col<agents>)
2. Resolve LLM provider + model + api_key
3. Persist user message en HiveDB (col<messages>)
4. Construir ToolRegistry con SecurityContext
5. compileContext:
   - system_prompt del agente
   - messages: historial (last 15, pendiente)
   - tools: todas las registradas (pendiente selectivas)
6. while iterations < max_iterations:
   a. Check signal.aborted (pendiente)
   b. callLLM(req) -> LlmResponse
   c. Emit StreamChunk::Agent { text } + StreamChunk::Usage
   d. if tool_calls.is_empty():
      - persist final assistant message
      - return Ok
   e. else:
      - push assistant msg (with tool_calls) to messages
      - emit StreamChunk::ToolCall for each
      - StuckLoopDetector.record_tool_call(signature)
      - execute_tool_batch(tool_calls, registry, timeout_ms)
      - for each result:
        - emit StreamChunk::ToolResult
        - persist TraceDoc en HiveDB (col<traces>)
      - append tool results to messages (role: "tool")
7. Final: synthesize_final_response (pendiente)
```

## AgentLoopOptions

```rust
pub struct AgentLoopOptions {
    pub agent_id: String,
    pub user_message: String,
    pub thread_id: String,
    pub max_iterations: u32,
    pub security: Arc<SecurityContext>,
}
```

## StreamChunk

| variante | descripcion |
|---|---|
| `Agent { text }` | texto generado por el LLM |
| `Reasoning { text }` | reasoning tokens (pendiente) |
| `ToolCall { name, args }` | el LLM solicita invocar una tool |
| `ToolResult { name, result }` | resultado de ejecutar la tool |
| `Usage { input_tokens, output_tokens }` | consumo de tokens |
| `Done { final_text }` | el loop termino |
| `Error { message }` | error fatal |

## Durable runs (`run_store.rs`)

Cada invocacion crea un `RunDoc` en HiveDB con:
- `id`, `kind` (chat|worker|goal|cron|project), `agent_id`, `thread_id`
- `status`: pending -> running -> completed | failed | interrupted
- `iterations_used`, `turns_used`, `tokens_used`
- `lease_expires_at` (para reclaim en crash)
- `state_json` (para resume, pendiente)

API:
- `create_run(db, kind, agent_id, thread_id, goal) -> run_id`
- `complete_run(db, run_id)`
- `fail_run(db, run_id, error)`

## StuckLoopDetector (`stuck.rs`)

Previene loops infinitos detectando:
- **Tool signature repetition**: si la misma tool con misma firma se repite 4+ veces consecutivas -> intervention message
- **Idle iterations**: 3+ iteraciones sin progreso -> intervention
- `reset_idle()` cuando hay progreso

```rust
let mut detector = StuckLoopDetector::new();
detector.record_tool_call("nmap:10.0.0.5");  // None
detector.record_tool_call("nmap:10.0.0.5");  // None
detector.record_tool_call("nmap:10.0.0.5");  // None
let intervention = detector.record_tool_call("nmap:10.0.0.5");
assert!(intervention.is_some());  // "Bucle atascado detectado..."
```

## Acceptance checks (`acceptance.rs`)

Deterministicos, sin LLM. Se aplican tras cada worker task:

```rust
let checks = run_acceptance_checks(
    objective,           // "Scan 10.0.0.0/24"
    acceptance_criteria, // [{id: "recon_coverage", checkTool: "recon_coverage"}]
    delivery_text,       // output del worker
    evidence,            // ["nmap: ...", "dig: ..."]
);
let status = verdict(&checks);  // Passed | Failed | Unchecked
```

| check | descripcion |
|---|---|
| `delivery_gate` | entrega vacia -> failed |
| `self_declared_failure` | worker dice "status: failed" -> failed |
| `checkTool` | invoca tool determinista con `{goal: description}` |
| `artifact_inspect` | verifica artifact_id en evidence |

## Compaction (implementado)

El loop compacta el *working-set en memoria* cuando su estimación de tokens supera el
**budget derivado del context window real del modelo** (`context_window * 0.70`, tomado de
`COL_MODELS` — el catálogo espejo de Hive). Si el modelo no está en el catálogo (p. ej.
local/ollama) cae al fallback `config.models.context_token_budget` (env
`HIVECYBER_CONTEXT_BUDGET`, default 24000; `0` desactiva). Módulos: `agent/compaction.rs`,
`agent/models_catalog.rs`.

- Antes de cada llamada al modelo, `maybe_compact` evalúa el presupuesto.
- Sumariza el prefijo antiguo en **un** mensaje `user` de resumen (vía el modelo,
  con fallback determinista `extractive_summary` si la llamada falla) y conserva
  las últimas `MIN_RECENT_MESSAGES` verbatim.
- **Corte seguro**: el límite avanza hasta un mensaje `role == "assistant"`, lo que
  (a) evita dejar un `tool_result` huérfano y (b) garantiza la alternancia
  `user(resumen) → assistant(...)`.
- **No toca `COL_MESSAGES`**: la conversación persistida (registro append-only para
  auditoría y `resume`) queda intacta; la compaction solo reduce lo que se envía al
  modelo. No hay context-window por modelo en la BD, así que el trigger es el
  presupuesto configurable (heurístico, ~4 chars/token).

Pendiente (Roadmap): checkpoints durables del run del coordinador y reconstrucción
de mensajes desde `COL_MESSAGES` en `resume` (hoy `resume` reinyecta una señal de
continuación, no rehidrata el historial).