# Delegacion coordinator->worker

## Resumen

Caelum (coordinador) descompone la mision del operador en sub-tareas y delega cada una a un worker especializado. Las sub-tareas independientes se delegan en paralelo (mismo turno). El coordinador termina su turno tras delegar; el DispatchLoop background ejecuta los worker tasks; al cerrar el grupo, un turno `[Sistema]` se reinyecta al coordinador con las entregas para integrar.

## Flujo completo

```
1. User -> "Escanea 10.0.0.0/24 y reporta hallazgos"

2. Caelum (agent loop) -> tool_call: task_delegate(worker_id="recon_operator",
                                                   task_description="...",
                                                   acceptance=[{id:"recon_coverage", checkTool:"recon_coverage"}])

3. TaskDelegate.execute -> TaskDelegateBackend.create_task:
   a. TaskDoc (status:pending, acceptance, worker_id, task_description, delegation_group_id=<turn_id>)
   b. DurableQueue.enqueue(lane:"task:<id>", type:"worker_task", payload={workerId, taskDescription, taskId, ...})
   c. return {ok:true, task_id, job_id, worker_id, status:"queued"}

4. Caelum recibe el resultado -> decide delegar otra sub-tarea en el mismo turno (paralelo)
   - puede hacer multiples task_delegate en una sola iteracion
   - termina su turno y le dice al user "delegando a worker X e Y..."

5. DispatchLoop (background, cada 500ms):
   a. find_pending_by_lane("task:<id>")
   b. claim_job(job_id) -> lease 30min + boot_id
   c. WorkerTaskExecutor.execute:
      - load worker agent (recon_operator) desde HiveDB
      - verificar enabled (auto-pause strict)
      - expand tool_allowlist contra ToolRegistry::filter_by_allowlist
      - runAgentIsolated (LLM call + tool calls con tools restringidas)
      - run_acceptance_checks (deterministic, sin LLM)
        - Failed -> increment_harmful, task->"blocked", retour {ok:false}
        - Passed/Unchecked -> increment_helpful, task->"completed" (progress 100)
   d. complete_job(job_id, result) -> fire terminal hooks

6. DelegationGroupManager detecta grupo completo (done+failed >= total)
   - reinyecta turno `[Sistema]` al coordinador con deliveries del grupo

7. Caelum recibe turno sintetico:
   - cada delivery tiene {content, evidence, checks, status}
   - juzga criterios no deterministas (que checkTool no cubrio)
   - puede hacer task_revise para criterios fallidos (pendiente)
   - integra todo en una respuesta final al user
```

## Estructuras HiveDB

### TaskDoc (`store/collections.rs`)

```rust
pub struct TaskDoc {
    pub id: String,
    pub status: String,           // pending, running, completed, blocked, failed
    pub delegation_group_id: String,
    pub catalog_agent_id: Option<String>,
    pub worker_id: String,
    pub task_description: String,
    pub acceptance: Vec<AcceptanceCriterion>,
    pub job_id: Option<String>,
    pub run_id: Option<String>,
    pub thread_id: Option<String>,
    pub progress: Option<u8>,
    pub delivery: Option<serde_json::Value>,
    pub created_at: String,
    pub updated_at: String,
}
```

### JobDoc

```rust
pub struct JobDoc {
    pub id: String,
    pub lane: String,             // "task:<task_id>" para worker_task, "session:<id>" para chat_turn
    pub job_type: String,         // chat_turn, worker_task, goal_run
    pub status: String,           // pending, running, completed, failed, cancelled, interrupted
    pub priority: i32,
    pub payload_json: Option<Value>,
    pub run_id: Option<String>,
    pub attempts: u32,
    pub max_attempts: u32,        // default 2
    pub not_before: Option<String>, // para backoff retry
    pub boot_id: Option<String>,
    pub lease_expires_at: Option<String>,
    pub result_json: Option<Value>,
    pub error: Option<String>,
    pub retry_count: u32,
    pub created_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
}
```

### DelegationGroup

```rust
pub struct DelegationGroup {
    pub turn_id: String,
    pub agent_id: String,         // coordinator agent_id
    pub thread_id: String,
    pub task_ids: Vec<String>,
    pub completed: Vec<String>,
    pub failed: Vec<String>,
}
```

## DurableQueue (`core/src/harness/durable_queue.rs`)

```rust
pub const DEFAULT_MAX_GLOBAL_CONCURRENCY: usize = 4;
pub const JOB_LEASE_MS: u64 = 30 * 60 * 1000;     // 30 min
pub const LEASE_RENEW_MS: u64 = 30 * 1000;         // 30 s
pub const MAINTENANCE_TICK_MS: u64 = 10 * 1000;
pub const MAX_RETRIES: u32 = 3;

impl DurableQueue {
    pub async fn enqueue(&self, lane, job_type, payload, run_id) -> Result<String>;
    pub async fn find_pending_by_lane(&self, lane) -> Vec<(job_id, type, payload)>;
    pub async fn claim_job(&self, job_id) -> Result<JobDoc>;
    pub async fn complete_job(&self, job_id, result) -> Result<()>;
    pub async fn fail_job(&self, job_id, error) -> Result<()>;  // retry exp backoff max 3
    pub async fn cancel_job(&self, job_id) -> Result<()>;
    pub async fn check_expired_leases(&self) -> Result<Vec<String>>;
    pub fn register_terminal_hook(&self, hook: TerminalHook);
}
```

## WorkerTaskExecutor (`core/src/harness/executors.rs`)

```rust
#[async_trait]
pub trait JobExecutor: Send + Sync {
    fn job_type(&self) -> &str;
    async fn execute(&self, job_id: &str, payload: &Value) -> Result<ExecutorResult>;
}

pub struct WorkerTaskExecutor { db, config, security }

impl JobExecutor for WorkerTaskExecutor {
    fn job_type(&self) -> &str { "worker_task" }
    async fn execute(&self, job_id, payload) -> Result<ExecutorResult> {
        // 1. Cargar task desde payload.taskId
        // 2. Cargar worker agent, verificar enabled
        // 3. Expand tool_allowlist contra ToolRegistry
        // 4. runAgentIsolated: loop LLM + tool calls
        // 5. run_acceptance_checks(objective, acceptance, delivery, evidence)
        // 6. Failed -> increment_harmful, task->blocked, return {ok:false}
        //    Passed/Unchecked -> increment_helpful, task->completed, return {ok:true}
    }
}
```

## DispatchLoop (`core/src/harness/dispatch_loop.rs`)

Background loop spawneado por `cmd_chat`:

```rust
pub async fn start(self: Arc<Self>) {
    let mut tick = interval(Duration::from_millis(MAINTENANCE_TICK_MS));  // 10s
    let mut dispatch_tick = interval(Duration::from_millis(500));         // 500ms
    loop {
        if !running { break; }
        select! {
            _ = tick.tick() => run_maintenance(),     // check_expired_leases
            _ = dispatch_tick.tick() => dispatch_all_pending(),
        }
    }
}
```

`dispatch_all_pending`:
- iterar lanes -> `find_pending_by_lane` -> `claim_job` -> `executor.execute` -> `complete_job` o `fail_job`
- respeta cap global (4 concurrentes, pendiente de implementar running_count)

## Lanes (serializacion FIFO)

Cada lane garantiza 1 concurrente:
- `task:<task_id>` — worker_task jobs
- `session:<session_id>` — chat_turn jobs (pendiente de usar)
- `goal:<run_id>` — goal_run jobs (pendiente)

Dentro de un lane: FIFO + priority (desc). Cross-lane: hasta 4 concurrentes.

## Retries

`fail_job`:
- `retry_count < MAX_RETRIES` (3) -> back to pending, `not_before = now + delay_ms`
- `retry_count >= MAX_RETRIES` -> status = "failed", fire terminal hook

Backoff exponencial + jitter:
- retry 0: 1000ms
- retry 1: 2000ms
- retry 2: 4000ms
- ...

## Terminal hooks

Registrables via `register_terminal_hook`:
```rust
queue.register_terminal_hook(Arc::new(|job_id, result| {
    // callback cuando job llega a completed o failed permanente
}));
```

Usado por `DelegationGroupManager` para:
- `record_completion` o `record_failure` en el grupo
- detectar grupo completo -> reinyectar turno `[Sistema]` al coordinador (pendiente)

## Pendiente vs Hive TS

| Hive TS | hiveCyber Rust |
|---|---|
| `prepareDelegation` expande tool_allowlist + lease MCP + resolve model | Implementado (WorkerTaskExecutor) |
| `runAgentIsolated` worker | Implementado en executors.rs (loop inline) |
| `runAcceptanceChecks` determinista | Implementado (sin checkTool exec real, pendiente) |
| DelegationGroupManager | Implementado (create/register/record/is_complete) |
| Reinyeccion `[Sistema]`Coordinator | Pendiente (terminal hook declarado pero coordinador loop no lo consume) |
| `task_revise` (mismo thread) | Pendiente |
| `task_status` tool | Implementado (lee COL_TASKS) |
| `chat_turn` lane bypass global cap | Pendiente |
| `goal_run` executor | Pendiente |