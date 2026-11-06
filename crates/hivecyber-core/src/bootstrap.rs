//! Shared runtime bootstrap used by both the CLI (`hivecyber`) and the web
//! gateway (`hivecyber-gateway`): agent seeding, skill sync, MCP init, the
//! delegation terminal hook, and job-completion re-injection to the
//! coordinator. Extracted verbatim from the CLI so there is one source of truth.

use crate::agent::{catalog, AgentLoop};
use crate::{Config, HiveDb};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

/// Load + connect the configured MCP servers (if MCP is enabled). Returns the
/// shared manager so its tools can be registered for every agent this command
/// runs. Returns `None` when MCP is disabled so the whole feature is a no-op.
pub async fn init_mcp(
    db: &HiveDb,
    config: &Config,
) -> Option<crate::agent::mcp_integration::SharedMcp> {
    if !config.mcp.enabled {
        return None;
    }
    Some(crate::agent::mcp_integration::load_and_connect(db).await)
}

/// Bundled skills dir (relative to the CLI crate in dev; falls back to ./skills).
pub fn bundled_skills_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../skills/bundled")
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from("./skills/bundled"))
}

/// Sync skills from the filesystem (bundled + managed) into `COL_SKILLS` so the
/// agent loop's BM25 skill-selector can rank them. Best-effort.
pub async fn sync_skills_to_db(db: &HiveDb, config: &Config) {
    let managed = PathBuf::from(&config.skills.managed_dir);
    let mut loader = hivecyber_skills::SkillLoader::new(&bundled_skills_dir(), &managed);
    if loader.load_all().is_err() {
        return;
    }
    for s in loader.list() {
        let doc = serde_json::json!({
            "id": s.name,
            "name": s.name,
            "description": s.description,
            "category": s.category,
            "version": s.version,
            "tags": s.category,
        });
        let _ = db.insert(
            crate::store::collections::COL_SKILLS,
            &s.name,
            doc,
        ).await;
    }
}

pub async fn run_agent_and_print(
    db: Arc<HiveDb>,
    config: &Config,
    opts: crate::agent::loop_runner::AgentLoopOptions,
) -> anyhow::Result<()> {
    let loop_runner = AgentLoop::new((*db).clone(), config.clone());
    let mut rx = loop_runner.run(opts).await?;

    while let Some(chunk) = rx.recv().await {
        use crate::agent::loop_runner::StreamChunk;
        match chunk {
            StreamChunk::Agent { text } => print!("{}", text),
            StreamChunk::Reasoning { text } => eprintln!("[reasoning] {}", text),
            StreamChunk::ToolCall { name, args } => eprintln!("\n[tool] {}({})", name, args),
            StreamChunk::ToolResult { name, result } => eprintln!("[result] {} -> {}", name, result),
            StreamChunk::Usage { input_tokens, output_tokens } => {
                eprintln!("[usage] in={} out={}", input_tokens, output_tokens);
            }
            StreamChunk::Done { final_text } => {
                if !final_text.is_empty() {
                    println!("\n{}", final_text);
                }
            }
            StreamChunk::Error { message } => eprintln!("[error] {}", message),
        }
    }

    Ok(())
}

pub fn install_terminal_hook(
    db: Arc<HiveDb>,
    config: Config,
    security: Arc<hivecyber_tools::SecurityContext>,
    queue: Arc<crate::harness::DurableQueue>,
    mcp: Option<crate::agent::mcp_integration::SharedMcp>,
) -> Arc<tokio::sync::Mutex<u32>> {
    let group_manager = Arc::new(
        crate::harness::delegation_groups::DelegationGroupManager::new((*db).clone()),
    );
    let processed: Arc<tokio::sync::Mutex<HashSet<String>>> = Arc::new(tokio::sync::Mutex::new(HashSet::new()));
    let pending_checks: Arc<std::sync::Mutex<u32>> = Arc::new(std::sync::Mutex::new(0));
    let active = Arc::new(tokio::sync::Mutex::new(0u32));

    let pending_checks_outer = pending_checks.clone();
    let db_outer = db.clone();
    let queue_hook = queue.clone();
    let active_hook = active.clone();
    queue.register_terminal_hook(Arc::new(move |job_id, result| {
        *pending_checks_outer.lock().unwrap() += 1;
        let db = db_outer.clone();
        let config = config.clone();
        let security = security.clone();
        let queue = queue_hook.clone();
        let group_manager = group_manager.clone();
        let processed = processed.clone();
        let pending_checks = pending_checks.clone();
        let active = active_hook.clone();
        let mcp = mcp.clone();
        tokio::spawn(async move {
            handle_job_completion(
                db,
                config,
                security,
                queue,
                group_manager,
                processed,
                active,
                job_id,
                result,
                mcp,
            )
            .await;
            let mut pc = pending_checks.lock().unwrap();
            *pc = pc.saturating_sub(1);
        });
    }));

    active
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_job_completion(
    db: Arc<HiveDb>,
    config: Config,
    security: Arc<hivecyber_tools::SecurityContext>,
    queue: Arc<crate::harness::DurableQueue>,
    group_manager: Arc<crate::harness::delegation_groups::DelegationGroupManager>,
    processed: Arc<tokio::sync::Mutex<HashSet<String>>>,
    active: Arc<tokio::sync::Mutex<u32>>,
    job_id: String,
    result: serde_json::Value,
    mcp: Option<crate::agent::mcp_integration::SharedMcp>,
) {
    use crate::agent::loop_runner::AgentLoopOptions;
    use crate::store::collections::{COL_DELEGATION_GROUPS, COL_JOBS, COL_TASKS};

    let job = db.get(COL_JOBS, &job_id).await;
    let task_id = job
        .as_ref()
        .and_then(|j| j.get("payload_json"))
        .and_then(|p| p.get("taskId"))
        .and_then(|t| t.as_str())
        .map(|s| s.to_string());
    let thread_id = job
        .as_ref()
        .and_then(|j| j.get("payload_json"))
        .and_then(|p| p.get("originThreadId"))
        .and_then(|t| t.as_str())
        .map(|s| s.to_string())
        .unwrap_or_default();

    let Some(task_id) = task_id else {
        return;
    };

    let task = db.get(COL_TASKS, &task_id).await;
    let Some(turn_id) = task
        .and_then(|t| {
            t.get("delegation_group_id")
                .and_then(|d| d.as_str())
                .map(|s| s.to_string())
        })
    else {
        return;
    };

    if group_manager.is_group_complete(&turn_id).await.is_none() {
        if db.get(COL_DELEGATION_GROUPS, &turn_id).await.is_none() {
            if let Err(e) = group_manager.create_group(&turn_id, "caelum", &thread_id).await {
                eprintln!("[sistema] error creando grupo {}: {}", turn_id, e);
            }
        }
        let tasks = db.list(COL_TASKS).await;
        for (tid, val) in tasks {
            let grp = val
                .get("delegation_group_id")
                .and_then(|d| d.as_str())
                .unwrap_or("");
            if grp == turn_id {
                let _ = group_manager.register_task(&turn_id, &tid).await;
            }
        }
    }

    let status = result.get("status").and_then(|s| s.as_str()).unwrap_or("");
    if status == "completed" || status == "ok" {
        if let Err(e) = group_manager.record_completion(&turn_id, &task_id).await {
            eprintln!("[sistema] error registro completado: {}", e);
        }
    } else if let Err(e) = group_manager.record_failure(&turn_id, &task_id).await {
        eprintln!("[sistema] error registro fallo: {}", e);
    }

    let mut processed_guard = processed.lock().await;
    if processed_guard.contains(&turn_id) {
        return;
    }
    let complete = group_manager.is_group_complete(&turn_id).await.unwrap_or(false);
    if !complete {
        return;
    }
    processed_guard.insert(turn_id.clone());
    drop(processed_guard);

    let deliveries = group_manager.get_group_deliveries(&turn_id).await;
    let mut msg = String::from(
        "[Sistema] Los workers delegados completaron sus tareas. Entregas:\n\n",
    );
    for (i, (status, delivery)) in deliveries.iter().enumerate() {
        msg.push_str(&format!("--- Entrega {} (status: {}) ---\n", i + 1, status));
        if let Some(obj) = delivery.as_object() {
            if let Some(c) = obj.get("content").and_then(|c| c.as_str()) {
                msg.push_str(c);
                msg.push('\n');
            }
            if let Some(ev) = obj.get("evidence").and_then(|e| e.as_array()) {
                for item in ev.iter().take(20) {
                    if let Some(s) = item.as_str() {
                        msg.push_str("  [evidencia] ");
                        msg.push_str(&s.chars().take(600).collect::<String>());
                        msg.push('\n');
                    }
                }
            }
        } else {
            msg.push_str("(sin contenido)\n");
        }
    }
    msg.push_str("\n[Fin de entregas] Responde al operador con un resumen ejecutivo de los hallazgos. Si falta trabajo final (p. ej. compilar un informe), delega a report_writer con task_delegate pasandole el contexto de los hallazgos.");

    eprintln!(
        "\n[sistema] grupo {} completo — reinyectando entregas a caelum",
        turn_id
    );

    *active.lock().await += 1;
    let active2 = active.clone();
    let db2 = db.clone();
    let config2 = config.clone();
    tokio::spawn(async move {
        let opts = AgentLoopOptions {
            agent_id: "caelum".into(),
            user_message: msg,
            thread_id,
            max_iterations: 10,
            security,
            queue: Some(queue),
            mcp_manager: mcp,
            rehydrate: false,
        };
        if let Err(e) = run_agent_and_print(db2, &config2, opts).await {
            eprintln!("[sistema] error en reinyeccion: {}", e);
        }
        let mut a = active2.lock().await;
        *a = a.saturating_sub(1);
    });
}

pub async fn backfill_catalog_tools(db: &HiveDb) {
    use crate::store::collections::COL_AGENTS;
    for persona in crate::agent::catalog::catalog_personas() {
        if persona.tool_allowlist.is_empty() {
            continue;
        }
        let Some(mut agent) = db.get(COL_AGENTS, &persona.id).await else { continue };
        if agent.get("source").and_then(|v| v.as_str()) != Some("catalog") {
            continue;
        }
        let Some(list) = agent.get_mut("tool_allowlist_json").and_then(|v| v.as_array_mut()) else {
            continue;
        };
        let present: std::collections::HashSet<&str> =
            list.iter().filter_map(|t| t.as_str()).collect();
        let missing: Vec<serde_json::Value> = persona
            .tool_allowlist
            .iter()
            .filter(|t| !present.contains(t.as_str()))
            .map(|t| serde_json::json!(t))
            .collect();
        if missing.is_empty() {
            continue;
        }
        list.extend(missing);
        let _ = db.insert(COL_AGENTS, &persona.id, agent).await;
    }
}

pub async fn ensure_seed_agents(db: &HiveDb, config: &Config) -> anyhow::Result<()> {
    let count = db.count(crate::store::collections::COL_AGENTS).await;
    if count > 0 {
        backfill_catalog_tools(db).await;
        return Ok(());
    }

    tracing::info!("seeding agents...");

    let coordinator = crate::store::collections::AgentDoc {
        id: "caelum".into(),
        name: "Caelum".into(),
        description: "Coordinador de operaciones de ciberseguridad".into(),
        system_prompt: Some(catalog::COORDINATOR_SYSTEM_PROMPT.into()),
        tone: None,
        role: "coordinator".into(),
        status: "active".into(),
        enabled: true,
        provider_id: None,
        model_id: None,
        tools_json: Some(vec!["task_delegate".into(), "task_revise".into(), "task_status".into()]),
        skills_json: None,
        tool_allowlist_json: None,
        mcp_server_ids_json: None,
        workspace_scope_json: None,
        model_override_json: None,
        default_acceptance_json: None,
        helpful_count: 0,
        harmful_count: 0,
        parent_id: None,
        max_iterations: Some(20),
        workspace: None,
        source: Some("user".into()),
        routing_examples_json: None,
        routing_exclusions_json: None,
        seed_version: Some(env!("CARGO_PKG_VERSION").into()),
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
    };

    db.insert(
        crate::store::collections::COL_AGENTS,
        "caelum",
        serde_json::to_value(&coordinator)?,
    ).await?;

    for persona in crate::agent::catalog::catalog_personas() {
        let now = chrono::Utc::now().to_rfc3339();
        let agent = crate::store::collections::AgentDoc {
            id: persona.id.clone(),
            name: persona.name.clone(),
            description: persona.description.clone(),
            system_prompt: Some(build_worker_prompt(&persona.id, &persona.description)),
            tone: Some("professional".into()),
            role: "worker".into(),
            status: "idle".into(),
            enabled: true,
            provider_id: None,
            model_id: None,
            tools_json: None,
            skills_json: Some(persona.skills.clone()),
            tool_allowlist_json: Some(persona.tool_allowlist.clone()),
            mcp_server_ids_json: None,
            workspace_scope_json: Some(persona.workspace_scope.clone()),
            model_override_json: persona.model_override.clone(),
            default_acceptance_json: Some(persona.default_acceptance.clone()),
            helpful_count: 0,
            harmful_count: 0,
            parent_id: Some("caelum".into()),
            max_iterations: Some(20),
            workspace: None,
            source: Some("catalog".into()),
            routing_examples_json: None,
            routing_exclusions_json: persona.routing_exclusions.clone(),
            seed_version: Some(env!("CARGO_PKG_VERSION").into()),
            created_at: now.clone(),
            updated_at: now,
        };

        db.insert(
            crate::store::collections::COL_AGENTS,
            &persona.id,
            serde_json::to_value(&agent)?,
        ).await?;
    }

    tracing::info!("seeded 1 coordinator + 8 workers");
    println!("Agents seeded: 1 coordinator (caelum) + 8 workers");

    Ok(())
}

pub fn build_worker_prompt(id: &str, desc: &str) -> String {
    format!(
        "# HIVECYBER Worker: {}\n\n{}\n\n## Reglas\n- No hablas con el operador.\n- No delegas.\n- No usas tools fuera de tu allowlist.\n- Declaras exito solo con evidencia verificable.\n- Output estructurado: status, what_was_done, artifacts, evidence, risks, question.",
        id, desc
    )

}
