use clap::{Parser, Subcommand};
use hivecyber_core::{Config, HiveDb};
use hivecyber_core::agent::{catalog, AgentLoop};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "hivecyber")]
#[command(version, about = "Harness de ciberseguridad con agentes de larga duracion")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(long, global = true)]
    unsafe_mode: bool,

    #[arg(long, global = true)]
    allowlist_hosts: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Commands {
    Chat {
        #[arg(long, default_value = "caelum")]
        agent: String,
    },
    Run {
        prompt: String,
        #[arg(long, default_value = "caelum")]
        agent: String,
    },
    Agent {
        #[command(subcommand)]
        action: AgentCommands,
    },
    Skills {
        #[command(subcommand)]
        action: SkillsCommands,
    },
    Mcp {
        #[command(subcommand)]
        action: McpCommands,
    },
    Config {
        #[command(subcommand)]
        action: ConfigCommands,
    },
    Logs,
    Resume {
        run_id: String,
    },
    Doctor,
    Audit {
        #[command(subcommand)]
        action: AuditCommands,
    },
    Version,
}

#[derive(Subcommand)]
enum AgentCommands {
    List,
    Show { id: String },
    Enable { id: String },
}

#[derive(Subcommand)]
enum SkillsCommands {
    List,
    Show { name: String },
    Reload,
}

#[derive(Subcommand)]
enum McpCommands {
    List,
    Connect { name: String },
}

#[derive(Subcommand)]
enum ConfigCommands {
    Show,
}

#[derive(Subcommand)]
enum AuditCommands {
    Show,
    Verify,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    let config = Config::default();
    let db_path = PathBuf::from(&config.home_dir).join("db");

    let db = Arc::new(HiveDb::open(&db_path).await?);

    let security = build_security_context(&cli);

    match cli.command {
        Commands::Chat { agent } => cmd_chat(db.clone(), &config, &agent, security.clone()).await,
        Commands::Run { prompt, agent } => cmd_run(db.clone(), &config, &agent, &prompt, security.clone()).await,
        Commands::Agent { action } => cmd_agent(db.clone(), action).await,
        Commands::Skills { action } => cmd_skills(db.clone(), action).await,
        Commands::Mcp { action } => cmd_mcp(db.clone(), action).await,
        Commands::Config { action } => cmd_config(&config, action).await,
        Commands::Logs => cmd_logs(db.clone()).await,
        Commands::Resume { run_id } => cmd_resume(db.clone(), &config, &run_id, security.clone()).await,
        Commands::Doctor => cmd_doctor().await,
        Commands::Audit { action } => cmd_audit(db.clone(), action).await,
        Commands::Version => {
            println!("hivecyber {}", hivecyber_core::VERSION);
            Ok(())
        }
    }
}

fn build_security_context(cli: &Cli) -> Arc<hivecyber_tools::SecurityContext> {
    let mut allowlist = Vec::new();

    if let Some(ref allowlist_path) = cli.allowlist_hosts {
        match std::fs::read_to_string(allowlist_path) {
            Ok(content) => {
                for line in content.lines() {
                    let entry = line.trim();
                    if entry.is_empty() || entry.starts_with('#') {
                        continue;
                    }
                    allowlist.push(entry.to_string());
                }
                eprintln!("Loaded {} allowlist entries from {}", allowlist.len(), allowlist_path.display());
            }
            Err(e) => {
                eprintln!(
                    "Warning: failed to read allowlist {}: {}",
                    allowlist_path.display(),
                    e
                );
            }
        }
    }

    let unsafe_mode = cli.unsafe_mode;
    if unsafe_mode && allowlist.is_empty() {
        eprintln!("Warning: --unsafe-mode set but --allowlist-hosts not provided or empty");
        eprintln!("         dangerous commands will be rejected");
    }

    let operator_id = std::env::var("USER").unwrap_or_else(|_| "unknown".into());

    Arc::new(hivecyber_tools::SecurityContext {
        unsafe_mode,
        allowlist_hosts: allowlist,
        operator_id,
    })
}

async fn cmd_chat(db: Arc<HiveDb>, config: &Config, agent_id: &str, security: Arc<hivecyber_tools::SecurityContext>) -> anyhow::Result<()> {
    use tokio::io::{AsyncBufReadExt, BufReader};

    ensure_seed_agents(&db, config).await?;

    let agent = db
        .get(hivecyber_core::store::collections::COL_AGENTS, agent_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("agent '{}' not found. Run `hivecyber agent list`", agent_id))?;

    let agent_name = agent
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or(agent_id);

    println!("hivecyber chat — agente: {} ({})", agent_name, agent_id);
    println!("Escribe tu mensaje. Ctrl+D o 'exit' para salir.\n");

    let dispatch = std::sync::Arc::new(hivecyber_core::harness::DispatchLoop::new(
        (*db).clone(),
        config.clone(),
    ).with_security(security.clone()));
    install_terminal_hook(db.clone(), config.clone(), security.clone(), dispatch.queue());
    dispatch.clone().start().await;

    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();

    let thread_id = uuid::Uuid::new_v4().to_string();

    loop {
        print!("> ");
        use tokio::io::AsyncWriteExt;
        std::io::Write::flush(&mut std::io::stdout())?;

        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break;
        }

        let input = line.trim();
        if input.is_empty() {
            continue;
        }
        if input == "exit" || input == "quit" {
            break;
        }

        let loop_runner = AgentLoop::new((*db).clone(), config.clone());
        let max_iter = agent
            .get("max_iterations")
            .and_then(|v| v.as_u64())
            .unwrap_or(20) as u32;

        let opts = hivecyber_core::agent::loop_runner::AgentLoopOptions {
            agent_id: agent_id.to_string(),
            user_message: input.to_string(),
            thread_id: thread_id.clone(),
            max_iterations: std::cmp::min(max_iter, 10),
            security: security.clone(),
            queue: Some(dispatch.queue()),
        };

        let mut rx = loop_runner.run(opts).await?;

        while let Some(chunk) = rx.recv().await {
            use hivecyber_core::agent::loop_runner::StreamChunk;
            match chunk {
                StreamChunk::Agent { text } => {
                    if !text.is_empty() {
                        print!("{}", text);
                        use std::io::Write;
                        std::io::stdout().flush().ok();
                    }
                }
                StreamChunk::Reasoning { text } => {
                    eprintln!("[reasoning] {}", text);
                }
                StreamChunk::ToolCall { name, args } => {
                    eprintln!("\n[tool] {}({})", name, args);
                }
                StreamChunk::ToolResult { name, result } => {
                    eprintln!("[result] {} -> {}", name, result);
                }
                StreamChunk::Usage { input_tokens, output_tokens } => {
                    eprintln!("[usage] in={} out={}", input_tokens, output_tokens);
                }
                StreamChunk::Done { final_text } => {
                    if !final_text.is_empty() {
                        println!("\n{}", final_text);
                    }
                    println!();
                }
                StreamChunk::Error { message } => {
                    eprintln!("[error] {}", message);
                }
            }
        }
    }

    dispatch.stop().await;
    Ok(())
}

async fn cmd_run(
    db: Arc<HiveDb>,
    config: &Config,
    agent_id: &str,
    prompt: &str,
    security: Arc<hivecyber_tools::SecurityContext>,
) -> anyhow::Result<()> {
    ensure_seed_agents(&db, config).await?;

    let thread_id = uuid::Uuid::new_v4().to_string();

    let dispatch = Arc::new(hivecyber_core::harness::DispatchLoop::new(
        (*db).clone(),
        config.clone(),
    ).with_security(security.clone()));
    let active = install_terminal_hook(db.clone(), config.clone(), security.clone(), dispatch.queue());
    dispatch.clone().start().await;

    let opts = hivecyber_core::agent::loop_runner::AgentLoopOptions {
        agent_id: agent_id.to_string(),
        user_message: prompt.to_string(),
        thread_id: thread_id.clone(),
        max_iterations: 10,
        security: security.clone(),
        queue: Some(dispatch.queue()),
    };

    *active.lock().await += 1;
    if let Err(e) = run_agent_and_print(db.clone(), config, opts).await {
        eprintln!("[error] {}", e);
    }
    let mut a = active.lock().await;
    *a = a.saturating_sub(1);
    drop(a);

    let mut clean_polls = 0u32;
    loop {
        let busy = *active.lock().await > 0 || count_in_flight_jobs(&db).await > 0;
        if busy {
            clean_polls = 0;
        } else {
            clean_polls += 1;
            if clean_polls >= 2 {
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(750)).await;
    }

    dispatch.stop().await;
    Ok(())
}

async fn run_agent_and_print(
    db: Arc<HiveDb>,
    config: &Config,
    opts: hivecyber_core::agent::loop_runner::AgentLoopOptions,
) -> anyhow::Result<()> {
    let loop_runner = AgentLoop::new((*db).clone(), config.clone());
    let mut rx = loop_runner.run(opts).await?;

    while let Some(chunk) = rx.recv().await {
        use hivecyber_core::agent::loop_runner::StreamChunk;
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

async fn count_in_flight_jobs(db: &HiveDb) -> usize {
    let jobs = db.list(hivecyber_core::store::collections::COL_JOBS).await;
    jobs.into_iter()
        .filter(|(_, v)| {
            let s = v.get("status").and_then(|x| x.as_str()).unwrap_or("");
            s == "pending" || s == "running"
        })
        .count()
}

fn install_terminal_hook(
    db: Arc<HiveDb>,
    config: Config,
    security: Arc<hivecyber_tools::SecurityContext>,
    queue: Arc<hivecyber_core::harness::DurableQueue>,
) -> Arc<tokio::sync::Mutex<u32>> {
    let group_manager = Arc::new(
        hivecyber_core::harness::delegation_groups::DelegationGroupManager::new((*db).clone()),
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
            )
            .await;
            let mut pc = pending_checks.lock().unwrap();
            *pc = pc.saturating_sub(1);
        });
    }));

    active
}

#[allow(clippy::too_many_arguments)]
async fn handle_job_completion(
    db: Arc<HiveDb>,
    config: Config,
    security: Arc<hivecyber_tools::SecurityContext>,
    queue: Arc<hivecyber_core::harness::DurableQueue>,
    group_manager: Arc<hivecyber_core::harness::delegation_groups::DelegationGroupManager>,
    processed: Arc<tokio::sync::Mutex<HashSet<String>>>,
    active: Arc<tokio::sync::Mutex<u32>>,
    job_id: String,
    result: serde_json::Value,
) {
    use hivecyber_core::agent::loop_runner::AgentLoopOptions;
    use hivecyber_core::store::collections::{COL_DELEGATION_GROUPS, COL_JOBS, COL_TASKS};

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
        };
        if let Err(e) = run_agent_and_print(db2, &config2, opts).await {
            eprintln!("[sistema] error en reinyeccion: {}", e);
        }
        let mut a = active2.lock().await;
        *a = a.saturating_sub(1);
    });
}

async fn cmd_agent(db: Arc<HiveDb>, action: AgentCommands) -> anyhow::Result<()> {
    match action {
        AgentCommands::List => {
            let agents = db.list(hivecyber_core::store::collections::COL_AGENTS).await;
            if agents.is_empty() {
                println!("No agents. Run `hivecyber chat` to seed defaults.");
                return Ok(());
            }
            println!("{:<30} {:<12} {:<8} {:<8} {}", "ID", "NAME", "ROLE", "ENABLED", "DESCRIPTION");
            for (id, val) in agents {
                let name = val.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let role = val.get("role").and_then(|v| v.as_str()).unwrap_or("");
                let enabled = val.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
                let desc = val.get("description").and_then(|v| v.as_str()).unwrap_or("");
                println!("{:<30} {:<12} {:<8} {:<8} {}", id, name, role, enabled, desc);
            }
        }
        AgentCommands::Show { id } => {
            let agent = db
                .get(hivecyber_core::store::collections::COL_AGENTS, &id)
                .await
                .ok_or_else(|| anyhow::anyhow!("agent not found"))?;
            println!("{}", serde_json::to_string_pretty(&agent)?);
        }
        AgentCommands::Enable { id } => {
            let mut agent = db
                .get(hivecyber_core::store::collections::COL_AGENTS, &id)
                .await
                .ok_or_else(|| anyhow::anyhow!("agent not found"))?;
            if let Some(obj) = agent.as_object_mut() {
                obj.insert("enabled".into(), serde_json::json!(true));
                obj.insert("status".into(), serde_json::json!("active"));
                obj.insert("updated_at".into(), chrono::Utc::now().to_rfc3339().into());
            }
            db.insert(hivecyber_core::store::collections::COL_AGENTS, &id, agent).await?;
            println!("Agent '{}' enabled.", id);
        }
    }
    Ok(())
}

async fn cmd_skills(db: Arc<HiveDb>, action: SkillsCommands) -> anyhow::Result<()> {
    let _ = db;
    let bundled = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../skills/bundled")
        .canonicalize()
        .unwrap_or_else(|_| std::path::PathBuf::from("./skills/bundled"));
    let managed = std::path::PathBuf::from(
        std::env::var("HIVECYBER_HOME").unwrap_or_else(|_| {
            directories::ProjectDirs::from("ai", "hivecyber", "hivecyber")
                .map(|d| d.data_dir().to_string_lossy().to_string())
                .unwrap_or_else(|| format!("{}/.hivecyber", std::env::var("HOME").unwrap_or_default()))
        }),
    ).join("skills");

    let mut loader = hivecyber_skills::SkillLoader::new(&bundled, &managed);
    if let Err(e) = loader.load_all() {
        eprintln!("Error loading skills: {}", e);
    }

    match action {
        SkillsCommands::List => {
            let skills = loader.list();
            if skills.is_empty() {
                println!("No skills loaded. Run from hiveCyber root dir.");
                return Ok(());
            }
            println!("{:<30} {:<12} {:<8} {}", "NAME", "CATEGORY", "VERSION", "DESCRIPTION");
            for skill in skills {
                println!(
                    "{:<30} {:<12} {:<8} {}",
                    skill.name,
                    skill.category,
                    skill.version.as_deref().unwrap_or("-"),
                    skill.description.chars().take(80).collect::<String>()
                );
            }
        }
        SkillsCommands::Show { name } => {
            match loader.get(&name) {
                Some(skill) => {
                    println!("{}", serde_json::to_string_pretty(&serde_json::to_value(skill)?)?);
                }
                None => println!("skill '{}' not found", name),
            }
        }
        SkillsCommands::Reload => {
            loader.load_all()?;
            println!("Skills reloaded: {} skills", loader.list().len());
        }
    }
    Ok(())
}

async fn cmd_mcp(db: Arc<HiveDb>, action: McpCommands) -> anyhow::Result<()> {
    let _ = db;
    match action {
        McpCommands::List => {
            println!("MCP servers (skeleton phase — no servers registered)");
        }
        McpCommands::Connect { name } => {
            println!("Connecting to MCP server '{}' (skeleton phase)", name);
        }
    }
    Ok(())
}

async fn cmd_config(config: &Config, action: ConfigCommands) -> anyhow::Result<()> {
    match action {
        ConfigCommands::Show => {
            println!("{}", serde_json::to_string_pretty(&serde_json::to_value(config)?)?);
        }
    }
    Ok(())
}

async fn cmd_logs(db: Arc<HiveDb>) -> anyhow::Result<()> {
    let traces = db.list(hivecyber_core::store::collections::COL_TRACES).await;
    if traces.is_empty() {
        println!("No traces yet.");
        return Ok(());
    }
    for (id, val) in traces.iter().take(50) {
        let tool = val.get("tool_name").and_then(|v| v.as_str()).unwrap_or("");
        let success = val.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
        let dur = val.get("duration_ms").and_then(|v| v.as_u64()).unwrap_or(0);
        println!("[{}] {} {} {}ms", id, tool, if success { "OK" } else { "FAIL" }, dur);
    }
    Ok(())
}

async fn cmd_resume(db: Arc<HiveDb>, config: &Config, run_id: &str, security: Arc<hivecyber_tools::SecurityContext>) -> anyhow::Result<()> {
    let run = db
        .get(hivecyber_core::store::collections::COL_RUNS, run_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("run not found: {}", run_id))?;

    let agent_id = run
        .get("agent_id")
        .and_then(|v| v.as_str())
        .unwrap_or("caelum");
    let thread_id = run
        .get("thread_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    println!("Resuming run {} (agent={}, thread={})", run_id, agent_id, thread_id);

    let loop_runner = AgentLoop::new((*db).clone(), config.clone());
    let opts = hivecyber_core::agent::loop_runner::AgentLoopOptions {
        agent_id: agent_id.to_string(),
        user_message: "Continua la operacion desde el ultimo checkpoint.".into(),
        thread_id: thread_id.to_string(),
        max_iterations: 10,
        security: security.clone(),
        queue: None,
    };

    let mut rx = loop_runner.run(opts).await?;
    while let Some(chunk) = rx.recv().await {
        use hivecyber_core::agent::loop_runner::StreamChunk;
        match chunk {
            StreamChunk::Agent { text } => print!("{}", text),
            StreamChunk::Done { final_text } => println!("\n{}", final_text),
            StreamChunk::Error { message } => eprintln!("[error] {}", message),
            _ => {}
        }
    }

    Ok(())
}

async fn cmd_doctor() -> anyhow::Result<()> {
    let tools = [
        ("nmap", "nmap"),
        ("nuclei", "nuclei"),
        ("sqlmap", "sqlmap"),
        ("metasploit", "msfconsole"),
        ("searchsploit", "searchsploit"),
        ("nikto", "nikto"),
        ("theHarvester", "theHarvester"),
        ("shodan", "shodan"),
        ("volatility3", "vol"),
        ("yara", "yara"),
        ("zeek", "zeek"),
        ("osquery", "osqueryi"),
        ("semgrep", "semgrep"),
        ("trivy", "trivy"),
        ("hydra", "hydra"),
        ("crackmapexec", "crackmapexec"),
    ];

    println!("hivecyber doctor — verificando dependencias:\n");
    let mut missing = 0;
    for (name, binary) in &tools {
        let found = std::process::Command::new("which")
            .arg(binary)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if found {
            println!("  [OK] {} ({})", name, binary);
        } else {
            println!("  [MISSING] {} ({})", name, binary);
            missing += 1;
        }
    }
    println!("\n{} tools found, {} missing", tools.len() - missing, missing);
    Ok(())
}

async fn cmd_audit(db: Arc<HiveDb>, action: AuditCommands) -> anyhow::Result<()> {
    match action {
        AuditCommands::Show => {
            let entries = db.list(hivecyber_core::store::collections::COL_AUDIT_LOG).await;
            if entries.is_empty() {
                println!("Audit log vacio.");
                return Ok(());
            }
            for (id, val) in entries.iter().take(100) {
                let ts = val.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
                let tool = val.get("tool").and_then(|v| v.as_str()).unwrap_or("");
                let target = val.get("target").and_then(|v| v.as_str()).unwrap_or("");
                let worker = val.get("worker").and_then(|v| v.as_str()).unwrap_or("");
                println!("[{}] {} {} target={} worker={}", ts, id, tool, target, worker);
            }
        }
        AuditCommands::Verify => {
            let (ok, errors) = hivecyber_core::security::audit::verify_chain(&db).await?;
            if ok {
                println!("Audit log chain: VERIFIED (all hashes valid)");
            } else {
                println!("Audit log chain: BROKEN ({} errors)", errors.len());
                for e in errors.iter().take(20) {
                    println!("  - {}", e);
                }
            }
        }
    }
    Ok(())
}

async fn ensure_seed_agents(db: &HiveDb, config: &Config) -> anyhow::Result<()> {
    let count = db.count(hivecyber_core::store::collections::COL_AGENTS).await;
    if count > 0 {
        return Ok(());
    }

    tracing::info!("seeding agents...");

    let coordinator = hivecyber_core::store::collections::AgentDoc {
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
        hivecyber_core::store::collections::COL_AGENTS,
        "caelum",
        serde_json::to_value(&coordinator)?,
    ).await?;

    for persona in catalog::catalog_personas() {
        let now = chrono::Utc::now().to_rfc3339();
        let agent = hivecyber_core::store::collections::AgentDoc {
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
            hivecyber_core::store::collections::COL_AGENTS,
            &persona.id,
            serde_json::to_value(&agent)?,
        ).await?;
    }

    tracing::info!("seeded 1 coordinator + 8 workers");
    println!("Agents seeded: 1 coordinator (caelum) + 8 workers");

    Ok(())
}

fn build_worker_prompt(id: &str, desc: &str) -> String {
    format!(
        "# HIVECYBER Worker: {}\n\n{}\n\n## Reglas\n- No hablas con el operador.\n- No delegas.\n- No usas tools fuera de tu allowlist.\n- Declaras exito solo con evidencia verificable.\n- Output estructurado: status, what_was_done, artifacts, evidence, risks, question.",
        id, desc
    )
}