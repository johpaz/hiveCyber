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

    #[arg(long, global = true)]
    engagement_policy: Option<PathBuf>,

    #[arg(long, global = true)]
    allow_cli_exec: bool,

    #[arg(long, global = true, value_name = "CATEGORY")]
    approve_human: Vec<String>,
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
    Provider {
        #[command(subcommand)]
        action: ProviderCommands,
    },
    /// Catálogo de modelos (provider, context window, costo USD/1M).
    Models {
        #[arg(long)]
        provider: Option<String>,
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
    Disable { id: String },
    /// Pin a model for an agent (empty string clears it → use the global default).
    SetModel { id: String, model: String },
    /// Pin a provider for an agent.
    SetProvider { id: String, provider: String },
}

#[derive(Subcommand)]
enum ProviderCommands {
    /// Store an API key (encrypted) and optional base URL / model for a provider.
    Set {
        id: String,
        #[arg(long)]
        api_key: Option<String>,
        #[arg(long)]
        base_url: Option<String>,
        #[arg(long)]
        model: Option<String>,
    },
    /// List known providers, whether a key is configured, and the current default.
    List,
    /// Show one provider's configuration (key masked).
    Show { id: String },
    /// Set the default provider (and optionally the default model).
    Default {
        id: String,
        #[arg(long)]
        model: Option<String>,
    },
}

#[derive(Subcommand)]
enum SkillsCommands {
    List,
    Show { name: String },
    Reload,
    /// Install a skill by copying its SKILL.md into the managed skills dir.
    Add { path: PathBuf },
}

#[derive(Subcommand)]
enum McpCommands {
    /// Register an MCP server. stdio: --command (+ optional --args); sse/http: --url.
    Add {
        name: String,
        #[arg(long, default_value = "stdio")]
        transport: String,
        #[arg(long)]
        command: Option<String>,
        /// Args for the stdio command (repeat: --arg -y --arg pkg). Hyphen-led
        /// values are allowed so flags like `-y` pass through.
        #[arg(long = "arg", allow_hyphen_values = true)]
        args: Vec<String>,
        #[arg(long)]
        url: Option<String>,
        /// Environment for the stdio process (repeat: --env KEY=VAL).
        #[arg(long = "env", value_parser = parse_kv)]
        env: Vec<(String, String)>,
        /// HTTP headers for sse/http transport (repeat: --header KEY=VAL).
        #[arg(long = "header", value_parser = parse_kv)]
        header: Vec<(String, String)>,
    },
    /// List registered MCP servers and their last-known status.
    List,
    /// Connect to a registered server and report the tools it exposes.
    Connect { name: String },
    /// Disconnect (only meaningful for a long-lived process; validates config).
    Disconnect { name: String },
    /// List the tools of one server (or all connected servers).
    Tools { name: Option<String> },
    /// Call a tool on a server with JSON arguments.
    Call {
        name: String,
        tool: String,
        #[arg(default_value = "{}")]
        args: String,
    },
    /// Remove a server from the registry.
    Remove { name: String },
}

/// clap value parser for `KEY=VALUE` pairs.
fn parse_kv(s: &str) -> Result<(String, String), String> {
    match s.split_once('=') {
        Some((k, v)) => Ok((k.to_string(), v.to_string())),
        None => Err(format!("expected KEY=VALUE, got '{}'", s)),
    }
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

    let mut config = Config::default();
    let db_path = PathBuf::from(&config.home_dir).join("db");

    let db = Arc::new(HiveDb::open(&db_path).await?);

    // Fold persisted operator settings (default provider/model, per-provider
    // overrides) into the config; environment variables still win.
    hivecyber_core::settings::Settings::load(&db)
        .await
        .apply_to_config(&mut config);

    let security = build_security_context(&cli);

    match cli.command {
        Commands::Chat { agent } => cmd_chat(db.clone(), &config, &agent, security.clone()).await,
        Commands::Run { prompt, agent } => cmd_run(db.clone(), &config, &agent, &prompt, security.clone()).await,
        Commands::Agent { action } => cmd_agent(db.clone(), action).await,
        Commands::Provider { action } => cmd_provider(db.clone(), &config, action).await,
        Commands::Models { provider } => cmd_models(db.clone(), provider).await,
        Commands::Skills { action } => cmd_skills(db.clone(), &config, action).await,
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
    if unsafe_mode && allowlist.is_empty() && cli.engagement_policy.is_none() {
        eprintln!("Warning: --unsafe-mode set but --allowlist-hosts not provided or empty");
        eprintln!("         dangerous commands will be rejected");
    }

    // Load explicit EngagementPolicy YAML if provided; otherwise migrate the
    // legacy --allowlist-hosts file into a permissive EngagementPolicy so the
    // path/method/rate-limit/prohibited machinery is uniformly enforced.
    let mut policy: Option<hivecyber_tools::EngagementPolicy> = None;
    if let Some(ref ep_path) = cli.engagement_policy {
        match std::fs::read_to_string(ep_path) {
            Ok(content) => match serde_yaml::from_str::<hivecyber_tools::EngagementPolicy>(&content) {
                Ok(p) => {
                    eprintln!(
                        "Loaded engagement policy '{}' with {} target(s) from {}",
                        p.program,
                        p.targets.len(),
                        ep_path.display()
                    );
                    policy = Some(p);
                }
                Err(e) => {
                    eprintln!(
                        "Warning: failed to parse engagement policy {}: {}",
                        ep_path.display(),
                        e
                    );
                }
            },
            Err(e) => {
                eprintln!(
                    "Warning: failed to read engagement policy {}: {}",
                    ep_path.display(),
                    e
                );
            }
        }
    }
    if policy.is_none() && !allowlist.is_empty() {
        policy = Some(hivecyber_tools::EngagementPolicy::from_allowlist_hosts(&allowlist));
    }

    let operator_id = std::env::var("USER").unwrap_or_else(|_| "unknown".into());

    let security = Arc::new(hivecyber_tools::SecurityContext {
        unsafe_mode,
        allowlist_hosts: allowlist,
        operator_id,
        engagement_policy: policy.map(Arc::new),
        human_approvals: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
        allow_cli_exec: cli.allow_cli_exec,
    });

    for category in &cli.approve_human {
        security.grant_human_approval(category);
    }

    security
}

/// Load + connect the configured MCP servers (if MCP is enabled). Returns the
/// shared manager so its tools can be registered for every agent this command
/// runs. Returns `None` when MCP is disabled so the whole feature is a no-op.
async fn init_mcp(
    db: &HiveDb,
    config: &Config,
) -> Option<hivecyber_core::agent::mcp_integration::SharedMcp> {
    if !config.mcp.enabled {
        return None;
    }
    Some(hivecyber_core::agent::mcp_integration::load_and_connect(db).await)
}

/// Bundled skills dir (relative to the CLI crate in dev; falls back to ./skills).
fn bundled_skills_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../skills/bundled")
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from("./skills/bundled"))
}

/// Sync skills from the filesystem (bundled + managed) into `COL_SKILLS` so the
/// agent loop's BM25 skill-selector can rank them. Best-effort.
async fn sync_skills_to_db(db: &HiveDb, config: &Config) {
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
            hivecyber_core::store::collections::COL_SKILLS,
            &s.name,
            doc,
        ).await;
    }
}

async fn cmd_chat(db: Arc<HiveDb>, config: &Config, agent_id: &str, security: Arc<hivecyber_tools::SecurityContext>) -> anyhow::Result<()> {
    use tokio::io::{AsyncBufReadExt, BufReader};

    ensure_seed_agents(&db, config).await?;
    sync_skills_to_db(&db, config).await;
    hivecyber_core::agent::models_catalog::sync_catalog(&db).await;

    let mcp = init_mcp(&db, config).await;

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
    ).with_security(security.clone()).with_mcp(mcp.clone()));
    install_terminal_hook(db.clone(), config.clone(), security.clone(), dispatch.queue(), mcp.clone());
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
            mcp_manager: mcp.clone(),
            rehydrate: false,
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
    sync_skills_to_db(&db, config).await;
    hivecyber_core::agent::models_catalog::sync_catalog(&db).await;

    let thread_id = uuid::Uuid::new_v4().to_string();

    let mcp = init_mcp(&db, config).await;

    let dispatch = Arc::new(hivecyber_core::harness::DispatchLoop::new(
        (*db).clone(),
        config.clone(),
    ).with_security(security.clone()).with_mcp(mcp.clone()));
    let active = install_terminal_hook(db.clone(), config.clone(), security.clone(), dispatch.queue(), mcp.clone());
    dispatch.clone().start().await;

    let opts = hivecyber_core::agent::loop_runner::AgentLoopOptions {
        agent_id: agent_id.to_string(),
        user_message: prompt.to_string(),
        thread_id: thread_id.clone(),
        max_iterations: 10,
        security: security.clone(),
        queue: Some(dispatch.queue()),
        mcp_manager: mcp.clone(),
        rehydrate: false,
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
    mcp: Option<hivecyber_core::agent::mcp_integration::SharedMcp>,
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
    mcp: Option<hivecyber_core::agent::mcp_integration::SharedMcp>,
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
            update_agent(&db, &id, |obj| {
                obj.insert("enabled".into(), serde_json::json!(true));
                obj.insert("status".into(), serde_json::json!("active"));
            })
            .await?;
            println!("Agent '{}' enabled.", id);
        }
        AgentCommands::Disable { id } => {
            update_agent(&db, &id, |obj| {
                obj.insert("enabled".into(), serde_json::json!(false));
                obj.insert("status".into(), serde_json::json!("disabled"));
            })
            .await?;
            println!("Agent '{}' disabled.", id);
        }
        AgentCommands::SetModel { id, model } => {
            let m = model.clone();
            update_agent(&db, &id, move |obj| {
                if m.is_empty() {
                    obj.remove("model_id");
                } else {
                    obj.insert("model_id".into(), serde_json::json!(m));
                }
            })
            .await?;
            if model.is_empty() {
                println!("Agent '{}' model cleared (uses global default).", id);
            } else {
                println!("Agent '{}' model set to '{}'.", id, model);
            }
        }
        AgentCommands::SetProvider { id, provider } => {
            let p = provider.clone();
            update_agent(&db, &id, move |obj| {
                obj.insert("provider_id".into(), serde_json::json!(p));
            })
            .await?;
            println!("Agent '{}' provider set to '{}'.", id, provider);
        }
    }
    Ok(())
}

/// Load an agent doc, apply `mutate` to its object, stamp `updated_at`, save.
async fn update_agent(
    db: &HiveDb,
    id: &str,
    mutate: impl FnOnce(&mut serde_json::Map<String, serde_json::Value>),
) -> anyhow::Result<()> {
    let mut agent = db
        .get(hivecyber_core::store::collections::COL_AGENTS, id)
        .await
        .ok_or_else(|| anyhow::anyhow!("agent not found: {}", id))?;
    let obj = agent
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("agent doc is not an object"))?;
    mutate(obj);
    obj.insert("updated_at".into(), chrono::Utc::now().to_rfc3339().into());
    db.insert(hivecyber_core::store::collections::COL_AGENTS, id, agent).await
}

/// Mask a secret for display: first 4 + last 4 chars, middle elided.
fn mask_secret(s: &str) -> String {
    let n = s.chars().count();
    if n <= 8 {
        "*".repeat(n.max(1))
    } else {
        let first: String = s.chars().take(4).collect();
        let last: String = s.chars().skip(n - 4).collect();
        format!("{}…{}", first, last)
    }
}

async fn cmd_provider(
    db: Arc<HiveDb>,
    config: &Config,
    action: ProviderCommands,
) -> anyhow::Result<()> {
    use hivecyber_core::security::crypto::{provider_key_name, resolve_api_key, SecretStore};
    use hivecyber_core::settings::Settings;
    use hivecyber_providers::ProviderRegistry;

    let known = ProviderRegistry::new().list_providers();
    let is_known = |id: &str| known.iter().any(|p| p == id);

    match action {
        ProviderCommands::Set {
            id,
            api_key,
            base_url,
            model,
        } => {
            if !is_known(&id) {
                anyhow::bail!(
                    "unknown provider '{}'. Known: {}",
                    id,
                    known.join(", ")
                );
            }
            if let Some(key) = api_key {
                let store = SecretStore::open(&config.home_dir)?;
                store.store(&db, &provider_key_name(&id), &key).await?;
                println!("API key for '{}' guardada (cifrada).", id);
            }
            if base_url.is_some() || model.is_some() {
                let mut settings = Settings::load(&db).await;
                {
                    let entry = settings.provider_entry(&id);
                    if let Some(u) = base_url {
                        entry.base_url = Some(u);
                    }
                    if let Some(m) = model {
                        entry.model = Some(m);
                    }
                }
                settings.save(&db).await?;
                println!("Configuración de '{}' actualizada.", id);
            }
        }
        ProviderCommands::List => {
            let settings = Settings::load(&db).await;
            println!(
                "{:<14} {:<8} {:<10} {}",
                "PROVIDER", "KEY", "DEFAULT", "MODEL"
            );
            for id in &known {
                let key = resolve_api_key(&db, &config.home_dir, id).await;
                let configured = if key.is_empty() { "-" } else { "set" };
                let is_default = if *id == config.models.default_provider {
                    "*"
                } else {
                    ""
                };
                let model = settings
                    .providers
                    .get(id)
                    .and_then(|p| p.model.clone())
                    .or_else(|| ProviderRegistry::new().default_model_for(id))
                    .unwrap_or_default();
                println!("{:<14} {:<8} {:<10} {}", id, configured, is_default, model);
            }
            println!(
                "\ndefault provider: {}  ·  default model: {}",
                config.models.default_provider,
                if config.models.default_model.is_empty() {
                    "(provider default)"
                } else {
                    &config.models.default_model
                }
            );
        }
        ProviderCommands::Show { id } => {
            if !is_known(&id) {
                anyhow::bail!("unknown provider '{}'. Known: {}", id, known.join(", "));
            }
            let settings = Settings::load(&db).await;
            let key = resolve_api_key(&db, &config.home_dir, &id).await;
            let ps = settings.providers.get(&id);
            println!("provider:   {}", id);
            println!(
                "api_key:    {}",
                if key.is_empty() {
                    "(no configurada)".to_string()
                } else {
                    mask_secret(&key)
                }
            );
            println!(
                "base_url:   {}",
                ps.and_then(|p| p.base_url.clone())
                    .unwrap_or_else(|| "(built-in)".into())
            );
            println!(
                "model:      {}",
                ps.and_then(|p| p.model.clone())
                    .or_else(|| ProviderRegistry::new().default_model_for(&id))
                    .unwrap_or_else(|| "(provider default)".into())
            );
            println!(
                "is_default: {}",
                id == config.models.default_provider
            );
        }
        ProviderCommands::Default { id, model } => {
            if !is_known(&id) {
                anyhow::bail!("unknown provider '{}'. Known: {}", id, known.join(", "));
            }
            let mut settings = Settings::load(&db).await;
            settings.default_provider = Some(id.clone());
            if let Some(m) = model {
                settings.default_model = Some(m);
            }
            settings.save(&db).await?;
            let m = settings.default_model.clone().unwrap_or_else(|| "(provider default)".into());
            println!("Default provider = '{}', model = '{}'.", id, m);
        }
    }
    Ok(())
}

async fn cmd_models(db: Arc<HiveDb>, provider: Option<String>) -> anyhow::Result<()> {
    let _ = db;
    let mut models = hivecyber_core::agent::models_catalog::model_catalog();
    if let Some(p) = &provider {
        models.retain(|m| &m.provider_id == p);
    }
    models.sort_by(|a, b| {
        a.provider_id.cmp(&b.provider_id).then(a.model_id.cmp(&b.model_id))
    });
    if models.is_empty() {
        println!("No hay modelos (provider '{}' desconocido).", provider.unwrap_or_default());
        return Ok(());
    }
    println!(
        "{:<13} {:<34} {:>9} {:>9} {:>9}",
        "PROVIDER", "MODEL", "CTX", "IN/1M", "OUT/1M"
    );
    for m in &models {
        let mid: String = if m.model_id.chars().count() > 34 {
            format!("{}…", m.model_id.chars().take(33).collect::<String>())
        } else {
            m.model_id.clone()
        };
        println!(
            "{:<13} {:<34} {:>9} {:>9.3} {:>9.3}",
            m.provider_id, mid, m.context_window, m.input_per_1m, m.output_per_1m
        );
    }
    println!("\n{} modelos (costo en USD por 1M tokens; ctx = context window)", models.len());
    Ok(())
}

async fn cmd_skills(db: Arc<HiveDb>, config: &Config, action: SkillsCommands) -> anyhow::Result<()> {
    let _ = db;
    let managed = std::path::PathBuf::from(&config.skills.managed_dir);

    let mut loader = hivecyber_skills::SkillLoader::new(&bundled_skills_dir(), &managed);
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
        SkillsCommands::Add { path } => {
            // Accept either a skill directory (containing SKILL.md) or the
            // SKILL.md file itself; copy the whole skill dir into the managed
            // dir under its basename, then reload.
            let src_dir = if path.is_file() {
                path.parent().map(|p| p.to_path_buf()).unwrap_or(path.clone())
            } else {
                path.clone()
            };
            let skill_md = src_dir.join("SKILL.md");
            if !skill_md.exists() {
                anyhow::bail!("no SKILL.md found in {}", src_dir.display());
            }
            let name = src_dir
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .ok_or_else(|| anyhow::anyhow!("cannot determine skill name from path"))?;
            let dest = managed.join(&name);
            copy_dir_recursive(&src_dir, &dest)?;
            println!("Skill '{}' instalada en {}", name, dest.display());
            loader.load_all()?;
            match loader.get(&name) {
                Some(s) => println!("Cargada: {} — {}", s.name, s.description.chars().take(80).collect::<String>()),
                None => println!("Aviso: copiada pero el loader no la reconoció (revisa SKILL.md)."),
            }
        }
    }
    Ok(())
}

/// Recursively copy `src` directory into `dest` (creating `dest`).
fn copy_dir_recursive(src: &std::path::Path, dest: &std::path::Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dest)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let from = entry.path();
        let to = dest.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_recursive(&from, &to)?;
        } else if ty.is_file() {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

async fn cmd_mcp(db: Arc<HiveDb>, action: McpCommands) -> anyhow::Result<()> {
    use hivecyber_core::store::collections::COL_MCP_SERVERS;
    use hivecyber_mcp::{McpClientManager, McpServerConfig};

    // Build a one-shot manager holding a single named server (loaded from the
    // registry) and connect it. Used by connect/tools/call — the CLI is
    // short-lived so connections don't persist across invocations; each command
    // spins the server up, does its work, and lets it drop.
    async fn connect_one(db: &HiveDb, name: &str) -> anyhow::Result<McpClientManager> {
        let doc = db
            .get(COL_MCP_SERVERS, name)
            .await
            .ok_or_else(|| anyhow::anyhow!("server not registered: {} (run `mcp add`)", name))?;
        let cfg: McpServerConfig = serde_json::from_value(doc)
            .map_err(|e| anyhow::anyhow!("bad config for '{}': {}", name, e))?;
        let mut mgr = McpClientManager::new();
        mgr.register(name, cfg);
        mgr.connect_server(name).await?;
        Ok(mgr)
    }

    match action {
        McpCommands::Add {
            name,
            transport,
            command,
            args,
            url,
            env,
            header,
        } => {
            match transport.as_str() {
                "stdio" => {
                    if command.is_none() {
                        anyhow::bail!("stdio transport requires --command");
                    }
                }
                "sse" | "http" | "streamable-http" => {
                    if url.is_none() {
                        anyhow::bail!("{} transport requires --url", transport);
                    }
                }
                other => anyhow::bail!("unsupported transport '{}' (use stdio|sse|http)", other),
            }
            let cfg = McpServerConfig {
                enabled: true,
                transport,
                command,
                args: if args.is_empty() { None } else { Some(args) },
                env: env.into_iter().collect(),
                url,
                headers: header.into_iter().collect(),
            };
            db.insert(COL_MCP_SERVERS, &name, serde_json::to_value(&cfg)?).await?;
            println!("MCP server '{}' registrado ({}).", name, cfg.transport);
            println!("Conecta con: hivecyber mcp connect {}", name);
        }
        McpCommands::List => {
            let servers = db.list(COL_MCP_SERVERS).await;
            if servers.is_empty() {
                println!("No hay servidores MCP registrados. Agrega uno con `hivecyber mcp add`.");
            } else {
                println!("Servidores MCP registrados:");
                for (name, doc) in servers {
                    let transport = doc.get("transport").and_then(|v| v.as_str()).unwrap_or("?");
                    let enabled = doc.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);
                    let target = doc
                        .get("command")
                        .and_then(|v| v.as_str())
                        .or_else(|| doc.get("url").and_then(|v| v.as_str()))
                        .unwrap_or("");
                    println!(
                        "  {:<20} {:<8} {:<6} {}",
                        name,
                        transport,
                        if enabled { "on" } else { "off" },
                        target
                    );
                }
            }
        }
        McpCommands::Connect { name } => {
            let mgr = connect_one(&db, &name).await?;
            let tools = mgr.list_tools();
            println!("Conectado a '{}' — {} tool(s):", name, tools.len());
            for t in tools {
                println!("  {} — {}", t.name, t.description);
            }
        }
        McpCommands::Disconnect { name } => {
            // Nothing persists across CLI runs; validate the server exists so the
            // command is honest rather than a silent no-op.
            if db.get(COL_MCP_SERVERS, &name).await.is_none() {
                anyhow::bail!("server not registered: {}", name);
            }
            println!("'{}' no tiene conexiones persistentes en modo CLI (no-op).", name);
        }
        McpCommands::Tools { name } => match name {
            Some(name) => {
                let mgr = connect_one(&db, &name).await?;
                let tools = mgr.list_tools();
                println!("{} tool(s) en '{}':", tools.len(), name);
                for t in tools {
                    println!("  {} — {}", t.name, t.description);
                }
            }
            None => {
                let servers = db.list(COL_MCP_SERVERS).await;
                for (name, _) in servers {
                    match connect_one(&db, &name).await {
                        Ok(mgr) => {
                            println!("[{}]", name);
                            for t in mgr.list_tools() {
                                println!("  {} — {}", t.name, t.description);
                            }
                        }
                        Err(e) => println!("[{}] error: {}", name, e),
                    }
                }
            }
        },
        McpCommands::Call { name, tool, args } => {
            let parsed: serde_json::Value = serde_json::from_str(&args)
                .map_err(|e| anyhow::anyhow!("args no es JSON valido: {}", e))?;
            let mut mgr = connect_one(&db, &name).await?;
            let result = mgr.call_tool(&name, &tool, &parsed).await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        McpCommands::Remove { name } => {
            if db.get(COL_MCP_SERVERS, &name).await.is_none() {
                anyhow::bail!("server not registered: {}", name);
            }
            db.delete(COL_MCP_SERVERS, &name).await?;
            println!("MCP server '{}' eliminado.", name);
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

    sync_skills_to_db(&db, config).await;
    hivecyber_core::agent::models_catalog::sync_catalog(&db).await;
    let mcp = init_mcp(&db, config).await;
    let loop_runner = AgentLoop::new((*db).clone(), config.clone());
    let opts = hivecyber_core::agent::loop_runner::AgentLoopOptions {
        agent_id: agent_id.to_string(),
        user_message: "Continua la operacion desde el ultimo checkpoint.".into(),
        thread_id: thread_id.to_string(),
        max_iterations: 10,
        security: security.clone(),
        queue: None,
        mcp_manager: mcp,
        rehydrate: true,
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

    // Platform banner + sandbox availability (this is what differs per OS).
    println!(
        "hivecyber doctor — plataforma: {} / {}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    if cfg!(target_os = "linux") {
        println!("  Sandbox del worker: DISPONIBLE (seccomp + rlimits + namespaces) — las tools");
        println!("  Isolation::Sandbox (metasploit_rpc, hydra, crackmapexec, mimikatz) se confinan.");
    } else {
        let opted = std::env::var("HIVECYBER_ALLOW_UNSANDBOXED")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        println!(
            "  Sandbox del worker: NO DISPONIBLE en {} — las tools Isolation::Sandbox se",
            std::env::consts::OS
        );
        if opted {
            println!("  RECHAZAN por defecto, pero HIVECYBER_ALLOW_UNSANDBOXED=1 está activo → correrán SIN confinar (inseguro).");
        } else {
            println!("  RECHAZAN por defecto (fail-closed). Usa la imagen Docker (Linux), o exporta");
            println!("  HIVECYBER_ALLOW_UNSANDBOXED=1 para forzarlas sin confinar (inseguro). Ver docs/distribution.md");
        }
    }
    // agent-browser (subproceso Chrome) — dependencia opcional para browser_*.
    let ab = std::env::var("AGENT_BROWSER_BIN").unwrap_or_else(|_| "agent-browser".into());
    let ab_ok = find_in_path(&ab).is_some();
    println!(
        "  agent-browser: {} (tools browser_*)",
        if ab_ok { "OK" } else { "MISSING (opcional)" }
    );

    println!("\nDependencias cybersec (shell-out):\n");
    let mut missing_bins: Vec<&str> = Vec::new();
    for (name, binary) in &tools {
        if find_in_path(binary).is_some() {
            println!("  [OK]      {} ({})", name, binary);
        } else {
            println!("  [MISSING] {} ({})", name, binary);
            missing_bins.push(binary);
        }
    }
    let missing = missing_bins.len();
    println!("\n{} tools found, {} missing", tools.len() - missing, missing);

    if missing > 0 {
        println!("\nInstalación (según tu SO):");
        match std::env::consts::OS {
            "linux" => {
                println!("  # Debian/Ubuntu (subset en apt):");
                println!("  sudo apt install -y nmap nikto hydra yara whois dnsutils zeek osquery");
                println!("  # nuclei/trivy/semgrep/theHarvester/volatility3: instaladores propios (go/pip/pipx)");
                println!("  # Toolchain completo sin instalar nada: usa la imagen Docker.");
            }
            "macos" => {
                println!("  brew install nmap nikto hydra yara nuclei trivy semgrep zeek");
                println!("  # metasploit/crackmapexec/volatility3: ver sus docs; o usa Docker (Linux) para el sandbox.");
            }
            "windows" => {
                println!("  choco install nmap  # cobertura parcial en Windows");
                println!("  # Recomendado en Windows: WSL2 o la imagen Docker (Linux) — habilita además el sandbox seccomp.");
            }
            other => println!("  (SO '{}' no reconocido — instala las tools manualmente)", other),
        }
    }
    Ok(())
}

/// Cross-platform PATH lookup for an executable (replaces shelling out to
/// `which`, which does not exist on Windows). On Windows, tries the `PATHEXT`
/// extensions.
fn find_in_path(binary: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    let exts: Vec<String> = if cfg!(windows) {
        std::env::var("PATHEXT")
            .unwrap_or_else(|_| ".EXE;.CMD;.BAT;.COM".into())
            .split(';')
            .map(|s| s.to_string())
            .collect()
    } else {
        vec![String::new()]
    };
    for dir in std::env::split_paths(&paths) {
        for ext in &exts {
            let candidate = dir.join(format!("{}{}", binary, ext));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
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