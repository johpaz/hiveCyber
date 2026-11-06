//! hivecyber-gateway — local HTTP/WS control plane for the Rune panel.
//!
//! Binds 127.0.0.1 by default. One operator, bearer-token auth (token printed
//! once at startup and stored 0600 in `$HIVECYBER_HOME/gateway.token`).

mod admin;
mod chat;
mod policy_store;
mod routes;
mod state;

use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use clap::Parser;
use hivecyber_core::{bootstrap, Config, HiveDb};
use state::{build_runtime, AppState, StartupFlags};
use tokio::sync::{Mutex, RwLock};
use tower_http::services::{ServeDir, ServeFile};

#[derive(Parser)]
#[command(name = "hivecyber-gateway", version, about = "Gateway HTTP/WS para el panel web de hiveCyber")]
struct Args {
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    port: Option<u16>,
    /// Permite bindear fuera de loopback (peligroso: el gateway controla agentes).
    #[arg(long)]
    allow_non_loopback: bool,
    /// EngagementPolicy (YAML/JSON) a importar como nueva versión activa al arrancar.
    #[arg(long)]
    engagement_policy: Option<PathBuf>,
    /// Sin política activa el chat queda bloqueado (siempre; flag informativo en /api/security/status).
    #[arg(long)]
    require_policy: bool,
    #[arg(long)]
    unsafe_mode: bool,
    #[arg(long)]
    allow_cli_exec: bool,
    /// Directorio con el build estático del panel (panel/dist).
    #[arg(long)]
    panel_dir: Option<PathBuf>,
}

async fn auth(State(s): State<state::Shared>, req: Request, next: Next) -> Result<Response, StatusCode> {
    let ok = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(|t| ct_eq(t.as_bytes(), s.token.as_bytes()))
        .unwrap_or(false);
    if ok { Ok(next.run(req).await) } else { Err(StatusCode::UNAUTHORIZED) }
}

/// Constant-time equality (token compare).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn load_or_create_token(home: &str) -> anyhow::Result<String> {
    use std::os::unix::fs::PermissionsExt;
    let path = PathBuf::from(home).join("gateway.token");
    if let Ok(t) = std::fs::read_to_string(&path) {
        let t = t.trim().to_string();
        if t.len() >= 32 {
            return Ok(t);
        }
    }
    let token: String = (0..2).map(|_| uuid::Uuid::new_v4().simple().to_string()).collect();
    std::fs::create_dir_all(home)?;
    std::fs::write(&path, &token)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(token)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let mut config = Config::default();
    let host = args.host.clone().unwrap_or_else(|| config.gateway.host.clone());
    let port = args.port.unwrap_or(config.gateway.port);
    let loopback = matches!(host.as_str(), "127.0.0.1" | "localhost" | "::1");
    if !loopback && !args.allow_non_loopback {
        anyhow::bail!("refusing to bind '{host}': use --allow-non-loopback only if you really mean to expose the gateway");
    }

    let db = Arc::new(HiveDb::open(&PathBuf::from(&config.home_dir).join("db")).await?);
    hivecyber_core::settings::Settings::load(&db).await.apply_to_config(&mut config);

    bootstrap::ensure_seed_agents(&db, &config).await?;
    bootstrap::sync_skills_to_db(&db, &config).await;
    hivecyber_core::agent::models_catalog::sync_catalog(&db).await;
    let mcp = bootstrap::init_mcp(&db, &config).await;

    let flags = StartupFlags {
        unsafe_mode: args.unsafe_mode,
        allow_cli_exec: args.allow_cli_exec,
        require_policy: args.require_policy,
        operator_id: std::env::var("USER").unwrap_or_else(|_| "unknown".into()),
    };

    // Optional startup import: becomes a new version, activated through the
    // same audited path as the UI.
    if let Some(path) = &args.engagement_policy {
        let raw = std::fs::read_to_string(path)?;
        let policy: serde_json::Value = serde_yaml::from_str(&raw)?;
        let draft = policy_store::save_draft(&db, policy, Some("imported at startup".into()), &flags.operator_id).await?;
        policy_store::activate(&db, draft["version"].as_u64().unwrap_or(1), &flags.operator_id).await?;
    }

    let policy = policy_store::active_policy(&db).await;
    if args.require_policy && policy.is_none() {
        eprintln!("warning: --require-policy and no active policy: chat stays blocked until one is activated");
    }
    let runtime = build_runtime(&db, &config, &flags, policy, mcp).await;

    let token = load_or_create_token(&config.home_dir)?;
    let shared: state::Shared = Arc::new(AppState {
        db,
        config,
        flags,
        token: token.clone(),
        runtime: RwLock::new(runtime),
        activation_lock: Mutex::new(()),
        tickets: Default::default(),
    });

    let api = Router::new()
        .route("/security/status", get(routes::security_status))
        .route("/ws-ticket", post(routes::ws_ticket))
        .route("/dashboard/summary", get(routes::dashboard))
        .route("/agents", get(routes::list_agents))
        .route("/agents/:id", get(routes::get_agent))
        .route("/runs", get(routes::list_runs))
        .route("/runs/by-thread/:thread/messages", get(admin::run_messages))
        .route("/agents/:id/enable", post(admin::agent_enable))
        .route("/agents/:id/disable", post(admin::agent_disable))
        .route("/agents/:id/model", axum::routing::put(admin::agent_set_model))
        .route("/agents/:id/provider", axum::routing::put(admin::agent_set_provider))
        .route("/providers", get(admin::list_providers))
        .route("/providers/default", axum::routing::put(admin::set_default_provider))
        .route("/providers/:id", axum::routing::put(admin::set_provider))
        .route("/providers/:id/live-models", get(admin::live_models))
        .route("/providers/:id/server-status", get(admin::server_status))
        .route("/providers/:id/load-model", post(admin::load_model))
        .route("/activity", get(admin::activity))
        .route("/models", get(admin::list_models))
        .route("/doctor", get(admin::doctor))
        .route("/skills", get(admin::list_skills))
        .route("/mcp", get(admin::list_mcp))
        .route("/audit", get(routes::list_audit))
        .route("/audit/verify", get(routes::verify_audit))
        .route("/engagement-policy", get(routes::get_policy).put(routes::put_policy))
        .route("/engagement-policy/versions", get(routes::policy_versions))
        .route("/engagement-policy/:version/activate", post(routes::activate_policy))
        .route_layer(middleware::from_fn_with_state(shared.clone(), auth));

    // The WS route authenticates with a one-shot ticket instead of a header.
    let mut app = Router::new()
        .nest("/api", api.route("/chat/:agent_id", get(chat::chat_ws)))
        .with_state(shared.clone());

    if let Some(dir) = &args.panel_dir {
        app = app.fallback_service(ServeDir::new(dir).fallback(ServeFile::new(dir.join("index.html"))));
    }

    let addr = format!("{host}:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("hivecyber-gateway escuchando en http://{addr}");
    println!("token (Authorization: Bearer …): {token}");
    println!("(guardado en {}/gateway.token — no ejecutes la CLI contra este HIVECYBER_HOME mientras el gateway esté activo)", shared.config.home_dir);
    axum::serve(listener, app).await?;
    Ok(())
}
