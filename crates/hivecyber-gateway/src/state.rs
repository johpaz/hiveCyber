//! Shared gateway state.
//!
//! The gateway is the ONLY long-lived process that opens `HiveDb` (the store
//! has no cross-process locking), so the CLI must not run against the same
//! `HIVECYBER_HOME` while the gateway is up.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hivecyber_core::agent::mcp_integration::SharedMcp;
use hivecyber_core::bootstrap;
use hivecyber_core::harness::DispatchLoop;
use hivecyber_core::{Config, HiveDb};
use hivecyber_tools::{EngagementPolicy, SecurityContext};
use tokio::sync::{Mutex, RwLock};

pub const COL_POLICIES: &str = "engagement_policies";

/// Flags fixed at process start. Deliberately NOT changeable over HTTP.
#[derive(Clone)]
pub struct StartupFlags {
    pub unsafe_mode: bool,
    pub allow_cli_exec: bool,
    pub require_policy: bool,
    pub operator_id: String,
}

/// Everything that must be rebuilt when the active EngagementPolicy changes:
/// the SecurityContext (policy + human approvals) and the worker dispatch loop
/// that captured it.
pub struct Runtime {
    pub security: Arc<SecurityContext>,
    pub dispatch: Arc<DispatchLoop>,
    pub mcp: Option<SharedMcp>,
}

pub struct AppState {
    pub db: Arc<HiveDb>,
    pub config: Config,
    pub flags: StartupFlags,
    pub token: String,
    pub runtime: RwLock<Arc<Runtime>>,
    /// Serializes policy activation (stop old dispatch → start new).
    pub activation_lock: Mutex<()>,
    /// One-shot, short-lived WebSocket tickets (browsers can't set headers on WS).
    pub tickets: std::sync::Mutex<HashMap<String, Instant>>,
}

pub type Shared = Arc<AppState>;

const TICKET_TTL: Duration = Duration::from_secs(30);

impl AppState {
    pub fn issue_ticket(&self) -> String {
        let t = uuid::Uuid::new_v4().simple().to_string();
        let mut m = self.tickets.lock().unwrap();
        m.retain(|_, at| at.elapsed() < TICKET_TTL);
        m.insert(t.clone(), Instant::now());
        t
    }

    /// Consume a ticket (single use).
    pub fn redeem_ticket(&self, t: &str) -> bool {
        let mut m = self.tickets.lock().unwrap();
        m.retain(|_, at| at.elapsed() < TICKET_TTL);
        m.remove(t).is_some()
    }

    pub async fn runtime(&self) -> Arc<Runtime> {
        self.runtime.read().await.clone()
    }
}

/// Build a fresh Runtime for the given policy: new SecurityContext (empty
/// human approvals — a new scope never inherits old approvals), new dispatch
/// loop + terminal hook.
pub async fn build_runtime(
    db: &Arc<HiveDb>,
    config: &Config,
    flags: &StartupFlags,
    policy: Option<EngagementPolicy>,
    mcp: Option<SharedMcp>,
) -> Arc<Runtime> {
    let security = Arc::new(SecurityContext {
        unsafe_mode: flags.unsafe_mode,
        allowlist_hosts: vec![],
        operator_id: flags.operator_id.clone(),
        engagement_policy: policy.map(Arc::new),
        human_approvals: Arc::new(std::sync::Mutex::new(Default::default())),
        allow_cli_exec: flags.allow_cli_exec,
        task_root: None,
    });
    let dispatch = Arc::new(
        DispatchLoop::new((**db).clone(), config.clone())
            .with_security(security.clone())
            .with_mcp(mcp.clone()),
    );
    bootstrap::install_terminal_hook(
        db.clone(),
        config.clone(),
        security.clone(),
        dispatch.queue(),
        mcp.clone(),
    );
    dispatch.clone().start().await;
    Arc::new(Runtime { security, dispatch, mcp })
}
