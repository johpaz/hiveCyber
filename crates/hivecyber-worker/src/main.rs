use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

mod sandbox;

// Wire-format snapshot of the caller's SecurityContext. A freshly spawned
// worker process has none of the caller's state (--unsafe-mode,
// --allowlist-hosts, engagement policy) — without this, every exploit tool
// routed here would see SecurityContext::default() and reject itself
// regardless of what the operator actually authorized.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct WorkerSecurityCtx {
    #[serde(default)]
    unsafe_mode: bool,
    #[serde(default)]
    allowlist_hosts: Vec<String>,
    #[serde(default)]
    operator_id: String,
    #[serde(default)]
    allow_cli_exec: bool,
    #[serde(default)]
    engagement_policy: Option<hivecyber_tools::EngagementPolicy>,
    #[serde(default)]
    task_root: Option<String>,
}

impl WorkerSecurityCtx {
    fn into_security_context(self) -> hivecyber_tools::SecurityContext {
        hivecyber_tools::SecurityContext {
            unsafe_mode: self.unsafe_mode,
            allowlist_hosts: self.allowlist_hosts,
            operator_id: self.operator_id,
            engagement_policy: self.engagement_policy.map(Arc::new),
            human_approvals: Arc::new(Mutex::new(HashSet::new())),
            allow_cli_exec: self.allow_cli_exec,
            task_root: self.task_root.map(std::path::PathBuf::from),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct WorkerRequest {
    job_id: String,
    tool_name: String,
    args: serde_json::Value,
    #[serde(default)]
    security: WorkerSecurityCtx,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WorkerResponse {
    job_id: String,
    success: bool,
    result: serde_json::Value,
    error: Option<String>,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    tracing::info!("hivecyber-worker starting (sandboxed)");

    // Sandboxing must run before any other OS thread exists: unshare(CLONE_NEWUSER)
    // only succeeds on a single-threaded process, and #[tokio::main] would have
    // already spawned the runtime's worker threads before our async body ran.
    // So we build the tokio runtime by hand, after the sandbox is in place.
    if let Err(e) = sandbox::apply_sandbox() {
        tracing::error!("sandbox setup failed — refusing to run: {}", e);
        std::process::exit(2);
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(run())
}

async fn run() -> anyhow::Result<()> {
    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let reader = BufReader::new(stdin);
    let mut lines = reader.lines();

    tracing::info!("worker ready, reading from stdin");

    while let Ok(Some(line)) = lines.next_line().await {
        let req: WorkerRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let resp = WorkerResponse {
                    job_id: "unknown".into(),
                    success: false,
                    result: serde_json::Value::Null,
                    error: Some(format!("parse error: {}", e)),
                };
                let json = serde_json::to_string(&resp)?;
                stdout.write_all(format!("{}\n", json).as_bytes()).await?;
                stdout.flush().await?;
                continue;
            }
        };

        // Rebuild the registry per request from the security snapshot the
        // caller sent — each call must explicitly carry its own authorized
        // posture rather than trusting ambient process state.
        let registry = hivecyber_tools::ToolRegistry::create_with_security(Arc::new(
            req.security.clone().into_security_context(),
        ));
        let result = execute_tool(&registry, &req.tool_name, &req.args).await;

        let resp = match result {
            Ok(r) => WorkerResponse {
                job_id: req.job_id,
                success: true,
                result: r,
                error: None,
            },
            Err(e) => WorkerResponse {
                job_id: req.job_id,
                success: false,
                result: serde_json::Value::Null,
                error: Some(e.to_string()),
            },
        };

        let json = serde_json::to_string(&resp)?;
        stdout.write_all(format!("{}\n", json).as_bytes()).await?;
        stdout.flush().await?;
    }

    Ok(())
}

async fn execute_tool(
    registry: &hivecyber_tools::ToolRegistry,
    tool_name: &str,
    args: &serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let tool = registry
        .get(tool_name)
        .ok_or_else(|| anyhow::anyhow!("tool '{}' not registered", tool_name))?
        .clone();

    tool.execute(args.clone()).await
}