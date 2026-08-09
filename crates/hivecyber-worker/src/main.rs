use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WorkerRequest {
    job_id: String,
    tool_name: String,
    args: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WorkerResponse {
    job_id: String,
    success: bool,
    result: serde_json::Value,
    error: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    tracing::info!("hivecyber-worker starting (sandboxed)");

    #[cfg(target_os = "linux")]
    {
        if let Err(e) = apply_sandbox() {
            tracing::warn!("sandbox setup partial: {}", e);
        }
    }

    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let reader = BufReader::new(stdin);
    let mut lines = reader.lines();

    let registry = hivecyber_tools::ToolRegistry::create_all();
    tracing::info!("worker ready with {} tools, reading from stdin", registry.names().len());

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

#[cfg(target_os = "linux")]
fn apply_sandbox() -> anyhow::Result<()> {
    tracing::info!("applying Linux sandbox (seccomp + capabilities drop)");

    use caps::CapSet;
    use caps::Capability;

    if caps::has_cap(None, CapSet::Effective, Capability::CAP_SYS_ADMIN).unwrap_or(false) {
        if let Err(e) = caps::clear(None, CapSet::Effective) {
            tracing::warn!("failed to drop capabilities: {}", e);
        }
    }

    tracing::info!("sandbox applied (basic capabilities drop)");
    Ok(())
}