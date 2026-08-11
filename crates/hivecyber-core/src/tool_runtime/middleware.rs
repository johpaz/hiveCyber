use anyhow::Result;
use serde::Serialize;
use std::sync::Arc;
use std::time::Instant;

use crate::store::HiveDb;
use crate::security::audit;
use crate::tool_runtime::batch::ToolBatchResult;

use hivecyber_tools::{Tool, ToolRegistry, Isolation};

#[derive(Debug, Clone, Serialize)]
pub struct AuditCtx {
    pub worker: String,
    pub run_id: String,
    pub operator_id: String,
}

pub struct ToolMiddleware {
    db: HiveDb,
    security: Arc<hivecyber_tools::SecurityContext>,
}

impl ToolMiddleware {
    pub fn new(db: HiveDb, security: Arc<hivecyber_tools::SecurityContext>) -> Self {
        ToolMiddleware { db, security }
    }

    pub async fn execute(
        &self,
        tool: Arc<dyn Tool>,
        tool_name: &str,
        args: serde_json::Value,
        timeout_ms: u64,
        ctx: &AuditCtx,
    ) -> ToolBatchResult {
        let start = Instant::now();
        let target = extract_target(tool_name, &args);

        // Isolation router: tools declaring Isolation::Sandbox never execute
        // in-process. They are dispatched to the `hivecyber-worker` binary
        // over stdio, where seccomp + rlimits + namespaces confine them.
        let outcome = if tool.isolation() == Isolation::Sandbox {
            dispatch_to_worker(tool_name, &args, timeout_ms, &self.security).await
        } else {
            match tokio::time::timeout(
                std::time::Duration::from_millis(timeout_ms),
                tool.execute(args.clone()),
            )
            .await
            {
                Ok(Ok(r)) => ToolOutcome {
                    success: true,
                    result: r,
                    error: None,
                },
                Ok(Err(e)) => ToolOutcome {
                    success: false,
                    result: serde_json::Value::Null,
                    error: Some(e.to_string()),
                },
                Err(_) => ToolOutcome {
                    success: false,
                    result: serde_json::Value::Null,
                    error: Some(format!("timeout after {}ms", timeout_ms)),
                },
            }
        };

        // Invariant: every attempt is audited. Fail closed if the audit chain
        // cannot be extended — the operation is treated as failed.
        if let Err(e) = self
            .audit(ctx, tool_name, target.as_deref().unwrap_or("unknown"), &outcome)
            .await
        {
            tracing::error!("audit log write failed for tool '{}': {}", tool_name, e);
            return ToolBatchResult {
                tool_name: tool_name.to_string(),
                success: false,
                result: serde_json::Value::Null,
                duration_ms: start.elapsed().as_millis() as u64,
                error: Some(format!(
                    "audit chain broken — operation sealed: {}",
                    e
                )),
            };
        }

        ToolBatchResult {
            tool_name: tool_name.to_string(),
            success: outcome.success,
            result: outcome.result,
            duration_ms: start.elapsed().as_millis() as u64,
            error: outcome.error,
        }
    }

    async fn audit(
        &self,
        ctx: &AuditCtx,
        tool_name: &str,
        target: &str,
        outcome: &ToolOutcome,
    ) -> Result<()> {
        // Atomic read-head + append under the global audit lock, so concurrent
        // tool executions can never fork the tamper-evident chain.
        let _new = audit::append_audit(
            &self.db,
            tool_name,
            target,
            &ctx.worker,
            &ctx.run_id,
            &ctx.operator_id,
        )
        .await?;
        tracing::debug!(
            "audited tool={} target={} worker={} run={} ok={}",
            tool_name,
            target,
            ctx.worker,
            ctx.run_id,
            outcome.success
        );
        Ok(())
    }
}

struct ToolOutcome {
    success: bool,
    result: serde_json::Value,
    error: Option<String>,
}

// Spawn a hivecyber-worker subprocess, send one tool request, read one
// response. The worker applies seccomp + rlimits + namespaces before
// executing; if the binary is missing we fall back to an explicit error so
// the operator never gets a silent in-process execution of a sandboxed tool.
async fn dispatch_to_worker(
    tool_name: &str,
    args: &serde_json::Value,
    timeout_ms: u64,
    security: &hivecyber_tools::SecurityContext,
) -> ToolOutcome {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::process::Command;

    // Platform gate: the worker's seccomp/namespaces sandbox is Linux-only. On
    // other platforms a sandboxed (exploit) tool would run UNCONFINED, so we
    // refuse by default — turning a silent security downgrade into an explicit,
    // audited failure. Operators who accept the risk opt in via
    // HIVECYBER_ALLOW_UNSANDBOXED=1 (e.g. an isolated macOS lab). The worker
    // itself enforces the same gate as defense in depth.
    if sandbox_refuses(sandbox_enforced(), allow_unsandboxed()) {
        return ToolOutcome {
            success: false,
            result: serde_json::Value::Null,
            error: Some(format!(
                "sandbox unavailable on {} — refusing to run sandboxed tool '{}'. \
                 Run it in the Linux Docker image, or set HIVECYBER_ALLOW_UNSANDBOXED=1 to override (unsafe).",
                std::env::consts::OS, tool_name
            )),
        };
    }

    let bin = std::env::var("HIVECYBER_WORKER_BIN")
        .unwrap_or_else(|_| "hivecyber-worker".to_string());

    let mut cmd = match Command::new(&bin).stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            return ToolOutcome {
                success: false,
                result: serde_json::Value::Null,
                error: Some(format!(
                    "failed to spawn hivecyber-worker '{}': {} (set HIVECYBER_WORKER_BIN)",
                    bin, e
                )),
            };
        }
    };

    // The worker builds its own ToolRegistry from a security snapshot sent
    // over the wire, since a fresh process has none of the caller's state
    // (--unsafe-mode, --allowlist-hosts, engagement policy). Without this,
    // every exploit tool routed here would always see SecurityContext::default()
    // (unsafe_mode=false, empty allowlist) and reject itself regardless of
    // what the operator actually authorized.
    let job_id = uuid::Uuid::new_v4().to_string();
    let req = serde_json::json!({
        "job_id": job_id,
        "tool_name": tool_name,
        "args": args,
        "security": {
            "unsafe_mode": security.unsafe_mode,
            "allowlist_hosts": security.allowlist_hosts,
            "operator_id": security.operator_id,
            "allow_cli_exec": security.allow_cli_exec,
            "engagement_policy": security.engagement_policy.as_ref().map(|p| p.as_ref()),
        },
    });

    let stdin = match cmd.stdin.take() {
        Some(s) => s,
        None => {
            return ToolOutcome {
                success: false,
                result: serde_json::Value::Null,
                error: Some("worker stdin unavailable".into()),
            };
        }
    };
    let stdout = match cmd.stdout.take() {
        Some(s) => s,
        None => {
            return ToolOutcome {
                success: false,
                result: serde_json::Value::Null,
                error: Some("worker stdout unavailable".into()),
            };
        }
    };

    let mut stdin = stdin;
    let mut writer_line = serde_json::to_string(&req).unwrap_or_default();
    writer_line.push('\n');

    let send = async {
        stdin.write_all(writer_line.as_bytes()).await?;
        stdin.flush().await?;
        stdin.shutdown().await
    };

    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    let recv = reader.read_line(&mut line);

    let io = tokio::time::timeout(
        std::time::Duration::from_millis(timeout_ms.max(60_000)),
        async {
            send.await.ok();
            recv.await
        },
    )
    .await;

    let _ = cmd.kill().await;

    match io {
        Ok(Ok(n)) if n > 0 => match serde_json::from_str::<serde_json::Value>(&line) {
            Ok(v) => {
                let success = v.get("success").and_then(|s| s.as_bool()).unwrap_or(false);
                let result = v.get("result").cloned().unwrap_or(serde_json::Value::Null);
                let error = v
                    .get("error")
                    .and_then(|e| e.as_str())
                    .map(String::from);
                ToolOutcome { success, result, error }
            }
            Err(e) => ToolOutcome {
                success: false,
                result: serde_json::Value::Null,
                error: Some(format!("worker parse error: {} ({})", e, line.chars().take(200).collect::<String>())),
            },
        },
        _ => ToolOutcome {
            success: false,
            result: serde_json::Value::Null,
            error: Some(format!("worker timeout or io error after {}ms", timeout_ms)),
        },
    }
}

pub fn extract_target(tool_name: &str, args: &serde_json::Value) -> Option<String> {
    let obj = args.as_object()?;
    match tool_name {
        "metasploit_rpc" | "hydra" | "crackmapexec" | "mimikatz" => {
            obj.get("target").and_then(|v| v.as_str()).map(String::from)
        }
        "nmap" | "dig" | "whois" | "theharvester" | "shodan" | "recon_ng" => obj
            .get("target")
            .or_else(|| obj.get("host"))
            .and_then(|v| v.as_str())
            .map(String::from),
        "web_fetch" | "web_search" | "nikto" | "nuclei" | "sqlmap" | "browser_navigate"
        | "browser_screenshot" | "browser_click" | "browser_type" | "browser_extract" => obj
            .get("url")
            .or_else(|| obj.get("target"))
            .and_then(|v| v.as_str())
            .map(String::from),
        "searchsploit" | "semgrep" | "trivy" => {
            obj.get("target").and_then(|v| v.as_str()).map(String::from)
        }
        "fs_read" | "fs_write" | "fs_edit" | "fs_glob" | "fs_exists" | "fs_list"
        | "fs_delete" => obj.get("path").and_then(|v| v.as_str()).map(String::from),
        "cli_exec" => obj
            .get("command")
            .and_then(|v| v.as_str())
            .map(cli_first_host),
        _ => None,
    }
}

fn cli_first_host(command: &str) -> String {
    for tok in command.split_whitespace() {
        if tok.contains('.') || tok.parse::<std::net::IpAddr>().is_ok() {
            return tok.trim_matches(':').to_string();
        }
    }
    command.chars().take(120).collect()
}

pub async fn execute_tool_batch_audited(
    tool_calls: Vec<(String, serde_json::Value)>,
    registry: &ToolRegistry,
    timeout_ms: u64,
    middleware: &ToolMiddleware,
    ctx: &AuditCtx,
) -> Vec<ToolBatchResult> {
    let mut results = Vec::new();
    for (tool_name, args) in tool_calls {
        let result = match registry.get(&tool_name) {
            Some(tool) => {
                let tool = tool.clone() as Arc<dyn Tool>;
                middleware.execute(tool, &tool_name, args, timeout_ms, ctx).await
            }
            None => ToolBatchResult {
                tool_name: tool_name.clone(),
                success: false,
                result: serde_json::Value::Null,
                duration_ms: 0,
                error: Some(format!("tool '{}' not in registry", tool_name)),
            },
        };
        results.push(result);
    }
    results
}

pub fn requires_sandbox(tool: &Arc<dyn Tool>) -> bool {
    tool.isolation() == Isolation::Sandbox
}

/// Whether the worker sandbox can actually confine tools on this build's
/// platform. The seccomp + rlimits + namespaces sandbox is Linux-only.
pub fn sandbox_enforced() -> bool {
    cfg!(target_os = "linux")
}

/// Operator opt-in to run sandboxed tools UNCONFINED on a platform without a
/// real sandbox (`HIVECYBER_ALLOW_UNSANDBOXED=1`). Off by default.
pub fn allow_unsandboxed() -> bool {
    std::env::var("HIVECYBER_ALLOW_UNSANDBOXED")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Pure policy: refuse a sandboxed tool when the platform can't sandbox and the
/// operator has not explicitly opted in. Factored out so the decision is unit
/// tested independently of the host OS.
pub fn sandbox_refuses(enforced: bool, allow_unsandboxed: bool) -> bool {
    !enforced && !allow_unsandboxed
}

#[cfg(test)]
mod sandbox_policy_tests {
    use super::sandbox_refuses;

    #[test]
    fn refuses_only_when_unenforced_and_not_opted_in() {
        // Linux (enforced) → never refuses, regardless of opt-in.
        assert!(!sandbox_refuses(true, false));
        assert!(!sandbox_refuses(true, true));
        // Non-Linux without opt-in → refuse (the security-correct default).
        assert!(sandbox_refuses(false, false));
        // Non-Linux with explicit opt-in → allowed (unsafe, operator's choice).
        assert!(!sandbox_refuses(false, true));
    }
}