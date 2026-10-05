//! Re-exec wrapper: when `--containerize` (or `HIVECYBER_CONTAINERIZE=1`) is
//! set, re-launch this exact invocation inside a Podman container instead of
//! running in-process on the bare host.
//!
//! This does NOT duplicate the agent-loop/dispatch logic — it builds a
//! `podman run` of the *same* `hivecyber` binary + subcommand + flags the
//! operator typed, with `docker/egress-entrypoint.sh` as the entrypoint (runs
//! as root to apply the nftables egress firewall derived from
//! `--engagement-policy`, then drops to the unprivileged `hive` user before
//! the real `hivecyber <subcommand>` runs). See the sandbox-architecture plan
//! for the full rationale: one container per process (interactive session or
//! `daemon`), not one per task — `EngagementPolicy` and `SecurityContext` are
//! already process-scoped, so the egress allowlist naturally is too.
//!
//! Two things get bind-mounted at identical in-container paths so existing
//! relative-path conventions (`--engagement-policy engagements/foo/policy.json`,
//! `findings/`, `reports/`) keep working unchanged inside the container:
//!   - the current working directory (the "workspace": findings/reports/
//!     engagements), and
//!   - `$HIVECYBER_HOME` (HiveDB `db/`, the audit log, and the per-task
//!     `scratch/` dirs from `harness/executors.rs` / `agent/loop_runner.rs`).

use std::path::Path;
use std::process::Stdio;

/// Whether this invocation should be re-exec'd inside Podman: either the
/// `--containerize` flag or `HIVECYBER_CONTAINERIZE=1`/`true`.
pub fn requested(containerize_flag: bool) -> bool {
    containerize_flag
        || std::env::var("HIVECYBER_CONTAINERIZE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
}

/// Build and run the `podman run` wrapping this same invocation, waiting for
/// it to exit. Returns the container's exit code (best-effort; non-zero on
/// any orchestration failure that prevents the container from ever running).
pub async fn exec_in_podman(engagement_policy: Option<&Path>) -> anyhow::Result<i32> {
    let image = std::env::var("HIVECYBER_IMAGE").unwrap_or_else(|_| "hivecyber:sandboxed".to_string());

    let cwd = std::env::current_dir()?;
    let home_dir = hivecyber_core::Config::default().home_dir;
    let container_name = format!("hivecyber-{}", uuid::Uuid::new_v4());

    // Reconstruct the original argv, dropping argv[0] (our own binary path)
    // and the `--containerize` flag itself (the in-container process must run
    // for real, not recurse into another podman launch). If an
    // `--engagement-policy <path>` pair is present, rewrite the path to the
    // fixed in-container mount point `/policy.json` — the host path won't
    // exist inside the container's mount namespace.
    let raw: Vec<String> = std::env::args().collect();
    let mut inner_args: Vec<String> = Vec::with_capacity(raw.len());
    let mut iter = raw.into_iter().skip(1).peekable();
    while let Some(arg) = iter.next() {
        if arg == "--containerize" {
            continue;
        }
        if arg == "--engagement-policy" {
            inner_args.push(arg);
            // Consume (and discard) the original path value; substitute the
            // fixed in-container mount point instead.
            iter.next();
            inner_args.push("/policy.json".to_string());
            continue;
        }
        inner_args.push(arg);
    }

    let mut cmd = tokio::process::Command::new("podman");
    cmd.arg("run")
        .arg("--rm")
        .arg("--name").arg(&container_name)
        .arg("--cap-add=NET_ADMIN")
        .arg("--user=0")
        .arg("--entrypoint=/usr/local/bin/egress-entrypoint.sh")
        // Workspace (findings/reports/engagements/…): same path in and out so
        // relative paths the operator already uses keep working.
        .arg("-v").arg(format!("{}:{}", cwd.display(), cwd.display()))
        .arg("--workdir").arg(cwd.display().to_string())
        // HiveDB (db/, audit log, per-task scratch/): same path in and out.
        .arg("-v").arg(format!("{}:{}", home_dir, home_dir))
        .arg("-e").arg(format!("HIVECYBER_HOME={}", home_dir));

    if let Some(policy_path) = engagement_policy {
        let abs_policy = if policy_path.is_absolute() {
            policy_path.to_path_buf()
        } else {
            cwd.join(policy_path)
        };
        cmd.arg("-v")
            .arg(format!("{}:/policy.json:ro", abs_policy.display()))
            .arg("-e")
            .arg("HIVECYBER_EGRESS_POLICY=/policy.json");
    } else {
        tracing::warn!(
            "--containerize sin --engagement-policy: el contenedor arrancara SIN firewall de egreso \
             (egress-entrypoint.sh lo advierte igual, pero quedate explicito: inseguro para bug bounty)."
        );
    }

    // Egress allowlist (LLM provider CIDR, MCP endpoints, etc.) and DNS
    // resolver: passed straight through from the operator's own environment,
    // same env vars `docker/egress-entrypoint.sh` already reads.
    for var in ["HIVECYBER_EGRESS_ALLOW", "HIVECYBER_EGRESS_RESOLVER"] {
        if let Ok(val) = std::env::var(var) {
            cmd.arg("-e").arg(format!("{}={}", var, val));
        }
    }

    // Interactive stdio passthrough (needed for `hivecyber chat`); harmless
    // for `daemon`/`run`, which don't read stdin. No `-t`: systemd/CI
    // invocations have no TTY, and `-it` without one fails outright.
    cmd.arg("-i");

    cmd.arg(&image).args(&inner_args);
    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    tracing::info!("containerize: podman run --name {} {}", container_name, image);

    let mut child = cmd.spawn()?;

    // Forward SIGINT to `podman stop` so Ctrl-C tears the container down
    // cleanly instead of leaving it orphaned (the outer `hivecyber` process
    // would otherwise exit while the containerized one keeps running).
    let stop_name = container_name.clone();
    let ctrl_c = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            let _ = tokio::process::Command::new("podman")
                .arg("stop").arg(&stop_name)
                .stdout(Stdio::null()).stderr(Stdio::null())
                .status()
                .await;
        }
    });

    let status = child.wait().await?;
    ctrl_c.abort();

    Ok(status.code().unwrap_or(1))
}
