use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::store::HiveDb;
use crate::store::collections::COL_TASKS;
use crate::config::Config;
use crate::harness::{DurableQueue, executors::{WorkerTaskExecutor, JobExecutor, ExecutorResult}};

/// Task statuses reaping treats as terminal — no further tool execution will
/// touch that task's scratch dir. `acceptance_pending`/`acceptance_unchecked`
/// are deliberately excluded: those tasks may still be re-run or re-checked.
const TERMINAL_TASK_STATUSES: &[&str] = &["completed", "blocked", "failed"];

pub struct DispatchLoop {
    db: HiveDb,
    config: Config,
    queue: Arc<DurableQueue>,
    executors: HashMap<String, Arc<dyn JobExecutor>>,
    running: Arc<Mutex<bool>>,
    security: Arc<hivecyber_tools::SecurityContext>,
    mcp: Option<crate::agent::mcp_integration::SharedMcp>,
}

impl DispatchLoop {
    pub fn new(db: HiveDb, config: Config) -> Self {
        let queue = Arc::new(DurableQueue::new(db.clone()));
        let security = Arc::new(hivecyber_tools::SecurityContext::default());

        let mut loop_ = DispatchLoop {
            db,
            config,
            queue,
            executors: HashMap::new(),
            running: Arc::new(Mutex::new(false)),
            security,
            mcp: None,
        };
        loop_.rebuild_worker_executor();
        loop_
    }

    /// Rebuild the `worker_task` executor from the current security + MCP so the
    /// builder setters compose (order-independent) instead of overwriting each
    /// other's configuration.
    fn rebuild_worker_executor(&mut self) {
        let worker_exec = Arc::new(
            WorkerTaskExecutor::new(self.db.clone(), self.config.clone())
                .with_security(self.security.clone())
                .with_mcp(self.mcp.clone()),
        );
        self.executors.insert("worker_task".to_string(), worker_exec);
    }

    pub fn with_security(mut self, security: Arc<hivecyber_tools::SecurityContext>) -> Self {
        self.security = security;
        self.rebuild_worker_executor();
        self
    }

    pub fn with_mcp(mut self, mcp: Option<crate::agent::mcp_integration::SharedMcp>) -> Self {
        self.mcp = mcp;
        self.rebuild_worker_executor();
        self
    }

    pub fn queue(&self) -> Arc<DurableQueue> {
        self.queue.clone()
    }

    pub async fn dispatch_all_pending(&self) -> Result<Vec<(String, ExecutorResult)>> {
        let lanes = self.queue.list_lanes().await;
        let mut results = Vec::new();

        for lane in lanes {
            let pending = self.queue.find_pending_by_lane(&lane).await;
            for (job_id, job_type, payload) in pending {
                let running = *self.running.lock().await;
                if !running {
                    break;
                }

                let executor = self.executors.get(&job_type);
                if executor.is_none() {
                    warn!("no executor for job type '{}', skipping {}", job_type, job_id);
                    continue;
                }

                match self.queue.claim_job(&job_id).await {
                    Ok(job) => {
                        info!("dispatching job {} type={} lane={}", job_id, job_type, lane);
                        let executor = executor.unwrap();
                        let exec_result = executor.execute(&job_id, &payload).await;

                        match exec_result {
                            Ok(er) => {
                                if er.ok {
                                    self.queue.complete_job(&job_id, er.result.clone()).await?;
                                } else {
                                    if er.retryable {
                                        self.queue.fail_job(&job_id, "retryable failure").await?;
                                    } else {
                                        self.queue.complete_job(&job_id, er.result.clone()).await?;
                                    }
                                }
                                results.push((job_id, er));
                            }
                            Err(e) => {
                                warn!("executor error for job {}: {}", job_id, e);
                                self.queue.fail_job(&job_id, &e.to_string()).await?;
                            }
                        }
                    }
                    Err(e) => {
                        warn!("claim failed for {}: {}", job_id, e);
                    }
                }
            }
        }

        Ok(results)
    }

    pub async fn run_maintenance(&self) -> Result<()> {
        let expired = self.queue.check_expired_leases().await?;
        if !expired.is_empty() {
            info!("maintenance: {} expired leases reclaimed", expired.len());
        }
        self.reap_scratch_dirs().await;
        Ok(())
    }

    /// Delete `$HIVECYBER_HOME/scratch/<task_id>/` for tasks that reached a
    /// terminal status more than `tools.scratch_retention_hours` ago.
    ///
    /// Scoped strictly to the `scratch/` subtree: this must never be widened
    /// to a blanket `$HIVECYBER_HOME` cleanup, since `findings/`/`reports/`
    /// (engagement deliverables) live as siblings of `scratch/` and are never
    /// meant to be reaped by this or any other maintenance pass.
    async fn reap_scratch_dirs(&self) {
        let scratch_root = std::path::PathBuf::from(&self.config.home_dir).join("scratch");
        if !scratch_root.is_dir() {
            return;
        }

        let retention = std::time::Duration::from_secs(
            self.config.tools.scratch_retention_hours.saturating_mul(3600),
        );
        let cutoff = chrono::Utc::now() - chrono::Duration::from_std(retention).unwrap_or_default();

        for (task_id, doc) in self.db.list(COL_TASKS).await {
            let status = doc.get("status").and_then(|s| s.as_str()).unwrap_or("");
            if !TERMINAL_TASK_STATUSES.contains(&status) {
                continue;
            }
            let updated_at = doc
                .get("updated_at")
                .and_then(|v| v.as_str())
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok());
            let is_stale = match updated_at {
                Some(ts) => ts < cutoff,
                // No (or unparseable) updated_at on a terminal task — don't
                // guess; leave it for a future pass once it has one.
                None => false,
            };
            if !is_stale {
                continue;
            }

            // Defense in depth: task_id is an internally generated uuid, but
            // never resolve/remove anything outside `scratch_root` regardless.
            let dir = scratch_root.join(&task_id);
            if dir.parent() != Some(scratch_root.as_path()) {
                warn!("maintenance: refusing to reap suspicious scratch path for task {}", task_id);
                continue;
            }
            if dir.is_dir() {
                match tokio::fs::remove_dir_all(&dir).await {
                    Ok(()) => info!("maintenance: reaped scratch dir for terminal task {}", task_id),
                    Err(e) => warn!("maintenance: failed to reap scratch dir for task {}: {}", task_id, e),
                }
            }
        }
    }

    pub async fn start(self: Arc<Self>) {
        let running = self.running.clone();
        *running.lock().await = true;

        let q = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(tokio::time::Duration::from_millis(crate::harness::durable_queue::MAINTENANCE_TICK_MS));
            let mut dispatch_tick = tokio::time::interval(tokio::time::Duration::from_millis(500));

            loop {
                let is_running = *running.lock().await;
                if !is_running {
                    break;
                }

                tokio::select! {
                    _ = tick.tick() => {
                        if let Err(e) = q.run_maintenance().await {
                            warn!("maintenance error: {}", e);
                        }
                    }
                    _ = dispatch_tick.tick() => {
                        if let Err(e) = q.dispatch_all_pending().await {
                            warn!("dispatch error: {}", e);
                        }
                    }
                }
            }
        });
    }

    pub async fn stop(&self) {
        *self.running.lock().await = false;
    }
}