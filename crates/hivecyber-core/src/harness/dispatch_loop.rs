use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::store::HiveDb;
use crate::config::Config;
use crate::harness::{DurableQueue, executors::{WorkerTaskExecutor, JobExecutor, ExecutorResult}};

pub struct DispatchLoop {
    db: HiveDb,
    config: Config,
    queue: Arc<DurableQueue>,
    executors: HashMap<String, Arc<dyn JobExecutor>>,
    running: Arc<Mutex<bool>>,
}

impl DispatchLoop {
    pub fn new(db: HiveDb, config: Config) -> Self {
        let queue = Arc::new(DurableQueue::new(db.clone()));
        let worker_exec = Arc::new(WorkerTaskExecutor::new(db.clone(), config.clone()));

        let mut executors: HashMap<String, Arc<dyn JobExecutor>> = HashMap::new();
        executors.insert("worker_task".to_string(), worker_exec);

        DispatchLoop {
            db,
            config,
            queue,
            executors,
            running: Arc::new(Mutex::new(false)),
        }
    }

    pub fn with_security(mut self, security: Arc<hivecyber_tools::SecurityContext>) -> Self {
        let worker_exec = Arc::new(
            WorkerTaskExecutor::new(self.db.clone(), self.config.clone()).with_security(security),
        );
        self.executors.insert("worker_task".to_string(), worker_exec);
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
        Ok(())
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