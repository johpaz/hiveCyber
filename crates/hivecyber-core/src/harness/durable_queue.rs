use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{interval, Duration};

use crate::store::HiveDb;
use crate::store::collections::{COL_JOBS, JobDoc};
use crate::agent::run_store::{
    JOB_STATUS_PENDING, JOB_STATUS_RUNNING, JOB_STATUS_COMPLETED,
    JOB_STATUS_FAILED, JOB_STATUS_CANCELLED,
};

pub const DEFAULT_MAX_GLOBAL_CONCURRENCY: usize = 4;
pub const JOB_LEASE_MS: u64 = 30 * 60 * 1000;
pub const LEASE_RENEW_MS: u64 = 30 * 1000;
pub const MAINTENANCE_TICK_MS: u64 = 10 * 1000;
pub const MAX_RETRIES: u32 = 3;

type TerminalHook = Arc<dyn Fn(String, serde_json::Value) + Send + Sync>;

pub struct DurableQueue {
    db: HiveDb,
    max_concurrency: usize,
    running_count: Arc<Mutex<usize>>,
    terminal_hooks: Arc<Mutex<Vec<TerminalHook>>>,
    boot_id: String,
}

impl DurableQueue {
    pub fn new(db: HiveDb) -> Self {
        DurableQueue {
            db,
            max_concurrency: DEFAULT_MAX_GLOBAL_CONCURRENCY,
            running_count: Arc::new(Mutex::new(0)),
            terminal_hooks: Arc::new(Mutex::new(Vec::new())),
            boot_id: uuid::Uuid::new_v4().to_string(),
        }
    }

    pub fn with_max_concurrency(mut self, max: usize) -> Self {
        self.max_concurrency = max;
        self
    }

    pub fn boot_id(&self) -> &str {
        &self.boot_id
    }

    pub async fn enqueue(
        &self,
        lane: &str,
        job_type: &str,
        payload: serde_json::Value,
        run_id: Option<&str>,
    ) -> Result<String> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();

        let job = JobDoc {
            id: id.clone(),
            lane: lane.into(),
            job_type: job_type.into(),
            status: JOB_STATUS_PENDING.into(),
            priority: 0,
            payload_json: Some(payload),
            run_id: run_id.map(|s| s.into()),
            attempts: 0,
            max_attempts: 2,
            not_before: None,
            boot_id: None,
            lease_expires_at: None,
            result_json: None,
            error: None,
            retry_count: 0,
            created_at: now,
            started_at: None,
            finished_at: None,
        };

        self.db.insert(COL_JOBS, &id, serde_json::to_value(&job)?).await?;
        tracing::info!("enqueued job {} lane={} type={}", id, lane, job_type);
        Ok(id)
    }

    pub async fn find_pending_by_lane(&self, lane: &str) -> Vec<(String, String, serde_json::Value)> {
        let jobs = self.db.list(COL_JOBS).await;
        let now = chrono::Utc::now();

        jobs.into_iter()
            .filter(|(_, v)| {
                let status = v.get("status").and_then(|s| s.as_str()).unwrap_or("");
                let job_lane = v.get("lane").and_then(|l| l.as_str()).unwrap_or("");
                if status != JOB_STATUS_PENDING || job_lane != lane {
                    return false;
                }
                if let Some(nb) = v.get("not_before").and_then(|n| n.as_str()) {
                    if let Ok(nb_time) = chrono::DateTime::parse_from_rfc3339(nb) {
                        return nb_time.with_timezone(&chrono::Utc) <= now;
                    }
                }
                true
            })
            .map(|(id, v)| {
                let jtype = v.get("type").and_then(|t| t.as_str()).unwrap_or("").to_string();
                let payload = v.get("payload_json").cloned().unwrap_or(serde_json::Value::Null);
                (id, jtype, payload)
            })
            .collect()
    }

    pub async fn claim_job(&self, job_id: &str) -> Result<JobDoc> {
        let mut job_val = self
            .db
            .get(COL_JOBS, job_id)
            .await
            .ok_or_else(|| anyhow::anyhow!("job not found"))?;

        let status = job_val.get("status").and_then(|s| s.as_str()).unwrap_or("");
        if status != JOB_STATUS_PENDING {
            anyhow::bail!("job not claimable: status={}", status);
        }

        if let Some(obj) = job_val.as_object_mut() {
            let attempts = obj.get("attempts").and_then(|a| a.as_u64()).unwrap_or(0) + 1;
            obj.insert("status".into(), JOB_STATUS_RUNNING.into());
            obj.insert("attempts".into(), serde_json::json!(attempts));
            obj.insert("boot_id".into(), self.boot_id.clone().into());
            obj.insert("started_at".into(), chrono::Utc::now().to_rfc3339().into());
            let lease = chrono::Utc::now()
                .checked_add_signed(chrono::Duration::milliseconds(JOB_LEASE_MS as i64))
                .unwrap_or_else(chrono::Utc::now);
            obj.insert("lease_expires_at".into(), lease.to_rfc3339().into());
        }

        self.db.insert(COL_JOBS, job_id, job_val.clone()).await?;
        Ok(serde_json::from_value(job_val)?)
    }

    pub async fn complete_job(&self, job_id: &str, result: serde_json::Value) -> Result<()> {
        let mut job = self.db.get(COL_JOBS, job_id).await
            .ok_or_else(|| anyhow::anyhow!("job not found"))?;

        if let Some(obj) = job.as_object_mut() {
            obj.insert("status".into(), JOB_STATUS_COMPLETED.into());
            obj.insert("result_json".into(), result.clone());
            obj.insert("boot_id".into(), serde_json::Value::Null);
            obj.insert("lease_expires_at".into(), serde_json::Value::Null);
            obj.insert("finished_at".into(), chrono::Utc::now().to_rfc3339().into());
        }

        self.db.insert(COL_JOBS, job_id, job).await?;
        self.fire_terminal_hooks(job_id, result).await;
        Ok(())
    }

    pub async fn fail_job(&self, job_id: &str, error: &str) -> Result<()> {
        let mut job = self.db.get(COL_JOBS, job_id).await
            .ok_or_else(|| anyhow::anyhow!("job not found"))?;

        if let Some(obj) = job.as_object_mut() {
            let retry_count = obj.get("retry_count").and_then(|r| r.as_u64()).unwrap_or(0) as u32;
            let max_retries = MAX_RETRIES;

            if retry_count < max_retries {
                let delay_ms = 1000u64 * (1 << retry_count.min(5));
                let not_before = chrono::Utc::now()
                    .checked_add_signed(chrono::Duration::milliseconds(delay_ms as i64))
                    .unwrap_or_else(chrono::Utc::now);
                obj.insert("status".into(), JOB_STATUS_PENDING.into());
                obj.insert("retry_count".into(), serde_json::json!(retry_count + 1));
                obj.insert("not_before".into(), not_before.to_rfc3339().into());
                obj.insert("error".into(), error.into());
                obj.insert("boot_id".into(), serde_json::Value::Null);
                obj.insert("lease_expires_at".into(), serde_json::Value::Null);
                tracing::warn!("job {} failed (retry {}/{}), requeue in {}ms", job_id, retry_count + 1, max_retries, delay_ms);
            } else {
                obj.insert("status".into(), JOB_STATUS_FAILED.into());
                obj.insert("error".into(), error.into());
                obj.insert("boot_id".into(), serde_json::Value::Null);
                obj.insert("lease_expires_at".into(), serde_json::Value::Null);
                obj.insert("finished_at".into(), chrono::Utc::now().to_rfc3339().into());
                tracing::error!("job {} failed permanently: {}", job_id, error);
            }
        }

        self.db.insert(COL_JOBS, job_id, job).await?;
        Ok(())
    }

    pub async fn cancel_job(&self, job_id: &str) -> Result<()> {
        let mut job = self.db.get(COL_JOBS, job_id).await
            .ok_or_else(|| anyhow::anyhow!("job not found"))?;

        if let Some(obj) = job.as_object_mut() {
            obj.insert("status".into(), JOB_STATUS_CANCELLED.into());
            obj.insert("boot_id".into(), serde_json::Value::Null);
            obj.insert("lease_expires_at".into(), serde_json::Value::Null);
            obj.insert("finished_at".into(), chrono::Utc::now().to_rfc3339().into());
        }

        self.db.insert(COL_JOBS, job_id, job).await?;
        Ok(())
    }

    pub async fn check_expired_leases(&self) -> Result<Vec<String>> {
        let jobs = self.db.list(COL_JOBS).await;
        let now = chrono::Utc::now();
        let mut expired = Vec::new();

        for (id, v) in jobs {
            let status = v.get("status").and_then(|s| s.as_str()).unwrap_or("");
            if status != JOB_STATUS_RUNNING {
                continue;
            }
            if let Some(lease) = v.get("lease_expires_at").and_then(|l| l.as_str()) {
                if let Ok(lease_time) = chrono::DateTime::parse_from_rfc3339(lease) {
                    if lease_time.with_timezone(&chrono::Utc) <= now {
                        let attempts = v.get("attempts").and_then(|a| a.as_u64()).unwrap_or(0) as u32;
                        let max_attempts = v.get("max_attempts").and_then(|a| a.as_u64()).unwrap_or(2) as u32;

                        let mut job = v.clone();
                        if let Some(obj) = job.as_object_mut() {
                            if attempts >= max_attempts {
                                obj.insert("status".into(), "interrupted".into());
                            } else {
                                obj.insert("status".into(), JOB_STATUS_PENDING.into());
                            }
                            obj.insert("boot_id".into(), serde_json::Value::Null);
                            obj.insert("lease_expires_at".into(), serde_json::Value::Null);
                        }
                        self.db.insert(COL_JOBS, &id, job).await?;
                        expired.push(id.clone());
                        tracing::warn!("lease expired for job {}, reclaiming", id);
                    }
                }
            }
        }

        Ok(expired)
    }

    pub async fn get_running_count(&self) -> usize {
        *self.running_count.lock().await
    }

    pub fn register_terminal_hook(&self, hook: TerminalHook) {
        let hooks = self.terminal_hooks.clone();
        tokio::spawn(async move {
            hooks.lock().await.push(hook);
        });
    }

    async fn fire_terminal_hooks(&self, job_id: &str, result: serde_json::Value) {
        let hooks = self.terminal_hooks.lock().await;
        for hook in hooks.iter() {
            hook(job_id.to_string(), result.clone());
        }
    }

    pub async fn list_lanes(&self) -> Vec<String> {
        let jobs = self.db.list(COL_JOBS).await;
        let mut lanes: std::collections::HashSet<String> = std::collections::HashSet::new();
        for (_, v) in jobs {
            if let Some(lane) = v.get("lane").and_then(|l| l.as_str()) {
                lanes.insert(lane.to_string());
            }
        }
        lanes.into_iter().collect()
    }
}