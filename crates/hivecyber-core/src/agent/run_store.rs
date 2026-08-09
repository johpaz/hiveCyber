use anyhow::Result;
use chrono::Utc;

use crate::store::HiveDb;
use crate::store::collections::{COL_RUNS, RunDoc, COL_JOBS, JobDoc};

pub const RUN_STATUS_PENDING: &str = "pending";
pub const RUN_STATUS_RUNNING: &str = "running";
pub const RUN_STATUS_COMPLETED: &str = "completed";
pub const RUN_STATUS_FAILED: &str = "failed";
pub const RUN_STATUS_INTERRUPTED: &str = "interrupted";

pub const JOB_STATUS_PENDING: &str = "pending";
pub const JOB_STATUS_RUNNING: &str = "running";
pub const JOB_STATUS_COMPLETED: &str = "completed";
pub const JOB_STATUS_FAILED: &str = "failed";
pub const JOB_STATUS_CANCELLED: &str = "cancelled";
pub const JOB_STATUS_INTERRUPTED: &str = "interrupted";

pub async fn create_run(
    db: &HiveDb,
    kind: &str,
    agent_id: &str,
    thread_id: &str,
    goal: serde_json::Value,
) -> Result<String> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    let run = RunDoc {
        id: id.clone(),
        kind: kind.into(),
        agent_id: agent_id.into(),
        thread_id: thread_id.into(),
        status: RUN_STATUS_PENDING.into(),
        goal,
        acceptance_json: None,
        epoch_json: None,
        state_json: None,
        lease_expires_at: None,
        parent_run_id: None,
        iterations_used: 0,
        turns_used: 0,
        tokens_used: 0,
        created_at: now,
    };

    db.insert(COL_RUNS, &id, serde_json::to_value(&run)?).await?;
    Ok(id)
}

pub async fn complete_run(db: &HiveDb, run_id: &str) -> Result<()> {
    let mut run = db
        .get(COL_RUNS, run_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("run not found"))?;
    if let Some(obj) = run.as_object_mut() {
        obj.insert("status".into(), RUN_STATUS_COMPLETED.into());
    }
    db.insert(COL_RUNS, run_id, run).await?;
    Ok(())
}

pub async fn fail_run(db: &HiveDb, run_id: &str, error: &str) -> Result<()> {
    let mut run = db
        .get(COL_RUNS, run_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("run not found"))?;
    if let Some(obj) = run.as_object_mut() {
        obj.insert("status".into(), RUN_STATUS_FAILED.into());
        if let Some(state) = obj.get_mut("state_json") {
            if state.is_null() {
                *state = serde_json::json!({"error": error});
            }
        }
    }
    db.insert(COL_RUNS, run_id, run).await?;
    Ok(())
}

pub async fn create_job(
    db: &HiveDb,
    lane: &str,
    job_type: &str,
    run_id: Option<&str>,
) -> Result<String> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    let job = JobDoc {
        id: id.clone(),
        lane: lane.into(),
        job_type: job_type.into(),
        status: JOB_STATUS_PENDING.into(),
        priority: 0,
        payload_json: None,
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

    db.insert(COL_JOBS, &id, serde_json::to_value(&job)?).await?;
    Ok(id)
}

pub async fn claim_job(db: &HiveDb, job_id: &str, boot_id: &str, lease_ms: u64) -> Result<()> {
    let mut job = db
        .get(COL_JOBS, job_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("job not found"))?;

    if let Some(obj) = job.as_object_mut() {
        let status = obj.get("status").and_then(|v| v.as_str()).unwrap_or("");
        if status != JOB_STATUS_PENDING && status != JOB_STATUS_RUNNING {
            anyhow::bail!("job not claimable: status={}", status);
        }
        obj.insert("status".into(), JOB_STATUS_RUNNING.into());
        obj.insert("attempts".into(), serde_json::json!(obj.get("attempts").and_then(|v| v.as_u64()).unwrap_or(0) + 1));
        obj.insert("boot_id".into(), boot_id.into());
        obj.insert("started_at".into(), Utc::now().to_rfc3339().into());
        let lease = Utc::now().checked_add_signed(chrono::Duration::milliseconds(lease_ms as i64))
            .unwrap_or_else(Utc::now);
        obj.insert("lease_expires_at".into(), lease.to_rfc3339().into());
    }

    db.insert(COL_JOBS, job_id, job).await?;
    Ok(())
}

pub async fn complete_job(db: &HiveDb, job_id: &str, result: serde_json::Value) -> Result<()> {
    let mut job = db
        .get(COL_JOBS, job_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("job not found"))?;

    if let Some(obj) = job.as_object_mut() {
        obj.insert("status".into(), JOB_STATUS_COMPLETED.into());
        obj.insert("result_json".into(), result);
        obj.insert("boot_id".into(), serde_json::Value::Null);
        obj.insert("lease_expires_at".into(), serde_json::Value::Null);
        obj.insert("finished_at".into(), Utc::now().to_rfc3339().into());
    }

    db.insert(COL_JOBS, job_id, job).await?;
    Ok(())
}