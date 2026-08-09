use anyhow::Result;
use sha2::{Digest, Sha256};

use crate::store::HiveDb;
use crate::store::collections::{COL_AUDIT_LOG, AuditLogEntry};

pub async fn log_audit(
    db: &HiveDb,
    tool: &str,
    target: &str,
    worker: &str,
    run_id: &str,
    operator_id: &str,
    prev_hash: &str,
) -> Result<String> {
    let id = uuid::Uuid::new_v4().to_string();
    let timestamp = chrono::Utc::now().to_rfc3339();

    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(timestamp.as_bytes());
    hasher.update(tool.as_bytes());
    hasher.update(target.as_bytes());
    hasher.update(worker.as_bytes());
    hasher.update(run_id.as_bytes());
    hasher.update(operator_id.as_bytes());
    let current_hash = format!("{:x}", hasher.finalize());

    let entry = AuditLogEntry {
        id: id.clone(),
        timestamp,
        tool: tool.into(),
        target: target.into(),
        worker: worker.into(),
        run_id: run_id.into(),
        operator_id: operator_id.into(),
        hash_chain_prev: prev_hash.into(),
    };

    db.insert(COL_AUDIT_LOG, &id, serde_json::to_value(&entry)?).await?;
    Ok(current_hash)
}

pub async fn get_last_hash(db: &HiveDb) -> String {
    let entries = db.list(COL_AUDIT_LOG).await;
    entries
        .last()
        .and_then(|(_, v)| {
            let entry: AuditLogEntry = serde_json::from_value(v.clone()).ok()?;
            let mut hasher = Sha256::new();
            hasher.update(entry.hash_chain_prev.as_bytes());
            hasher.update(entry.timestamp.as_bytes());
            hasher.update(entry.tool.as_bytes());
            hasher.update(entry.target.as_bytes());
            hasher.update(entry.worker.as_bytes());
            hasher.update(entry.run_id.as_bytes());
            hasher.update(entry.operator_id.as_bytes());
            Some(format!("{:x}", hasher.finalize()))
        })
        .unwrap_or_else(|| "0000000000000000000000000000000000000000000000000000000000000000".into())
}

pub async fn verify_chain(db: &HiveDb) -> Result<(bool, Vec<String>)> {
    let mut entries = db.list(COL_AUDIT_LOG).await;
    entries.sort_by(|a, b| {
        let ts_a = a.1.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
        let ts_b = b.1.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
        ts_a.cmp(ts_b)
    });

    let mut errors = Vec::new();
    let mut prev_hash = "0000000000000000000000000000000000000000000000000000000000000000".to_string();

    for (id, val) in &entries {
        let entry: AuditLogEntry = match serde_json::from_value(val.clone()) {
            Ok(e) => e,
            Err(e) => {
                errors.push(format!("entry {}: parse error: {}", id, e));
                continue;
            }
        };

        if entry.hash_chain_prev != prev_hash {
            errors.push(format!(
                "entry {}: hash chain broken (expected {} got {})",
                id, prev_hash, entry.hash_chain_prev
            ));
        }

        let mut hasher = Sha256::new();
        hasher.update(entry.hash_chain_prev.as_bytes());
        hasher.update(entry.timestamp.as_bytes());
        hasher.update(entry.tool.as_bytes());
        hasher.update(entry.target.as_bytes());
        hasher.update(entry.worker.as_bytes());
        hasher.update(entry.run_id.as_bytes());
        hasher.update(entry.operator_id.as_bytes());
        prev_hash = format!("{:x}", hasher.finalize());
    }

    Ok((errors.is_empty(), errors))
}