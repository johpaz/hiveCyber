use anyhow::Result;
use sha2::{Digest, Sha256};

use crate::store::HiveDb;
use crate::store::collections::{COL_AUDIT_LOG, AuditLogEntry};

pub const GENESIS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// SHA-256 over the entry's canonical field order. Single source of truth so
/// `log_audit`, `get_last_hash`, and `verify_chain` can never drift.
fn entry_hash(e: &AuditLogEntry) -> String {
    let mut hasher = Sha256::new();
    hasher.update(e.hash_chain_prev.as_bytes());
    hasher.update(e.timestamp.as_bytes());
    hasher.update(e.tool.as_bytes());
    hasher.update(e.target.as_bytes());
    hasher.update(e.worker.as_bytes());
    hasher.update(e.run_id.as_bytes());
    hasher.update(e.operator_id.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Total order over audit entries: chronological, with the id as tiebreaker.
/// **Both** the writer (`get_last_hash`) and the verifier (`verify_chain`) must
/// use this exact order — `db.list` returns entries sorted by id (UUID), which
/// is NOT chronological, so relying on `list().last()` picked the wrong "prev"
/// once ids stopped sorting in insertion order and broke the chain.
fn sorted_entries(mut entries: Vec<(String, serde_json::Value)>) -> Vec<(String, serde_json::Value)> {
    entries.sort_by(|a, b| {
        let ts_a = a.1.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
        let ts_b = b.1.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
        ts_a.cmp(ts_b).then_with(|| a.0.cmp(&b.0))
    });
    entries
}

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
    let current_hash = entry_hash(&entry);

    db.insert(COL_AUDIT_LOG, &id, serde_json::to_value(&entry)?).await?;
    Ok(current_hash)
}

pub async fn get_last_hash(db: &HiveDb) -> String {
    let entries = sorted_entries(db.list(COL_AUDIT_LOG).await);
    entries
        .last()
        .and_then(|(_, v)| serde_json::from_value::<AuditLogEntry>(v.clone()).ok())
        .map(|e| entry_hash(&e))
        .unwrap_or_else(|| GENESIS_HASH.to_string())
}

pub async fn verify_chain(db: &HiveDb) -> Result<(bool, Vec<String>)> {
    let entries = sorted_entries(db.list(COL_AUDIT_LOG).await);

    let mut errors = Vec::new();
    let mut prev_hash = GENESIS_HASH.to_string();

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

        prev_hash = entry_hash(&entry);
    }

    Ok((errors.is_empty(), errors))
}