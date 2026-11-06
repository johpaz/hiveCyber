//! Versioned, append-only EngagementPolicy storage.
//!
//! Scope can only change through this module: a policy is saved as an inactive
//! `draft` version, then explicitly activated (two separate calls). Each
//! activation is written to the tamper-evident audit chain. Removing a
//! prohibited activity relative to the active policy requires a justification.

use anyhow::{anyhow, Result};
use hivecyber_core::security::audit;
use hivecyber_core::HiveDb;
use hivecyber_tools::EngagementPolicy;
use serde_json::{json, Value};

use crate::state::COL_POLICIES;

pub async fn list_versions(db: &HiveDb) -> Vec<Value> {
    let mut v: Vec<Value> = db.list(COL_POLICIES).await.into_iter().map(|(_, d)| d).collect();
    v.sort_by_key(|d| d.get("version").and_then(|x| x.as_u64()).unwrap_or(0));
    v
}

pub async fn active(db: &HiveDb) -> Option<Value> {
    list_versions(db)
        .await
        .into_iter()
        .find(|d| d.get("status").and_then(|s| s.as_str()) == Some("active"))
}

pub fn parse_policy(doc: &Value) -> Result<EngagementPolicy> {
    let p = doc.get("policy").ok_or_else(|| anyhow!("version without policy"))?;
    Ok(serde_json::from_value(p.clone())?)
}

pub async fn active_policy(db: &HiveDb) -> Option<EngagementPolicy> {
    active(db).await.and_then(|d| parse_policy(&d).ok())
}

fn name_of<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default()
}

/// Controls loosened relative to `old`: prohibited activities lifted and
/// human-approval requirements dropped. Both need a justification.
fn removed_prohibitions(old: &EngagementPolicy, new: &EngagementPolicy) -> Vec<String> {
    let lifted = old.prohibited.iter().filter(|a| !new.prohibited.contains(a)).map(name_of);
    let dropped = old
        .require_human_approval
        .iter()
        .filter(|a| !new.require_human_approval.contains(a))
        .map(|a| format!("approval:{}", name_of(a)));
    lifted.chain(dropped).collect()
}

/// Save a new draft version. Deserialization uses the same `EngagementPolicy`
/// type the CLI validates with (no duplicated rules in the browser).
pub async fn save_draft(
    db: &HiveDb,
    policy_json: Value,
    justification: Option<String>,
    operator: &str,
) -> Result<Value> {
    let policy: EngagementPolicy = serde_json::from_value(policy_json)
        .map_err(|e| anyhow!("invalid EngagementPolicy: {e}"))?;
    if policy.program.trim().is_empty() {
        return Err(anyhow!("program name is required"));
    }
    if policy.targets.is_empty() {
        return Err(anyhow!("at least one target rule is required"));
    }

    let versions = list_versions(db).await;
    let next = versions
        .iter()
        .filter_map(|d| d.get("version").and_then(|x| x.as_u64()))
        .max()
        .unwrap_or(0)
        + 1;

    let removed = match active_policy(db).await {
        Some(cur) => removed_prohibitions(&cur, &policy),
        None => vec![],
    };
    if !removed.is_empty() && justification.as_deref().map(str::trim).unwrap_or("").is_empty() {
        return Err(anyhow!(
            "justification required to loosen controls: {}",
            removed.join(", ")
        ));
    }

    let doc = json!({
        "version": next,
        "status": "draft",
        "policy": serde_json::to_value(&policy)?,
        "justification": justification,
        "lifted_prohibitions": removed,
        "created_by": operator,
        "created_at": chrono::Utc::now().to_rfc3339(),
    });
    db.insert(COL_POLICIES, &format!("v{next}"), doc.clone()).await?;
    Ok(doc)
}

/// Mark `version` active (previous active becomes `archived`) and audit it.
/// Returns the activated policy. The caller rebuilds the runtime afterwards.
pub async fn activate(db: &HiveDb, version: u64, operator: &str) -> Result<EngagementPolicy> {
    let id = format!("v{version}");
    let mut doc = db
        .get(COL_POLICIES, &id)
        .await
        .ok_or_else(|| anyhow!("policy version {version} not found"))?;
    let policy = parse_policy(&doc)?;

    // Audit first, fail closed: no audit entry → no activation.
    audit::append_audit(
        db,
        "policy_activate",
        &policy.program,
        "gateway",
        &id,
        operator,
    )
    .await?;

    for (pid, mut d) in db.list(COL_POLICIES).await {
        if d.get("status").and_then(|s| s.as_str()) == Some("active") {
            d["status"] = json!("archived");
            db.insert(COL_POLICIES, &pid, d).await?;
        }
    }
    doc["status"] = json!("active");
    doc["activated_at"] = json!(chrono::Utc::now().to_rfc3339());
    doc["activated_by"] = json!(operator);
    db.insert(COL_POLICIES, &id, doc).await?;
    Ok(policy)
}
