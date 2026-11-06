//! REST routes (MVP: security status, dashboard, agents, runs, audit,
//! EngagementPolicy). Read-only wherever the CLI is read-only; scope changes
//! go exclusively through the versioned policy store.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use hivecyber_core::security::audit;
use hivecyber_core::store::collections::{COL_AGENTS, COL_AUDIT_LOG, COL_RUNS};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::policy_store;
use crate::state::{build_runtime, Shared};

pub type ApiResult = Result<Json<Value>, (StatusCode, Json<Value>)>;

fn err(code: StatusCode, msg: impl ToString) -> (StatusCode, Json<Value>) {
    (code, Json(json!({ "error": msg.to_string() })))
}

/// Read-only. `unsafe_mode` / `allow_cli_exec` can only be set by startup flags.
pub async fn security_status(State(s): State<Shared>) -> ApiResult {
    let rt = s.runtime().await;
    let active = policy_store::active(&s.db).await;
    Ok(Json(json!({
        "unsafe_mode": s.flags.unsafe_mode,
        "allow_cli_exec": s.flags.allow_cli_exec,
        "require_policy": s.flags.require_policy,
        "operator_id": s.flags.operator_id,
        "has_policy": rt.security.engagement_policy.is_some(),
        "active_policy_version": active.as_ref().and_then(|d| d.get("version")).cloned(),
        "program": rt.security.engagement_policy.as_ref().map(|p| p.program.clone()),
        "window": rt.security.engagement_policy.as_ref().and_then(|p| p.time_windows.as_ref().map(|w| json!({
            "allowed_hours_utc": w.allowed_hours_utc,
            "allowed_days": w.allowed_days,
            "open_now": p.is_within_window(chrono::Utc::now()),
        }))),
        "required_headers": rt.security.engagement_policy.as_ref()
            .map(|p| p.required_headers.keys().cloned().collect::<Vec<_>>()),
        "require_human_approval": rt.security.engagement_policy.as_ref()
            .map(|p| serde_json::to_value(&p.require_human_approval).unwrap_or(Value::Null)),
    })))
}

pub async fn ws_ticket(State(s): State<Shared>) -> ApiResult {
    Ok(Json(json!({ "ticket": s.issue_ticket(), "ttl_seconds": 30 })))
}

pub async fn list_agents(State(s): State<Shared>) -> ApiResult {
    let mut agents: Vec<Value> = s.db.list(COL_AGENTS).await.into_iter().map(|(_, v)| v).collect();
    agents.sort_by_key(|a| (a["role"] != "coordinator", a["id"].as_str().unwrap_or("").to_string()));
    Ok(Json(json!(agents)))
}

pub async fn get_agent(State(s): State<Shared>, Path(id): Path<String>) -> ApiResult {
    match s.db.get(COL_AGENTS, &id).await {
        Some(a) => Ok(Json(a)),
        None => Err(err(StatusCode::NOT_FOUND, format!("agent '{id}' not found"))),
    }
}

pub async fn list_runs(State(s): State<Shared>) -> ApiResult {
    let mut runs: Vec<Value> = s.db.list(COL_RUNS).await.into_iter().map(|(_, v)| v).collect();
    runs.sort_by(|a, b| {
        b["created_at"].as_str().unwrap_or("").cmp(a["created_at"].as_str().unwrap_or(""))
    });
    Ok(Json(json!(runs)))
}

#[derive(Deserialize)]
pub struct LimitQ {
    pub limit: Option<usize>,
}

pub async fn list_audit(State(s): State<Shared>, Query(q): Query<LimitQ>) -> ApiResult {
    let mut entries: Vec<Value> = s.db.list(COL_AUDIT_LOG).await.into_iter().map(|(_, v)| v).collect();
    entries.sort_by(|a, b| {
        b["timestamp"].as_str().unwrap_or("").cmp(a["timestamp"].as_str().unwrap_or(""))
    });
    entries.truncate(q.limit.unwrap_or(100).min(1000));
    Ok(Json(json!(entries)))
}

pub async fn verify_audit(State(s): State<Shared>) -> ApiResult {
    match audit::verify_chain(&s.db).await {
        Ok((ok, errors)) => Ok(Json(json!({ "verified": ok, "errors": errors }))),
        Err(e) => Err(err(StatusCode::INTERNAL_SERVER_ERROR, e)),
    }
}

pub async fn dashboard(State(s): State<Shared>) -> ApiResult {
    let agents = s.db.list(COL_AGENTS).await;
    let enabled = agents.iter().filter(|(_, a)| a["enabled"].as_bool().unwrap_or(false)).count();
    let runs = s.db.list(COL_RUNS).await;
    let count_status = |st: &str| runs.iter().filter(|(_, r)| r["status"] == st).count();
    let (verified, errors) = audit::verify_chain(&s.db).await.unwrap_or((false, vec!["verify failed".into()]));
    let audit_total = s.db.count(COL_AUDIT_LOG).await;
    let rt = s.runtime().await;
    Ok(Json(json!({
        "agents": { "total": agents.len(), "enabled": enabled },
        "runs": {
            "total": runs.len(),
            "running": count_status("running"),
            "interrupted": count_status("interrupted"),
            "completed": count_status("completed"),
            "failed": count_status("failed"),
        },
        "audit": { "entries": audit_total, "verified": verified, "errors": errors.len() },
        "scope": {
            "has_policy": rt.security.engagement_policy.is_some(),
            "program": rt.security.engagement_policy.as_ref().map(|p| p.program.clone()),
            "targets": rt.security.engagement_policy.as_ref().map(|p| p.targets.len()),
        },
        "unsafe_mode": s.flags.unsafe_mode,
    })))
}

// ---- EngagementPolicy ------------------------------------------------------

pub async fn get_policy(State(s): State<Shared>) -> ApiResult {
    let versions = policy_store::list_versions(&s.db).await;
    let active = versions.iter().find(|d| d["status"] == "active").cloned();
    let draft = versions.iter().rev().find(|d| d["status"] == "draft").cloned();
    Ok(Json(json!({ "active": active, "latest_draft": draft })))
}

pub async fn policy_versions(State(s): State<Shared>) -> ApiResult {
    Ok(Json(json!(policy_store::list_versions(&s.db).await)))
}

#[derive(Deserialize)]
pub struct PutPolicy {
    pub policy: Value,
    pub justification: Option<String>,
}

/// Saves a DRAFT only. Never changes the scope the agents run under.
pub async fn put_policy(State(s): State<Shared>, Json(body): Json<PutPolicy>) -> ApiResult {
    policy_store::save_draft(&s.db, body.policy, body.justification, &s.flags.operator_id)
        .await
        .map(Json)
        .map_err(|e| err(StatusCode::UNPROCESSABLE_ENTITY, e))
}

/// Activates a saved version: audited, then the runtime (SecurityContext +
/// worker dispatch loop) is rebuilt so narrowing AND widening apply everywhere.
pub async fn activate_policy(State(s): State<Shared>, Path(version): Path<u64>) -> ApiResult {
    let _g = s.activation_lock.lock().await;
    let policy = policy_store::activate(&s.db, version, &s.flags.operator_id)
        .await
        .map_err(|e| err(StatusCode::UNPROCESSABLE_ENTITY, e))?;

    let old = s.runtime().await;
    old.dispatch.stop().await;
    let new_rt = build_runtime(&s.db, &s.config, &s.flags, Some(policy), old.mcp.clone()).await;
    *s.runtime.write().await = new_rt;
    Ok(Json(json!({ "activated": version })))
}
