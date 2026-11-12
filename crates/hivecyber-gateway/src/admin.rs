//! Admin routes (Phase 2–5): agents, providers/models, doctor, skills, MCP,
//! run messages. Secrets are write-only: API keys are never returned.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use hivecyber_core::security::audit;
use hivecyber_core::security::crypto::{provider_key_name, resolve_api_key, SecretStore};
use hivecyber_core::settings::Settings;
use hivecyber_core::store::collections::{COL_AGENTS, COL_MCP_SERVERS, COL_MESSAGES, COL_SKILLS};
use hivecyber_providers::ProviderRegistry;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::routes::ApiResult;
use crate::state::Shared;

fn err(code: StatusCode, msg: impl ToString) -> (StatusCode, Json<Value>) {
    (code, Json(json!({ "error": msg.to_string() })))
}

// ---- agents ----------------------------------------------------------------

async fn update_agent(s: &Shared, id: &str, f: impl FnOnce(&mut serde_json::Map<String, Value>)) -> ApiResult {
    let mut agent = s
        .db
        .get(COL_AGENTS, id)
        .await
        .ok_or_else(|| err(StatusCode::NOT_FOUND, format!("agent '{id}' not found")))?;
    let obj = agent.as_object_mut().ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "bad agent doc"))?;
    f(obj);
    obj.insert("updated_at".into(), chrono::Utc::now().to_rfc3339().into());
    s.db.insert(COL_AGENTS, id, agent.clone()).await.map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let _ = audit::append_audit(&s.db, "agent_update", id, "gateway", "", &s.flags.operator_id).await;
    Ok(Json(agent))
}

pub async fn agent_enable(State(s): State<Shared>, Path(id): Path<String>) -> ApiResult {
    update_agent(&s, &id, |o| {
        o.insert("enabled".into(), json!(true));
        o.insert("status".into(), json!("active"));
    })
    .await
}

pub async fn agent_disable(State(s): State<Shared>, Path(id): Path<String>) -> ApiResult {
    // The coordinator is the only entry point; disabling it would brick delegation.
    let is_coord = s.db.get(COL_AGENTS, &id).await.map(|a| a["role"] == "coordinator").unwrap_or(false);
    if is_coord {
        return Err(err(StatusCode::CONFLICT, "the coordinator cannot be disabled"));
    }
    update_agent(&s, &id, |o| {
        o.insert("enabled".into(), json!(false));
        o.insert("status".into(), json!("disabled"));
    })
    .await
}

#[derive(Deserialize)]
pub struct ModelBody {
    pub model: String,
}
pub async fn agent_set_model(State(s): State<Shared>, Path(id): Path<String>, Json(b): Json<ModelBody>) -> ApiResult {
    update_agent(&s, &id, move |o| {
        if b.model.trim().is_empty() {
            o.remove("model_id");
        } else {
            o.insert("model_id".into(), json!(b.model.trim()));
        }
    })
    .await
}

#[derive(Deserialize)]
pub struct ProviderBody {
    pub provider: String,
}
pub async fn agent_set_provider(State(s): State<Shared>, Path(id): Path<String>, Json(b): Json<ProviderBody>) -> ApiResult {
    // Empty = clear the pin → agent falls back to the global default provider.
    if b.provider.trim().is_empty() {
        return update_agent(&s, &id, |o| {
            o.remove("provider_id");
        })
        .await;
    }
    if !ProviderRegistry::new().list_providers().contains(&b.provider) {
        return Err(err(StatusCode::UNPROCESSABLE_ENTITY, format!("unknown provider '{}'", b.provider)));
    }
    update_agent(&s, &id, move |o| {
        o.insert("provider_id".into(), json!(b.provider));
    })
    .await
}

// ---- providers / models ----------------------------------------------------

pub async fn list_providers(State(s): State<Shared>) -> ApiResult {
    let settings = Settings::load(&s.db).await;
    let reg = ProviderRegistry::new();
    let mut out = vec![];
    for id in reg.list_providers() {
        let key = resolve_api_key(&s.db, &s.config.home_dir, &id).await;
        let ps = settings.providers.get(&id);
        out.push(json!({
            "id": id,
            "key_set": !key.is_empty(),      // never the key itself
            "is_default": id == s.config.models.default_provider,
            "base_url": ps.and_then(|p| p.base_url.clone()),
            "model": ps.and_then(|p| p.model.clone()).or_else(|| reg.default_model_for(&id)),
        }));
    }
    Ok(Json(json!({
        "providers": out,
        "default_provider": s.config.models.default_provider,
        "default_model": s.config.models.default_model,
    })))
}

#[derive(Deserialize)]
pub struct SetProvider {
    pub api_key: Option<String>,
    pub base_url: Option<String>,
    pub model: Option<String>,
}
pub async fn set_provider(State(s): State<Shared>, Path(id): Path<String>, Json(b): Json<SetProvider>) -> ApiResult {
    if !ProviderRegistry::new().list_providers().contains(&id) {
        return Err(err(StatusCode::UNPROCESSABLE_ENTITY, format!("unknown provider '{id}'")));
    }
    let ie = |e: anyhow::Error| err(StatusCode::INTERNAL_SERVER_ERROR, e);
    if let Some(key) = b.api_key.filter(|k| !k.trim().is_empty()) {
        let store = SecretStore::open(&s.config.home_dir).map_err(ie)?;
        store.store(&s.db, &provider_key_name(&id), key.trim()).await.map_err(ie)?;
    }
    if b.base_url.is_some() || b.model.is_some() {
        let mut settings = Settings::load(&s.db).await;
        {
            let e = settings.provider_entry(&id);
            if let Some(u) = b.base_url.filter(|u| !u.is_empty()) { e.base_url = Some(u); }
            if let Some(m) = b.model.filter(|m| !m.is_empty()) { e.model = Some(m); }
        }
        settings.save(&s.db).await.map_err(ie)?;
    }
    let _ = audit::append_audit(&s.db, "provider_update", &id, "gateway", "", &s.flags.operator_id).await;
    Ok(Json(json!({ "ok": true, "note": "restart the gateway to apply provider changes to running loops" })))
}

#[derive(Deserialize)]
pub struct ModelsQ {
    pub provider: Option<String>,
}
pub async fn list_models(Query(q): Query<ModelsQ>) -> ApiResult {
    let mut m = hivecyber_core::agent::models_catalog::model_catalog();
    if let Some(p) = q.provider {
        m.retain(|x| x.provider_id == p);
    }
    m.sort_by(|a, b| a.provider_id.cmp(&b.provider_id).then(a.model_id.cmp(&b.model_id)));
    Ok(Json(serde_json::to_value(m).unwrap_or(Value::Null)))
}

// ---- doctor ----------------------------------------------------------------

fn find_in_path(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join(bin).is_file()))
        .unwrap_or(false)
}

/// Obscura ships as `obscura` (run as `obscura mcp`), usually in ~/.hivecode/bin
/// which is not on the gateway's PATH. Accept the legacy `obscura-mcp` name too.
fn find_obscura() -> Option<String> {
    let mut dirs: Vec<std::path::PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    if let Some(h) = std::env::var_os("HOME") {
        let h = std::path::PathBuf::from(h);
        dirs.push(h.join(".hivecode/bin"));
        dirs.push(h.join(".local/bin"));
    }
    for d in dirs {
        for n in ["obscura", "obscura-mcp"] {
            let c = d.join(n);
            if c.is_file() {
                return Some(c.to_string_lossy().into_owned());
            }
        }
    }
    None
}

pub async fn doctor() -> ApiResult {
    let tools = [
        ("nmap", "nmap"), ("nuclei", "nuclei"), ("sqlmap", "sqlmap"), ("metasploit", "msfconsole"),
        ("searchsploit", "searchsploit"), ("nikto", "nikto"), ("theHarvester", "theHarvester"),
        ("shodan", "shodan"), ("volatility3", "vol"), ("yara", "yara"), ("zeek", "zeek"),
        ("osquery", "osqueryi"), ("semgrep", "semgrep"), ("trivy", "trivy"), ("hydra", "hydra"),
        ("crackmapexec", "crackmapexec"),
    ];
    let list: Vec<Value> = tools.iter().map(|(n, b)| json!({"name": n, "binary": b, "ok": find_in_path(b)})).collect();
    let sandbox = cfg!(target_os = "linux");
    Ok(Json(json!({
        "platform": format!("{} / {}", std::env::consts::OS, std::env::consts::ARCH),
        "sandbox_available": sandbox,
        "allow_unsandboxed": std::env::var("HIVECYBER_ALLOW_UNSANDBOXED").map(|v| v == "1").unwrap_or(false),
        "obscura_mcp": find_obscura().is_some(),
        "obscura_path": find_obscura(),
        "tools": list,
    })))
}

// ---- skills / mcp (read-only) -------------------------------------------------

pub async fn list_skills(State(s): State<Shared>) -> ApiResult {
    let mut v: Vec<Value> = s.db.list(COL_SKILLS).await.into_iter().map(|(_, d)| d).collect();
    v.sort_by_key(|d| d["name"].as_str().unwrap_or("").to_string());
    Ok(Json(json!(v)))
}

/// Server docs may hold credentials in `headers`/`env`: expose only the key names.
fn redact(mut doc: Value) -> Value {
    for field in ["headers", "env"] {
        if let Some(m) = doc.get_mut(field).and_then(|x| x.as_object_mut()) {
            for (_, v) in m.iter_mut() {
                *v = json!("***");
            }
        }
    }
    doc
}
pub async fn list_mcp(State(s): State<Shared>) -> ApiResult {
    let v: Vec<Value> = s.db.list(COL_MCP_SERVERS).await.into_iter().map(|(_, d)| redact(d)).collect();
    Ok(Json(json!(v)))
}

// ---- run messages -----------------------------------------------------------

pub async fn run_messages(State(s): State<Shared>, Path(thread): Path<String>) -> ApiResult {
    let mut v: Vec<Value> = s
        .db
        .list(COL_MESSAGES)
        .await
        .into_iter()
        .map(|(_, d)| d)
        .filter(|d| d["thread_id"] == thread.as_str())
        .collect();
    v.sort_by_key(|d| d["created_at"].as_str().unwrap_or("").to_string());
    Ok(Json(json!(v)))
}

// ---- default provider ---------------------------------------------------------

#[derive(Deserialize)]
pub struct DefaultBody {
    pub id: String,
    pub model: Option<String>,
}
pub async fn set_default_provider(State(s): State<Shared>, Json(b): Json<DefaultBody>) -> ApiResult {
    if !ProviderRegistry::new().list_providers().contains(&b.id) {
        return Err(err(StatusCode::UNPROCESSABLE_ENTITY, format!("unknown provider '{}'", b.id)));
    }
    let mut settings = Settings::load(&s.db).await;
    settings.default_provider = Some(b.id.clone());
    if let Some(m) = b.model.filter(|m| !m.is_empty()) {
        settings.default_model = Some(m);
    }
    settings.save(&s.db).await.map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let _ = audit::append_audit(&s.db, "provider_default", &b.id, "gateway", "", &s.flags.operator_id).await;
    Ok(Json(json!({ "ok": true, "note": "restart the gateway to apply the new default" })))
}

// ---- live activity (feeds the 3D hive view) --------------------------------------

/// Snapshot of what the agents are doing right now: per-agent working state,
/// recent delegated tasks and recent tool traces. The panel polls this.
pub async fn activity(State(s): State<Shared>) -> ApiResult {
    use hivecyber_core::store::collections::{COL_JOBS, COL_TASKS, COL_TRACES};
    let sort_desc = |v: &mut Vec<Value>, key: &str| {
        v.sort_by(|a, b| b[key].as_str().unwrap_or("").cmp(a[key].as_str().unwrap_or("")))
    };
    let mut tasks: Vec<Value> = s.db.list(COL_TASKS).await.into_iter().map(|(_, d)| d).collect();
    sort_desc(&mut tasks, "updated_at");
    tasks.truncate(30);
    let mut traces: Vec<Value> = s.db.list(COL_TRACES).await.into_iter().map(|(_, d)| d).collect();
    sort_desc(&mut traces, "created_at");
    traces.truncate(40);
    // Args/results can be large or sensitive: expose only the shape the view needs.
    let traces: Vec<Value> = traces
        .into_iter()
        .map(|t| json!({
            "id": t["id"], "agent_id": t["agent_id"], "tool_name": t["tool_name"],
            "success": t["success"], "duration_ms": t["duration_ms"], "created_at": t["created_at"],
        }))
        .collect();
    let tasks: Vec<Value> = tasks
        .into_iter()
        .map(|t| json!({
            "id": t["id"], "worker_id": t["worker_id"], "status": t["status"],
            "description": t["task_description"].as_str().map(|d| d.chars().take(160).collect::<String>()),
            "progress": t["progress"], "updated_at": t["updated_at"],
        }))
        .collect();
    let running_jobs = s.db.list(COL_JOBS).await.into_iter().filter(|(_, j)| j["status"] == "running").count();
    let agents: Vec<Value> = s
        .db
        .list(COL_AGENTS)
        .await
        .into_iter()
        .map(|(_, a)| {
            let id = a["id"].as_str().unwrap_or("").to_string();
            let working = tasks.iter().any(|t| t["worker_id"] == id.as_str() && t["status"] == "running");
            json!({ "id": id, "name": a["name"], "role": a["role"], "enabled": a["enabled"], "working": working })
        })
        .collect();
    Ok(Json(json!({
        "now": chrono::Utc::now().to_rfc3339(),
        "agents": agents, "tasks": tasks, "traces": traces, "running_jobs": running_jobs,
    })))
}

// ---- live models of a provider ---------------------------------------------------

fn parse_models(v: &Value) -> Vec<Value> {
    let arr = v.as_array().cloned().or_else(|| v.get("data").and_then(|d| d.as_array()).cloned()).unwrap_or_default();
    arr.into_iter()
        .filter_map(|m| {
            let id = m.as_str().map(String::from).or_else(|| m["id"].as_str().or(m["name"].as_str()).map(String::from))?;
            Some(json!({ "id": id, "size_gb": m["sizeGb"], "context": m["context_window"], "native_context": m["native_context_window"], "max_output_tokens": m["max_output_tokens"], "installed": m["installed"], "capabilities": m["capabilities"], "roles": m["roles"] }))
        })
        // llm-api also lists audio-model shards (MiniMax-Music3 parts): not chat models.
        .filter(|m| !m["id"].as_str().unwrap_or("").to_lowercase().contains("music"))
        .collect()
}

/// Models the provider's own server exposes right now (e.g. the local llm-api
/// `/api/models`, or an OpenAI-compatible `/v1/models`). The URL comes from the
/// operator's provider settings — never from the request.
pub async fn live_models(State(s): State<Shared>, Path(id): Path<String>) -> ApiResult {
    let reg = ProviderRegistry::new();
    if !reg.list_providers().contains(&id) {
        return Err(err(StatusCode::NOT_FOUND, format!("unknown provider '{id}'")));
    }
    let settings = Settings::load(&s.db).await;
    let base = settings
        .providers
        .get(&id)
        .and_then(|p| p.base_url.clone())
        .filter(|u| !u.is_empty())
        .or_else(|| reg.base_url_for(&id))
        .unwrap_or_default();
    let base = base.trim_end_matches('/').to_string();
    if !(base.starts_with("http://") || base.starts_with("https://")) {
        return Err(err(StatusCode::UNPROCESSABLE_ENTITY, "provider base_url must be http(s)"));
    }
    let origin = base.trim_end_matches("/v1").to_string();
    let key = resolve_api_key(&s.db, &s.config.home_dir, &id).await;
    let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(5)).build().map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    // 1) llm-api style public listing, 2) OpenAI-compatible /models (with key if any).
    let mut tried = vec![];
    for (url, auth) in [(format!("{origin}/api/models"), false), (format!("{base}/models"), true)] {
        let mut rq = client.get(&url);
        if auth && !key.is_empty() {
            rq = rq.bearer_auth(&key);
        }
        match rq.send().await {
            Ok(r) if r.status().is_success() => {
                if let Ok(v) = r.json::<Value>().await {
                    let models = parse_models(&v);
                    if !models.is_empty() {
                        return Ok(Json(json!({ "source": url, "models": models })));
                    }
                }
                tried.push(format!("{url}: empty/unrecognised"));
            }
            Ok(r) => tried.push(format!("{url}: HTTP {}", r.status())),
            Err(e) => tried.push(format!("{url}: {e}")),
        }
    }
    Err(err(StatusCode::BAD_GATEWAY, format!("no model list from provider — {}", tried.join(" | "))))
}

// ---- llm-api server control (status / load) ------------------------------------------

async fn server_origin(s: &Shared, id: &str) -> Result<(String, String), (StatusCode, Json<Value>)> {
    let reg = ProviderRegistry::new();
    if !reg.list_providers().contains(&id.to_string()) {
        return Err(err(StatusCode::NOT_FOUND, format!("unknown provider '{id}'")));
    }
    let settings = Settings::load(&s.db).await;
    let base = settings
        .providers
        .get(id)
        .and_then(|p| p.base_url.clone())
        .filter(|u| !u.is_empty())
        .or_else(|| reg.base_url_for(id))
        .unwrap_or_default();
    let base = base.trim_end_matches('/');
    if !(base.starts_with("http://") || base.starts_with("https://")) {
        return Err(err(StatusCode::UNPROCESSABLE_ENTITY, "provider base_url must be http(s)"));
    }
    let key = resolve_api_key(&s.db, &s.config.home_dir, id).await;
    Ok((base.trim_end_matches("/v1").to_string(), key))
}

/// Which model the HiveAgents-style server (llm-api) has loaded. Public upstream endpoint.
pub async fn server_status(State(s): State<Shared>, Path(id): Path<String>) -> ApiResult {
    let (origin, _) = server_origin(&s, &id).await?;
    let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(5)).build().map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    // llm-api expone /api/status. El endpoint de ciberseguridad gestiona la carga bajo demanda
    // y solo publica /health: en ese caso se informa como "gestionado por el servidor".
    if let Ok(r) = client.get(format!("{origin}/api/status")).send().await {
        if r.status().is_success() {
            if let Ok(v) = r.json::<Value>().await {
                return Ok(Json(json!({ "loaded": v["loaded"], "loading": v["loading"], "model": v["model"]["name"].as_str().map(|n| json!(n)).unwrap_or_else(|| v["model"].clone()), "error": v["error"] })));
            }
        }
    }
    match client.get(format!("{origin}/health")).send().await {
        Ok(r) if r.status().is_success() => Ok(Json(json!({ "loaded": true, "loading": false, "model": "carga bajo demanda (gestionada por el endpoint)", "error": Value::Null }))),
        Ok(r) => Err(err(StatusCode::BAD_GATEWAY, format!("el servidor respondió {}", r.status()))),
        Err(e) => Err(err(StatusCode::BAD_GATEWAY, e)),
    }
}

#[derive(Deserialize)]
pub struct LoadBody {
    pub model: String,
    #[serde(default)]
    pub ctx: Option<u32>,
}

/// Ask the server to load a model. NOTE: on llm-api this is global — it changes
/// what every client of that server sees. Uses the key stored server-side; the
/// key never reaches the browser. Audited.
pub async fn load_model(State(s): State<Shared>, Path(id): Path<String>, Json(b): Json<LoadBody>) -> ApiResult {
    let (origin, key) = server_origin(&s, &id).await?;
    if key.is_empty() {
        return Err(err(StatusCode::UNPROCESSABLE_ENTITY, "no API key stored for this provider"));
    }
    let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(15)).build().map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let r = client
        .post(format!("{origin}/api/load"))
        .bearer_auth(&key)
        .json(&match b.ctx { Some(c) => json!({ "model": b.model, "config": { "ctx": c } }), None => json!({ "model": b.model }) })
        .send()
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, e))?;
    let status = r.status();
    let body: Value = r.json().await.unwrap_or(Value::Null);
    let _ = audit::append_audit(&s.db, "provider_load_model", &b.model, "gateway", &id, &s.flags.operator_id).await;
    if status.is_success() {
        Ok(Json(json!({ "accepted": true, "upstream": body })))
    } else {
        Err(err(StatusCode::BAD_GATEWAY, format!("server answered {status}: {body}")))
    }
}
