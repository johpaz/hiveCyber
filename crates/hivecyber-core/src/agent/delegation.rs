use anyhow::Result;

use crate::store::HiveDb;
use crate::store::collections::{
    COL_TASKS, TaskDoc, AcceptanceCriterion, COL_AGENTS, AgentDoc,
};

pub struct PreparedDelegation {
    pub worker_id: String,
    pub tool_names: Vec<String>,
    pub skill_ids: Vec<String>,
    pub mcp_server_ids: Vec<String>,
    pub provider_id: String,
    pub model_id: String,
}

pub async fn prepare_delegation(
    db: &HiveDb,
    worker_id: &str,
    parent_provider: &str,
    parent_model: &str,
) -> Result<PreparedDelegation> {
    let agent_val = db
        .get(COL_AGENTS, worker_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("worker agent not found: {}", worker_id))?;

    let agent: AgentDoc = serde_json::from_value(agent_val)?;

    if !agent.enabled {
        anyhow::bail!("agent {} is disabled", worker_id);
    }

    let tool_names = agent
        .tool_allowlist_json
        .clone()
        .unwrap_or_else(|| agent.tools_json.clone().unwrap_or_default());

    let skill_ids = agent.skills_json.clone().unwrap_or_default();
    let mcp_server_ids = agent.mcp_server_ids_json.clone().unwrap_or_default();

    let (provider_id, model_id) = match (&agent.provider_id, &agent.model_id) {
        (Some(p), Some(m)) => (p.clone(), m.clone()),
        _ => (parent_provider.to_string(), parent_model.to_string()),
    };

    Ok(PreparedDelegation {
        worker_id: worker_id.to_string(),
        tool_names,
        skill_ids,
        mcp_server_ids,
        provider_id,
        model_id,
    })
}

pub async fn create_task(
    db: &HiveDb,
    worker_id: &str,
    task_description: &str,
    acceptance: Vec<AcceptanceCriterion>,
    delegation_group_id: &str,
) -> Result<String> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    let task = TaskDoc {
        id: id.clone(),
        status: "pending".into(),
        delegation_group_id: delegation_group_id.into(),
        catalog_agent_id: if worker_id.starts_with("recon_")
            || worker_id.starts_with("vuln_")
            || worker_id.starts_with("exploit_")
            || worker_id.starts_with("forensics_")
            || worker_id.starts_with("web_")
            || worker_id.starts_with("threat_")
            || worker_id.starts_with("report_")
            || worker_id.starts_with("workspace_")
            || worker_id.starts_with("software_")
            || worker_id.starts_with("office_")
            || worker_id.starts_with("api_")
            || worker_id.starts_with("schedule_")
            || worker_id.starts_with("browser_")
            || worker_id.starts_with("a2ui_")
        {
            Some(worker_id.to_string())
        } else {
            None
        },
        worker_id: worker_id.into(),
        task_description: task_description.into(),
        acceptance,
        job_id: None,
        run_id: None,
        thread_id: None,
        progress: None,
        delivery: None,
        created_at: now.clone(),
        updated_at: now,
    };

    db.insert(COL_TASKS, &id, serde_json::to_value(&task)?).await?;
    Ok(id)
}