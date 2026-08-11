use serde::{Deserialize, Serialize};

pub const COL_AGENTS: &str = "agents";
pub const COL_RUNS: &str = "runs";
pub const COL_JOBS: &str = "jobs";
pub const COL_TASKS: &str = "tasks";
pub const COL_MESSAGES: &str = "messages";
pub const COL_TRACES: &str = "traces";
pub const COL_REFLECTIONS: &str = "reflections";
pub const COL_PLAYBOOK: &str = "playbook";
pub const COL_AGENT_PROPOSALS: &str = "agent_proposals";
pub const COL_DELEGATION_GROUPS: &str = "delegation_groups";
pub const COL_SKILLS: &str = "skills";
pub const COL_MCP_SERVERS: &str = "mcp_servers";
pub const COL_CAPABILITY_DOCS: &str = "capability_docs";
pub const COL_AUDIT_LOG: &str = "audit_log";
pub const COL_PROOF_PACKETS: &str = "proof_packets";
pub const COL_SECRETS: &str = "secrets";
pub const COL_MEMORY: &str = "memory";
pub const COL_SETTINGS: &str = "settings";
pub const COL_MODELS: &str = "models";

/// Model catalog entry — mirror of Hive's `storage/seed.ts` models array. The
/// single source of truth for provider, context window and cost. Doc id is
/// `"<provider_id>::<model_id>"` so reseller providers can offer the same model
/// without colliding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelDoc {
    pub id: String,
    pub model_id: String,
    pub provider_id: String,
    pub name: String,
    pub model_type: String,
    #[serde(default)]
    pub context_window: u32,
    #[serde(default)]
    pub input_per_1m: f64,
    #[serde(default)]
    pub output_per_1m: f64,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "lowercase")]
pub enum AgentRole {
    Coordinator,
    Worker,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentDoc {
    pub id: String,
    pub name: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_prompt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tone: Option<String>,
    pub role: String,
    pub status: String,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools_json: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skills_json: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_allowlist_json: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_server_ids_json: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_scope_json: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_override_json: Option<ModelOverride>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_acceptance_json: Option<Vec<AcceptanceCriterion>>,
    #[serde(default)]
    pub helpful_count: u32,
    #[serde(default)]
    pub harmful_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_iterations: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing_examples_json: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing_exclusions_json: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seed_version: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelOverride {
    pub required_capabilities: Vec<String>,
    pub fallback: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefer_different_family: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcceptanceCriterion {
    pub id: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub check_tool: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageDoc {
    pub id: String,
    pub thread_id: String,
    pub role: String,
    pub content: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceDoc {
    pub id: String,
    pub agent_id: String,
    pub run_id: String,
    pub thread_id: String,
    pub tool_name: String,
    pub tool_args: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub success: Option<bool>,
    pub duration_ms: u64,
    pub tokens_used: u64,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub id: String,
    pub timestamp: String,
    pub tool: String,
    pub target: String,
    pub worker: String,
    pub run_id: String,
    pub operator_id: String,
    pub hash_chain_prev: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskDoc {
    pub id: String,
    pub status: String, // pending, running, completed, blocked, failed
    pub delegation_group_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub catalog_agent_id: Option<String>,
    pub worker_id: String,
    pub task_description: String,
    pub acceptance: Vec<AcceptanceCriterion>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivery: Option<serde_json::Value>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunDoc {
    pub id: String,
    pub kind: String, // chat, worker, goal, cron, project
    pub agent_id: String,
    pub thread_id: String,
    pub status: String, // pending, running, completed, failed, interrupted
    pub goal: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acceptance_json: Option<Vec<AcceptanceCriterion>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch_json: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_json: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_run_id: Option<String>,
    pub iterations_used: u32,
    pub turns_used: u32,
    pub tokens_used: u64,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobDoc {
    pub id: String,
    pub lane: String,
    #[serde(rename = "type")]
    pub job_type: String, // chat_turn, worker_task, goal_run
    pub status: String, // pending, running, completed, failed, cancelled, interrupted
    pub priority: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_json: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    pub attempts: u32,
    pub max_attempts: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boot_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_json: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub retry_count: u32,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
}