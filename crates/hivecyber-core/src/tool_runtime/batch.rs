use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolBatchResult {
    pub tool_name: String,
    pub success: bool,
    pub result: serde_json::Value,
    pub duration_ms: u64,
    pub error: Option<String>,
}

// `execute_tool_batch` (unaudited, isolation()-blind) used to live here and
// has been removed: it called `tool.execute()` directly with no
// `Isolation::Sandbox` check at all, unlike `execute_tool_batch_audited`
// (tool_runtime/middleware.rs) which every real call site actually uses. It
// had no callers — resurrecting a non-audited batch path as a "convenience"
// would silently bypass the hivecyber-worker sandbox for cli_exec/fs_write/
// fs_edit/fs_delete/the exploit tools. If a non-audited path is ever
// genuinely needed, it must still check `tool.isolation()` and still require
// an `AuditCtx`, not skip both.