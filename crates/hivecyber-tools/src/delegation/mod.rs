use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

use crate::registry::{Tool, ToolCategory, ToolSchema};

pub struct TaskDelegate {
    pub db: Arc<dyn TaskDelegateBackend>,
}

#[async_trait]
pub trait TaskDelegateBackend: Send + Sync {
    async fn create_task(
        &self,
        worker_id: &str,
        task_description: &str,
        acceptance: Vec<Value>,
        turn_id: &str,
        thread_id: &str,
    ) -> Result<(String, String)>;

    /// Return the current state of a delegated task, or `None` if it does not
    /// exist. Implementations read the task document from the store.
    async fn get_task_status(&self, task_id: &str) -> Result<Option<Value>>;

    /// List delegated tasks (most recent first), optionally filtered by status,
    /// capped at `limit`. Returns projected summaries (not full deliveries).
    async fn list_tasks(&self, status: Option<String>, limit: usize) -> Result<Vec<Value>>;

    /// Re-delegate an existing task to the same worker, appending `notes` as
    /// revision guidance and re-queuing it. Returns a summary of the new job.
    async fn revise_task(&self, task_id: &str, notes: &str) -> Result<Value>;
}

#[async_trait]
impl Tool for TaskDelegate {
    fn name(&self) -> &str {
        "task_delegate"
    }
    fn description(&self) -> &str {
        "Delega una sub-tarea a un worker especializado. Modo async (default) retorna inmediatamente."
    }
    fn category(&self) -> ToolCategory {
        ToolCategory::Base
    }
    fn parameters(&self) -> ToolSchema {
        let mut props = HashMap::new();
        props.insert("worker_id".into(), json!({"type": "string", "description": "ID del worker: recon_operator, vuln_scanner, exploit_operator, forensics_analyst, web_pentester, threat_intel_analyst, report_writer, workspace_file_operator"}));
        props.insert("task_description".into(), json!({"type": "string"}));
        props.insert("mode".into(), json!({"type": "string", "default": "async", "enum": ["async", "sync"]}));
        props.insert("acceptance".into(), json!({"type": "array", "items": {"type": "object", "properties": {"id": {"type": "string"}, "description": {"type": "string"}, "checkTool": {"type": "string"}}}}));
        ToolSchema {
            schema_type: "object".into(),
            properties: props,
            required: Some(vec!["worker_id".into(), "task_description".into()]),
        }
    }

    async fn execute(&self, params: Value) -> Result<Value> {
        let obj = params
            .as_object()
            .ok_or_else(|| anyhow!("params must be object"))?;

        let worker_id = obj
            .get("worker_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("worker_id required"))?;

        let task_description = obj
            .get("task_description")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("task_description required"))?;

        let acceptance = obj
            .get("acceptance")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let turn_id = obj
            .get("__turn_id")
            .and_then(|v| v.as_str())
            .unwrap_or("default");

        let thread_id = obj
            .get("__thread_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let (task_id, job_id) = self
            .db
            .create_task(worker_id, task_description, acceptance, turn_id, thread_id)
            .await?;

        Ok(json!({
            "ok": true,
            "task_id": task_id,
            "job_id": job_id,
            "worker_id": worker_id,
            "status": "queued",
        }))
    }
}

pub struct TaskStatus {
    pub db: Arc<dyn TaskDelegateBackend>,
}

#[async_trait]
impl Tool for TaskStatus {
    fn name(&self) -> &str {
        "task_status"
    }
    fn description(&self) -> &str {
        "Consulta el estado de una tarea delegada."
    }
    fn category(&self) -> ToolCategory {
        ToolCategory::Base
    }
    fn parameters(&self) -> ToolSchema {
        let mut props = HashMap::new();
        props.insert("task_id".into(), json!({"type": "string"}));
        ToolSchema {
            schema_type: "object".into(),
            properties: props,
            required: Some(vec!["task_id".into()]),
        }
    }

    async fn execute(&self, params: Value) -> Result<Value> {
        let task_id = params
            .get("task_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("task_id required"))?;

        match self.db.get_task_status(task_id).await? {
            Some(task) => Ok(task),
            None => Ok(json!({
                "task_id": task_id,
                "status": "not_found",
                "message": "no delegated task with that id",
            })),
        }
    }
}

pub struct TaskList {
    pub db: Arc<dyn TaskDelegateBackend>,
}

#[async_trait]
impl Tool for TaskList {
    fn name(&self) -> &str {
        "task_list"
    }
    fn description(&self) -> &str {
        "Lista las tareas delegadas (mas recientes primero), con su estado. Filtra por status opcional (pending/running/completed/failed/blocked)."
    }
    fn category(&self) -> ToolCategory {
        ToolCategory::Base
    }
    fn parameters(&self) -> ToolSchema {
        let mut props = HashMap::new();
        props.insert("status".into(), json!({"type": "string", "description": "Filtro opcional por estado", "enum": ["pending", "running", "completed", "failed", "blocked"]}));
        props.insert("limit".into(), json!({"type": "integer", "default": 20}));
        ToolSchema {
            schema_type: "object".into(),
            properties: props,
            required: None,
        }
    }

    async fn execute(&self, params: Value) -> Result<Value> {
        let status = params
            .get("status")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let limit = params
            .get("limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(20)
            .clamp(1, 100) as usize;

        let tasks = self.db.list_tasks(status, limit).await?;
        Ok(json!({ "count": tasks.len(), "tasks": tasks }))
    }
}

pub struct TaskRevise {
    pub db: Arc<dyn TaskDelegateBackend>,
}

#[async_trait]
impl Tool for TaskRevise {
    fn name(&self) -> &str {
        "task_revise"
    }
    fn description(&self) -> &str {
        "Re-delega una tarea existente al mismo worker, agregando notas de revision. Util cuando una entrega no paso los acceptance checks."
    }
    fn category(&self) -> ToolCategory {
        ToolCategory::Base
    }
    fn parameters(&self) -> ToolSchema {
        let mut props = HashMap::new();
        props.insert("task_id".into(), json!({"type": "string"}));
        props.insert("notes".into(), json!({"type": "string", "description": "Que corregir o mejorar en la nueva iteracion"}));
        ToolSchema {
            schema_type: "object".into(),
            properties: props,
            required: Some(vec!["task_id".into(), "notes".into()]),
        }
    }

    async fn execute(&self, params: Value) -> Result<Value> {
        let task_id = params
            .get("task_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("task_id required"))?;
        let notes = params
            .get("notes")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("notes required"))?;

        self.db.revise_task(task_id, notes).await
    }
}