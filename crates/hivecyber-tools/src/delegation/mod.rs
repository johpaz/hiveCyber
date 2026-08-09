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

    async fn execute(&self, _params: Value) -> Result<Value> {
        Ok(json!({
            "status": "not_implemented",
            "message": "task_status requires DB access — use agent system prompt to track"
        }))
    }
}