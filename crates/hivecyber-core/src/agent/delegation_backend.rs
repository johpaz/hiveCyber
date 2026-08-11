use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use std::sync::Arc;

use crate::harness::DurableQueue;
use crate::agent::delegation::create_task;
use crate::store::HiveDb;

pub struct TaskDelegateBackend {
    pub db: HiveDb,
    pub queue: Arc<DurableQueue>,
}

#[async_trait]
impl hivecyber_tools::delegation::TaskDelegateBackend for TaskDelegateBackend {
    async fn create_task(
        &self,
        worker_id: &str,
        task_description: &str,
        acceptance: Vec<Value>,
        turn_id: &str,
        thread_id: &str,
    ) -> Result<(String, String)> {
        let acceptance_struct: Vec<crate::store::collections::AcceptanceCriterion> = acceptance
            .iter()
            .filter_map(|v| serde_json::from_value(v.clone()).ok())
            .collect();

        let task_id = create_task(
            &self.db,
            worker_id,
            task_description,
            acceptance_struct,
            turn_id,
        )
        .await?;

        self.ensure_group(turn_id, thread_id, &task_id).await?;

        let lane = format!("task:{}", task_id);
        let payload = serde_json::json!({
            "workerId": worker_id,
            "taskDescription": task_description,
            "taskId": task_id,
            "originThreadId": thread_id,
            "acceptance": acceptance,
        });

        let job_id = self
            .queue
            .enqueue(&lane, "worker_task", payload, None)
            .await?;

        let mut task_val = self
            .db
            .get(crate::store::collections::COL_TASKS, &task_id)
            .await
            .unwrap_or_default();
        if let Some(obj) = task_val.as_object_mut() {
            obj.insert("job_id".into(), job_id.clone().into());
            obj.insert("updated_at".into(), chrono::Utc::now().to_rfc3339().into());
        }
        self.db
            .insert(crate::store::collections::COL_TASKS, &task_id, task_val)
            .await?;

        Ok((task_id, job_id))
    }

    async fn list_tasks(&self, status: Option<String>, limit: usize) -> Result<Vec<Value>> {
        use crate::store::collections::COL_TASKS;
        let mut tasks: Vec<(String, Value)> = self.db.list(COL_TASKS).await;
        // Most recent first by updated_at (falls back to created_at).
        tasks.sort_by(|a, b| {
            let ka = a.1.get("updated_at").and_then(|v| v.as_str()).unwrap_or("");
            let kb = b.1.get("updated_at").and_then(|v| v.as_str()).unwrap_or("");
            kb.cmp(ka)
        });

        let out: Vec<Value> = tasks
            .into_iter()
            .filter(|(_, t)| match &status {
                Some(s) => t.get("status").and_then(|v| v.as_str()) == Some(s.as_str()),
                None => true,
            })
            .take(limit)
            .map(|(id, t)| {
                let desc = t
                    .get("task_description")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                serde_json::json!({
                    "task_id": id,
                    "worker_id": t.get("worker_id").or_else(|| t.get("assigned_to")).cloned(),
                    "status": t.get("status").and_then(|v| v.as_str()).unwrap_or("unknown"),
                    "progress": t.get("progress").cloned(),
                    "delegation_group_id": t.get("delegation_group_id").cloned(),
                    "description": desc.chars().take(140).collect::<String>(),
                    "updated_at": t.get("updated_at").cloned(),
                })
            })
            .collect();
        Ok(out)
    }

    async fn revise_task(&self, task_id: &str, notes: &str) -> Result<Value> {
        use crate::store::collections::{COL_DELEGATION_GROUPS, COL_TASKS};

        let mut task = self
            .db
            .get(COL_TASKS, task_id)
            .await
            .ok_or_else(|| anyhow::anyhow!("task not found: {}", task_id))?;

        let worker_id = task
            .get("worker_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("task has no worker_id"))?
            .to_string();
        let group_id = task
            .get("delegation_group_id")
            .and_then(|v| v.as_str())
            .unwrap_or("default")
            .to_string();
        let original_desc = task
            .get("task_description")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // Recover the originating thread from the delegation group so the
        // executive-summary reinjection still targets the right conversation.
        let thread_id = self
            .db
            .get(COL_DELEGATION_GROUPS, &group_id)
            .await
            .and_then(|g| g.get("thread_id").and_then(|v| v.as_str()).map(String::from))
            .unwrap_or_default();

        let revised_desc = format!(
            "{}\n\n[Revisión solicitada por el coordinador] {}",
            original_desc, notes
        );

        // Reset the task to pending and record the revision on the doc.
        if let Some(obj) = task.as_object_mut() {
            obj.insert("status".into(), "pending".into());
            obj.insert("task_description".into(), revised_desc.clone().into());
            obj.insert("revision_notes".into(), notes.into());
            obj.insert("updated_at".into(), chrono::Utc::now().to_rfc3339().into());
        }
        self.db.insert(COL_TASKS, task_id, task).await?;

        // Re-queue the worker with the revised description, same task id.
        let lane = format!("task:{}", task_id);
        let payload = serde_json::json!({
            "workerId": worker_id,
            "taskDescription": revised_desc,
            "taskId": task_id,
            "originThreadId": thread_id,
            "revision": true,
        });
        let job_id = self.queue.enqueue(&lane, "worker_task", payload, None).await?;

        // Point the task at its new job.
        if let Some(mut t) = self.db.get(COL_TASKS, task_id).await {
            if let Some(obj) = t.as_object_mut() {
                obj.insert("job_id".into(), job_id.clone().into());
            }
            self.db.insert(COL_TASKS, task_id, t).await?;
        }

        Ok(serde_json::json!({
            "ok": true,
            "task_id": task_id,
            "job_id": job_id,
            "worker_id": worker_id,
            "status": "queued",
            "revised": true,
        }))
    }

    async fn get_task_status(&self, task_id: &str) -> Result<Option<Value>> {
        let Some(task) = self.db.get(crate::store::collections::COL_TASKS, task_id).await else {
            return Ok(None);
        };
        // Project the fields Caelum needs to judge progress, keeping the payload
        // small (deliveries can be large — surface only content + checks).
        let delivery = task.get("delivery").cloned();
        Ok(Some(serde_json::json!({
            "task_id": task_id,
            "status": task.get("status").and_then(|v| v.as_str()).unwrap_or("unknown"),
            "worker_id": task.get("worker_id").or_else(|| task.get("assigned_to")).cloned(),
            "progress": task.get("progress").cloned(),
            "delegation_group_id": task.get("delegation_group_id").cloned(),
            "job_id": task.get("job_id").cloned(),
            "updated_at": task.get("updated_at").cloned(),
            "delivery": delivery,
        })))
    }
}

impl TaskDelegateBackend {
    async fn ensure_group(&self, turn_id: &str, thread_id: &str, task_id: &str) -> Result<()> {
        use crate::store::collections::COL_DELEGATION_GROUPS;

        let existing = self.db.get(COL_DELEGATION_GROUPS, turn_id).await;
        let mut group = match existing {
            Some(v) => v,
            None => serde_json::json!({
                "turn_id": turn_id,
                "agent_id": "caelum",
                "thread_id": thread_id,
                "task_ids": [],
                "completed": [],
                "failed": [],
            }),
        };

        if let Some(obj) = group.as_object_mut() {
            let ids = obj
                .entry("task_ids".to_string())
                .or_insert_with(|| serde_json::json!([]));
            if let Some(arr) = ids.as_array_mut() {
                if !arr.iter().any(|t| t.as_str() == Some(task_id)) {
                    arr.push(serde_json::Value::String(task_id.to_string()));
                }
            }
        }

        self.db.insert(COL_DELEGATION_GROUPS, turn_id, group).await?;
        Ok(())
    }
}