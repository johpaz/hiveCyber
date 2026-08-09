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
}