use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::store::HiveDb;
use crate::store::collections::COL_DELEGATION_GROUPS;

pub const GROUP_PENDING: &str = "pending";
pub const GROUP_ALL_DONE: &str = "all_done";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DelegationGroup {
    pub turn_id: String,
    pub agent_id: String,
    pub thread_id: String,
    pub task_ids: Vec<String>,
    pub completed: Vec<String>,
    pub failed: Vec<String>,
}

pub struct DelegationGroupManager {
    db: HiveDb,
    groups: Arc<Mutex<HashMap<String, DelegationGroup>>>,
}

impl DelegationGroupManager {
    pub fn new(db: HiveDb) -> Self {
        DelegationGroupManager {
            db,
            groups: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn create_group(
        &self,
        turn_id: &str,
        agent_id: &str,
        thread_id: &str,
    ) -> Result<()> {
        let group = DelegationGroup {
            turn_id: turn_id.to_string(),
            agent_id: agent_id.to_string(),
            thread_id: thread_id.to_string(),
            task_ids: Vec::new(),
            completed: Vec::new(),
            failed: Vec::new(),
        };

        self.db
            .insert(
                COL_DELEGATION_GROUPS,
                turn_id,
                serde_json::to_value(&group)?,
            )
            .await?;

        self.groups.lock().await.insert(turn_id.to_string(), group);
        Ok(())
    }

    pub async fn register_task(&self, turn_id: &str, task_id: &str) -> Result<()> {
        let mut groups = self.groups.lock().await;

        let mut group_val = self
            .db
            .get(COL_DELEGATION_GROUPS, turn_id)
            .await
            .ok_or_else(|| anyhow::anyhow!("group not found: {}", turn_id))?;

        if let Some(obj) = group_val.as_object_mut() {
            if let Some(arr) = obj.get_mut("task_ids").and_then(|t| t.as_array_mut()) {
                arr.push(serde_json::Value::String(task_id.to_string()));
            }
        }

        self.db
            .insert(COL_DELEGATION_GROUPS, turn_id, group_val.clone())
            .await?;

        if let Some(group) = groups.get_mut(turn_id) {
            group.task_ids.push(task_id.to_string());
        }

        Ok(())
    }

    pub async fn record_completion(&self, turn_id: &str, task_id: &str) -> Result<()> {
        let mut group_val = self
            .db
            .get(COL_DELEGATION_GROUPS, turn_id)
            .await
            .ok_or_else(|| anyhow::anyhow!("group not found: {}", turn_id))?;

        if let Some(obj) = group_val.as_object_mut() {
            if let Some(arr) = obj.get_mut("completed").and_then(|c| c.as_array_mut()) {
                arr.push(serde_json::Value::String(task_id.to_string()));
            }
        }

        self.db
            .insert(COL_DELEGATION_GROUPS, turn_id, group_val)
            .await?;

        if let Some(group) = self.groups.lock().await.get_mut(turn_id) {
            group.completed.push(task_id.to_string());
        }

        Ok(())
    }

    pub async fn record_failure(&self, turn_id: &str, task_id: &str) -> Result<()> {
        let mut group_val = self
            .db
            .get(COL_DELEGATION_GROUPS, turn_id)
            .await
            .ok_or_else(|| anyhow::anyhow!("group not found: {}", turn_id))?;

        if let Some(obj) = group_val.as_object_mut() {
            if let Some(arr) = obj.get_mut("failed").and_then(|f| f.as_array_mut()) {
                arr.push(serde_json::Value::String(task_id.to_string()));
            }
        }

        self.db
            .insert(COL_DELEGATION_GROUPS, turn_id, group_val)
            .await?;

        if let Some(group) = self.groups.lock().await.get_mut(turn_id) {
            group.failed.push(task_id.to_string());
        }

        Ok(())
    }

    pub async fn is_group_complete(&self, turn_id: &str) -> Option<bool> {
        let group_val = self.db.get(COL_DELEGATION_GROUPS, turn_id).await?;
        let total = group_val
            .get("task_ids")
            .and_then(|t| t.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        let done = group_val
            .get("completed")
            .and_then(|c| c.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        let failed = group_val
            .get("failed")
            .and_then(|f| f.as_array())
            .map(|a| a.len())
            .unwrap_or(0);

        Some(done + failed >= total && total > 0)
    }

    pub async fn get_group_deliveries(
        &self,
        turn_id: &str,
    ) -> Vec<(String, serde_json::Value)> {
        let group_val = self.db.get(COL_DELEGATION_GROUPS, turn_id).await;
        let group_val = match group_val {
            Some(v) => v,
            None => return Vec::new(),
        };

        let task_ids: Vec<String> = group_val
            .get("task_ids")
            .and_then(|t| serde_json::from_value(t.clone()).ok())
            .unwrap_or_default();

        let mut deliveries = Vec::new();
        for task_id in task_ids {
            if let Some(task) = self.db.get(crate::store::collections::COL_TASKS, &task_id).await {
                let status = task.get("status").and_then(|s| s.as_str()).unwrap_or("");
                let delivery = task.get("delivery").cloned().unwrap_or(serde_json::Value::Null);
                deliveries.push((status.to_string(), delivery));
            }
        }
        deliveries
    }
}