//! Agent memory tools — durable notes an agent can write and recall across
//! turns and runs. Backed by `COL_MEMORY` in the store via `MemoryBackend`
//! (implemented in `hivecyber-core`, so this crate stays store-agnostic, same
//! pattern as the delegation tools).

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

use crate::registry::{Tool, ToolCategory, ToolSchema};

#[async_trait]
pub trait MemoryBackend: Send + Sync {
    /// Upsert a note under (namespace, key). Returns the stored doc id.
    async fn write(
        &self,
        namespace: &str,
        key: &str,
        content: &str,
        tags: Vec<String>,
    ) -> Result<String>;

    /// Fetch a note by (namespace, key).
    async fn read(&self, namespace: &str, key: &str) -> Result<Option<Value>>;

    /// List notes (most recent first), optionally within a namespace.
    async fn list(&self, namespace: Option<&str>, limit: usize) -> Result<Vec<Value>>;

    /// Substring/keyword search over content, key and tags. Returns matches with
    /// a relevance score, most relevant first.
    async fn search(&self, query: &str, namespace: Option<&str>, limit: usize) -> Result<Vec<Value>>;
}

const DEFAULT_NS: &str = "default";

pub struct MemoryWrite {
    pub db: Arc<dyn MemoryBackend>,
}

#[async_trait]
impl Tool for MemoryWrite {
    fn name(&self) -> &str {
        "memory_write"
    }
    fn description(&self) -> &str {
        "Guarda una nota persistente (memoria del agente) bajo una clave, para recordarla en turnos futuros. Usa namespace para agrupar (p.ej. host, hallazgos)."
    }
    fn category(&self) -> ToolCategory {
        ToolCategory::Base
    }
    fn parameters(&self) -> ToolSchema {
        let mut props = HashMap::new();
        props.insert("key".into(), json!({"type": "string"}));
        props.insert("content".into(), json!({"type": "string"}));
        props.insert("namespace".into(), json!({"type": "string", "default": "default"}));
        props.insert("tags".into(), json!({"type": "array", "items": {"type": "string"}}));
        ToolSchema {
            schema_type: "object".into(),
            properties: props,
            required: Some(vec!["key".into(), "content".into()]),
        }
    }

    async fn execute(&self, params: Value) -> Result<Value> {
        let key = params.get("key").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("key required"))?;
        let content = params
            .get("content")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("content required"))?;
        let namespace = params.get("namespace").and_then(|v| v.as_str()).unwrap_or(DEFAULT_NS);
        let tags: Vec<String> = params
            .get("tags")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|t| t.as_str().map(String::from)).collect())
            .unwrap_or_default();

        let id = self.db.write(namespace, key, content, tags).await?;
        Ok(json!({ "ok": true, "id": id, "namespace": namespace, "key": key }))
    }
}

pub struct MemoryRead {
    pub db: Arc<dyn MemoryBackend>,
}

#[async_trait]
impl Tool for MemoryRead {
    fn name(&self) -> &str {
        "memory_read"
    }
    fn description(&self) -> &str {
        "Lee una nota de memoria por clave (y namespace opcional)."
    }
    fn category(&self) -> ToolCategory {
        ToolCategory::Base
    }
    fn parameters(&self) -> ToolSchema {
        let mut props = HashMap::new();
        props.insert("key".into(), json!({"type": "string"}));
        props.insert("namespace".into(), json!({"type": "string", "default": "default"}));
        ToolSchema {
            schema_type: "object".into(),
            properties: props,
            required: Some(vec!["key".into()]),
        }
    }

    async fn execute(&self, params: Value) -> Result<Value> {
        let key = params.get("key").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("key required"))?;
        let namespace = params.get("namespace").and_then(|v| v.as_str()).unwrap_or(DEFAULT_NS);
        match self.db.read(namespace, key).await? {
            Some(doc) => Ok(doc),
            None => Ok(json!({ "found": false, "namespace": namespace, "key": key })),
        }
    }
}

pub struct MemoryList {
    pub db: Arc<dyn MemoryBackend>,
}

#[async_trait]
impl Tool for MemoryList {
    fn name(&self) -> &str {
        "memory_list"
    }
    fn description(&self) -> &str {
        "Lista notas de memoria (mas recientes primero), opcionalmente por namespace."
    }
    fn category(&self) -> ToolCategory {
        ToolCategory::Base
    }
    fn parameters(&self) -> ToolSchema {
        let mut props = HashMap::new();
        props.insert("namespace".into(), json!({"type": "string"}));
        props.insert("limit".into(), json!({"type": "integer", "default": 20}));
        ToolSchema {
            schema_type: "object".into(),
            properties: props,
            required: None,
        }
    }

    async fn execute(&self, params: Value) -> Result<Value> {
        let namespace = params.get("namespace").and_then(|v| v.as_str());
        let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(20).clamp(1, 200) as usize;
        let notes = self.db.list(namespace, limit).await?;
        Ok(json!({ "count": notes.len(), "notes": notes }))
    }
}

pub struct MemorySearch {
    pub db: Arc<dyn MemoryBackend>,
}

#[async_trait]
impl Tool for MemorySearch {
    fn name(&self) -> &str {
        "memory_search"
    }
    fn description(&self) -> &str {
        "Busca en las notas de memoria por palabra clave (contenido, clave y tags)."
    }
    fn category(&self) -> ToolCategory {
        ToolCategory::Base
    }
    fn parameters(&self) -> ToolSchema {
        let mut props = HashMap::new();
        props.insert("query".into(), json!({"type": "string"}));
        props.insert("namespace".into(), json!({"type": "string"}));
        props.insert("limit".into(), json!({"type": "integer", "default": 10}));
        ToolSchema {
            schema_type: "object".into(),
            properties: props,
            required: Some(vec!["query".into()]),
        }
    }

    async fn execute(&self, params: Value) -> Result<Value> {
        let query = params.get("query").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("query required"))?;
        let namespace = params.get("namespace").and_then(|v| v.as_str());
        let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(10).clamp(1, 100) as usize;
        let hits = self.db.search(query, namespace, limit).await?;
        Ok(json!({ "count": hits.len(), "hits": hits }))
    }
}
