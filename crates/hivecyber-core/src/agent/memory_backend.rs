//! `MemoryBackend` over `HiveDb` + `COL_MEMORY`.
//!
//! Notes are keyed by a deterministic `namespace::key` id so `memory_write`
//! upserts and `memory_read` is an exact fetch. `memory_search` does a simple
//! case-insensitive keyword scan over content/key/tags scored by hit count —
//! adequate for the modest number of notes an agent keeps, with no separate
//! index to maintain.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use crate::store::HiveDb;
use crate::store::collections::COL_MEMORY;

pub struct MemoryBackend {
    pub db: HiveDb,
}

fn doc_id(namespace: &str, key: &str) -> String {
    format!("{}::{}", namespace, key)
}

#[async_trait]
impl hivecyber_tools::memory::MemoryBackend for MemoryBackend {
    async fn write(
        &self,
        namespace: &str,
        key: &str,
        content: &str,
        tags: Vec<String>,
    ) -> Result<String> {
        let id = doc_id(namespace, key);
        let now = chrono::Utc::now().to_rfc3339();
        let created_at = self
            .db
            .get(COL_MEMORY, &id)
            .await
            .and_then(|d| d.get("created_at").and_then(|v| v.as_str()).map(String::from))
            .unwrap_or_else(|| now.clone());
        let doc = serde_json::json!({
            "id": id,
            "namespace": namespace,
            "key": key,
            "content": content,
            "tags": tags,
            "created_at": created_at,
            "updated_at": now,
        });
        self.db.insert(COL_MEMORY, &id, doc).await?;
        Ok(id)
    }

    async fn read(&self, namespace: &str, key: &str) -> Result<Option<Value>> {
        Ok(self.db.get(COL_MEMORY, &doc_id(namespace, key)).await)
    }

    async fn list(&self, namespace: Option<&str>, limit: usize) -> Result<Vec<Value>> {
        let mut notes: Vec<(String, Value)> = self.db.list(COL_MEMORY).await;
        notes.sort_by(|a, b| {
            let ka = a.1.get("updated_at").and_then(|v| v.as_str()).unwrap_or("");
            let kb = b.1.get("updated_at").and_then(|v| v.as_str()).unwrap_or("");
            kb.cmp(ka)
        });
        Ok(notes
            .into_iter()
            .filter(|(_, d)| match namespace {
                Some(ns) => d.get("namespace").and_then(|v| v.as_str()) == Some(ns),
                None => true,
            })
            .take(limit)
            .map(|(_, d)| d)
            .collect())
    }

    async fn search(
        &self,
        query: &str,
        namespace: Option<&str>,
        limit: usize,
    ) -> Result<Vec<Value>> {
        let terms: Vec<String> = query
            .split_whitespace()
            .map(|t| t.to_lowercase())
            .filter(|t| !t.is_empty())
            .collect();
        if terms.is_empty() {
            return Ok(Vec::new());
        }

        let notes: Vec<(String, Value)> = self.db.list(COL_MEMORY).await;
        let mut scored: Vec<(usize, Value)> = notes
            .into_iter()
            .filter(|(_, d)| match namespace {
                Some(ns) => d.get("namespace").and_then(|v| v.as_str()) == Some(ns),
                None => true,
            })
            .filter_map(|(_, d)| {
                let hay = searchable_text(&d).to_lowercase();
                let score = terms.iter().filter(|t| hay.contains(t.as_str())).count();
                if score > 0 {
                    Some((score, d))
                } else {
                    None
                }
            })
            .collect();

        // Most hits first; break ties by recency.
        scored.sort_by(|a, b| {
            b.0.cmp(&a.0).then_with(|| {
                let ka = a.1.get("updated_at").and_then(|v| v.as_str()).unwrap_or("");
                let kb = b.1.get("updated_at").and_then(|v| v.as_str()).unwrap_or("");
                kb.cmp(ka)
            })
        });

        Ok(scored
            .into_iter()
            .take(limit)
            .map(|(score, mut d)| {
                if let Some(obj) = d.as_object_mut() {
                    obj.insert("_score".into(), serde_json::json!(score));
                }
                d
            })
            .collect())
    }
}

/// Concatenate the fields a keyword search should match against.
fn searchable_text(doc: &Value) -> String {
    let mut s = String::new();
    for field in ["key", "content"] {
        if let Some(v) = doc.get(field).and_then(|v| v.as_str()) {
            s.push_str(v);
            s.push(' ');
        }
    }
    if let Some(tags) = doc.get("tags").and_then(|v| v.as_array()) {
        for t in tags {
            if let Some(t) = t.as_str() {
                s.push_str(t);
                s.push(' ');
            }
        }
    }
    s
}
