//! `KnowledgeBackend` sobre el cerebro (`crate::knowledge`).
//!
//! El programa (engagement) se fija al construir el backend, no lo elige el
//! modelo: así una tool no puede leer el conocimiento privado de otro programa.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::{json, Value};
use std::str::FromStr;
use std::sync::Arc;

use crate::knowledge::{self, KnowledgeKind};
use crate::store::HiveDb;

const EXCERPT_CHARS: usize = 1200;

pub struct KnowledgeBackend {
    pub db: HiveDb,
    pub program: Option<String>,
}

impl KnowledgeBackend {
    pub fn new(db: HiveDb, program: Option<String>) -> Self {
        Self { db, program }
    }

    /// Registra `knowledge_search` en `registry` con el programa del engagement.
    pub fn register(
        registry: &mut hivecyber_tools::ToolRegistry,
        db: &HiveDb,
        program: Option<String>,
    ) {
        let backend = Arc::new(KnowledgeBackend::new(db.clone(), program));
        registry.register(Arc::new(hivecyber_tools::knowledge::KnowledgeSearch { db: backend }));
    }
}

impl FromStr for KnowledgeKind {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        Ok(match s {
            "playbook" => KnowledgeKind::Playbook,
            "checklist" => KnowledgeKind::Checklist,
            "scope" => KnowledgeKind::Scope,
            "finding" => KnowledgeKind::Finding,
            other => anyhow::bail!("kind invalido: {other}"),
        })
    }
}

#[async_trait]
impl hivecyber_tools::knowledge::KnowledgeBackend for KnowledgeBackend {
    async fn search(
        &self,
        query: &str,
        kind: Option<&str>,
        limit: usize,
        full: bool,
    ) -> Result<Vec<Value>> {
        let kind = kind.map(str::parse::<KnowledgeKind>).transpose()?;
        let hits = knowledge::search(&self.db, kind, self.program.as_deref(), query, limit).await?;
        Ok(hits
            .into_iter()
            .map(|h| {
                let body = if full {
                    h.doc.body.clone()
                } else {
                    knowledge::excerpt(&h.doc.body, EXCERPT_CHARS)
                };
                json!({
                    "id": h.doc.id,
                    "kind": h.doc.kind.as_str(),
                    "title": h.doc.title,
                    "score": h.score,
                    "refs": h.doc.refs,
                    "severity_hint": h.doc.severity_hint,
                    "program": h.doc.program,
                    "body": body,
                })
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::knowledge::{ingest, KnowledgeDoc};
    use hivecyber_tools::knowledge::KnowledgeSearch;
    use hivecyber_tools::registry::Tool;

    fn finding(id: &str, program: &str) -> KnowledgeDoc {
        KnowledgeDoc {
            id: id.into(),
            kind: KnowledgeKind::Finding,
            title: "IDOR en pedidos".into(),
            tags: vec![],
            refs: vec![],
            severity_hint: None,
            program: Some(program.into()),
            dedup_key: None,
            body: format!("idor en pedidos de {program}"),
        }
    }

    async fn db() -> (HiveDb, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("hc_kb_{}", uuid::Uuid::new_v4()));
        let db = HiveDb::open(&dir).await.unwrap();
        ingest(&db, &[finding("f-acme", "acme"), finding("f-other", "other")]).await.unwrap();
        (db, dir)
    }

    #[tokio::test]
    async fn tool_only_sees_its_own_programs_private_knowledge() {
        let (db, dir) = db().await;
        let tool = KnowledgeSearch { db: Arc::new(KnowledgeBackend::new(db.clone(), Some("acme".into()))) };
        // El modelo intenta forzar otro programa: el parametro se ignora.
        let out = tool
            .execute(json!({"query": "idor pedidos", "kind": "finding", "program": "other"}))
            .await
            .unwrap();
        let ids: Vec<&str> = out["results"].as_array().unwrap().iter().map(|r| r["id"].as_str().unwrap()).collect();
        assert_eq!(ids, ["f-acme"]);

        // Sin programa activo no ve hallazgos privados de nadie.
        let none = KnowledgeSearch { db: Arc::new(KnowledgeBackend::new(db, None)) };
        let out = none.execute(json!({"query": "idor pedidos", "kind": "finding"})).await.unwrap();
        assert_eq!(out["count"], 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn tool_validates_input_and_truncates_unless_full() {
        let (db, dir) = db().await;
        let long = KnowledgeDoc { body: "idor ".repeat(1000), ..finding("f-long", "acme") };
        ingest(&db, &[long]).await.unwrap();
        let tool = KnowledgeSearch { db: Arc::new(KnowledgeBackend::new(db, Some("acme".into()))) };

        assert!(tool.execute(json!({})).await.is_err(), "query requerida");
        assert!(tool.execute(json!({"query": "x", "kind": "nope"})).await.is_err(), "kind invalido");

        let short = tool.execute(json!({"query": "idor", "kind": "finding", "limit": 10})).await.unwrap();
        let len = |o: &serde_json::Value, id: &str| {
            o["results"].as_array().unwrap().iter().find(|r| r["id"] == id).unwrap()["body"]
                .as_str().unwrap().chars().count()
        };
        assert!(len(&short, "f-long") <= 1201);
        let full = tool.execute(json!({"query": "idor", "kind": "finding", "limit": 10, "full": true})).await.unwrap();
        assert_eq!(len(&full, "f-long"), 5000);
        std::fs::remove_dir_all(&dir).ok();
    }
}
