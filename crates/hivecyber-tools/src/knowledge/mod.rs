//! Knowledge tools — consulta del cerebro (playbooks, checklists, scope y
//! hallazgos previos). Igual que `memory`, la tool vive aquí y el backend lo
//! implementa `hivecyber-core`, para que este crate no dependa del store.

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

use crate::registry::{Tool, ToolCategory, ToolSchema};

const DEFAULT_LIMIT: usize = 3;
const MAX_LIMIT: usize = 10;

#[async_trait]
pub trait KnowledgeBackend: Send + Sync {
    /// Busca conocimiento relevante, más relevante primero. El programa
    /// (engagement) lo fija quien construye el backend: la tool no puede
    /// consultar el conocimiento privado de otro programa.
    /// `kind`: playbook | checklist | scope | finding. `full`: cuerpo completo
    /// en vez de un extracto.
    async fn search(
        &self,
        query: &str,
        kind: Option<&str>,
        limit: usize,
        full: bool,
    ) -> Result<Vec<Value>>;
}

pub struct KnowledgeSearch {
    pub db: Arc<dyn KnowledgeBackend>,
}

#[async_trait]
impl Tool for KnowledgeSearch {
    fn name(&self) -> &str {
        "knowledge_search"
    }
    fn description(&self) -> &str {
        "Busca en el cerebro de conocimiento: playbooks de metodologia por clase de bug, checklists, reglas de scope del programa y hallazgos ya registrados. Usala para fundamentar el metodo y, antes de reportar, para comprobar si un hallazgo ya existe (kind=finding)."
    }
    fn category(&self) -> ToolCategory {
        ToolCategory::Base
    }
    fn parameters(&self) -> ToolSchema {
        let mut props = HashMap::new();
        props.insert("query".into(), json!({"type": "string", "description": "Texto libre: clase de bug, endpoint, tecnica."}));
        props.insert(
            "kind".into(),
            json!({"type": "string", "enum": ["playbook", "checklist", "scope", "finding"]}),
        );
        props.insert("limit".into(), json!({"type": "integer", "default": DEFAULT_LIMIT}));
        props.insert("full".into(), json!({"type": "boolean", "default": false}));
        ToolSchema {
            schema_type: "object".into(),
            properties: props,
            required: Some(vec!["query".into()]),
        }
    }

    async fn execute(&self, params: Value) -> Result<Value> {
        let query = params
            .get("query")
            .and_then(|v| v.as_str())
            .filter(|q| !q.trim().is_empty())
            .ok_or_else(|| anyhow!("query required"))?;
        let kind = params.get("kind").and_then(|v| v.as_str());
        if let Some(k) = kind {
            if !["playbook", "checklist", "scope", "finding"].contains(&k) {
                return Err(anyhow!("kind invalido: {k}"));
            }
        }
        let limit = params
            .get("limit")
            .and_then(|v| v.as_u64())
            .map(|l| (l as usize).clamp(1, MAX_LIMIT))
            .unwrap_or(DEFAULT_LIMIT);
        let full = params.get("full").and_then(|v| v.as_bool()).unwrap_or(false);

        let results = self.db.search(query, kind, limit, full).await?;
        Ok(json!({ "query": query, "count": results.len(), "results": results }))
    }
}

/// Backend de la memoria de hallazgos (lo implementa `hivecyber-core`). El
/// programa activo y el actor los fija quien construye el backend.
#[async_trait]
pub trait FindingBackend: Send + Sync {
    /// Registra un hallazgo aplicando el gate de deduplicación. `input` son los
    /// parámetros de la tool tal cual; el backend valida y devuelve el veredicto.
    async fn record(&self, input: Value) -> Result<Value>;

    /// Hallazgos que el redactor puede incluir en un informe (los borradores y
    /// los posibles duplicados quedan retenidos para revisión humana).
    async fn list_reportable(&self, limit: usize) -> Result<Value>;
}

pub struct FindingRecord {
    pub db: Arc<dyn FindingBackend>,
}

#[async_trait]
impl Tool for FindingRecord {
    fn name(&self) -> &str {
        "finding_record"
    }
    fn description(&self) -> &str {
        "Registra un hallazgo en la memoria del programa. Antes de guardar lo compara con los hallazgos previos: un duplicado exacto NO se guarda; un posible duplicado queda retenido para revision humana; sin reproduccion queda en borrador. Llamala al confirmar un hallazgo, con la reproduccion paso a paso."
    }
    fn category(&self) -> ToolCategory {
        ToolCategory::Base
    }
    fn parameters(&self) -> ToolSchema {
        let mut props = HashMap::new();
        props.insert("vulnerability".into(), json!({"type": "string", "description": "Clase: idor, ssrf, sqli, xss, llm-tool-exfil..."}));
        props.insert("host".into(), json!({"type": "string"}));
        props.insert("endpoint".into(), json!({"type": "string", "description": "Ruta afectada, p.ej. /api/orders/123"}));
        props.insert("parameter".into(), json!({"type": "string", "description": "Parametro vulnerable, si aplica"}));
        props.insert("title".into(), json!({"type": "string"}));
        props.insert("severity".into(), json!({"type": "string", "enum": ["info", "low", "medium", "high", "critical"]}));
        props.insert("cvss".into(), json!({"type": "string"}));
        props.insert("reproduction".into(), json!({"type": "string", "description": "Pasos reproducibles. Sin esto queda en borrador."}));
        props.insert("evidence".into(), json!({"type": "array", "items": {"type": "object"}}));
        ToolSchema {
            schema_type: "object".into(),
            properties: props,
            required: Some(vec!["vulnerability".into(), "host".into()]),
        }
    }

    async fn execute(&self, params: Value) -> Result<Value> {
        self.db.record(params).await
    }
}

pub struct FindingList {
    pub db: Arc<dyn FindingBackend>,
}

#[async_trait]
impl Tool for FindingList {
    fn name(&self) -> &str {
        "finding_list"
    }
    fn description(&self) -> &str {
        "Lista los hallazgos del programa que se pueden incluir en un informe. Consultala SIEMPRE antes de redactar: los borradores y posibles duplicados no aparecen (requieren revision humana) y solo se informa cuantos quedan retenidos."
    }
    fn category(&self) -> ToolCategory {
        ToolCategory::Base
    }
    fn parameters(&self) -> ToolSchema {
        let mut props = HashMap::new();
        props.insert("limit".into(), json!({"type": "integer", "default": 50}));
        ToolSchema { schema_type: "object".into(), properties: props, required: None }
    }

    async fn execute(&self, params: Value) -> Result<Value> {
        let limit = params
            .get("limit")
            .and_then(|v| v.as_u64())
            .map(|l| (l as usize).clamp(1, 200))
            .unwrap_or(50);
        self.db.list_reportable(limit).await
    }
}
