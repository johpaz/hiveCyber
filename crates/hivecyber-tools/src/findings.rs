//! Tool `finding_submit`: el agente registra un hallazgo tipado. Backend en
//! `hivecyber-core` (mismo patrón que memory/delegation). La tool NO puede
//! marcar un hallazgo como listo ni enviarlo: eso lo decide un humano.

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

use crate::registry::{Tool, ToolCategory, ToolSchema};

#[async_trait]
pub trait FindingsBackend: Send + Sync {
    async fn submit(&self, input: Value) -> Result<Value>;
}

pub struct FindingSubmit {
    pub db: Arc<dyn FindingsBackend>,
}

#[async_trait]
impl Tool for FindingSubmit {
    fn name(&self) -> &str {
        "finding_submit"
    }
    fn description(&self) -> &str {
        "Registra un hallazgo de seguridad tipado (vulnerability, host, endpoint, parámetro, severidad, pasos de reproducción y evidencia). Verifica scope y duplicados; queda en revisión humana, NO se envía al programa."
    }
    fn category(&self) -> ToolCategory {
        ToolCategory::Base
    }
    fn parameters(&self) -> ToolSchema {
        let mut p = HashMap::new();
        p.insert("vulnerability".into(), json!({"type": "string", "description": "clase: idor, ssrf, xss, sqli, llm-tool-exfil…"}));
        p.insert("host".into(), json!({"type": "string"}));
        p.insert("endpoint".into(), json!({"type": "string"}));
        p.insert("parameter".into(), json!({"type": "string"}));
        p.insert("title".into(), json!({"type": "string"}));
        p.insert("severity".into(), json!({"type": "string", "enum": ["info", "low", "medium", "high", "critical"]}));
        p.insert("cvss".into(), json!({"type": "string"}));
        p.insert("reproduction".into(), json!({"type": "string", "description": "pasos reproducibles; sin ellos queda en draft"}));
        p.insert("evidence".into(), json!({"type": "array", "items": {"type": "string"}}));
        ToolSchema {
            schema_type: "object".into(),
            properties: p,
            required: Some(vec!["vulnerability".into(), "host".into()]),
        }
    }
    async fn execute(&self, params: Value) -> Result<Value> {
        if !params.is_object() {
            return Err(anyhow!("se esperaba un objeto"));
        }
        self.db.submit(params).await
    }
}
