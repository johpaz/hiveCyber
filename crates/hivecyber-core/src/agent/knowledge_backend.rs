//! `KnowledgeBackend` sobre el cerebro (`crate::knowledge`).
//!
//! El programa (engagement) se fija al construir el backend, no lo elige el
//! modelo: así una tool no puede leer el conocimiento privado de otro programa.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::{json, Value};
use std::str::FromStr;
use std::sync::Arc;

use crate::knowledge::finding::{self, FindingInput, FindingStatus, RecordOptions, Verdict};
use crate::knowledge::{self, KnowledgeKind};
use crate::store::HiveDb;

const EXCERPT_CHARS: usize = 1200;

pub struct KnowledgeBackend {
    pub db: HiveDb,
    pub program: Option<String>,
    /// Quién registra (id del agente), para `created_by`.
    pub actor: String,
    pub opts: RecordOptions,
}

impl KnowledgeBackend {
    pub fn new(db: HiveDb, program: Option<String>) -> Self {
        Self { db, program, actor: "agent".into(), opts: RecordOptions::default() }
    }

    /// Registra `knowledge_search`, `finding_record` y `finding_list` en
    /// `registry`, acotados al programa y a la politica del engagement activo.
    pub fn register(
        registry: &mut hivecyber_tools::ToolRegistry,
        db: &HiveDb,
        security: &hivecyber_tools::SecurityContext,
        actor: &str,
    ) {
        let policy = security.engagement_policy.as_ref();
        let program = policy.map(|p| p.program.trim().to_string()).filter(|p| !p.is_empty());
        let opts = policy
            .map(|p| RecordOptions {
                threshold: p.knowledge.dedup_threshold,
                autonomous_submission_allowed: p.ai_policy.autonomous_submission_allowed,
                ai_assisted: true,
            })
            .unwrap_or_default();
        let backend = Arc::new(KnowledgeBackend { db: db.clone(), program, actor: actor.to_string(), opts });
        registry.register(Arc::new(hivecyber_tools::knowledge::KnowledgeSearch { db: backend.clone() }));
        registry.register(Arc::new(hivecyber_tools::knowledge::FindingRecord { db: backend.clone() }));
        registry.register(Arc::new(hivecyber_tools::knowledge::FindingList { db: backend }));
    }
}

#[async_trait]
impl hivecyber_tools::knowledge::FindingBackend for KnowledgeBackend {
    async fn record(&self, input: Value) -> Result<Value> {
        let program = self.program.as_deref().ok_or_else(|| {
            anyhow::anyhow!("finding_record requiere un engagement activo (--engagement-policy con 'program')")
        })?;
        let input: FindingInput = serde_json::from_value(input)
            .map_err(|e| anyhow::anyhow!("parametros invalidos: {e}"))?;
        let rec = finding::record(&self.db, program, &self.actor, input, self.opts).await?;

        Ok(match (&rec.verdict, &rec.finding) {
            (Verdict::Duplicate { of }, _) => json!({
                "recorded": false,
                "verdict": "duplicate",
                "duplicate_of": of,
                "message": "Duplicado exacto de un hallazgo ya registrado: no se guardo. No lo reportes de nuevo.",
            }),
            (verdict, Some(f)) => {
                let (name, extra) = match verdict {
                    Verdict::Possible { similarity, .. } => ("possible_duplicate", json!({ "similarity": similarity })),
                    _ => ("new", json!({})),
                };
                let message = match f.status {
                    FindingStatus::PossibleDuplicate => "Posible duplicado: retenido hasta que una persona lo revise. No lo incluyas en informes.",
                    FindingStatus::Draft => "Guardado como borrador: falta la reproduccion paso a paso. Completa 'reproduction' y vuelve a registrarlo.",
                    FindingStatus::NeedsHumanReview => "Guardado. El programa no permite envio autonomo: queda a la espera de revision humana.",
                    _ => "Guardado y listo.",
                };
                json!({
                    "recorded": true,
                    "verdict": name,
                    "id": f.id,
                    "status": f.status.as_str(),
                    "dedup_key": f.dedup_key,
                    "duplicate_of": f.duplicate_of,
                    "message": message,
                    "details": extra,
                    // Evidencia tipada que el harness recoge para la aceptacion.
                    "evidence_item": { "type": "finding_status", "id": f.id, "status": f.status.as_str() },
                })
            }
            _ => unreachable!("un veredicto no duplicado siempre persiste el hallazgo"),
        })
    }

    async fn list_reportable(&self, limit: usize) -> Result<Value> {
        // Sin engagement activo no hay memoria de hallazgos: resultado vacio
        // (no error) para no bloquear la redaccion de informes sueltos.
        let Some(program) = self.program.as_deref() else {
            return Ok(json!({
                "program": null,
                "reportable": 0,
                "held_back": 0,
                "findings": [],
                "note": "Sin engagement activo: no hay memoria de hallazgos para este informe.",
                "evidence_item": { "type": "findings_reviewed", "reportable": 0, "held_back": 0 },
            }));
        };
        let (reportable, held_back) = finding::reportable(&self.db, program).await?;
        let total = reportable.len();
        let items: Vec<Value> = reportable
            .into_iter()
            .take(limit)
            .map(|f| {
                json!({
                    "id": f.id, "title": f.title, "vulnerability": f.vulnerability,
                    "host": f.host, "endpoint": f.endpoint, "parameter": f.parameter,
                    "severity": f.severity, "cvss": f.cvss, "status": f.status.as_str(),
                    "reproduction": f.reproduction, "ai_assisted": f.ai_assisted,
                })
            })
            .collect();
        Ok(json!({
            "program": program,
            "reportable": total,
            "held_back": held_back,
            "findings": items,
            "note": "Los borradores y posibles duplicados no se listan: requieren revision humana antes de reportarse.",
            "evidence_item": { "type": "findings_reviewed", "reportable": total, "held_back": held_back },
        }))
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

#[cfg(test)]
mod finding_tool_tests {
    use super::*;
    use hivecyber_tools::knowledge::{FindingList, FindingRecord};
    use hivecyber_tools::registry::Tool;
    use hivecyber_tools::{EngagementPolicy, SecurityContext};

    fn security(program: &str, autonomous: bool) -> SecurityContext {
        let mut p = EngagementPolicy { program: program.into(), ..Default::default() };
        p.ai_policy.autonomous_submission_allowed = autonomous;
        SecurityContext { engagement_policy: Some(Arc::new(p)), ..Default::default() }
    }

    fn tools(db: &HiveDb, sec: &SecurityContext) -> (FindingRecord, FindingList) {
        let mut reg = hivecyber_tools::ToolRegistry::new();
        KnowledgeBackend::register(&mut reg, db, sec, "web_pentester");
        let backend = Arc::new(KnowledgeBackend {
            db: db.clone(),
            program: sec.engagement_policy.as_ref().map(|p| p.program.clone()),
            actor: "web_pentester".into(),
            opts: RecordOptions {
                autonomous_submission_allowed: sec.engagement_policy.as_ref().map(|p| p.ai_policy.autonomous_submission_allowed).unwrap_or(false),
                ..Default::default()
            },
        });
        assert!(reg.get("finding_record").is_some() && reg.get("finding_list").is_some() && reg.get("knowledge_search").is_some());
        (FindingRecord { db: backend.clone() }, FindingList { db: backend })
    }

    #[tokio::test]
    async fn record_then_list_enforces_the_gate_and_emits_typed_evidence() {
        let dir = std::env::temp_dir().join(format!("hc_ft_{}", uuid::Uuid::new_v4()));
        let db = HiveDb::open(&dir).await.unwrap();
        let (record, list) = tools(&db, &security("acme", false));
        let args = |ep: &str, repro: &str| json!({"vulnerability":"IDOR","host":"api.acme.com","endpoint":ep,"parameter":"id","reproduction":repro});

        let r1 = record.execute(args("/api/orders/1", "GET con token ajeno")).await.unwrap();
        assert_eq!(r1["verdict"], "new");
        assert_eq!(r1["status"], "needs_human_review", "sin envio autonomo");
        assert_eq!(r1["evidence_item"]["type"], "finding_status");

        let dup = record.execute(args("/api/orders/9", "otra vez")).await.unwrap();
        assert_eq!(dup["recorded"], false);
        assert_eq!(dup["verdict"], "duplicate");
        assert_eq!(dup["duplicate_of"], r1["id"]);
        assert!(dup.get("evidence_item").is_none());

        let draft = record.execute(args("/api/users/1", "")).await.unwrap();
        assert_eq!(draft["status"], "draft");

        let l = list.execute(json!({})).await.unwrap();
        assert_eq!(l["reportable"], 1);
        assert_eq!(l["held_back"], 1);
        assert_eq!(l["findings"][0]["id"], r1["id"]);
        assert_eq!(l["evidence_item"], json!({"type":"findings_reviewed","reportable":1,"held_back":1}));

        // Entrada invalida -> error claro, nada se guarda.
        assert!(record.execute(json!({"vulnerability":"idor"})).await.is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn without_a_program_record_fails_but_list_is_empty_not_an_error() {
        let dir = std::env::temp_dir().join(format!("hc_ft_{}", uuid::Uuid::new_v4()));
        let db = HiveDb::open(&dir).await.unwrap();
        let backend = Arc::new(KnowledgeBackend::new(db, None));
        let err = FindingRecord { db: backend.clone() }
            .execute(json!({"vulnerability":"idor","host":"h"}))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("engagement activo"), "{err}");
        let l = FindingList { db: backend }.execute(json!({})).await.unwrap();
        assert_eq!(l["reportable"], 0);
        assert_eq!(l["evidence_item"]["type"], "findings_reviewed");
        std::fs::remove_dir_all(&dir).ok();
    }
}
