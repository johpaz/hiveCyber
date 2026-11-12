//! El cerebro de hiveCyber: conocimiento recuperable (playbooks, checklists,
//! scope de programa, memoria de hallazgos).
//!
//! El documento autoritativo vive en `COL_KNOWLEDGE`; el índice híbrido de
//! HiveDB (BM25 con analizador en español) es un derivado que se reconstruye
//! desde la colección. El filtro escalar del índice solo soporta igualdad, así
//! que `kind` y `program` son filtros `Eq` y "general + programa" se resuelve
//! con dos consultas fusionadas.

pub mod finding;

use crate::store::collections::COL_KNOWLEDGE;
use crate::store::HiveDb;
use anyhow::{bail, Context, Result};
use hivedb_core::{HybridQuery, IndexDoc, ScalarFilter};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Valor del filtro `program` para el corpus general (sin programa).
pub const GENERAL_PROGRAM: &str = "_general";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KnowledgeKind {
    Playbook,
    Scope,
    Finding,
    Checklist,
}

impl KnowledgeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            KnowledgeKind::Playbook => "playbook",
            KnowledgeKind::Scope => "scope",
            KnowledgeKind::Finding => "finding",
            KnowledgeKind::Checklist => "checklist",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KnowledgeDoc {
    pub id: String,
    pub kind: KnowledgeKind,
    pub title: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity_hint: Option<String>,
    /// `None` = corpus general; `Some(slug)` = privado de un engagement.
    #[serde(default)]
    pub program: Option<String>,
    /// Clave estable de deduplicación (solo `kind=finding`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dedup_key: Option<String>,
    #[serde(default)]
    pub body: String,
}

#[derive(Debug, Clone)]
pub struct KnowledgeHit {
    pub doc: KnowledgeDoc,
    pub score: f32,
}

impl KnowledgeDoc {
    /// Parsea un documento `---\n<frontmatter YAML>\n---\n<cuerpo Markdown>`.
    pub fn parse_markdown(content: &str) -> Result<Self> {
        let content = content.replace("\r\n", "\n");
        let rest = content
            .strip_prefix("---\n")
            .context("falta el frontmatter (el archivo debe empezar con '---')")?;
        let end = rest
            .find("\n---")
            .context("frontmatter sin cierre '---'")?;
        let (front, after) = rest.split_at(end);
        let body = after[4..].trim_start_matches('\n').trim_end().to_string();
        let mut doc: KnowledgeDoc =
            serde_yaml::from_str(front).context("frontmatter YAML inválido")?;
        doc.body = body;
        if doc.id.trim().is_empty() {
            bail!("frontmatter sin 'id'");
        }
        Ok(doc)
    }

    fn program_filter(&self) -> &str {
        self.program.as_deref().unwrap_or(GENERAL_PROGRAM)
    }

    fn to_index_doc(&self) -> IndexDoc {
        // refs y tags comparten el campo `tags` (boost 3.0) para que "CWE-639"
        // o "api1" encuentren el playbook.
        let tags = self
            .tags
            .iter()
            .chain(self.refs.iter())
            .cloned()
            .collect::<Vec<_>>()
            .join(" ");
        IndexDoc::new(&self.id)
            .with_name(&self.title)
            .with_tags(tags)
            .with_body(&self.body)
            .with_filters(vec![
                ScalarFilter::eq("kind", self.kind.as_str()),
                ScalarFilter::eq("program", self.program_filter()),
            ])
    }
}

/// Palabras vacías (es/en). El analizador del índice no las elimina y, con una
/// consulta en lenguaje natural ("IDOR en un endpoint de pedidos"), términos
/// como "de" o "en" terminan dominando el ranking por el boost del título.
const STOPWORDS: &[&str] = &[
    "el", "la", "los", "las", "un", "una", "unos", "unas", "de", "del", "al", "en", "y", "o", "u",
    "a", "que", "por", "para", "con", "sin", "se", "su", "sus", "es", "son", "lo", "le", "les",
    "como", "cómo", "mas", "más", "qué", "pero", "esto", "esta", "este", "the", "an", "of", "in", "on", "to", "and",
    "or", "for", "with", "is", "are", "how", "what",
];

/// Quita stopwords de la consulta. Si todo eran stopwords, devuelve la original.
fn clean_query(query: &str) -> String {
    let kept: Vec<&str> = query
        .split_whitespace()
        .filter(|w| {
            let t = w
                .trim_matches(|c: char| !c.is_alphanumeric())
                .to_lowercase();
            !t.is_empty() && !STOPWORDS.contains(&t.as_str())
        })
        .collect();
    if kept.is_empty() {
        query.trim().to_string()
    } else {
        kept.join(" ")
    }
}

/// Escribe (upsert) documentos en la colección y los indexa. Idempotente.
pub async fn ingest(db: &HiveDb, docs: &[KnowledgeDoc]) -> Result<usize> {
    for d in docs {
        db.insert(COL_KNOWLEDGE, &d.id, serde_json::to_value(d)?)
            .await?;
    }
    db.index_upsert_batch(docs.iter().map(KnowledgeDoc::to_index_doc).collect())
        .await?;
    Ok(docs.len())
}

/// Ingiere todos los `.md` de un directorio (recursivo). Los archivos sin
/// frontmatter válido se omiten y se devuelven en el segundo valor.
pub async fn ingest_dir(db: &HiveDb, dir: &Path) -> Result<(usize, Vec<String>)> {
    let mut docs = Vec::new();
    let mut skipped = Vec::new();
    for entry in walkdir::WalkDir::new(dir).sort_by_file_name() {
        let entry = entry?;
        if !entry.file_type().is_file()
            || entry.path().extension().and_then(|e| e.to_str()) != Some("md")
        {
            continue;
        }
        let text = std::fs::read_to_string(entry.path())?;
        match KnowledgeDoc::parse_markdown(&text) {
            Ok(d) => docs.push(d),
            Err(e) => skipped.push(format!("{}: {e}", entry.path().display())),
        }
    }
    let n = ingest(db, &docs).await?;
    Ok((n, skipped))
}

/// Busca conocimiento. Devuelve el corpus general más, si `program` es
/// `Some`, el privado de ese programa; ordenado por score BM25 descendente.
pub async fn search(
    db: &HiveDb,
    kind: Option<KnowledgeKind>,
    program: Option<&str>,
    query: &str,
    k: usize,
) -> Result<Vec<KnowledgeHit>> {
    if query.trim().is_empty() || k == 0 {
        return Ok(Vec::new());
    }
    let query = clean_query(query);
    let mut scopes = vec![GENERAL_PROGRAM];
    if let Some(p) = program {
        if p != GENERAL_PROGRAM {
            scopes.push(p);
        }
    }

    let mut best: HashMap<String, f32> = HashMap::new();
    for scope in scopes {
        let mut filters = vec![ScalarFilter::eq("program", scope)];
        if let Some(kind) = kind {
            filters.push(ScalarFilter::eq("kind", kind.as_str()));
        }
        let hits = db
            .index_search(
                HybridQuery::default()
                    .with_text(&query)
                    .with_filters(filters)
                    .with_k(k),
            )
            .await?;
        for h in hits {
            let e = best.entry(h.id).or_insert(h.score);
            if h.score > *e {
                *e = h.score;
            }
        }
    }

    let mut ranked: Vec<(String, f32)> = best.into_iter().collect();
    ranked.sort_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    ranked.truncate(k);

    let mut out = Vec::with_capacity(ranked.len());
    for (id, score) in ranked {
        if let Some(v) = db.get(COL_KNOWLEDGE, &id).await {
            if let Ok(doc) = serde_json::from_value::<KnowledgeDoc>(v) {
                out.push(KnowledgeHit { doc, score });
            }
        }
    }
    Ok(out)
}

/// Documento `kind=scope` derivado de la `EngagementPolicy`, en lenguaje
/// natural para que el agente lo consulte. `None` si la política no tiene
/// `program` (p. ej. la política permisiva derivada de `--allowlist-hosts`).
/// El id es estable (`scope-<program>`), así que re-ingerirlo actualiza.
pub fn scope_doc(policy: &hivecyber_tools::EngagementPolicy) -> Option<KnowledgeDoc> {
    let program = policy.program.trim();
    if program.is_empty() {
        return None;
    }
    let names = |v: &[serde_json::Value]| -> Vec<String> {
        v.iter().filter_map(|x| x.as_str().map(String::from)).collect()
    };
    let to_names = |items: Vec<serde_json::Value>| names(&items);
    let prohibited = to_names(
        policy.prohibited.iter().filter_map(|a| serde_json::to_value(a).ok()).collect(),
    );
    let approval = to_names(
        policy
            .require_human_approval
            .iter()
            .filter_map(|a| serde_json::to_value(a).ok())
            .collect(),
    );

    let mut body = format!("# Scope del programa {program}\n\n## Objetivos autorizados\n");
    if policy.targets.is_empty() {
        body.push_str("- (ninguno declarado)\n");
    }
    for t in &policy.targets {
        let paths = if t.paths.is_empty() { "/**".to_string() } else { t.paths.join(", ") };
        let methods = if t.methods.is_empty() { "cualquiera".to_string() } else { t.methods.join(", ") };
        body.push_str(&format!("- {} — rutas: {paths}; metodos: {methods}", t.host));
        if let Some(rps) = t.rate_limit_rps {
            body.push_str(&format!("; limite {rps} req/s"));
        }
        if t.only_own_accounts {
            body.push_str("; solo cuentas propias");
        }
        body.push('\n');
    }
    body.push_str("\n## Fuera de scope (excluidos)\n");
    if policy.excluded.is_empty() {
        body.push_str("- (ninguno)\n");
    }
    for e in &policy.excluded {
        body.push_str(&format!("- {e}\n"));
    }
    body.push_str(&format!(
        "\n## Actividades prohibidas\n{}\n",
        if prohibited.is_empty() { "- (ninguna declarada)".to_string() } else { format!("- {}", prohibited.join("\n- ")) }
    ));
    body.push_str(&format!(
        "\n## Requieren aprobacion humana\n{}\n",
        if approval.is_empty() { "- (ninguna declarada)".to_string() } else { format!("- {}", approval.join("\n- ")) }
    ));
    body.push_str(&format!(
        "\n## Politica de IA\n- declarar uso de IA en los reportes: {}\n- envio autonomo de reportes: {}\n- umbral de duplicados: {:.2}\n",
        if policy.ai_policy.disclosure_required { "obligatorio" } else { "no exigido" },
        if policy.ai_policy.autonomous_submission_allowed { "permitido" } else { "NO permitido (un humano debe enviar)" },
        policy.knowledge.dedup_threshold,
    ));
    if let Some(tw) = &policy.time_windows {
        body.push_str(&format!(
            "\n## Ventana operativa\n- dias: {}\n- horas UTC: {}\n",
            if tw.allowed_days.is_empty() { "todos".to_string() } else { tw.allowed_days.join(", ") },
            tw.allowed_hours_utc
                .map(|(a, b)| format!("{a:02}:00-{b:02}:00"))
                .unwrap_or_else(|| "todas".to_string()),
        ));
    }

    Some(KnowledgeDoc {
        id: format!("scope-{program}"),
        kind: KnowledgeKind::Scope,
        title: format!("Scope y reglas del programa {program}"),
        tags: vec!["scope".into(), "reglas".into(), "programa".into(), program.to_string()],
        refs: vec![],
        severity_hint: None,
        program: Some(program.to_string()),
        dedup_key: None,
        body,
    })
}

/// Máximo de documentos de conocimiento inyectados por turno.
pub const MAX_PER_TURN: usize = 3;
/// Un hit entra si su score es al menos esta fracción del mejor (como
/// `skill_selector`).
pub const RELEVANCE_RATIO: f32 = 0.3;

/// Selecciona el conocimiento relevante para `message`: top-N del corpus
/// general + el privado de `program`, con corte relativo. Vacío si nada puntúa.
pub async fn select(db: &HiveDb, message: &str, program: Option<&str>) -> Vec<KnowledgeHit> {
    let hits = match search(db, None, program, message, MAX_PER_TURN * 2).await {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!(error = %e, "knowledge select failed");
            return Vec::new();
        }
    };
    let top = hits.first().map(|h| h.score).unwrap_or(0.0);
    hits.into_iter()
        .filter(|h| top > 0.0 && h.score >= top * RELEVANCE_RATIO)
        .take(MAX_PER_TURN)
        .collect()
}

/// Recorta `s` a `max` caracteres (por char, no por byte) añadiendo `…`.
pub fn excerpt(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tmp() -> PathBuf {
        std::env::temp_dir().join(format!("hc_kn_{}", uuid::Uuid::new_v4()))
    }

    fn doc(id: &str, kind: KnowledgeKind, program: Option<&str>, title: &str, body: &str) -> KnowledgeDoc {
        KnowledgeDoc {
            id: id.into(),
            kind,
            title: title.into(),
            tags: vec![],
            refs: vec![],
            severity_hint: None,
            program: program.map(String::from),
            dedup_key: None,
            body: body.into(),
        }
    }

    #[tokio::test]
    async fn scope_doc_is_derived_from_policy_and_searchable() {
        let policy: hivecyber_tools::EngagementPolicy = serde_yaml::from_str(
            r#"{"program":"acme","targets":[{"host":"api.acme.com","paths":["/api/**"],"methods":["GET"],"rate_limit_rps":2.0,"only_own_accounts":true}],
               "excluded":["blog.acme.com"],"prohibited":["denial_of_service"],"require_human_approval":["exploit"]}"#,
        )
        .unwrap();
        let d = scope_doc(&policy).unwrap();
        assert_eq!(d.id, "scope-acme");
        assert_eq!(d.program.as_deref(), Some("acme"));
        assert!(d.body.contains("api.acme.com") && d.body.contains("blog.acme.com"));
        assert!(d.body.contains("denial_of_service") && d.body.contains("exploit"));
        assert!(scope_doc(&hivecyber_tools::EngagementPolicy::empty()).is_none());

        let dir = tmp();
        let db = HiveDb::open(&dir).await.unwrap();
        ingest(&db, &[d]).await.unwrap();
        let hits = search(&db, Some(KnowledgeKind::Scope), Some("acme"), "que hosts estan excluidos", 3).await.unwrap();
        assert_eq!(hits.first().map(|h| h.doc.id.as_str()), Some("scope-acme"));
        // Otro programa no lo ve.
        assert!(search(&db, Some(KnowledgeKind::Scope), Some("otro"), "hosts excluidos", 3).await.unwrap().is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn select_applies_relative_cutoff_and_limit() {
        let dir = tmp();
        let db = HiveDb::open(&dir).await.unwrap();
        ingest(
            &db,
            &[
                doc("a", KnowledgeKind::Playbook, None, "SSRF metadata cloud", "ssrf ssrf ssrf metadata"),
                doc("b", KnowledgeKind::Playbook, None, "Otra cosa", "nada que ver con redes"),
            ],
        )
        .await
        .unwrap();
        let got = select(&db, "ssrf metadata", None).await;
        assert_eq!(got.iter().map(|h| h.doc.id.as_str()).collect::<Vec<_>>(), ["a"]);
        assert!(select(&db, "   ", None).await.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn parses_frontmatter_and_body() {
        let d = KnowledgeDoc::parse_markdown(
            "---\nid: pb-x\nkind: playbook\ntitle: \"Prueba\"\ntags: [a, b]\nrefs: [CWE-1]\nprogram: null\n---\n\n# Cuerpo\nTexto\n",
        )
        .unwrap();
        assert_eq!(d.id, "pb-x");
        assert_eq!(d.kind, KnowledgeKind::Playbook);
        assert_eq!(d.tags, ["a", "b"]);
        assert_eq!(d.program, None);
        assert_eq!(d.body, "# Cuerpo\nTexto");
    }

    #[test]
    fn rejects_missing_or_broken_frontmatter() {
        assert!(KnowledgeDoc::parse_markdown("# sin frontmatter").is_err());
        assert!(KnowledgeDoc::parse_markdown("---\nid: x\nkind: playbook\n").is_err());
        assert!(KnowledgeDoc::parse_markdown("---\nid: \"\"\nkind: playbook\ntitle: t\n---\nx").is_err());
        assert!(KnowledgeDoc::parse_markdown("---\nid: x\nkind: nope\ntitle: t\n---\nx").is_err());
    }

    #[tokio::test]
    async fn search_matches_spanish_stems_and_accents() {
        let dir = tmp();
        let db = HiveDb::open(&dir).await.unwrap();
        ingest(
            &db,
            &[
                doc("a", KnowledgeKind::Playbook, None, "Autorización rota", "Validar la propiedad de los objetos"),
                doc("b", KnowledgeKind::Playbook, None, "Inyección SQL", "Parámetros sin escapar"),
            ],
        )
        .await
        .unwrap();
        let hits = search(&db, None, None, "autorizacion objetos", 5).await.unwrap();
        assert_eq!(hits.first().map(|h| h.doc.id.as_str()), Some("a"));
        assert!(hits.iter().all(|h| h.doc.id != "b"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn search_filters_by_kind_and_scopes_by_program() {
        let dir = tmp();
        let db = HiveDb::open(&dir).await.unwrap();
        ingest(
            &db,
            &[
                doc("pb", KnowledgeKind::Playbook, None, "IDOR checkout", "idor en pedidos"),
                doc("f-acme", KnowledgeKind::Finding, Some("acme"), "IDOR pedidos", "idor en pedidos de acme"),
                doc("f-other", KnowledgeKind::Finding, Some("other"), "IDOR pedidos", "idor en pedidos de other"),
            ],
        )
        .await
        .unwrap();

        let ids = |hits: Vec<KnowledgeHit>| {
            let mut v: Vec<String> = hits.into_iter().map(|h| h.doc.id).collect();
            v.sort();
            v
        };
        // Sin programa: solo corpus general.
        assert_eq!(ids(search(&db, None, None, "idor pedidos", 10).await.unwrap()), ["pb"]);
        // Con programa: general + privado de ese programa, nunca el de otro.
        assert_eq!(
            ids(search(&db, None, Some("acme"), "idor pedidos", 10).await.unwrap()),
            ["f-acme", "pb"]
        );
        // Filtro por kind.
        assert_eq!(
            ids(search(&db, Some(KnowledgeKind::Finding), Some("acme"), "idor pedidos", 10).await.unwrap()),
            ["f-acme"]
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn ingest_is_idempotent_and_survives_reopen() {
        let dir = tmp();
        let d = doc("pb", KnowledgeKind::Playbook, None, "SSRF", "peticiones del lado del servidor");
        {
            let db = HiveDb::open(&dir).await.unwrap();
            ingest(&db, &[d.clone()]).await.unwrap();
            ingest(&db, &[d.clone()]).await.unwrap();
            assert_eq!(db.count(COL_KNOWLEDGE).await, 1);
        }
        let db = HiveDb::open(&dir).await.unwrap();
        let hits = search(&db, None, None, "servidor", 5).await.unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].doc, d);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn clean_query_drops_stopwords_but_never_empties() {
        assert_eq!(clean_query("IDOR en un endpoint de pedidos"), "IDOR endpoint pedidos");
        assert_eq!(clean_query("¿Qué es el SSRF?"), "SSRF?");
        assert_eq!(clean_query("de la en"), "de la en");
    }

    #[tokio::test]
    async fn natural_language_query_ranks_idor_playbook_first() {
        let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../knowledge");
        let dir = tmp();
        let db = HiveDb::open(&dir).await.unwrap();
        ingest_dir(&db, &corpus).await.unwrap();
        let hits = search(&db, None, None, "IDOR en un endpoint de pedidos", 4).await.unwrap();
        assert_eq!(hits.first().map(|h| h.doc.id.as_str()), Some("pb-idor"), "{:?}",
            hits.iter().map(|h| (&h.doc.id, h.score)).collect::<Vec<_>>());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn bundled_corpus_ingests_and_idor_query_finds_playbook() {
        let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../knowledge");
        let dir = tmp();
        let db = HiveDb::open(&dir).await.unwrap();
        let (n, skipped) = ingest_dir(&db, &corpus).await.unwrap();
        assert!(skipped.is_empty(), "archivos inválidos: {skipped:?}");
        assert!(n >= 4, "esperaba playbooks + checklist, got {n}");
        let hits = search(&db, Some(KnowledgeKind::Playbook), None, "IDOR", 3).await.unwrap();
        assert_eq!(hits.first().map(|h| h.doc.id.as_str()), Some("pb-idor"));
        std::fs::remove_dir_all(&dir).ok();
    }
}
