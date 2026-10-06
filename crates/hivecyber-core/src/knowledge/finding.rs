//! Memoria de hallazgos y gate de deduplicación.
//!
//! Un hallazgo se guarda tipado en `COL_FINDINGS` (autoritativo) y se proyecta
//! como documento `kind=finding` del cerebro para que `knowledge_search` lo
//! encuentre. Antes de persistir se compara con los hallazgos previos del mismo
//! programa:
//!
//! - misma `dedup_key` → **duplicado exacto**: no se guarda;
//! - similitud estructurada ≥ umbral → se guarda como `possible_duplicate` y
//!   queda fuera de lo reportable hasta que una persona lo revise;
//! - si no → nuevo. Sin reproducción queda en `draft`; con reproducción pasa a
//!   `needs_human_review` (o `ready` si el programa permite envío autónomo).
//!
//! La similitud NO usa el score BM25 (sin cota en modo texto): compara los campos
//! normalizados, así que el umbral `dedup_threshold` ∈ [0,1] es interpretable.

use crate::knowledge::{ingest, KnowledgeDoc, KnowledgeKind};
use crate::store::collections::COL_FINDINGS;
use crate::store::HiveDb;
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    Draft,
    NeedsHumanReview,
    PossibleDuplicate,
    Ready,
    Submitted,
    Accepted,
    Duplicate,
    Rejected,
}

impl FindingStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            FindingStatus::Draft => "draft",
            FindingStatus::NeedsHumanReview => "needs_human_review",
            FindingStatus::PossibleDuplicate => "possible_duplicate",
            FindingStatus::Ready => "ready",
            FindingStatus::Submitted => "submitted",
            FindingStatus::Accepted => "accepted",
            FindingStatus::Duplicate => "duplicate",
            FindingStatus::Rejected => "rejected",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        serde_json::from_value(serde_json::json!(s)).map_err(|_| {
            anyhow::anyhow!(
                "status invalido '{s}' (draft|needs_human_review|possible_duplicate|ready|submitted|accepted|duplicate|rejected)"
            )
        })
    }

    /// Lo que el redactor de informes puede incluir sin revisión adicional.
    pub fn is_reportable(&self) -> bool {
        matches!(
            self,
            FindingStatus::Ready | FindingStatus::NeedsHumanReview | FindingStatus::Accepted | FindingStatus::Submitted
        )
    }
}

/// Hallazgo tipado (ver `knowledge/schemas/finding.schema.json`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub program: String,
    pub vulnerability: String,
    #[serde(default)]
    pub title: String,
    pub host: String,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub parameter: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvss: Option<String>,
    pub dedup_key: String,
    pub status: FindingStatus,
    #[serde(default)]
    pub evidence: Vec<serde_json::Value>,
    #[serde(default)]
    pub reproduction: String,
    #[serde(default)]
    pub ai_assisted: bool,
    pub created_at: String,
    #[serde(default)]
    pub created_by: String,
    /// Si es `possible_duplicate`/`duplicate`: id del hallazgo con el que choca.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duplicate_of: Option<String>,
}

/// Entrada de un worker al registrar un hallazgo.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct FindingInput {
    pub vulnerability: String,
    pub host: String,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub parameter: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub cvss: Option<String>,
    #[serde(default)]
    pub reproduction: String,
    #[serde(default)]
    pub evidence: Vec<serde_json::Value>,
}

/// Resultado de comparar un candidato con los hallazgos previos.
#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    New,
    /// Misma `dedup_key`: duplicado exacto de `of`.
    Duplicate { of: String },
    /// Similitud ≥ umbral con `of`.
    Possible { of: String, similarity: f32 },
}

/// Opciones del programa que gobiernan el registro.
#[derive(Debug, Clone, Copy)]
pub struct RecordOptions {
    pub threshold: f32,
    pub autonomous_submission_allowed: bool,
    pub ai_assisted: bool,
}

impl Default for RecordOptions {
    fn default() -> Self {
        RecordOptions { threshold: 0.72, autonomous_submission_allowed: false, ai_assisted: true }
    }
}

#[derive(Debug, Clone)]
pub struct Recorded {
    pub verdict: Verdict,
    /// `None` solo para un duplicado exacto (no se persiste).
    pub finding: Option<Finding>,
}

// ---------------------------------------------------------------------------
// Normalización
// ---------------------------------------------------------------------------

/// Clase de vulnerabilidad normalizada: minúsculas, `-` como separador y alias
/// habituales (p. ej. `BOLA` y `Broken Object Level Authorization` → `idor`).
pub fn normalize_vulnerability(v: &str) -> String {
    let slug = v
        .trim()
        .to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    match slug.as_str() {
        "bola" | "idor-bola" | "bola-idor" | "broken-object-level-authorization"
        | "insecure-direct-object-reference" | "insecure-direct-object-references" => "idor".into(),
        "server-side-request-forgery" => "ssrf".into(),
        "sql-injection" | "sql-injection-sqli" | "sqli-injection" => "sqli".into(),
        "cross-site-scripting" => "xss".into(),
        "cross-site-request-forgery" => "csrf".into(),
        "open-redirect" | "unvalidated-redirect" => "open-redirect".into(),
        _ => slug,
    }
}

pub fn normalize_host(h: &str) -> String {
    hivecyber_tools::engagement::normalize_host(h)
}

/// Segmento de ruta que es un identificador (numérico, UUID o hex largo).
fn is_id_segment(seg: &str) -> bool {
    if seg.is_empty() {
        return false;
    }
    let numeric = seg.chars().all(|c| c.is_ascii_digit());
    let uuid = seg.len() == 36
        && seg.chars().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) { c == '-' } else { c.is_ascii_hexdigit() }
        });
    let long_hex = seg.len() >= 16 && seg.chars().all(|c| c.is_ascii_hexdigit());
    numeric || uuid || long_hex
}

/// Ruta normalizada: sin esquema/host/query/fragmento, en minúsculas, sin `/`
/// final y con los segmentos-identificador sustituidos por `{id}`, de modo que
/// `/api/orders/123` y `/api/orders/456` cuentan como el mismo endpoint.
pub fn normalize_endpoint(e: &str) -> String {
    let mut s = e.trim();
    if let Some(i) = s.find("://") {
        s = &s[i + 3..];
        s = s.find('/').map(|j| &s[j..]).unwrap_or("/");
    }
    let s = s.split(['?', '#']).next().unwrap_or("");
    let segs: Vec<String> = s
        .split('/')
        .filter(|p| !p.is_empty())
        .map(|p| {
            if is_id_segment(p) { "{id}".to_string() } else { p.to_lowercase() }
        })
        .collect();
    format!("/{}", segs.join("/"))
}

pub fn normalize_parameter(p: &str) -> String {
    p.trim().to_lowercase()
}

/// Clave estable de deduplicación: hash de programa + clase + host + endpoint
/// normalizado + parámetro.
pub fn dedup_key(program: &str, vulnerability: &str, host: &str, endpoint: &str, parameter: &str) -> String {
    let material = [
        program.trim().to_lowercase(),
        normalize_vulnerability(vulnerability),
        normalize_host(host),
        normalize_endpoint(endpoint),
        normalize_parameter(parameter),
    ]
    .join("\u{1f}");
    let digest = Sha256::digest(material.as_bytes());
    digest.iter().take(12).map(|b| format!("{b:02x}")).collect()
}

fn segments(endpoint: &str) -> HashSet<String> {
    normalize_endpoint(endpoint)
        .split('/')
        .filter(|p| !p.is_empty())
        .map(String::from)
        .collect()
}

/// Similitud estructurada ∈ [0,1] entre dos hallazgos.
///
/// `misma_clase × mismo_host × (0.8·jaccard(segmentos del endpoint) + 0.2·mismo_parámetro)`.
/// Mismo bug en otro host o de otra clase → 0; mismo endpoint con otro
/// parámetro → 0.8 (probable misma causa raíz); otro endpoint de la misma clase
/// y host → < 0.72 salvo que casi toda la ruta coincida.
pub fn similarity(a: (&str, &str, &str, &str), b: (&str, &str, &str, &str)) -> f32 {
    let (va, ha, ea, pa) = a;
    let (vb, hb, eb, pb) = b;
    if normalize_vulnerability(va) != normalize_vulnerability(vb) || normalize_host(ha) != normalize_host(hb) {
        return 0.0;
    }
    let (sa, sb) = (segments(ea), segments(eb));
    let jaccard = if sa.is_empty() && sb.is_empty() {
        1.0
    } else {
        sa.intersection(&sb).count() as f32 / sa.union(&sb).count() as f32
    };
    let param_eq = if normalize_parameter(pa) == normalize_parameter(pb) { 1.0 } else { 0.0 };
    0.8 * jaccard + 0.2 * param_eq
}

// ---------------------------------------------------------------------------
// Persistencia
// ---------------------------------------------------------------------------

/// Crea los índices secundarios de `COL_FINDINGS` (idempotente).
async fn ensure_indexes(db: &HiveDb) -> Result<()> {
    db.create_index(COL_FINDINGS, "program", false).await?;
    db.create_index(COL_FINDINGS, "dedup_key", false).await?;
    Ok(())
}

async fn program_findings(db: &HiveDb, program: &str) -> Result<Vec<Finding>> {
    ensure_indexes(db).await?;
    Ok(db
        .find_by(COL_FINDINGS, "program", serde_json::json!(program))
        .await?
        .into_iter()
        .filter_map(|(_, v)| serde_json::from_value::<Finding>(v).ok())
        .collect())
}

/// Compara un candidato con los hallazgos previos del programa.
pub async fn check(db: &HiveDb, program: &str, input: &FindingInput, threshold: f32) -> Result<Verdict> {
    let key = dedup_key(program, &input.vulnerability, &input.host, &input.endpoint, &input.parameter);
    let existing = program_findings(db, program).await?;
    if let Some(f) = existing.iter().find(|f| f.dedup_key == key) {
        return Ok(Verdict::Duplicate { of: f.id.clone() });
    }
    let cand = (
        input.vulnerability.as_str(),
        input.host.as_str(),
        input.endpoint.as_str(),
        input.parameter.as_str(),
    );
    let best = existing
        .iter()
        .map(|f| {
            (
                f,
                similarity(cand, (&f.vulnerability, &f.host, &f.endpoint, &f.parameter)),
            )
        })
        .max_by(|a, b| a.1.total_cmp(&b.1).then_with(|| b.0.id.cmp(&a.0.id)));
    Ok(match best {
        Some((f, sim)) if sim >= threshold => Verdict::Possible { of: f.id.clone(), similarity: sim },
        _ => Verdict::New,
    })
}

fn projection(f: &Finding) -> KnowledgeDoc {
    let mut body = format!("{} en {}{}", f.vulnerability, f.host, f.endpoint);
    if !f.parameter.is_empty() {
        body.push_str(&format!(" parametro {}", f.parameter));
    }
    if !f.reproduction.is_empty() {
        body.push_str(&format!("\n{}", f.reproduction));
    }
    KnowledgeDoc {
        id: f.id.clone(),
        kind: KnowledgeKind::Finding,
        title: if f.title.is_empty() { format!("{} en {}", f.vulnerability, f.host) } else { f.title.clone() },
        tags: vec![f.vulnerability.clone(), f.host.clone()],
        refs: vec![],
        severity_hint: f.severity.clone(),
        program: Some(f.program.clone()),
        dedup_key: Some(f.dedup_key.clone()),
        body,
    }
}

/// Registra un hallazgo aplicando el gate de deduplicación.
pub async fn record(
    db: &HiveDb,
    program: &str,
    actor: &str,
    input: FindingInput,
    opts: RecordOptions,
) -> Result<Recorded> {
    if program.trim().is_empty() {
        bail!("registrar hallazgos requiere un programa (engagement) activo");
    }
    if input.vulnerability.trim().is_empty() || input.host.trim().is_empty() {
        bail!("vulnerability y host son obligatorios");
    }

    let verdict = check(db, program, &input, opts.threshold).await?;
    if matches!(verdict, Verdict::Duplicate { .. }) {
        return Ok(Recorded { verdict, finding: None });
    }

    let (status, duplicate_of) = match &verdict {
        Verdict::Possible { of, .. } => (FindingStatus::PossibleDuplicate, Some(of.clone())),
        _ if input.reproduction.trim().is_empty() => (FindingStatus::Draft, None),
        _ if opts.autonomous_submission_allowed => (FindingStatus::Ready, None),
        _ => (FindingStatus::NeedsHumanReview, None),
    };

    let finding = Finding {
        id: uuid::Uuid::new_v4().to_string(),
        program: program.to_string(),
        vulnerability: normalize_vulnerability(&input.vulnerability),
        title: input.title,
        host: normalize_host(&input.host),
        endpoint: normalize_endpoint(&input.endpoint),
        parameter: normalize_parameter(&input.parameter),
        severity: input.severity,
        cvss: input.cvss,
        dedup_key: dedup_key(program, &input.vulnerability, &input.host, &input.endpoint, &input.parameter),
        status,
        evidence: input.evidence,
        reproduction: input.reproduction,
        ai_assisted: opts.ai_assisted,
        created_at: chrono::Utc::now().to_rfc3339(),
        created_by: actor.to_string(),
        duplicate_of,
    };
    db.insert(COL_FINDINGS, &finding.id, serde_json::to_value(&finding)?).await?;
    ingest(db, &[projection(&finding)]).await?;
    Ok(Recorded { verdict, finding: Some(finding) })
}

/// Revisión humana: cambia el estado de un hallazgo. Devuelve el hallazgo
/// actualizado o `None` si no existe.
pub async fn set_status(db: &HiveDb, id: &str, status: FindingStatus) -> Result<Option<Finding>> {
    let Some(v) = db.get(COL_FINDINGS, id).await else { return Ok(None) };
    let mut f: Finding = serde_json::from_value(v)?;
    f.status = status;
    db.insert(COL_FINDINGS, id, serde_json::to_value(&f)?).await?;
    Ok(Some(f))
}

/// Todos los hallazgos del programa, más antiguos primero.
pub async fn list(db: &HiveDb, program: &str) -> Result<Vec<Finding>> {
    let mut all = program_findings(db, program).await?;
    all.sort_by(|a, b| a.created_at.cmp(&b.created_at).then_with(|| a.id.cmp(&b.id)));
    Ok(all)
}

/// Lo que el redactor puede incluir en un informe, y cuántos quedan retenidos
/// (borradores y posibles duplicados) a la espera de revisión humana.
pub async fn reportable(db: &HiveDb, program: &str) -> Result<(Vec<Finding>, usize)> {
    let all = list(db, program).await?;
    let held = all.iter().filter(|f| matches!(f.status, FindingStatus::Draft | FindingStatus::PossibleDuplicate)).count();
    Ok((all.into_iter().filter(|f| f.status.is_reportable()).collect(), held))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(v: &str, host: &str, ep: &str, param: &str, repro: &str) -> FindingInput {
        FindingInput {
            vulnerability: v.into(),
            host: host.into(),
            endpoint: ep.into(),
            parameter: param.into(),
            title: format!("{v} {ep}"),
            reproduction: repro.into(),
            ..Default::default()
        }
    }

    async fn db() -> (HiveDb, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("hc_fd_{}", uuid::Uuid::new_v4()));
        (HiveDb::open(&dir).await.unwrap(), dir)
    }

    #[test]
    fn normalizes_endpoints_and_classes() {
        assert_eq!(normalize_endpoint("https://API.acme.com/Api/Orders/123/?x=1#f"), "/api/orders/{id}");
        assert_eq!(normalize_endpoint("/api/orders/550e8400-e29b-41d4-a716-446655440000/"), "/api/orders/{id}");
        assert_eq!(normalize_endpoint(""), "/");
        assert_eq!(normalize_vulnerability("BOLA"), "idor");
        assert_eq!(normalize_vulnerability("Broken Object Level Authorization"), "idor");
        assert_eq!(normalize_vulnerability("Server-Side Request Forgery"), "ssrf");
        assert_eq!(normalize_vulnerability("Stored XSS"), "stored-xss");
    }

    #[test]
    fn dedup_key_is_stable_across_cosmetic_differences() {
        let a = dedup_key("acme", "IDOR", "API.acme.com", "/api/orders/123?x=1", "Order_ID");
        let b = dedup_key("acme", "bola", "api.acme.com", "https://api.acme.com/api/orders/999/", "order_id");
        assert_eq!(a, b);
        assert_ne!(a, dedup_key("acme", "idor", "api.acme.com", "/api/users/1", "order_id"));
        assert_ne!(a, dedup_key("other", "idor", "api.acme.com", "/api/orders/1", "order_id"));
        assert_eq!(a.len(), 24);
    }

    #[test]
    fn similarity_is_bounded_and_interpretable() {
        let base = ("idor", "api.acme.com", "/api/orders/1", "id");
        assert_eq!(similarity(base, ("idor", "api.acme.com", "/api/orders/2", "id")), 1.0);
        // mismo endpoint, otro parametro: probable misma causa raiz
        assert!((similarity(base, ("idor", "api.acme.com", "/api/orders/1", "uid")) - 0.8).abs() < 1e-6);
        // otro endpoint de la misma clase/host: distinto hallazgo
        assert!(similarity(base, ("idor", "api.acme.com", "/api/users/1", "id")) < 0.72);
        // otra clase o host: nada que ver
        assert_eq!(similarity(base, ("ssrf", "api.acme.com", "/api/orders/1", "id")), 0.0);
        assert_eq!(similarity(base, ("idor", "www.acme.com", "/api/orders/1", "id")), 0.0);
    }

    #[tokio::test]
    async fn record_applies_the_dedup_gate() {
        let (db, dir) = db().await;
        let o = RecordOptions::default();

        let first = record(&db, "acme", "web_pentester", input("idor", "api.acme.com", "/api/orders/1", "id", "GET /api/orders/2 con token de A"), o).await.unwrap();
        assert_eq!(first.verdict, Verdict::New);
        let first = first.finding.unwrap();
        assert_eq!(first.status, FindingStatus::NeedsHumanReview, "sin envio autonomo se detiene para revision");

        // Duplicado exacto (cosmetica distinta): no se guarda.
        let exact = record(&db, "acme", "vuln_scanner", input("BOLA", "API.acme.com", "/api/orders/77?z=1", "ID", "x"), o).await.unwrap();
        assert_eq!(exact.verdict, Verdict::Duplicate { of: first.id.clone() });
        assert!(exact.finding.is_none());
        assert_eq!(list(&db, "acme").await.unwrap().len(), 1);

        // Mismo endpoint, otro parametro: posible duplicado, retenido.
        let poss = record(&db, "acme", "web_pentester", input("idor", "api.acme.com", "/api/orders/1", "uid", "repro"), o).await.unwrap();
        assert!(matches!(poss.verdict, Verdict::Possible { ref of, .. } if *of == first.id));
        let poss = poss.finding.unwrap();
        assert_eq!(poss.status, FindingStatus::PossibleDuplicate);
        assert_eq!(poss.duplicate_of.as_deref(), Some(first.id.as_str()));

        // Otro endpoint: nuevo. Sin reproduccion: borrador.
        let draft = record(&db, "acme", "web_pentester", input("idor", "api.acme.com", "/api/users/1", "id", ""), o).await.unwrap();
        assert_eq!(draft.verdict, Verdict::New);
        assert_eq!(draft.finding.unwrap().status, FindingStatus::Draft);

        // Reportable: solo el primero; retenidos: posible duplicado + borrador.
        let (rep, held) = reportable(&db, "acme").await.unwrap();
        assert_eq!(rep.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(), [first.id.as_str()]);
        assert_eq!(held, 2);

        // Otro programa no comparte historial.
        let other = record(&db, "otro", "w", input("idor", "api.acme.com", "/api/orders/1", "id", "r"), o).await.unwrap();
        assert_eq!(other.verdict, Verdict::New);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn autonomous_programs_mark_reproduced_findings_ready() {
        let (db, dir) = db().await;
        let o = RecordOptions { autonomous_submission_allowed: true, ..Default::default() };
        let r = record(&db, "acme", "w", input("ssrf", "api.acme.com", "/fetch", "url", "repro"), o).await.unwrap();
        assert_eq!(r.finding.unwrap().status, FindingStatus::Ready);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn rejects_missing_program_and_fields() {
        let (db, dir) = db().await;
        let o = RecordOptions::default();
        assert!(record(&db, "", "w", input("idor", "h", "/", "", ""), o).await.is_err());
        assert!(record(&db, "acme", "w", input("", "h", "/", "", ""), o).await.is_err());
        assert!(record(&db, "acme", "w", input("idor", " ", "/", "", ""), o).await.is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn findings_are_searchable_in_the_brain_and_status_is_reviewable() {
        let (db, dir) = db().await;
        let o = RecordOptions::default();
        let f = record(&db, "acme", "w", input("idor", "api.acme.com", "/api/orders/1", "id", "repro"), o).await.unwrap().finding.unwrap();

        let hits = crate::knowledge::search(&db, Some(KnowledgeKind::Finding), Some("acme"), "idor orders", 3).await.unwrap();
        assert_eq!(hits.first().map(|h| h.doc.id.as_str()), Some(f.id.as_str()));
        assert!(crate::knowledge::search(&db, Some(KnowledgeKind::Finding), Some("otro"), "idor orders", 3).await.unwrap().is_empty());

        let upd = set_status(&db, &f.id, FindingStatus::Rejected).await.unwrap().unwrap();
        assert_eq!(upd.status, FindingStatus::Rejected);
        assert!(set_status(&db, "nope", FindingStatus::Ready).await.unwrap().is_none());
        assert!(FindingStatus::parse("ready").is_ok() && FindingStatus::parse("x").is_err());
        // Un rechazado sigue contando como duplicado si se vuelve a encontrar.
        let again = record(&db, "acme", "w", input("idor", "api.acme.com", "/api/orders/9", "id", "repro"), o).await.unwrap();
        assert_eq!(again.verdict, Verdict::Duplicate { of: f.id });
        std::fs::remove_dir_all(&dir).ok();
    }
}
