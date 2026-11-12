//! Pipeline de hallazgos: ingesta tipada → dedup → revisión humana.
//!
//! Invariantes de seguridad:
//!  * Un hallazgo SOLO puede entrar como `draft`, `needs_human_review` o
//!    `possible_duplicate`. Nunca `ready`/`submitted` desde un agente.
//!  * Pasar a `ready`/`submitted`/`accepted`… exige `human_review`
//!    (comando CLI `findings review`), no una tool del agente.
//!  * El host del hallazgo debe estar en el scope de la política (si hay).
//!  * Reproducción y evidencia se persisten con secretos redactados.

use anyhow::{anyhow, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::OnceLock;

use crate::store::collections::COL_FINDINGS;
use crate::store::HiveDb;
use hivecyber_tools::EngagementPolicy;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
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
    pub fn parse(s: &str) -> Option<Self> {
        serde_json::from_value(Value::String(s.trim().to_lowercase())).ok()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub cvss: Option<String>,
    pub dedup_key: String,
    pub status: FindingStatus,
    #[serde(default)]
    pub evidence: Vec<Value>,
    #[serde(default)]
    pub reproduction: String,
    pub ai_assisted: bool,
    pub created_at: String,
    #[serde(default)]
    pub created_by: String,
    #[serde(default)]
    pub duplicate_of: Option<String>,
    #[serde(default)]
    pub similarity: Option<f64>,
    #[serde(default)]
    pub review_note: Option<String>,
}

// ───────────────────────── normalización / dedup ─────────────────────────

pub fn normalize_vulnerability(v: &str) -> String {
    v.trim()
        .to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

/// Path normalizado: sin query/fragment, minúsculas, ids numéricos/uuid/hex
/// largos → `{id}` (así `/users/12` y `/users/99` deduplican como el mismo bug).
pub fn normalize_endpoint(e: &str) -> String {
    let mut s = e.trim().to_lowercase();
    if let Some(rest) = s.strip_prefix("https://").or_else(|| s.strip_prefix("http://")) {
        s = rest.split_once('/').map(|(_, p)| format!("/{}", p)).unwrap_or_default();
    }
    for sep in ['?', '#'] {
        if let Some(i) = s.find(sep) {
            s.truncate(i);
        }
    }
    let segs: Vec<String> = s
        .split('/')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let numeric = p.chars().all(|c| c.is_ascii_digit());
            let hexy = p.len() >= 16 && p.chars().all(|c| c.is_ascii_hexdigit() || c == '-');
            if numeric || hexy { "{id}".to_string() } else { p.to_string() }
        })
        .collect();
    format!("/{}", segs.join("/"))
}

pub fn dedup_key(vulnerability: &str, host: &str, endpoint: &str, parameter: &str) -> String {
    let raw = format!(
        "{}|{}|{}|{}",
        normalize_vulnerability(vulnerability),
        hivecyber_tools::engagement::normalize_host(host),
        normalize_endpoint(endpoint),
        parameter.trim().to_lowercase()
    );
    let digest = Sha256::digest(raw.as_bytes());
    digest.iter().take(8).map(|b| format!("{:02x}", b)).collect()
}

fn tokens(f: &Finding) -> HashSet<String> {
    let mut t: HashSet<String> = HashSet::new();
    t.insert(format!("v:{}", normalize_vulnerability(&f.vulnerability)));
    t.insert(format!("h:{}", hivecyber_tools::engagement::normalize_host(&f.host)));
    for seg in normalize_endpoint(&f.endpoint).split('/').filter(|s| !s.is_empty()) {
        t.insert(format!("p:{}", seg));
    }
    if !f.parameter.trim().is_empty() {
        t.insert(format!("q:{}", f.parameter.trim().to_lowercase()));
    }
    t
}

/// Similitud de Jaccard entre dos hallazgos (0.0–1.0).
pub fn similarity(a: &Finding, b: &Finding) -> f64 {
    let (ta, tb) = (tokens(a), tokens(b));
    let inter = ta.intersection(&tb).count() as f64;
    let union = ta.union(&tb).count() as f64;
    if union == 0.0 { 0.0 } else { inter / union }
}

// ───────────────────────────── redacción ─────────────────────────────────

fn secret_patterns() -> &'static Vec<(Regex, &'static str)> {
    static P: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    P.get_or_init(|| {
        let defs: &[(&str, &str)] = &[
            (r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{12,}", "$1 [REDACTED]"),
            (r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", "[REDACTED_JWT]"),
            (r"\bAKIA[0-9A-Z]{16}\b", "[REDACTED_AWS_KEY]"),
            (r"\b(?:sk|pk|rk)-[A-Za-z0-9_-]{16,}", "[REDACTED_API_KEY]"),
            (r"\bgh[pousr]_[A-Za-z0-9]{20,}", "[REDACTED_GH_TOKEN]"),
            (r"\bxox[baprs]-[A-Za-z0-9-]{10,}", "[REDACTED_SLACK_TOKEN]"),
            (
                r#"(?i)\b(password|passwd|pwd|secret|api[_-]?key|token|authorization|cookie|set-cookie)\b(\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s,;&]+)"#,
                "$1$2[REDACTED]",
            ),
        ];
        defs.iter().map(|(p, r)| (Regex::new(p).expect("regex"), *r)).collect()
    })
}

pub fn redact_secrets(text: &str) -> String {
    let mut out = text.to_string();
    for (re, rep) in secret_patterns() {
        out = re.replace_all(&out, *rep).into_owned();
    }
    out
}

fn redact_value(v: &Value) -> Value {
    match v {
        Value::String(s) => Value::String(redact_secrets(s)),
        Value::Array(a) => Value::Array(a.iter().map(redact_value).collect()),
        Value::Object(o) => Value::Object(o.iter().map(|(k, v)| (k.clone(), redact_value(v))).collect()),
        other => other.clone(),
    }
}

// ───────────────────────────── ingesta ───────────────────────────────────

#[derive(Debug, Clone, Default, Deserialize)]
pub struct NewFinding {
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
    pub evidence: Vec<Value>,
}

const SEVERITIES: &[&str] = &["info", "low", "medium", "high", "critical"];

/// Ingresa un hallazgo. Devuelve el `Finding` persistido (nunca `ready`).
pub async fn ingest(
    db: &HiveDb,
    policy: Option<&EngagementPolicy>,
    created_by: &str,
    input: NewFinding,
) -> Result<Finding> {
    if input.vulnerability.trim().is_empty() || input.host.trim().is_empty() {
        return Err(anyhow!("vulnerability y host son obligatorios"));
    }
    if let Some(sev) = &input.severity {
        if !SEVERITIES.contains(&sev.to_lowercase().as_str()) {
            return Err(anyhow!("severity inválida '{}' (usa {:?})", sev, SEVERITIES));
        }
    }
    let (program, threshold) = match policy {
        Some(p) => {
            let out = p.target_allowed(&input.host);
            if out.excluded || out.rule.is_none() {
                return Err(anyhow!(
                    "el host '{}' está fuera del scope del programa '{}': no se registra el hallazgo",
                    input.host, p.program
                ));
            }
            (p.program.clone(), p.knowledge.dedup_threshold as f64)
        }
        None => ("unscoped".to_string(), 0.72),
    };

    let mut f = Finding {
        id: uuid::Uuid::new_v4().to_string(),
        program: program.clone(),
        vulnerability: normalize_vulnerability(&input.vulnerability),
        title: redact_secrets(&input.title),
        host: hivecyber_tools::engagement::normalize_host(&input.host),
        endpoint: normalize_endpoint(&input.endpoint),
        parameter: input.parameter.trim().to_lowercase(),
        severity: input.severity.map(|s| s.to_lowercase()),
        cvss: input.cvss,
        dedup_key: String::new(),
        status: FindingStatus::NeedsHumanReview,
        evidence: input.evidence.iter().map(redact_value).collect(),
        reproduction: redact_secrets(&input.reproduction),
        ai_assisted: true,
        created_at: chrono::Utc::now().to_rfc3339(),
        created_by: created_by.to_string(),
        duplicate_of: None,
        similarity: None,
        review_note: None,
    };
    f.dedup_key = dedup_key(&f.vulnerability, &f.host, &f.endpoint, &f.parameter);

    // Gate de dedup contra hallazgos previos del mismo programa.
    let mut best: Option<(String, f64)> = None;
    for (id, doc) in db.list(COL_FINDINGS).await {
        let Ok(prev) = serde_json::from_value::<Finding>(doc) else { continue };
        if prev.program != program || prev.status == FindingStatus::Rejected {
            continue;
        }
        let sim = if prev.dedup_key == f.dedup_key { 1.0 } else { similarity(&f, &prev) };
        if sim >= threshold && best.as_ref().map_or(true, |(_, s)| sim > *s) {
            best = Some((id, sim));
        }
    }
    if let Some((id, sim)) = best {
        f.status = FindingStatus::PossibleDuplicate;
        f.duplicate_of = Some(id);
        f.similarity = Some((sim * 100.0).round() / 100.0);
    } else if f.reproduction.trim().is_empty() {
        // El gate exige pasos reproducibles antes de revisión humana.
        f.status = FindingStatus::Draft;
    }

    db.insert(COL_FINDINGS, &f.id, serde_json::to_value(&f)?).await?;
    Ok(f)
}

/// Transición manual (solo desde el CLI, nunca desde una tool de agente).
pub async fn human_review(
    db: &HiveDb,
    id: &str,
    to: FindingStatus,
    note: Option<String>,
) -> Result<Finding> {
    let doc = db.get(COL_FINDINGS, id).await.ok_or_else(|| anyhow!("finding '{}' no existe", id))?;
    let mut f: Finding = serde_json::from_value(doc)?;
    if matches!(to, FindingStatus::Ready | FindingStatus::Submitted | FindingStatus::Accepted)
        && f.reproduction.trim().is_empty()
    {
        return Err(anyhow!("no puede pasar a '{:?}': faltan pasos de reproducción", to));
    }
    if to == FindingStatus::Ready && f.status == FindingStatus::Draft {
        return Err(anyhow!("un borrador sin reproducción no puede pasar a ready"));
    }
    f.status = to;
    f.review_note = note;
    db.insert(COL_FINDINGS, &f.id, serde_json::to_value(&f)?).await?;
    Ok(f)
}

// ─────────────────────────── reporte Markdown ───────────────────────────

fn status_label(s: FindingStatus) -> String {
    serde_json::to_value(s)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_default()
}

/// Reporte Markdown listo para pegar en Bugcrowd/HackerOne. Los campos ya se
/// guardaron redactados. Si la política exige divulgación de IA
/// (`ai_policy.disclosure_required`) se añade la declaración. Un hallazgo que
/// aún no pasó revisión humana (`ready` o posterior) sale marcado BORRADOR.
pub fn render_report(f: &Finding, ai_disclosure: bool) -> String {
    let reviewed = matches!(
        f.status,
        FindingStatus::Ready | FindingStatus::Submitted | FindingStatus::Accepted
    );
    let mut r = String::new();
    if !reviewed {
        r.push_str(&format!(
            "> ⚠️ **BORRADOR — no revisado por un humano** (estado: `{}`). No enviar.\n\n",
            status_label(f.status)
        ));
    }
    let title = if f.title.trim().is_empty() {
        format!("{} en {}{}", f.vulnerability, f.host, f.endpoint)
    } else {
        f.title.clone()
    };
    r.push_str(&format!("# {}\n\n", title));
    r.push_str("## Resumen\n\n");
    r.push_str(&format!("- **Programa:** {}\n", f.program));
    r.push_str(&format!("- **Clase:** {}\n", f.vulnerability));
    r.push_str(&format!("- **Activo afectado:** `{}{}`\n", f.host, f.endpoint));
    if !f.parameter.is_empty() {
        r.push_str(&format!("- **Parámetro:** `{}`\n", f.parameter));
    }
    r.push_str(&format!(
        "- **Severidad:** {}\n",
        f.severity.as_deref().unwrap_or("sin clasificar")
    ));
    if let Some(c) = &f.cvss {
        r.push_str(&format!("- **CVSS:** `{}`\n", c));
    }
    if f.status == FindingStatus::PossibleDuplicate {
        r.push_str(&format!(
            "- **Posible duplicado de:** `{}` (similitud {:.2})\n",
            f.duplicate_of.as_deref().unwrap_or("?"),
            f.similarity.unwrap_or(0.0)
        ));
    }
    r.push_str("\n## Pasos para reproducir\n\n");
    if f.reproduction.trim().is_empty() {
        r.push_str("_Faltan pasos de reproducción: el hallazgo no es reportable todavía._\n");
    } else {
        r.push_str(f.reproduction.trim());
        r.push('\n');
    }
    if !f.evidence.is_empty() {
        r.push_str("\n## Evidencia\n\n");
        for e in &f.evidence {
            let line = match e {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            r.push_str(&format!("- {}\n", line));
        }
    }
    if let Some(n) = &f.review_note {
        r.push_str(&format!("\n## Nota del revisor\n\n{}\n", n));
    }
    if ai_disclosure {
        r.push_str(
            "\n## Divulgación de IA\n\nEste hallazgo fue identificado con asistencia de un agente de IA \
             (hiveCyber) y revisado manualmente por el investigador antes de enviarse.\n",
        );
    }
    r
}

// ─────────────── backend de la tool `finding_submit` ───────────────

pub struct FindingsBackend {
    pub db: HiveDb,
    pub policy: Option<std::sync::Arc<EngagementPolicy>>,
    pub created_by: String,
}

#[async_trait::async_trait]
impl hivecyber_tools::findings::FindingsBackend for FindingsBackend {
    async fn submit(&self, input: Value) -> Result<Value> {
        let nf: NewFinding = serde_json::from_value(input)?;
        let f = ingest(&self.db, self.policy.as_deref(), &self.created_by, nf).await?;
        Ok(serde_json::json!({
            "id": f.id,
            "status": f.status,
            "dedup_key": f.dedup_key,
            "duplicate_of": f.duplicate_of,
            "similarity": f.similarity,
            "next": "un humano debe revisarlo con `hivecyber findings review`; no se envía automáticamente",
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_ids_collapse_and_query_dropped() {
        assert_eq!(normalize_endpoint("https://a.com/Api/Users/123?x=1"), "/api/users/{id}");
        assert_eq!(normalize_endpoint("/api/users/99/"), "/api/users/{id}");
        assert_eq!(
            normalize_endpoint("/o/3f2b8c1a-9d4e-4f6a-8b2c-1a2b3c4d5e6f"),
            "/o/{id}"
        );
    }

    #[test]
    fn same_bug_same_key_regardless_of_id_and_case() {
        let a = dedup_key("IDOR", "API.acme.com", "/api/users/12", "id");
        let b = dedup_key("idor", "api.acme.com:443", "https://api.acme.com/api/users/99?z=1", "ID");
        assert_eq!(a, b);
        assert_ne!(a, dedup_key("idor", "api.acme.com", "/api/orders/12", "id"));
    }

    #[test]
    fn redacts_common_secrets() {
        let t = "Authorization: Bearer abcdefghijklmnop1234 password=hunter2 key AKIAABCDEFGHIJKLMNOP \
                 jwt eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.SflKxwRJSMeKKF2QT4 tok ghp_abcdefghijklmnopqrstuv";
        let r = redact_secrets(t);
        for leak in ["abcdefghijklmnop1234", "hunter2", "AKIAABCDEFGHIJKLMNOP", "SflKxwRJSMeKKF2QT4", "ghp_abcdefghij"] {
            assert!(!r.contains(leak), "filtró {leak}: {r}");
        }
        assert!(r.contains("[REDACTED"));
    }

    #[test]
    fn report_marks_unreviewed_draft_and_adds_disclosure() {
        let mut f = Finding {
            id: "1".into(), program: "acme".into(), vulnerability: "idor".into(),
            title: String::new(), host: "api.acme.com".into(), endpoint: "/api/users/{id}".into(),
            parameter: "id".into(), severity: Some("high".into()), cvss: None,
            dedup_key: "k".into(), status: FindingStatus::NeedsHumanReview,
            evidence: vec![serde_json::json!("GET /api/users/2 -> 200")],
            reproduction: "1. login como A\n2. pide /api/users/2".into(), ai_assisted: true,
            created_at: "t".into(), created_by: "w".into(), duplicate_of: None,
            similarity: None, review_note: None,
        };
        let r = render_report(&f, true);
        assert!(r.contains("BORRADOR"));
        assert!(r.contains("Divulgación de IA"));
        assert!(r.contains("idor en api.acme.com/api/users/{id}"));
        f.status = FindingStatus::Ready;
        let r = render_report(&f, false);
        assert!(!r.contains("BORRADOR") && !r.contains("Divulgación"));
        assert!(r.contains("GET /api/users/2 -> 200"));
    }

    #[test]
    fn status_parse_and_snake_case() {
        assert_eq!(FindingStatus::parse("needs_human_review"), Some(FindingStatus::NeedsHumanReview));
        assert_eq!(FindingStatus::parse("READY"), Some(FindingStatus::Ready));
        assert_eq!(FindingStatus::parse("nope"), None);
    }

    fn policy() -> EngagementPolicy {
        use hivecyber_tools::TargetRule;
        EngagementPolicy {
            program: "acme".into(),
            targets: vec![TargetRule { host: "*.acme.com".into(), ..Default::default() }],
            ..Default::default()
        }
    }

    fn nf(endpoint: &str, repro: &str) -> NewFinding {
        NewFinding {
            vulnerability: "IDOR".into(),
            host: "api.acme.com".into(),
            endpoint: endpoint.into(),
            parameter: "id".into(),
            severity: Some("high".into()),
            reproduction: repro.into(),
            ..Default::default()
        }
    }

    async fn tmp_db() -> HiveDb {
        let dir = std::env::temp_dir().join(format!("hc-findings-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        HiveDb::open(&dir).await.unwrap()
    }

    #[tokio::test]
    async fn pipeline_never_auto_ready_and_dedups() {
        let db = tmp_db().await;
        let p = policy();

        let a = ingest(&db, Some(&p), "w1", nf("/api/users/1", "curl -H 'Authorization: Bearer abcdefghijklmnop1234' …")).await.unwrap();
        assert_eq!(a.status, FindingStatus::NeedsHumanReview);
        assert!(!a.reproduction.contains("abcdefghijklmnop1234"));

        // Mismo bug con otro id → posible duplicado del primero.
        let b = ingest(&db, Some(&p), "w2", nf("/api/users/2", "otra repro")).await.unwrap();
        assert_eq!(b.status, FindingStatus::PossibleDuplicate);
        assert_eq!(b.duplicate_of.as_deref(), Some(a.id.as_str()));

        // Sin reproducción → draft, y no puede pasar a ready.
        let c = ingest(&db, Some(&p), "w3", NewFinding { vulnerability: "ssrf".into(), ..nf("/fetch", "") }).await.unwrap();
        assert_eq!(c.status, FindingStatus::Draft);
        assert!(human_review(&db, &c.id, FindingStatus::Ready, None).await.is_err());

        // Revisión humana sí puede marcar ready.
        let r = human_review(&db, &a.id, FindingStatus::Ready, Some("ok".into())).await.unwrap();
        assert_eq!(r.status, FindingStatus::Ready);
    }

    #[tokio::test]
    async fn out_of_scope_finding_is_refused() {
        let db = tmp_db().await;
        let p = policy();
        let mut bad = nf("/x", "r");
        bad.host = "evil.example.org".into();
        assert!(ingest(&db, Some(&p), "w", bad).await.is_err());
        assert_eq!(db.count(COL_FINDINGS).await, 0);
    }
}
