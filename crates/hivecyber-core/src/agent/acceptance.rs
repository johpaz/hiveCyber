use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcceptanceCheckResult {
    pub criterion_id: String,
    pub check: String,
    pub met: Option<bool>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CheckStatus {
    Passed,
    Failed,
    Pending,
    Unchecked,
}

pub fn run_acceptance_checks(
    objective: &str,
    acceptance: &[crate::store::collections::AcceptanceCriterion],
    delivery: &str,
    evidence: &[String],
) -> Vec<AcceptanceCheckResult> {
    let mut results = Vec::new();

    if delivery.is_empty() {
        results.push(AcceptanceCheckResult {
            criterion_id: "delivery_gate".into(),
            check: "delivery_gate".into(),
            met: Some(false),
            detail: "Entrega vacia".into(),
        });
        return results;
    }

    let self_declared_failure = delivery.contains("status: failed")
        || delivery.contains("\"status\":\"failed\"");

    if self_declared_failure {
        results.push(AcceptanceCheckResult {
            criterion_id: "self_declared".into(),
            check: "delivery_gate".into(),
            met: Some(false),
            detail: "Worker declaro status: failed".into(),
        });
    }

    for criterion in acceptance {
        if let Some(ref check_tool) = criterion.check_tool {
            let met = verify_check_tool(check_tool, objective, delivery, evidence);
            let detail = describe_check_result(check_tool, met);
            results.push(AcceptanceCheckResult {
                criterion_id: criterion.id.clone(),
                check: check_tool.clone(),
                met,
                detail,
            });
        } else {
            results.push(AcceptanceCheckResult {
                criterion_id: criterion.id.clone(),
                check: "none".into(),
                met: None,
                detail: format!(
                    "Criterio '{}' requiere juicio del coordinador (sin check_tool)",
                    criterion.description
                ),
            });
        }
    }

    for ev in evidence {
        if ev.contains("artifact_id:") {
            results.push(AcceptanceCheckResult {
                criterion_id: "artifact".into(),
                check: "artifact_inspect".into(),
                met: None,
                detail: "Artifact inspection pendiente".into(),
            });
        }
    }

    results
}

pub fn verdict(results: &[AcceptanceCheckResult]) -> CheckStatus {
    if results.is_empty() {
        return CheckStatus::Unchecked;
    }
    if results.iter().any(|r| r.met == Some(false)) {
        return CheckStatus::Failed;
    }
    if results.iter().any(|r| r.met.is_none()) {
        return CheckStatus::Pending;
    }
    if results.iter().any(|r| r.met == Some(true)) {
        return CheckStatus::Passed;
    }
    CheckStatus::Unchecked
}

fn describe_check_result(check_tool: &str, met: Option<bool>) -> String {
    match met {
        Some(true) => format!("Verificador '{}' satisfecho", check_tool),
        Some(false) => format!("Verificador '{}' NO satisfecho (evidencia insuficiente)", check_tool),
        None => format!(
            "Verificador '{}' desconocido: requiere juicio del coordinador",
            check_tool
        ),
    }
}

pub fn verify_check_tool(
    check_tool: &str,
    _objective: &str,
    delivery: &str,
    evidence: &[String],
) -> Option<bool> {
    // Acceptance now runs over a typed evidence model rather than regex over free
    // text. `parse_evidence` accepts explicit typed items (a tool/worker can push
    // `{"type":"vulnerability","id":"CVE-…","severity":"high"}`) and, for legacy
    // `"<tool>: <text>"` lines, derives typed items so existing deliveries keep
    // working. Verifiers assert on the structured facts.
    let items = parse_evidence(evidence);
    match check_tool {
        "recon_coverage" => Some(v_recon_coverage(&items)),
        "vuln_findings" => Some(v_vuln_findings(&items)),
        "exploit_proof" => Some(v_exploit_proof(&items)),
        "forensics_evidence" => Some(v_forensics_evidence(&items)),
        "web_exploit_reproducible" => Some(v_web_exploit_reproducible(&items)),
        "intel_correlation" => Some(v_intel_correlation(&items)),
        "report_complete" => Some(v_report_complete(delivery, &items)),
        "readback" => Some(v_readback(&items)),
        _ => None,
    }
}

/// Typed acceptance evidence. Either emitted explicitly by a tool/worker (as a
/// JSON object with a `type` tag) or derived from a legacy `"<tool>: <text>"`
/// evidence line by `parse_evidence`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EvidenceItem {
    /// A tool was executed (against an optional target).
    ToolRun { tool: String, #[serde(default)] target: Option<String> },
    /// A discovered host / IP.
    Host { value: String },
    /// A vulnerability finding.
    Vulnerability {
        #[serde(default)] id: Option<String>,
        #[serde(default)] severity: Option<String>,
        #[serde(default)] title: Option<String>,
    },
    /// Proof of exploitation: an interactive session or captured credential.
    ShellSession { #[serde(default)] kind: Option<String> },
    Credential { #[serde(default)] kind: Option<String> },
    /// A forensic artifact with chain-of-custody (hash + acquisition time).
    Artifact {
        #[serde(default)] hash: Option<String>,
        #[serde(default)] acquired_at: Option<String>,
        #[serde(default)] path: Option<String>,
    },
    /// An intel correlation citing independent sources.
    Correlation { #[serde(default)] indicator: Option<String>, #[serde(default)] sources: Vec<String> },
    /// A written report file.
    ReportFile { path: String, #[serde(default)] sections: Vec<String> },
    /// A reproduction count for a PoC.
    Reproduction { count: u32 },
    Note { text: String },
}

/// Build the typed evidence set from raw evidence lines: explicit typed JSON
/// items pass through; legacy `"<tool>: <text>"` lines yield a `ToolRun` plus any
/// facts derivable from their text.
pub fn parse_evidence(raw: &[String]) -> Vec<EvidenceItem> {
    let mut items = Vec::new();
    for line in raw {
        let trimmed = line.trim();
        if trimmed.starts_with('{') {
            if let Ok(item) = serde_json::from_str::<EvidenceItem>(trimmed) {
                items.push(item);
                continue;
            }
        }
        let (tool, payload) = match line.split_once(':') {
            Some((t, p)) if !t.trim().is_empty() && !t.contains(char::is_whitespace) => {
                (t.trim().to_string(), p.trim().to_string())
            }
            _ => (String::new(), line.clone()),
        };
        if !tool.is_empty() {
            items.push(EvidenceItem::ToolRun { tool: tool.to_lowercase(), target: None });
        }
        derive_from_text(&payload, &mut items);
    }
    items
}

fn first_match(text: &str, pattern: &str) -> Option<String> {
    regex::Regex::new(pattern)
        .ok()
        .and_then(|re| re.find(text).map(|m| m.as_str().to_string()))
}

/// Derive typed facts from a free-text evidence payload (legacy path).
fn derive_from_text(payload: &str, items: &mut Vec<EvidenceItem>) {
    let lower = payload.to_lowercase();

    // Host / IP.
    if let Some(ip) = first_match(payload, r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b") {
        items.push(EvidenceItem::Host { value: ip });
    } else if let Some(host) = first_match(&lower, r"\b[a-z0-9-]+\.[a-z0-9-]+\.[a-z]{2,}\b") {
        items.push(EvidenceItem::Host { value: host });
    }

    // Vulnerability id or severity.
    let vuln_id = first_match(payload, r"\bCVE-\d{4}-\d{4,7}\b")
        .or_else(|| first_match(payload, r"\bEID-\d+\b"))
        .or_else(|| first_match(payload, r"\bEXPDB-\d+\b"));
    let severity = ["critical", "high", "medium", "low"]
        .iter()
        .find(|s| lower.contains(*s) && (lower.contains("severity") || lower.contains("risk") || vuln_id.is_some()))
        .map(|s| s.to_string());
    if vuln_id.is_some() || severity.is_some() {
        items.push(EvidenceItem::Vulnerability { id: vuln_id, severity, title: None });
    }

    // Exploit proof markers.
    let session_markers = ["meterpreter", "command shell", "session opened", "session 1 opened", "shell session", "pwned", "proof file"];
    if session_markers.iter().any(|m| lower.contains(m)) {
        items.push(EvidenceItem::ShellSession { kind: None });
    }
    let cred_markers = ["dumped password hashes", "ntlm hash", "nt hash", "credential captured", "credentials"];
    if cred_markers.iter().any(|m| lower.contains(m)) {
        items.push(EvidenceItem::Credential { kind: None });
    }

    // Forensic artifact: sha256 + acquisition timestamp.
    let hash = first_match(payload, r"\b[0-9a-fA-F]{64}\b");
    let ts = first_match(payload, r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}");
    if hash.is_some() && ts.is_some() {
        items.push(EvidenceItem::Artifact { hash, acquired_at: ts, path: None });
    }

    // Report file extension.
    if let Some(path) = first_match(&lower, r"[\w./-]+\.(md|html|pdf|docx|txt|odt)\b") {
        items.push(EvidenceItem::ReportFile { path, sections: Vec::new() });
    }

    // Reproduction markers.
    let repro: usize = ["poc", "reproduc", "run 2", "second run", "2x"]
        .iter()
        .map(|m| lower.matches(m).count())
        .sum();
    if repro > 0 {
        items.push(EvidenceItem::Reproduction { count: repro as u32 });
    }
}

fn tool_runs<'a>(items: &'a [EvidenceItem]) -> impl Iterator<Item = &'a str> {
    items.iter().filter_map(|i| match i {
        EvidenceItem::ToolRun { tool, .. } => Some(tool.as_str()),
        _ => None,
    })
}

fn count_tool_runs(items: &[EvidenceItem], allowed: &[&str]) -> usize {
    tool_runs(items).filter(|t| allowed.contains(t)).count()
}

fn distinct_tool_runs(items: &[EvidenceItem], allowed: &[&str]) -> usize {
    let set: std::collections::HashSet<&str> =
        tool_runs(items).filter(|t| allowed.contains(t)).collect();
    set.len()
}

fn v_recon_coverage(items: &[EvidenceItem]) -> bool {
    let recon = ["nmap", "dig", "whois", "theharvester", "shodan", "web_search", "web_fetch", "recon_ng"];
    let has_host = items.iter().any(|i| matches!(i, EvidenceItem::Host { .. }));
    count_tool_runs(items, &recon) >= 2 && has_host
}

fn v_vuln_findings(items: &[EvidenceItem]) -> bool {
    items.iter().any(|i| matches!(i, EvidenceItem::Vulnerability { id, severity, .. } if id.is_some() || severity.is_some()))
}

fn v_exploit_proof(items: &[EvidenceItem]) -> bool {
    items.iter().any(|i| matches!(i, EvidenceItem::ShellSession { .. } | EvidenceItem::Credential { .. }))
}

fn v_forensics_evidence(items: &[EvidenceItem]) -> bool {
    items.iter().any(|i| matches!(i, EvidenceItem::Artifact { hash, acquired_at, .. } if hash.is_some() && acquired_at.is_some()))
}

fn v_web_exploit_reproducible(items: &[EvidenceItem]) -> bool {
    let repro: u32 = items.iter().filter_map(|i| match i {
        EvidenceItem::Reproduction { count } => Some(*count),
        _ => None,
    }).sum();
    if repro >= 2 {
        return true;
    }
    let web = ["nikto", "sqlmap", "nuclei", "browser_navigate", "browser_screenshot", "browser_click", "browser_type", "browser_extract", "web_fetch"];
    count_tool_runs(items, &web) >= 2
}

fn v_intel_correlation(items: &[EvidenceItem]) -> bool {
    // Explicit correlation with ≥2 sources, or ≥2 distinct intel tools used.
    if items.iter().any(|i| matches!(i, EvidenceItem::Correlation { sources, .. } if sources.len() >= 2)) {
        return true;
    }
    let intel = ["web_search", "web_fetch", "shodan", "whois", "dig"];
    distinct_tool_runs(items, &intel) >= 2
}

fn v_report_complete(delivery: &str, items: &[EvidenceItem]) -> bool {
    let lower = delivery.to_lowercase();
    let has_summary = ["exec-summary", "exec_summary", "executive summary", "resumen ejecutivo"]
        .iter().any(|m| lower.contains(m));
    let has_findings = ["findings", "hallazgos", "recommendation", "remediation", "remediacion"]
        .iter().any(|m| lower.contains(m));
    let wrote_report = items.iter().any(|i| matches!(i, EvidenceItem::ReportFile { .. }))
        && count_tool_runs(items, &["fs_write", "fs_edit"]) >= 1;
    has_summary && has_findings && wrote_report
}

fn v_readback(items: &[EvidenceItem]) -> bool {
    count_tool_runs(items, &["fs_write", "fs_edit"]) >= 1
        && count_tool_runs(items, &["fs_read", "fs_list", "fs_exists", "fs_glob"]) >= 1
}