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
    match check_tool {
        "recon_coverage" => Some(verify_recon_coverage(evidence)),
        "vuln_findings" => Some(verify_vuln_findings(evidence)),
        "exploit_proof" => Some(verify_exploit_proof(evidence)),
        "forensics_evidence" => Some(verify_forensics_evidence(evidence)),
        "web_exploit_reproducible" => Some(verify_web_exploit_reproducible(evidence)),
        "intel_correlation" => Some(verify_intel_correlation(evidence)),
        "report_complete" => Some(verify_report_complete(delivery, evidence)),
        "readback" => Some(verify_readback(evidence)),
        _ => None,
    }
}

fn evidence_text(evidence: &[String]) -> String {
    evidence.join("\n")
}

fn evidence_tool_count(evidence: &[String], tools: &[&str]) -> usize {
    let lower_tools: Vec<String> = tools.iter().map(|t| format!("{}:", t.to_lowercase())).collect();
    evidence
        .iter()
        .filter(|ev| {
            let lower = ev.to_lowercase();
            lower_tools.iter().any(|p| lower.starts_with(p.as_str()))
        })
        .count()
}

fn has_regex(text: &str, pattern: &str) -> bool {
    regex::Regex::new(pattern)
        .map(|re| re.is_match(text))
        .unwrap_or(false)
}

fn verify_recon_coverage(evidence: &[String]) -> bool {
    let recon_tools = [
        "nmap", "dig", "whois", "theharvester", "shodan",
        "web_search", "web_fetch", "recon_ng",
    ];
    let recon_count = evidence_tool_count(evidence, &recon_tools);
    let text = evidence_text(evidence).to_lowercase();
    let has_ip = has_regex(&text, r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b");
    let has_dotted_host = has_regex(&text, r"\b[a-z0-9-]+\.[a-z0-9-]+\.[a-z]{2,}\b");
    recon_count >= 2 && (has_ip || has_dotted_host)
}

fn verify_vuln_findings(evidence: &[String]) -> bool {
    let text = evidence_text(evidence);
    has_regex(&text, r"\bCVE-\d{4}-\d{4,7}\b")
        || has_regex(&text, r"\bEID-\d+\b")
        || has_regex(&text, r"\bEXPDB-\d+\b")
        || {
            let lower = text.to_lowercase();
            (lower.contains("severity") || lower.contains("risk"))
                && (lower.contains("critical")
                    || lower.contains("high")
                    || lower.contains("medium")
                    || lower.contains("low"))
        }
}

fn verify_exploit_proof(evidence: &[String]) -> bool {
    let text = evidence_text(evidence).to_lowercase();
    let markers = [
        "meterpreter", "command shell", "session opened", "session 1 opened",
        "dumped password hashes", "ntlm hash", "nt hash", "credentials",
        "credential captured", "shell session", "pwned", "proof file",
    ];
    markers.iter().any(|m| text.contains(m))
}

fn verify_forensics_evidence(evidence: &[String]) -> bool {
    let text = evidence_text(evidence);
    let has_sha256 = has_regex(&text, r"\b[0-9a-fA-F]{64}\b");
    let has_timestamp = has_regex(&text, r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}");
    has_sha256 && has_timestamp
}

fn verify_web_exploit_reproducible(evidence: &[String]) -> bool {
    let text = evidence_text(evidence).to_lowercase();
    let repro_markers = ["poc", "reproduc", "reproduced", "run 2", "second run", "2x"];
    let total_repro: usize = repro_markers
        .iter()
        .map(|m| text.matches(m).count())
        .sum();
    if total_repro >= 2 {
        return true;
    }
    let web_tools = [
        "nikto", "sqlmap", "nuclei", "browser_navigate", "browser_screenshot",
        "browser_click", "browser_type", "browser_extract", "web_fetch",
    ];
    evidence_tool_count(evidence, &web_tools) >= 2
}

fn verify_intel_correlation(evidence: &[String]) -> bool {
    let intel_tools = [
        "web_search", "web_fetch", "shodan", "whois", "dig",
    ];
    let mut distinct = std::collections::HashSet::new();
    for ev in evidence {
        let lower = ev.to_lowercase();
        for t in &intel_tools {
            if lower.starts_with(&format!("{}:", t)) {
                distinct.insert(*t);
            }
        }
    }
    distinct.len() >= 2
}

fn verify_report_complete(delivery: &str, evidence: &[String]) -> bool {
    let lower = delivery.to_lowercase();
    let has_summary = lower.contains("exec-summary")
        || lower.contains("exec_summary")
        || lower.contains("executive summary")
        || lower.contains("resumen ejecutivo");
    let has_findings = lower.contains("findings")
        || lower.contains("hallazgos")
        || lower.contains("recommendation")
        || lower.contains("remediation")
        || lower.contains("remediacion");
    let ev_text = evidence_text(evidence).to_lowercase();
    let report_write = ev_text.contains("fs_write") || ev_text.contains("fs_edit");
    let report_ext = has_regex(&ev_text, r"\.(md|html|pdf|docx|txt|odt)");
    has_summary && has_findings && report_write && report_ext
}

fn verify_readback(evidence: &[String]) -> bool {
    let write_tools = ["fs_write", "fs_edit"];
    let read_tools = ["fs_read", "fs_list", "fs_exists", "fs_glob"];
    let writes = evidence_tool_count(evidence, &write_tools);
    let reads = evidence_tool_count(evidence, &read_tools);
    writes >= 1 && reads >= 1
}