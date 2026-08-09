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
            results.push(AcceptanceCheckResult {
                criterion_id: criterion.id.clone(),
                check: check_tool.clone(),
                met: None,
                detail: format!(
                    "checkTool '{}' requiere ejecucion via tool registry (no implementado en skeleton)",
                    check_tool
                ),
            });
        } else {
            results.push(AcceptanceCheckResult {
                criterion_id: criterion.id.clone(),
                check: "none".into(),
                met: None,
                detail: format!("Criterio '{}' requiere juicio del coordinador", criterion.description),
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
    if results.iter().any(|r| r.met == Some(false)) {
        CheckStatus::Failed
    } else if results.iter().any(|r| r.met == Some(true)) {
        CheckStatus::Passed
    } else {
        CheckStatus::Unchecked
    }
}