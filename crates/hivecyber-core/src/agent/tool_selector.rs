//! Dynamic tool selection — Rust port of Hive's `tool-selector.ts`.
//!
//! Before each LLM call, score the available tools against the user message
//! with BM25 (via `capability_search`) and keep only the most relevant ones,
//! capped per turn. This keeps the tool schema sent to the model small (fewer
//! tokens, better precision) instead of shipping the whole catalog every turn.
//!
//! Stateless: each message is evaluated independently. Conversational messages
//! (greetings, thanks, acknowledgements) short-circuit to an empty selection.

use crate::agent::capability_search::{
    apply_relative_cutoff, CapabilityDoc, CapabilityIndex, CapabilityType,
};

/// Max tools returned per turn. Keeps token count low and forces prioritization.
pub const MAX_TOOLS_PER_TURN: usize = 12;

/// Keep a hit only if it scores at least this fraction of the top hit.
pub const RELEVANCE_RATIO: f32 = 0.3;

#[derive(Debug, Clone)]
pub struct ToolDescriptor {
    pub name: String,
    pub description: String,
    pub category: String,
}

#[derive(Debug, Clone)]
pub struct ToolSelection {
    /// Names of the tools selected for this turn.
    pub selected: Vec<String>,
    /// Whether the message was treated as conversational (no tools intended).
    pub conversational: bool,
    /// True when the selector produced a real, ranked match (vs. a fallback).
    pub matched: bool,
    pub reasoning: String,
}

/// Conversational openers that should carry no tools. Anchored, case-insensitive.
fn is_conversational(message: &str) -> bool {
    let m = message.trim().to_lowercase();
    if m.is_empty() || m == "?" || m == "¿?" {
        return true;
    }
    const OPENERS: &[&str] = &[
        "hola", "buenas", "buenos dias", "buenas tardes", "buenas noches",
        "gracias", "muchas gracias", "ok", "okay", "vale", "perfecto", "genial",
        "claro", "de acuerdo", "adios", "chau", "nos vemos", "hasta luego",
        "entiendo", "ya veo", "bien", "hi", "hello", "hey", "thanks",
        "thank you", "yes", "no", "bye",
    ];
    // Treat as conversational only when the whole (short) message is an opener,
    // not when a task merely starts with "ok, escanea…".
    let word_count = m.split_whitespace().count();
    if word_count > 4 {
        return false;
    }
    OPENERS.iter().any(|o| m == *o || m.starts_with(&format!("{} ", o)) && word_count <= 2)
}

/// Select the tools relevant to `message` from `tools`.
///
/// Returns at most `MAX_TOOLS_PER_TURN` names. On a conversational message the
/// selection is empty (`conversational = true`). When the message is a real
/// request but nothing scores above the cutoff, `matched = false` and
/// `selected` is empty — the caller decides whether to fall back to the full
/// set (recommended, so a vague request is not left tool-less).
pub fn select_tools(message: &str, tools: &[ToolDescriptor]) -> ToolSelection {
    if is_conversational(message) {
        return ToolSelection {
            selected: Vec::new(),
            conversational: true,
            matched: false,
            reasoning: "mensaje conversacional — sin tools".into(),
        };
    }

    // Tools mentioned explicitly by name in the message survive the BM25 cut
    // unconditionally. Token dilution (long missions, many tools) can deprioritize
    // an otherwise-perfect match — and an explicit mention like "llama
    // bugcrowd_get_public_brief" must always reach the model.
    let msg_lower = message.to_lowercase();
    let explicit: Vec<String> = tools
        .iter()
        .filter(|t| {
            let nm = t.name.to_lowercase();
            nm.len() >= 3 && msg_lower.contains(&nm)
        })
        .map(|t| t.name.clone())
        .collect();

    let docs: Vec<CapabilityDoc> = tools
        .iter()
        .map(|t| CapabilityDoc {
            typ: CapabilityType::Tool,
            raw_id: t.name.clone(),
            name: t.name.clone(),
            // Category + name tokens carry routing intent (boosted above body).
            tags: format!("{} {}", t.category, t.name.replace('_', " ")),
            body: t.description.clone(),
        })
        .collect();

    let index = match CapabilityIndex::build(&docs) {
        Ok(idx) => idx,
        Err(e) => {
            // Never strip all tools on an index failure — fall back to everything.
            return ToolSelection {
                selected: tools.iter().map(|t| t.name.clone()).collect(),
                conversational: false,
                matched: false,
                reasoning: format!("fallback (index error: {})", e),
            };
        }
    };

    let hits = index.search(message, &[CapabilityType::Tool], MAX_TOOLS_PER_TURN * 2);
    let hits = apply_relative_cutoff(hits, RELEVANCE_RATIO);
    let mut selected: Vec<String> = hits
        .into_iter()
        .take(MAX_TOOLS_PER_TURN)
        .map(|h| h.raw_id)
        .collect();

    // Merge the explicitly-mentioned tools (de-dup). Explicit mentions bypass
    // MAX_TOOLS_PER_TURN: a direct operator instruction ("llama
    // bugcrowd_get_public_brief") must always reach the model — even if the
    // BM25 already filled 12 slots with other tools.
    for name in explicit {
        if !selected.contains(&name) {
            selected.push(name);
        }
    }

    if selected.is_empty() {
        return ToolSelection {
            selected,
            conversational: false,
            matched: false,
            reasoning: "sin coincidencia fuerte — el caller decide fallback".into(),
        };
    }

    let n = selected.len();
    ToolSelection {
        selected,
        conversational: false,
        matched: true,
        reasoning: format!("{} tools seleccionadas por relevancia BM25 (incluye menciones explicitas)", n),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn td(name: &str, cat: &str, desc: &str) -> ToolDescriptor {
        ToolDescriptor { name: name.into(), category: cat.into(), description: desc.into() }
    }

    fn catalog() -> Vec<ToolDescriptor> {
        vec![
            td("nmap", "recon", "Escaneo de red con nmap: puertos y servicios."),
            td("sqlmap", "vulns", "Detecta y explota inyecciones SQL en aplicaciones web."),
            td("office_write", "base", "Genera informes en docx, pdf y xlsx."),
            td("hydra", "exploit", "Fuerza bruta de credenciales."),
            td("volatility", "forensics", "Analisis de memoria RAM forense."),
        ]
    }

    #[test]
    fn conversational_message_selects_nothing() {
        let sel = select_tools("hola", &catalog());
        assert!(sel.conversational);
        assert!(sel.selected.is_empty());
    }

    #[test]
    fn task_that_starts_with_ok_is_not_conversational() {
        let sel = select_tools("ok, escanea los puertos de 10.0.0.5", &catalog());
        assert!(!sel.conversational);
        assert!(sel.matched);
        assert!(sel.selected.contains(&"nmap".to_string()));
    }

    #[test]
    fn scan_request_selects_nmap() {
        let sel = select_tools("necesito escanear puertos abiertos del host", &catalog());
        assert!(sel.selected.contains(&"nmap".to_string()));
        assert!(sel.selected.len() <= MAX_TOOLS_PER_TURN);
    }

    #[test]
    fn report_request_selects_office() {
        let sel = select_tools("redacta un informe pdf con los hallazgos", &catalog());
        assert!(sel.selected.contains(&"office_write".to_string()));
    }

    #[test]
    fn unrelated_request_reports_no_match() {
        let sel = select_tools("cuentame un chiste sobre gatos", &catalog());
        // Not conversational, but nothing in the security toolset matches.
        assert!(!sel.conversational);
        assert!(!sel.matched);
        assert!(sel.selected.is_empty());
    }

    #[test]
    fn explicit_tool_mention_survives_bm25_cutoff() {
        // A mission instructs calling a specific tool by name: that tool must be
        // in the selection even when surrounding tokens dilute its BM25 score.
        let mut big_catalog = catalog();
        big_catalog.push(td(
            "bugcrowd_get_public_brief",
            "mcp",
            "Lee el brief publico vigente: estado, safe harbor, scope, targets, recompensas y reglas.",
        ));
        let mission = "Llama bugcrowd_get_public_brief con el codigo cfr. \
            Confirma que el programa sigue abierto y que thinkglobalhealth.org continua en alcance. \
            Realiza reconocimiento inicial pasivo y no intrusivo sobre https://thinkglobalhealth.org/.";
        let sel = select_tools(mission, &big_catalog);
        assert!(sel.selected.contains(&"bugcrowd_get_public_brief".to_string()));
        assert!(sel.matched);
    }
}
