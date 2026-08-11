//! Catalog selection / agent routing — Rust port of Hive's `catalog-selector.ts`.
//!
//! Ranks the worker catalog against a request with BM25 and drops agents whose
//! `routing_exclusions` overlap the query — the field existed in the catalog
//! but was previously dead. Also renders the routing catalog text (with the
//! "NO usar para…" hints) that the coordinator sees.

use std::collections::HashSet;

use crate::agent::capability_search::{
    apply_relative_cutoff, CapabilityDoc, CapabilityIndex, CapabilityType,
};

const RELEVANCE_RATIO: f32 = 0.35;

const ROUTING_STOP_WORDS: &[&str] = &[
    "a", "al", "de", "del", "el", "en", "la", "las", "lo", "los", "o", "otro",
    "otra", "un", "una", "y", "con", "para", "por",
];

/// Minimal agent view the selector needs.
#[derive(Debug, Clone)]
pub struct RoutableAgent {
    pub id: String,
    pub name: String,
    pub description: String,
    /// tool allowlist + skills, joined — used as BM25 tags.
    pub tags: String,
    pub routing_exclusions: Vec<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone)]
pub struct AgentMatch {
    pub id: String,
    pub score: f32,
}

/// Normalize + tokenize a phrase for routing-exclusion comparison: strip
/// accents, lowercase, split on non-alphanumerics, drop stop words, and
/// singularize trailing 's' on tokens longer than 4 chars (port of Hive's
/// `routingTokens`).
fn routing_tokens(value: &str) -> HashSet<String> {
    value
        .chars()
        .map(fold_accent)
        .collect::<String>()
        .to_lowercase()
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|t| !t.is_empty())
        .map(|t| {
            if t.len() > 4 && t.ends_with('s') {
                t[..t.len() - 1].to_string()
            } else {
                t.to_string()
            }
        })
        .filter(|t| !ROUTING_STOP_WORDS.contains(&t.as_str()))
        .collect()
}

fn fold_accent(c: char) -> char {
    match c {
        'á' | 'à' | 'ä' | 'â' => 'a',
        'é' | 'è' | 'ë' | 'ê' => 'e',
        'í' | 'ì' | 'ï' | 'î' => 'i',
        'ó' | 'ò' | 'ö' | 'ô' => 'o',
        'ú' | 'ù' | 'ü' | 'û' => 'u',
        'ñ' => 'n',
        other => other,
    }
}

/// True when the query overlaps one of the agent's routing exclusions strongly
/// enough to route away from it: at least 2 shared significant tokens, and that
/// overlap covering at least 35% of the exclusion phrase's tokens.
pub fn matches_routing_exclusion(query: &str, agent: &RoutableAgent) -> bool {
    if agent.routing_exclusions.is_empty() {
        return false;
    }
    let query_tokens = routing_tokens(query);
    agent.routing_exclusions.iter().any(|exclusion| {
        let ex = routing_tokens(exclusion);
        if ex.is_empty() {
            return false;
        }
        let shared = ex.iter().filter(|t| query_tokens.contains(*t)).count();
        shared >= 2 && (shared as f32 / ex.len() as f32) >= 0.35
    })
}

/// Rank enabled agents against `query`, dropping routing-excluded ones. Returns
/// up to `k` matches sorted by descending score.
pub fn search_catalog_agents(query: &str, agents: &[RoutableAgent], k: usize) -> Vec<AgentMatch> {
    let docs: Vec<CapabilityDoc> = agents
        .iter()
        .filter(|a| a.enabled)
        .map(|a| CapabilityDoc {
            typ: CapabilityType::Agent,
            raw_id: a.id.clone(),
            name: format!("{} {}", a.name, a.id),
            tags: a.tags.clone(),
            body: a.description.clone(),
        })
        .collect();

    let index = match CapabilityIndex::build(&docs) {
        Ok(i) => i,
        Err(_) => return Vec::new(),
    };

    let hits = apply_relative_cutoff(
        index.search(query, &[CapabilityType::Agent], k),
        RELEVANCE_RATIO,
    );

    let by_id: std::collections::HashMap<&str, &RoutableAgent> =
        agents.iter().map(|a| (a.id.as_str(), a)).collect();

    hits.into_iter()
        .filter_map(|h| {
            let agent = by_id.get(h.raw_id.as_str())?;
            if !agent.enabled || matches_routing_exclusion(query, agent) {
                return None;
            }
            Some(AgentMatch { id: h.raw_id, score: h.score })
        })
        .collect()
}

/// Render the coordinator's routing catalog, appending each agent's
/// exclusions as a "NO usar para: …" hint (port of `renderAgentRoutingCatalog`).
pub fn render_agent_routing_catalog(agents: &[RoutableAgent]) -> String {
    agents
        .iter()
        .filter(|a| a.enabled)
        .map(|a| {
            let excl = if a.routing_exclusions.is_empty() {
                String::new()
            } else {
                format!(" NO usar para: {}.", a.routing_exclusions.join("; "))
            };
            format!("- {}: {}{}", a.id, a.description, excl)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(id: &str, name: &str, desc: &str, tags: &str, excl: &[&str]) -> RoutableAgent {
        RoutableAgent {
            id: id.into(),
            name: name.into(),
            description: desc.into(),
            tags: tags.into(),
            routing_exclusions: excl.iter().map(|s| s.to_string()).collect(),
            enabled: true,
        }
    }

    fn roster() -> Vec<RoutableAgent> {
        vec![
            agent(
                "recon_operator",
                "Operador de Reconocimiento",
                "Ejecuta reconocimiento activo y OSINT sobre targets.",
                "nmap shodan osint reconocimiento",
                &[],
            ),
            agent(
                "report_writer",
                "Redactor de Informes",
                "Genera informes de pentest con exec-summary y remediation.",
                "office informe reporte documento",
                &["escaneo de puertos", "explotacion de vulnerabilidades"],
            ),
        ]
    }

    #[test]
    fn ranks_recon_for_scan_query() {
        let m = search_catalog_agents("escanear puertos y hacer reconocimiento", &roster(), 5);
        assert!(!m.is_empty());
        assert_eq!(m[0].id, "recon_operator");
    }

    #[test]
    fn routing_exclusion_drops_report_writer_for_scan() {
        // "escaneo de puertos" is an exclusion on report_writer.
        let excluded = matches_routing_exclusion("necesito un escaneo de puertos", &roster()[1]);
        assert!(excluded, "report_writer must be excluded from port-scan requests");
    }

    #[test]
    fn report_query_routes_to_report_writer() {
        let m = search_catalog_agents("redacta el informe final del pentest", &roster(), 5);
        assert!(m.iter().any(|a| a.id == "report_writer"));
    }

    #[test]
    fn render_catalog_includes_exclusion_hints() {
        let text = render_agent_routing_catalog(&roster());
        assert!(text.contains("recon_operator:"));
        assert!(text.contains("NO usar para: escaneo de puertos; explotacion de vulnerabilidades."));
    }
}
