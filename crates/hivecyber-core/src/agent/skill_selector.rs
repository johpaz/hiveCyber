//! Dynamic skill selection — Rust port of Hive's `skill-selector.ts`.
//!
//! Ranks the available skills against the task with BM25 (via `capability_search`,
//! `CapabilityType::Skill`) and returns the most relevant few, to be surfaced in
//! the agent's system prompt as suggested playbooks. Mirrors `tool_selector`.

use crate::agent::capability_search::{
    apply_relative_cutoff, CapabilityDoc, CapabilityIndex, CapabilityType,
};

/// Max skills surfaced per turn — a short, focused list of playbooks.
pub const MAX_SKILLS_PER_TURN: usize = 5;

/// Keep a skill only if it scores at least this fraction of the top hit.
pub const RELEVANCE_RATIO: f32 = 0.3;

#[derive(Debug, Clone)]
pub struct SkillDescriptor {
    pub name: String,
    pub description: String,
    pub category: String,
    pub tags: String,
}

#[derive(Debug, Clone)]
pub struct SkillSelection {
    pub selected: Vec<String>,
    pub matched: bool,
}

/// Select the skills relevant to `message`. Empty selection (`matched=false`)
/// when nothing scores above the cutoff — the caller then injects nothing.
pub fn select_skills(message: &str, skills: &[SkillDescriptor]) -> SkillSelection {
    if skills.is_empty() || message.trim().is_empty() {
        return SkillSelection { selected: Vec::new(), matched: false };
    }

    let docs: Vec<CapabilityDoc> = skills
        .iter()
        .map(|s| CapabilityDoc {
            typ: CapabilityType::Skill,
            raw_id: s.name.clone(),
            name: s.name.replace('_', " "),
            tags: format!("{} {}", s.category, s.tags),
            body: s.description.clone(),
        })
        .collect();

    let index = match CapabilityIndex::build(&docs) {
        Ok(i) => i,
        Err(_) => return SkillSelection { selected: Vec::new(), matched: false },
    };

    let hits = apply_relative_cutoff(
        index.search(message, &[CapabilityType::Skill], MAX_SKILLS_PER_TURN * 2),
        RELEVANCE_RATIO,
    );
    let selected: Vec<String> = hits
        .into_iter()
        .take(MAX_SKILLS_PER_TURN)
        .map(|h| h.raw_id)
        .collect();
    let matched = !selected.is_empty();
    SkillSelection { selected, matched }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sk(name: &str, cat: &str, desc: &str) -> SkillDescriptor {
        SkillDescriptor { name: name.into(), category: cat.into(), description: desc.into(), tags: String::new() }
    }

    fn roster() -> Vec<SkillDescriptor> {
        vec![
            sk("recon_workflow", "recon", "Flujo de reconocimiento: nmap, subdominios y servicios."),
            sk("cve_lookup", "vulns", "Busca y correlaciona CVEs de un servicio o versión."),
            sk("pentest_report", "report", "Estructura un informe de pentest con exec summary y remediación."),
            sk("memory_analysis", "forensics", "Análisis de volcado de memoria con volatility."),
        ]
    }

    #[test]
    fn scan_task_selects_recon_workflow() {
        let sel = select_skills("hacer reconocimiento de puertos y servicios del host", &roster());
        assert!(sel.matched);
        assert!(sel.selected.contains(&"recon_workflow".to_string()));
        assert!(sel.selected.len() <= MAX_SKILLS_PER_TURN);
    }

    #[test]
    fn report_task_selects_report_skill() {
        let sel = select_skills("redactar el informe final del pentest", &roster());
        assert!(sel.selected.contains(&"pentest_report".to_string()));
    }

    #[test]
    fn empty_roster_matches_nothing() {
        let sel = select_skills("cualquier cosa", &[]);
        assert!(!sel.matched);
        assert!(sel.selected.is_empty());
    }
}
