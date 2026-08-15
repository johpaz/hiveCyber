//! Live prompt context built from the BM25 selectors.
//!
//! - `build_coordinator_context`: ranks the worker roster (from `COL_AGENTS`)
//!   against the request and renders the routing catalog (with exclusions) that
//!   gets appended to the coordinator's system prompt — the previously-static
//!   worker table becomes a live, ranked routing aid.
//! - `build_skill_context`: ranks the available skills (from `COL_SKILLS`)
//!   against the task and surfaces the most relevant playbooks in the prompt.
//! - `build_mcp_tools_context`: lists the connected MCP servers' tools so the
//!   coordinator knows what capabilities are available beyond the built-in set —
//!   critical for 27B-class models that may not reliably inspect the tool schema.

use crate::agent::catalog_selector::{
    render_agent_routing_catalog, search_catalog_agents, RoutableAgent,
};
use crate::agent::skill_selector::{select_skills, SkillDescriptor};
use crate::store::HiveDb;
use crate::store::collections::{COL_AGENTS, COL_SKILLS};

const MAX_RANKED_WORKERS: usize = 5;
const MAX_MCP_TOOLS_LISTED: usize = 25;

/// Build the coordinator's live routing block, or empty string if there are no
/// worker agents to route to.
pub async fn build_coordinator_context(db: &HiveDb, message: &str) -> String {
    let roster = load_roster(db).await;
    if roster.is_empty() {
        return String::new();
    }

    let mut s = String::from("## Ruteo de workers (ranking BM25 en vivo para esta solicitud)\n");
    let ranked = search_catalog_agents(message, &roster, MAX_RANKED_WORKERS);
    if ranked.is_empty() {
        s.push_str(
            "Sin coincidencia fuerte con un worker específico; evalúa el catálogo completo abajo.\n",
        );
    } else {
        s.push_str("Workers más relevantes para la solicitud actual (delega preferentemente en estos):\n");
        for m in &ranked {
            if let Some(a) = roster.iter().find(|a| a.id == m.id) {
                s.push_str(&format!("- {} — {} (score {:.2})\n", a.id, a.description, m.score));
            }
        }
    }
    s.push_str("\nCatálogo completo (respeta las exclusiones):\n");
    s.push_str(&render_agent_routing_catalog(&roster));
    s
}

/// Build the "skills relevantes" block for `message`, or empty string when
/// nothing is relevant.
pub async fn build_skill_context(db: &HiveDb, message: &str) -> String {
    let skills = load_skills(db).await;
    if skills.is_empty() {
        return String::new();
    }
    let sel = select_skills(message, &skills);
    if !sel.matched {
        return String::new();
    }
    let mut s = String::from("## Skills relevantes para esta tarea\n");
    s.push_str("Playbooks sugeridos (consulta su contenido con la skill si aplica):\n");
    for id in &sel.selected {
        if let Some(sk) = skills.iter().find(|k| k.name == *id) {
            s.push_str(&format!(
                "- {} — {}\n",
                sk.name,
                sk.description.chars().take(120).collect::<String>()
            ));
        }
    }
    s
}

async fn load_roster(db: &HiveDb) -> Vec<RoutableAgent> {
    db.list(COL_AGENTS)
        .await
        .into_iter()
        .filter_map(|(id, v)| {
            if v.get("role").and_then(|r| r.as_str()) != Some("worker") {
                return None;
            }
            let enabled = v.get("enabled").and_then(|e| e.as_bool()).unwrap_or(false);
            let name = v.get("name").and_then(|n| n.as_str()).unwrap_or(&id).to_string();
            let description = v.get("description").and_then(|d| d.as_str()).unwrap_or("").to_string();
            let tool_allowlist: Vec<String> = v
                .get("tool_allowlist_json")
                .and_then(|t| serde_json::from_value(t.clone()).ok())
                .unwrap_or_default();
            let skills: Vec<String> = v
                .get("skills_json")
                .and_then(|t| serde_json::from_value(t.clone()).ok())
                .unwrap_or_default();
            let routing_exclusions: Vec<String> = v
                .get("routing_exclusions_json")
                .and_then(|t| serde_json::from_value(t.clone()).ok())
                .unwrap_or_default();
            let tags = format!("{} {}", tool_allowlist.join(" "), skills.join(" "));
            Some(RoutableAgent { id, name, description, tags, routing_exclusions, enabled })
        })
        .collect()
}

async fn load_skills(db: &HiveDb) -> Vec<SkillDescriptor> {
    db.list(COL_SKILLS)
        .await
        .into_iter()
        .map(|(id, v)| {
            let name = v.get("name").and_then(|n| n.as_str()).unwrap_or(&id).to_string();
            let description = v.get("description").and_then(|d| d.as_str()).unwrap_or("").to_string();
            let category = v.get("category").and_then(|c| c.as_str()).unwrap_or("").to_string();
            let tags = v.get("tags").and_then(|t| t.as_str()).unwrap_or("").to_string();
            SkillDescriptor { name, description, category, tags }
        })
        .collect()
}

/// Build a context block listing the connected MCP servers and their tools, so
/// the coordinator can see (in its system prompt) what MCP capabilities are
/// available — not just what the BM25 selector happened to surface this turn.
pub async fn build_mcp_tools_context(mcp: &crate::agent::mcp_integration::SharedMcp) -> String {
    let tools: Vec<(String, String, String)> = {
        let mgr = mcp.lock().await;
        mgr.list_tools()
            .into_iter()
            .map(|t| (t.server_name.clone(), t.name.clone(), t.description.clone()))
            .collect()
    };
    if tools.is_empty() {
        return String::new();
    }
    let mut servers: std::collections::BTreeMap<String, Vec<(String, String)>> =
        std::collections::BTreeMap::new();
    for (server, name, desc) in &tools {
        servers
            .entry(server.clone())
            .or_default()
            .push((name.clone(), desc.clone()));
    }
    let mut s = String::from("## Herramientas MCP disponibles (conectadas y listas)\n");
    s.push_str("Estas tools están registradas y disponibles para tu uso. Menciónalas por nombre exacto.\n\n");
    let mut total = 0;
    for (server, tool_list) in &servers {
        s.push_str(&format!("**{}** ({} tools):\n", server, tool_list.len()));
        for (name, desc) in tool_list {
            if total >= MAX_MCP_TOOLS_LISTED {
                s.push_str(&format!("  … y {} más\n", tools.len() - total));
                break;
            }
            let short_desc = desc.chars().take(100).collect::<String>();
            s.push_str(&format!("  - `{}` — {}\n", name, short_desc));
            total += 1;
        }
        if total >= MAX_MCP_TOOLS_LISTED {
            break;
        }
    }
    s
}
