use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogPersona {
    pub id: String,
    pub name: String,
    pub description: String,
    pub tool_allowlist: Vec<String>,
    pub skills: Vec<String>,
    pub default_acceptance: Vec<crate::store::collections::AcceptanceCriterion>,
    pub workspace_scope: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_override: Option<crate::store::collections::ModelOverride>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing_exclusions: Option<Vec<String>>,
}

pub fn catalog_personas() -> Vec<CatalogPersona> {
    use crate::store::collections::*;

    let mut personas = vec![
        CatalogPersona {
            id: "recon_operator".into(),
            name: "Operador de Reconocimiento".into(),
            description: "Ejecuta reconocimiento activo y OSINT sobre targets autorizados. Incluye nmap, recon-ng, theHarvester, whois, dig, shodan.".into(),
            tool_allowlist: vec![
                "nmap".into(), "recon_ng".into(), "theharvester".into(),
                "whois".into(), "dig".into(), "shodan".into(),
                "web_search".into(), "web_fetch".into(),
            ],
            skills: vec!["recon_workflow".into(), "osint_correlation".into()],
            default_acceptance: vec![
                AcceptanceCriterion {
                    id: "recon_coverage".into(),
                    description: "La cobertura de puertos/subdominios coincide con el scope especificado".into(),
                    check_tool: Some("recon_coverage".into()),
                },
            ],
            workspace_scope: serde_json::json!({"kind": "none"}),
            model_override: None,
            routing_exclusions: None,
        },
        CatalogPersona {
            id: "vuln_scanner".into(),
            name: "Analista de Vulnerabilidades".into(),
            description: "Detecta y analiza vulnerabilidades con nuclei, nikto, sqlmap, searchsploit, semgrep, trivy.".into(),
            tool_allowlist: vec![
                "nuclei".into(), "nikto".into(), "sqlmap".into(),
                "searchsploit".into(), "semgrep".into(), "trivy".into(),
                "fs_read".into(), "fs_glob".into(),
            ],
            skills: vec!["vuln_scan_workflow".into(), "cve_lookup".into()],
            default_acceptance: vec![
                AcceptanceCriterion {
                    id: "vuln_findings".into(),
                    description: "Findings parseados con CVE/EID y severidad valida".into(),
                    check_tool: Some("vuln_findings".into()),
                },
            ],
            workspace_scope: serde_json::json!({"kind": "none"}),
            model_override: Some(ModelOverride {
                required_capabilities: vec!["code".into(), "function_calling".into()],
                fallback: "general".into(),
                prefer_different_family: None,
            }),
            routing_exclusions: None,
        },
        CatalogPersona {
            id: "exploit_operator".into(),
            name: "Operador de Explotacion".into(),
            description: "Ejecuta explotacion con metasploit, hydra, crackmapexec, mimikatz. Requiere --unsafe y allowlist de hosts.".into(),
            tool_allowlist: vec![
                "metasploit_rpc".into(), "hydra".into(), "crackmapexec".into(),
                "mimikatz".into(), "cli_exec".into(),
            ],
            skills: vec!["pwn_check".into(), "post_exploit_chain".into(), "lateral_movement".into()],
            default_acceptance: vec![
                AcceptanceCriterion {
                    id: "exploit_proof".into(),
                    description: "Sesion shell/cred/hash verificada en host de allowlist".into(),
                    check_tool: Some("exploit_proof".into()),
                },
            ],
            workspace_scope: serde_json::json!({"kind": "none"}),
            model_override: Some(ModelOverride {
                required_capabilities: vec!["code".into(), "function_calling".into()],
                fallback: "general".into(),
                prefer_different_family: Some(true),
            }),
            routing_exclusions: None,
        },
        CatalogPersona {
            id: "forensics_analyst".into(),
            name: "Analista Forense".into(),
            description: "Analisis post-incidente con volatility, yara, zeek, osquery, parsers de logs. Cadena de custodia obligatoria.".into(),
            tool_allowlist: vec![
                "volatility".into(), "yara_scan".into(), "zeek_parse".into(),
                "osquery".into(), "log_parse".into(), "fs_read".into(),
            ],
            skills: vec!["memory_analysis".into(), "log_timeline".into(), "ioc_extraction".into()],
            default_acceptance: vec![
                AcceptanceCriterion {
                    id: "forensics_evidence".into(),
                    description: "Evidencia con hash SHA-256 y timestamp de adquisicion".into(),
                    check_tool: Some("forensics_evidence".into()),
                },
            ],
            workspace_scope: serde_json::json!({"kind": "none"}),
            model_override: None,
            routing_exclusions: None,
        },
        CatalogPersona {
            id: "web_pentester".into(),
            name: "Pentester Web".into(),
            description: "Pentesting de aplicaciones web con nikto, sqlmap, nuclei, browser automation. Requiere --unsafe.".into(),
            tool_allowlist: vec![
                "nikto".into(), "sqlmap".into(), "nuclei".into(),
                "browser_navigate".into(), "browser_screenshot".into(),
                "browser_click".into(), "browser_type".into(),
                "browser_extract".into(), "web_fetch".into(), "cli_exec".into(),
            ],
            skills: vec!["web_pentest_methodology".into(), "poc_reproduction".into()],
            default_acceptance: vec![
                AcceptanceCriterion {
                    id: "web_exploit_reproducible".into(),
                    description: "PoC reproduce el hallazgo al menos 2 veces".into(),
                    check_tool: Some("web_exploit_reproducible".into()),
                },
            ],
            workspace_scope: serde_json::json!({"kind": "none"}),
            model_override: Some(ModelOverride {
                required_capabilities: vec!["code".into(), "function_calling".into()],
                fallback: "general".into(),
                prefer_different_family: None,
            }),
            routing_exclusions: None,
        },
        CatalogPersona {
            id: "threat_intel_analyst".into(),
            name: "Analista de Threat Intel".into(),
            description: "OSINT y correlacion de IoCs con shodan, whois, dig, web rearch.".into(),
            tool_allowlist: vec![
                "web_search".into(), "web_fetch".into(), "shodan".into(),
                "whois".into(), "dig".into(), "fs_read".into(),
            ],
            skills: vec!["ioc_extraction".into(), "threat_modeling".into()],
            default_acceptance: vec![
                AcceptanceCriterion {
                    id: "intel_correlation".into(),
                    description: "IoCs con al menos 2 fuentes independientes citadas".into(),
                    check_tool: Some("intel_correlation".into()),
                },
            ],
            workspace_scope: serde_json::json!({"kind": "none"}),
            model_override: None,
            routing_exclusions: None,
        },
        CatalogPersona {
            id: "report_writer".into(),
            name: "Redactor de Informes".into(),
            description: "Genera informes de pentest/forense con exec-summary, findings, remediation.".into(),
            tool_allowlist: vec![
                "fs_read".into(), "fs_write".into(), "fs_edit".into(),
                "office_read".into(), "office_write".into(),
            ],
            skills: vec!["pentest_report".into(), "cvss_scoring".into()],
            default_acceptance: vec![
                AcceptanceCriterion {
                    id: "report_complete".into(),
                    description: "Informe existe, abre sin error, incluye exec-summary + findings + remediation".into(),
                    check_tool: Some("report_complete".into()),
                },
            ],
            workspace_scope: serde_json::json!({"kind": "workspace", "read": "**/*", "write": "**/*"}),
            model_override: None,
            routing_exclusions: None,
        },
        CatalogPersona {
            id: "workspace_file_operator".into(),
            name: "Operador de Archivos".into(),
            description: "Operaciones genericas de filesystem: leer, escribir, editar, buscar.".into(),
            tool_allowlist: vec![
                "fs_read".into(), "fs_write".into(), "fs_edit".into(),
                "fs_delete".into(), "fs_list".into(), "fs_glob".into(),
                "fs_exists".into(),
            ],
            skills: vec!["workspace_file_operator".into()],
            default_acceptance: vec![
                AcceptanceCriterion {
                    id: "readback".into(),
                    description: "Estado final de cada path verificado via read/list/exists".into(),
                    check_tool: Some("readback".into()),
                },
            ],
            workspace_scope: serde_json::json!({"kind": "workspace", "read": "**/*", "write": "**/*"}),
            model_override: None,
            routing_exclusions: None,
        },
    ];

    // Activate the (previously dead) routing_exclusions field so the
    // catalog-selector can route a request away from workers whose exclusions
    // overlap it (e.g. don't send a port-scan to report_writer).
    for p in personas.iter_mut() {
        p.routing_exclusions = routing_exclusions_for(&p.id);
    }
    personas
}

/// Per-worker routing exclusions ("NO usar para…"). Kept here so both the seed
/// and the live routing catalog share one source of truth.
fn routing_exclusions_for(id: &str) -> Option<Vec<String>> {
    let ex: &[&str] = match id {
        "recon_operator" => &["redaccion de informes", "explotacion de vulnerabilidades", "analisis forense de memoria"],
        "vuln_scanner" => &["redaccion de informes", "reconocimiento de red", "explotacion activa"],
        "exploit_operator" => &["redaccion de informes", "reconocimiento de red", "analisis forense"],
        "forensics_analyst" => &["escaneo de red", "explotacion de vulnerabilidades", "redaccion de informes"],
        "web_pentester" => &["analisis forense de memoria", "redaccion de informes", "reconocimiento de red"],
        "threat_intel_analyst" => &["explotacion de vulnerabilidades", "analisis forense", "redaccion de informes"],
        "report_writer" => &["escaneo de puertos", "explotacion de vulnerabilidades", "reconocimiento activo"],
        "workspace_file_operator" => &["escaneo de red", "explotacion de vulnerabilidades", "analisis forense"],
        _ => &[],
    };
    if ex.is_empty() {
        None
    } else {
        Some(ex.iter().map(|s| s.to_string()).collect())
    }
}

pub const COORDINATOR_SYSTEM_PROMPT: &str = r#"# HIVECYBER — Caelum (Agente Coordinador)

Eres Caelum, el coordinador de operaciones de ciberseguridad del harness hiveCyber.

## Tu rol
- Eres el UNICO agente que habla con el operador.
- NO haces el trabajo tu mismo. Descompones la mision en sub-tareas.
- Delegas cada sub-tarea al worker especializado mas apropiado del catalogo.
- Paralelizas sub-tareas independientes en un mismo turno.
- Cuando todas las tareas delegadas terminan, integras los resultados y juzgas los criterios no deterministas.
- Si una entrega falla, puedes `task_revise` al mismo worker (mismo thread, contexto preservado) o arreglar trivialidades tu mismo.

## Catalogo de Workers

| id | especialidad |
|---|---|
| recon_operator | Reconocimiento activo + OSINT |
| vuln_scanner | Deteccion y analisis de vulnerabilidades |
| exploit_operator | Explotacion (requiere --unsafe + allowlist) |
| forensics_analyst | Analisis post-incidente + cadena de custodia |
| web_pentester | Pentesting de aplicaciones web |
| threat_intel_analyst | Threat intel y correlacion de IoCs |
| report_writer | Redaccion de informes |
| workspace_file_operator | Operaciones genericas de filesystem |

## Politicas de seguridad (ESTRICTAS)
- exploit_operator y web_pentester SOLO operan sobre hosts en la allowlist.
- Cadena de custodia forense obligatoria (hash SHA-256 + timestamp).
- herramientas de explotacion se auto-pausan tras 3 strikes.
- audit log inmutable para toda accion de explotacion.

## Output
- Structurado: `status, what_was_done, artifacts, evidence, risks, question`.
- Nunca declares exito sin evidencia verificable por acceptance criteria."#;