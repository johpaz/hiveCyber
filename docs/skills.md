# Skills

## Formato SKILL.md

Cada skill es un archivo Markdown con YAML frontmatter:

```yaml
---
name: recon_workflow
version: "1.0"
author: hivecyber
description: Flujo completo de reconocimiento activo y pasivo sobre un target autorizado.
category: recon
icon: radar
permissions:
  - nmap
  - recon_ng
  - theharvester
  - whois
  - dig
  - shodan
  - web_search
  - web_fetch
tools:
  - nmap
  - recon_ng
  - theharvester
  - whois
  - dig
  - shodan
triggers:
  - recon
  - reconocimiento
  - escaneo
  - discovery
  - footprinting
steps:
  - step: Pasivo
    action: theharvester
    instruction: Ejecuta OSINT pasivo con theHarvester sobre el dominio objetivo
  - step: Activo
    action: nmap
    instruction: Escaneo activo con nmap -sV -T4 sobre el scope autorizado
rules:
  - Solo autorizado. Verifica scope con el operador antes de activo.
  - Reporta cobertura exacta (puertos/subdominios descubiertos).
preferred_agents:
  - recon_operator
output_format:
  structure: findings
  language: es
  sections:
    - scope
    - methodology
    - hosts
    - ports
    - subdomains
    - services
    - summary
  max_length: 4000
---

# Recon Workflow

Procedimiento ordenado para descubrir superficie de ataque...
```

## Campos frontmatter

| campo | tipo | descripcion |
|---|---|---|
| `name` | string | ID unico de la skill |
| `version` | string | version semantica |
| `author` | string | autor |
| `description` | string | descripcion breve |
| `category` | string | recon, vulns, exploit, forensics, tradecraft, reporting |
| `icon` | string | nombre de icono (cosmetico) |
| `permissions` | list[string] | tools permitidas por esta skill |
| `tools` | list[string] | tools que la skill guia usar |
| `triggers` | list[string] | palabras/phrases que activan esta skill |
| `steps` | list[{step, action, instruction}] | pasos del workflow |
| `rules` | list[string] | reglas/guardrails |
| `preferred_agents` | list[string] | workers preferidos para esta skill |
| `output_format` | {structure, language, sections, max_length} | formato de salida esperado |

## Categorias bundled (17 skills)

### recon (2)
- `recon_workflow` — flujo activo+pasivo, orden pasivo->activo
- `osint_correlation` — correlacion de IoCs con 2+ fuentes

### vulns (2)
- `vuln_scan_workflow` — nuclei+nikto+sqlmap+searchsploit+semgrep+trivy
- `cve_lookup` — NVD + CVSSv3 + exploit refs

### exploit (4)
- `pwn_check` — PoC reproducible con --unsafe + allowlist
- `post_exploit_chain` — pivot, lateral, persistencia post-pwn
- `lateral_movement` — movimiento interno, cada hop en allowlist
- `poc_reproduction` — requiere 2+ reproducciones exitosas para validar

### forensics (3)
- `memory_analysis` — volatility3 con cadena de custodia (SHA-256 + timestamp)
- `log_timeline` — colecta + parse + sort cronologico UTC
- `ioc_extraction` — extrae IoCs (IPs, hashes, URLs) + correlaciona con threat intel

### reporting (3)
- `pentest_report` — estructura: exec-summary, scope, methodology, findings, remediation
- `cvss_scoring` — vector CVSS v3.1 base + temporal
- `threat_modeling` — STRIDE (Spoofing, Tampering, Repudiation, Info Disclosure, DoS, EoP)

### tradecraft (3)
- `opsec` — minimizar huella, evade Sysmon EIDs
- `clean_up` — limpieza post-explotacion (sesiones, droppers, persistence)
- `persistence` — tecnicas MITRE T1130-T1543 con rollback documentado

## Loader (`crates/hivecyber-skills/src/lib.rs`)

```rust
pub struct SkillLoader {
    bundled_dir: PathBuf,
    managed_dir: PathBuf,
    extra_dirs: Vec<PathBuf>,
    cache: HashMap<String, Skill>,
}

impl SkillLoader {
    pub fn new(bundled_dir: &Path, managed_dir: &Path) -> Self;
    pub fn add_extra_dir(&mut self, dir: &Path);
    pub fn load_all(&mut self) -> Result<()>;
    pub fn get(&self, name: &str) -> Option<&Skill>;
    pub fn list(&self) -> Vec<&Skill>;
}
```

## Prioridad de carga

Orden de precedencia (ultima sobreescribe primera por name):
1. **Bundled** (skills/bundled/) — lowest priority
2. **Managed** (`~/.hivecyber/skills/` o `$HIVECYBER_HOME/skills/`)
3. **Extra dirs** (configurables via `add_extra_dir`)
4. **Workspace** (`<workspace>/skills`) — highest priority (pendiente)

## Parsing

1. Regex: `^---\n(.*?)\n---\n(.*)$` separa frontmatter de body
2. YAML parse del frontmatter via `serde_yaml`
3. Body = Markdown rest (se inyecta en system prompt del worker si la skill esta seleccionada)

## Skill selection (pendiente)

En Hive:
- `skill-selector.ts` invocado por `context-compiler.ts`
- `selectSkills(userMessage)` -> BM25 search sobre triggers + description
- Skills seleccionadas expanden el tool loadout del turno
- Skill bodies + rules se inyectan en system prompt

En hiveCyber MVP: skills cargadas pero skill-selector pendiente de implementar. El CLI puede listarlas via `hivecyber skills list`. El nombre de skills se referencia en `preferred_agents` del catalog.

## CLI

```bash
hivecyber skills list          # lista todas con categoria + version + description
hivecyber skills show <name>   # JSON completo de la skill
hivecyber skills reload        # recarga del disco
```