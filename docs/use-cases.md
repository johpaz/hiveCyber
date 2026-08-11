# Casos de uso

hiveCyber es un **harness de ciberseguridad con agentes de larga duración**: un
coordinador (Caelum) delega en 8 workers especializados, con acceptance checks
deterministas, audit log inmutable (hash-chain SHA-256) y sandbox seccomp para las
tools ofensivas. Está diseñado para **contextos autorizados**: pentesting con alcance,
defensa, DFIR, investigación y educación.

> ⚠️ **Uso responsable.** Las tools de explotación exigen `--unsafe-mode` **y** una
> allowlist de hosts (o una EngagementPolicy). Úsalo solo sobre sistemas para los que
> tienes autorización explícita. Toda ejecución queda auditada.

## Mapa: worker → especialidad → tools

| Worker | Para qué sirve | Tools típicas |
|--------|----------------|---------------|
| `recon_operator` | Descubrimiento de superficie | nmap, dig, whois, theHarvester, recon_ng, shodan |
| `vuln_scanner` | Detección de vulnerabilidades | nuclei, nikto, sqlmap, searchsploit, semgrep, trivy |
| `exploit_operator` | Explotación autorizada (red team) | metasploit_rpc, hydra, crackmapexec, mimikatz *(sandbox)* |
| `forensics_analyst` | Forense / DFIR | volatility, yara_scan, zeek_parse, osquery, log_parse |
| `web_pentester` | Pentest web + automatización de navegador | sqlmap, nikto, nuclei, browser_* (agent-browser) |
| `threat_intel_analyst`| OSINT / inteligencia de amenazas | shodan, web_search, theHarvester, web_fetch |
| `report_writer` | Informes ejecutivos y técnicos | office_read/write (docx/xlsx/pdf), fs_* |
| `workspace_file_operator` | Manejo de archivos del workspace | fs_read/write/edit/glob/exists/list/delete |

Todos disponen además de `memory_*` (notas persistentes) y el coordinador de
`task_delegate/status/list/revise`. Los tools MCP conectados se exponen dinámicamente.

## 1. Reconocimiento de superficie (autorizado)

Mapear hosts, puertos y servicios de un rango propio antes de un assessment.

```bash
echo "10.0.0.0/24" > targets.txt
hivecyber run "Enumera hosts vivos, puertos y servicios en 10.0.0.0/24 y resume por host" \
  --allowlist-hosts targets.txt
```

Caelum delega en `recon_operator`; el acceptance check `recon_coverage` valida cobertura.

## 2. OSINT / Threat Intelligence

Correlacionar huella pública de un dominio/organización (sin tocar sus sistemas).

```bash
export SHODAN_API_KEY=...
hivecyber run "Recolecta OSINT de example.com: subdominios, correos, hosts expuestos en Shodan, y correlaciona hallazgos"
```

`threat_intel_analyst` usa `theHarvester`, `shodan`, `web_search`. Útil para due diligence,
brand-protection y superficie de ataque externa.

## 3. Escaneo de vulnerabilidades

Priorizar hallazgos sobre objetivos autorizados.

```bash
hivecyber run "Escanea vulnerabilidades web en https://staging.miapp.local con nuclei y nikto; lista CVEs con severidad" \
  --allowlist-hosts targets.txt
```

`vuln_scanner`; el check `vuln_findings` exige evidencia (p. ej. CVE) para aprobar.

## 4. Pentest web

Pruebas de inyección, misconfig y flujos autenticados con automatización de navegador.

```bash
hivecyber run "Prueba inyección SQL en el login de https://staging.miapp.local y navega el flujo de checkout reportando errores" \
  --allowlist-hosts targets.txt
```

`web_pentester` combina `sqlmap`/`nuclei` con `browser_*` (agent-browser) para flujos UI.

## 5. Explotación autorizada (red team)

Reproducir un exploit conocido en un laboratorio con alcance. **Requiere modo inseguro.**

```bash
echo "10.0.0.5" > targets.txt
hivecyber run "Reproduce EternalBlue (CVE-2017-0144) en 10.0.0.5 y captura prueba de acceso" \
  --unsafe-mode --allowlist-hosts targets.txt
```

`exploit_operator`; las tools son `Isolation::Sandbox` (confinadas por seccomp en Linux).
El check `exploit_proof` exige evidencia de acceso. Recomendado dentro de la imagen Docker.

## 6. Forense de memoria y DFIR

Análisis de un volcado de memoria o disco con cadena de custodia (hash + timestamp).

```bash
hivecyber run "Analiza /casos/memdump.raw con volatility: procesos, conexiones y artefactos sospechosos; extrae IOCs"
```

`forensics_analyst` usa `volatility`, `yara_scan`, `log_parse`. La evidencia forense se
sella (hash+timestamp); el check `forensics_evidence` valida la cadena.

## 7. Blue team / detección

Reglas YARA, análisis de tráfico (Zeek), consultas de estado del host (osquery) y timelines.

```bash
hivecyber run "Corre las reglas YARA de /reglas sobre /muestras, parsea los logs Zeek de /pcap y construye un timeline de IOCs"
```

Ideal para hunting, triage de alertas y construcción de líneas de tiempo de incidentes.

## 8. Supply-chain / SAST

Escaneo de código y dependencias.

```bash
hivecyber run "Corre semgrep y trivy sobre ./mi-repo y reporta findings críticos con remediación"
```

`vuln_scanner` con `semgrep` (SAST) y `trivy` (deps/imágenes).

## 9. CTF y educación

Resolver retos o enseñar metodología paso a paso en un entorno controlado.

```bash
hivecyber run "Enumera el objetivo del CTF 10.10.10.10, identifica el servicio vulnerable y sugiere el vector" \
  --unsafe-mode --allowlist-hosts targets.txt
```

El audit log + acceptance checks hacen visible el razonamiento y la metodología.

## 10. Informes ejecutivos y técnicos

Consolidar hallazgos de todos los workers en un entregable.

```bash
hivecyber run "Compila un informe ejecutivo en docx con los hallazgos del assessment y una tabla de riesgos en xlsx"
```

`report_writer` genera docx/xlsx/pdf. Caelum reinyecta las entregas de los workers y produce
el resumen ejecutivo automáticamente al cerrar el grupo de delegación.

## 11. Extender con MCP

Conectar herramientas externas (filesystem, GitHub, bases de conocimiento, APIs internas)
vía Model Context Protocol; sus tools quedan disponibles para los agentes.

```bash
hivecyber mcp add fs --transport stdio --command npx \
  --arg -y --arg @modelcontextprotocol/server-filesystem --arg /casos
hivecyber run "Usando el MCP de filesystem, correlaciona los reportes previos en /casos con el hallazgo actual"
```

## 12. Operaciones de larga duración

Campañas multi-fase donde el agente recuerda hallazgos entre turnos (memoria persistente),
delega en paralelo, revisa entregas que no pasan los checks (`task_revise`) y retoma runs
interrumpidos (`hivecyber resume <run_id>`).

---

## Cuándo **no** usar hiveCyber

- Contra sistemas sin autorización explícita (ilegal; además el harness exige allowlist).
- Como reemplazo de un analista: los acceptance checks son heurísticos deterministas, no un
  juicio experto — revisa siempre los entregables.
- Para evasión de detección con fines maliciosos (fuera de alcance por diseño).
