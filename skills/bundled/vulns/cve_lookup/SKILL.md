---
name: cve_lookup
version: "1.0"
author: hivecyber
description: Busca y analiza CVEs especificos con CVSS y exploit availability.
category: vulns
icon: bug
permissions:
  - web_search
  - web_fetch
  - searchsploit
tools:
  - web_search
  - web_fetch
  - searchsploit
triggers:
  - CVE
  - CVE lookup
  - CVSS
rules:
  - Cita NVD como fuente principal.
  - Reporta CVSSv3 base + temporal si existe.
  - Indica si exploit publico existe.
preferred_agents:
  - vuln_scanner
output_format:
  structure: findings
  language: es
  sections: [cve_id, cvss, affected, exploit_refs, summary]
  max_length: 2000
---

# CVE Lookup

## Procedimiento

1. Busca CVE-ID en NVD (web_fetch).
2. Extrae CVSSv3 vector + base score.
3. Lista productos/versiones afectadas.
4. Verifica exploit publico con searchsploit.
5. Sintetiza: riesgo real dado contexto del target.