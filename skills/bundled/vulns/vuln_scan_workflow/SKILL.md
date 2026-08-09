---
name: vuln_scan_workflow
version: '1.0'
author: hivecyber
description: Flujo deteccion y analisis de vulnerabilidades con nucleon, nikto, sqlmap,
  searchsploit, semgrep, trivy.
category: vulns
icon: shield
permissions:
- nuclei
- nikto
- sqlmap
- searchsploit
- semgrep
- trivy
- fs_read
- fs_glob
tools:
- nuclei
- nikto
- sqlmap
- searchsploit
- semgrep
- trivy
triggers:
- vuln
- vulnerabilidad
- scan
- CVE
- CVE lookup
steps:
- step: Web scan
  action: nuclei
  instruction: Lanza nuclei con templates http sobre el target web
- step: Web server scan
  action: nikto
  instruction: Lanza nikto sobre la URL target
- step: Exploit lookup
  action: searchsploit
  instruction: Busca exploits conocidos para servicios descubiertos
- step: SQLi detection
  action: sqlmap
  instruction: Prueba SQLi en parametros detectados
- step: SAST
  action: semgrep
  instruction: Si hay codigo fuente, lanza semgrep scan
- step: Container scan
  action: trivy
  instruction: Si hay imagenes Docker, lanza trivy image
rules:
- Documenta CVE/EID por cada hallazgo.
- Reporta severidad CVSS cuando este disponible.
- 'Diferencia: confirmado vs probable vs informativo.'
preferred_agents:
- vuln_scanner
output_format:
  structure: findings
  language: es
  sections:
  - methodology
  - findings
  - cve_list
  - severity
  - recommendations
  - summary
  max_length: 5000
---

# Vuln Scan Workflow

## Metodología

1. **Web**: nuclei + nikto sobre URL/hosts.
2. **Exploit lookup**: searchsploit para servicios descubiertos en recon.
3. **SQLi**: sqlmap solo en URLs con parámetros.
4. **SAST**: semgrep si hay código fuente.
5. **Container**: trivy image si hay Dockerfile/imagen.

## Criterios

- Cada finding con CVE/EID + severidad.
- Confirmado: PoC reproduce el hallazgo.
- Probable: indicio fuerte sin PoC.
- Informativo: hardening/missing patches.