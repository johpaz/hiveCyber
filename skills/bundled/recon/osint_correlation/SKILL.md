---
name: osint_correlation
version: "1.0"
author: hivecyber
description: Correlaciona datos OSINT de multiples fuentes para construir perfil de threat intel.
category: recon
icon: search
permissions:
  - web_search
  - web_fetch
  - shodan
  - whois
  - dig
tools:
  - web_search
  - web_fetch
  - shodan
  - whois
  - dig
triggers:
  - osint
  - threat intel
  - correlacion
  - ioc
rules:
  - Reporta cada fuente citando URL o ID.
  - Mínimo 2 fuentes independientes para confirmar IoC.
preferred_agents:
  - threat_intel_analyst
output_format:
  structure: findings
  language: es
  sections: [iocs, sources, correlations, confidence, summary]
  max_length: 3000
---

# OSINT Correlation

## Procedimiento

1. Identifica IoCs clave (IPs, dominios, hashes, emails).
2. Busca cada IoC en 3+ fuentes independientes.
3. Correlaciona: mismo actor, misma campaña, mismo TTP.
4. Reporta nivel de confianza (high/medium/low).
5. Cita todas las fuentes con URL/ID.