---
name: ioc_extraction
version: "1.0"
author: hivecyber
description: Extrae IoCs de evidencia forense y los correlaciona con threat intel.
category: forensics
icon: fingerprint
permissions:
  - log_parse
  - yara_scan
  - fs_read
  - web_search
  - web_fetch
  - shodan
tools:
  - log_parse
  - yara_scan
  - web_search
  - shodan
triggers:
  - ioc
  - indicators of compromise
  - threat intel
rules:
  - Mínimo 2 fuentes independientes para confirmar IoC.
  - Cita fuente原文.
preferred_agents:
  - forensics_analyst
  - threat_intel_analyst
output_format:
  structure: findings
  language: es
  sections: [iocs, types, sources, confidence, summary]
  max_length: 3000
---

# IOC Extraction

1. Parse logs/memoria en busca de:
   - IPs conn extrañas
   - Hashes de archivos
   - URLs/Dominios
   - Mutex names
   - Scheduled tasks nuevas
2. Por cada IoC:
   - Shodan (IP)
   - VirusTotal (hash/url) — via web_fetch
   - URLhaus / Abuse.ch (via web_fetch)
3. Agrupa por campaña si correlacionan.
4. Nivel de confianza: high/medium/low.