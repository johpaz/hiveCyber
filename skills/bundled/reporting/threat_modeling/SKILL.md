---
name: threat_modeling
version: '1.0'
author: hivecyber
description: Modelado de amenazas con STRIDE o PASTA a partir de arquitectura dada.
category: reporting
icon: brain
permissions:
- fs_read
- web_search
- web_fetch
triggers:
- threat model
- stride
- pasta
rules:
- 'Cubre 6 categorias STRIDE: Spoofing, Tampering, Repudiation, Info Disclosure, DoS,
  EoP.'
- 'Por cada amenaza: impacto (cia), likelihood, mitigation.'
preferred_agents:
- threat_intel_analyst
output_format:
  structure: findings
  language: es
  sections:
  - architecture
  - threats
  - risk_matrix
  - recommendations
  - summary
  max_length: 5000
---

# Threat Modeling (STRIDE)

## Procedimiento

1. **Diagrama arquitectura**: data flow, trust boundaries.
2. **Identifica assets**: C/I/A sensibles.
3. **STRIDE per componente**:
   - Spoofing (identidad)
   - Tampering (datos)
   - Repudiation (no repudio)
   - Information Disclosure
   - Denial of Service
   - Elevation of Privilege
4. **Riesgo**: impact × likelihood (matriz 5x5).
5. **Mitigations**: por amenaza prioritaria.