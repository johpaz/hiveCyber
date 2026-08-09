---
name: cvss_scoring
version: "1.0"
author: hivecyber
description: Calcula y asigna CVSS v3.1 base + temporal scores a vulnerabilidades.
category: reporting
icon: gauge
permissions:
  - fs_read
  - web_search
tools:
  - web_search
triggers:
  - CVSS
  - score
  - scoring
rules:
  - Usa CVSS v3.1 (default).
  - Justifica vector (base + temporal + environmental si relevante).
preferred_agents:
  - report_writer
  - vuln_scanner
output_format:
  structure: findings
  language: es
  sections: [vector, base_score, temporal_score, justification, summary]
  max_length: 1500
---

# CVSS Scoring

## Vector CVSS v3.1
`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (ejemplo EternalBlue aproximado).

## Base Metrics
- **Attack Vector (AV)**: N(etwork), A(djacent), L(ocal), P(hysical)
- **Attack Complexity (AC)**: L(low), H(igh)
- **Privileges Required (PR)**: N(one), L(low), H(high)
- **User Interaction (UI)**: N(one), R(equired)
- **Scope (S)**: U(nchanged), C(hanged)
- **Confidentiality/Integrity/Availability**: N/L/H

Calculo: reglas CVSS v3.1 spec. Output: score base + cualitativo (Critical >= 9).