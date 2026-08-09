---
name: opsec
version: "1.0"
author: hivecyber
description: "Procedimientos OPSEC para pentesting: minimizar huella, evadir deteccion."
category: tradecraft
icon: shield-alt
permissions:
  - cli_exec
triggers:
  - opsec
  - evasion
  - stealth
  - deteccion
rules:
  - Documenta posibles EID de Sysmon y orígenes de log generados por cada acción.
  - Minimiza logs generados.
preferred_agents:
  - exploit_operator
  - web_pentester
output_format:
  structure: guide
  language: es
  sections: [objective, techniques, mitigations, sources, summary]
  max_length: 3000
---

# OPSEC Tradecraft

## Reglas basicas

1. **No ejecutar binarios de proceso no plausible** (powershell + cradle = flag rojo).
2. **Usar herramientas nativas** (lolbins).
3. **Limpiar post-ejecucion**:
   - `exit` sesion MSF.
   - Borrar drop en C:\Windows\Temp.
   - Clear-EventLog solo en lab autorizado.
4. **Timing**: scans no en horario laboral si lab/honeypot persigue.
5. **Egress**: encapsular por 443 si CSP bloquea.

## Event IDs Sysmon comunes a evitar/rotear
- 1 Process Create
- 3 Network Connect
- 8 Remote Thread
- 10 Process Access
- 11 File Create
- 22 DNS Query

## Tecnicas conoce + rotea
- Mimikatz genera EID 10 (Process Access a LSASS). Usar "RunAsUser + sekurlsa" desde proceso plausible.
- WMI lateral genera EID 20. Alternativa: WinRM (EID 4648).