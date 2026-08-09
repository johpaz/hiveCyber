---
name: persistence
version: "1.0"
author: hivecyber
description: Tecnicas de persistencia para mantener acceso. Solo en entornos autorizados.
category: tradecraft
icon: anchor
permissions:
  - cli_exec
  - metasploit_rpc
triggers:
  - persistence
  - persistencia
  - mantener acceso
rules:
  - REQUIERE --unsafe + allowlist.
  - Documenta cada tecnica elegida y rollback.
preferred_agents:
  - exploit_operator
output_format:
  structure: guide
  language: es
  sections: [techniques, implementation, detection_paths, rollback, summary]
  max_length: 3000
---

# Persistence Techniques

## Tecnicas MITRE ATT&CK (T1130-T1543)

- **Run Keys**: `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- **Scheduled Tasks**: `schtasks /create`
- **Services**: sc create
- **WMI Event Subscription**
- **DLL Search Order Hijack**
- **Bootkit** (si external)

## Documentacion

Por cada tecnica aplicada:
- Llave exacta / ruta de archivo.
- Comando completo.
- Deteccion: que IOCs genera.
- Rollback: comando inverso para limpieza.