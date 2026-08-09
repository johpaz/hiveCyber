---
name: clean_up
version: "1.0"
author: hivecyber
description: Procedimientos de limpieza post-explotacion. Solo en entornos autorizados.
category: tradecraft
icon: broom
permissions:
  - cli_exec
triggers:
  - cleanup
  - cleanup
  - limpiar
  - post-explotacion
rules:
  - Solo en entornos autorizados (scope explicito).
  - Documenta que se borro y que permecio (a proposito).
preferred_agents:
  - exploit_operator
output_format:
  structure: checklist
  language: es
  sections: [artifacts_created, sessions, persistence, logs, summary]
  max_length: 2000
---

# Clean-Up Checklist

## Procedimiento

1. **Sesiones MSF**: `sessions -K` (kill all).
2. **Droppers**: borra `C:\Windows\Temp\*.exe`, `/tmp/*.sh` que dejaste.
3. **Persistence creada**: borra claves Run, scheduled tasks agregadas, servicios rogue.
4. **Logs**: solo si scope explicito autoriza limpiar logs (default NO tocar).
5. **Hashes/creds**: no persistir dumps en disco. Memoria -> reportar -> borrar.
6. **Documenta**: que se borro, que permecio (y por que), que quedo como evidencia.