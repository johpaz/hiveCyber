---
name: log_timeline
version: "1.0"
author: hivecyber
description: Construye timeline de eventos forenses a partir de multiplex logs.
category: forensics
icon: clock
permissions:
  - log_parse
  - fs_read
  - volatility
  - yara_scan
tools:
  - log_parse
  - fs_read
triggers:
  - timeline
  - logs forense
  - cadena de eventos
rules:
  - Cronologico (UTC obligatorio).
  - Fuente por cada evento.
  - Hash de logs originales.
preferred_agents:
  - forensics_analyst
output_format:
  structure: timeline
  language: es
  sections: [events, sources, anomalies, summary]
  max_length: 4000
---

# Log Timeline

## Procedimiento

1. **Colecta**: Event logs (EVTX), auth logs, syslog, AppLogs.
2. **Hash de cada log**: SHA-256 (cadena de custodia).
3. **Parse**: `log_parse` con regex por tipo de log.
4. **Normalize**: timestamp UTC, source, event_id, data.
5. **Sort**: chrono, dedup.
6. **Anomaly detection**: out-of-pattern events.

## Salida
Tabla cronológica:
```
2024-01-15T10:23:01Z | Security | 4624 | Logon Type 10 | usuario@host
2024-01-15T10:23:05Z | Security | 4688 | Process Create | cmd.exe → powershell.exe
...
```