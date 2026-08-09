---
name: memory_analysis
version: '1.0'
author: hivecyber
description: Analisis forense de memoria con volatility. Cadena de custodia obligatoria.
category: forensics
icon: memory
permissions:
- volatility
- fs_read
tools:
- volatility
- fs_read
triggers:
- memoria forense
- memory dump
- volatility
- proceso malicioso
steps:
- step: Adquisicion
  action: volatility
  instruction: Verifica dump con imageinfo
- step: Procesos
  action: volatility
  instruction: pslist + pstree + psscan
- step: Conexiones
  action: volatility
  instruction: netscan + connections
- step: Malware
  action: volatility
  instruction: malfind + yarascan
- step: Persistencia
  action: volatility
  instruction: printkey + shimcache
rules:
- 'Cadena de custodia obligatoria: hash SHA-256 + timestamp de adquisicion.'
- No modificar el dump original.
- Documenta cada comando volatility usado.
preferred_agents:
- forensics_analyst
output_format:
  structure: findings
  language: es
  sections:
  - acquisition
  - processes
  - network
  - malware
  - persistence
  - timeline
  - summary
  max_length: 6000
---

# Memory Analysis con Volatility3

## Procedimiento

1. **Adquisicion**: hash SHA-256 + timestamp. Verifica con `vol -f dump.raw windows.info`.
2. **Procesos**: `pslist`, `pstree`, `psscan` (detecta hidden).
3. **Conexiones**: `netscan` (Windows 10+), `connections` (legacy).
4. **Malware**: `malfind`, `yarascan` con reglas yarac.
5. **Persistencia**: `printkey` en `Software\Microsoft\Windows\CurrentVersion\Run`, `shimcache`.
6. **Timeline**: integra con `log_timeline`.

## Cadena de Custodia
Toda evidencia reproducida debe tener:
- SHA-256 del dump original.
- Timestamp ISO-8601 de adquisición.
- Comando exacto de volatility.
- Output reproducible sin modificaciones.