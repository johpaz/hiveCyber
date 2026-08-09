---
name: recon_workflow
version: '1.0'
author: hivecyber
description: Flujo completo de reconocimiento activo y pasivo sobre un target autorizado.
category: recon
icon: radar
permissions:
- nmap
- recon_ng
- theharvester
- whois
- dig
- shodan
- web_search
- web_fetch
tools:
- nmap
- recon_ng
- theharvester
- whois
- dig
- shodan
triggers:
- recon
- reconocimiento
- escaneo
- discovery
- footprinting
steps:
- step: Pasivo
  action: theharvester
  instruction: Ejecuta OSINT pasivo con theHarvester sobre el dominio objetivo
- step: Activo
  action: nmap
  instruction: Escaneo activo con nmap -sV -T4 sobre el scope autorizado
- step: DNS
  action: dig
  instruction: Enumera records A, MX, TXT, NS, CNAME del dominio
- step: WHOIS
  action: whois
  instruction: Obtiene info de registro del dominio o IP
- step: Shodan
  action: shodan
  instruction: Busca servicios expuestos en Shodan
rules:
- Solo autorizado. Verifica scope con el operador antes de activo.
- Reporta cobertura exacta (puertos/subdominios descubiertos).
- 'SINCO sigue el orden: pasivo → activo.'
preferred_agents:
- recon_operator
output_format:
  structure: findings
  language: es
  sections:
  - scope
  - methodology
  - hosts
  - ports
  - subdomains
  - services
  - summary
  max_length: 4000
---

# Recon Workflow

Procedimiento ordenado para descubrir superficie de ataque en un target autorizado.

## Orden recomendado

1. **Pasivo (primero)**: theHarvester, OSINT, Shodan. Minima huella.
2. **Activo (después)**: nmap -sV -sC -T4 con permiso explícito.
3. **DNS enum**: dig A, MX, TXT, NS, CNAME, AXFR intent (si zona lo permite).
4. **WHOIS** para info de registro, contactos, fechas.
5. **Shodan** para servicios expuestos sin tocar el target.

## Criterios de exito

- Cobertura de puertos documentada (TCP y UDP si aplica).
- Todos los subdominios descubiertos listados.
- Servicios versionados.
- Hallazgos sin falsos positivos.