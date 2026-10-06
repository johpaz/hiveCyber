---
id: ck-api-web
kind: checklist
title: "Checklist API / Web (OWASP API Top 10 + WSTG)"
tags: [checklist, api, web, owasp]
refs: [OWASP-API-Top10:2023, OWASP-WSTG]
program: null
---

# Checklist API / Web

Lista accionable para el `web_pentester` y el `vuln_scanner`. Cada ítem se valida contra el
scope del engagement antes de ejecutarse.

## Control de acceso
- [ ] BOLA/IDOR: acceso a objetos de otra cuenta/tenant (ver `pb-idor`).
- [ ] Autorización a nivel de función: endpoints admin alcanzables por usuario normal.
- [ ] Autorización a nivel de propiedad: modificar campos que no deberías (mass assignment).
- [ ] Endpoints secundarios (export, print, share, webhooks) que saltan el control principal.

## Autenticación y sesión
- [ ] Flujos de login, reset de contraseña, MFA, OAuth/OIDC.
- [ ] Manejo de tokens: expiración, revocación, alcance, almacenamiento.
- [ ] Rate limiting en endpoints sensibles.

## Entrada y lógica
- [ ] Inyección (SQL, NoSQL, comando, template) — `sqlmap`/`nuclei`/manual.
- [ ] SSRF en funciones que fetchean URLs (ver `pb-ssrf`).
- [ ] Lógica de negocio: race conditions, manipulación de precios/cantidades, reuso de cupones.
- [ ] Carga de archivos: tipo, tamaño, path, procesamiento posterior.

## Exposición de datos y configuración
- [ ] Respuestas que devuelven más campos de los necesarios.
- [ ] Secretos en JS empaquetado, respuestas de API o repos (`trufflehog`/`gitleaks`).
- [ ] Headers de seguridad, CORS mal configurado, documentación de API expuesta.
- [ ] Versiones y dependencias con CVEs conocidos (`nuclei`/`trivy`).

## Superficie de IA (si aplica)
- [ ] Inyección de prompt indirecta con impacto (ver `pb-llm-app`).
- [ ] Autorización en el plano de herramientas del agente.
- [ ] Exfiltración vía conectores.

## Antes de reportar
- [ ] PoC reproducible con evidencia tipada (`EvidenceItem`).
- [ ] Gate de deduplicación contra findings previos del programa.
- [ ] Impacto claro y severidad (CVSS vía skill `cvss_scoring`).
- [ ] Revisión de política de IA del programa (declarar uso si se exige).
