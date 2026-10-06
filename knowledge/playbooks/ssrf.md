---
id: pb-ssrf
kind: playbook
title: "Server-Side Request Forgery (SSRF)"
tags: [ssrf, web, api, cloud, owasp-api7]
refs: [OWASP-API7:2023, CWE-918, WSTG-INPV-19]
severity_hint: high
program: null
---

# SSRF

## Qué es
El servidor realiza peticiones a un destino controlable por el atacante, permitiendo alcanzar
sistemas internos no expuestos (metadata de nube, servicios de la red interna, loopback).

## Dónde vive
- Funciones que fetchean URLs provistas por el usuario: importadores, previsualizadores de
  enlaces, webhooks, generadores de miniaturas/PDF, integraciones.
- Parámetros que aceptan una URL, host o esquema.
- Parsers de documentos/imágenes que resuelven recursos remotos.

## Cómo se detecta (metodología)
1. Identificar entradas que provoquen una petición saliente del servidor.
2. Apuntar a un **colaborador/canario propio** (servidor HTTP bajo tu control, dentro del
   alcance del programa) y observar si el servidor lo contacta — evidencia out-of-band.
3. Evaluar si se puede dirigir a destinos internos (rangos privados, loopback, endpoints de
   metadata del proveedor cloud). Confirmar impacto sin exfiltrar datos sensibles reales.
4. Probar defensas típicas y sus límites: redirecciones, representaciones alternativas del
   host, esquemas no-HTTP.

## Cómo se evidencia
- Interacción out-of-band registrada en tu canario (timestamp + origen).
- Si se alcanza un recurso interno, capturar la respuesta mínima que demuestre acceso, sin
  volcar secretos.
- `EvidenceItem`: `{ vulnerability: "ssrf", host, endpoint, oob_confirmed: true, internal_reach: "..." }`.

## Impacto a argumentar
Acceso a servicios internos, lectura de metadata de nube, pivote hacia la red interna; en el
peor caso, robo de credenciales de instancia.

## Remediación (para el reporte)
Allowlist de destinos, resolución y validación del host final tras redirecciones, bloqueo de
rangos internos y endpoints de metadata, egress controlado.

## Notas de scope y seguridad
No usar la SSRF para pivotar más allá de lo autorizado. Demostrar el acceso, no explotarlo a
fondo. El control de egreso de hiveCyber (`docs/egress.md`, nftables default-deny) ayuda a que
tus propias pruebas no se salgan del alcance.
