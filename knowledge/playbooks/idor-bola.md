---
id: pb-idor
kind: playbook
title: "IDOR / Broken Object Level Authorization"
tags: [access-control, api, web, owasp-api1, multitenant]
refs: [OWASP-API1:2023, CWE-639, WSTG-ATHZ-04]
severity_hint: high
program: null
---

# IDOR / BOLA

## Qué es
Falla de control de acceso donde un usuario puede operar sobre objetos que no le pertenecen
manipulando un identificador (numérico, UUID, slug) sin que el servidor valide la propiedad.
Es la primera categoría de OWASP API Security Top 10 (API1:2023) y una de las de mayor pago
por su impacto directo sobre datos de otros usuarios.

## Dónde vive
- Endpoints REST con id en la ruta o el query (`/api/orders/{id}`, `?userId=`).
- Mutaciones GraphQL que reciben ids de nodo.
- Arquitecturas multitenant: cruce de tenant es el caso crítico (un tenant lee/escribe datos
  de otro). Zona de alto valor y donde los equipos suelen fallar al delegar el aislamiento al
  ORM en vez de a una capa de autorización explícita.
- Flujos indirectos: exportaciones, webhooks, endpoints de "compartir", generación de PDFs.

## Cómo se detecta (metodología)
1. Autenticarse con **dos cuentas** del mismo rol (y, si aplica, de dos tenants).
2. Mapear todos los endpoints que reciben un identificador de objeto.
3. Con la sesión de la cuenta A, intentar acceder a objetos de la cuenta B.
4. Probar también: cambio de método (GET→PUT/DELETE), ids predecibles vs UUID, objetos
   anidados, y endpoints "secundarios" (export, print, share) que a veces saltan el control.
5. Verificar que un `403/404` sea realmente autorización y no solo UI oculta.

## Cómo se evidencia
- Dos capturas correlacionadas: request de A obteniendo recurso de B, con el identificador y
  el dato ajeno visible (minimizar/enmascarar PII en el reporte).
- `EvidenceItem` tipado: `{ vulnerability: "idor", host, endpoint, object_id, cross_account: true }`.
- Reproducción paso a paso con ambas sesiones.

## Impacto a argumentar
Lectura/escritura/borrado de datos de otros usuarios o tenants; escalada si el objeto controla
permisos o facturación.

## Remediación (para el reporte)
Autorización a nivel de objeto en cada acceso, verificada contra el principal autenticado;
no confiar en ids opacos como control; pruebas automatizadas de cross-tenant.

## Notas de scope
Acceder a datos reales de otros usuarios puede exceder el alcance. Preferir cuentas de prueba
propias o datos sembrados. Si el programa lo prohíbe, evidenciar con el mínimo cruce posible y
detener en cuanto se demuestra el control roto.
