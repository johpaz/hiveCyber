# Web.com (Bugcrowd) — bitácora del engagement

Programa público: <https://bugcrowd.com/engagements/webdotcom>. **El brief vigente manda**:
reléelo antes de cada sesión; este archivo solo resume cómo se trabajó con hiveCyber.

## Alcance y política
- Hosts en alcance (exactos): `app.web.com`, `www.networksolutions.com`, `www.bluehost.com`, `www.hostgator.com`.
- Todo lo demás es otro asset: no se toca.
- `engagement-policy.json` es la política de este engagement. Antes de usarla, cambia el valor de
  `X-Bugcrowd-Ninja` por tu usuario de Bugcrowd y cárgala desde el panel (Política → guardar borrador → activar).
- El programa exige la cabecera `X-Request-Purpose: Research`: va en `required_headers` y la añaden las
  herramientas web y el navegador acotado, no el modelo.

## Qué se hizo (2026-11-06)
1. **Fase 1 — reconocimiento pasivo con `web_fetch`/`web_head`**: 11 peticiones GET, 1 por segundo.
2. **Fase 2 — navegador acotado (`scoped-browser`)**: una página principal por host.

## Resultados (hechos observados)
- `app.web.com`: HTTP 200, aplicación de una sola página. No renderizó en el navegador acotado,
  probablemente porque se bloquearon sus dependencias de terceros (fuera de alcance).
  `/import-map.json` es público y solo lista los módulos de la aplicación.
- `www.networksolutions.com`, `www.bluehost.com`, `www.hostgator.com`: HTTP 403 de Cloudflare
  (desafío a clientes automatizados). No se intentó evadirlo.
- **Sin hallazgos.** Sesión total: 59 peticiones permitidas a hosts del programa, auditoría íntegra.

## Cómo retomarlo
- Las pruebas que requieren sesión o pasar el desafío de Cloudflare las hace el operador en su navegador;
  los agentes ayudan a analizar lo que él comparta (peticiones, respuestas, parámetros) y a redactar el borrador.
- Registro solo con un correo `@bugcrowdninja.com`. No interactuar con clientes ni cuentas reales.
- Si algo se parece a un hallazgo previo, consulta primero la memoria de hallazgos (control de duplicados)
  y deja el reporte en borrador: lo revisa y lo envía una persona.
- Operación del panel y del navegador acotado: `docs/panel.md`.
