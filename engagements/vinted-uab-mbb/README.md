# Vinted (Bugcrowd) — bitácora del engagement

Programa público: <https://bugcrowd.com/engagements/vinted-uab-mbb>. Reléelo antes de cada sesión;
el brief vigente manda.

## Estado (2026-11-06)
- Fase pasiva en los hosts secundarios (`careers`, `company`): solo cabeceras y `robots.txt`; sin hallazgos.
  `news.vinted.com` no resolvía en DNS ese día.
- Fase con cuenta propia (`@bugcrowdninja.com`): la API de `www.vinted.com` respondió **403 con desafío de
  Cloudflare** a peticiones automatizadas, incluso con las cookies de sesión del propio operador.
  No se intentó evadir el desafío.

## Qué queda
- Pruebas manuales del operador en su navegador con dos cuentas propias (comprador/vendedor).
- Los fallos de lógica de negocio se validan a mano antes de redactar el reporte.
