# hiveCyber — notas para sesiones de Claude Code

Harness Rust de agentes (Caelum + 8 workers) para bug bounty autorizado en Bugcrowd. Panel web en Rune (`panel/`) sobre `hivecyber-gateway`.

## Operar
- `scripts/gateway.sh start|stop|restart|status|token|logs|panel|register-browser`. Estado persistente en `.hivecyber/gateway/` (ignorado por git). Usa `HIVECYBER_GATEWAY_HOME`; no heredar `HIVECYBER_HOME` del shell.
- No ejecutes la CLI contra el mismo home mientras el gateway esté activo (HiveDb sin locking entre procesos).
- Proveedor `hiveagents` → `http://127.0.0.1:3002/v1` (5 modelos cyber). La clave se guarda con `scripts/set-provider-key.sh hiveagents` desde el portapapeles o desde el panel; nunca por el chat.
- Tests: `cargo test --workspace`.

## Reglas con programas de bug bounty
- Relee el brief antes de cada sesión; manda sobre las bitácoras en `engagements/`.
- El alcance lo fuerza la EngagementPolicy activa (host exacto, método, rate, cabeceras `required_headers`). Guardar = borrador; activar = paso aparte y auditado.
- No evadir Cloudflare/WAF ni usar modos stealth. Si hay desafío, parar y que el operador pruebe en su navegador.
- ffuf/feroxbuster/arjun/etc. se bloquean si la política prohíbe `automated_scanning` o DoS.
- Cuentas solo con alias `@bugcrowdninja.com`. Reportes: borrador local, los revisa y envía una persona.
- Cookies/tokens en `sessions/` (0600), nunca en el chat ni en commits.

## Pendiente
Aprobaciones por run con caducidad (Fase 6), SSE de logs, alta/baja de skills y MCP, probar cybertiel-35b con herramientas en Juice Shop, empujar la rama y abrir PR.
