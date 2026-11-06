# Panel web (Rune) + hivecyber-gateway

Panel de control local para el operador. Frontend en `../panel` (rune-ts + Vite); backend
`crates/hivecyber-gateway` (axum). **Sustituye la decisión previa "sin UI web"**, pero conserva
el modelo de seguridad: el navegador nunca es fuente de autorización.

## Arranque
```bash
cargo build --release -p hivecyber-gateway
(cd ../panel && npm install && npm run build)
hivecyber-gateway --panel-dir ../panel/dist      # imprime el token (también en $HIVECYBER_HOME/gateway.token)
# desarrollo: (cd ../panel && npm run dev)       # proxy /api → 127.0.0.1:18791
```
- Bind por defecto `127.0.0.1`; fuera de loopback exige `--allow-non-loopback`.
- Auth: `Authorization: Bearer <token>`; el WebSocket del chat usa un ticket de un solo uso (`POST /api/ws-ticket`, 30 s).
- **El gateway es el único proceso que abre HiveDb**: no ejecutes la CLI contra el mismo `HIVECYBER_HOME` mientras corre.

## Controles de alcance
- `unsafe_mode` / `allow_cli_exec` / `require_policy` solo se fijan por flags de arranque; la API los expone en solo lectura.
- El alcance cambia únicamente vía `EngagementPolicy` versionada: `PUT /api/engagement-policy` crea un **borrador**;
  `POST /api/engagement-policy/:v/activate` lo activa (auditado, falla cerrado) y reconstruye SecurityContext + dispatch loop.
- Relajar controles (levantar una prohibición o quitar una aprobación humana) exige justificación (validado en servidor).
- Sin política activa el chat se rechaza (servidor) y el compositor se bloquea (UI).
- **Approval gate**: `ToolMiddleware` no ejecuta una tool de categoría gated (`approval_categories_for_tool`) sin aprobación;
  devuelve `blocked_pending_approval`, el gateway emite `ApprovalRequired` por WS y `approve`/`deny` quedan en el audit log.
  Limitación: las aprobaciones son un set por proceso, sin caducidad ni scoping por run (pendiente).
- API keys de providers: write-only (nunca se devuelven); credenciales MCP redactadas.

## Notas de Rune
- Los `<tr>` insertados dinámicamente por `ListView` se pierden (el parser los descarta): para tablas editables se re-renderiza la página.
- `view.data` es de solo lectura (mutar en ssitio); un `ListView` comparte y muta el array que recibe.
