# scoped-browser

Servidor MCP (stdio) de navegador **solo lectura** sobre `Bun.WebView` (backend Chrome/CDP).
Aplica la `EngagementPolicy` activa del gateway a *cada* petición del navegador, también las del
JavaScript de la página: bloquea lo que esté fuera de alcance antes de salir, solo permite GET,
añade las `required_headers` del programa, respeta `rate_limit_rps` por host y un tope total
(`SCOPED_BROWSER_MAX_REQUESTS`, 150 por defecto). Si Cloudflare desafía la petición, informa y no insiste.

Herramientas: `browser_navigate`, `browser_text`, `browser_links`, `browser_forms` (no los envía), `browser_stats`.
Sin clic, sin rellenar formularios, sin `evaluate` arbitrario. Log: `$HIVECYBER_HOME/scoped-browser.jsonl`.

Registro (con el gateway parado):
    HIVECYBER_HOME=… hivecyber mcp add scoped-browser --command bun \
      --arg $PWD/tools/scoped-browser/server.ts --env HIVECYBER_HOME=… --env BUN_CHROME_PATH=<chrome>

Límites conocidos: arranca Chrome con `--no-sandbox`; `Bun.WebView` admite un solo `cdp()` pendiente
(se serializa con una cola); el log no está en la cadena de auditoría del gateway.
