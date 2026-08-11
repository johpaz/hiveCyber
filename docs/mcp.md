# MCP (Model Context Protocol)

## Resumen

hiveCyber implementa MCP nativamente en Rust, sin depender del crate `rmcp`. El
protocolo es JSON-RPC 2.0 con dos transportes: **stdio** (proceso hijo) y
**streamable-HTTP / SSE** (`reqwest`, con eco de `Mcp-Session-Id`). Los servers se
persisten en la colección `mcp_servers`, se conectan en el arranque de
`chat`/`run`, y cada tool descubierta se expone al agente como una tool normal
(`McpToolProxy`) que fluye por el tool-selector BM25. WebSocket queda como
Roadmap.

## Arquitectura

```
crates/hivecyber-mcp/src/lib.rs
├── McpServerConfig     (transport, command, args, env, url, headers, enabled)
├── McpTool             ({ name, description, parameters, server_name })
├── McpServerState      ({ name, config, status, tools, last_error })
├── StdioConnection     (child: tokio::process::Child, stdin, stdout)
├── HttpConnection      (reqwest::Client, url, headers, session_id)  ← SSE/HTTP
├── Transport           (Stdio | Http)
└── McpClientManager    (servers + conns + req_id)

crates/hivecyber-core/src/agent/mcp_integration.rs
├── SharedMcp           (Arc<Mutex<McpClientManager>>)
├── load_and_connect()  (lee mcp_servers, registra, connect_all)
├── register_mcp_tools()(agrega un McpToolProxy por tool al ToolRegistry)
└── McpToolProxy        (impl hivecyber_tools::Tool → manager.call_tool)
```

## McpClientManager API

```rust
pub fn new() -> Self;
pub fn register(&mut self, name: &str, config: McpServerConfig);
pub async fn connect_server(&mut self, name: &str) -> Result<()>;   // stdio + sse
pub async fn connect_all(&mut self) -> Vec<String>;  // devuelve errores
pub async fn disconnect_server(&mut self, name: &str) -> Result<()>;
pub async fn disconnect_all(&mut self);
pub async fn call_tool(&mut self, server: &str, tool: &str, args: &Value) -> Result<Value>;
pub fn list_servers(&self) -> Vec<&McpServerState>;
pub fn list_tools(&self) -> Vec<&McpTool>;
```

## Transportes

### stdio
`spawn` del `command` con `args`/`env`; JSON-RPC line-delimited sobre stdin/stdout
(stderr descartado). El proceso hijo se reap-ea en `disconnect_server`.

### streamable-HTTP / SSE
Cada mensaje JSON-RPC se hace `POST` a `url` con
`Accept: application/json, text/event-stream`. La respuesta se acepta como cuerpo
`application/json` **o** como el primer frame `data:` de un `text/event-stream`.
El `Mcp-Session-Id` devuelto en `initialize` se guarda y se re-envía en cada
request posterior. Transports admitidos: `sse`, `http`, `streamable-http`.

Cubierto por el test de integración `crates/hivecyber-mcp/tests/sse_transport.rs`
(servidor mock: initialize sobre SSE + session id, tools/list como JSON, tools/call).

## Protocolo JSON-RPC 2.0

`initialize` → `notifications/initialized` → `tools/list` en connect;
`tools/call` en cada invocación. (Ejemplos de payloads sin cambios respecto al
estándar MCP 2024-11-05.)

## Integración con el agente (tool-sync)

Equivalente en Rust del `mcp/tool-sync.ts` de Hive:

1. En el arranque de `chat`/`run`/`resume`, `mcp_integration::load_and_connect`
   lee `mcp_servers`, registra y conecta (best-effort: un server que falla no
   tumba al resto).
2. `register_mcp_tools` crea un `McpToolProxy` por cada tool descubierta y lo
   registra en el `ToolRegistry`. **Los tools nativos ganan** ante colisión de
   nombre (un tool MCP que se llame como un built-in se omite), para no ensombrecer
   los tools con gate de seguridad.
3. Al estar en el registry, los tools MCP entran automáticamente al tool-selector
   BM25 — no hay un índice MCP aparte.
4. El manager compartido (`SharedMcp`) se inyecta en `AgentLoopOptions.mcp_manager`
   (loop del coordinador) y en `WorkerTaskExecutor`/`DispatchLoop` (workers).

## Configuración y persistencia

Los servers viven en la colección `mcp_servers` (un doc por server, forma
`McpServerConfig`). Se gestionan con `hivecyber mcp add/remove`. `config.mcp.enabled`
(env `HIVECYBER_MCP_ENABLED`, default on) controla si se cargan.

## CLI

```bash
# stdio
hivecyber mcp add fs --transport stdio --command npx \
  --arg -y --arg @modelcontextprotocol/server-filesystem --arg /tmp
# sse / streamable-http
hivecyber mcp add remote --transport sse --url https://api.example.com/mcp \
  --header "Authorization=Bearer token123"

hivecyber mcp list                 # servers registrados + status
hivecyber mcp connect <name>       # conecta y lista sus tools
hivecyber mcp tools [name]         # tools de un server (o de todos)
hivecyber mcp call <name> <tool> '<json-args>'
hivecyber mcp disconnect <name>
hivecyber mcp remove <name>
```

Nota: en modo CLI cada comando abre una conexión efímera (el proceso es
corto). Las conexiones persistentes viven durante una sesión `chat`/`run`.

## Diferencias con Hive TS

| Hive TS | hiveCyber Rust |
|---|---|
| `@modelcontextprotocol/sdk` | Implementación nativa JSON-RPC |
| SSE transport (`transports/sse.ts`) | Implementado (`reqwest`, session id) |
| WebSocket transport (`transports/websocket.ts`) | Roadmap (`tokio-tungstenite` presente) |
| tool-sync al índice de capacidades | `McpToolProxy` en el `ToolRegistry` → BM25 |
| Lazy connect on-demand 8s | Connect en boot de `chat`/`run` |
| Reconnect stale-session | Roadmap |
| Hot-reload de config | Roadmap |
