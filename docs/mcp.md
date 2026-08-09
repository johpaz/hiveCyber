# MCP (Model Context Protocol)

## Resumen

hiveCyber implementa MCP nativamente en Rust, sin depender del crate `rmcp`. El protocolo es JSON-RPC 2.0 sobre stdio. Soporte SSE/WebSocket declarado pero stubbeado en MVP.

## Arquitectura

```
crates/hivecyber-mcp/src/lib.rs
├── McpServerConfig     (config de un server: transport, command, args, env, url, headers)
├── McpConfig            ({ servers: HashMap<name, McpServerConfig> })
├── McpTool              ({ name, description, parameters, server_name })
├── McpServerState       ({ name, config, status, tools, last_error })
├── StdioConnection      (child: tokio::process::Child, stdin, stdout: Arc<Mutex<BufReader>>)
└── McpClientManager     (servers + conns + req_id)
```

## McpClientManager API

```rust
pub fn new() -> Self;
pub fn register(&mut self, name: &str, config: McpServerConfig);
pub async fn connect_server(&mut self, name: &str) -> Result<()>;
pub async fn connect_all(&mut self) -> Vec<String>;  // returns errors
pub async fn disconnect_server(&mut self, name: &str) -> Result<()>;
pub async fn disconnect_all(&mut self);
pub async fn call_tool(&mut self, server: &str, tool: &str, args: &Value) -> Result<Value>;
pub fn list_servers(&self) -> Vec<&McpServerState>;
pub fn list_tools(&self) -> Vec<&McpTool>;
```

## Protocolo JSON-RPC 2.0

### initialize

Request:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {
    "protocolVersion": "2024-11-05",
    "capabilities": {},
    "clientInfo": {"name": "hivecyber", "version": "0.1.0"}
  }
}
```

### notifications/initialized

Notification (no response):
```json
{
  "jsonrpc": "2.0",
  "method": "notifications/initialized"
}
```

### tools/list

Request:
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/list",
  "params": {}
}
```

Response:
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "tools": [
      {
        "name": "search",
        "description": "Search the web",
        "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}
      }
    ]
  }
}
```

### tools/call

Request:
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "search",
    "arguments": {"query": "nmap cheatsheet"}
  }
}
```

Response:
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {"content": [{"type": "text", "text": "..."}]}
}
```

## Lifecycle de conexion

```
1. register(name, config) -> McpServerState.status = "disconnected"
2. connect_server(name):
   a. Si transport != "stdio" -> stub (status = "connected", sin spawn)
   b. spawn Command::new(config.command).args(config.args).envs(config.env)
      - stdin(Dpio::piped()), stdout(Stdio::piped()), stderr(Stdio::null())
   c. Enviar initialize, esperar respuesta
   d. Enviar notifications/initialized
   e. Enviar tools/list, poblar state.tools
   f. status = "connected"
3. call_tool(server, tool, args):
   a. Generar req_id (counter atomica)
   b. Enviar tools/call con args
   c. Leer respuesta por stdout (linea-delimited JSON)
   d. Retornar result o error
4. disconnect_server(name):
   a. child.kill()
   b. status = "disconnected", tools.clear()
```

## Configuracion

MCP servers se configuran en la config global (pendiente de integrar con `config.rs`). Formato YAML:

```yaml
mcp:
  enabled: true
  servers:
    filesystem:
      transport: stdio
      command: npx
      args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
    github:
      transport: stdio
      command: npx
      args: ["-y", "@modelcontextprotocol/server-github"]
      env:
        GITHUB_PERSONAL_ACCESS_TOKEN: ghp_xxx
    remote:
      transport: sse
      url: https://api.example.com/mcp
      headers:
        Authorization: Bearer token123
```

En MVP: la config esta cargada pero los servers no se auto-registran en boot. Pendiente wire con `config.mcp` y `McpClientManager::register` al iniciar.

## Lazy connect (local-first)

Hive promueve lazy connect: los servers MCP no se spawnean al registrar, sino cuando una tool los necesita. En hiveCyber MVP:
- `connect_server` se invoca explicitamente via CLI (`hivecyber mcp connect <name>`)
- Pendiente: timeout 8s para connect on-demand desde el agent loop cuando se referencia una tool MCP

## Reconnect en stale-session

Si `call_tool` recibe error 401 o session expired, Hive reconecta una vez y reintenta. En hiveCyber MVP: pendiente de implementar.

## CLI

```bash
hivecyber mcp list              # muestra servers registrados y status
hivecyber mcp connect <name>    # intenta conectar explicitamente
```

## Diferencias con Hive TS

| Hive TS | hiveCyber Rust |
|---|---|
| `@modelcontextprotocol/sdk` | Implementacion nativa JSON-RPC |
| SSE transport custom (`transports/sse.ts`) | Stub (pendiente reqwest event-stream) |
| WebSocket transport custom (`transports/websocket.ts`) | Stub (pendiente tokio-tungstenite) |
| Lazy connect on-demand 8s | Explicito via CLI en MVP |
| Reconnect stale-session | Pendiente |
| Hot-reload de config | Pendiente |