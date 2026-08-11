//! Integration test for the WebSocket MCP transport, against a real in-process
//! `tokio-tungstenite` server that speaks the minimal MCP handshake:
//! initialize → tools/list (one `add` tool) → tools/call (returns a+b).

use std::collections::HashMap;

use futures::{SinkExt, StreamExt};
use hivecyber_mcp::{McpClientManager, McpServerConfig};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

#[tokio::test]
async fn ws_transport_connects_lists_and_calls() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("ws://{}/mcp", addr);

    // Mock MCP WebSocket server.
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        while let Some(Ok(msg)) = ws.next().await {
            let Message::Text(txt) = msg else { continue };
            let req: serde_json::Value = match serde_json::from_str(txt.as_str()) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
            let id = req.get("id").cloned().unwrap_or(serde_json::Value::Null);
            let resp = match method {
                "initialize" => serde_json::json!({
                    "jsonrpc": "2.0", "id": id,
                    "result": {"protocolVersion": "2024-11-05", "capabilities": {}, "serverInfo": {"name": "wsmock", "version": "1"}}
                }),
                "tools/list" => serde_json::json!({
                    "jsonrpc": "2.0", "id": id,
                    "result": {"tools": [{
                        "name": "add", "description": "suma",
                        "inputSchema": {"type": "object", "properties": {"a": {"type": "number"}, "b": {"type": "number"}}, "required": ["a", "b"]}
                    }]}
                }),
                "tools/call" => {
                    let args = req.get("params").and_then(|p| p.get("arguments")).cloned().unwrap_or_default();
                    let a = args.get("a").and_then(|v| v.as_f64()).unwrap_or(0.0);
                    let b = args.get("b").and_then(|v| v.as_f64()).unwrap_or(0.0);
                    serde_json::json!({
                        "jsonrpc": "2.0", "id": id,
                        "result": {"content": [{"type": "text", "text": format!("{}", (a + b) as i64)}]}
                    })
                }
                // Notification: no response.
                _ => continue,
            };
            ws.send(Message::text(resp.to_string())).await.unwrap();
        }
    });

    let mut mgr = McpClientManager::new();
    mgr.register(
        "wsecho",
        McpServerConfig {
            enabled: true,
            transport: "ws".into(),
            command: None,
            args: None,
            env: HashMap::new(),
            url: Some(url),
            headers: HashMap::new(),
        },
    );

    mgr.connect_server("wsecho").await.expect("ws connect");

    let tools = mgr.list_tools();
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, "add");
    assert_eq!(tools[0].server_name, "wsecho");

    let result = mgr
        .call_tool("wsecho", "add", &serde_json::json!({"a": 2, "b": 40}))
        .await
        .expect("ws call");
    let text = result
        .get("content")
        .and_then(|c| c.as_array())
        .and_then(|a| a.first())
        .and_then(|o| o.get("text"))
        .and_then(|t| t.as_str())
        .unwrap_or("");
    assert_eq!(text, "42");

    server.abort();
}
