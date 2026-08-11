//! Integration test for the streamable-HTTP / SSE MCP transport.
//!
//! Spins a minimal raw-TCP HTTP/1.1 server that speaks just enough of the MCP
//! wire protocol to exercise the client's SSE parsing and session handling:
//!   1. `initialize`  → replied over `text/event-stream` (a `data:` frame) plus
//!      an `Mcp-Session-Id` header the client must echo back afterwards.
//!   2. `notifications/initialized` → 202 with an empty body.
//!   3. `tools/list`  → replied as `application/json`; asserts the session id
//!      handed out on step 1 is echoed here.
//!   4. `tools/call`  → JSON result echoing the arguments.

use std::collections::HashMap;

use hivecyber_mcp::{McpClientManager, McpServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const SESSION_ID: &str = "test-session-123";

/// Read one HTTP request off the socket and return (headers_blob, body).
async fn read_request(stream: &mut tokio::net::TcpStream) -> (String, String) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    // Read until we have the full headers.
    let header_end = loop {
        let n = stream.read(&mut tmp).await.unwrap();
        if n == 0 {
            return (String::from_utf8_lossy(&buf).to_string(), String::new());
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
    };
    let headers = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let content_len = headers
        .lines()
        .find_map(|l| {
            let l = l.to_ascii_lowercase();
            l.strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap_or(0))
        })
        .unwrap_or(0);
    // Read the rest of the body if not already buffered.
    let mut body = buf[header_end..].to_vec();
    while body.len() < content_len {
        let n = stream.read(&mut tmp).await.unwrap();
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    (headers, String::from_utf8_lossy(&body).to_string())
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[tokio::test]
async fn sse_transport_connects_lists_and_calls() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}/mcp", addr);

    // Mock server: answer requests in the order the client makes them.
    let server = tokio::spawn(async move {
        let mut saw_session_echo = false;
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            let (headers, body) = read_request(&mut stream).await;
            let method = serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v.get("method").and_then(|m| m.as_str()).map(String::from))
                .unwrap_or_default();

            let response: String = match method.as_str() {
                "initialize" => {
                    // Reply over SSE and hand out a session id.
                    let payload = r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"mock","version":"1"}}}"#;
                    let sse = format!("event: message\ndata: {}\n\n", payload);
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nMcp-Session-Id: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        SESSION_ID,
                        sse.len(),
                        sse
                    )
                }
                "notifications/initialized" => {
                    "HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
                }
                "tools/list" => {
                    // The client must echo the session id from initialize.
                    if headers.to_ascii_lowercase().contains(&format!("mcp-session-id: {}", SESSION_ID)) {
                        saw_session_echo = true;
                    }
                    let payload = r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","description":"Echo back the message","inputSchema":{"type":"object","properties":{"msg":{"type":"string"}},"required":["msg"]}}]}}"#;
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        payload.len(),
                        payload
                    )
                }
                "tools/call" => {
                    let payload = r#"{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"pong"}]}}"#;
                    let done = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        payload.len(),
                        payload
                    );
                    // Write final response, then stop the server.
                    stream.write_all(done.as_bytes()).await.unwrap();
                    stream.flush().await.unwrap();
                    return saw_session_echo;
                }
                _ => "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
            };

            stream.write_all(response.as_bytes()).await.unwrap();
            stream.flush().await.unwrap();
        }
        saw_session_echo
    });

    let mut mgr = McpClientManager::new();
    mgr.register(
        "mock",
        McpServerConfig {
            enabled: true,
            transport: "sse".into(),
            command: None,
            args: None,
            env: HashMap::new(),
            url: Some(url),
            headers: HashMap::new(),
        },
    );

    mgr.connect_server("mock").await.expect("connect over sse");

    // Tool discovered from the SSE/JSON handshake.
    let tools = mgr.list_tools();
    assert_eq!(tools.len(), 1, "expected 1 discovered tool");
    assert_eq!(tools[0].name, "echo");
    assert_eq!(tools[0].server_name, "mock");

    // Call the tool and read the result content.
    let result = mgr
        .call_tool("mock", "echo", &serde_json::json!({"msg": "ping"}))
        .await
        .expect("call tool over sse");
    let text = result
        .get("content")
        .and_then(|c| c.as_array())
        .and_then(|a| a.first())
        .and_then(|o| o.get("text"))
        .and_then(|t| t.as_str())
        .unwrap_or("");
    assert_eq!(text, "pong");

    // The server confirms the client echoed the session id on tools/list.
    let saw_session_echo = server.await.unwrap();
    assert!(saw_session_echo, "client did not echo Mcp-Session-Id");
}
