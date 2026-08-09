use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex;
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub transport: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,
    #[serde(default)]
    pub env: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpConfig {
    pub servers: HashMap<String, McpServerConfig>,
}

#[derive(Debug, Clone)]
pub struct McpTool {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
    pub server_name: String,
}

#[derive(Debug, Clone)]
pub struct McpServerState {
    pub name: String,
    pub config: McpServerConfig,
    pub status: String,
    pub tools: Vec<McpTool>,
    pub last_error: Option<String>,
}

struct StdioConnection {
    child: Child,
    stdin: ChildStdin,
    stdout: Arc<Mutex<BufReader<ChildStdout>>>,
}

pub struct McpClientManager {
    servers: HashMap<String, McpServerState>,
    conns: HashMap<String, Arc<Mutex<StdioConnection>>>,
    req_id: Arc<Mutex<u64>>,
}

impl McpClientManager {
    pub fn new() -> Self {
        McpClientManager {
            servers: HashMap::new(),
            conns: HashMap::new(),
            req_id: Arc::new(Mutex::new(0)),
        }
    }

    pub fn register(&mut self, name: &str, config: McpServerConfig) {
        self.servers.insert(
            name.to_string(),
            McpServerState {
                name: name.to_string(),
                config,
                status: "disconnected".into(),
                tools: Vec::new(),
                last_error: None,
            },
        );
    }

    pub async fn connect_server(&mut self, name: &str) -> Result<()> {
        let config = self
            .servers
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("server not registered: {}", name))?
            .config
            .clone();

        if config.transport != "stdio" {
            if let Some(state) = self.servers.get_mut(name) {
                state.status = "connected".into();
            }
            info!("MCP server '{}' ({} transport) stubbed", name, config.transport);
            return Ok(());
        }

        let command = config
            .command
            .clone()
            .ok_or_else(|| anyhow::anyhow!("stdio transport requires command"))?;
        let args = config.args.clone().unwrap_or_default();

        let mut env: HashMap<String, String> = std::env::vars().collect();
        for (k, v) in &config.env {
            env.insert(k.clone(), v.clone());
        }

        info!("MCP server '{}' connecting via stdio: {} {:?}", name, command, args);

        let mut cmd = Command::new(&command);
        cmd.args(&args);
        cmd.envs(&env);
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::null());

        let mut child = cmd.spawn().with_context(|| format!("spawn {}", command))?;
        let stdin = child.stdin.take().context("no stdin")?;
        let stdout = child.stdout.take().context("no stdout")?;
        let reader = Arc::new(Mutex::new(BufReader::new(stdout)));

        let conn = StdioConnection { child, stdin, stdout: reader };
        self.conns.insert(name.to_string(), Arc::new(Mutex::new(conn)));

        if let Some(state) = self.servers.get_mut(name) {
            state.status = "connecting".into();
            state.last_error = None;
        }

        let init_req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "hivecyber", "version": "0.1.0"},
            }
        });
        let _ = self.send_jsonrpc(name, &init_req).await?;

        let notif = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        });
        let _ = self.send_jsonrpc_notification(name, &notif).await?;

        let list_tools = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        });
        let resp = self.send_jsonrpc(name, &list_tools).await?;

        if let Some(tools_arr) = resp
            .get("result")
            .and_then(|r| r.get("tools"))
            .and_then(|t| t.as_array())
        {
            let tools: Vec<McpTool> = tools_arr
                .iter()
                .filter_map(|t| {
                    Some(McpTool {
                        name: t.get("name")?.as_str()?.to_string(),
                        description: t.get("description").and_then(|d| d.as_str()).unwrap_or("").to_string(),
                        parameters: t.get("inputSchema").cloned().unwrap_or(serde_json::Value::Null),
                        server_name: name.to_string(),
                    })
                })
                .collect();
            if let Some(state) = self.servers.get_mut(name) {
                state.tools = tools;
            }
        }

        if let Some(state) = self.servers.get_mut(name) {
            state.status = "connected".into();
        }

        info!(
            "MCP server '{}' connected with {} tools",
            name,
            self.servers.get(name).map(|s| s.tools.len()).unwrap_or(0)
        );
        Ok(())
    }

    pub async fn connect_all(&mut self) -> Vec<String> {
        let names: Vec<String> = self.servers.keys().cloned().collect();
        let mut errors = Vec::new();
        for name in names {
            if let Err(e) = self.connect_server(&name).await {
                errors.push(format!("{}: {}", name, e));
            }
        }
        errors
    }

    pub async fn disconnect_server(&mut self, name: &str) -> Result<()> {
        if let Some(conn) = self.conns.remove(name) {
            let mut c = conn.lock().await;
            let _ = c.child.kill().await;
        }
        if let Some(state) = self.servers.get_mut(name) {
            state.status = "disconnected".into();
            state.tools.clear();
        }
        Ok(())
    }

    pub async fn disconnect_all(&mut self) {
        let names: Vec<String> = self.servers.keys().cloned().collect();
        for name in names {
            let _ = self.disconnect_server(&name).await;
        }
    }

    pub async fn call_tool(
        &mut self,
        server: &str,
        tool: &str,
        args: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let next_id = {
            let mut counter = self.req_id.lock().await;
            *counter += 1;
            *counter
        };

        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": next_id,
            "method": "tools/call",
            "params": {
                "name": tool,
                "arguments": args,
            }
        });

        let resp = self.send_jsonrpc(server, &req).await?;

        if let Some(err) = resp.get("error") {
            return Err(anyhow::anyhow!("mcp error: {}", err));
        }

        Ok(resp.get("result").cloned().unwrap_or(serde_json::Value::Null))
    }

    async fn send_jsonrpc(&self, server: &str, req: &serde_json::Value) -> Result<serde_json::Value> {
        let conn = self
            .conns
            .get(server)
            .ok_or_else(|| anyhow::anyhow!("server not connected: {}", server))?
            .clone();

        let mut c = conn.lock().await;
        let json = serde_json::to_string(req)?;
        c.stdin.write_all(format!("{}\n", json).as_bytes()).await?;
        c.stdin.flush().await?;

        let mut reader = c.stdout.lock().await;
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        drop(reader);
        drop(c);

        serde_json::from_str(&line)
            .with_context(|| format!("parse mcp resp: {}", line.chars().take(200).collect::<String>()))
    }

    async fn send_jsonrpc_notification(&self, server: &str, req: &serde_json::Value) -> Result<()> {
        if let Some(conn) = self.conns.get(server) {
            let mut c = conn.lock().await;
            let json = serde_json::to_string(req)?;
            c.stdin.write_all(format!("{}\n", json).as_bytes()).await?;
            c.stdin.flush().await?;
        }
        Ok(())
    }

    pub fn list_servers(&self) -> Vec<&McpServerState> {
        self.servers.values().collect()
    }

    pub fn list_tools(&self) -> Vec<&McpTool> {
        self.servers.values().flat_map(|s| s.tools.iter()).collect()
    }
}

impl Default for McpClientManager {
    fn default() -> Self {
        Self::new()
    }
}