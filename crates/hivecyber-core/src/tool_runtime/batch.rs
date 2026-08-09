use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolBatchResult {
    pub tool_name: String,
    pub success: bool,
    pub result: serde_json::Value,
    pub duration_ms: u64,
    pub error: Option<String>,
}

pub async fn execute_tool_batch(
    tool_calls: Vec<(String, serde_json::Value)>,
    registry: &hivecyber_tools::ToolRegistry,
    timeout_ms: u64,
) -> Vec<ToolBatchResult> {
    let mut results = Vec::new();

    for (tool_name, args) in tool_calls {
        let start = std::time::Instant::now();

        let result = match registry.get(&tool_name) {
            Some(tool) => {
                let tool = tool.clone() as Arc<dyn hivecyber_tools::Tool>;
                match tokio::time::timeout(
                    std::time::Duration::from_millis(timeout_ms),
                    tool.execute(args.clone()),
                ).await {
                    Ok(Ok(r)) => ToolBatchResult {
                        tool_name,
                        success: true,
                        result: r,
                        duration_ms: start.elapsed().as_millis() as u64,
                        error: None,
                    },
                    Ok(Err(e)) => ToolBatchResult {
                        tool_name,
                        success: false,
                        result: serde_json::Value::Null,
                        duration_ms: start.elapsed().as_millis() as u64,
                        error: Some(e.to_string()),
                    },
                    Err(_) => ToolBatchResult {
                        tool_name,
                        success: false,
                        result: serde_json::Value::Null,
                        duration_ms: start.elapsed().as_millis() as u64,
                        error: Some(format!("timeout after {}ms", timeout_ms)),
                    },
                }
            }
            None => ToolBatchResult {
                tool_name: tool_name.clone(),
                success: false,
                result: serde_json::Value::Null,
                duration_ms: start.elapsed().as_millis() as u64,
                error: Some(format!("tool '{}' not in registry", tool_name)),
            },
        };

        results.push(result);
    }

    results
}