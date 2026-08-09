use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub home_dir: String,
    pub gateway: GatewayConfig,
    pub models: ModelsConfig,
    pub tools: ToolsConfig,
    pub skills: SkillsConfig,
    pub mcp: McpConfig,
    pub security: SecurityConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelsConfig {
    pub default_provider: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolsConfig {
    pub worker_pool: WorkerPoolConfig,
    pub exec: ExecConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerPoolConfig {
    pub enabled: bool,
    pub max_workers: usize,
    pub tool_timeout_ms: u64,
    pub parallel_tool_calls: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecConfig {
    pub enabled: bool,
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillsConfig {
    pub allow_bundled: bool,
    pub managed_dir: String,
    pub hot_reload: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpConfig {
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub unsafe_default: bool,
    pub audit_log_enabled: bool,
    pub exploit_session_timeout_min: u64,
    pub max_message_length: usize,
}

impl Default for Config {
    fn default() -> Self {
        let home = directories::ProjectDirs::from("ai", "hivecyber", "hivecyber")
            .map(|d| d.data_dir().to_string_lossy().to_string())
            .unwrap_or_else(|| {
                std::env::var("HIVECYBER_HOME").unwrap_or_else(|_| {
                    format!("{}/.hivecyber", dirs_home())
                })
            });

        Config {
            home_dir: home.clone(),
            gateway: GatewayConfig {
                host: std::env::var("HIVECYBER_HOST").unwrap_or_else(|_| "127.0.0.1".into()),
                port: std::env::var("HIVECYBER_PORT")
                    .ok()
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(18791),
            },
            models: ModelsConfig {
                default_provider: std::env::var("HIVECYBER_DEFAULT_PROVIDER")
                    .unwrap_or_else(|_| "anthropic".into()),
            },
            tools: ToolsConfig {
                worker_pool: WorkerPoolConfig {
                    enabled: true,
                    max_workers: num_workers(),
                    tool_timeout_ms: 300_000,
                    parallel_tool_calls: true,
                },
                exec: ExecConfig {
                    enabled: true,
                    timeout_seconds: 30,
                },
            },
            skills: SkillsConfig {
                allow_bundled: true,
                managed_dir: format!("{}/skills", home.clone()),
                hot_reload: true,
            },
            mcp: McpConfig {
                enabled: std::env::var("HIVECYBER_MCP_ENABLED")
                    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                    .unwrap_or(true),
            },
            security: SecurityConfig {
                unsafe_default: false,
                audit_log_enabled: true,
                exploit_session_timeout_min: 15,
                max_message_length: 100_000,
            },
        }
    }
}

fn num_workers() -> usize {
    std::thread::available_parallelism()
        .map(|n| std::cmp::min(4, n.get()))
        .unwrap_or(2)
}

fn dirs_home() -> String {
    std::env::var("HOME").unwrap_or_else(|_| "/tmp".into())
}

pub fn load() -> Config {
    let mut config = Config::default();

    if let Ok(home) = std::env::var("HIVECYBER_HOME") {
        let expanded = expand_tilde(&home);
        config.home_dir = expanded.clone();
        config.skills.managed_dir = format!("{}/skills", expanded);
    }

    config
}

fn expand_tilde(path: &str) -> String {
    if path.starts_with("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{}{}", home, &path[1..]);
        }
    }
    path.to_string()
}