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
    /// Global fallback model id used when an agent doc has no `model_id`.
    /// Empty means "let the provider registry pick its own default_model".
    #[serde(default)]
    pub default_model: String,
    /// Estimated-token budget that triggers loop context compaction. There is
    /// no per-model context window stored anywhere, so this is a heuristic cap
    /// on the in-memory working set (env `HIVECYBER_CONTEXT_BUDGET`).
    #[serde(default = "default_context_budget")]
    pub context_token_budget: usize,
}

fn default_context_budget() -> usize {
    24_000
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolsConfig {
    pub worker_pool: WorkerPoolConfig,
    pub exec: ExecConfig,
    /// How long a task's `$HIVECYBER_HOME/scratch/<task_id>/` dir survives
    /// after the task reaches a terminal status, before `DispatchLoop`'s
    /// maintenance tick reaps it. Does not apply to `findings/`/`reports/`
    /// (engagement-scoped, persistent, never reaped by this mechanism).
    #[serde(default = "default_scratch_retention_hours")]
    pub scratch_retention_hours: u64,
}

fn default_scratch_retention_hours() -> u64 {
    24
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
        // Explicit `HIVECYBER_HOME` wins (docs and operators expect it to), then
        // the OS data dir, then a home-relative fallback. Previously ProjectDirs
        // came first and silently ignored HIVECYBER_HOME, breaking test isolation
        // and any operator relying on the env var.
        let home = std::env::var("HIVECYBER_HOME").unwrap_or_else(|_| {
            directories::ProjectDirs::from("ai", "hivecyber", "hivecyber")
                .map(|d| d.data_dir().to_string_lossy().to_string())
                .unwrap_or_else(|| format!("{}/.hivecyber", dirs_home()))
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
                default_model: std::env::var("HIVECYBER_DEFAULT_MODEL").unwrap_or_default(),
                context_token_budget: std::env::var("HIVECYBER_CONTEXT_BUDGET")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(default_context_budget),
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
                scratch_retention_hours: std::env::var("HIVECYBER_SCRATCH_RETENTION_HOURS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(default_scratch_retention_hours),
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