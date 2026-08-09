use anyhow::Result;

use crate::store::HiveDb;
use crate::config::Config;

pub struct LlmClient {
    pub provider: String,
    pub model: String,
    pub api_key: String,
}

pub fn resolve_provider_config(
    db: &HiveDb,
    agent: &serde_json::Value,
    config: &Config,
) -> (String, String, String) {
    let provider = agent
        .get("provider_id")
        .and_then(|v| v.as_str())
        .unwrap_or(&config.models.default_provider);

    let model = agent
        .get("model_id")
        .and_then(|v| v.as_str())
        .unwrap_or(default_model_for(provider));

    let api_key = api_key_for(provider).unwrap_or_default();

    (provider.to_string(), model.to_string(), api_key)
}

fn default_model_for(provider: &str) -> &str {
    match provider {
        "anthropic" => "claude-sonnet-4-20250514",
        "openai" => "gpt-4o",
        "gemini" => "gemini-2.0-flash",
        "ollama" => "llama3.2",
        "groq" => "llama-3.3-70b-versatile",
        _ => "gpt-4o",
    }
}

fn api_key_for(provider: &str) -> Option<String> {
    let key = match provider {
        "anthropic" => "ANTHROPIC_API_KEY",
        "openai" => "OPENAI_API_KEY",
        "gemini" => "GOOGLE_API_KEY",
        "ollama" => "OLLAMA_API_KEY",
        "groq" => "GROQ_API_KEY",
        "mistral" => "MISTRAL_API_KEY",
        "openrouter" => "OPENROUTER_API_KEY",
        "deepseek" => "DEEPSEEK_API_KEY",
        _ => return std::env::var("ANTHROPIC_API_KEY").ok(),
    };
    std::env::var(key).ok()
}

pub async fn _get_default_llm() -> Result<(String, String, String)> {
    Ok((
        "anthropic".into(),
        "claude-sonnet-4-20250514".into(),
        std::env::var("ANTHROPIC_API_KEY").unwrap_or_default(),
    ))
}