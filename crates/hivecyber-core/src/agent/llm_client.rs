use anyhow::Result;

use crate::config::Config;

pub struct LlmClient {
    pub provider: String,
    pub model: String,
    pub api_key: String,
}

/// Resolve (provider, model, api_key) for an agent, delegating model and
/// api-key resolution to the shared `ProviderRegistry` so there is exactly one
/// source of truth for provider defaults (same as `loop_runner` and
/// `harness/executors`). No hardcoded per-provider maps live here anymore.
pub fn resolve_provider_config(
    agent: &serde_json::Value,
    config: &Config,
) -> (String, String, String) {
    let provider = agent
        .get("provider_id")
        .and_then(|v| v.as_str())
        .unwrap_or(&config.models.default_provider)
        .to_string();

    // Agent model_id, else the global config default, else empty — an empty
    // model tells `ProviderRegistry::get` to use that provider's own
    // `default_model`.
    let model = agent
        .get("model_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(&config.models.default_model)
        .to_string();

    let api_key =
        hivecyber_providers::ProviderRegistry::get_default_api_key(&provider).unwrap_or_default();

    (provider, model, api_key)
}

pub async fn _get_default_llm(config: &Config) -> Result<(String, String, String)> {
    let provider = config.models.default_provider.clone();
    let model = config.models.default_model.clone();
    let api_key =
        hivecyber_providers::ProviderRegistry::get_default_api_key(&provider).unwrap_or_default();
    Ok((provider, model, api_key))
}
