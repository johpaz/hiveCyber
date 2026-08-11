use std::collections::HashMap;
use std::sync::Arc;

use crate::traits::*;

pub struct ProviderRegistry {
    configs: Vec<ProviderConfig>,
}

struct ProviderConfig {
    id: String,
    base_url: String,
    default_model: String,
    api_key_env: String,
    custom: bool,
}

impl ProviderRegistry {
    pub fn new() -> Self {
        let configs = vec![
            ProviderConfig {
                id: "anthropic".into(),
                base_url: "https://api.anthropic.com".into(),
                default_model: "claude-sonnet-5".into(),
                api_key_env: "ANTHROPIC_API_KEY".into(),
                custom: true,
            },
            ProviderConfig {
                id: "openai".into(),
                base_url: "https://api.openai.com".into(),
                default_model: "gpt-4o".into(),
                api_key_env: "OPENAI_API_KEY".into(),
                custom: false,
            },
            ProviderConfig {
                id: "gemini".into(),
                base_url: "https://generativelanguage.googleapis.com".into(),
                default_model: "gemini-3.6-flash".into(),
                api_key_env: "GEMINI_API_KEY".into(),
                custom: true,
            },
            ProviderConfig {
                id: "ollama".into(),
                base_url: "http://localhost:11434".into(),
                default_model: "llama3.2".into(),
                api_key_env: "OLLAMA_API_KEY".into(),
                custom: true,
            },
            ProviderConfig {
                id: "groq".into(),
                base_url: "https://api.groq.com/openai/v1".into(),
                default_model: "llama-3.3-70b-versatile".into(),
                api_key_env: "GROQ_API_KEY".into(),
                custom: false,
            },
            ProviderConfig {
                id: "mistral".into(),
                base_url: "https://api.mistral.ai/v1".into(),
                default_model: "mistral-large-latest".into(),
                api_key_env: "MISTRAL_API_KEY".into(),
                custom: false,
            },
            ProviderConfig {
                id: "openrouter".into(),
                base_url: "https://openrouter.ai/api/v1".into(),
                default_model: "anthropic/claude-sonnet-4".into(),
                api_key_env: "OPENROUTER_API_KEY".into(),
                custom: false,
            },
            ProviderConfig {
                id: "deepseek".into(),
                base_url: "https://api.deepseek.com/v1".into(),
                default_model: "deepseek-chat".into(),
                api_key_env: "DEEPSEEK_API_KEY".into(),
                custom: false,
            },
            ProviderConfig {
                id: "kimi".into(),
                base_url: "https://api.moonshot.ai/v1".into(),
                default_model: "kimi-k2.5".into(),
                api_key_env: "KIMI_API_KEY".into(),
                custom: false,
            },
            ProviderConfig {
                id: "nvidia".into(),
                base_url: "https://integrate.api.nvidia.com/v1".into(),
                default_model: "meta/llama-3.1-405b-instruct".into(),
                api_key_env: "NVIDIA_API_KEY".into(),
                custom: false,
            },
            ProviderConfig {
                id: "qwen".into(),
                base_url: "https://dashscope-intl.aliyuncs.com/compatible-mode/v1".into(),
                default_model: "qwen-max".into(),
                api_key_env: "QWEN_API_KEY".into(),
                custom: false,
            },
            ProviderConfig {
                id: "minimax".into(),
                base_url: "https://api.minimaxi.com/v1".into(),
                default_model: "abab6.5s-chat".into(),
                api_key_env: "MINIMAX_API_KEY".into(),
                custom: false,
            },
            ProviderConfig {
                id: "z-ai".into(),
                base_url: "https://api.z.ai/api/paas/v4".into(),
                default_model: "glm-4-plus".into(),
                api_key_env: "ZAI_API_KEY".into(),
                custom: false,
            },
            ProviderConfig {
                id: "modelscope".into(),
                base_url: "https://api-inference.modelscope.ai/v1".into(),
                default_model: "Qwen/Qwen2.5-72B-Instruct".into(),
                api_key_env: "MODELSCOPE_API_KEY".into(),
                custom: false,
            },
            ProviderConfig {
                id: "opencode-go".into(),
                base_url: "https://opencode.ai/zen/go/v1".into(),
                default_model: "kimi-k2.6".into(),
                api_key_env: "OPENCODE_GO_API_KEY".into(),
                custom: false,
            },
            ProviderConfig {
                id: "hiveagents".into(),
                base_url: "https://llm.hiveagents.io/v1".into(),
                default_model: "hive-max".into(),
                api_key_env: "HIVEAGENTS_API_KEY".into(),
                custom: false,
            },
        ];

        ProviderRegistry { configs }
    }

    pub fn list_providers(&self) -> Vec<String> {
        self.configs.iter().map(|c| c.id.clone()).collect()
    }

    /// Override a provider's base URL and/or default model at runtime (from
    /// persisted settings written by `provider set`). Unknown provider ids and
    /// `None` fields are ignored, so callers can pass partial overrides.
    pub fn apply_override(
        &mut self,
        provider_id: &str,
        base_url: Option<String>,
        default_model: Option<String>,
    ) {
        if let Some(cfg) = self.configs.iter_mut().find(|c| c.id == provider_id) {
            if let Some(url) = base_url {
                if !url.is_empty() {
                    cfg.base_url = url;
                }
            }
            if let Some(model) = default_model {
                if !model.is_empty() {
                    cfg.default_model = model;
                }
            }
        }
    }

    /// The default model id configured for a provider (built-in or overridden).
    pub fn default_model_for(&self, provider_id: &str) -> Option<String> {
        self.configs
            .iter()
            .find(|c| c.id == provider_id)
            .map(|c| c.default_model.clone())
    }

    pub fn get(
        &self,
        provider_id: &str,
        model: &str,
        api_key: &str,
    ) -> Option<Arc<dyn LlmProvider>> {
        let cfg = self
            .configs
            .iter()
            .find(|c| c.id == provider_id)?;

        let model = if model.is_empty() {
            cfg.default_model.clone()
        } else {
            model.to_string()
        };

        if cfg.custom {
            match cfg.id.as_str() {
                "anthropic" => Some(Arc::new(crate::anthropic::AnthropicProvider::new(api_key, &model))),
                "gemini" => Some(Arc::new(crate::gemini::GeminiProvider::new(api_key, &model))),
                "ollama" => Some(Arc::new(crate::ollama::OllamaProvider::new(
                    &model,
                    Some(&cfg.base_url),
                ))),
                _ => Some(Arc::new(crate::openai_compat::OpenAiCompatProvider::new(
                    api_key,
                    &model,
                    &cfg.base_url,
                ))),
            }
        } else {
            Some(Arc::new(crate::openai_compat::OpenAiCompatProvider::new(
                api_key,
                &model,
                &cfg.base_url,
            )))
        }
    }

    pub fn get_default_api_key(provider_id: &str) -> Option<String> {
        let env_map: HashMap<&str, &str> = [
            ("anthropic", "ANTHROPIC_API_KEY"),
            ("openai", "OPENAI_API_KEY"),
            ("gemini", "GOOGLE_API_KEY"),
            ("ollama", "OLLAMA_API_KEY"),
            ("groq", "GROQ_API_KEY"),
            ("mistral", "MISTRAL_API_KEY"),
            ("openrouter", "OPENROUTER_API_KEY"),
            ("deepseek", "DEEPSEEK_API_KEY"),
            ("kimi", "KIMI_API_KEY"),
            ("nvidia", "NVIDIA_API_KEY"),
            ("qwen", "QWEN_API_KEY"),
            ("minimax", "MINIMAX_API_KEY"),
            ("z-ai", "ZAI_API_KEY"),
            ("modelscope", "MODELSCOPE_API_KEY"),
            ("opencode-go", "OPENCODE_GO_API_KEY"),
            ("hiveagents", "HIVEAGENTS_API_KEY"),
        ]
        .into_iter()
        .collect();

        env_map
            .get(provider_id)
            .and_then(|env| std::env::var(env).ok())
            .or_else(|| {
                if provider_id == "gemini" {
                    std::env::var("GOOGLE_API_KEY").ok()
                } else {
                    None
                }
            })
    }
}