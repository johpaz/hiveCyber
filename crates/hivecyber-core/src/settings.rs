//! Persisted operator settings — default provider/model and per-provider
//! overrides (base URL, model) written by the `provider` CLI commands.
//!
//! Stored as a single doc `global` in `COL_SETTINGS`. Environment variables
//! always win over persisted settings (12-factor: env is the explicit override),
//! so a host configured once via `provider default` runs with no env vars, yet a
//! developer can still override per-shell.

use std::collections::HashMap;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use hivecyber_providers::ProviderRegistry;

use crate::config::Config;
use crate::store::HiveDb;
use crate::store::collections::COL_SETTINGS;

const SETTINGS_ID: &str = "global";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProviderSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Settings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_model: Option<String>,
    #[serde(default)]
    pub providers: HashMap<String, ProviderSettings>,
}

impl Settings {
    pub async fn load(db: &HiveDb) -> Settings {
        db.get(COL_SETTINGS, SETTINGS_ID)
            .await
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_default()
    }

    pub async fn save(&self, db: &HiveDb) -> Result<()> {
        db.insert(COL_SETTINGS, SETTINGS_ID, serde_json::to_value(self)?).await
    }

    pub fn provider_entry(&mut self, id: &str) -> &mut ProviderSettings {
        self.providers.entry(id.to_string()).or_default()
    }

    /// Fold persisted defaults into a `Config`, without clobbering values that
    /// were explicitly set through environment variables.
    pub fn apply_to_config(&self, config: &mut Config) {
        if std::env::var("HIVECYBER_DEFAULT_PROVIDER").is_err() {
            if let Some(p) = &self.default_provider {
                config.models.default_provider = p.clone();
            }
        }
        if std::env::var("HIVECYBER_DEFAULT_MODEL").is_err() {
            // Prefer an explicit global default_model; else the chosen provider's
            // per-provider model hint.
            if let Some(m) = &self.default_model {
                config.models.default_model = m.clone();
            } else if let Some(ps) = self.providers.get(&config.models.default_provider) {
                if let Some(m) = &ps.model {
                    config.models.default_model = m.clone();
                }
            }
        }
    }

    /// Build a provider registry with this settings' per-provider overrides
    /// applied (base URL / default model).
    pub fn build_registry(&self) -> ProviderRegistry {
        let mut registry = ProviderRegistry::new();
        for (id, ps) in &self.providers {
            registry.apply_override(id, ps.base_url.clone(), ps.model.clone());
        }
        registry
    }
}

/// Convenience: load settings and build the override-aware registry.
pub async fn registry_for(db: &HiveDb) -> ProviderRegistry {
    Settings::load(db).await.build_registry()
}
