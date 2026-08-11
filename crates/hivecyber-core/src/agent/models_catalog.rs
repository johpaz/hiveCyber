//! LLM model catalog — Rust mirror of Hive's `storage/seed.ts` `models` array.
//!
//! Single source of truth for provider, context window and cost (USD/1M tokens).
//! Seeded into `COL_MODELS`; the compaction budget is derived from `context_window`
//! and `hivecyber models` lists it. Generated from Hive — keep in sync with the
//! providers registry ([[providers-match-hive]]).

use crate::store::HiveDb;
use crate::store::collections::{ModelDoc, COL_MODELS};

/// Fraction of a model's context window reserved for the input working set; the
/// rest is left for output + overhead. Compaction triggers past this.
const INPUT_BUDGET_RATIO: f64 = 0.70;

/// Derive the compaction token budget from the model's real context window
/// (looked up in `COL_MODELS`). Falls back to `fallback` when the model is not
/// in the catalog or has no context window (custom / local models).
pub async fn resolve_context_budget(
    db: &HiveDb,
    provider_id: &str,
    model_id: &str,
    fallback: usize,
) -> usize {
    if model_id.is_empty() {
        return fallback;
    }
    let key = format!("{}::{}", provider_id, model_id);
    if let Some(doc) = db.get(COL_MODELS, &key).await {
        if let Some(ctx) = doc.get("context_window").and_then(|v| v.as_u64()) {
            if ctx > 0 {
                return ((ctx as f64) * INPUT_BUDGET_RATIO) as usize;
            }
        }
    }
    fallback
}

/// Upsert the built-in catalog into `COL_MODELS` (best-effort). Operator edits to
/// individual docs are overwritten on the next sync — the catalog is the source
/// of truth, same contract as Hive's reseed.
pub async fn sync_catalog(db: &HiveDb) {
    for md in model_catalog() {
        if let Ok(v) = serde_json::to_value(&md) {
            let _ = db.insert(COL_MODELS, &md.id, v).await;
        }
    }
}

fn m(
    model_id: &str,
    provider_id: &str,
    name: &str,
    context_window: u32,
    input_per_1m: f64,
    output_per_1m: f64,
    capabilities: &[&str],
) -> ModelDoc {
    ModelDoc {
        id: format!("{}::{}", provider_id, model_id),
        model_id: model_id.to_string(),
        provider_id: provider_id.to_string(),
        name: name.to_string(),
        model_type: "llm".to_string(),
        context_window,
        input_per_1m,
        output_per_1m,
        capabilities: capabilities.iter().map(|s| s.to_string()).collect(),
    }
}

/// The full LLM model catalog (89 models, mirror of Hive).
pub fn model_catalog() -> Vec<ModelDoc> {
    vec![
        m("claude-opus-5", "anthropic", "Claude Opus 5", 1000000, 5.0, 25.0, &["chat", "vision", "json_mode", "function_calling", "streaming", "code", "reasoning"]),
        m("claude-sonnet-5", "anthropic", "Claude Sonnet 5", 1000000, 3.0, 15.0, &["chat", "vision", "json_mode", "function_calling", "streaming", "code", "reasoning"]),
        m("claude-fable-5", "anthropic", "Claude Fable 5", 1000000, 10.0, 50.0, &["chat", "vision", "json_mode", "function_calling", "streaming", "code", "reasoning"]),
        m("claude-haiku-4-5-20251001", "anthropic", "Claude Haiku 4.5", 200000, 1.0, 5.0, &["chat", "vision", "json_mode", "function_calling", "streaming", "reasoning"]),
        m("gpt-5.6-luna", "openai", "GPT-5.6 Luna", 1050000, 0.1, 0.6, &["chat", "vision", "json_mode", "function_calling", "streaming", "code", "reasoning"]),
        m("gpt-5.6-terra", "openai", "GPT-5.6 Terra", 1050000, 1.0, 6.0, &["chat", "vision", "json_mode", "function_calling", "streaming", "code", "reasoning"]),
        m("gpt-5.6-sol", "openai", "GPT-5.6 Sol", 1050000, 5.0, 30.0, &["chat", "vision", "json_mode", "function_calling", "streaming", "code", "reasoning"]),
        m("gemini-3.6-flash", "gemini", "Gemini 3.6 Flash", 1048576, 1.5, 7.5, &["chat", "vision", "json_mode", "function_calling", "streaming", "reasoning"]),
        m("gemini-3.5-flash", "gemini", "Gemini 3.5 Flash", 1048576, 1.5, 9.0, &["chat", "vision", "json_mode", "function_calling", "streaming", "reasoning"]),
        m("gemini-3.5-flash-lite", "gemini", "Gemini 3.5 Flash Lite", 1048576, 0.3, 2.5, &["chat", "vision", "json_mode", "function_calling", "streaming"]),
        m("gemini-3.1-pro-preview", "gemini", "Gemini 3.1 Pro Preview", 1048576, 2.0, 12.0, &["chat", "vision", "json_mode", "function_calling", "streaming", "reasoning"]),
        m("gemini-3.1-flash-lite", "gemini", "Gemini 3.1 Flash Lite", 1048576, 0.25, 1.5, &["chat", "vision", "json_mode", "function_calling", "streaming"]),
        m("mistral-large-2512", "mistral", "Mistral Large 2512", 262144, 0.5, 1.5, &["chat", "vision", "json_mode", "function_calling", "streaming"]),
        m("devstral-2512", "mistral", "Devstral 2512", 262144, 0.4, 2.0, &["chat", "code", "function_calling", "streaming"]),
        m("ministral-14b-2512", "mistral", "Ministral 14B", 262144, 0.2, 0.2, &["chat", "json_mode", "function_calling", "streaming"]),
        m("ministral-8b-2512", "mistral", "Ministral 8B", 262144, 0.15, 0.15, &["chat", "json_mode", "function_calling", "streaming"]),
        m("codestral-2508", "mistral", "Codestral 2508", 262144, 0.2, 0.6, &["chat", "code", "function_calling", "streaming"]),
        m("mistral-small-3.2-24b-instruct", "mistral", "Mistral Small 3.2 24B", 131072, 0.1, 0.3, &["chat", "json_mode", "function_calling", "streaming"]),
        m("mistral-large-latest", "mistral", "Mistral Large (latest)", 262144, 0.5, 1.5, &["chat", "vision", "json_mode", "function_calling", "streaming"]),
        m("codestral-latest", "mistral", "Codestral (latest)", 262144, 0.2, 0.6, &["chat", "code", "function_calling", "streaming"]),
        m("deepseek-v4-pro", "deepseek", "DeepSeek V4 Pro", 1000000, 0.435, 0.87, &["chat", "json_mode", "function_calling", "streaming", "code", "reasoning"]),
        m("deepseek-v4-flash", "deepseek", "DeepSeek V4 Flash", 1000000, 0.14, 0.28, &["chat", "json_mode", "function_calling", "streaming", "code", "reasoning"]),
        m("kimi-k3", "kimi", "Kimi K3", 1000000, 3.0, 15.0, &["chat", "vision", "json_mode", "function_calling", "streaming", "code", "reasoning"]),
        m("kimi-k2.7-code", "kimi", "Kimi K2.7 Code", 262144, 0.73, 3.5, &["chat", "vision", "json_mode", "function_calling", "streaming", "code"]),
        m("kimi-k2.6", "kimi", "Kimi K2.6", 262144, 0.6, 3.41, &["chat", "vision", "json_mode", "function_calling", "streaming", "code"]),
        m("anthropic/claude-opus-5", "openrouter", "Claude Opus 5 (OR)", 1000000, 5.0, 25.0, &["chat", "vision", "json_mode", "function_calling", "streaming", "code", "reasoning"]),
        m("anthropic/claude-sonnet-5", "openrouter", "Claude Sonnet 5 (OR)", 1000000, 2.0, 10.0, &["chat", "vision", "json_mode", "function_calling", "streaming", "code", "reasoning"]),
        m("openai/gpt-5.6-sol", "openrouter", "GPT-5.6 Sol (OR)", 1050000, 5.0, 30.0, &["chat", "vision", "json_mode", "function_calling", "streaming", "code", "reasoning"]),
        m("openai/gpt-5.6-terra", "openrouter", "GPT-5.6 Terra (OR)", 1050000, 1.0, 6.0, &["chat", "vision", "json_mode", "function_calling", "streaming", "code"]),
        m("openai/gpt-5.6-luna", "openrouter", "GPT-5.6 Luna (OR)", 1050000, 0.1, 0.6, &["chat", "vision", "json_mode", "function_calling", "streaming"]),
        m("google/gemini-3.6-flash", "openrouter", "Gemini 3.6 Flash (OR)", 1048576, 1.5, 7.5, &["chat", "vision", "json_mode", "function_calling", "streaming", "reasoning"]),
        m("google/gemini-3.5-flash", "openrouter", "Gemini 3.5 Flash (OR)", 1048576, 1.5, 9.0, &["chat", "vision", "json_mode", "function_calling", "streaming", "reasoning"]),
        m("google/gemini-3.1-pro-preview", "openrouter", "Gemini 3.1 Pro (OR)", 1048576, 2.0, 12.0, &["chat", "vision", "json_mode", "function_calling", "streaming", "reasoning"]),
        m("deepseek/deepseek-v4-pro", "openrouter", "DeepSeek V4 Pro (OR)", 1048576, 0.435, 0.87, &["chat", "json_mode", "function_calling", "streaming", "code", "reasoning"]),
        m("deepseek/deepseek-v4-flash", "openrouter", "DeepSeek V4 Flash (OR)", 1048576, 0.14, 0.28, &["chat", "json_mode", "function_calling", "streaming", "code"]),
        m("moonshotai/kimi-k3", "openrouter", "Kimi K3 (OR)", 1048576, 3.0, 15.0, &["chat", "vision", "json_mode", "function_calling", "streaming", "code", "reasoning"]),
        m("moonshotai/kimi-k2.7-code", "openrouter", "Kimi K2.7 Code (OR)", 262144, 0.73, 3.5, &["chat", "vision", "json_mode", "function_calling", "streaming", "code"]),
        m("minimax/minimax-m3", "openrouter", "MiniMax M3 (OR)", 1048576, 0.3, 1.2, &["chat", "vision", "json_mode", "function_calling", "streaming", "code", "reasoning"]),
        m("z-ai/glm-5.2", "openrouter", "GLM 5.2 (OR)", 1048576, 0.63, 1.98, &["chat", "json_mode", "function_calling", "streaming", "code", "reasoning"]),
        m("qwen/qwen3.8-max", "openrouter", "Qwen3.8 Max (OR)", 1000000, 2.0, 6.0, &["chat", "json_mode", "function_calling", "streaming", "reasoning"]),
        m("qwen/qwen3.7-flash", "openrouter", "Qwen3.7 Flash (OR)", 1000000, 0.03, 0.13, &["chat", "json_mode", "function_calling", "streaming"]),
        m("x-ai/grok-4.5", "openrouter", "Grok 4.5 (OR)", 500000, 2.0, 6.0, &["chat", "vision", "json_mode", "function_calling", "streaming", "reasoning"]),
        m("mistralai/mistral-medium-3-5", "openrouter", "Mistral Medium 3.5 (OR)", 262144, 1.5, 7.5, &["chat", "json_mode", "function_calling", "streaming", "code"]),
        m("llama-3.3-70b-versatile", "groq", "Llama 3.3 70B", 131072, 0.59, 0.79, &["chat", "json_mode", "function_calling", "streaming"]),
        m("llama-3.1-8b-instant", "groq", "Llama 3.1 8B Instant", 131072, 0.05, 0.08, &["chat", "json_mode", "function_calling", "streaming"]),
        m("openai/gpt-oss-120b", "groq", "GPT OSS 120B", 131072, 0.15, 0.6, &["chat", "json_mode", "function_calling", "streaming", "code"]),
        m("openai/gpt-oss-20b", "groq", "GPT OSS 20B", 131072, 0.075, 0.3, &["chat", "json_mode", "function_calling", "streaming"]),
        m("groq/compound", "groq", "Groq Compound", 131072, 0.0, 0.0, &["chat", "json_mode", "function_calling", "streaming"]),
        m("groq/compound-mini", "groq", "Groq Compound Mini", 131072, 0.0, 0.0, &["chat", "json_mode", "function_calling", "streaming"]),
        m("moonshotai/kimi-k2-instruct-0905", "groq", "Kimi K2 (Groq)", 262144, 0.45, 2.2, &["chat", "json_mode", "function_calling", "streaming", "code"]),
        m("qwen/qwen3-32b", "groq", "Qwen3 32B (Groq)", 128000, 0.0, 0.0, &["chat", "json_mode", "function_calling", "streaming", "reasoning"]),
        m("qwen3.7-max", "qwen", "Qwen 3.7 Max", 1000000, 1.475, 4.425, &["chat", "vision", "json_mode", "function_calling", "streaming", "reasoning"]),
        m("qwen3.7-plus", "qwen", "Qwen 3.7 Plus", 1000000, 0.32, 1.28, &["chat", "vision", "json_mode", "function_calling", "streaming", "reasoning"]),
        m("qwen3.6-flash", "qwen", "Qwen 3.6 Flash", 1000000, 0.1875, 1.125, &["chat", "json_mode", "function_calling", "streaming"]),
        m("qwen3.5-omni-plus", "qwen", "Qwen 3.5 Omni Plus", 131072, 0.32, 1.28, &["chat", "json_mode", "function_calling", "streaming"]),
        m("z-ai/glm-5.2", "nvidia", "GLM 5.2 (NVIDIA)", 200000, 0.0, 0.0, &["chat", "code", "json_mode", "function_calling", "streaming", "reasoning"]),
        m("moonshotai/kimi-k2.6", "nvidia", "Kimi K2.6 (NVIDIA)", 262144, 0.0, 0.0, &["chat", "code", "vision", "function_calling", "streaming", "reasoning"]),
        m("minimaxai/minimax-m3", "nvidia", "MiniMax M3 (NVIDIA)", 1000000, 0.0, 0.0, &["chat", "code", "vision", "json_mode", "function_calling", "streaming", "reasoning"]),
        m("nvidia/nemotron-3-ultra-550b-a55b", "nvidia", "Nemotron 3 Ultra 550B", 1000000, 0.0, 0.0, &["chat", "code", "json_mode", "function_calling", "streaming", "reasoning"]),
        m("nvidia/nemotron-3-super-120b-a12b", "nvidia", "Nemotron 3 Super 120B", 1000000, 0.0, 0.0, &["chat", "code", "json_mode", "function_calling", "streaming", "reasoning"]),
        m("deepseek-ai/deepseek-v4-pro", "nvidia", "DeepSeek V4 Pro (NVIDIA)", 1000000, 0.0, 0.0, &["chat", "code", "json_mode", "function_calling", "streaming", "reasoning"]),
        m("Qwen-Ambassador/Qwen3.8-Max", "modelscope", "Qwen3.8 Max (Embajador)", 1000000, 0.0, 0.0, &["chat", "code", "vision", "json_mode", "function_calling", "streaming", "reasoning"]),
        m("Qwen-Ambassador/Qwen3.7-Max", "modelscope", "Qwen3.7 Max (Embajador)", 1000000, 0.0, 0.0, &["chat", "code", "vision", "json_mode", "function_calling", "streaming", "reasoning"]),
        m("Qwen-Ambassador/Qwen3.7-Plus", "modelscope", "Qwen3.7 Plus (Embajador)", 1000000, 0.0, 0.0, &["chat", "code", "vision", "json_mode", "function_calling", "streaming", "reasoning"]),
        m("Qwen/Qwen3.5-397B-A17B", "modelscope", "Qwen3.5 397B (ModelScope)", 262144, 0.0, 0.0, &["chat", "code", "json_mode", "function_calling", "streaming", "reasoning"]),
        m("Qwen/Qwen3-Next-80B-A3B-Instruct", "modelscope", "Qwen3 Next 80B (ModelScope)", 262144, 0.0, 0.0, &["chat", "code", "json_mode", "function_calling", "streaming"]),
        m("Qwen/Qwen3-Coder-30B-A3B-Instruct", "modelscope", "Qwen3 Coder 30B (ModelScope)", 262144, 0.0, 0.0, &["chat", "code", "json_mode", "function_calling", "streaming"]),
        m("Qwen/Qwen3-VL-235B-A22B-Instruct", "modelscope", "Qwen3 VL 235B (ModelScope)", 131072, 0.0, 0.0, &["chat", "vision", "json_mode", "function_calling", "streaming"]),
        m("MiniMax-M3", "minimax", "MiniMax M3", 1000000, 0.3, 1.2, &["chat", "code", "vision", "function_calling", "streaming", "reasoning"]),
        m("MiniMax-M2.7", "minimax", "MiniMax M2.7", 204800, 0.3, 1.2, &["chat", "code", "function_calling", "streaming"]),
        m("MiniMax-M2.7-highspeed", "minimax", "MiniMax M2.7 Highspeed", 204800, 0.3, 1.2, &["chat", "code", "function_calling", "streaming"]),
        m("glm-5.2", "z-ai", "GLM 5.2", 1000000, 0.63, 1.98, &["chat", "code", "json_mode", "function_calling", "streaming", "reasoning"]),
        m("glm-5.1", "z-ai", "GLM 5.1", 204800, 0.97, 3.04, &["chat", "code", "json_mode", "function_calling", "streaming", "reasoning"]),
        m("glm-5", "z-ai", "GLM 5", 200000, 0.97, 3.04, &["chat", "code", "json_mode", "function_calling", "streaming", "reasoning"]),
        m("minimax-m3", "opencode-go", "MiniMax M3", 1000000, 0.0, 0.0, &["chat", "code", "vision", "function_calling", "streaming", "reasoning"]),
        m("minimax-m2.7", "opencode-go", "MiniMax M2.7", 1000000, 0.0, 0.0, &["chat", "code", "function_calling", "streaming"]),
        m("minimax-m2.5", "opencode-go", "MiniMax M2.5", 1000000, 0.0, 0.0, &["chat", "code", "function_calling", "streaming"]),
        m("kimi-k2.6", "opencode-go", "Kimi K2.6", 262144, 0.0, 0.0, &["chat", "code", "function_calling", "streaming"]),
        m("kimi-k2.5", "opencode-go", "Kimi K2.5", 262144, 0.0, 0.0, &["chat", "code", "function_calling", "streaming"]),
        m("glm-5.1", "opencode-go", "GLM-5.1", 128000, 0.0, 0.0, &["chat", "code", "function_calling", "streaming"]),
        m("glm-5", "opencode-go", "GLM-5", 128000, 0.0, 0.0, &["chat", "code", "function_calling", "streaming"]),
        m("deepseek-v4-pro", "opencode-go", "DeepSeek V4 Pro", 128000, 0.0, 0.0, &["chat", "code", "function_calling", "streaming", "reasoning"]),
        m("deepseek-v4-flash", "opencode-go", "DeepSeek V4 Flash", 128000, 0.0, 0.0, &["chat", "code", "function_calling", "streaming"]),
        m("mimo-v2-pro", "opencode-go", "MiMo-V2 Pro", 128000, 0.0, 0.0, &["chat", "code", "function_calling", "streaming", "reasoning"]),
        m("mimo-v2-omni", "opencode-go", "MiMo-V2 Omni", 128000, 0.0, 0.0, &["chat", "code", "function_calling", "streaming"]),
        m("mimo-v2.5-pro", "opencode-go", "MiMo-V2.5 Pro", 128000, 0.0, 0.0, &["chat", "code", "function_calling", "streaming", "reasoning"]),
        m("mimo-v2.5", "opencode-go", "MiMo-V2.5", 128000, 0.0, 0.0, &["chat", "code", "function_calling", "streaming"]),
        m("hy3-preview", "opencode-go", "Hunyuan 3 Preview", 128000, 0.0, 0.0, &["chat", "code", "function_calling", "streaming"]),
        m("Qwen3.6-35B-A3B-UD-Q4_K_M.gguf", "hiveagents", "Qwen3.6 35B MoE (Recomendado)", 50000, 0.0, 0.0, &["chat", "streaming", "reasoning", "function_calling"]),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_is_populated_and_well_formed() {
        let c = model_catalog();
        assert!(c.len() >= 80, "expected the full Hive LLM catalog");
        // Every entry has a namespaced id and a context window.
        for md in &c {
            assert_eq!(md.id, format!("{}::{}", md.provider_id, md.model_id));
            assert_eq!(md.model_type, "llm");
        }
        // Spot-check known anchors (provider parity with Hive).
        let anchor = c.iter().find(|m| m.provider_id == "hiveagents").expect("hiveagents present");
        assert!(anchor.context_window > 0);
        assert!(c.iter().any(|m| m.provider_id == "anthropic" && m.model_id == "claude-sonnet-5" && m.context_window == 1_000_000));
    }
}
