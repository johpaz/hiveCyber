use crate::registry::ProviderRegistry;
use crate::traits::*;

#[test]
fn test_registry_lists_all_16_providers() {
    let reg = ProviderRegistry::new();
    let providers = reg.list_providers();
    assert_eq!(providers.len(), 16, "expected 16 providers, got {}", providers.len());

    let expected = [
        "anthropic", "openai", "gemini", "ollama",
        "groq", "mistral", "openrouter", "deepseek",
        "kimi", "nvidia", "qwen", "minimax",
        "zai", "modelscope", "opencode_go", "hiveagents",
    ];
    for id in &expected {
        assert!(
            providers.contains(&id.to_string()),
            "provider '{}' missing from registry",
            id
        );
    }
}

#[test]
fn test_anthropic_provider_constructs() {
    let p = crate::anthropic::AnthropicProvider::new("sk-test-fake", "claude-sonnet-4-20250514");
    let _ = p;
}

#[test]
fn test_gemini_provider_constructs() {
    let p = crate::gemini::GeminiProvider::new("fake-key", "gemini-2.0-flash");
    let _ = p;
}

#[test]
fn test_ollama_provider_constructs_default() {
    let p = crate::ollama::OllamaProvider::default();
    let _ = p;
}

#[test]
fn test_ollama_provider_custom_url() {
    let p = crate::ollama::OllamaProvider::new("qwen2.5", Some("http://192.168.1.10:11434"));
    let _ = p;
}

#[test]
fn test_openai_compat_provider_constructs() {
    let p = crate::openai_compat::OpenAiCompatProvider::new(
        "sk-fake",
        "gpt-4o",
        "https://api.openai.com",
    );
    let _ = p;
}

#[test]
fn test_registry_get_anthropic() {
    let reg = ProviderRegistry::new();
    let client = reg.get("anthropic", "claude-sonnet-4", "sk-fake");
    assert!(client.is_some(), "anthropic provider should construct");
}

#[test]
fn test_registry_get_openai() {
    let reg = ProviderRegistry::new();
    let client = reg.get("openai", "gpt-4o", "sk-fake");
    assert!(client.is_some(), "openai provider should construct");
}

#[test]
fn test_registry_get_gemini() {
    let reg = ProviderRegistry::new();
    let client = reg.get("gemini", "gemini-2.0-flash", "fake-key");
    assert!(client.is_some(), "gemini provider should construct");
}

#[test]
fn test_registry_get_ollama() {
    let reg = ProviderRegistry::new();
    let client = reg.get("ollama", "llama3.2", "");
    assert!(client.is_some(), "ollama provider should construct");
}

#[test]
fn test_registry_get_groq_openai_compat() {
    let reg = ProviderRegistry::new();
    let client = reg.get("groq", "llama-3.3-70b-versatile", "gsk-fake");
    assert!(client.is_some(), "groq provider should construct as OpenAI-compat");
}

#[test]
fn test_registry_get_mistral_openai_compat() {
    let reg = ProviderRegistry::new();
    let client = reg.get("mistral", "mistral-large-latest", "fake-key");
    assert!(client.is_some());
}

#[test]
fn test_registry_get_openrouter_openai_compat() {
    let reg = ProviderRegistry::new();
    let client = reg.get("openrouter", "anthropic/claude-sonnet-4", "sk-or-fake");
    assert!(client.is_some());
}

#[test]
fn test_registry_get_deepseek_openai_compat() {
    let reg = ProviderRegistry::new();
    let client = reg.get("deepseek", "deepseek-chat", "sk-fake");
    assert!(client.is_some());
}

#[test]
fn test_registry_get_kimi_openai_compat() {
    let reg = ProviderRegistry::new();
    let client = reg.get("kimi", "moonshot-v1-128k", "sk-fake");
    assert!(client.is_some());
}

#[test]
fn test_registry_get_nvidia_openai_compat() {
    let reg = ProviderRegistry::new();
    let client = reg.get("nvidia", "meta/llama-3.1-405b-instruct", "nvapi-fake");
    assert!(client.is_some());
}

#[test]
fn test_registry_get_qwen_openai_compat() {
    let reg = ProviderRegistry::new();
    let client = reg.get("qwen", "qwen-max", "sk-fake");
    assert!(client.is_some());
}

#[test]
fn test_registry_get_minimax_openai_compat() {
    let reg = ProviderRegistry::new();
    let client = reg.get("minimax", "abab6.5s-chat", "fake-key");
    assert!(client.is_some());
}

#[test]
fn test_registry_get_zai_openai_compat() {
    let reg = ProviderRegistry::new();
    let client = reg.get("zai", "glm-4-plus", "fake-key");
    assert!(client.is_some());
}

#[test]
fn test_registry_get_modelscope_openai_compat() {
    let reg = ProviderRegistry::new();
    let client = reg.get("modelscope", "Qwen/Qwen2.5-72B-Instruct", "fake-key");
    assert!(client.is_some());
}

#[test]
fn test_registry_get_opencode_go_openai_compat() {
    let reg = ProviderRegistry::new();
    let client = reg.get("opencode_go", "opencode-go/glm-5.2", "fake-key");
    assert!(client.is_some());
}

#[test]
fn test_registry_get_hiveagents_openai_compat() {
    let reg = ProviderRegistry::new();
    let client = reg.get("hiveagents", "hive-max", "fake-key");
    assert!(client.is_some());
}

#[test]
fn test_registry_get_unknown_provider_returns_none() {
    let reg = ProviderRegistry::new();
    let client = reg.get("nonexistent_provider", "model-x", "key");
    assert!(client.is_none(), "unknown provider should return None");
}

#[test]
fn test_registry_empty_model_falls_back_to_default() {
    let reg = ProviderRegistry::new();
    let client = reg.get("openai", "", "sk-fake");
    assert!(client.is_some(), "empty model should fall back to default");
}

#[test]
fn test_get_default_api_key_from_env() {
    std::env::set_var("ANTHROPIC_API_KEY", "sk-ant-test-123");
    let key = ProviderRegistry::get_default_api_key("anthropic");
    assert_eq!(key, Some("sk-ant-test-123".into()));

    std::env::set_var("OPENAI_API_KEY", "sk-test-456");
    let key = ProviderRegistry::get_default_api_key("openai");
    assert_eq!(key, Some("sk-test-456".into()));

    let key = ProviderRegistry::get_default_api_key("nonexistent");
    assert_eq!(key, None);
}

#[test]
fn test_llm_response_content_text_extracts_text() {
    let resp = LlmResponse {
        content: vec![
            ContentBlock::Text { text: "hello world".into() },
        ],
        tool_calls: vec![],
        stop_reason: "end_turn".into(),
        input_tokens: 10,
        output_tokens: 5,
    };
    assert_eq!(resp.content_text(), Some("hello world".into()));
}

#[test]
fn test_llm_response_tool_calls_extracted() {
    let resp = LlmResponse {
        content: vec![
            ContentBlock::ToolUse {
                id: "call_1".into(),
                name: "nmap".into(),
                input: serde_json::json!({"target": "10.0.0.5"}),
            },
        ],
        tool_calls: vec![ToolCall {
            id: "call_1".into(),
            name: "nmap".into(),
            arguments: serde_json::json!({"target": "10.0.0.5"}),
        }],
        stop_reason: "tool_use".into(),
        input_tokens: 50,
        output_tokens: 20,
    };
    assert_eq!(resp.tool_calls().len(), 1);
    assert_eq!(resp.tool_calls()[0].name, "nmap");
}

#[test]
fn test_tool_def_serialization() {
    let td = ToolDef {
        name: "fs_read".into(),
        description: "Read a file".into(),
        parameters: serde_json::json!({
            "type": "object",
            "properties": {
                "path": {"type": "string"}
            },
            "required": ["path"]
        }),
    };
    let json = serde_json::to_value(&td).unwrap();
    assert_eq!(json.get("name").and_then(|v| v.as_str()), Some("fs_read"));
}

#[test]
fn test_call_request_construction() {
    let req = CallRequest {
        system: Some("You are Caelum".into()),
        messages: vec![Message {
            role: "user".into(),
            content: Content::Text("Hola".into()),
        }],
        tools: vec![],
        max_tokens: Some(4096),
    };
    assert_eq!(req.system, Some("You are Caelum".into()));
    assert_eq!(req.messages.len(), 1);
    assert_eq!(req.max_tokens, Some(4096));
}