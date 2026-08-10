# Providers LLM

## Trait LlmProvider

```rust
#[async_trait]
pub trait LlmProvider: Send + Sync {
    async fn call(&self, req: &CallRequest) -> Result<LlmResponse>;
}

pub struct CallRequest {
    pub system: Option<String>,
    pub messages: Vec<Message>,
    pub tools: Vec<ToolDef>,
    pub max_tokens: Option<u64>,
}

pub struct Message {
    pub role: String,                   // user, assistant, tool, system
    pub content: Content,
}

pub enum Content {
    Text(String),
    ToolResult { tool_call_id, content },
}

pub struct LlmResponse {
    pub content: Vec<ContentBlock>,      // Text or ToolUse
    pub tool_calls: Vec<ToolCall>,
    pub stop_reason: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
}
```

## Providers implementados (16+)

### Custom (3)

Estos tienen adapters especificos porque su API difiere de OpenAI:

- **Anthropic** (`crates/hivecyber-providers/src/anthropic.rs`)
  - Endpoint: `POST https://api.anthropic.com/v1/messages`
  - Headers: `x-api-key`, `anthropic-version: 2023-06-01`
  - Request: `{model, max_tokens, system, messages, tools}`
  - Response: `content: [{type: "text"|"tool_use", ...}]`, `stop_reason`, `usage`

- **Gemini** (`crates/hivecyber-providers/src/gemini.rs`)
  - Endpoint: `POST https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}`
  - Request: `{contents: [{role, parts: [{text}]}], system_instruction: {parts}, generation_config: {max_output_tokens}}`
  - Response: `{candidates: [{content: {parts: [{text}]}, finish_reason}], usage_metadata}`

- **Ollama** (`crates/hivecyber-providers/src/ollama.rs`)
  - Endpoint: `POST http://localhost:11434/api/chat`
  - Request: `{model, messages: [{role, content}], stream: false, options: {num_ctx}}`
  - Response: `{message: {role, content}, done}`

### OpenAI-compat (13)

Usan un unico adapter `OpenAiCompatProvider` con `base_url` custom:

| provider_id | base_url | default_model | api_key_env |
|---|---|---|---|
| openai | https://api.openai.com | gpt-4o | OPENAI_API_KEY |
| groq | https://api.groq.com/openai | llama-3.3-70b-versatile | GROQ_API_KEY |
| mistral | https://api.mistral.ai/v1 | mistral-large-latest | MISTRAL_API_KEY |
| openrouter | https://openrouter.ai/api/v1 | anthropic/claude-sonnet-4 | OPENROUTER_API_KEY |
| deepseek | https://api.deepseek.com/v1 | deepseek-chat | DEEPSEEK_API_KEY |
| kimi | https://api.moonshot.cn/v1 | moonshot-v1-128k | KIMI_API_KEY |
| nvidia | https://integrate.api.nvidia.com/v1 | meta/llama-3.1-405b-instruct | NVIDIA_API_KEY |
| qwen | https://dashscope.aliyuncs.com/compatible-mode/v1 | qwen-max | QWEN_API_KEY |
| minimax | https://api.minimax.chat/v1 | abab6.5s-chat | MINIMAX_API_KEY |
| zai | https://api.z.ai/api/paas/v4 | glm-4-plus | ZAI_API_KEY |
| modelscope | https://api-inference.modelscope.cn/v1 | Qwen/Qwen2.5-72B-Instruct | MODELSCOPE_API_KEY |
| opencode_go | https://opencode.ai/zen/go | kimi-k2.6 | OPENCODE_GO_API_KEY |
| hiveagents | https://api.hiveagents.ai/v1 | hive-max | HIVEAGENTS_API_KEY |

OpenAI-compat request:
```json
{
  "model": "gpt-4o",
  "max_tokens": 8192,
  "messages": [{"role": "system", "content": "..."}, {"role": "user", "content": "..."}],
  "tools": [{"type": "function", "function": {"name": "...", "description": "...", "parameters": {...}}}]
}
```

Response:
```json
{
  "choices": [{
    "message": {
      "content": "...",
      "tool_calls": [{"id": "call_1", "function": {"name": "nmap", "arguments": "{\"target\":\"10.0.0.5\"}"}}]
    },
    "finish_reason": "stop|tool_calls"
  }],
  "usage": {"prompt_tokens": 50, "completion_tokens": 20}
}
```

## ProviderRegistry (`crates/hivecyber-providers/src/registry.rs`)

```rust
pub struct ProviderRegistry {
    configs: Vec<ProviderConfig>,
}

impl ProviderRegistry {
    pub fn new() -> Self;
    pub fn list_providers(&self) -> Vec<String>;
    pub fn get(&self, provider_id, model, api_key) -> Option<Arc<dyn LlmProvider>>;
    pub fn get_default_api_key(provider_id) -> Option<String>;
    pub fn create_all() -> Self;
}
```

`get` retorna `Arc<dyn LlmProvider>`:
- Si `cfg.custom` -> construye adapter especifico (Anthropic/Gemini/Ollama)
- Si `!cfg.custom` -> construye `OpenAiCompatProvider::new(api_key, model, base_url)`

## Resolucion en el agent loop

```rust
let provider = agent.get("provider_id").or(config.models.default_provider);  // "anthropic"
let model = agent.get("model_id").or(default_model_for(provider));          // "claude-sonnet-4-20250514"
let api_key = match provider {
    "anthropic" => std::env::var("ANTHROPIC_API_KEY")?,
    "openai" => std::env::var("OPENAI_API_KEY")?,
    "gemini" => std::env::var("GOOGLE_API_KEY")?,
    "ollama" => std::env::var("OLLAMA_API_KEY").or(String::new()),
    "groq" => std::env::var("GROQ_API_KEY")?,
    _ => std::env::var("ANTHROPIC_API_KEY")?,
};
let registry = ProviderRegistry::new();
let client = registry.get(provider, model, &api_key)?;
let response = client.call(&req).await?;
```

## Herencia en delegacion

Workers sin `provider_id`/`model_id` heredan del coordinador:
```rust
let (provider, model) = match (&agent.provider_id, &agent.model_id) {
    (Some(p), Some(m)) => (p, m),
    _ => (parent_provider, parent_model),
};
```

`exploit_operator` y `vuln_scanner` tienen `model_override = {required_capabilities: ["code", "function_calling"], fallback: "general"}` (pendiente de usar en resolucion).

## CLI

No hay comando `providers` explicito. La verificacion se hace via tests:

```bash
cargo test -p hivecyber-providers
# 29 tests covering all 16 providers + API key env + serialization
```

Para usar un provider especifico:

```bash
ANTHROPIC_API_KEY=sk-ant-... hivecyber chat
OPENAI_API_KEY=sk-... hivecyber chat   # pendiente wire default_provider config
GROQ_API_KEY=gsk-... hivecyber chat     # pendiente wire default_provider config
```

En MVP, `default_provider = "anthropic"` hardcoded en config. Para cambiar, setear `HIVECYBER_DEFAULT_PROVIDER` (pendiente wire).