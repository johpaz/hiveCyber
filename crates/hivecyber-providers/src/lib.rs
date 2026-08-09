pub mod traits;
pub mod anthropic;
pub mod openai_compat;
pub mod gemini;
pub mod ollama;
pub mod registry;
pub mod tests;

pub use traits::{LlmProvider, CallRequest, LlmResponse, Message, Content, ToolCall, ToolDef};
pub use registry::ProviderRegistry;