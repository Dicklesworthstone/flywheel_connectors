//! Request and response types for OpenAI-compatible providers.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;

use crate::OpenAiError;

/// JSON object extension map for provider-specific request knobs.
pub type ProviderExtensions = BTreeMap<String, Value>;

const CHAT_REQUEST_FIELDS: &[&str] = &[
    "model",
    "messages",
    "temperature",
    "max_tokens",
    "top_p",
    "stop",
    "stream",
    "tools",
    "tool_choice",
    "response_format",
    "seed",
    "user",
    "n",
    "presence_penalty",
    "frequency_penalty",
    "logit_bias",
    "logprobs",
    "top_logprobs",
];
const ASSISTANT_MESSAGE_FIELDS: &[&str] =
    &["role", "content", "reasoning_content", "tool_calls", "name"];
const EMBEDDING_REQUEST_FIELDS: &[&str] = &["model", "input", "encoding_format", "dimensions"];
// The legacy client only implements a complete JSON response. Extensions must
// not silently switch it to an SSE response, even though stream is not typed.
const COMPLETION_REQUEST_FIELDS: &[&str] =
    &["model", "prompt", "max_tokens", "temperature", "stream"];

fn validate_extensions(
    extensions: &ProviderExtensions,
    reserved: &[&str],
) -> Result<(), OpenAiError> {
    if reserved.iter().any(|field| extensions.contains_key(*field)) {
        return Err(OpenAiError::InvalidRequest {
            message: "Provider extensions must not replace typed request or message fields".into(),
            param: Some("provider_extensions".into()),
            code: Some("reserved_provider_extension".into()),
        });
    }
    Ok(())
}

fn serialize_extensions<S: Serializer>(
    extensions: &ProviderExtensions,
    reserved: &[&str],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    validate_extensions(extensions, reserved).map_err(<S::Error as serde::ser::Error>::custom)?;
    extensions.serialize(serializer)
}

fn serialize_chat_extensions<S: Serializer>(
    extensions: &ProviderExtensions,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serialize_extensions(extensions, CHAT_REQUEST_FIELDS, serializer)
}

fn serialize_assistant_extensions<S: Serializer>(
    extensions: &ProviderExtensions,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serialize_extensions(extensions, ASSISTANT_MESSAGE_FIELDS, serializer)
}

fn serialize_embedding_extensions<S: Serializer>(
    extensions: &ProviderExtensions,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serialize_extensions(extensions, EMBEDDING_REQUEST_FIELDS, serializer)
}

fn serialize_completion_extensions<S: Serializer>(
    extensions: &ProviderExtensions,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serialize_extensions(extensions, COMPLETION_REQUEST_FIELDS, serializer)
}

/// Chat completions request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChatCompletionsRequest {
    /// Model identifier.
    pub model: String,
    /// Conversation messages.
    pub messages: Vec<ChatMessage>,
    /// Sampling temperature.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    /// Maximum generated tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    /// Nucleus sampling value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f32>,
    /// Stop sequences.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop: Option<Vec<String>>,
    /// Streaming flag.
    pub stream: bool,
    /// Tool definitions available to the model.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<ToolDefinition>>,
    /// Tool selection policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<ToolChoice>,
    /// Response format contract.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_format: Option<ResponseFormat>,
    /// Deterministic seed when supported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seed: Option<i64>,
    /// Abuse-detection user identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Number of completions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<u32>,
    /// Presence penalty.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presence_penalty: Option<f32>,
    /// Frequency penalty.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frequency_penalty: Option<f32>,
    /// Logit bias map.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logit_bias: Option<BTreeMap<String, f32>>,
    /// Whether log probabilities are requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logprobs: Option<bool>,
    /// Number of top log probabilities.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_logprobs: Option<u32>,
    /// Provider-specific request fields flattened into the JSON body.
    #[serde(
        default,
        flatten,
        skip_serializing_if = "BTreeMap::is_empty",
        serialize_with = "serialize_chat_extensions"
    )]
    pub provider_extensions: ProviderExtensions,
}

impl ChatCompletionsRequest {
    /// Reject extension fields that could change the authorized request or
    /// reinterpret an assistant message as another role when flattened.
    ///
    /// # Errors
    /// Returns an invalid-request error for any typed-field collision, including
    /// optional fields that currently have no value. Serialization enforces the
    /// same rule for callers that do not use the shared HTTP client.
    pub fn validate_provider_extensions(&self) -> Result<(), OpenAiError> {
        validate_extensions(&self.provider_extensions, CHAT_REQUEST_FIELDS)?;
        for message in &self.messages {
            if let ChatMessage::Assistant {
                provider_extensions,
                ..
            } = message
            {
                validate_extensions(provider_extensions, ASSISTANT_MESSAGE_FIELDS)?;
            }
        }
        Ok(())
    }

    /// Create a minimal non-streaming chat request.
    pub fn new(model: impl Into<String>, messages: Vec<ChatMessage>) -> Self {
        Self {
            model: model.into(),
            messages,
            temperature: None,
            max_tokens: None,
            top_p: None,
            stop: None,
            stream: false,
            tools: None,
            tool_choice: None,
            response_format: None,
            seed: None,
            user: None,
            n: None,
            presence_penalty: None,
            frequency_penalty: None,
            logit_bias: None,
            logprobs: None,
            top_logprobs: None,
            provider_extensions: ProviderExtensions::new(),
        }
    }
}

/// Message in a chat-completions request or response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "snake_case")]
pub enum ChatMessage {
    /// System/developer instructions.
    System {
        /// Message content.
        content: String,
        /// Optional participant name.
        #[serde(skip_serializing_if = "Option::is_none")]
        name: Option<String>,
    },
    /// User message.
    User {
        /// User content.
        content: ContentParts,
        /// Optional participant name.
        #[serde(skip_serializing_if = "Option::is_none")]
        name: Option<String>,
    },
    /// Assistant message.
    Assistant {
        /// Assistant text, absent for pure tool-call responses.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        content: Option<String>,
        /// Provider reasoning trace, when exposed separately from final content.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reasoning_content: Option<String>,
        /// Modern tool calls.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tool_calls: Option<Vec<ToolCall>>,
        /// Optional participant name.
        #[serde(skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        /// Provider-specific message fields flattened into the JSON object.
        #[serde(
            default,
            flatten,
            skip_serializing_if = "BTreeMap::is_empty",
            serialize_with = "serialize_assistant_extensions"
        )]
        provider_extensions: ProviderExtensions,
    },
    /// Tool response.
    Tool {
        /// Tool output content.
        content: String,
        /// Tool-call identifier.
        tool_call_id: String,
        /// Optional tool name.
        #[serde(skip_serializing_if = "Option::is_none")]
        name: Option<String>,
    },
}

impl ChatMessage {
    /// Build a text user message.
    pub fn user_text(content: impl Into<String>) -> Self {
        Self::User {
            content: ContentParts::Text(content.into()),
            name: None,
        }
    }
}

/// Text or multimodal user content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ContentParts {
    /// Plain text content.
    Text(String),
    /// Multimodal content blocks.
    Multimodal(Vec<ContentPart>),
}

/// Multimodal content block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentPart {
    /// Text block.
    Text {
        /// Text payload.
        text: String,
    },
    /// Image URL block.
    ImageUrl {
        /// URL plus optional detail hint.
        image_url: ImageUrl,
    },
    /// Input audio block.
    InputAudio {
        /// Base64 audio payload and format.
        input_audio: InputAudio,
    },
}

/// Image URL content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageUrl {
    /// Image URL.
    pub url: String,
    /// Detail hint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<ImageDetail>,
}

/// Image detail hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageDetail {
    /// Let the provider decide.
    Auto,
    /// Low-detail processing.
    Low,
    /// High-detail processing.
    High,
}

/// Input audio content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputAudio {
    /// Base64 audio bytes.
    pub data: String,
    /// Audio encoding.
    pub format: AudioFormat,
}

/// Supported OpenAI-compatible input audio formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AudioFormat {
    /// WAV.
    Wav,
    /// MP3.
    Mp3,
}

/// Tool definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolDefinition {
    /// Tool type. OpenAI-compatible providers use `function`.
    #[serde(rename = "type")]
    pub tool_type: String,
    /// Function definition.
    pub function: FunctionDefinition,
}

/// Function schema for a tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionDefinition {
    /// Function name.
    pub name: String,
    /// Function description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// JSON Schema parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameters: Option<Value>,
}

/// Tool choice policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ToolChoice {
    /// Named policy such as `none`, `auto`, or `required`.
    Mode(String),
    /// Specific function selection.
    Specific {
        /// Tool type.
        #[serde(rename = "type")]
        tool_type: String,
        /// Function selector.
        function: ToolChoiceFunction,
    },
}

/// Function selector for a specific tool choice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolChoiceFunction {
    /// Function name.
    pub name: String,
}

/// Response format request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseFormat {
    /// Format type, for example `json_object`.
    #[serde(rename = "type")]
    pub format_type: String,
}

/// Tool call in the modern OpenAI-compatible shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolCall {
    /// Tool-call ID.
    pub id: String,
    /// Tool type.
    #[serde(rename = "type")]
    pub tool_type: String,
    /// Function call payload.
    pub function: FunctionCall,
}

/// Function call payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionCall {
    /// Function name.
    pub name: String,
    /// JSON-encoded arguments.
    pub arguments: String,
}

/// Chat-completions response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatCompletionsResponse {
    /// Response ID.
    pub id: String,
    /// Object type.
    pub object: String,
    /// Creation timestamp.
    pub created: i64,
    /// Model identifier.
    pub model: String,
    /// Choices.
    pub choices: Vec<ChatChoice>,
    /// Usage accounting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<Usage>,
    /// Provider system fingerprint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_fingerprint: Option<String>,
}

/// Chat-completions choice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatChoice {
    /// Choice index.
    pub index: u32,
    /// Assistant message.
    pub message: ChatMessage,
    /// Finish reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finish_reason: Option<String>,
}

/// Streaming chat chunk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatChunk {
    /// Chunk ID.
    pub id: String,
    /// Object type.
    pub object: String,
    /// Creation timestamp.
    pub created: i64,
    /// Model identifier.
    pub model: String,
    /// Delta choices.
    pub choices: Vec<ChatChunkChoice>,
    /// Usage, usually emitted only on the final chunk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<Usage>,
    /// Provider system fingerprint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_fingerprint: Option<String>,
}

/// Streaming chunk choice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatChunkChoice {
    /// Choice index.
    pub index: u32,
    /// Delta payload.
    pub delta: ChatDelta,
    /// Finish reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finish_reason: Option<String>,
}

/// Streaming delta payload.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatDelta {
    /// Role, usually present on the first chunk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Content delta.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    /// Tool-call deltas.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<ToolCallDelta>>,
    /// Provider reasoning delta, when exposed separately from final content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_content: Option<String>,
    /// Provider-specific delta fields flattened into the JSON object.
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub provider_extensions: ProviderExtensions,
}

/// Tool-call streaming delta.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolCallDelta {
    /// Tool-call index.
    pub index: u32,
    /// Tool-call ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Tool type.
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub tool_type: Option<String>,
    /// Function delta.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function: Option<FunctionCallDelta>,
}

/// Function-call streaming delta.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionCallDelta {
    /// Function name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Arguments delta.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<String>,
}

/// Token usage.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    /// Prompt tokens.
    #[serde(default)]
    pub prompt_tokens: u32,
    /// Completion tokens.
    #[serde(default)]
    pub completion_tokens: u32,
    /// Total tokens.
    #[serde(default)]
    pub total_tokens: u32,
}

/// Embeddings request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbeddingsRequest {
    /// Model identifier.
    pub model: String,
    /// Input text or batch.
    pub input: EmbeddingInput,
    /// Encoding format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoding_format: Option<String>,
    /// Requested dimensions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dimensions: Option<u32>,
    /// Provider-specific request fields.
    #[serde(
        default,
        flatten,
        skip_serializing_if = "BTreeMap::is_empty",
        serialize_with = "serialize_embedding_extensions"
    )]
    pub provider_extensions: ProviderExtensions,
}

impl EmbeddingsRequest {
    /// Validate extension fields before authorization or provider dispatch.
    ///
    /// # Errors
    /// Rejects extensions that shadow model, input, encoding or dimensions.
    pub fn validate_provider_extensions(&self) -> Result<(), OpenAiError> {
        validate_extensions(&self.provider_extensions, EMBEDDING_REQUEST_FIELDS)
    }
}

/// Embedding input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EmbeddingInput {
    /// Single text input.
    Single(String),
    /// Batch text input.
    Batch(Vec<String>),
}

/// Embeddings response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EmbeddingsResponse {
    /// Object type.
    pub object: String,
    /// Embedding entries.
    pub data: Vec<EmbeddingData>,
    /// Model identifier.
    pub model: String,
    /// Usage accounting.
    pub usage: EmbeddingUsage,
}

/// Embedding vector entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EmbeddingData {
    /// Object type.
    pub object: String,
    /// Entry index.
    pub index: u32,
    /// Vector.
    pub embedding: Vec<f32>,
}

/// Embeddings usage.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbeddingUsage {
    /// Prompt tokens.
    #[serde(default)]
    pub prompt_tokens: u32,
    /// Total tokens.
    #[serde(default)]
    pub total_tokens: u32,
}

/// Model listing response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelsResponse {
    /// Object type.
    pub object: String,
    /// Models.
    pub data: Vec<ModelInfo>,
}

/// Model metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelInfo {
    /// Model identifier.
    pub id: String,
    /// Object type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,
    /// Owner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owned_by: Option<String>,
    /// Creation timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<i64>,
}

/// Legacy completions request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompletionsRequest {
    /// Model identifier.
    pub model: String,
    /// Prompt input.
    pub prompt: PromptInput,
    /// Maximum generated tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    /// Temperature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    /// Provider-specific request fields.
    #[serde(
        default,
        flatten,
        skip_serializing_if = "BTreeMap::is_empty",
        serialize_with = "serialize_completion_extensions"
    )]
    pub provider_extensions: ProviderExtensions,
}

impl CompletionsRequest {
    /// Validate extension fields before authorization or provider dispatch.
    ///
    /// # Errors
    /// Rejects typed-field collisions and unsupported streaming overrides.
    pub fn validate_provider_extensions(&self) -> Result<(), OpenAiError> {
        validate_extensions(&self.provider_extensions, COMPLETION_REQUEST_FIELDS)
    }
}

/// Legacy prompt input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PromptInput {
    /// Single prompt.
    Single(String),
    /// Prompt batch.
    Batch(Vec<String>),
}

/// Legacy completions response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletionsResponse {
    /// Response ID.
    pub id: String,
    /// Object type.
    pub object: String,
    /// Creation timestamp.
    pub created: i64,
    /// Model identifier.
    pub model: String,
    /// Choices.
    pub choices: Vec<CompletionChoice>,
    /// Usage accounting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<Usage>,
}

/// Legacy completion choice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletionChoice {
    /// Choice text.
    pub text: String,
    /// Choice index.
    pub index: u32,
    /// Finish reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finish_reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn chat_extensions_cannot_shadow_authorized_fields_in_any_serializer() {
        for field in [
            "model",
            "messages",
            "stream",
            "tools",
            "max_tokens",
            "tool_choice",
        ] {
            let mut request = ChatCompletionsRequest::new(
                "authorized-model",
                vec![ChatMessage::user_text("hello")],
            );
            request
                .provider_extensions
                .insert(field.into(), json!("private-collision-value"));
            let error = request.validate_provider_extensions().expect_err(field);
            assert!(matches!(error, OpenAiError::InvalidRequest { .. }));
            assert!(!error.to_string().contains("private-collision-value"));
            assert!(
                serde_json::to_value(&request).is_err(),
                "value serializer accepted {field}"
            );
            assert!(
                serde_json::to_vec(&request).is_err(),
                "wire serializer accepted {field}"
            );
        }
    }

    #[test]
    fn assistant_extensions_cannot_change_message_role_or_content() {
        for field in ["role", "content", "reasoning_content", "tool_calls", "name"] {
            let message = ChatMessage::Assistant {
                content: Some("original assistant content".into()),
                reasoning_content: None,
                tool_calls: None,
                name: None,
                provider_extensions: BTreeMap::from([(field.into(), json!("system"))]),
            };
            assert!(serde_json::to_value(&message).is_err(), "accepted {field}");
            assert!(serde_json::to_vec(&message).is_err(), "accepted {field}");
            let request = ChatCompletionsRequest::new("model", vec![message]);
            assert!(request.validate_provider_extensions().is_err());
            assert!(serde_json::to_vec(&request).is_err());
        }
    }

    #[test]
    fn embeddings_and_legacy_extensions_cannot_change_request_or_response_mode() {
        for field in ["model", "input", "encoding_format", "dimensions"] {
            let request = EmbeddingsRequest {
                model: "authorized-model".into(),
                input: EmbeddingInput::Single("text".into()),
                encoding_format: None,
                dimensions: None,
                provider_extensions: BTreeMap::from([(field.into(), json!("override"))]),
            };
            assert!(
                request.validate_provider_extensions().is_err(),
                "accepted {field}"
            );
            assert!(serde_json::to_value(&request).is_err());
            assert!(serde_json::to_vec(&request).is_err());
        }
        for field in ["model", "prompt", "max_tokens", "temperature", "stream"] {
            let request = CompletionsRequest {
                model: "authorized-model".into(),
                prompt: PromptInput::Single("text".into()),
                max_tokens: None,
                temperature: None,
                provider_extensions: BTreeMap::from([(field.into(), json!(true))]),
            };
            assert!(
                request.validate_provider_extensions().is_err(),
                "accepted {field}"
            );
            assert!(serde_json::to_value(&request).is_err());
            assert!(serde_json::to_vec(&request).is_err());
        }
    }

    #[test]
    fn legitimate_extensions_preserve_nested_values_and_round_trip() {
        let request = ChatCompletionsRequest {
            provider_extensions: BTreeMap::from([(
                "vendor_options".into(),
                json!({
                    "model": "this nested value is data", "stream": true
                }),
            )]),
            messages: vec![ChatMessage::Assistant {
                content: Some("answer".into()),
                reasoning_content: None,
                tool_calls: None,
                name: None,
                provider_extensions: BTreeMap::from([(
                    "vendor_trace".into(),
                    json!({"role": "data"}),
                )]),
            }],
            ..ChatCompletionsRequest::new("authorized-model", Vec::new())
        };
        request.validate_provider_extensions().unwrap();
        let bytes = serde_json::to_vec(&request).unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["model"], "authorized-model");
        assert_eq!(value["stream"], false);
        assert_eq!(value["vendor_options"]["stream"], true);
        assert_eq!(value["messages"][0]["role"], "assistant");
        assert_eq!(value["messages"][0]["vendor_trace"]["role"], "data");
        assert_eq!(
            serde_json::from_slice::<ChatCompletionsRequest>(&bytes).unwrap(),
            request
        );
    }

    #[test]
    fn chat_request_omits_none_fields_and_flattens_extensions() {
        let mut req =
            ChatCompletionsRequest::new("llama-3.3", vec![ChatMessage::user_text("hello")]);
        req.provider_extensions
            .insert("reasoning_effort".to_string(), json!("high"));

        let value = serde_json::to_value(req).expect("chat request serializes");
        assert_eq!(value["model"], "llama-3.3");
        assert_eq!(value["stream"], false);
        assert_eq!(value["reasoning_effort"], "high");
        assert!(value.get("temperature").is_none());
        assert!(value.get("provider_extensions").is_none());
    }

    #[test]
    fn multimodal_message_round_trips() {
        let message = ChatMessage::User {
            name: Some("operator".to_string()),
            content: ContentParts::Multimodal(vec![
                ContentPart::Text {
                    text: "inspect".to_string(),
                },
                ContentPart::ImageUrl {
                    image_url: ImageUrl {
                        url: "https://example.test/image.png".to_string(),
                        detail: Some(ImageDetail::High),
                    },
                },
            ]),
        };

        let value = serde_json::to_value(&message).expect("message serializes");
        let round_trip: ChatMessage = serde_json::from_value(value).expect("message deserializes");
        assert_eq!(round_trip, message);
    }

    #[test]
    fn embeddings_request_omits_none_fields() {
        let req = EmbeddingsRequest {
            model: "embedding-model".to_string(),
            input: EmbeddingInput::Single("hello".to_string()),
            encoding_format: None,
            dimensions: None,
            provider_extensions: ProviderExtensions::new(),
        };

        let value = serde_json::to_value(req).expect("embedding request serializes");
        assert!(value.get("dimensions").is_none());
        assert_eq!(value["input"], "hello");
    }

    #[test]
    fn assistant_message_preserves_reasoning_content_and_extensions() {
        let message: ChatMessage = serde_json::from_value(json!({
            "role": "assistant",
            "content": "final answer",
            "reasoning_content": "private trace",
            "deepseek_trace_id": "trace-1"
        }))
        .expect("assistant response decodes");

        assert!(matches!(message, ChatMessage::Assistant { .. }));
        if let ChatMessage::Assistant {
            content,
            reasoning_content,
            provider_extensions,
            ..
        } = &message
        {
            assert_eq!(content.as_deref(), Some("final answer"));
            assert_eq!(reasoning_content.as_deref(), Some("private trace"));
            assert_eq!(provider_extensions["deepseek_trace_id"], "trace-1");
        }

        let value = serde_json::to_value(message).expect("assistant response serializes");
        assert_eq!(value["reasoning_content"], "private trace");
        assert_eq!(value["deepseek_trace_id"], "trace-1");
        assert!(value.get("provider_extensions").is_none());
    }

    #[test]
    fn chat_delta_preserves_reasoning_content_and_extensions() {
        let delta: ChatDelta = serde_json::from_value(json!({
            "role": "assistant",
            "reasoning_content": "thinking ",
            "content": "answer",
            "provider_specific": {"phase": "reasoning"}
        }))
        .expect("delta decodes");

        assert_eq!(delta.role.as_deref(), Some("assistant"));
        assert_eq!(delta.reasoning_content.as_deref(), Some("thinking "));
        assert_eq!(delta.content.as_deref(), Some("answer"));
        assert_eq!(
            delta.provider_extensions["provider_specific"]["phase"],
            "reasoning"
        );

        let value = serde_json::to_value(delta).expect("delta serializes");
        assert_eq!(value["reasoning_content"], "thinking ");
        assert_eq!(value["provider_specific"]["phase"], "reasoning");
        assert!(value.get("provider_extensions").is_none());
    }
}
