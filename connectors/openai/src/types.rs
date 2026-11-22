//! OpenAI API types.

use serde::{Deserialize, Serialize};

/// Available OpenAI models.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Model {
    /// GPT-4o - Most capable multimodal model
    #[serde(rename = "gpt-4o")]
    Gpt4o,
    /// GPT-4o mini - Smaller, faster GPT-4o
    #[serde(rename = "gpt-4o-mini")]
    Gpt4oMini,
    /// GPT-4 Turbo - Previous generation
    #[serde(rename = "gpt-4-turbo")]
    Gpt4Turbo,
    /// GPT-4 - Original GPT-4
    #[serde(rename = "gpt-4")]
    Gpt4,
    /// GPT-3.5 Turbo - Fast and cost-effective
    #[serde(rename = "gpt-3.5-turbo")]
    Gpt35Turbo,
}

impl Model {
    /// Get the model string for API requests.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Gpt4o => "gpt-4o",
            Self::Gpt4oMini => "gpt-4o-mini",
            Self::Gpt4Turbo => "gpt-4-turbo",
            Self::Gpt4 => "gpt-4",
            Self::Gpt35Turbo => "gpt-3.5-turbo",
        }
    }

    /// Get input price per million tokens.
    #[must_use]
    pub const fn input_price_per_million(&self) -> f64 {
        match self {
            Self::Gpt4o => 2.50,
            Self::Gpt4oMini => 0.15,
            Self::Gpt4Turbo => 10.0,
            Self::Gpt4 => 30.0,
            Self::Gpt35Turbo => 0.50,
        }
    }

    /// Get output price per million tokens.
    #[must_use]
    pub const fn output_price_per_million(&self) -> f64 {
        match self {
            Self::Gpt4o => 10.0,
            Self::Gpt4oMini => 0.60,
            Self::Gpt4Turbo => 30.0,
            Self::Gpt4 => 60.0,
            Self::Gpt35Turbo => 1.50,
        }
    }
}

impl Default for Model {
    fn default() -> Self {
        Self::Gpt4o
    }
}

/// A message in a conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Role of the message sender.
    pub role: Role,
    /// Content of the message. Assistant tool calls may omit text content.
    #[serde(default)]
    pub content: MessageContent,
    /// Optional name for the participant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Tool calls made by the assistant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<ToolCall>>,
    /// ID of the tool call this message is responding to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

impl Message {
    /// Create a user message.
    #[must_use]
    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: Role::User,
            content: MessageContent::Text(content.into()),
            name: None,
            tool_calls: None,
            tool_call_id: None,
        }
    }

    /// Create an assistant message.
    #[must_use]
    pub fn assistant(content: impl Into<String>) -> Self {
        Self {
            role: Role::Assistant,
            content: MessageContent::Text(content.into()),
            name: None,
            tool_calls: None,
            tool_call_id: None,
        }
    }

    /// Create a system message.
    #[must_use]
    pub fn system(content: impl Into<String>) -> Self {
        Self {
            role: Role::System,
            content: MessageContent::Text(content.into()),
            name: None,
            tool_calls: None,
            tool_call_id: None,
        }
    }
}

/// Role in a conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// System message
    System,
    /// User message
    User,
    /// Assistant message
    Assistant,
    /// Tool message (function result)
    Tool,
}

/// Content of a message (text, multimodal, or an assistant tool-call turn).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MessageContent {
    /// Simple text content
    Text(String),
    /// Complex content with multiple parts (for vision)
    Parts(Vec<ContentPart>),
    /// No text content; valid for an assistant message containing tool calls.
    #[default]
    Null,
}

impl From<&str> for MessageContent {
    fn from(s: &str) -> Self {
        Self::Text(s.to_string())
    }
}

impl From<String> for MessageContent {
    fn from(s: String) -> Self {
        Self::Text(s)
    }
}

/// A content part for multimodal messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentPart {
    /// Text content
    Text { text: String },
    /// Image URL
    ImageUrl { image_url: ImageUrl },
}

/// Image URL for vision requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageUrl {
    /// URL of the image (can be data: URL for base64)
    pub url: String,
    /// Detail level for the image
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<ImageDetail>,
}

/// Detail level for image processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ImageDetail {
    /// Automatic detail level
    Auto,
    /// Low detail (faster, cheaper)
    Low,
    /// High detail (more accurate)
    High,
}

/// Input accepted by the Responses API without forcing it through chat messages.
///
/// Item objects are retained verbatim so callers can return function outputs,
/// replay reasoning items, or include multimodal content.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ResponsesInput {
    /// A text prompt.
    Text(String),
    /// Ordered input items, including messages and function-call outputs.
    Items(Vec<serde_json::Value>),
}

/// Non-streaming request to `POST /v1/responses`.
///
/// Model identifiers are intentionally not restricted to the legacy chat model
/// enum. Unknown top-level fields are rejected instead of silently discarded.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponsesRequest {
    /// Provider model identifier.
    pub model: String,
    /// Text or ordered input items.
    pub input: ResponsesInput,
    /// Instructions for this response; not inherited from a previous response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
    /// Response whose context should precede this request's input.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_response_id: Option<String>,
    /// Flat function declarations. Hosted tools require separate authority.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<serde_json::Value>>,
    /// none, auto, required, or a flat function selection object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<serde_json::Value>,
    /// Upper bound including both visible output and reasoning tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u32>,
    /// Provider reasoning configuration, retained without narrowing its fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning: Option<serde_json::Value>,
    /// Text configuration, including structured output in `text.format`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<serde_json::Value>,
    /// Whether the provider should retain the response for later retrieval.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub store: Option<bool>,
    /// Additional provider output fields to include.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include: Option<Vec<String>>,
    /// Provider metadata attached to the response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<std::collections::BTreeMap<String, String>>,
    /// Whether the model may emit multiple tool calls in parallel.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parallel_tool_calls: Option<bool>,
    /// Sampling temperature, when supported by the selected model.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    /// Nucleus sampling probability, when supported by the selected model.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f64>,
    /// Only false is supported by this synchronous operation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    /// Only false is supported until background-job lifecycle operations exist.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub background: Option<bool>,
}

impl ResponsesRequest {
    /// Validate the supported request shape before authorization or provider I/O.
    ///
    /// Only client-executed function declarations and passive conversation items
    /// are accepted. Hosted tools and approvals require separate authority.
    /// Function arguments and outputs are never parsed, executed, or rewritten.
    ///
    /// # Errors
    ///
    /// Rejects malformed fields, unsupported tools, and streaming/background modes.
    pub fn validate(&self) -> crate::error::OpenAIResult<()> {
        let invalid = |message: &str| crate::error::OpenAIError::InvalidInput {
            message: message.to_owned(),
        };
        if self.model.trim().is_empty() || self.model.trim() != self.model.as_str() {
            return Err(invalid(
                "Responses model must be nonempty without surrounding whitespace",
            ));
        }
        if self.stream == Some(true) {
            return Err(invalid(
                "Responses streaming is not supported by this operation",
            ));
        }
        if self.background == Some(true) {
            return Err(invalid(
                "Responses background execution is not supported by this operation",
            ));
        }
        if self
            .previous_response_id
            .as_ref()
            .is_some_and(|id| id.trim().is_empty() || id.trim() != id.as_str())
        {
            return Err(invalid(
                "previous_response_id must be nonempty without surrounding whitespace",
            ));
        }
        if self.max_output_tokens.is_some_and(|limit| limit < 16) {
            return Err(invalid("max_output_tokens must be at least 16"));
        }
        if self
            .temperature
            .is_some_and(|value| !value.is_finite() || !(0.0..=2.0).contains(&value))
        {
            return Err(invalid("temperature must be between 0 and 2"));
        }
        if self
            .top_p
            .is_some_and(|value| !value.is_finite() || !(0.0..=1.0).contains(&value))
        {
            return Err(invalid("top_p must be between 0 and 1"));
        }
        if self
            .reasoning
            .as_ref()
            .is_some_and(|value| !value.is_object())
        {
            return Err(invalid("reasoning must be an object"));
        }
        if let Some(text) = &self.text {
            if !text.is_object() {
                return Err(invalid("text must be an object"));
            }
            if text.get("format").is_some_and(|format| !format.is_object()) {
                return Err(invalid("text.format must be an object"));
            }
        }
        if let ResponsesInput::Items(items) = &self.input {
            for item in items {
                if !item.is_object() {
                    return Err(invalid("Responses input items must be objects"));
                }
                if item.get("id").is_some_and(|id| {
                    id.as_str()
                        .is_none_or(|id| id.trim().is_empty() || id.trim() != id)
                }) {
                    return Err(invalid(
                        "Responses input item ids must be nonempty without surrounding whitespace",
                    ));
                }
                let kind = match item.get("type") {
                    None => None,
                    Some(serde_json::Value::String(kind)) if !kind.trim().is_empty() => {
                        Some(kind.as_str())
                    }
                    _ => {
                        return Err(invalid(
                            "Responses input item type must be a nonempty string",
                        ));
                    }
                };
                match kind {
                    None | Some("message") => {
                        if !matches!(
                            item.get("role").and_then(serde_json::Value::as_str),
                            Some("user" | "assistant" | "system" | "developer")
                        ) {
                            return Err(invalid("Responses message items require a valid role"));
                        }
                        let content = item
                            .get("content")
                            .ok_or_else(|| invalid("Responses messages require content"))?;
                        Self::validate_content(content)?;
                    }
                    Some("function_call_output") => {
                        if item
                            .get("call_id")
                            .and_then(serde_json::Value::as_str)
                            .is_none_or(|id| id.trim().is_empty() || id.trim() != id)
                        {
                            return Err(invalid(
                                "function_call_output requires a nonempty call_id without surrounding whitespace",
                            ));
                        }
                        let output = item
                            .get("output")
                            .ok_or_else(|| invalid("function_call_output requires output"))?;
                        Self::validate_content(output)?;
                    }
                    Some("function_call") => {
                        if ["call_id", "name"].into_iter().any(|field| {
                            item.get(field)
                                .and_then(serde_json::Value::as_str)
                                .is_none_or(|value| {
                                    value.trim().is_empty() || value.trim() != value
                                })
                        }) || !item
                            .get("arguments")
                            .is_some_and(serde_json::Value::is_string)
                        {
                            return Err(invalid(
                                "function_call requires unpadded call_id, name and string arguments",
                            ));
                        }
                    }
                    Some("item_reference") => {
                        if item
                            .get("id")
                            .and_then(serde_json::Value::as_str)
                            .is_none_or(|id| id.trim().is_empty() || id.trim() != id)
                        {
                            return Err(invalid(
                                "item_reference requires a nonempty id without surrounding whitespace",
                            ));
                        }
                    }
                    Some("reasoning") => {}
                    _ => {
                        return Err(invalid(
                            "Only message, function_call, function_call_output, reasoning and item_reference inputs are supported",
                        ));
                    }
                }
            }
        }
        if let Some(tools) = &self.tools {
            for tool in tools {
                if tool.get("type").and_then(serde_json::Value::as_str) != Some("function") {
                    return Err(invalid("Only flat Responses function tools are supported"));
                }
                if tool
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .is_none_or(|name| name.trim().is_empty() || name.trim() != name)
                {
                    return Err(invalid(
                        "Responses function tools require a nonempty top-level name without surrounding whitespace",
                    ));
                }
                if tool
                    .get("parameters")
                    .is_some_and(|value| !value.is_null() && !value.is_object())
                {
                    return Err(invalid("Function parameters must be a JSON Schema object"));
                }
            }
        }
        if let Some(choice) = &self.tool_choice {
            match choice {
                serde_json::Value::String(value)
                    if matches!(value.as_str(), "none" | "auto" | "required") => {}
                serde_json::Value::Object(object) => {
                    if object.get("type").and_then(serde_json::Value::as_str) != Some("function")
                        || object
                            .keys()
                            .any(|key| !matches!(key.as_str(), "type" | "name"))
                    {
                        return Err(invalid(
                            "Responses tool_choice objects must contain only type=function and name",
                        ));
                    }
                    if object
                        .get("name")
                        .and_then(serde_json::Value::as_str)
                        .is_none_or(|name| name.trim().is_empty() || name.trim() != name)
                    {
                        return Err(invalid(
                            "Responses function tool_choice requires a nonempty top-level name without surrounding whitespace",
                        ));
                    }
                }
                _ => {
                    return Err(invalid(
                        "tool_choice must be none, auto, required, or a function selection",
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_content(content: &serde_json::Value) -> crate::error::OpenAIResult<()> {
        let invalid = |message: &str| crate::error::OpenAIError::InvalidInput {
            message: message.to_owned(),
        };
        if content.is_string() {
            return Ok(());
        }
        let parts = content
            .as_array()
            .ok_or_else(|| invalid("Responses content must be a string or an array of objects"))?;
        for part in parts {
            let object = part
                .as_object()
                .ok_or_else(|| invalid("Responses content parts must be objects"))?;
            if let Some(id) = object.get("file_id") {
                if id
                    .as_str()
                    .is_none_or(|id| id.trim().is_empty() || id.trim() != id)
                {
                    return Err(invalid(
                        "Content file_id must be nonempty without surrounding whitespace",
                    ));
                }
            }
            for field in ["file_url", "image_url"] {
                if let Some(value) = object.get(field) {
                    let value = value
                        .as_str()
                        .ok_or_else(|| invalid("Content URLs must be strings"))?;
                    if value.trim().is_empty()
                        || value.trim() != value
                        || value.chars().any(char::is_control)
                    {
                        return Err(invalid(
                            "Content URLs must be nonempty without whitespace padding or control characters",
                        ));
                    }
                    let parsed = url::Url::parse(value)
                        .map_err(|_| invalid("Content URLs must be valid absolute URLs"))?;
                    if field == "image_url"
                        && parsed.scheme() == "data"
                        && value.starts_with("data:image/")
                        && value
                            .split_once(',')
                            .is_some_and(|(_, data)| !data.is_empty())
                    {
                        continue;
                    }
                    if !matches!(parsed.scheme(), "http" | "https")
                        || parsed.host_str().is_none()
                        || !parsed.username().is_empty()
                        || parsed.password().is_some()
                    {
                        return Err(invalid(
                            "Content URLs must use HTTP(S) without credentials; image_url also accepts inline data:image URLs",
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

/// Actual token usage reported by the Responses API.
///
/// Detailed cached/reasoning token information and future provider fields are
/// retained in `extra`. There is no inferred cost or default token estimate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponsesUsage {
    /// Actual input token count.
    pub input_tokens: u64,
    /// Actual output token count, including any reasoning tokens.
    pub output_tokens: u64,
    /// Provider-reported combined token count.
    pub total_tokens: u64,
    /// Additional provider usage fields.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// Complete structured Responses API result.
///
/// Output items stay in provider order and preserve call IDs, raw argument
/// strings, reasoning continuity fields, annotations, and unknown item types.
/// Top-level status/error/incomplete details are retained rather than collapsed
/// into a text-only completion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponsesResponse {
    /// Response identifier used by `previous_response_id`.
    pub id: String,
    /// Provider object discriminator.
    pub object: String,
    /// Provider status, such as completed, incomplete, or failed.
    pub status: String,
    /// Actual provider model identifier.
    pub model: String,
    /// Ordered, unmodified provider output items.
    pub output: Vec<serde_json::Value>,
    /// Actual usage, or none when the provider has not supplied it.
    pub usage: Option<ResponsesUsage>,
    /// All other provider response fields, including errors and continuation data.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl ResponsesResponse {
    /// Concatenate assistant text output without discarding structured items.
    #[must_use]
    pub fn output_text(&self) -> String {
        self.output
            .iter()
            .filter(|item| item.get("type").and_then(serde_json::Value::as_str) == Some("message"))
            .filter_map(|item| item.get("content").and_then(serde_json::Value::as_array))
            .flatten()
            .filter(|part| {
                part.get("type").and_then(serde_json::Value::as_str) == Some("output_text")
            })
            .filter_map(|part| part.get("text").and_then(serde_json::Value::as_str))
            .collect()
    }

    /// Inspect complete function-call items without parsing or executing arguments.
    pub fn function_calls(&self) -> impl Iterator<Item = &serde_json::Value> {
        self.output.iter().filter(|item| {
            item.get("type").and_then(serde_json::Value::as_str) == Some("function_call")
        })
    }
}

/// Request to the Chat Completions API.
#[derive(Debug, Clone, Serialize)]
pub struct ChatCompletionRequest {
    /// Model to use
    pub model: String,
    /// Messages in the conversation
    pub messages: Vec<Message>,
    /// Maximum tokens to generate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    /// Temperature for sampling
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    /// Top-p sampling
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f64>,
    /// Number of completions to generate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<u32>,
    /// Whether to stream the response
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    /// Stop sequences
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop: Option<Vec<String>>,
    /// Presence penalty (-2.0 to 2.0)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presence_penalty: Option<f64>,
    /// Frequency penalty (-2.0 to 2.0)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frequency_penalty: Option<f64>,
    /// User identifier for abuse detection
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Tools available to the model
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<Tool>>,
    /// How to choose which tool to use
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<ToolChoice>,
    /// Response format (for JSON mode)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_format: Option<ResponseFormat>,
    /// Seed for deterministic outputs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seed: Option<i64>,
}

/// A tool definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tool {
    /// Type of tool (always "function" for now)
    #[serde(rename = "type")]
    pub tool_type: String,
    /// Function definition
    pub function: FunctionDefinition,
}

/// Function definition for a tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionDefinition {
    /// Function name
    pub name: String,
    /// Function description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Parameters schema (JSON Schema)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<serde_json::Value>,
}

/// How to choose which tool to use.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ToolChoice {
    /// String choice: "none", "auto", or "required"
    String(String),
    /// Specific tool choice
    Specific {
        #[serde(rename = "type")]
        choice_type: String,
        function: ToolChoiceFunction,
    },
}

/// Function choice for specific tool selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolChoiceFunction {
    /// Name of the function to call
    pub name: String,
}

/// Response format specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseFormat {
    /// Type of response format
    #[serde(rename = "type")]
    pub format_type: String,
}

/// A tool call made by the assistant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    /// Unique ID for this tool call
    pub id: String,
    /// Type of tool (always "function")
    #[serde(rename = "type")]
    pub tool_type: String,
    /// Function call details
    pub function: FunctionCall,
}

/// Function call details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCall {
    /// Name of the function to call
    pub name: String,
    /// Arguments as a JSON string
    pub arguments: String,
}

/// Response from the Chat Completions API.
#[derive(Debug, Clone, Deserialize)]
pub struct ChatCompletionResponse {
    /// Response ID
    pub id: String,
    /// Object type (always "chat.completion")
    pub object: String,
    /// Unix timestamp of creation
    pub created: i64,
    /// Model used
    pub model: String,
    /// Choices (completions)
    pub choices: Vec<Choice>,
    /// Usage statistics
    pub usage: Option<Usage>,
    /// System fingerprint
    pub system_fingerprint: Option<String>,
}

/// A completion choice.
#[derive(Debug, Clone, Deserialize)]
pub struct Choice {
    /// Index of this choice
    pub index: u32,
    /// The message
    pub message: ResponseMessage,
    /// Finish reason
    pub finish_reason: Option<FinishReason>,
}

/// Message in a response.
#[derive(Debug, Clone, Deserialize)]
pub struct ResponseMessage {
    /// Role (always "assistant")
    pub role: Role,
    /// Text content
    pub content: Option<String>,
    /// Tool calls made by the assistant
    pub tool_calls: Option<Vec<ToolCall>>,
}

/// Reason the model stopped generating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinishReason {
    /// Natural end of message
    Stop,
    /// Hit max tokens
    Length,
    /// Model wants to use a tool
    ToolCalls,
    /// Content was filtered
    ContentFilter,
}

/// Token usage statistics.
#[derive(Debug, Clone, Copy, Deserialize, Default)]
pub struct Usage {
    /// Prompt tokens used
    pub prompt_tokens: u32,
    /// Completion tokens used
    pub completion_tokens: u32,
    /// Total tokens used
    pub total_tokens: u32,
    /// Detailed breakdown of prompt tokens
    #[serde(default)]
    pub prompt_tokens_details: Option<PromptTokensDetails>,
}

/// Detailed breakdown of prompt tokens.
#[derive(Debug, Clone, Copy, Deserialize, Default)]
pub struct PromptTokensDetails {
    /// Number of tokens retrieved from the cache
    pub cached_tokens: u32,
}

impl Usage {
    /// Calculate cost for this usage with a given model.
    #[must_use]
    pub fn calculate_cost(&self, model: Model) -> f64 {
        let base_input_price = model.input_price_per_million();
        let output_price = model.output_price_per_million();

        let cached_tokens = self
            .prompt_tokens_details
            .map(|d| d.cached_tokens)
            .unwrap_or(0);

        // OpenAI pricing: Cached input tokens are 50% discounted
        let uncached_input = self.prompt_tokens.saturating_sub(cached_tokens);

        let input_cost = (f64::from(uncached_input) / 1_000_000.0) * base_input_price
            + (f64::from(cached_tokens) / 1_000_000.0) * (base_input_price * 0.5);

        let output_cost = (f64::from(self.completion_tokens) / 1_000_000.0) * output_price;

        input_cost + output_cost
    }
}

/// Streaming chunk from the Chat Completions API.
#[derive(Debug, Clone, Deserialize)]
pub struct ChatCompletionChunk {
    /// Chunk ID
    pub id: String,
    /// Object type (always "chat.completion.chunk")
    pub object: String,
    /// Unix timestamp of creation
    pub created: i64,
    /// Model used
    pub model: String,
    /// Choices (partial completions)
    pub choices: Vec<ChunkChoice>,
    /// System fingerprint
    pub system_fingerprint: Option<String>,
    /// Usage (only in final chunk if requested)
    pub usage: Option<Usage>,
}

/// A choice in a streaming chunk.
#[derive(Debug, Clone, Deserialize)]
pub struct ChunkChoice {
    /// Index of this choice
    pub index: u32,
    /// Delta (incremental content)
    pub delta: ChunkDelta,
    /// Finish reason (only in final chunk)
    pub finish_reason: Option<FinishReason>,
}

/// Delta content in a streaming chunk.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ChunkDelta {
    /// Role (only in first chunk)
    pub role: Option<Role>,
    /// Content delta
    pub content: Option<String>,
    /// Tool calls delta
    pub tool_calls: Option<Vec<ToolCallDelta>>,
}

/// Tool call delta in streaming.
#[derive(Debug, Clone, Deserialize)]
pub struct ToolCallDelta {
    /// Index of the tool call
    pub index: u32,
    /// ID (only in first chunk for this tool call)
    pub id: Option<String>,
    /// Type (only in first chunk)
    #[serde(rename = "type")]
    pub tool_type: Option<String>,
    /// Function delta
    pub function: Option<FunctionCallDelta>,
}

/// Function call delta in streaming.
#[derive(Debug, Clone, Deserialize)]
pub struct FunctionCallDelta {
    /// Name (only in first chunk)
    pub name: Option<String>,
    /// Arguments delta (incremental JSON string)
    pub arguments: Option<String>,
}

// ─────────────────────── Embeddings ───────────────────────

/// Available embedding models.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EmbeddingModel {
    /// text-embedding-3-small
    #[serde(rename = "text-embedding-3-small")]
    TextEmbedding3Small,
    /// text-embedding-3-large
    #[serde(rename = "text-embedding-3-large")]
    TextEmbedding3Large,
    /// text-embedding-ada-002 (legacy)
    #[serde(rename = "text-embedding-ada-002")]
    TextEmbeddingAda002,
}

impl EmbeddingModel {
    /// Get the model string for API requests.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::TextEmbedding3Small => "text-embedding-3-small",
            Self::TextEmbedding3Large => "text-embedding-3-large",
            Self::TextEmbeddingAda002 => "text-embedding-ada-002",
        }
    }

    /// Get the default output dimensions.
    #[must_use]
    pub const fn default_dimensions(&self) -> u32 {
        match self {
            Self::TextEmbedding3Large => 3072,
            Self::TextEmbedding3Small | Self::TextEmbeddingAda002 => 1536,
        }
    }

    /// Get price per million tokens.
    #[must_use]
    pub const fn price_per_million(&self) -> f64 {
        match self {
            Self::TextEmbedding3Small => 0.02,
            Self::TextEmbedding3Large => 0.13,
            Self::TextEmbeddingAda002 => 0.10,
        }
    }

    /// Maximum input tokens.
    #[must_use]
    pub const fn max_input_tokens(&self) -> u32 {
        8191
    }
}

impl Default for EmbeddingModel {
    fn default() -> Self {
        Self::TextEmbedding3Small
    }
}

/// Request to the Embeddings API.
#[derive(Debug, Clone, Serialize)]
pub struct EmbeddingRequest {
    /// Model to use.
    pub model: String,
    /// Input text(s) to embed.
    pub input: EmbeddingInput,
    /// Output encoding format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding_format: Option<String>,
    /// Output dimensions (text-embedding-3 only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dimensions: Option<u32>,
}

/// Embedding input: single string or array of strings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EmbeddingInput {
    /// Single text input.
    Single(String),
    /// Batch of text inputs.
    Batch(Vec<String>),
}

/// Response from the Embeddings API.
#[derive(Debug, Clone, Deserialize)]
pub struct EmbeddingResponse {
    /// Object type (always "list").
    pub object: String,
    /// Embedding data entries.
    pub data: Vec<EmbeddingData>,
    /// Model used.
    pub model: String,
    /// Usage statistics.
    pub usage: EmbeddingUsage,
}

/// A single embedding vector.
#[derive(Debug, Clone, Deserialize)]
pub struct EmbeddingData {
    /// Object type (always "embedding").
    pub object: String,
    /// Index of this embedding.
    pub index: u32,
    /// The embedding vector.
    pub embedding: Vec<f64>,
}

/// Usage statistics for embeddings.
#[derive(Debug, Clone, Copy, Deserialize, Default)]
pub struct EmbeddingUsage {
    /// Prompt tokens used.
    pub prompt_tokens: u32,
    /// Total tokens used.
    pub total_tokens: u32,
}

impl EmbeddingUsage {
    /// Calculate cost for this usage with a given embedding model.
    #[must_use]
    pub fn calculate_cost(&self, model: EmbeddingModel) -> f64 {
        (f64::from(self.total_tokens) / 1_000_000.0) * model.price_per_million()
    }
}

// ─────────────────────── Images ───────────────────────

/// Image generation models.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImageModel {
    /// DALL-E 3
    #[serde(rename = "dall-e-3")]
    DallE3,
    /// DALL-E 2
    #[serde(rename = "dall-e-2")]
    DallE2,
}

impl ImageModel {
    /// Get the model string for API requests.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::DallE3 => "dall-e-3",
            Self::DallE2 => "dall-e-2",
        }
    }
}

impl Default for ImageModel {
    fn default() -> Self {
        Self::DallE3
    }
}

/// Image size options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImageSize {
    /// 256x256 (DALL-E 2 only)
    #[serde(rename = "256x256")]
    Size256,
    /// 512x512 (DALL-E 2 only)
    #[serde(rename = "512x512")]
    Size512,
    /// 1024x1024
    #[serde(rename = "1024x1024")]
    Size1024,
    /// 1792x1024 (DALL-E 3 only)
    #[serde(rename = "1792x1024")]
    SizeLandscape,
    /// 1024x1792 (DALL-E 3 only)
    #[serde(rename = "1024x1792")]
    SizePortrait,
}

impl Default for ImageSize {
    fn default() -> Self {
        Self::Size1024
    }
}

/// Image quality options (DALL-E 3 only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ImageQuality {
    /// Standard quality.
    Standard,
    /// HD quality.
    Hd,
}

impl Default for ImageQuality {
    fn default() -> Self {
        Self::Standard
    }
}

/// Request to the Images API.
#[derive(Debug, Clone, Serialize)]
pub struct ImageGenerationRequest {
    /// Model to use.
    pub model: String,
    /// Text prompt.
    pub prompt: String,
    /// Number of images to generate (1-10, DALL-E 2; always 1 for DALL-E 3).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<u32>,
    /// Image size.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<ImageSize>,
    /// Image quality (DALL-E 3 only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quality: Option<ImageQuality>,
    /// Response format.
    pub response_format: String,
}

/// Response from the Images API.
#[derive(Debug, Clone, Deserialize)]
pub struct ImageGenerationResponse {
    /// Unix timestamp of creation.
    pub created: i64,
    /// Generated image data.
    pub data: Vec<ImageData>,
}

/// A single generated image.
#[derive(Debug, Clone, Deserialize)]
pub struct ImageData {
    /// Base64-encoded image data (when `response_format` is `b64_json`).
    #[serde(default)]
    pub b64_json: Option<String>,
    /// URL of generated image (when `response_format` is `url`).
    #[serde(default)]
    pub url: Option<String>,
    /// Revised prompt (DALL-E 3 only).
    #[serde(default)]
    pub revised_prompt: Option<String>,
}

// ─────────────────────── Videos ───────────────────────

/// OpenAI video generation models.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VideoModel {
    /// Sora 2
    #[serde(rename = "sora-2")]
    Sora2,
    /// Sora 2 Pro
    #[serde(rename = "sora-2-pro")]
    Sora2Pro,
}

impl VideoModel {
    /// Get the model string for API requests.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Sora2 => "sora-2",
            Self::Sora2Pro => "sora-2-pro",
        }
    }
}

impl Default for VideoModel {
    fn default() -> Self {
        Self::Sora2
    }
}

/// Supported OpenAI video durations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VideoDurationSeconds {
    /// Four seconds.
    #[serde(rename = "4")]
    Seconds4,
    /// Eight seconds.
    #[serde(rename = "8")]
    Seconds8,
    /// Twelve seconds.
    #[serde(rename = "12")]
    Seconds12,
}

impl VideoDurationSeconds {
    /// Parse an exact supported duration.
    #[must_use]
    pub const fn from_u64(value: u64) -> Option<Self> {
        match value {
            4 => Some(Self::Seconds4),
            8 => Some(Self::Seconds8),
            12 => Some(Self::Seconds12),
            _ => None,
        }
    }

    /// Get the API string.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Seconds4 => "4",
            Self::Seconds8 => "8",
            Self::Seconds12 => "12",
        }
    }
}

/// Supported OpenAI video output sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VideoSize {
    /// 720x1280 portrait.
    #[serde(rename = "720x1280")]
    Size720x1280,
    /// 1280x720 landscape.
    #[serde(rename = "1280x720")]
    Size1280x720,
    /// 1024x1792 portrait.
    #[serde(rename = "1024x1792")]
    Size1024x1792,
    /// 1792x1024 landscape.
    #[serde(rename = "1792x1024")]
    Size1792x1024,
}

impl VideoSize {
    /// Get the API string.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Size720x1280 => "720x1280",
            Self::Size1280x720 => "1280x720",
            Self::Size1024x1792 => "1024x1792",
            Self::Size1792x1024 => "1792x1024",
        }
    }
}

/// Request to the Videos API.
#[derive(Debug, Clone, Serialize)]
pub struct VideoGenerationRequest {
    /// Model to use.
    pub model: String,
    /// Text prompt.
    pub prompt: String,
    /// Requested duration in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seconds: Option<String>,
    /// Requested output size.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<String>,
}

/// Video generation job status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VideoStatus {
    /// Job is queued.
    Queued,
    /// Job is running.
    InProgress,
    /// Job completed.
    Completed,
    /// Job failed.
    Failed,
    /// Unknown status returned by the provider.
    #[serde(other)]
    Unknown,
}

/// OpenAI video generation error payload.
#[derive(Debug, Clone, Deserialize)]
pub struct VideoError {
    /// Provider error code.
    pub code: Option<String>,
    /// Provider error message.
    pub message: Option<String>,
}

/// Response from the Videos API.
#[derive(Debug, Clone, Deserialize)]
pub struct VideoGenerationResponse {
    /// Video job ID.
    pub id: Option<String>,
    /// Model used by the provider.
    pub model: Option<String>,
    /// Current job status.
    pub status: Option<VideoStatus>,
    /// Prompt associated with the job.
    pub prompt: Option<String>,
    /// Provider duration metadata.
    pub seconds: Option<String>,
    /// Provider size metadata.
    pub size: Option<String>,
    /// Provider error details.
    pub error: Option<VideoError>,
}

/// Completed OpenAI video asset.
#[derive(Debug, Clone)]
pub struct GeneratedVideoAsset {
    /// Provider job ID.
    pub video_id: String,
    /// Model reported by the provider.
    pub model: String,
    /// Final provider status.
    pub status: VideoStatus,
    /// Duration metadata.
    pub seconds: Option<String>,
    /// Size metadata.
    pub size: Option<String>,
    /// Downloaded video bytes.
    pub bytes: Vec<u8>,
    /// Downloaded video MIME type.
    pub mime_type: String,
}

// ─────────────────────── Audio ───────────────────────

/// Whisper transcription models.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WhisperModel {
    /// whisper-1
    #[serde(rename = "whisper-1")]
    Whisper1,
}

impl WhisperModel {
    /// Get the model string for API requests.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Whisper1 => "whisper-1",
        }
    }

    /// Price per minute of audio.
    #[must_use]
    pub const fn price_per_minute(&self) -> f64 {
        match self {
            Self::Whisper1 => 0.006,
        }
    }
}

impl Default for WhisperModel {
    fn default() -> Self {
        Self::Whisper1
    }
}

/// Text-to-speech models.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TtsModel {
    /// tts-1 (standard quality, lower latency)
    #[serde(rename = "tts-1")]
    Tts1,
    /// tts-1-hd (higher quality)
    #[serde(rename = "tts-1-hd")]
    Tts1Hd,
}

impl TtsModel {
    /// Get the model string for API requests.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Tts1 => "tts-1",
            Self::Tts1Hd => "tts-1-hd",
        }
    }

    /// Price per 1M characters.
    #[must_use]
    pub const fn price_per_million_chars(&self) -> f64 {
        match self {
            Self::Tts1 => 15.0,
            Self::Tts1Hd => 30.0,
        }
    }
}

impl Default for TtsModel {
    fn default() -> Self {
        Self::Tts1
    }
}

/// TTS voice options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TtsVoice {
    /// Alloy voice.
    Alloy,
    /// Echo voice.
    Echo,
    /// Fable voice.
    Fable,
    /// Onyx voice.
    Onyx,
    /// Nova voice.
    Nova,
    /// Shimmer voice.
    Shimmer,
}

impl TtsVoice {
    /// Get the voice string for API requests.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Alloy => "alloy",
            Self::Echo => "echo",
            Self::Fable => "fable",
            Self::Onyx => "onyx",
            Self::Nova => "nova",
            Self::Shimmer => "shimmer",
        }
    }
}

impl Default for TtsVoice {
    fn default() -> Self {
        Self::Alloy
    }
}

/// TTS output audio formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TtsResponseFormat {
    /// MP3 audio.
    Mp3,
    /// Opus audio.
    Opus,
    /// AAC audio.
    Aac,
    /// FLAC audio.
    Flac,
}

impl TtsResponseFormat {
    /// Get the format string for API requests.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Mp3 => "mp3",
            Self::Opus => "opus",
            Self::Aac => "aac",
            Self::Flac => "flac",
        }
    }

    /// Get the MIME type for this format.
    #[must_use]
    pub const fn mime_type(&self) -> &'static str {
        match self {
            Self::Mp3 => "audio/mpeg",
            Self::Opus => "audio/opus",
            Self::Aac => "audio/aac",
            Self::Flac => "audio/flac",
        }
    }
}

impl Default for TtsResponseFormat {
    fn default() -> Self {
        Self::Mp3
    }
}

/// Request to the TTS API.
#[derive(Debug, Clone, Serialize)]
pub struct TtsRequest {
    /// Model to use.
    pub model: String,
    /// Text to convert to speech (max 4096 chars).
    pub input: String,
    /// Voice to use.
    pub voice: String,
    /// Output audio format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_format: Option<String>,
    /// Playback speed (0.25 to 4.0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub speed: Option<f64>,
}

/// Response from the Transcriptions API.
#[derive(Debug, Clone, Deserialize)]
pub struct TranscriptionResponse {
    /// Transcribed text.
    pub text: String,
}

// ─────────────────────── Fine-tuning ───────────────────────

/// Fine-tuning job status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FineTuneStatus {
    /// Job is validating files.
    ValidatingFiles,
    /// Job is queued.
    Queued,
    /// Job is actively running.
    Running,
    /// Job completed successfully.
    Succeeded,
    /// Job failed.
    Failed,
    /// Job was cancelled.
    Cancelled,
}

/// Hyperparameters for fine-tuning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FineTuneHyperparameters {
    /// Number of epochs (or "auto").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n_epochs: Option<serde_json::Value>,
    /// Batch size (or "auto").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_size: Option<serde_json::Value>,
    /// Learning rate multiplier (or "auto").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub learning_rate_multiplier: Option<serde_json::Value>,
}

/// Request to create a fine-tuning job.
#[derive(Debug, Clone, Serialize)]
pub struct CreateFineTuneRequest {
    /// Training file ID.
    pub training_file: String,
    /// Model to fine-tune.
    pub model: String,
    /// Optional validation file ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_file: Option<String>,
    /// Hyperparameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hyperparameters: Option<FineTuneHyperparameters>,
    /// Suffix for the fine-tuned model name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suffix: Option<String>,
}

/// Fine-tuning job object.
#[derive(Debug, Clone, Deserialize)]
pub struct FineTuneJob {
    /// Job ID.
    pub id: String,
    /// Object type (always "fine_tuning.job").
    pub object: String,
    /// Base model being fine-tuned.
    pub model: String,
    /// Job status.
    pub status: FineTuneStatus,
    /// Training file ID.
    pub training_file: String,
    /// Validation file ID.
    pub validation_file: Option<String>,
    /// Fine-tuned model name (available after success).
    pub fine_tuned_model: Option<String>,
    /// Unix timestamp of creation.
    pub created_at: i64,
    /// Unix timestamp of completion.
    pub finished_at: Option<i64>,
    /// Hyperparameters used.
    pub hyperparameters: Option<FineTuneHyperparameters>,
    /// Trained token count.
    pub trained_tokens: Option<u64>,
    /// Error information if failed.
    pub error: Option<FineTuneError>,
}

/// Error details for a failed fine-tuning job.
#[derive(Debug, Clone, Deserialize)]
pub struct FineTuneError {
    /// Error code.
    pub code: Option<String>,
    /// Error message.
    pub message: Option<String>,
}

/// Response from listing fine-tuning jobs.
#[derive(Debug, Clone, Deserialize)]
pub struct FineTuneListResponse {
    /// List of fine-tuning jobs.
    pub data: Vec<FineTuneJob>,
    /// Whether there are more results.
    pub has_more: bool,
}

/// A fine-tuning event.
#[derive(Debug, Clone, Deserialize)]
pub struct FineTuneEvent {
    /// Event ID.
    pub id: String,
    /// Object type (always "fine_tuning.job.event").
    pub object: String,
    /// Unix timestamp.
    pub created_at: i64,
    /// Event level (info, warn, error).
    pub level: String,
    /// Event message.
    pub message: String,
}

/// Response from listing fine-tuning events.
#[derive(Debug, Clone, Deserialize)]
pub struct FineTuneEventListResponse {
    /// List of events.
    pub data: Vec<FineTuneEvent>,
    /// Whether there are more results.
    pub has_more: bool,
}

// ─────────────────────── Assistants ───────────────────────

/// Tool definition for assistants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssistantTool {
    /// Tool type: "code_interpreter", "file_search", or "function".
    #[serde(rename = "type")]
    pub tool_type: String,
    /// Function definition (only for "function" type).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<serde_json::Value>,
}

/// Request to create an assistant.
#[derive(Debug, Clone, Serialize)]
pub struct CreateAssistantRequest {
    /// Model to use.
    pub model: String,
    /// Name of the assistant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// System instructions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
    /// Tools the assistant can use.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<AssistantTool>>,
    /// Metadata key-value pairs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// An assistant object.
#[derive(Debug, Clone, Deserialize)]
pub struct Assistant {
    /// Assistant ID.
    pub id: String,
    /// Object type.
    pub object: String,
    /// Unix timestamp of creation.
    pub created_at: i64,
    /// Name of the assistant.
    pub name: Option<String>,
    /// Model used.
    pub model: String,
    /// System instructions.
    pub instructions: Option<String>,
    /// Tools the assistant can use.
    pub tools: Vec<AssistantTool>,
    /// Metadata.
    pub metadata: Option<serde_json::Value>,
}

/// Response from listing assistants.
#[derive(Debug, Clone, Deserialize)]
pub struct AssistantListResponse {
    /// List of assistants.
    pub data: Vec<Assistant>,
    /// Whether there are more results.
    pub has_more: bool,
}

// ─────────────────────── Threads ───────────────────────

/// A thread object.
#[derive(Debug, Clone, Deserialize)]
pub struct Thread {
    /// Thread ID.
    pub id: String,
    /// Object type.
    pub object: String,
    /// Unix timestamp of creation.
    pub created_at: i64,
    /// Metadata.
    pub metadata: Option<serde_json::Value>,
}

/// Content part of a thread message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadMessageContentPart {
    /// Content type: "text" or "image_file".
    #[serde(rename = "type")]
    pub content_type: String,
    /// Text content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<MessageText>,
}

/// Text content with optional annotations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageText {
    /// The text value.
    pub value: String,
    /// Annotations (citations, file references).
    #[serde(default)]
    pub annotations: Vec<serde_json::Value>,
}

/// A message in a thread.
#[derive(Debug, Clone, Deserialize)]
pub struct ThreadMessage {
    /// Message ID.
    pub id: String,
    /// Object type.
    pub object: String,
    /// Unix timestamp of creation.
    pub created_at: i64,
    /// Thread this message belongs to.
    pub thread_id: String,
    /// Role: "user" or "assistant".
    pub role: String,
    /// Content parts.
    pub content: Vec<ThreadMessageContentPart>,
    /// Assistant ID (if role is "assistant").
    pub assistant_id: Option<String>,
    /// Run ID that generated this message.
    pub run_id: Option<String>,
    /// Metadata.
    pub metadata: Option<serde_json::Value>,
}

/// Response from listing thread messages.
#[derive(Debug, Clone, Deserialize)]
pub struct ThreadMessageListResponse {
    /// List of messages.
    pub data: Vec<ThreadMessage>,
    /// Whether there are more results.
    pub has_more: bool,
}

// ─────────────────────── Runs ───────────────────────

/// Run status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    /// Run is queued for processing.
    Queued,
    /// Run is in progress.
    InProgress,
    /// Run requires action (tool outputs).
    RequiresAction,
    /// Run is cancelling.
    Cancelling,
    /// Run was cancelled.
    Cancelled,
    /// Run failed.
    Failed,
    /// Run completed successfully.
    Completed,
    /// Run is incomplete.
    Incomplete,
    /// Run expired.
    Expired,
}

/// A run on a thread.
#[derive(Debug, Clone, Deserialize)]
pub struct Run {
    /// Run ID.
    pub id: String,
    /// Object type.
    pub object: String,
    /// Unix timestamp of creation.
    pub created_at: i64,
    /// Thread ID.
    pub thread_id: String,
    /// Assistant ID.
    pub assistant_id: String,
    /// Run status.
    pub status: RunStatus,
    /// Model used.
    pub model: String,
    /// Instructions override.
    pub instructions: Option<String>,
    /// Tools used.
    pub tools: Vec<AssistantTool>,
    /// Unix timestamp of start.
    pub started_at: Option<i64>,
    /// Unix timestamp of completion.
    pub completed_at: Option<i64>,
    /// Unix timestamp of failure.
    pub failed_at: Option<i64>,
    /// Unix timestamp of cancellation.
    pub cancelled_at: Option<i64>,
    /// Last error.
    pub last_error: Option<RunError>,
    /// Usage statistics.
    pub usage: Option<RunUsage>,
    /// Metadata.
    pub metadata: Option<serde_json::Value>,
}

/// Run error details.
#[derive(Debug, Clone, Deserialize)]
pub struct RunError {
    /// Error code.
    pub code: String,
    /// Error message.
    pub message: String,
}

/// Usage statistics for a run.
#[derive(Debug, Clone, Deserialize)]
pub struct RunUsage {
    /// Prompt tokens used.
    pub prompt_tokens: u64,
    /// Completion tokens used.
    pub completion_tokens: u64,
    /// Total tokens used.
    pub total_tokens: u64,
}

/// Response from listing runs.
#[derive(Debug, Clone, Deserialize)]
pub struct RunListResponse {
    /// List of runs.
    pub data: Vec<Run>,
    /// Whether there are more results.
    pub has_more: bool,
}

/// API error response.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiError {
    /// Error details
    pub error: ApiErrorDetails,
}

/// API error details.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorDetails {
    /// Error message
    pub message: String,
    /// Error type
    #[serde(rename = "type")]
    pub error_type: String,
    /// Parameter that caused the error
    pub param: Option<String>,
    /// Error code
    pub code: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ---- Model ----

    #[test]
    fn model_as_str_all_variants() {
        assert_eq!(Model::Gpt4o.as_str(), "gpt-4o");
        assert_eq!(Model::Gpt4oMini.as_str(), "gpt-4o-mini");
        assert_eq!(Model::Gpt4Turbo.as_str(), "gpt-4-turbo");
        assert_eq!(Model::Gpt4.as_str(), "gpt-4");
        assert_eq!(Model::Gpt35Turbo.as_str(), "gpt-3.5-turbo");
    }

    #[test]
    fn model_default_is_gpt4o() {
        assert_eq!(Model::default(), Model::Gpt4o);
    }

    #[test]
    fn model_pricing_gpt4o() {
        assert_eq!(Model::Gpt4o.input_price_per_million(), 2.50);
        assert_eq!(Model::Gpt4o.output_price_per_million(), 10.0);
    }

    #[test]
    fn model_pricing_gpt4o_mini() {
        assert_eq!(Model::Gpt4oMini.input_price_per_million(), 0.15);
        assert_eq!(Model::Gpt4oMini.output_price_per_million(), 0.60);
    }

    #[test]
    fn model_pricing_gpt4() {
        assert_eq!(Model::Gpt4.input_price_per_million(), 30.0);
        assert_eq!(Model::Gpt4.output_price_per_million(), 60.0);
    }

    #[test]
    fn model_serde_roundtrip() {
        let model = Model::Gpt4o;
        let json = serde_json::to_value(model).unwrap();
        assert_eq!(json, "gpt-4o");
        let back: Model = serde_json::from_value(json).unwrap();
        assert_eq!(back, Model::Gpt4o);
    }

    #[test]
    fn model_serde_all_variants() {
        for (model, expected) in [
            (Model::Gpt4o, "gpt-4o"),
            (Model::Gpt4oMini, "gpt-4o-mini"),
            (Model::Gpt4Turbo, "gpt-4-turbo"),
            (Model::Gpt4, "gpt-4"),
            (Model::Gpt35Turbo, "gpt-3.5-turbo"),
        ] {
            let json = serde_json::to_value(model).unwrap();
            assert_eq!(json.as_str().unwrap(), expected);
            let back: Model = serde_json::from_value(json).unwrap();
            assert_eq!(back, model);
        }
    }

    // ---- Role ----

    #[test]
    fn role_serde_all_variants() {
        for (role, expected) in [
            (Role::System, "system"),
            (Role::User, "user"),
            (Role::Assistant, "assistant"),
            (Role::Tool, "tool"),
        ] {
            let json = serde_json::to_value(role).unwrap();
            assert_eq!(json.as_str().unwrap(), expected);
            let back: Role = serde_json::from_value(json).unwrap();
            assert_eq!(back, role);
        }
    }

    // ---- Message constructors ----

    #[test]
    fn message_user_constructor() {
        let msg = Message::user("Hello");
        assert_eq!(msg.role, Role::User);
        match &msg.content {
            MessageContent::Text(t) => assert_eq!(t, "Hello"),
            MessageContent::Parts(_) | MessageContent::Null => panic!("Expected Text content"),
        }
        assert!(msg.name.is_none());
        assert!(msg.tool_calls.is_none());
        assert!(msg.tool_call_id.is_none());
    }

    #[test]
    fn message_assistant_constructor() {
        let msg = Message::assistant("Response");
        assert_eq!(msg.role, Role::Assistant);
        match &msg.content {
            MessageContent::Text(t) => assert_eq!(t, "Response"),
            MessageContent::Parts(_) | MessageContent::Null => panic!("Expected Text content"),
        }
    }

    #[test]
    fn message_system_constructor() {
        let msg = Message::system("You are helpful");
        assert_eq!(msg.role, Role::System);
        match &msg.content {
            MessageContent::Text(t) => assert_eq!(t, "You are helpful"),
            MessageContent::Parts(_) | MessageContent::Null => panic!("Expected Text content"),
        }
    }

    // ---- MessageContent ----

    #[test]
    fn message_content_from_str() {
        let content: MessageContent = "test".into();
        match content {
            MessageContent::Text(t) => assert_eq!(t, "test"),
            MessageContent::Parts(_) | MessageContent::Null => panic!("Expected Text"),
        }
    }

    #[test]
    fn message_content_from_string() {
        let content: MessageContent = String::from("test").into();
        match content {
            MessageContent::Text(t) => assert_eq!(t, "test"),
            MessageContent::Parts(_) | MessageContent::Null => panic!("Expected Text"),
        }
    }

    #[test]
    fn message_content_text_serde() {
        let content = MessageContent::Text("hello".into());
        let json = serde_json::to_value(&content).unwrap();
        assert_eq!(json, "hello");
    }

    #[test]
    fn message_content_parts_serde() {
        let content = MessageContent::Parts(vec![
            ContentPart::Text {
                text: "Look at this:".into(),
            },
            ContentPart::ImageUrl {
                image_url: ImageUrl {
                    url: "https://example.com/img.png".into(),
                    detail: Some(ImageDetail::High),
                },
            },
        ]);
        let json = serde_json::to_value(&content).unwrap();
        let parts = json.as_array().unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0]["type"], "text");
        assert_eq!(parts[1]["type"], "image_url");
        assert_eq!(parts[1]["image_url"]["detail"], "high");
    }

    #[test]
    fn assistant_tool_calls_accept_null_and_omitted_content() {
        let tool_calls = json!([{
            "id": "call_weather",
            "type": "function",
            "function": {
                "name": "get_weather",
                "arguments": r#"{"city":"San Francisco"}"#
            }
        }]);
        for explicit_null in [false, true] {
            let mut value = json!({"role": "assistant", "tool_calls": tool_calls});
            if explicit_null {
                value["content"] = serde_json::Value::Null;
            }
            let message: Message =
                serde_json::from_value(value).expect("assistant tool message must deserialize");
            assert!(matches!(message.content, MessageContent::Null));
            let serialized = serde_json::to_value(message).unwrap();
            assert!(serialized["content"].is_null());
            assert_eq!(serialized["tool_calls"], tool_calls);
        }
    }

    #[test]
    fn tool_result_preserves_call_binding() {
        let value = json!({
            "role": "tool",
            "content": "18 C, sunny",
            "tool_call_id": "call_weather"
        });
        let message: Message = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(message).unwrap(), value);
    }

    // ---- ContentPart ----

    #[test]
    fn content_part_text_serde() {
        let part = ContentPart::Text { text: "hi".into() };
        let json = serde_json::to_value(&part).unwrap();
        assert_eq!(json["type"], "text");
        assert_eq!(json["text"], "hi");
        let back: ContentPart = serde_json::from_value(json).unwrap();
        match back {
            ContentPart::Text { text } => assert_eq!(text, "hi"),
            ContentPart::ImageUrl { .. } => panic!("Expected Text"),
        }
    }

    #[test]
    fn content_part_image_url_serde() {
        let part = ContentPart::ImageUrl {
            image_url: ImageUrl {
                url: "data:image/png;base64,abc".into(),
                detail: None,
            },
        };
        let json = serde_json::to_value(&part).unwrap();
        assert_eq!(json["type"], "image_url");
        assert_eq!(json["image_url"]["url"], "data:image/png;base64,abc");
    }

    // ---- ImageDetail ----

    #[test]
    fn image_detail_serde() {
        for (detail, expected) in [
            (ImageDetail::Auto, "auto"),
            (ImageDetail::Low, "low"),
            (ImageDetail::High, "high"),
        ] {
            let json = serde_json::to_value(detail).unwrap();
            assert_eq!(json.as_str().unwrap(), expected);
        }
    }

    // ---- FinishReason ----

    #[test]
    fn finish_reason_serde_all_variants() {
        for (reason, expected) in [
            (FinishReason::Stop, "stop"),
            (FinishReason::Length, "length"),
            (FinishReason::ToolCalls, "tool_calls"),
            (FinishReason::ContentFilter, "content_filter"),
        ] {
            let json = serde_json::to_value(reason).unwrap();
            assert_eq!(json.as_str().unwrap(), expected);
            let back: FinishReason = serde_json::from_value(json).unwrap();
            assert_eq!(back, reason);
        }
    }

    // ---- Usage ----

    #[test]
    fn usage_default() {
        let usage = Usage::default();
        assert_eq!(usage.prompt_tokens, 0);
        assert_eq!(usage.completion_tokens, 0);
        assert_eq!(usage.total_tokens, 0);
        assert!(usage.prompt_tokens_details.is_none());
    }

    #[test]
    fn usage_calculate_cost_basic() {
        let usage = Usage {
            prompt_tokens: 1_000_000,
            completion_tokens: 1_000_000,
            total_tokens: 2_000_000,
            prompt_tokens_details: None,
        };
        let cost = usage.calculate_cost(Model::Gpt4o);
        // 1M input * $2.50/M + 1M output * $10/M = $12.50
        assert!((cost - 12.50).abs() < 0.001);
    }

    #[test]
    fn usage_calculate_cost_with_cached_tokens() {
        let usage = Usage {
            prompt_tokens: 1_000_000,
            completion_tokens: 0,
            total_tokens: 1_000_000,
            prompt_tokens_details: Some(PromptTokensDetails {
                cached_tokens: 500_000,
            }),
        };
        let cost = usage.calculate_cost(Model::Gpt4o);
        // 500K uncached * $2.50/M + 500K cached * $1.25/M = $1.25 + $0.625 = $1.875
        assert!((cost - 1.875).abs() < 0.001);
    }

    #[test]
    fn usage_calculate_cost_zero() {
        let usage = Usage::default();
        let cost = usage.calculate_cost(Model::Gpt4oMini);
        assert_eq!(cost, 0.0);
    }

    #[test]
    fn usage_calculate_cost_gpt35_turbo() {
        let usage = Usage {
            prompt_tokens: 1_000,
            completion_tokens: 500,
            total_tokens: 1_500,
            prompt_tokens_details: None,
        };
        let cost = usage.calculate_cost(Model::Gpt35Turbo);
        // 1K * $0.50/M + 500 * $1.50/M = $0.0005 + $0.00075 = $0.00125
        assert!((cost - 0.00125).abs() < 0.000001);
    }

    #[test]
    fn usage_deserialize_with_details() {
        let json = json!({
            "prompt_tokens": 100,
            "completion_tokens": 50,
            "total_tokens": 150,
            "prompt_tokens_details": { "cached_tokens": 30 }
        });
        let usage: Usage = serde_json::from_value(json).unwrap();
        assert_eq!(usage.prompt_tokens, 100);
        assert_eq!(usage.completion_tokens, 50);
        let details = usage.prompt_tokens_details.unwrap();
        assert_eq!(details.cached_tokens, 30);
    }

    #[test]
    fn usage_deserialize_minimal() {
        let json = json!({
            "prompt_tokens": 10,
            "completion_tokens": 5,
            "total_tokens": 15
        });
        let usage: Usage = serde_json::from_value(json).unwrap();
        assert_eq!(usage.total_tokens, 15);
        assert!(usage.prompt_tokens_details.is_none());
    }

    // ---- EmbeddingModel ----

    #[test]
    fn embedding_model_as_str() {
        assert_eq!(
            EmbeddingModel::TextEmbedding3Small.as_str(),
            "text-embedding-3-small"
        );
        assert_eq!(
            EmbeddingModel::TextEmbedding3Large.as_str(),
            "text-embedding-3-large"
        );
        assert_eq!(
            EmbeddingModel::TextEmbeddingAda002.as_str(),
            "text-embedding-ada-002"
        );
    }

    #[test]
    fn embedding_model_default() {
        assert_eq!(
            EmbeddingModel::default(),
            EmbeddingModel::TextEmbedding3Small
        );
    }

    #[test]
    fn embedding_model_dimensions() {
        assert_eq!(
            EmbeddingModel::TextEmbedding3Small.default_dimensions(),
            1536
        );
        assert_eq!(
            EmbeddingModel::TextEmbedding3Large.default_dimensions(),
            3072
        );
        assert_eq!(
            EmbeddingModel::TextEmbeddingAda002.default_dimensions(),
            1536
        );
    }

    #[test]
    fn embedding_model_pricing() {
        assert_eq!(
            EmbeddingModel::TextEmbedding3Small.price_per_million(),
            0.02
        );
        assert_eq!(
            EmbeddingModel::TextEmbedding3Large.price_per_million(),
            0.13
        );
        assert_eq!(
            EmbeddingModel::TextEmbeddingAda002.price_per_million(),
            0.10
        );
    }

    #[test]
    fn embedding_model_max_input_tokens() {
        assert_eq!(EmbeddingModel::TextEmbedding3Small.max_input_tokens(), 8191);
        assert_eq!(EmbeddingModel::TextEmbedding3Large.max_input_tokens(), 8191);
    }

    #[test]
    fn embedding_model_serde() {
        let model = EmbeddingModel::TextEmbedding3Large;
        let json = serde_json::to_value(model).unwrap();
        assert_eq!(json, "text-embedding-3-large");
        let back: EmbeddingModel = serde_json::from_value(json).unwrap();
        assert_eq!(back, EmbeddingModel::TextEmbedding3Large);
    }

    // ---- EmbeddingUsage ----

    #[test]
    fn embedding_usage_calculate_cost() {
        let usage = EmbeddingUsage {
            prompt_tokens: 1000,
            total_tokens: 1000,
        };
        let cost = usage.calculate_cost(EmbeddingModel::TextEmbedding3Small);
        // 1000 / 1M * $0.02 = $0.00002
        assert!((cost - 0.00002).abs() < 0.0000001);
    }

    // ---- EmbeddingInput ----

    #[test]
    fn embedding_input_single_serde() {
        let input = EmbeddingInput::Single("hello".into());
        let json = serde_json::to_value(&input).unwrap();
        assert_eq!(json, "hello");
    }

    #[test]
    fn embedding_input_batch_serde() {
        let input = EmbeddingInput::Batch(vec!["a".into(), "b".into()]);
        let json = serde_json::to_value(&input).unwrap();
        let arr = json.as_array().unwrap();
        assert_eq!(arr.len(), 2);
    }

    // ---- ImageModel ----

    #[test]
    fn image_model_as_str() {
        assert_eq!(ImageModel::DallE3.as_str(), "dall-e-3");
        assert_eq!(ImageModel::DallE2.as_str(), "dall-e-2");
    }

    #[test]
    fn image_model_default() {
        assert_eq!(ImageModel::default(), ImageModel::DallE3);
    }

    #[test]
    fn image_model_serde() {
        let model = ImageModel::DallE2;
        let json = serde_json::to_value(model).unwrap();
        assert_eq!(json, "dall-e-2");
        let back: ImageModel = serde_json::from_value(json).unwrap();
        assert_eq!(back, ImageModel::DallE2);
    }

    // ---- ImageSize ----

    #[test]
    fn image_size_default() {
        assert_eq!(ImageSize::default(), ImageSize::Size1024);
    }

    #[test]
    fn image_size_serde_all() {
        for (size, expected) in [
            (ImageSize::Size256, "256x256"),
            (ImageSize::Size512, "512x512"),
            (ImageSize::Size1024, "1024x1024"),
            (ImageSize::SizeLandscape, "1792x1024"),
            (ImageSize::SizePortrait, "1024x1792"),
        ] {
            let json = serde_json::to_value(size).unwrap();
            assert_eq!(json.as_str().unwrap(), expected);
            let back: ImageSize = serde_json::from_value(json).unwrap();
            assert_eq!(back, size);
        }
    }

    // ---- ImageQuality ----

    #[test]
    fn image_quality_default() {
        assert_eq!(ImageQuality::default(), ImageQuality::Standard);
    }

    #[test]
    fn image_quality_serde() {
        let json = serde_json::to_value(ImageQuality::Hd).unwrap();
        assert_eq!(json, "hd");
        let back: ImageQuality = serde_json::from_value(json).unwrap();
        assert_eq!(back, ImageQuality::Hd);
    }

    // ---- VideoModel ----

    #[test]
    fn video_model_default() {
        assert_eq!(VideoModel::default(), VideoModel::Sora2);
        assert_eq!(VideoModel::Sora2.as_str(), "sora-2");
        assert_eq!(VideoModel::Sora2Pro.as_str(), "sora-2-pro");
    }

    #[test]
    fn video_duration_seconds_exact_parse() {
        assert_eq!(
            VideoDurationSeconds::from_u64(4),
            Some(VideoDurationSeconds::Seconds4)
        );
        assert_eq!(
            VideoDurationSeconds::from_u64(8),
            Some(VideoDurationSeconds::Seconds8)
        );
        assert_eq!(
            VideoDurationSeconds::from_u64(12),
            Some(VideoDurationSeconds::Seconds12)
        );
        assert_eq!(VideoDurationSeconds::from_u64(6), None);
    }

    #[test]
    fn video_size_as_str_all() {
        assert_eq!(VideoSize::Size720x1280.as_str(), "720x1280");
        assert_eq!(VideoSize::Size1280x720.as_str(), "1280x720");
        assert_eq!(VideoSize::Size1024x1792.as_str(), "1024x1792");
        assert_eq!(VideoSize::Size1792x1024.as_str(), "1792x1024");
    }

    #[test]
    fn video_status_unknown_deserializes_safely() {
        let status: VideoStatus = serde_json::from_value(json!("provider_new_status")).unwrap();
        assert_eq!(status, VideoStatus::Unknown);
    }

    // ---- WhisperModel ----

    #[test]
    fn whisper_model_as_str() {
        assert_eq!(WhisperModel::Whisper1.as_str(), "whisper-1");
    }

    #[test]
    fn whisper_model_default() {
        assert_eq!(WhisperModel::default(), WhisperModel::Whisper1);
    }

    #[test]
    fn whisper_model_pricing() {
        assert_eq!(WhisperModel::Whisper1.price_per_minute(), 0.006);
    }

    #[test]
    fn whisper_model_serde() {
        let json = serde_json::to_value(WhisperModel::Whisper1).unwrap();
        assert_eq!(json, "whisper-1");
        let back: WhisperModel = serde_json::from_value(json).unwrap();
        assert_eq!(back, WhisperModel::Whisper1);
    }

    // ---- TtsModel ----

    #[test]
    fn tts_model_as_str() {
        assert_eq!(TtsModel::Tts1.as_str(), "tts-1");
        assert_eq!(TtsModel::Tts1Hd.as_str(), "tts-1-hd");
    }

    #[test]
    fn tts_model_default() {
        assert_eq!(TtsModel::default(), TtsModel::Tts1);
    }

    #[test]
    fn tts_model_pricing() {
        assert_eq!(TtsModel::Tts1.price_per_million_chars(), 15.0);
        assert_eq!(TtsModel::Tts1Hd.price_per_million_chars(), 30.0);
    }

    #[test]
    fn tts_model_serde() {
        let json = serde_json::to_value(TtsModel::Tts1Hd).unwrap();
        assert_eq!(json, "tts-1-hd");
        let back: TtsModel = serde_json::from_value(json).unwrap();
        assert_eq!(back, TtsModel::Tts1Hd);
    }

    // ---- TtsVoice ----

    #[test]
    fn tts_voice_as_str_all() {
        assert_eq!(TtsVoice::Alloy.as_str(), "alloy");
        assert_eq!(TtsVoice::Echo.as_str(), "echo");
        assert_eq!(TtsVoice::Fable.as_str(), "fable");
        assert_eq!(TtsVoice::Onyx.as_str(), "onyx");
        assert_eq!(TtsVoice::Nova.as_str(), "nova");
        assert_eq!(TtsVoice::Shimmer.as_str(), "shimmer");
    }

    #[test]
    fn tts_voice_default() {
        assert_eq!(TtsVoice::default(), TtsVoice::Alloy);
    }

    #[test]
    fn tts_voice_serde() {
        let json = serde_json::to_value(TtsVoice::Nova).unwrap();
        assert_eq!(json, "nova");
        let back: TtsVoice = serde_json::from_value(json).unwrap();
        assert_eq!(back, TtsVoice::Nova);
    }

    // ---- TtsResponseFormat ----

    #[test]
    fn tts_response_format_as_str_all() {
        assert_eq!(TtsResponseFormat::Mp3.as_str(), "mp3");
        assert_eq!(TtsResponseFormat::Opus.as_str(), "opus");
        assert_eq!(TtsResponseFormat::Aac.as_str(), "aac");
        assert_eq!(TtsResponseFormat::Flac.as_str(), "flac");
    }

    #[test]
    fn tts_response_format_mime_types() {
        assert_eq!(TtsResponseFormat::Mp3.mime_type(), "audio/mpeg");
        assert_eq!(TtsResponseFormat::Opus.mime_type(), "audio/opus");
        assert_eq!(TtsResponseFormat::Aac.mime_type(), "audio/aac");
        assert_eq!(TtsResponseFormat::Flac.mime_type(), "audio/flac");
    }

    #[test]
    fn tts_response_format_default() {
        assert_eq!(TtsResponseFormat::default(), TtsResponseFormat::Mp3);
    }

    #[test]
    fn tts_response_format_serde() {
        let json = serde_json::to_value(TtsResponseFormat::Opus).unwrap();
        assert_eq!(json, "opus");
        let back: TtsResponseFormat = serde_json::from_value(json).unwrap();
        assert_eq!(back, TtsResponseFormat::Opus);
    }

    // ---- FineTuneStatus ----

    #[test]
    fn fine_tune_status_serde_all() {
        for (status, expected) in [
            (FineTuneStatus::ValidatingFiles, "validating_files"),
            (FineTuneStatus::Queued, "queued"),
            (FineTuneStatus::Running, "running"),
            (FineTuneStatus::Succeeded, "succeeded"),
            (FineTuneStatus::Failed, "failed"),
            (FineTuneStatus::Cancelled, "cancelled"),
        ] {
            let json = serde_json::to_value(status).unwrap();
            assert_eq!(json.as_str().unwrap(), expected);
            let back: FineTuneStatus = serde_json::from_value(json).unwrap();
            assert_eq!(back, status);
        }
    }

    // ---- RunStatus ----

    #[test]
    fn run_status_serde_all() {
        for (status, expected) in [
            (RunStatus::Queued, "queued"),
            (RunStatus::InProgress, "in_progress"),
            (RunStatus::RequiresAction, "requires_action"),
            (RunStatus::Cancelling, "cancelling"),
            (RunStatus::Cancelled, "cancelled"),
            (RunStatus::Failed, "failed"),
            (RunStatus::Completed, "completed"),
            (RunStatus::Incomplete, "incomplete"),
            (RunStatus::Expired, "expired"),
        ] {
            let json = serde_json::to_value(status).unwrap();
            assert_eq!(json.as_str().unwrap(), expected);
            let back: RunStatus = serde_json::from_value(json).unwrap();
            assert_eq!(back, status);
        }
    }

    // ---- ChatCompletionResponse deserialize ----

    #[test]
    fn chat_completion_response_deserialize() {
        let json = json!({
            "id": "chatcmpl-123",
            "object": "chat.completion",
            "created": 1677652288,
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "Hello!"
                },
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 5,
                "total_tokens": 15
            }
        });
        let resp: ChatCompletionResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.id, "chatcmpl-123");
        assert_eq!(resp.model, "gpt-4o");
        assert_eq!(resp.choices.len(), 1);
        assert_eq!(resp.choices[0].message.content.as_deref(), Some("Hello!"));
        assert_eq!(resp.choices[0].finish_reason, Some(FinishReason::Stop));
        let usage = resp.usage.unwrap();
        assert_eq!(usage.prompt_tokens, 10);
    }

    #[test]
    fn chat_completion_response_with_tool_calls() {
        let json = json!({
            "id": "chatcmpl-456",
            "object": "chat.completion",
            "created": 1677652288,
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_abc",
                        "type": "function",
                        "function": {
                            "name": "get_weather",
                            "arguments": "{\"location\":\"NYC\"}"
                        }
                    }]
                },
                "finish_reason": "tool_calls"
            }],
            "usage": {
                "prompt_tokens": 20,
                "completion_tokens": 10,
                "total_tokens": 30
            }
        });
        let resp: ChatCompletionResponse = serde_json::from_value(json).unwrap();
        assert!(resp.choices[0].message.content.is_none());
        let tc = resp.choices[0].message.tool_calls.as_ref().unwrap();
        assert_eq!(tc.len(), 1);
        assert_eq!(tc[0].function.name, "get_weather");
        assert_eq!(resp.choices[0].finish_reason, Some(FinishReason::ToolCalls));
    }

    // ---- ChatCompletionChunk deserialize ----

    #[test]
    fn chat_completion_chunk_deserialize() {
        let json = json!({
            "id": "chatcmpl-stream-1",
            "object": "chat.completion.chunk",
            "created": 1677652288,
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "delta": {
                    "content": "Hello"
                },
                "finish_reason": null
            }]
        });
        let chunk: ChatCompletionChunk = serde_json::from_value(json).unwrap();
        assert_eq!(chunk.id, "chatcmpl-stream-1");
        assert_eq!(chunk.choices[0].delta.content.as_deref(), Some("Hello"));
        assert!(chunk.choices[0].finish_reason.is_none());
    }

    // ---- Tool / ToolChoice serde ----

    #[test]
    fn tool_serde_roundtrip() {
        let tool = Tool {
            tool_type: "function".into(),
            function: FunctionDefinition {
                name: "get_weather".into(),
                description: Some("Get weather info".into()),
                parameters: Some(json!({
                    "type": "object",
                    "properties": {
                        "location": { "type": "string" }
                    }
                })),
            },
        };
        let json = serde_json::to_value(&tool).unwrap();
        assert_eq!(json["type"], "function");
        assert_eq!(json["function"]["name"], "get_weather");
        let back: Tool = serde_json::from_value(json).unwrap();
        assert_eq!(back.function.name, "get_weather");
    }

    #[test]
    fn tool_choice_string_serde() {
        let choice = ToolChoice::String("auto".into());
        let json = serde_json::to_value(&choice).unwrap();
        assert_eq!(json, "auto");
    }

    #[test]
    fn tool_choice_specific_serde() {
        let choice = ToolChoice::Specific {
            choice_type: "function".into(),
            function: ToolChoiceFunction {
                name: "get_weather".into(),
            },
        };
        let json = serde_json::to_value(&choice).unwrap();
        assert_eq!(json["type"], "function");
        assert_eq!(json["function"]["name"], "get_weather");
    }

    // ---- ImageGenerationResponse deserialize ----

    #[test]
    fn image_generation_response_deserialize() {
        let json = json!({
            "created": 1700000000,
            "data": [{
                "b64_json": "iVBOR...",
                "revised_prompt": "A revised description"
            }]
        });
        let resp: ImageGenerationResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.created, 1700000000);
        assert_eq!(resp.data.len(), 1);
        assert_eq!(resp.data[0].b64_json.as_deref(), Some("iVBOR..."));
        assert!(resp.data[0].revised_prompt.is_some());
    }

    #[test]
    fn image_data_url_variant() {
        let json = json!({
            "url": "https://example.com/image.png"
        });
        let data: ImageData = serde_json::from_value(json).unwrap();
        assert!(data.b64_json.is_none());
        assert_eq!(data.url.as_deref(), Some("https://example.com/image.png"));
    }

    // ---- TranscriptionResponse ----

    #[test]
    fn transcription_response_deserialize() {
        let json = json!({ "text": "Hello, world!" });
        let resp: TranscriptionResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.text, "Hello, world!");
    }

    // ---- FineTuneJob deserialize ----

    #[test]
    fn fine_tune_job_deserialize() {
        let json = json!({
            "id": "ftjob-123",
            "object": "fine_tuning.job",
            "model": "gpt-4o-mini-2024-07-18",
            "status": "running",
            "training_file": "file-abc",
            "validation_file": null,
            "fine_tuned_model": null,
            "created_at": 1700000000,
            "finished_at": null,
            "hyperparameters": { "n_epochs": 3 },
            "trained_tokens": null,
            "error": null
        });
        let job: FineTuneJob = serde_json::from_value(json).unwrap();
        assert_eq!(job.id, "ftjob-123");
        assert_eq!(job.status, FineTuneStatus::Running);
        assert!(job.fine_tuned_model.is_none());
        assert!(job.finished_at.is_none());
    }

    #[test]
    fn fine_tune_job_succeeded_with_model() {
        let json = json!({
            "id": "ftjob-456",
            "object": "fine_tuning.job",
            "model": "gpt-4o-mini-2024-07-18",
            "status": "succeeded",
            "training_file": "file-abc",
            "validation_file": "file-def",
            "fine_tuned_model": "ft:gpt-4o-mini:my-org:custom:abc123",
            "created_at": 1700000000,
            "finished_at": 1700003600,
            "trained_tokens": 50000,
            "error": null
        });
        let job: FineTuneJob = serde_json::from_value(json).unwrap();
        assert_eq!(job.status, FineTuneStatus::Succeeded);
        assert_eq!(
            job.fine_tuned_model.as_deref(),
            Some("ft:gpt-4o-mini:my-org:custom:abc123")
        );
        assert_eq!(job.trained_tokens, Some(50000));
    }

    #[test]
    fn fine_tune_job_with_error() {
        let json = json!({
            "id": "ftjob-789",
            "object": "fine_tuning.job",
            "model": "gpt-4o-mini-2024-07-18",
            "status": "failed",
            "training_file": "file-bad",
            "created_at": 1700000000,
            "error": {
                "code": "invalid_training_file",
                "message": "Training file format is invalid"
            }
        });
        let job: FineTuneJob = serde_json::from_value(json).unwrap();
        assert_eq!(job.status, FineTuneStatus::Failed);
        let error = job.error.unwrap();
        assert_eq!(error.code.as_deref(), Some("invalid_training_file"));
    }

    // ---- Assistant deserialize ----

    #[test]
    fn assistant_deserialize() {
        let json = json!({
            "id": "asst_123",
            "object": "assistant",
            "created_at": 1700000000,
            "name": "Math Tutor",
            "model": "gpt-4o",
            "instructions": "You help with math.",
            "tools": [{"type": "code_interpreter"}],
            "metadata": {}
        });
        let asst: Assistant = serde_json::from_value(json).unwrap();
        assert_eq!(asst.id, "asst_123");
        assert_eq!(asst.name.as_deref(), Some("Math Tutor"));
        assert_eq!(asst.tools.len(), 1);
        assert_eq!(asst.tools[0].tool_type, "code_interpreter");
    }

    // ---- Thread deserialize ----

    #[test]
    fn thread_deserialize() {
        let json = json!({
            "id": "thread_abc",
            "object": "thread",
            "created_at": 1700000000,
            "metadata": {}
        });
        let thread: Thread = serde_json::from_value(json).unwrap();
        assert_eq!(thread.id, "thread_abc");
        assert_eq!(thread.object, "thread");
    }

    // ---- ThreadMessage deserialize ----

    #[test]
    fn thread_message_deserialize() {
        let json = json!({
            "id": "msg_123",
            "object": "thread.message",
            "created_at": 1700000000,
            "thread_id": "thread_abc",
            "role": "user",
            "content": [{
                "type": "text",
                "text": { "value": "Hello!", "annotations": [] }
            }],
            "assistant_id": null,
            "run_id": null,
            "metadata": {}
        });
        let msg: ThreadMessage = serde_json::from_value(json).unwrap();
        assert_eq!(msg.id, "msg_123");
        assert_eq!(msg.thread_id, "thread_abc");
        assert_eq!(msg.role, "user");
        assert_eq!(msg.content.len(), 1);
        assert_eq!(msg.content[0].content_type, "text");
        assert_eq!(msg.content[0].text.as_ref().unwrap().value, "Hello!");
    }

    // ---- Run deserialize ----

    #[test]
    fn run_deserialize() {
        let json = json!({
            "id": "run_abc",
            "object": "thread.run",
            "created_at": 1700000000,
            "thread_id": "thread_abc",
            "assistant_id": "asst_123",
            "status": "completed",
            "model": "gpt-4o",
            "instructions": null,
            "tools": [],
            "started_at": 1700000001,
            "completed_at": 1700000010,
            "failed_at": null,
            "cancelled_at": null,
            "last_error": null,
            "usage": {
                "prompt_tokens": 100,
                "completion_tokens": 50,
                "total_tokens": 150
            },
            "metadata": {}
        });
        let run: Run = serde_json::from_value(json).unwrap();
        assert_eq!(run.id, "run_abc");
        assert_eq!(run.status, RunStatus::Completed);
        assert_eq!(run.started_at, Some(1700000001));
        let usage = run.usage.unwrap();
        assert_eq!(usage.prompt_tokens, 100);
    }

    #[test]
    fn run_with_error() {
        let json = json!({
            "id": "run_fail",
            "object": "thread.run",
            "created_at": 1700000000,
            "thread_id": "thread_abc",
            "assistant_id": "asst_123",
            "status": "failed",
            "model": "gpt-4o",
            "tools": [],
            "last_error": {
                "code": "rate_limit_exceeded",
                "message": "Too many requests"
            }
        });
        let run: Run = serde_json::from_value(json).unwrap();
        assert_eq!(run.status, RunStatus::Failed);
        let error = run.last_error.unwrap();
        assert_eq!(error.code, "rate_limit_exceeded");
    }

    // ---- ApiError deserialize ----

    #[test]
    fn api_error_deserialize() {
        let json = json!({
            "error": {
                "message": "Incorrect API key",
                "type": "invalid_request_error",
                "param": null,
                "code": "invalid_api_key"
            }
        });
        let err: ApiError = serde_json::from_value(json).unwrap();
        assert_eq!(err.error.error_type, "invalid_request_error");
        assert_eq!(err.error.code.as_deref(), Some("invalid_api_key"));
        assert!(err.error.param.is_none());
    }

    #[test]
    fn api_error_with_param() {
        let json = json!({
            "error": {
                "message": "Invalid value for temperature",
                "type": "invalid_request_error",
                "param": "temperature",
                "code": null
            }
        });
        let err: ApiError = serde_json::from_value(json).unwrap();
        assert_eq!(err.error.param.as_deref(), Some("temperature"));
        assert!(err.error.code.is_none());
    }

    // ---- Message serde roundtrip ----

    #[test]
    fn message_serde_roundtrip() {
        let msg = Message::user("Hello world");
        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(json["role"], "user");
        assert_eq!(json["content"], "Hello world");
        // tool_calls and tool_call_id should be skipped
        assert!(json.get("tool_calls").is_none());
        assert!(json.get("tool_call_id").is_none());
    }

    // ---- ResponseFormat serde ----

    #[test]
    fn response_format_serde() {
        let fmt = ResponseFormat {
            format_type: "json_object".into(),
        };
        let json = serde_json::to_value(&fmt).unwrap();
        assert_eq!(json["type"], "json_object");
        let back: ResponseFormat = serde_json::from_value(json).unwrap();
        assert_eq!(back.format_type, "json_object");
    }

    // ---- ToolCall serde ----

    #[test]
    fn tool_call_serde() {
        let tc = ToolCall {
            id: "call_1".into(),
            tool_type: "function".into(),
            function: FunctionCall {
                name: "search".into(),
                arguments: r#"{"q":"rust"}"#.into(),
            },
        };
        let json = serde_json::to_value(&tc).unwrap();
        assert_eq!(json["id"], "call_1");
        assert_eq!(json["type"], "function");
        assert_eq!(json["function"]["name"], "search");
        let back: ToolCall = serde_json::from_value(json).unwrap();
        assert_eq!(back.function.arguments, r#"{"q":"rust"}"#);
    }

    // ---- FineTuneHyperparameters serde ----

    #[test]
    fn fine_tune_hyperparameters_auto() {
        let hp = FineTuneHyperparameters {
            n_epochs: Some(json!("auto")),
            batch_size: None,
            learning_rate_multiplier: None,
        };
        let json = serde_json::to_value(&hp).unwrap();
        assert_eq!(json["n_epochs"], "auto");
        assert!(json.get("batch_size").is_none());
    }

    #[test]
    fn fine_tune_hyperparameters_numeric() {
        let hp = FineTuneHyperparameters {
            n_epochs: Some(json!(3)),
            batch_size: Some(json!(16)),
            learning_rate_multiplier: Some(json!(0.1)),
        };
        let json = serde_json::to_value(&hp).unwrap();
        assert_eq!(json["n_epochs"], 3);
        assert_eq!(json["batch_size"], 16);
    }

    // ---- EmbeddingResponse deserialize ----

    #[test]
    fn embedding_response_deserialize() {
        let json = json!({
            "object": "list",
            "data": [{
                "object": "embedding",
                "index": 0,
                "embedding": [0.1, 0.2, 0.3]
            }],
            "model": "text-embedding-3-small",
            "usage": {
                "prompt_tokens": 5,
                "total_tokens": 5
            }
        });
        let resp: EmbeddingResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.object, "list");
        assert_eq!(resp.data.len(), 1);
        assert_eq!(resp.data[0].embedding.len(), 3);
        assert_eq!(resp.usage.prompt_tokens, 5);
    }

    // ---- AssistantTool serde ----

    #[test]
    fn assistant_tool_code_interpreter() {
        let tool = AssistantTool {
            tool_type: "code_interpreter".into(),
            function: None,
        };
        let json = serde_json::to_value(&tool).unwrap();
        assert_eq!(json["type"], "code_interpreter");
        assert!(json.get("function").is_none());
    }

    #[test]
    fn assistant_tool_function() {
        let tool = AssistantTool {
            tool_type: "function".into(),
            function: Some(json!({
                "name": "my_func",
                "parameters": {}
            })),
        };
        let json = serde_json::to_value(&tool).unwrap();
        assert_eq!(json["type"], "function");
        assert_eq!(json["function"]["name"], "my_func");
    }

    // ---- FineTuneListResponse deserialize ----

    #[test]
    fn fine_tune_list_response_deserialize() {
        let json = json!({
            "data": [{
                "id": "ftjob-1",
                "object": "fine_tuning.job",
                "model": "gpt-4o-mini-2024-07-18",
                "status": "succeeded",
                "training_file": "file-abc",
                "created_at": 1700000000
            }],
            "has_more": false
        });
        let resp: FineTuneListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.data.len(), 1);
        assert!(!resp.has_more);
    }

    // ---- FineTuneEvent deserialize ----

    #[test]
    fn fine_tune_event_deserialize() {
        let json = json!({
            "id": "fte-1",
            "object": "fine_tuning.job.event",
            "created_at": 1700000000,
            "level": "info",
            "message": "Training started"
        });
        let evt: FineTuneEvent = serde_json::from_value(json).unwrap();
        assert_eq!(evt.id, "fte-1");
        assert_eq!(evt.level, "info");
        assert_eq!(evt.message, "Training started");
    }

    // ---- TtsRequest serde ----

    #[test]
    fn tts_request_serialize() {
        let req = TtsRequest {
            model: "tts-1".into(),
            input: "Hello world".into(),
            voice: "alloy".into(),
            response_format: Some("mp3".into()),
            speed: Some(1.5),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["model"], "tts-1");
        assert_eq!(json["voice"], "alloy");
        assert_eq!(json["speed"], 1.5);
    }

    #[test]
    fn tts_request_serialize_minimal() {
        let req = TtsRequest {
            model: "tts-1-hd".into(),
            input: "Hi".into(),
            voice: "nova".into(),
            response_format: None,
            speed: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert!(json.get("response_format").is_none());
        assert!(json.get("speed").is_none());
    }

    // ---- RunListResponse deserialize ----

    #[test]
    fn run_list_response_deserialize() {
        let json = json!({
            "data": [{
                "id": "run_1",
                "object": "thread.run",
                "created_at": 1700000000,
                "thread_id": "thread_abc",
                "assistant_id": "asst_123",
                "status": "queued",
                "model": "gpt-4o",
                "tools": []
            }],
            "has_more": true
        });
        let resp: RunListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.data.len(), 1);
        assert!(resp.has_more);
        assert_eq!(resp.data[0].status, RunStatus::Queued);
    }

    // ---- AssistantListResponse deserialize ----

    #[test]
    fn assistant_list_response_deserialize() {
        let json = json!({
            "data": [{
                "id": "asst_1",
                "object": "assistant",
                "created_at": 1700000000,
                "model": "gpt-4o",
                "tools": []
            }],
            "has_more": false
        });
        let resp: AssistantListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.data.len(), 1);
        assert!(!resp.has_more);
    }

    // ---- ThreadMessageListResponse deserialize ----

    #[test]
    fn thread_message_list_response_deserialize() {
        let json = json!({
            "data": [{
                "id": "msg_1",
                "object": "thread.message",
                "created_at": 1700000000,
                "thread_id": "thread_abc",
                "role": "user",
                "content": [{ "type": "text", "text": { "value": "Hi", "annotations": [] } }]
            }],
            "has_more": false
        });
        let resp: ThreadMessageListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.data.len(), 1);
        assert!(!resp.has_more);
    }
}
