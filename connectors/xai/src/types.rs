use std::collections::{BTreeMap, BTreeSet};

use fcp_openai_compat::{
    ChatCompletionsRequest, ChatMessage, ContentPart, ContentParts, OpenAiError,
    ProviderExtensions, ResponseFormat, ToolChoice, ToolDefinition,
};
use fcp_prelude::{FcpError, FcpResult};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::{Map, Value, json};
use url::Url;

use crate::client::DEFAULT_MODEL;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChatInvokeInput {
    pub model: Option<String>,
    pub messages: Vec<ChatMessage>,
    pub temperature: Option<f32>,
    pub max_tokens: Option<u32>,
    pub top_p: Option<f32>,
    pub stop: Option<Vec<String>>,
    pub tools: Option<Vec<ToolDefinition>>,
    pub tool_choice: Option<ToolChoice>,
    pub response_format: Option<ResponseFormat>,
    pub seed: Option<i64>,
    pub user: Option<String>,
    pub n: Option<u32>,
    pub presence_penalty: Option<f32>,
    pub frequency_penalty: Option<f32>,
    pub logit_bias: Option<BTreeMap<String, f32>>,
    pub logprobs: Option<bool>,
    pub top_logprobs: Option<u32>,
    pub reasoning_effort: Option<String>,
    pub search_parameters: Option<Value>,
    #[serde(default)]
    pub provider_extensions: ProviderExtensions,
}

impl ChatInvokeInput {
    pub fn into_request(mut self, default_model: &str) -> FcpResult<ChatCompletionsRequest> {
        validate_xai_chat_input(&self)?;
        normalize_chat_images(&mut self.messages)?;
        if let Some(reasoning_effort) = self.reasoning_effort {
            self.provider_extensions
                .insert("reasoning_effort".to_string(), json!(reasoning_effort));
        }
        if let Some(search_parameters) = self.search_parameters {
            self.provider_extensions
                .insert("search_parameters".to_string(), search_parameters);
        }

        Ok(ChatCompletionsRequest {
            model: self.model.unwrap_or_else(|| default_model.to_string()),
            messages: self.messages,
            temperature: self.temperature,
            max_tokens: self.max_tokens,
            top_p: self.top_p,
            stop: self.stop,
            stream: false,
            tools: self.tools,
            tool_choice: self.tool_choice,
            response_format: self.response_format,
            seed: self.seed,
            user: self.user,
            n: self.n,
            presence_penalty: self.presence_penalty,
            frequency_penalty: self.frequency_penalty,
            logit_bias: self.logit_bias,
            logprobs: self.logprobs,
            top_logprobs: self.top_logprobs,
            provider_extensions: self.provider_extensions,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebSearchOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_domains: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub excluded_domains: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_image_understanding: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponsesCreateInput {
    pub model: Option<String>,
    pub input: Value,
    pub instructions: Option<String>,
    pub include: Option<Vec<String>>,
    pub web_search: Option<WebSearchOptions>,
    pub tools: Option<Vec<Value>>,
    pub tool_choice: Option<Value>,
    pub max_output_tokens: Option<u32>,
    pub temperature: Option<f32>,
    pub top_p: Option<f32>,
    pub store: Option<bool>,
    pub previous_response_id: Option<String>,
    pub metadata: Option<Value>,
    #[serde(default)]
    pub provider_extensions: ProviderExtensions,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ResponsesCreateRequest {
    pub model: String,
    pub input: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_response_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    #[serde(serialize_with = "serialize_response_extensions")]
    pub provider_extensions: ProviderExtensions,
}

const RESPONSE_FIELDS: &[&str] = &[
    "model",
    "input",
    "instructions",
    "include",
    "tools",
    "tool_choice",
    "max_output_tokens",
    "temperature",
    "top_p",
    "store",
    "previous_response_id",
    "metadata",
    "stream",
    "web_search",
    // These modes/reference forms have no authority representation in this
    // synchronous, web-search operation.
    "background",
    "conversation",
    "prompt",
];

fn validate_response_extensions(extensions: &ProviderExtensions) -> Result<(), OpenAiError> {
    if RESPONSE_FIELDS
        .iter()
        .any(|field| extensions.contains_key(*field))
    {
        return Err(OpenAiError::InvalidRequest {
            message: "Provider extensions must not replace typed Responses fields or response mode"
                .into(),
            param: Some("provider_extensions".into()),
            code: Some("reserved_provider_extension".into()),
        });
    }
    Ok(())
}

fn serialize_response_extensions<S: Serializer>(
    extensions: &ProviderExtensions,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    validate_response_extensions(extensions).map_err(<S::Error as serde::ser::Error>::custom)?;
    extensions.serialize(serializer)
}

impl ResponsesCreateRequest {
    /// Reject extensions that change authorized fields or select unsupported SSE.
    pub fn validate_provider_extensions(&self) -> Result<(), OpenAiError> {
        validate_response_extensions(&self.provider_extensions)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseCitation {
    #[serde(rename = "type")]
    pub citation_type: String,
    pub url: String,
    pub host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_index: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_index: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ResponsesSummary {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    pub output_text: String,
    pub output_text_bytes: usize,
    pub citation_count: usize,
    pub citation_hosts: Vec<String>,
    pub citations: Vec<ResponseCitation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_side_tool_usage: Option<Value>,
}

pub fn chat_request_from_value(
    value: Value,
    default_model: &str,
) -> FcpResult<ChatCompletionsRequest> {
    let input: ChatInvokeInput =
        serde_json::from_value(value).map_err(|err| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid xAI chat input: {err}"),
        })?;
    input.into_request(if default_model.trim().is_empty() {
        DEFAULT_MODEL
    } else {
        default_model
    })
}

pub fn responses_request_from_value(
    value: Value,
    default_model: &str,
) -> FcpResult<ResponsesCreateRequest> {
    let input: ResponsesCreateInput =
        serde_json::from_value(value).map_err(|err| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid xAI responses input: {err}"),
        })?;
    input.into_request(if default_model.trim().is_empty() {
        DEFAULT_MODEL
    } else {
        default_model
    })
}

pub fn summarize_responses_value(raw: &Value) -> ResponsesSummary {
    let mut output_text_parts = Vec::new();
    let mut citations = Vec::new();

    if let Some(output) = raw.get("output").and_then(Value::as_array) {
        for item in output {
            collect_output_text_and_annotations(item, &mut output_text_parts, &mut citations);
        }
    }
    if output_text_parts.is_empty() {
        if let Some(text) = raw
            .get("output_text")
            .or_else(|| raw.pointer("/text/value"))
            .and_then(Value::as_str)
        {
            output_text_parts.push(text.to_string());
        }
    }
    collect_legacy_citation_urls(raw, &mut citations);

    let output_text = output_text_parts.join("\n");
    let citation_hosts = citations
        .iter()
        .map(|citation| citation.host.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    ResponsesSummary {
        id: raw
            .get("id")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        model: raw
            .get("model")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        status: raw
            .get("status")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        output_text_bytes: output_text.len(),
        output_text,
        citation_count: citations.len(),
        citation_hosts,
        citations,
        usage: raw.get("usage").cloned(),
        server_side_tool_usage: raw.get("server_side_tool_usage").cloned(),
    }
}

impl ResponsesCreateInput {
    fn into_request(mut self, default_model: &str) -> FcpResult<ResponsesCreateRequest> {
        validate_responses_input(&self)?;
        normalize_responses_input(&mut self.input)?;
        if let Some(id) = &self.previous_response_id {
            validate_reference_id(id)?;
        }
        let mut tools = self.tools.unwrap_or_default();
        match self.web_search {
            Some(options) => {
                if tools.iter().any(is_web_search_tool) {
                    return Err(FcpError::InvalidRequest {
                        code: 1003,
                        message: "Provide web_search shorthand or a raw web_search tool, not both"
                            .into(),
                    });
                }
                tools.push(web_search_tool_value(&options)?);
            }
            None if !tools.iter().any(is_web_search_tool) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message:
                        "xai.responses.create requires a web_search tool or web_search options"
                            .into(),
                });
            }
            None => {}
        }
        for tool in &tools {
            validate_raw_web_search_tool(tool)?;
        }
        validate_search_tool_choice(self.tool_choice.as_ref())?;

        Ok(ResponsesCreateRequest {
            model: self.model.unwrap_or_else(|| default_model.to_string()),
            input: self.input,
            instructions: self.instructions,
            include: self.include,
            tools,
            tool_choice: self.tool_choice,
            max_output_tokens: self.max_output_tokens,
            temperature: self.temperature,
            top_p: self.top_p,
            store: self.store,
            previous_response_id: self.previous_response_id,
            metadata: self.metadata,
            provider_extensions: self.provider_extensions,
        })
    }
}

fn validate_xai_chat_input(input: &ChatInvokeInput) -> FcpResult<()> {
    if ["reasoning_effort", "search_parameters"]
        .iter()
        .any(|field| input.provider_extensions.contains_key(*field))
    {
        return Err(invalid_input(
            "Provider extensions must not replace typed xAI chat fields",
        ));
    }
    if let Some(parameters) = &input.search_parameters
        && !parameters.as_object().is_some_and(|object| {
            object.len() == 1 && object.get("mode").and_then(Value::as_str) == Some("off")
        })
    {
        return Err(invalid_input(
            "Live search requires xai.responses.create; chat search_parameters may only explicitly disable search with mode off",
        ));
    }
    if input.messages.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "messages must be a non-empty array".into(),
        });
    }
    if input.n.is_some_and(|n| n == 0) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "n must be greater than 0 when supplied".into(),
        });
    }
    Ok(())
}

fn invalid_input(message: &str) -> FcpError {
    FcpError::InvalidRequest {
        code: 1003,
        message: message.into(),
    }
}

fn canonical_input_url(raw: &str, allow_inline: bool) -> FcpResult<String> {
    if allow_inline && raw.starts_with("data:") {
        return Ok(raw.to_owned());
    }
    let invalid = || {
        invalid_input(
            "Input URL must be absolute HTTP(S) without embedded credentials or a fragment",
        )
    };
    let url = Url::parse(raw).map_err(|_| invalid())?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid());
    }
    Ok(url.to_string())
}

fn validate_reference_id(id: &str) -> FcpResult<()> {
    if id.is_empty()
        || id.len() > 256
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(invalid_input(
            "Stored resource IDs must be literal ASCII identifiers of at most 256 bytes",
        ));
    }
    Ok(())
}

fn normalize_chat_images(messages: &mut [ChatMessage]) -> FcpResult<()> {
    for message in messages {
        if let ChatMessage::User {
            content: ContentParts::Multimodal(parts),
            ..
        } = message
        {
            for part in parts {
                if let ContentPart::ImageUrl { image_url } = part {
                    image_url.url = canonical_input_url(&image_url.url, true)?;
                }
            }
        }
    }
    Ok(())
}

/// Return remote image resources from the normalized request sent to xAI.
pub(crate) fn chat_resource_uris(request: &ChatCompletionsRequest) -> Vec<String> {
    let mut resources = BTreeSet::new();
    for message in &request.messages {
        if let ChatMessage::User {
            content: ContentParts::Multimodal(parts),
            ..
        } = message
        {
            for part in parts {
                if let ContentPart::ImageUrl { image_url } = part
                    && !image_url.url.starts_with("data:")
                {
                    resources.insert(format!("xai:image_url:{}", image_url.url));
                }
            }
        }
    }
    resources.into_iter().collect()
}

/// Return every stored or remote input resource after request normalization.
pub(crate) fn responses_resource_uris(request: &ResponsesCreateRequest) -> Vec<String> {
    let mut resources = BTreeSet::new();
    if let Some(id) = &request.previous_response_id {
        resources.insert(format!("xai:response:{id}"));
    }
    collect_input_resources(&request.input, &mut resources);
    resources.into_iter().collect()
}

fn collect_input_resources(value: &Value, resources: &mut BTreeSet<String>) {
    match value {
        Value::Array(values) => {
            for child in values {
                collect_input_resources(child, resources);
            }
        }
        Value::Object(object) => {
            if matches!(
                object.get("type").and_then(Value::as_str),
                Some("input_image" | "input_file")
            ) {
                for (field, prefix) in [
                    ("image_url", "xai:image_url:"),
                    ("file_url", "xai:file_url:"),
                    ("file_id", "xai:file:"),
                ] {
                    if let Some(source) = object.get(field).and_then(Value::as_str)
                        && !source.starts_with("data:")
                    {
                        resources.insert(format!("{prefix}{source}"));
                    }
                }
            }
            for child in object.values() {
                collect_input_resources(child, resources);
            }
        }
        _ => {}
    }
}

fn allowed_fields(object: &Map<String, Value>, fields: &[&str]) -> FcpResult<()> {
    if object.keys().any(|key| !fields.contains(&key.as_str())) {
        return Err(invalid_input(
            "Unsupported field in Responses input or web-search tool",
        ));
    }
    Ok(())
}

fn normalize_responses_input(input: &mut Value) -> FcpResult<()> {
    match input {
        Value::String(_) => Ok(()),
        Value::Array(items) => {
            for item in items {
                normalize_response_item(item)?;
            }
            Ok(())
        }
        _ => Err(invalid_input(
            "Responses input must be text or an array of supported input items",
        )),
    }
}

fn normalize_response_item(item: &mut Value) -> FcpResult<()> {
    let object = item
        .as_object_mut()
        .ok_or_else(|| invalid_input("Responses input items must be objects"))?;
    let kind = match object.get("type") {
        None => "message".to_owned(),
        Some(Value::String(kind)) => kind.clone(),
        _ => return Err(invalid_input("Responses item type must be a string")),
    };
    match kind.as_str() {
        "message" => {
            allowed_fields(object, &["type", "role", "content", "id", "status"])?;
            if !matches!(
                object.get("role").and_then(Value::as_str),
                Some("user" | "assistant" | "system" | "developer")
            ) {
                return Err(invalid_input("Responses message requires a supported role"));
            }
            normalize_response_content(
                object
                    .get_mut("content")
                    .ok_or_else(|| invalid_input("Responses message requires content"))?,
            )
        }
        "function_call_output" => {
            allowed_fields(object, &["type", "call_id", "output", "id", "status"])?;
            validate_reference_id(
                object
                    .get("call_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid_input("Tool output requires a literal call_id"))?,
            )?;
            normalize_response_content(
                object
                    .get_mut("output")
                    .ok_or_else(|| invalid_input("Tool output requires output content"))?,
            )
        }
        // These are inline conversation history, not instructions to execute a
        // new tool. Preserve opaque reasoning and prior call payloads unchanged.
        "reasoning" | "function_call" | "web_search_call" => reject_unbound_references(item),
        _ => Err(invalid_input(
            "Unsupported Responses input reference or control item",
        )),
    }
}

fn normalize_response_content(content: &mut Value) -> FcpResult<()> {
    match content {
        Value::String(_) => Ok(()),
        Value::Array(parts) => {
            for part in parts {
                normalize_response_part(part)?;
            }
            Ok(())
        }
        _ => Err(invalid_input(
            "Responses content must be text or a content-part array",
        )),
    }
}

fn normalize_response_part(part: &mut Value) -> FcpResult<()> {
    let object = part
        .as_object_mut()
        .ok_or_else(|| invalid_input("Responses content parts must be objects"))?;
    let kind = object
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_input("Responses content part requires a type"))?
        .to_owned();
    let sources: &[&str] = match kind.as_str() {
        "input_text" | "output_text" | "summary_text" => {
            if !object.get("text").is_some_and(Value::is_string) {
                return Err(invalid_input("Text content parts require string text"));
            }
            return reject_unbound_references(part);
        }
        "refusal" => {
            if !object.get("refusal").is_some_and(Value::is_string) {
                return Err(invalid_input("Refusal content requires string text"));
            }
            return reject_unbound_references(part);
        }
        "input_image" => {
            allowed_fields(object, &["type", "image_url", "file_id", "detail"])?;
            &["image_url", "file_id"]
        }
        "input_file" => {
            allowed_fields(
                object,
                &[
                    "type",
                    "file_url",
                    "file_id",
                    "file_data",
                    "filename",
                    "detail",
                ],
            )?;
            &["file_url", "file_id", "file_data"]
        }
        _ => {
            return Err(invalid_input(
                "Unsupported Responses content or reference type",
            ));
        }
    };
    let present: Vec<_> = sources
        .iter()
        .copied()
        .filter(|field| object.get(*field).is_some_and(|value| !value.is_null()))
        .collect();
    let [source] = present.as_slice() else {
        return Err(invalid_input(
            "Image/file content requires exactly one source",
        ));
    };
    for field in ["filename", "detail"] {
        if object
            .get(field)
            .is_some_and(|value| !value.is_null() && !value.is_string())
        {
            return Err(invalid_input("Image/file metadata must be string-valued"));
        }
    }
    let value = object
        .get_mut(*source)
        .ok_or_else(|| invalid_input("Image/file source is missing"))?;
    let raw = value
        .as_str()
        .ok_or_else(|| invalid_input("Image/file sources must be strings"))?;
    match *source {
        "image_url" | "file_url" => {
            *value = Value::String(canonical_input_url(raw, *source == "image_url")?);
        }
        "file_id" => validate_reference_id(raw)?,
        "file_data" if raw.is_empty() => {
            return Err(invalid_input("Inline file data must not be empty"));
        }
        _ => {}
    }
    Ok(())
}

fn reject_unbound_references(value: &Value) -> FcpResult<()> {
    match value {
        Value::Array(values) => {
            for child in values {
                reject_unbound_references(child)?;
            }
        }
        Value::Object(object) => {
            if object.keys().any(|key| {
                matches!(
                    key.as_str(),
                    "image_url"
                        | "file_url"
                        | "file_id"
                        | "file_data"
                        | "previous_response_id"
                        | "response_id"
                        | "conversation"
                )
            }) || object.get("type").and_then(Value::as_str) == Some("item_reference")
            {
                return Err(invalid_input(
                    "External references require a supported image/file content part or previous_response_id",
                ));
            }
            for child in object.values() {
                reject_unbound_references(child)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_raw_web_search_tool(tool: &Value) -> FcpResult<()> {
    let object = tool
        .as_object()
        .ok_or_else(|| invalid_input("Responses tools must be web_search objects"))?;
    allowed_fields(object, &["type", "filters", "enable_image_understanding"])?;
    if !is_web_search_tool(tool) {
        return Err(invalid_input(
            "This Responses operation only authorizes web_search tools",
        ));
    }
    let mut options = WebSearchOptions {
        allowed_domains: None,
        excluded_domains: None,
        enable_image_understanding: None,
    };
    if let Some(filters) = object.get("filters") {
        let filter_object = filters
            .as_object()
            .ok_or_else(|| invalid_input("Web-search filters must be an object"))?;
        allowed_fields(filter_object, &["allowed_domains", "excluded_domains"])?;
        options = serde_json::from_value(filters.clone())
            .map_err(|_| invalid_input("Invalid web-search domain filters"))?;
    }
    if let Some(enabled) = object.get("enable_image_understanding") {
        options.enable_image_understanding = Some(
            enabled
                .as_bool()
                .ok_or_else(|| invalid_input("enable_image_understanding must be a boolean"))?,
        );
    }
    validate_web_search_options(&options)
}

fn validate_search_tool_choice(choice: Option<&Value>) -> FcpResult<()> {
    match choice {
        None | Some(Value::Null) => Ok(()),
        Some(Value::String(choice)) if matches!(choice.as_str(), "auto" | "none" | "required") => {
            Ok(())
        }
        Some(Value::Object(object))
            if object.len() == 1
                && object.get("type").and_then(Value::as_str) == Some("web_search") =>
        {
            Ok(())
        }
        _ => Err(invalid_input(
            "tool_choice must select the authorized web_search tool or a supported selection mode",
        )),
    }
}

fn validate_responses_input(input: &ResponsesCreateInput) -> FcpResult<()> {
    if input.input.is_null() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "input is required for xai.responses.create".into(),
        });
    }
    if let Some(options) = &input.web_search {
        validate_web_search_options(options)?;
    }
    if let Some(include) = &input.include {
        for value in include {
            validate_header_safe_string("include", value)?;
        }
    }
    Ok(())
}

fn validate_web_search_options(options: &WebSearchOptions) -> FcpResult<()> {
    if options.allowed_domains.is_some() && options.excluded_domains.is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "allowed_domains cannot be combined with excluded_domains".into(),
        });
    }
    validate_domain_list("allowed_domains", options.allowed_domains.as_deref())?;
    validate_domain_list("excluded_domains", options.excluded_domains.as_deref())?;
    Ok(())
}

fn validate_domain_list(field: &str, domains: Option<&[String]>) -> FcpResult<()> {
    let Some(domains) = domains else {
        return Ok(());
    };
    if domains.is_empty() || domains.len() > 5 {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must contain between 1 and 5 domains"),
        });
    }
    for domain in domains {
        validate_header_safe_string(field, domain)?;
        if domain.contains('/') || domain.contains(':') || domain.trim().starts_with('.') {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("{field} entries must be domain names, not URLs"),
            });
        }
    }
    Ok(())
}

fn validate_header_safe_string(field: &str, value: &str) -> FcpResult<()> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} entries must not be empty"),
        });
    }
    if trimmed
        .bytes()
        .any(|byte| matches!(byte, b'\r' | b'\n' | 0))
    {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} entries contain invalid control characters"),
        });
    }
    Ok(())
}

fn web_search_tool_value(options: &WebSearchOptions) -> FcpResult<Value> {
    validate_web_search_options(options)?;
    let mut tool = Map::new();
    tool.insert("type".into(), json!("web_search"));
    if let Some(enable_image_understanding) = options.enable_image_understanding {
        tool.insert(
            "enable_image_understanding".into(),
            json!(enable_image_understanding),
        );
    }
    let mut filters = Map::new();
    if let Some(allowed_domains) = &options.allowed_domains {
        filters.insert("allowed_domains".into(), json!(allowed_domains));
    }
    if let Some(excluded_domains) = &options.excluded_domains {
        filters.insert("excluded_domains".into(), json!(excluded_domains));
    }
    if !filters.is_empty() {
        tool.insert("filters".into(), Value::Object(filters));
    }
    Ok(Value::Object(tool))
}

fn is_web_search_tool(value: &Value) -> bool {
    value
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|tool_type| tool_type == "web_search")
}

fn collect_output_text_and_annotations(
    value: &Value,
    output_text_parts: &mut Vec<String>,
    citations: &mut Vec<ResponseCitation>,
) {
    if value
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|kind| kind == "output_text")
    {
        if let Some(text) = value.get("text").and_then(Value::as_str) {
            output_text_parts.push(text.to_string());
        }
        if let Some(annotations) = value.get("annotations").and_then(Value::as_array) {
            for annotation in annotations {
                if let Some(citation) = citation_from_annotation(annotation) {
                    citations.push(citation);
                }
            }
        }
    }

    match value {
        Value::Array(values) => {
            for child in values {
                collect_output_text_and_annotations(child, output_text_parts, citations);
            }
        }
        Value::Object(map) => {
            for child in map.values() {
                collect_output_text_and_annotations(child, output_text_parts, citations);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn citation_from_annotation(value: &Value) -> Option<ResponseCitation> {
    let citation_type = value
        .get("type")
        .and_then(Value::as_str)
        .filter(|kind| *kind == "url_citation")?;
    let url = value.get("url").and_then(Value::as_str)?;
    let host = host_for_url(url)?;
    Some(ResponseCitation {
        citation_type: citation_type.to_string(),
        url: url.to_string(),
        host,
        title: value
            .get("title")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        start_index: value.get("start_index").and_then(Value::as_u64),
        end_index: value.get("end_index").and_then(Value::as_u64),
    })
}

fn collect_legacy_citation_urls(raw: &Value, citations: &mut Vec<ResponseCitation>) {
    let Some(values) = raw.get("citations").and_then(Value::as_array) else {
        return;
    };
    for value in values {
        let Some(url) = value.as_str() else {
            continue;
        };
        let Some(host) = host_for_url(url) else {
            continue;
        };
        citations.push(ResponseCitation {
            citation_type: "url_citation".into(),
            url: url.to_string(),
            host,
            title: None,
            start_index: None,
            end_index: None,
        });
    }
}

fn host_for_url(raw: &str) -> Option<String> {
    Url::parse(raw)
        .ok()
        .and_then(|url| url.host_str().map(ToString::to_string))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_openai_compat::ChatMessage;
    use serde_json::json;

    #[test]
    fn chat_request_does_not_enable_search_by_default() {
        let request = chat_request_from_value(
            json!({"messages": [{"role": "user", "content": "hello"}]}),
            DEFAULT_MODEL,
        )
        .expect("chat request should build");
        let value = serde_json::to_value(request).expect("request serializes");

        assert_eq!(value["model"], DEFAULT_MODEL);
        assert_eq!(value["stream"], false);
        assert!(value.get("search_parameters").is_none());
    }

    #[test]
    fn chat_request_only_preserves_explicitly_disabled_legacy_search() {
        let request = chat_request_from_value(
            json!({
                "messages": [{"role": "user", "content": "fresh news"}],
                "search_parameters": {"mode": "off"}
            }),
            DEFAULT_MODEL,
        )
        .expect("chat request should build");
        let value = serde_json::to_value(request).expect("request serializes");

        assert_eq!(value["search_parameters"]["mode"], "off");
        for parameters in [
            json!({"mode":"auto"}),
            json!({"mode":"on"}),
            json!({}),
            json!({"mode":"off", "sources":[{"type":"web"}]}),
            json!("off"),
        ] {
            assert!(
                chat_request_from_value(
                    json!({"messages":[{"role":"user","content":"hello"}],
                    "search_parameters":parameters}),
                    DEFAULT_MODEL,
                )
                .is_err()
            );
        }
        for field in ["reasoning_effort", "search_parameters"] {
            assert!(
                chat_request_from_value(
                    json!({"messages":[{"role":"user","content":"hello"}],
                    "provider_extensions":{field:{"mode":"off"}}}),
                    DEFAULT_MODEL,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn chat_image_authority_matches_the_canonical_body() {
        let request = chat_request_from_value(
            json!({"messages":[{"role":"user","content":[
                {"type":"image_url","image_url":{"url":"https://EXAMPLE.com:443/a/../input.png"}},
                {"type":"image_url","image_url":{"url":"data:image/png;base64,aGVsbG8="}}
            ]}]}),
            DEFAULT_MODEL,
        )
        .unwrap();
        assert_eq!(
            chat_resource_uris(&request),
            vec!["xai:image_url:https://example.com/input.png"]
        );
        let body = serde_json::to_value(request).unwrap();
        assert_eq!(
            body["messages"][0]["content"][0]["image_url"]["url"],
            "https://example.com/input.png"
        );
        assert_eq!(
            body["messages"][0]["content"][1]["image_url"]["url"],
            "data:image/png;base64,aGVsbG8="
        );
        for url in [
            "file:///etc/hosts",
            "https://user:secret@example.com/image",
            "https://example.com/image#fragment",
            "relative/image",
        ] {
            assert!(
                chat_request_from_value(
                    json!({"messages":[{"role":"user","content":[
                        {"type":"image_url","image_url":{"url":url}}
                    ]}]}),
                    DEFAULT_MODEL,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn responses_authority_covers_all_remote_and_stored_sources() {
        let request = responses_request_from_value(
            json!({
                "input":[{"role":"user","content":[
                    {"type":"input_text","text":"Compare these"},
                    {"type":"input_image","image_url":"https://EXAMPLE.com:443/a/../image.png"},
                    {"type":"input_image","image_url":"data:image/png;base64,aGVsbG8="},
                    {"type":"input_file","file_url":"https://EXAMPLE.com:443/report.pdf"},
                    {"type":"input_file","file_id":"file-1"},
                    {"type":"input_image","file_id":"file-2"},
                    {"type":"input_file","file_data":"aGVsbG8=","filename":"inline.txt"}
                ]}],
                "previous_response_id":"resp-1",
                "web_search":{}
            }),
            DEFAULT_MODEL,
        )
        .unwrap();
        assert_eq!(
            responses_resource_uris(&request),
            vec![
                "xai:file:file-1",
                "xai:file:file-2",
                "xai:file_url:https://example.com/report.pdf",
                "xai:image_url:https://example.com/image.png",
                "xai:response:resp-1",
            ]
        );
        let body = serde_json::to_value(request).unwrap();
        assert_eq!(
            body["input"][0]["content"][1]["image_url"],
            "https://example.com/image.png"
        );
        assert_eq!(
            body["input"][0]["content"][3]["file_url"],
            "https://example.com/report.pdf"
        );
    }

    #[test]
    fn responses_preserve_inline_history_and_meter_tool_output_sources() {
        let reasoning =
            json!({"type":"reasoning", "summary":[], "encrypted_content":"opaque-inline-history"});
        let call = json!({"type":"function_call", "name":"describe", "call_id":"call-1", "arguments":"{}"});
        let request = responses_request_from_value(
            json!({"input":[
                reasoning,
                call,
                {"type":"function_call_output","call_id":"call-1","output":[
                    {"type":"input_image","image_url":"https://EXAMPLE.com:443/image.png"}
                ]},
                {"type":"message","role":"assistant","id":"msg-1","status":"completed",
                    "content":[{"type":"output_text","text":"Prior answer","annotations":[]}]}
            ],"web_search":{}}),
            DEFAULT_MODEL,
        )
        .unwrap();
        assert_eq!(request.input[0], reasoning);
        assert_eq!(request.input[1], call);
        assert_eq!(
            responses_resource_uris(&request),
            vec!["xai:image_url:https://example.com/image.png"]
        );
    }

    #[test]
    fn responses_reject_ambiguous_or_unbound_reference_shapes() {
        for part in [
            json!({"type":"input_image","image_url":"https://example.com/a","file_id":"file-1"}),
            json!({"type":"input_image","image_url":{"url":"https://example.com/a"}}),
            json!({"type":"input_image","image_url":"https://user:private@example.com/a"}),
            json!({"type":"input_file","file_id":"file-*"}),
            json!({"type":"input_file","file_url":"file:///etc/hosts"}),
            json!({"type":"input_file","file_data":"aGVsbG8=","file_url":"https://example.com/a"}),
            json!({"type":"input_file"}),
            json!({"type":"input_text","text":"hello","file_id":"file-1"}),
            json!({"type":"unknown_reference","id":"file-1"}),
        ] {
            assert!(
                responses_request_from_value(
                    json!({"input":[{"role":"user","content":[part]}],"web_search":{}}),
                    DEFAULT_MODEL,
                )
                .is_err()
            );
        }
        for input in [
            json!(false),
            json!({"file_id":"file-1"}),
            json!([{"type":"item_reference","id":"msg-1"}]),
            json!([{"type":"mcp_approval_response","approval_request_id":"mcp-1","approve":true}]),
            json!([{"type":"reasoning","summary":[],"file_id":"file-1"}]),
        ] {
            assert!(responses_request_from_value(
                json!({"input":input,"web_search":{}}), DEFAULT_MODEL,
            ).is_err());
        }
        for id in ["", "resp-*", " resp-1", "resp/1"] {
            assert!(
                responses_request_from_value(
                    json!({"input":"hello","web_search":{},"previous_response_id":id}),
                    DEFAULT_MODEL,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn responses_reject_additional_tools_and_unvalidated_tool_controls() {
        for tool in [
            json!({"type":"code_interpreter"}),
            json!({"type":"mcp","server_url":"https://example.com"}),
            json!({"type":"function","name":"side_effect"}),
            json!({"type":"web_search","filters":{"allowed_domains":["x.ai"],"excluded_domains":["example.com"]}}),
            json!({"type":"web_search","enable_image_understanding":"true"}),
            json!({"type":"web_search","server_url":"https://example.com"}),
        ] {
            assert!(
                responses_request_from_value(
                    json!({"input":"hello","tools":[{"type":"web_search"},tool]}),
                    DEFAULT_MODEL,
                )
                .is_err()
            );
        }
        for choice in [
            json!({"type":"function","name":"side_effect"}),
            json!({"type":"mcp"}),
            json!(true),
        ] {
            assert!(
                responses_request_from_value(
                    json!({"input":"hello","web_search":{},"tool_choice":choice}),
                    DEFAULT_MODEL,
                )
                .is_err()
            );
        }
        assert!(responses_request_from_value(
            json!({"input":"hello","tools":[{"type":"web_search","filters":{"allowed_domains":["x.ai"]}}],"tool_choice":{"type":"web_search"}}),
            DEFAULT_MODEL,
        ).is_ok());
    }

    #[test]
    fn responses_extensions_cannot_shadow_any_typed_field_or_response_mode() {
        let request =
            responses_request_from_value(json!({"input":"hello","web_search":{}}), DEFAULT_MODEL)
                .unwrap();
        for field in RESPONSE_FIELDS {
            let mut malicious = request.clone();
            malicious
                .provider_extensions
                .insert((*field).into(), json!("private-value-sentinel"));
            let error = malicious.validate_provider_extensions().unwrap_err();
            assert!(!error.to_string().contains("private-value-sentinel"));
            assert!(serde_json::to_value(&malicious).is_err());
            assert!(serde_json::to_vec(&malicious).is_err());
        }
        let mut allowed = request;
        allowed
            .provider_extensions
            .insert("parallel_tool_calls".into(), json!(false));
        allowed.validate_provider_extensions().unwrap();
        assert_eq!(
            serde_json::to_value(allowed).unwrap()["parallel_tool_calls"],
            false
        );
    }

    #[test]
    fn responses_web_search_shorthand_builds_current_tool_shape() {
        let request = responses_request_from_value(
            json!({
                "model": "grok-4.3",
                "input": [{"role": "user", "content": "What is xAI?"}],
                "include": ["no_inline_citations"],
                "web_search": {
                    "allowed_domains": ["x.ai"],
                    "enable_image_understanding": true
                }
            }),
            DEFAULT_MODEL,
        )
        .expect("responses request should build");
        let value = serde_json::to_value(request).expect("request serializes");

        assert_eq!(value["tools"][0]["type"], "web_search");
        assert_eq!(value["tools"][0]["filters"]["allowed_domains"][0], "x.ai");
        assert_eq!(value["tools"][0]["enable_image_understanding"], true);
        assert_eq!(value["include"][0], "no_inline_citations");
    }

    #[test]
    fn responses_web_search_rejects_ambiguous_domain_filters() {
        let error = responses_request_from_value(
            json!({
                "input": "hello",
                "web_search": {
                    "allowed_domains": ["x.ai"],
                    "excluded_domains": ["example.com"]
                }
            }),
            DEFAULT_MODEL,
        )
        .expect_err("ambiguous filters should be rejected");

        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn responses_requires_web_search_tool() {
        let error =
            responses_request_from_value(json!({"input": "hello", "tools": []}), DEFAULT_MODEL)
                .expect_err("plain responses should be rejected for this operation");

        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn citation_summary_extracts_annotations_and_hosts() {
        let raw = json!({
            "id": "resp_1",
            "model": "grok-4.3",
            "status": "completed",
            "output": [{
                "type": "message",
                "content": [{
                    "type": "output_text",
                    "text": "xAI ships Grok.[[1]](https://x.ai/news/grok-4-fast)",
                    "annotations": [{
                        "type": "url_citation",
                        "url": "https://x.ai/news/grok-4-fast",
                        "title": "1",
                        "start_index": 15,
                        "end_index": 55
                    }]
                }]
            }],
            "usage": {"input_tokens": 4, "output_tokens": 8}
        });

        let summary = summarize_responses_value(&raw);
        assert_eq!(summary.id.as_deref(), Some("resp_1"));
        assert_eq!(summary.citation_count, 1);
        assert_eq!(summary.citation_hosts, vec!["x.ai"]);
        assert_eq!(summary.citations[0].start_index, Some(15));
        assert!(summary.output_text.contains("[[1]]"));
    }

    #[test]
    fn multimodal_chat_message_still_uses_shared_oai_types() {
        let message = ChatMessage::user_text("inspect this");
        let request = ChatCompletionsRequest::new("grok-4.3", vec![message]);
        let value = serde_json::to_value(request).expect("request serializes");
        assert_eq!(value["messages"][0]["role"], "user");
    }
}
