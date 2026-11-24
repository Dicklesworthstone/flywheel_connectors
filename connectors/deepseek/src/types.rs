use std::collections::BTreeMap;

use fcp_openai_compat::{
    ChatCompletionsRequest, ChatMessage, ProviderExtensions, ResponseFormat, ToolChoice,
    ToolDefinition,
};
use fcp_prelude::{FcpError, FcpResult};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::client::DEFAULT_MODEL;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThinkingConfig {
    #[serde(rename = "type")]
    pub thinking_type: String,
}

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
    pub user_id: Option<String>,
    pub n: Option<u32>,
    pub presence_penalty: Option<f32>,
    pub frequency_penalty: Option<f32>,
    pub logit_bias: Option<BTreeMap<String, f32>>,
    pub logprobs: Option<bool>,
    pub top_logprobs: Option<u32>,
    pub thinking: Option<ThinkingConfig>,
    pub reasoning_effort: Option<String>,
    #[serde(default)]
    pub provider_extensions: ProviderExtensions,
}

impl ChatInvokeInput {
    pub fn into_request(mut self, default_model: &str) -> FcpResult<ChatCompletionsRequest> {
        validate_deepseek_chat_input(&self)?;
        if let Some(user_id) = self.user_id {
            self.provider_extensions
                .insert("user_id".to_string(), json!(user_id));
        }
        if let Some(thinking) = self.thinking {
            self.provider_extensions.insert(
                "thinking".to_string(),
                serde_json::to_value(thinking).map_err(|err| FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Invalid thinking parameter: {err}"),
                })?,
            );
        }
        if let Some(reasoning_effort) = self.reasoning_effort {
            self.provider_extensions
                .insert("reasoning_effort".to_string(), json!(reasoning_effort));
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
            user: None,
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

pub fn chat_request_from_value(
    value: Value,
    default_model: &str,
) -> FcpResult<ChatCompletionsRequest> {
    let input: ChatInvokeInput =
        serde_json::from_value(value).map_err(|err| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid DeepSeek chat input: {err}"),
        })?;
    input.into_request(if default_model.trim().is_empty() {
        DEFAULT_MODEL
    } else {
        default_model
    })
}

fn validate_deepseek_chat_input(input: &ChatInvokeInput) -> FcpResult<()> {
    // DeepSeek-specific controls also have typed fields. Flattened extension
    // keys must not bypass their validation or override an explicit value.
    if ["thinking", "reasoning_effort", "user_id"]
        .iter()
        .any(|field| input.provider_extensions.contains_key(*field))
    {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message:
                "Use typed thinking, reasoning_effort and user_id fields, not provider_extensions"
                    .into(),
        });
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
    if let Some(thinking) = &input.thinking {
        validate_enum(
            "thinking.type",
            &thinking.thinking_type,
            &["enabled", "disabled"],
        )?;
    }
    if let Some(reasoning_effort) = &input.reasoning_effort {
        validate_enum(
            "reasoning_effort",
            reasoning_effort,
            &["high", "max", "low", "medium", "xhigh"],
        )?;
    }
    Ok(())
}

fn validate_enum(field: &str, value: &str, allowed: &[&str]) -> FcpResult<()> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must be one of {}", allowed.join(", ")),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deepseek_typed_extensions_are_flattened_into_request_body() {
        let request = chat_request_from_value(
            json!({
                "model": "deepseek-v4-pro",
                "messages": [{"role": "user", "content": "hello"}],
                "thinking": {"type": "enabled"},
                "reasoning_effort": "max",
                "user_id": "operator-1"
            }),
            DEFAULT_MODEL,
        )
        .expect("request should decode");

        let value = serde_json::to_value(request).expect("request serializes");
        assert_eq!(value["thinking"]["type"], "enabled");
        assert_eq!(value["reasoning_effort"], "max");
        assert_eq!(value["user_id"], "operator-1");
        assert!(value.get("provider_extensions").is_none());
        assert!(value.get("user").is_none());
    }

    #[test]
    fn invalid_reasoning_effort_is_rejected() {
        let error = chat_request_from_value(
            json!({
                "messages": [{"role": "user", "content": "hello"}],
                "reasoning_effort": "tiny"
            }),
            DEFAULT_MODEL,
        )
        .expect_err("invalid effort should fail");

        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn invalid_thinking_type_is_rejected() {
        let error = chat_request_from_value(
            json!({
                "messages": [{"role": "user", "content": "hello"}],
                "thinking": {"type": "verbose"}
            }),
            DEFAULT_MODEL,
        )
        .expect_err("invalid thinking type should fail");

        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn provider_extensions_cannot_shadow_typed_deepseek_controls() {
        for field in ["thinking", "reasoning_effort", "user_id"] {
            let mut extensions = serde_json::Map::new();
            extensions.insert(field.into(), json!("unchecked"));
            let result = chat_request_from_value(
                json!({
                    "messages": [{"role":"user", "content":"hello"}],
                    "provider_extensions": extensions,
                }),
                DEFAULT_MODEL,
            );
            assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
        }
    }
}
