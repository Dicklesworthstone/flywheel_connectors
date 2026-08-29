use std::collections::BTreeMap;
use std::time::Duration;

use reqwest::header::HeaderName;
use reqwest::{Client, RequestBuilder};
use tracing::debug;

use fcp_sdk::ConnectorRuntime;
use fcp_sdk::migration::{AttemptOutcome, HttpRetryConfig, RetryLoop};
use fcp_sdk::sigv4::{
    AwsCredentials, EMPTY_PAYLOAD_HASH, SigV4Signer, SignableRequest, SigningScope,
};

use crate::error::{BedrockError, BedrockResult, bedrock_error_from_status};
use crate::event_stream::decode_event_stream;
use crate::types::{
    BedrockAuth, BedrockStreamEvent, BedrockStreamResponse, ConverseInput, FoundationModelSummary,
    FoundationModelsResponse, HealthStatus, InvokeModelInput, ListModelsInput, ModelListSource,
};

pub struct BedrockClient {
    client: Client,
    auth: BedrockAuth,
    region: String,
    retry_config: HttpRetryConfig,
    runtime_base_url: Option<String>,
    control_base_url: Option<String>,
    mantle_bearer_token: Option<String>,
    mantle_base_url: Option<String>,
}

impl std::fmt::Debug for BedrockClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BedrockClient")
            .field("client", &self.client)
            .field("auth", &self.auth)
            .field("region", &self.region)
            .field("retry_config", &self.retry_config)
            .field("runtime_base_url", &self.runtime_base_url)
            .field("control_base_url", &self.control_base_url)
            .field(
                "mantle_bearer_token",
                &self.mantle_bearer_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("mantle_base_url", &self.mantle_base_url)
            .finish()
    }
}

impl BedrockClient {
    pub fn new(
        auth: BedrockAuth,
        region: &str,
        retry_config: HttpRetryConfig,
        request_timeout_ms: u64,
        runtime_base_url: Option<String>,
        control_base_url: Option<String>,
        mantle_bearer_token: Option<String>,
        mantle_base_url: Option<String>,
    ) -> BedrockResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_millis(request_timeout_ms))
            .build()
            .map_err(BedrockError::Http)?;

        Ok(Self {
            client,
            auth,
            region: region.to_string(),
            retry_config,
            runtime_base_url: normalize_base_url(runtime_base_url),
            control_base_url: normalize_base_url(control_base_url),
            mantle_bearer_token: trim_optional_nonempty(mantle_bearer_token),
            mantle_base_url: normalize_base_url(mantle_base_url),
        })
    }

    pub fn region(&self) -> &str {
        &self.region
    }

    fn runtime_url(&self) -> String {
        self.runtime_base_url
            .clone()
            .unwrap_or_else(|| format!("https://bedrock-runtime.{}.amazonaws.com", self.region))
    }

    fn control_url(&self) -> String {
        self.control_base_url
            .clone()
            .unwrap_or_else(|| format!("https://bedrock.{}.amazonaws.com", self.region))
    }

    fn mantle_root_url(&self) -> String {
        self.mantle_base_url
            .clone()
            .unwrap_or_else(|| format!("https://bedrock-mantle.{}.api.aws", self.region))
    }

    fn mantle_openai_url(&self) -> String {
        resolve_mantle_openai_base_url(&self.mantle_root_url())
    }

    fn mantle_anthropic_url(&self) -> String {
        resolve_mantle_anthropic_base_url(&self.mantle_root_url())
    }

    pub async fn converse(
        &self,
        runtime: &ConnectorRuntime,
        input: &ConverseInput,
    ) -> BedrockResult<serde_json::Value> {
        self.require_sigv4_credentials()?;
        validate_model_id(&input.model_id)?;
        let path = format!("/model/{}/converse", input.model_id);
        let url = format!("{}{}", self.runtime_url(), path);
        let body = input.request_body();
        self.post_json(runtime, url, path, body, "converse").await
    }

    pub async fn converse_stream(
        &self,
        runtime: &ConnectorRuntime,
        input: &ConverseInput,
    ) -> BedrockResult<BedrockStreamResponse> {
        self.require_sigv4_credentials()?;
        validate_model_id(&input.model_id)?;
        let path = format!("/model/{}/converse-stream", input.model_id);
        let url = format!("{}{}", self.runtime_url(), path);
        let body = input.request_body();
        self.post_event_stream(runtime, url, path, body, "converse_stream")
            .await
    }

    pub async fn invoke_model(
        &self,
        runtime: &ConnectorRuntime,
        input: &InvokeModelInput,
    ) -> BedrockResult<serde_json::Value> {
        if input.is_mantle_anthropic_messages() {
            return self
                .mantle_anthropic_messages(runtime, input, false, "invoke_model")
                .await;
        }
        self.require_sigv4_credentials()?;
        validate_model_id(&input.model_id)?;
        let path = format!("/model/{}/invoke", input.model_id);
        let url = format!("{}{}", self.runtime_url(), path);
        let body = input.request_body()?;
        self.post_json_with_invoke_headers(runtime, url, path, body, input, "invoke_model")
            .await
    }

    pub async fn invoke_model_stream(
        &self,
        runtime: &ConnectorRuntime,
        input: &InvokeModelInput,
    ) -> BedrockResult<BedrockStreamResponse> {
        if input.is_mantle_anthropic_messages() {
            return self.mantle_anthropic_messages_stream(runtime, input).await;
        }
        self.require_sigv4_credentials()?;
        validate_model_id(&input.model_id)?;
        let path = format!("/model/{}/invoke-with-response-stream", input.model_id);
        let url = format!("{}{}", self.runtime_url(), path);
        let body = input.request_body()?;
        self.post_event_stream_with_invoke_headers(
            runtime,
            url,
            path,
            body,
            input,
            "invoke_model_stream",
        )
        .await
    }

    pub async fn list_models(
        &self,
        runtime: &ConnectorRuntime,
        input: &ListModelsInput,
    ) -> BedrockResult<FoundationModelsResponse> {
        if matches!(input.source, Some(ModelListSource::Mantle)) {
            return self.list_mantle_models(runtime).await;
        }
        self.require_sigv4_credentials()?;
        let mut query = Vec::new();
        push_query(
            &mut query,
            "byCustomizationType",
            input.by_customization_type.as_deref(),
        );
        push_query(
            &mut query,
            "byInferenceType",
            input.by_inference_type.as_deref(),
        );
        push_query(
            &mut query,
            "byOutputModality",
            input.by_output_modality.as_deref(),
        );
        push_query(&mut query, "byProvider", input.by_provider.as_deref());
        let query_string = if query.is_empty() {
            String::new()
        } else {
            format!("?{}", query.join("&"))
        };
        let path = format!("/foundation-models{query_string}");
        let url = format!("{}{}", self.control_url(), path);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            let region = self.region.clone();
            async move {
                debug!(attempt, "Bedrock list foundation models");
                let req = sign_request(
                    client.get(&url),
                    &auth,
                    &region,
                    "bedrock",
                    "GET",
                    &url,
                    &[],
                );
                handle_json_response::<FoundationModelsResponse>(req).await
            }
        })
        .await
    }

    pub async fn health_check(&self, runtime: &ConnectorRuntime) -> BedrockResult<HealthStatus> {
        let models = self
            .list_models(runtime, &ListModelsInput::default())
            .await?;
        Ok(HealthStatus {
            control_plane_reachable: true,
            model_count: models.model_summaries.len(),
        })
    }

    async fn list_mantle_models(
        &self,
        runtime: &ConnectorRuntime,
    ) -> BedrockResult<FoundationModelsResponse> {
        let auth_value = self.require_mantle_bearer_token()?;
        let url = format!("{}/models", self.mantle_openai_url());
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth_value = auth_value.clone();
            async move {
                debug!(attempt, "Bedrock Mantle list models");
                let req = with_bearer_auth(
                    with_static_request_header(client.get(&url), "Accept", "application/json"),
                    &auth_value,
                );
                match handle_json_response::<MantleModelsResponse>(req).await {
                    AttemptOutcome::Success(response) => {
                        AttemptOutcome::Success(FoundationModelsResponse::from(response))
                    }
                    AttemptOutcome::Retryable { error, retry_after } => {
                        AttemptOutcome::Retryable { error, retry_after }
                    }
                    AttemptOutcome::Terminal(error) => AttemptOutcome::Terminal(error),
                }
            }
        })
        .await
    }

    async fn mantle_anthropic_messages(
        &self,
        runtime: &ConnectorRuntime,
        input: &InvokeModelInput,
        force_stream: bool,
        op: &'static str,
    ) -> BedrockResult<serde_json::Value> {
        validate_nonblank("model_id", &input.model_id)?;
        let body = input.mantle_anthropic_body(force_stream)?;
        let beta_header = input.mantle_beta_header();
        let auth_value = self.require_mantle_bearer_token()?;
        let url = format!("{}/v1/messages", self.mantle_anthropic_url());
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth_value = auth_value.clone();
            let beta_header = beta_header.clone();
            let body = body.clone();
            async move {
                debug!(attempt, op, "Bedrock Mantle Anthropic Messages request");
                let req = with_bearer_auth(
                    with_static_request_header(
                        with_static_request_header(
                            with_static_request_header(
                                client.post(&url),
                                "Accept",
                                "application/json",
                            ),
                            "Content-Type",
                            "application/json",
                        ),
                        "anthropic-beta",
                        &beta_header,
                    ),
                    &auth_value,
                )
                .json(&body);
                handle_json_response::<serde_json::Value>(req).await
            }
        })
        .await
    }

    async fn mantle_anthropic_messages_stream(
        &self,
        runtime: &ConnectorRuntime,
        input: &InvokeModelInput,
    ) -> BedrockResult<BedrockStreamResponse> {
        validate_nonblank("model_id", &input.model_id)?;
        let body = input.mantle_anthropic_body(true)?;
        let beta_header = input.mantle_beta_header();
        let auth_value = self.require_mantle_bearer_token()?;
        let url = format!("{}/v1/messages", self.mantle_anthropic_url());
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth_value = auth_value.clone();
            let beta_header = beta_header.clone();
            let body = body.clone();
            async move {
                debug!(attempt, "Bedrock Mantle Anthropic Messages stream request");
                let req = with_bearer_auth(
                    with_static_request_header(
                        with_static_request_header(
                            with_static_request_header(
                                client.post(&url),
                                "Accept",
                                "text/event-stream",
                            ),
                            "Content-Type",
                            "application/json",
                        ),
                        "anthropic-beta",
                        &beta_header,
                    ),
                    &auth_value,
                )
                .json(&body);
                handle_sse_response(req).await
            }
        })
        .await
    }

    fn require_mantle_bearer_token(&self) -> BedrockResult<String> {
        self.mantle_bearer_token
            .clone()
            .ok_or_else(|| BedrockError::Unauthorized(
                "mantle_bearer_token is required for Bedrock Mantle operations; pass a token derived from AWS_BEARER_TOKEN_BEDROCK or an IAM bearer-token generator".into(),
            ))
    }

    fn require_sigv4_credentials(&self) -> BedrockResult<()> {
        if self.auth.has_sigv4_credentials() {
            Ok(())
        } else {
            Err(BedrockError::Unauthorized(
                "access_key_id and secret_access_key are required for native Bedrock SigV4 operations".into(),
            ))
        }
    }

    async fn post_json(
        &self,
        runtime: &ConnectorRuntime,
        url: String,
        path: String,
        body: serde_json::Value,
        op: &'static str,
    ) -> BedrockResult<serde_json::Value> {
        self.post_json_with_headers(runtime, url, path, body, op, |req| {
            with_static_request_header(
                with_static_request_header(req, "Accept", "application/json"),
                "Content-Type",
                "application/json",
            )
        })
        .await
    }

    async fn post_json_with_invoke_headers(
        &self,
        runtime: &ConnectorRuntime,
        url: String,
        path: String,
        body: serde_json::Value,
        input: &InvokeModelInput,
        op: &'static str,
    ) -> BedrockResult<serde_json::Value> {
        let input = input.clone();
        self.post_json_with_headers(runtime, url, path, body, op, move |req| {
            apply_invoke_headers(req, &input, false)
        })
        .await
    }

    async fn post_json_with_headers<F>(
        &self,
        runtime: &ConnectorRuntime,
        url: String,
        _path: String,
        body: serde_json::Value,
        op: &'static str,
        apply_headers: F,
    ) -> BedrockResult<serde_json::Value>
    where
        F: Fn(RequestBuilder) -> RequestBuilder + Clone,
    {
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let body_bytes = serde_json::to_vec(&body)?;

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            let region = self.region.clone();
            let body = body.clone();
            let body_bytes = body_bytes.clone();
            let apply_headers = apply_headers.clone();
            async move {
                debug!(attempt, op, "Bedrock JSON request");
                let req = sign_request(
                    client.post(&url),
                    &auth,
                    &region,
                    "bedrock",
                    "POST",
                    &url,
                    &body_bytes,
                );
                let req = apply_headers(req).json(&body);
                handle_json_response::<serde_json::Value>(req).await
            }
        })
        .await
    }

    async fn post_event_stream(
        &self,
        runtime: &ConnectorRuntime,
        url: String,
        path: String,
        body: serde_json::Value,
        op: &'static str,
    ) -> BedrockResult<BedrockStreamResponse> {
        self.post_event_stream_with_headers(runtime, url, path, body, op, |req| {
            with_static_request_header(
                with_static_request_header(req, "Accept", "application/vnd.amazon.eventstream"),
                "Content-Type",
                "application/json",
            )
        })
        .await
    }

    async fn post_event_stream_with_invoke_headers(
        &self,
        runtime: &ConnectorRuntime,
        url: String,
        path: String,
        body: serde_json::Value,
        input: &InvokeModelInput,
        op: &'static str,
    ) -> BedrockResult<BedrockStreamResponse> {
        let input = input.clone();
        self.post_event_stream_with_headers(runtime, url, path, body, op, move |req| {
            apply_invoke_headers(req, &input, true)
        })
        .await
    }

    async fn post_event_stream_with_headers<F>(
        &self,
        runtime: &ConnectorRuntime,
        url: String,
        _path: String,
        body: serde_json::Value,
        op: &'static str,
        apply_headers: F,
    ) -> BedrockResult<BedrockStreamResponse>
    where
        F: Fn(RequestBuilder) -> RequestBuilder + Clone,
    {
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let body_bytes = serde_json::to_vec(&body)?;

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            let region = self.region.clone();
            let body = body.clone();
            let body_bytes = body_bytes.clone();
            let apply_headers = apply_headers.clone();
            async move {
                debug!(attempt, op, "Bedrock event-stream request");
                let req = sign_request(
                    client.post(&url),
                    &auth,
                    &region,
                    "bedrock",
                    "POST",
                    &url,
                    &body_bytes,
                );
                let req = apply_headers(req).json(&body);
                handle_event_stream_response(req).await
            }
        })
        .await
    }
}

fn normalize_base_url(base_url: Option<String>) -> Option<String> {
    base_url.and_then(|value| {
        let trimmed = value.trim().trim_end_matches('/').to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

fn trim_optional_nonempty(value: Option<String>) -> Option<String> {
    value.and_then(|entry| {
        let trimmed = entry.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

fn strip_known_mantle_suffix(base_url: &str) -> String {
    let trimmed = base_url.trim().trim_end_matches('/');
    if let Some(root) = trimmed.strip_suffix("/anthropic") {
        root.to_string()
    } else if let Some(root) = trimmed.strip_suffix("/v1") {
        root.to_string()
    } else {
        trimmed.to_string()
    }
}

fn resolve_mantle_openai_base_url(base_url: &str) -> String {
    format!("{}/v1", strip_known_mantle_suffix(base_url))
}

fn resolve_mantle_anthropic_base_url(base_url: &str) -> String {
    format!("{}/anthropic", strip_known_mantle_suffix(base_url))
}

fn validate_model_id(model_id: &str) -> BedrockResult<()> {
    let trimmed = model_id.trim();
    if trimmed.is_empty() {
        return Err(BedrockError::InvalidInput("model_id is required".into()));
    }
    let lower = trimmed.to_ascii_lowercase();
    if trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains("..")
        || lower.contains("%2f")
        || lower.contains("%5c")
    {
        return Err(BedrockError::InvalidInput(
            "model_id contains path traversal characters; pass a Bedrock model id or inference profile id, not an unencoded path".into(),
        ));
    }
    Ok(())
}

fn validate_nonblank(label: &str, value: &str) -> BedrockResult<()> {
    if value.trim().is_empty() {
        return Err(BedrockError::InvalidInput(format!("{label} is required")));
    }
    Ok(())
}

fn push_query(query: &mut Vec<String>, key: &str, value: Option<&str>) {
    let Some(value) = value else {
        return;
    };
    let value = value.trim();
    if value.is_empty() {
        return;
    }
    query.push(format!("{key}={}", percent_encode_query(value)));
}

fn percent_encode_query(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            b' ' => encoded.push_str("%20"),
            _ => {
                use std::fmt::Write as _;
                write!(encoded, "%{byte:02X}").expect("writing to a String cannot fail");
            }
        }
    }
    encoded
}

fn apply_invoke_headers(
    mut req: RequestBuilder,
    input: &InvokeModelInput,
    streaming: bool,
) -> RequestBuilder {
    req = with_static_request_header(req, "Content-Type", input.content_type());
    if streaming {
        req = with_static_request_header(req, "X-Amzn-Bedrock-Accept", input.accept());
    } else {
        req = with_static_request_header(req, "Accept", input.accept());
    }
    if let Some(trace) = &input.trace {
        req = with_static_request_header(req, "X-Amzn-Bedrock-Trace", trace);
    }
    if let Some(guardrail_identifier) = &input.guardrail_identifier {
        req = with_static_request_header(
            req,
            "X-Amzn-Bedrock-GuardrailIdentifier",
            guardrail_identifier,
        );
    }
    if let Some(guardrail_version) = &input.guardrail_version {
        req = with_static_request_header(req, "X-Amzn-Bedrock-GuardrailVersion", guardrail_version);
    }
    if let Some(latency) = &input.performance_config_latency {
        req = with_static_request_header(req, "X-Amzn-Bedrock-PerformanceConfig-Latency", latency);
    }
    if let Some(service_tier) = &input.service_tier {
        req = with_static_request_header(req, "X-Amzn-Bedrock-Service-Tier", service_tier);
    }
    req
}

fn sign_request(
    req: RequestBuilder,
    auth: &BedrockAuth,
    region: &str,
    service: &str,
    method: &str,
    url: &str,
    payload: &[u8],
) -> RequestBuilder {
    if auth.access_key_id.is_empty() {
        return req;
    }

    let credentials = AwsCredentials {
        access_key_id: auth.access_key_id.clone(),
        secret_access_key: auth.secret_access_key.clone(),
        session_token: auth.session_token.clone(),
    };
    let scope = SigningScope {
        region: region.to_string(),
        service: service.to_string(),
    };
    let signer = SigV4Signer::new(credentials, scope);
    let parsed = url::Url::parse(url).expect("Bedrock URL should be valid");
    let query_params: BTreeMap<String, String> = parsed
        .query_pairs()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect();
    let mut headers = BTreeMap::new();
    if let Some(host) = parsed.host_str() {
        headers.insert("host".to_string(), host.to_string());
    }
    let payload_hash = if payload.is_empty() {
        EMPTY_PAYLOAD_HASH.to_string()
    } else {
        SignableRequest::hash_payload(payload)
    };
    let signed_request = signer.sign(&SignableRequest {
        method: method.to_string(),
        uri: parsed.path().to_string(),
        query_params,
        headers,
        payload_hash: payload_hash.clone(),
    });

    let mut req = with_static_request_header(
        with_static_request_header(
            with_static_request_header(req, "Authorization", &signed_request.authorization),
            "X-Amz-Date",
            &signed_request.x_amz_date,
        ),
        "X-Amz-Content-Sha256",
        &payload_hash,
    );
    if let Some(token) = &signed_request.x_amz_security_token {
        req = with_static_request_header(req, "X-Amz-Security-Token", token);
    }
    req
}

fn with_static_request_header(
    req: RequestBuilder,
    name: &'static str,
    value: &str,
) -> RequestBuilder {
    let name = HeaderName::from_bytes(name.as_bytes())
        .expect("static Bedrock request header name should be valid");
    req.header(name, value) // ubs:ignore - outgoing reqwest request header, not a response header sink
}

fn with_bearer_auth(req: RequestBuilder, auth_value: &str) -> RequestBuilder {
    with_static_request_header(req, "Authorization", &format!("Bearer {auth_value}"))
}

async fn handle_json_response<T: serde::de::DeserializeOwned>(
    req: RequestBuilder,
) -> AttemptOutcome<T, BedrockError> {
    let resp = match req.send().await {
        Ok(response) => response,
        Err(error) => {
            return AttemptOutcome::Retryable {
                error: BedrockError::Http(error),
                retry_after: None,
            };
        }
    };
    let status = resp.status().as_u16();
    let retry_after = retry_after(&resp);
    let text = match resp.text().await {
        Ok(body) => body,
        Err(error) => return AttemptOutcome::Terminal(BedrockError::Http(error)),
    };
    if !(200..300).contains(&status) {
        return classify_error(status, retry_after, &text);
    }
    match serde_json::from_str::<T>(&text) {
        Ok(value) => AttemptOutcome::Success(value),
        Err(error) => AttemptOutcome::Terminal(BedrockError::Json(error)),
    }
}

async fn handle_event_stream_response(
    req: RequestBuilder,
) -> AttemptOutcome<BedrockStreamResponse, BedrockError> {
    let resp = match req.send().await {
        Ok(response) => response,
        Err(error) => {
            return AttemptOutcome::Retryable {
                error: BedrockError::Http(error),
                retry_after: None,
            };
        }
    };
    let status = resp.status().as_u16();
    let retry_after = retry_after(&resp);
    let bytes = match resp.bytes().await {
        Ok(body) => body,
        Err(error) => return AttemptOutcome::Terminal(BedrockError::Http(error)),
    };
    if !(200..300).contains(&status) {
        let body = String::from_utf8_lossy(&bytes);
        return classify_error(status, retry_after, &body);
    }
    match decode_event_stream(&bytes) {
        Ok(messages) => AttemptOutcome::Success(BedrockStreamResponse::from_messages(messages)),
        Err(error) => AttemptOutcome::Terminal(BedrockError::EventStream(error)),
    }
}

async fn handle_sse_response(
    req: RequestBuilder,
) -> AttemptOutcome<BedrockStreamResponse, BedrockError> {
    let resp = match req.send().await {
        Ok(response) => response,
        Err(error) => {
            return AttemptOutcome::Retryable {
                error: BedrockError::Http(error),
                retry_after: None,
            };
        }
    };
    let status = resp.status().as_u16();
    let retry_after = retry_after(&resp);
    let text = match resp.text().await {
        Ok(body) => body,
        Err(error) => return AttemptOutcome::Terminal(BedrockError::Http(error)),
    };
    if !(200..300).contains(&status) {
        return classify_error(status, retry_after, &text);
    }
    AttemptOutcome::Success(decode_sse_stream(&text))
}

fn retry_after(resp: &reqwest::Response) -> Option<Duration> {
    resp.headers()
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs)
}

fn classify_error<T>(
    status: u16,
    retry_after: Option<Duration>,
    body: &str,
) -> AttemptOutcome<T, BedrockError> {
    if status == 429 {
        return AttemptOutcome::Retryable {
            error: BedrockError::RateLimited {
                retry_after_ms: u64::try_from(
                    retry_after.unwrap_or(Duration::from_secs(30)).as_millis(),
                )
                .unwrap_or(u64::MAX),
            },
            retry_after,
        };
    }
    let error = bedrock_error_from_status(status, body);
    if error.is_retryable() {
        AttemptOutcome::Retryable { error, retry_after }
    } else {
        AttemptOutcome::Terminal(error)
    }
}

#[derive(Debug, serde::Deserialize)]
struct MantleModelsResponse {
    #[serde(default)]
    data: Vec<MantleModelEntry>,
}

#[derive(Debug, serde::Deserialize)]
struct MantleModelEntry {
    id: String,
    #[serde(default)]
    owned_by: Option<String>,
}

impl From<MantleModelsResponse> for FoundationModelsResponse {
    fn from(value: MantleModelsResponse) -> Self {
        let model_summaries = value
            .data
            .into_iter()
            .filter(|model| !model.id.trim().is_empty())
            .map(|model| FoundationModelSummary {
                model_arn: None,
                model_id: model.id.clone(),
                model_name: Some(model.id),
                provider_name: model
                    .owned_by
                    .or_else(|| Some("Amazon Bedrock Mantle".into())),
                input_modalities: vec!["TEXT".into()],
                output_modalities: vec!["TEXT".into()],
                response_streaming_supported: Some(true),
                customizations_supported: Vec::new(),
                inference_types_supported: vec!["MANTLE".into()],
            })
            .collect();
        Self { model_summaries }
    }
}

fn decode_sse_stream(text: &str) -> BedrockStreamResponse {
    let mut events = Vec::new();
    let mut event_type: Option<String> = None;
    let mut data_lines = Vec::new();

    for line in text.lines().chain(std::iter::once("")) {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            if !data_lines.is_empty() {
                let payload = data_lines.join("\n");
                let payload_json = serde_json::from_str::<serde_json::Value>(&payload).ok();
                let payload_utf8 = if payload_json.is_none() {
                    Some(payload.clone())
                } else {
                    None
                };
                events.push(BedrockStreamEvent {
                    event_type: event_type.take(),
                    headers: BTreeMap::new(),
                    payload_bytes: payload.len(),
                    payload_json,
                    payload_utf8,
                });
                data_lines.clear();
            }
            event_type = None;
            continue;
        }
        if line.starts_with(':') {
            continue;
        }
        if let Some(value) = line.strip_prefix("event:") {
            event_type = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("data:") {
            let value = value.trim_start();
            if value != "[DONE]" {
                data_lines.push(value.to_string());
            }
        }
    }

    BedrockStreamResponse::from_events(events)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_id_rejects_path_traversal() {
        assert!(validate_model_id("anthropic.claude-3-sonnet-20240229-v1:0").is_ok());
        assert!(validate_model_id("../secret").is_err());
        assert!(validate_model_id("arn:aws:bedrock:us-east-1::foundation-model/foo").is_err());
    }

    #[test]
    fn query_values_are_percent_encoded() {
        assert_eq!(percent_encode_query("Amazon Titan"), "Amazon%20Titan");
    }

    #[test]
    fn mantle_base_url_derivation_handles_openai_and_anthropic_suffixes() {
        assert_eq!(
            resolve_mantle_openai_base_url("https://bedrock-mantle.us-east-1.api.aws"),
            "https://bedrock-mantle.us-east-1.api.aws/v1"
        );
        assert_eq!(
            resolve_mantle_anthropic_base_url("https://bedrock-mantle.us-east-1.api.aws/v1"),
            "https://bedrock-mantle.us-east-1.api.aws/anthropic"
        );
        assert_eq!(
            resolve_mantle_openai_base_url("https://bedrock-mantle.us-east-1.api.aws/anthropic"),
            "https://bedrock-mantle.us-east-1.api.aws/v1"
        );
    }

    #[test]
    fn sse_decoder_maps_anthropic_events_to_stream_response() {
        let stream = concat!(
            "event: message_start\n",
            "data: {\"type\":\"message_start\"}\n\n",
            "event: content_block_delta\n",
            "data: {\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n",
            "data: [DONE]\n\n",
        );

        let decoded = decode_sse_stream(stream);

        assert_eq!(decoded.chunk_count, 2);
        assert_eq!(
            decoded.events[0].event_type.as_deref(),
            Some("message_start")
        );
        assert_eq!(
            decoded.events[1].payload_json.as_ref().unwrap()["delta"]["text"],
            "hi"
        );
    }
}
