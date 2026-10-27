//! Generic Google REST executor substrate.
//!
//! This module centralizes request validation and HTTP mechanics so individual
//! connectors can focus on service semantics instead of rebuilding transport,
//! URL-template expansion, pagination extraction, upload/download routing, and
//! Google error parsing.

#![allow(clippy::result_large_err)]

use std::collections::BTreeMap;

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::{Method, StatusCode};

use crate::auth::GoogleMaterializedAuth;
use crate::{DiscoveryMethod, DiscoverySchema};

const PATH_SEGMENT_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

const MAX_SCHEMA_VALIDATION_DEPTH: usize = 64;

/// Upload mode for methods that expose Discovery `mediaUpload` metadata.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum GoogleUploadMode {
    /// `uploadType=media` (bytes-only payload).
    Simple,
    /// `uploadType=multipart` (metadata + media payload in multipart/related).
    Multipart,
    /// `uploadType=resumable` (session-init metadata request).
    Resumable,
}

impl GoogleUploadMode {
    #[must_use]
    const fn upload_type(self) -> &'static str {
        match self {
            Self::Simple => "media",
            Self::Multipart => "multipart",
            Self::Resumable => "resumable",
        }
    }
}

/// Upload payload details.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct GoogleUploadPayload {
    /// Upload mode.
    pub mode: GoogleUploadMode,
    /// MIME type for media bytes.
    pub content_type: String,
    /// Media bytes.
    pub bytes: Vec<u8>,
    /// Optional metadata JSON payload.
    pub metadata: Option<serde_json::Value>,
}

impl GoogleUploadPayload {
    /// Construct a simple media upload payload.
    #[must_use]
    pub fn simple(content_type: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            mode: GoogleUploadMode::Simple,
            content_type: content_type.into(),
            bytes,
            metadata: None,
        }
    }

    /// Construct a multipart upload payload.
    #[must_use]
    pub fn multipart(
        content_type: impl Into<String>,
        bytes: Vec<u8>,
        metadata: serde_json::Value,
    ) -> Self {
        Self {
            mode: GoogleUploadMode::Multipart,
            content_type: content_type.into(),
            bytes,
            metadata: Some(metadata),
        }
    }

    /// Construct a resumable upload init payload.
    #[must_use]
    pub fn resumable(
        content_type: impl Into<String>,
        bytes: Vec<u8>,
        metadata: serde_json::Value,
    ) -> Self {
        Self {
            mode: GoogleUploadMode::Resumable,
            content_type: content_type.into(),
            bytes,
            metadata: Some(metadata),
        }
    }
}

/// Preferred response decoding mode.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum GoogleResponseMode {
    /// Auto-detect from content type and payload shape.
    Auto,
    /// Decode strictly as JSON.
    Json,
    /// Return binary bytes.
    Binary,
}

/// Response body variant.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum GoogleResponseBody {
    /// Empty response body.
    Empty,
    /// JSON response payload.
    Json(serde_json::Value),
    /// Binary response payload.
    Binary(Vec<u8>),
}

impl GoogleResponseBody {
    /// JSON view when payload is JSON.
    #[must_use]
    pub const fn as_json(&self) -> Option<&serde_json::Value> {
        match self {
            Self::Json(value) => Some(value),
            Self::Empty | Self::Binary(_) => None,
        }
    }

    /// Byte-slice view when payload is binary.
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Binary(bytes) => Some(bytes.as_slice()),
            Self::Empty | Self::Json(_) => None,
        }
    }
}

/// Normalized Google API error payload.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct GoogleApiError {
    /// HTTP status code.
    pub status_code: u16,
    /// Top-level message.
    pub message: String,
    /// Optional canonical Google status (`PERMISSION_DENIED`, etc).
    pub status: Option<String>,
    /// Optional reason from the first detailed error.
    pub reason: Option<String>,
    /// Optional domain from the first detailed error.
    pub domain: Option<String>,
    /// Whether the error indicates API not enabled/configured.
    pub access_not_configured_hint: bool,
    /// Parsed `Retry-After` header value in milliseconds, if present.
    pub retry_after_ms: Option<u64>,
}

impl GoogleApiError {
    /// Whether this API error is retryable (429 or 5xx).
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(self.status_code, 429 | 500..=599)
    }

    /// Convert this Google API error into an [`fcp_core::FcpError`].
    ///
    /// The `service` parameter identifies the connector for diagnostics
    /// (e.g. `"google-ai"`, `"bigquery"`).
    #[must_use]
    pub fn to_fcp_error(&self, service: &str) -> fcp_core::FcpError {
        if self.status_code == 401 || self.status_code == 403 {
            fcp_core::FcpError::Unauthorized {
                code: 2001,
                message: self.message.clone(),
            }
        } else if self.status_code == 429 {
            fcp_core::FcpError::RateLimited {
                retry_after_ms: self.retry_after_ms.unwrap_or(60_000),
                violation: None,
            }
        } else {
            fcp_core::FcpError::External {
                service: service.into(),
                message: self.message.clone(),
                status_code: Some(self.status_code),
                retryable: self.is_retryable(),
                retry_after: None,
            }
        }
    }
}

/// Request parameters for one generic Google REST invocation.
#[derive(Debug)]
pub struct GoogleExecuteRequest<'a> {
    /// Normalized method metadata from Discovery.
    pub method: &'a DiscoveryMethod,
    /// Snapshot schema map for request body validation.
    pub schemas: &'a BTreeMap<String, DiscoverySchema>,
    /// Base API URL (for example `https://gmail.googleapis.com/`).
    pub base_url: &'a str,
    /// Parameter map (path/query values by parameter name).
    pub parameters: BTreeMap<String, Vec<String>>,
    /// Optional JSON request body.
    pub body: Option<serde_json::Value>,
    /// Optional upload payload for media-capable methods.
    pub upload: Option<GoogleUploadPayload>,
    /// Response decoding mode.
    pub response_mode: GoogleResponseMode,
    /// Optional materialized auth payload.
    pub auth: Option<&'a GoogleMaterializedAuth>,
    /// Additional headers to add after auth headers.
    pub extra_headers: Vec<(String, String)>,
}

impl<'a> GoogleExecuteRequest<'a> {
    /// Construct a minimal execution request.
    #[allow(clippy::missing_const_for_fn)]
    #[must_use]
    pub fn new(
        method: &'a DiscoveryMethod,
        schemas: &'a BTreeMap<String, DiscoverySchema>,
        base_url: &'a str,
    ) -> Self {
        Self {
            method,
            schemas,
            base_url,
            parameters: BTreeMap::new(),
            body: None,
            upload: None,
            response_mode: GoogleResponseMode::Auto,
            auth: None,
            extra_headers: Vec::new(),
        }
    }
}

/// Execution response with pagination metadata.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct GoogleExecuteResponse {
    /// HTTP status code.
    pub status_code: u16,
    /// Response headers in lowercase-preserving insertion order.
    pub headers: Vec<(String, String)>,
    /// Decoded response body.
    pub body: GoogleResponseBody,
    /// Extracted pagination token when present (`nextPageToken`).
    pub next_page_token: Option<String>,
}

/// Shared REST execution errors.
#[derive(Debug, thiserror::Error)]
pub enum GoogleRestError {
    /// Unsupported HTTP method in discovery metadata.
    #[error("unsupported http method `{method}`")]
    UnsupportedHttpMethod {
        /// Method string from discovery metadata.
        method: String,
    },

    /// Required parameter missing.
    #[error("missing required parameter `{name}`{location_suffix}")]
    MissingRequiredParameter {
        /// Parameter name.
        name: String,
        /// Optional discovery location (`path`, `query`, ...).
        location: Option<String>,
        /// Cached display suffix.
        location_suffix: String,
    },

    /// Parameter provided with no values.
    #[error("parameter `{name}` must include at least one value")]
    EmptyParameterValue {
        /// Parameter name.
        name: String,
    },

    /// Parameter repeated where discovery metadata marks it non-repeated.
    #[error("parameter `{name}` is not repeatable")]
    InvalidParameterMultiplicity {
        /// Parameter name.
        name: String,
    },

    /// Parameter not declared in discovery metadata.
    #[error("unknown parameter `{name}` for method `{method_key}`")]
    UnknownParameter {
        /// Method key.
        method_key: String,
        /// Parameter name.
        name: String,
    },

    /// Malformed path template.
    #[error("invalid path template `{template}`: {message}")]
    InvalidPathTemplate {
        /// Template string.
        template: String,
        /// Validation failure details.
        message: String,
    },

    /// Missing value for a template path parameter.
    #[error("missing path parameter `{name}` for template `{template}`")]
    MissingPathParameter {
        /// Parameter name.
        name: String,
        /// Template string.
        template: String,
    },

    /// Path traversal guard rejected a segment.
    #[error("path parameter `{name}` contains disallowed segment `{segment}`")]
    PathTraversalRejected {
        /// Parameter name.
        name: String,
        /// Rejected segment value.
        segment: String,
    },

    /// Base URL parse failed.
    #[error("invalid base url `{base_url}`: {message}")]
    InvalidBaseUrl {
        /// Base URL string.
        base_url: String,
        /// Parser error details.
        message: String,
    },

    /// URL join failed.
    #[error("failed to join path `{path}` against base `{base_url}`: {message}")]
    UrlJoin {
        /// Base URL string.
        base_url: String,
        /// Path string.
        path: String,
        /// Parser error details.
        message: String,
    },

    /// Request body is required by schema-aware validation.
    #[error("request body required for schema `{schema}`")]
    MissingRequestBody {
        /// Discovery schema reference.
        schema: String,
    },

    /// Request body provided where the method does not permit one.
    #[error("request body is not allowed for `{http_method}` without upload")]
    BodyNotAllowed {
        /// HTTP method name.
        http_method: String,
    },

    /// Request body failed schema validation.
    #[error("request body validation failed for `{schema}` at `{path}`: {message}")]
    RequestBodyValidation {
        /// Root schema reference.
        schema: String,
        /// JSON path in the payload.
        path: String,
        /// Validation details.
        message: String,
    },

    /// Unknown schema reference.
    #[error("unknown schema reference `{schema}`")]
    UnknownSchemaReference {
        /// Missing schema name.
        schema: String,
    },

    /// Upload mode/path mismatch.
    #[error("invalid upload configuration: {message}")]
    InvalidUploadConfiguration {
        /// Error detail.
        message: String,
    },

    /// Upload content type is invalid.
    #[error("invalid upload content type `{content_type}`: {message}")]
    InvalidUploadContentType {
        /// Content type string.
        content_type: String,
        /// Error detail.
        message: String,
    },

    /// A response exceeded the caller's retained-body budget.
    #[error("google rest response exceeded {limit} bytes")]
    ResponseTooLarge {
        /// Maximum permitted response bytes.
        limit: usize,
    },

    /// HTTP transport failure.
    #[error("google rest transport failed: {source}")]
    Http {
        /// Upstream reqwest error.
        source: reqwest::Error,
    },

    /// JSON decode failure.
    #[error("failed to decode response json: {source}")]
    JsonDecode {
        /// Upstream serde error.
        source: serde_json::Error,
    },

    /// Non-success Google API response.
    #[error("google api error {status_code}: {message}")]
    Api {
        /// Parsed API error payload.
        error: GoogleApiError,
        /// Cached status code.
        status_code: u16,
        /// Cached message.
        message: String,
    },
}

/// Shared Google REST executor.
#[derive(Debug, Clone)]
pub struct GoogleRestExecutor {
    client: reqwest::Client,
}

impl Default for GoogleRestExecutor {
    fn default() -> Self {
        Self {
            client: crate::default_http_client(),
        }
    }
}

impl GoogleRestExecutor {
    /// Construct an executor with a default HTTP client.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct an executor with a caller-provided client.
    #[must_use]
    pub fn with_client(mut self, client: reqwest::Client) -> Self {
        self.client = client;
        self
    }

    /// Execute a normalized Google API method request.
    ///
    /// # Errors
    ///
    /// Returns [`GoogleRestError`] when validation fails, transport fails, or
    /// the response is a non-success Google API error.
    pub async fn execute(
        &self,
        request: &GoogleExecuteRequest<'_>,
    ) -> Result<GoogleExecuteResponse, GoogleRestError> {
        self.execute_with_limit(request, None).await
    }

    /// Execute with a limit on bytes retained from either a success or error body.
    ///
    /// The limit is checked while reading, including responses without a
    /// `Content-Length`. An oversized response may follow a committed mutation;
    /// callers must not interpret this error as permission to replay the request.
    ///
    /// # Errors
    /// Returns the usual execution errors, or [`GoogleRestError::ResponseTooLarge`].
    pub async fn execute_bounded(
        &self,
        request: &GoogleExecuteRequest<'_>,
        max_response_bytes: usize,
    ) -> Result<GoogleExecuteResponse, GoogleRestError> {
        self.execute_with_limit(request, Some(max_response_bytes))
            .await
    }

    /// Send one chunk or status probe to a validated resumable-upload session.
    ///
    /// The caller must validate the session URI against its provider origin and
    /// use an executor configured with redirects disabled. The URI and query
    /// are preserved exactly; no `uploadType` parameter or retry is added.
    /// `308 Resume Incomplete` is returned with its headers for reconciliation.
    ///
    /// # Errors
    /// Returns bounded transport/API errors, with session URLs removed from
    /// transport diagnostics. An error never establishes whether bytes committed.
    pub async fn execute_resumable_put(
        &self,
        session_url: &reqwest::Url,
        auth: &GoogleMaterializedAuth,
        content_range: &str,
        body: Vec<u8>,
        max_response_bytes: usize,
        timeout: std::time::Duration,
    ) -> Result<GoogleExecuteResponse, GoogleRestError> {
        let mut builder = self
            .client
            .put(session_url.clone())
            .header(reqwest::header::CONTENT_RANGE, content_range)
            .header(reqwest::header::CONTENT_LENGTH, body.len())
            .body(body)
            .timeout(timeout);
        let mut headers = Vec::new();
        auth.apply_headers(&mut headers);
        for (name, value) in headers {
            builder = builder.header(name, value);
        }
        let response = builder
            .send()
            .await
            .map_err(|source| GoogleRestError::Http {
                source: source.without_url(),
            })?;
        Self::read_response(
            response,
            GoogleResponseMode::Json,
            Some(max_response_bytes),
            true,
        )
        .await
        .map_err(|error| match error {
            GoogleRestError::Http { source } => GoogleRestError::Http {
                source: source.without_url(),
            },
            other => other,
        })
    }

    async fn execute_with_limit(
        &self,
        request: &GoogleExecuteRequest<'_>,
        max_response_bytes: Option<usize>,
    ) -> Result<GoogleExecuteResponse, GoogleRestError> {
        validate_parameters(request.method, &request.parameters)?;
        let method = parse_http_method(&request.method.http_method)?;
        let path_template = resolve_path_template(request.method, request.upload.as_ref())?;
        let rendered_path = render_path_template(path_template, &request.parameters)?;
        let mut url = build_url(request.base_url, &rendered_path)?;
        append_query_parameters(&mut url, request)?;

        let validation_body = body_for_validation(request);
        validate_request_body(
            request.method,
            request.schemas,
            validation_body.as_ref(),
            request.upload.as_ref(),
        )?;

        let mut builder = self.client.request(method.clone(), url);

        if let Some(auth) = request.auth {
            let mut headers = Vec::new();
            auth.apply_headers(&mut headers);
            for (name, value) in headers {
                builder = builder.header(name, value);
            }
        }
        for (name, value) in &request.extra_headers {
            builder = builder.header(name, value);
        }

        builder = apply_payload(builder, &method, request, validation_body.as_ref())?;

        let response = builder
            .send()
            .await
            .map_err(|source| GoogleRestError::Http { source })?;
        Self::read_response(response, request.response_mode, max_response_bytes, false).await
    }

    async fn read_response(
        mut response: reqwest::Response,
        response_mode: GoogleResponseMode,
        max_response_bytes: Option<usize>,
        accept_resume_incomplete: bool,
    ) -> Result<GoogleExecuteResponse, GoogleRestError> {
        let status = response.status();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_ascii_lowercase);
        let headers = collect_headers(response.headers());
        let bytes = if let Some(limit) = max_response_bytes {
            if response
                .content_length()
                .is_some_and(|length| length > u64::try_from(limit).unwrap_or(u64::MAX))
            {
                return Err(GoogleRestError::ResponseTooLarge { limit });
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|source| GoogleRestError::Http { source })?
            {
                if chunk.len() > limit.saturating_sub(bytes.len()) {
                    return Err(GoogleRestError::ResponseTooLarge { limit });
                }
                bytes.extend_from_slice(&chunk);
            }
            bytes.into()
        } else {
            response
                .bytes()
                .await
                .map_err(|source| GoogleRestError::Http { source })?
        };

        let resume_incomplete = accept_resume_incomplete && status.as_u16() == 308;
        if !status.is_success() && !resume_incomplete {
            let mut error = parse_google_api_error(status, &bytes);
            error.retry_after_ms = parse_retry_after_header(&headers);
            return Err(GoogleRestError::Api {
                status_code: error.status_code,
                message: error.message.clone(),
                error,
            });
        }

        let body = if resume_incomplete {
            GoogleResponseBody::Empty
        } else {
            decode_response_body(&bytes, content_type.as_deref(), response_mode)?
        };
        let next_page_token = body
            .as_json()
            .and_then(extract_next_page_token)
            .map(ToString::to_string);

        Ok(GoogleExecuteResponse {
            status_code: status.as_u16(),
            headers,
            body,
            next_page_token,
        })
    }
}

fn parse_http_method(http_method: &str) -> Result<Method, GoogleRestError> {
    match http_method.trim().to_ascii_uppercase().as_str() {
        "GET" => Ok(Method::GET),
        "POST" => Ok(Method::POST),
        "PUT" => Ok(Method::PUT),
        "PATCH" => Ok(Method::PATCH),
        "DELETE" => Ok(Method::DELETE),
        other => Err(GoogleRestError::UnsupportedHttpMethod {
            method: other.to_string(),
        }),
    }
}

fn validate_parameters(
    method: &DiscoveryMethod,
    parameters: &BTreeMap<String, Vec<String>>,
) -> Result<(), GoogleRestError> {
    for (name, values) in parameters {
        let Some(param_meta) = method.parameters.get(name) else {
            return Err(GoogleRestError::UnknownParameter {
                method_key: method.key.clone(),
                name: name.clone(),
            });
        };

        if values.is_empty() {
            return Err(GoogleRestError::EmptyParameterValue { name: name.clone() });
        }
        if !param_meta.repeated && values.len() > 1 {
            return Err(GoogleRestError::InvalidParameterMultiplicity { name: name.clone() });
        }
    }

    for (name, param_meta) in &method.parameters {
        if !param_meta.required {
            continue;
        }

        let Some(values) = parameters.get(name) else {
            return Err(GoogleRestError::MissingRequiredParameter {
                name: name.clone(),
                location: param_meta.location.clone(),
                location_suffix: location_suffix(param_meta.location.as_deref()),
            });
        };

        if values.iter().all(|value| value.trim().is_empty()) {
            return Err(GoogleRestError::MissingRequiredParameter {
                name: name.clone(),
                location: param_meta.location.clone(),
                location_suffix: location_suffix(param_meta.location.as_deref()),
            });
        }
    }

    Ok(())
}

fn location_suffix(location: Option<&str>) -> String {
    location.map_or_else(String::new, |value| format!(" in `{value}`"))
}

fn resolve_path_template<'a>(
    method: &'a DiscoveryMethod,
    upload: Option<&GoogleUploadPayload>,
) -> Result<&'a str, GoogleRestError> {
    if let Some(upload) = upload {
        let Some(media_upload) = method.media_upload.as_ref() else {
            return Err(GoogleRestError::InvalidUploadConfiguration {
                message: "method does not expose mediaUpload metadata".to_string(),
            });
        };

        let selected = match upload.mode {
            GoogleUploadMode::Simple | GoogleUploadMode::Multipart => {
                media_upload.simple_path.as_deref()
            }
            GoogleUploadMode::Resumable => media_upload.resumable_path.as_deref(),
        };

        return selected.ok_or_else(|| GoogleRestError::InvalidUploadConfiguration {
            message: format!(
                "upload mode `{}` not supported by method",
                upload.mode.upload_type()
            ),
        });
    }

    Ok(method.canonical_path.as_str())
}

fn render_path_template(
    template: &str,
    parameters: &BTreeMap<String, Vec<String>>,
) -> Result<String, GoogleRestError> {
    if template.trim().is_empty() {
        return Err(GoogleRestError::InvalidPathTemplate {
            template: template.to_string(),
            message: "template must not be empty".to_string(),
        });
    }

    let mut rendered = String::with_capacity(template.len());
    let mut remainder = template;

    while let Some(open_idx) = remainder.find('{') {
        let prefix = &remainder[..open_idx];
        if prefix.contains('}') {
            return Err(GoogleRestError::InvalidPathTemplate {
                template: template.to_string(),
                message: "unmatched `}` in template".to_string(),
            });
        }
        rendered.push_str(prefix);

        let token_start = open_idx + 1;
        let Some(close_rel) = remainder[token_start..].find('}') else {
            return Err(GoogleRestError::InvalidPathTemplate {
                template: template.to_string(),
                message: "missing closing `}`".to_string(),
            });
        };
        let token_end = token_start + close_rel;
        let token = &remainder[token_start..token_end];
        if token.is_empty() {
            return Err(GoogleRestError::InvalidPathTemplate {
                template: template.to_string(),
                message: "empty placeholder token".to_string(),
            });
        }

        let (reserved, name) = token
            .strip_prefix('+')
            .map_or((false, token), |name| (true, name));
        if name.is_empty() {
            return Err(GoogleRestError::InvalidPathTemplate {
                template: template.to_string(),
                message: "empty placeholder name".to_string(),
            });
        }

        let value = first_parameter_value(name, template, parameters)?;
        reject_path_traversal(name, value, reserved)?;
        let encoded = encode_path_value(value, reserved);
        rendered.push_str(&encoded);

        let next = token_end + 1;
        remainder = &remainder[next..];
    }

    if remainder.contains('}') {
        return Err(GoogleRestError::InvalidPathTemplate {
            template: template.to_string(),
            message: "unmatched `}` in template".to_string(),
        });
    }
    rendered.push_str(remainder);

    Ok(rendered)
}

fn first_parameter_value<'a>(
    name: &str,
    template: &str,
    parameters: &'a BTreeMap<String, Vec<String>>,
) -> Result<&'a str, GoogleRestError> {
    let Some(values) = parameters.get(name) else {
        return Err(GoogleRestError::MissingPathParameter {
            name: name.to_string(),
            template: template.to_string(),
        });
    };

    let Some(value) = values.first() else {
        return Err(GoogleRestError::MissingPathParameter {
            name: name.to_string(),
            template: template.to_string(),
        });
    };

    if value.trim().is_empty() {
        return Err(GoogleRestError::MissingPathParameter {
            name: name.to_string(),
            template: template.to_string(),
        });
    }

    Ok(value)
}

fn reject_path_traversal(
    name: &str,
    value: &str,
    reserved_expansion: bool,
) -> Result<(), GoogleRestError> {
    let invalid = if reserved_expansion {
        value
            .split('/')
            .find(|segment| matches!(*segment, "." | ".."))
    } else if matches!(value, "." | "..") {
        Some(value)
    } else {
        None
    };

    if let Some(segment) = invalid {
        return Err(GoogleRestError::PathTraversalRejected {
            name: name.to_string(),
            segment: segment.to_string(),
        });
    }

    Ok(())
}

fn encode_path_value(value: &str, reserved_expansion: bool) -> String {
    if reserved_expansion {
        value
            .split('/')
            .map(encode_path_segment)
            .collect::<Vec<_>>()
            .join("/")
    } else {
        encode_path_segment(value)
    }
}

fn encode_path_segment(value: &str) -> String {
    utf8_percent_encode(value, PATH_SEGMENT_ENCODE_SET).to_string()
}

fn build_url(base_url: &str, rendered_path: &str) -> Result<reqwest::Url, GoogleRestError> {
    let base = reqwest::Url::parse(base_url).map_err(|error| GoogleRestError::InvalidBaseUrl {
        base_url: base_url.to_string(),
        message: error.to_string(),
    })?;

    let joined = base
        .join(rendered_path.trim_start_matches('/'))
        .map_err(|error| GoogleRestError::UrlJoin {
            base_url: base_url.to_string(),
            path: rendered_path.to_string(),
            message: error.to_string(),
        })?;

    Ok(joined)
}

fn append_query_parameters(
    url: &mut reqwest::Url,
    request: &GoogleExecuteRequest<'_>,
) -> Result<(), GoogleRestError> {
    let mut pairs = url.query_pairs_mut();

    for (name, values) in &request.parameters {
        let Some(meta) = request.method.parameters.get(name) else {
            return Err(GoogleRestError::UnknownParameter {
                method_key: request.method.key.clone(),
                name: name.clone(),
            });
        };

        let is_path = meta.location.as_deref() == Some("path");
        if is_path {
            continue;
        }

        for value in values {
            pairs.append_pair(name, value);
        }
    }

    if let Some(upload) = request.upload.as_ref() {
        pairs.append_pair("uploadType", upload.mode.upload_type());
    }

    let should_force_media_alt = matches!(request.response_mode, GoogleResponseMode::Binary)
        && request.method.supports_media_download
        && !request.parameters.contains_key("alt");
    if should_force_media_alt {
        pairs.append_pair("alt", "media");
    }

    drop(pairs);
    Ok(())
}

fn body_for_validation(request: &GoogleExecuteRequest<'_>) -> Option<serde_json::Value> {
    request
        .upload
        .as_ref()
        .and_then(|upload| upload.metadata.clone())
        .or_else(|| request.body.clone())
}

fn validate_request_body(
    method: &DiscoveryMethod,
    schemas: &BTreeMap<String, DiscoverySchema>,
    body: Option<&serde_json::Value>,
    upload: Option<&GoogleUploadPayload>,
) -> Result<(), GoogleRestError> {
    let Some(schema_ref) = method.request_ref.as_deref() else {
        return Ok(());
    };

    let requires_body = matches!(method.http_method.as_str(), "POST" | "PUT" | "PATCH")
        || matches!(
            upload.map(|payload| payload.mode),
            Some(GoogleUploadMode::Multipart | GoogleUploadMode::Resumable)
        );

    if body.is_none() && requires_body {
        return Err(GoogleRestError::MissingRequestBody {
            schema: schema_ref.to_string(),
        });
    }

    let Some(value) = body else {
        return Ok(());
    };

    let Some(schema) = schemas.get(schema_ref) else {
        return Err(GoogleRestError::UnknownSchemaReference {
            schema: schema_ref.to_string(),
        });
    };

    validate_schema_value(schema_ref, schema, value, schemas, "$", 0)
}

#[allow(clippy::too_many_lines)]
fn validate_schema_value(
    root_schema_ref: &str,
    schema: &DiscoverySchema,
    value: &serde_json::Value,
    schemas: &BTreeMap<String, DiscoverySchema>,
    path: &str,
    depth: usize,
) -> Result<(), GoogleRestError> {
    if depth > MAX_SCHEMA_VALIDATION_DEPTH {
        return Err(GoogleRestError::RequestBodyValidation {
            schema: root_schema_ref.to_string(),
            path: path.to_string(),
            message: "schema validation depth limit exceeded".to_string(),
        });
    }

    if let Some(ref_name) = schema.ref_name.as_deref() {
        let Some(next_schema) = schemas.get(ref_name) else {
            return Err(GoogleRestError::UnknownSchemaReference {
                schema: ref_name.to_string(),
            });
        };
        return validate_schema_value(
            root_schema_ref,
            next_schema,
            value,
            schemas,
            path,
            depth + 1,
        );
    }

    let treats_as_object = schema.type_name.as_deref() == Some("object")
        || (schema.type_name.is_none()
            && (!schema.properties.is_empty() || !schema.required.is_empty()));

    if treats_as_object {
        let Some(object) = value.as_object() else {
            return Err(GoogleRestError::RequestBodyValidation {
                schema: root_schema_ref.to_string(),
                path: path.to_string(),
                message: "expected object".to_string(),
            });
        };

        for required in &schema.required {
            if !object.contains_key(required) {
                return Err(GoogleRestError::RequestBodyValidation {
                    schema: root_schema_ref.to_string(),
                    path: format!("{path}.{required}"),
                    message: "missing required field".to_string(),
                });
            }
        }

        for (field_name, field_value) in object {
            if let Some(field_schema) = schema.properties.get(field_name) {
                validate_schema_value(
                    root_schema_ref,
                    field_schema,
                    field_value,
                    schemas,
                    &format!("{path}.{field_name}"),
                    depth + 1,
                )?;
                continue;
            }

            if let Some(additional_schema) = schema.additional_properties.as_deref() {
                validate_schema_value(
                    root_schema_ref,
                    additional_schema,
                    field_value,
                    schemas,
                    &format!("{path}.{field_name}"),
                    depth + 1,
                )?;
            }
        }

        return Ok(());
    }

    match schema.type_name.as_deref() {
        Some("array") => {
            let Some(items) = value.as_array() else {
                return Err(GoogleRestError::RequestBodyValidation {
                    schema: root_schema_ref.to_string(),
                    path: path.to_string(),
                    message: "expected array".to_string(),
                });
            };

            if let Some(item_schema) = schema.items.as_deref() {
                for (index, item) in items.iter().enumerate() {
                    validate_schema_value(
                        root_schema_ref,
                        item_schema,
                        item,
                        schemas,
                        &format!("{path}[{index}]"),
                        depth + 1,
                    )?;
                }
            }
            Ok(())
        }
        Some("string") if !value.is_string() => Err(GoogleRestError::RequestBodyValidation {
            schema: root_schema_ref.to_string(),
            path: path.to_string(),
            message: "expected string".to_string(),
        }),
        Some("integer") if !(value.is_i64() || value.is_u64()) => {
            Err(GoogleRestError::RequestBodyValidation {
                schema: root_schema_ref.to_string(),
                path: path.to_string(),
                message: "expected integer".to_string(),
            })
        }
        Some("number") if !value.is_number() => Err(GoogleRestError::RequestBodyValidation {
            schema: root_schema_ref.to_string(),
            path: path.to_string(),
            message: "expected number".to_string(),
        }),
        Some("boolean") if !value.is_boolean() => Err(GoogleRestError::RequestBodyValidation {
            schema: root_schema_ref.to_string(),
            path: path.to_string(),
            message: "expected boolean".to_string(),
        }),
        _ => Ok(()),
    }
}

fn apply_payload(
    mut builder: reqwest::RequestBuilder,
    method: &Method,
    request: &GoogleExecuteRequest<'_>,
    validation_body: Option<&serde_json::Value>,
) -> Result<reqwest::RequestBuilder, GoogleRestError> {
    if let Some(upload) = request.upload.as_ref() {
        validate_upload_content_type(&upload.content_type)?;
        match upload.mode {
            GoogleUploadMode::Simple => {
                builder = builder
                    .header(reqwest::header::CONTENT_TYPE, upload.content_type.as_str())
                    .body(upload.bytes.clone());
            }
            GoogleUploadMode::Multipart => {
                let metadata = validation_body
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!({}));

                let (content_type, body) = multipart_related_body(upload, &metadata)?;
                builder = builder
                    .header(reqwest::header::CONTENT_TYPE, content_type)
                    .header(reqwest::header::CONTENT_LENGTH, body.len())
                    .body(body);
            }
            GoogleUploadMode::Resumable => {
                let metadata = validation_body
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!({}));
                builder = builder
                    .header("X-Upload-Content-Type", upload.content_type.as_str())
                    .header("X-Upload-Content-Length", upload.bytes.len())
                    .json(&metadata);
            }
        }

        return Ok(builder);
    }

    if let Some(body) = validation_body {
        if matches!(*method, Method::GET | Method::DELETE) {
            return Err(GoogleRestError::BodyNotAllowed {
                http_method: method.as_str().to_string(),
            });
        }
        builder = builder.json(body);
    }

    Ok(builder)
}

/// Validate a concrete media MIME type before embedding it in an upload header.
///
/// # Errors
/// Rejects malformed types, wildcards, and header control characters.
pub fn validate_upload_content_type(content_type: &str) -> Result<(), GoogleRestError> {
    let invalid = || GoogleRestError::InvalidUploadContentType {
        content_type: content_type.to_string(),
        message: "expected a concrete MIME type without header control characters".to_string(),
    };
    if content_type.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(invalid());
    }
    let parsed = content_type.parse::<mime::Mime>().map_err(|_| invalid())?;
    if parsed.type_() == mime::STAR
        || parsed.subtype() == mime::STAR
        || parsed.type_().as_str().is_empty()
        || parsed.subtype().as_str().is_empty()
    {
        return Err(invalid());
    }
    Ok(())
}

fn multipart_related_body(
    upload: &GoogleUploadPayload,
    metadata: &serde_json::Value,
) -> Result<(String, Vec<u8>), GoogleRestError> {
    validate_upload_content_type(&upload.content_type)?;
    let metadata = metadata.to_string().into_bytes();
    let mut digest = blake3::Hasher::new();
    digest.update(&metadata);
    digest.update(&upload.bytes);
    let digest = digest.finalize().to_hex();

    // A MIME delimiter must never appear in either part. The digest keeps
    // ordinary requests on the first candidate; explicit collision checks
    // preserve arbitrary binary data even when it resembles MIME framing.
    let boundary = (0..16)
        .map(|suffix| format!("fcp-google-{}-{suffix}", &digest.as_str()[..40]))
        .find(|candidate| {
            let delimiter = candidate.as_bytes();
            !metadata
                .windows(delimiter.len())
                .any(|part| part == delimiter)
                && !upload
                    .bytes
                    .windows(delimiter.len())
                    .any(|part| part == delimiter)
        })
        .ok_or_else(|| GoogleRestError::InvalidUploadConfiguration {
            message: "could not select an unambiguous multipart boundary".to_string(),
        })?;

    let metadata_header =
        format!("--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n");
    let media_header = format!(
        "\r\n--{boundary}\r\nContent-Type: {}\r\n\r\n",
        upload.content_type
    );
    let closing = format!("\r\n--{boundary}--\r\n");
    let capacity = [
        metadata_header.len(),
        metadata.len(),
        media_header.len(),
        upload.bytes.len(),
        closing.len(),
    ]
    .into_iter()
    .try_fold(0usize, usize::checked_add)
    .ok_or_else(|| GoogleRestError::InvalidUploadConfiguration {
        message: "multipart body length overflow".to_string(),
    })?;
    let mut body = Vec::with_capacity(capacity);
    body.extend_from_slice(metadata_header.as_bytes());
    body.extend_from_slice(&metadata);
    body.extend_from_slice(media_header.as_bytes());
    body.extend_from_slice(&upload.bytes);
    body.extend_from_slice(closing.as_bytes());

    Ok((format!("multipart/related; boundary={boundary}"), body))
}

/// Extract the `Retry-After` header value in milliseconds.
///
/// Supports integer delta-seconds and HTTP-date values (RFC 7231 §7.1.3).
fn parse_retry_after_header(headers: &[(String, String)]) -> Option<u64> {
    let value = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("retry-after"))
        .map(|(_, value)| value.trim())?;

    if let Ok(secs) = value.parse::<u64>() {
        return Some(secs.saturating_mul(1000));
    }

    let retry_at = chrono::DateTime::parse_from_rfc2822(value)
        .ok()?
        .with_timezone(&chrono::Utc);
    let now = chrono::Utc::now();
    if retry_at <= now {
        return Some(0);
    }

    let delay_ms = retry_at.signed_duration_since(now).num_milliseconds();
    Some(u64::try_from(delay_ms).unwrap_or(u64::MAX))
}

fn collect_headers(headers: &reqwest::header::HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            let value = String::from_utf8_lossy(value.as_bytes()).to_string();
            (name.as_str().to_string(), value)
        })
        .collect()
}

fn decode_response_body(
    bytes: &[u8],
    content_type: Option<&str>,
    response_mode: GoogleResponseMode,
) -> Result<GoogleResponseBody, GoogleRestError> {
    if bytes.is_empty() {
        return Ok(GoogleResponseBody::Empty);
    }

    match response_mode {
        GoogleResponseMode::Binary => Ok(GoogleResponseBody::Binary(bytes.to_vec())),
        GoogleResponseMode::Json => serde_json::from_slice(bytes)
            .map(GoogleResponseBody::Json)
            .map_err(|source| GoogleRestError::JsonDecode { source }),
        GoogleResponseMode::Auto => {
            let looks_like_json = content_type.is_some_and(|value| value.contains("json"))
                || matches!(bytes.first(), Some(b'{' | b'['));
            if looks_like_json {
                serde_json::from_slice(bytes).map_or_else(
                    |_| Ok(GoogleResponseBody::Binary(bytes.to_vec())),
                    |value| Ok(GoogleResponseBody::Json(value)),
                )
            } else {
                Ok(GoogleResponseBody::Binary(bytes.to_vec()))
            }
        }
    }
}

fn extract_next_page_token(body: &serde_json::Value) -> Option<&str> {
    body.get("nextPageToken")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            body.get("next_page_token")
                .and_then(serde_json::Value::as_str)
        })
}

#[derive(Debug, Clone, serde::Deserialize)]
struct GoogleErrorEnvelope {
    #[serde(default)]
    error: Option<GoogleErrorBody>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct GoogleErrorBody {
    #[serde(default)]
    code: Option<u16>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    errors: Vec<GoogleErrorDetail>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct GoogleErrorDetail {
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    domain: Option<String>,
}

/// Parse a Google API error response body into a normalized [`GoogleApiError`].
///
/// Handles the standard `{ "error": { "code": N, "message": "...", ... } }`
/// envelope used by all Google REST APIs, falling back to a plain HTTP-status
/// message when the body is not valid JSON or does not match the envelope shape.
#[must_use]
pub fn parse_google_api_error(status: StatusCode, body: &[u8]) -> GoogleApiError {
    let fallback_message = String::from_utf8_lossy(body).trim().to_string();

    if let Ok(envelope) = serde_json::from_slice::<GoogleErrorEnvelope>(body)
        && let Some(error) = envelope.error
    {
        let message = error
            .message
            .clone()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| format!("HTTP {}", status.as_u16()));
        let reason = error
            .errors
            .first()
            .and_then(|detail| detail.reason.clone());
        let domain = error
            .errors
            .first()
            .and_then(|detail| detail.domain.clone());
        let access_not_configured_hint = reason.as_deref() == Some("accessNotConfigured")
            || message.contains("accessNotConfigured")
            || message.contains("has not been used in project");

        return GoogleApiError {
            status_code: error.code.unwrap_or_else(|| status.as_u16()),
            message,
            status: error.status,
            reason,
            domain,
            access_not_configured_hint,
            retry_after_ms: None,
        };
    }

    GoogleApiError {
        status_code: status.as_u16(),
        message: if fallback_message.is_empty() {
            format!("HTTP {}", status.as_u16())
        } else {
            format!("HTTP {}: {fallback_message}", status.as_u16())
        },
        status: None,
        reason: None,
        domain: None,
        access_not_configured_hint: false,
        retry_after_ms: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multipart_related_preserves_binary_media_and_json_metadata() {
        let metadata = serde_json::json!({
            "name": "résumé\r\n\".bin",
            "parents": ["parent-123"]
        });
        for media in [
            Vec::new(),
            b"\0\xff\xfe\r\n--old-boundary\r\n\x80data".to_vec(),
        ] {
            let upload = GoogleUploadPayload::multipart(
                "application/octet-stream",
                media.clone(),
                metadata.clone(),
            );
            let (content_type, body) = multipart_related_body(&upload, &metadata).unwrap();
            let boundary = content_type
                .strip_prefix("multipart/related; boundary=")
                .unwrap();
            assert!(boundary.len() <= 70);
            let prefix =
                format!("--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n");
            assert!(body.starts_with(prefix.as_bytes()));
            let separator =
                format!("\r\n--{boundary}\r\nContent-Type: application/octet-stream\r\n\r\n");
            let separator_offset = body
                .windows(separator.len())
                .position(|part| part == separator.as_bytes())
                .unwrap();
            let actual_metadata: serde_json::Value =
                serde_json::from_slice(&body[prefix.len()..separator_offset]).unwrap();
            assert_eq!(actual_metadata, metadata);
            let closing = format!("\r\n--{boundary}--\r\n");
            assert!(body.ends_with(closing.as_bytes()));
            assert_eq!(
                &body[separator_offset + separator.len()..body.len() - closing.len()],
                media.as_slice(),
            );
            assert!(
                !body
                    .windows(b"Content-Disposition".len())
                    .any(|part| part == b"Content-Disposition")
            );
        }
    }

    #[test]
    fn upload_rejects_malformed_or_injected_mime_headers_for_every_mode() {
        let method = method_fixture("POST", "files", BTreeMap::new());
        let schemas = BTreeMap::new();
        for content_type in [
            "",
            "text",
            "text/",
            "*/*",
            "image/*",
            "text/plain\r\nX-Injected: yes",
            "text/plain\0",
            "text/plain\n",
            "text/plain; charset=\"unterminated",
        ] {
            for mode in [
                GoogleUploadMode::Simple,
                GoogleUploadMode::Multipart,
                GoogleUploadMode::Resumable,
            ] {
                let mut request = GoogleExecuteRequest::new(&method, &schemas, "http://127.0.0.1/");
                request.upload = Some(GoogleUploadPayload {
                    mode,
                    content_type: content_type.to_string(),
                    bytes: b"data".to_vec(),
                    metadata: Some(serde_json::json!({})),
                });
                let builder = reqwest::Client::new().post("http://127.0.0.1/files");
                assert!(
                    matches!(
                        apply_payload(builder, &Method::POST, &request, None),
                        Err(GoogleRestError::InvalidUploadContentType { .. }),
                    ),
                    "accepted {content_type:?} for {mode:?}"
                );
            }
        }
        for content_type in [
            "text/plain; charset=utf-8",
            "application/octet-stream",
            "image/svg+xml",
        ] {
            validate_upload_content_type(content_type).unwrap();
        }
    }

    #[fcp_async_core::runtime::test]
    async fn bounded_response_rejects_oversized_success_and_error_bodies() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path},
        };
        let server = MockServer::start().await;
        for status in [200, 500] {
            Mock::given(method("GET"))
                .and(path(format!("/{status}")))
                .respond_with(ResponseTemplate::new(status).set_body_string("x".repeat(128)))
                .expect(1)
                .mount(&server)
                .await;
            let discovery_method = method_fixture("GET", &status.to_string(), BTreeMap::new());
            let schemas = BTreeMap::new();
            let base_url = server.uri();
            let request = GoogleExecuteRequest::new(&discovery_method, &schemas, &base_url);
            assert!(matches!(
                GoogleRestExecutor::new()
                    .execute_bounded(&request, 64)
                    .await,
                Err(GoogleRestError::ResponseTooLarge { limit: 64 }),
            ));
        }
    }

    #[fcp_async_core::runtime::test]
    async fn bounded_response_checks_chunked_bodies_without_content_length() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut connection, _) = listener.accept().unwrap();
            connection
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut input = [0u8; 4096];
            let _ = connection.read(&mut input).unwrap();
            connection.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n8\r\n12345678\r\n8\r\nabcdefgh\r\n0\r\n\r\n").unwrap();
        });
        let discovery_method = method_fixture("GET", "data", BTreeMap::new());
        let schemas = BTreeMap::new();
        let base_url = format!("http://{address}/");
        let request = GoogleExecuteRequest::new(&discovery_method, &schemas, &base_url);
        assert!(matches!(
            GoogleRestExecutor::new()
                .execute_bounded(&request, 12)
                .await,
            Err(GoogleRestError::ResponseTooLarge { limit: 12 }),
        ));
        server.join().unwrap();
    }

    fn method_fixture(
        http_method: &str,
        canonical_path: &str,
        parameters: BTreeMap<String, crate::DiscoveryParameter>,
    ) -> DiscoveryMethod {
        DiscoveryMethod {
            key: "users.messages.list".to_string(),
            id: "gmail.users.messages.list".to_string(),
            http_method: http_method.to_string(),
            path: canonical_path.to_string(),
            flat_path: None,
            canonical_path: canonical_path.to_string(),
            resource_path: vec!["users".to_string(), "messages".to_string()],
            description: None,
            scopes: Vec::new(),
            request_ref: None,
            response_ref: None,
            parameters,
            supports_media_download: false,
            supports_media_upload: false,
            media_upload: None,
        }
    }

    fn path_param(required: bool) -> crate::DiscoveryParameter {
        crate::DiscoveryParameter {
            location: Some("path".to_string()),
            required,
            repeated: false,
            type_name: Some("string".to_string()),
            format: None,
            description: None,
        }
    }

    fn query_parameter_meta(required: bool, repeated: bool) -> crate::DiscoveryParameter {
        crate::DiscoveryParameter {
            location: Some("query".to_string()),
            required,
            repeated,
            type_name: Some("string".to_string()),
            format: None,
            description: None,
        }
    }

    fn schema_object(required: Vec<&str>) -> DiscoverySchema {
        DiscoverySchema {
            type_name: Some("object".to_string()),
            format: None,
            description: None,
            required: required.into_iter().map(str::to_string).collect(),
            enum_values: Vec::new(),
            properties: BTreeMap::new(),
            items: None,
            ref_name: None,
            additional_properties: None,
        }
    }

    #[test]
    fn render_path_template_encodes_and_preserves_reserved_slashes() {
        let params = BTreeMap::from([
            ("userId".to_string(), vec!["me@example.com".to_string()]),
            (
                "name".to_string(),
                vec!["projects/demo/topics/a/b".to_string()],
            ),
        ]);

        let rendered = render_path_template("gmail/v1/users/{userId}/{+name}", &params)
            .expect("rendered path");

        assert_eq!(
            rendered,
            "gmail/v1/users/me%40example.com/projects/demo/topics/a/b"
        );
    }

    #[test]
    fn render_path_template_rejects_traversal_segments() {
        let params = BTreeMap::from([("resource".to_string(), vec!["../etc".to_string()])]);

        let error = render_path_template("gmail/v1/{+resource}", &params)
            .expect_err("traversal should be rejected");

        assert!(matches!(
            error,
            GoogleRestError::PathTraversalRejected { .. }
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn execute_rejects_missing_required_parameter() {
        let mut params = BTreeMap::new();
        params.insert("userId".to_string(), path_param(true));

        let method = method_fixture("GET", "gmail/v1/users/{userId}/messages", params);
        let schemas = BTreeMap::new();
        let executor = GoogleRestExecutor::new();

        let request = GoogleExecuteRequest::new(&method, &schemas, "https://gmail.googleapis.com/");
        let error = executor
            .execute(&request)
            .await
            .expect_err("required parameter should fail");

        assert!(matches!(
            error,
            GoogleRestError::MissingRequiredParameter {
                name,
                location,
                ..
            } if name == "userId" && location.as_deref() == Some("path")
        ));
    }

    #[test]
    fn append_query_parameters_adds_upload_type_and_alt_media() {
        let mut method_params = BTreeMap::new();
        method_params.insert("userId".to_string(), path_param(true));
        method_params.insert("maxResults".to_string(), query_parameter_meta(false, false));
        let mut method = method_fixture("GET", "gmail/v1/users/{userId}/messages", method_params);
        method.supports_media_download = true;
        let schemas = BTreeMap::new();

        let mut request =
            GoogleExecuteRequest::new(&method, &schemas, "https://gmail.googleapis.com/");
        request
            .parameters
            .insert("userId".to_string(), vec!["me".to_string()]);
        request
            .parameters
            .insert("maxResults".to_string(), vec!["10".to_string()]);

        request.upload = Some(GoogleUploadPayload::simple(
            "application/octet-stream",
            b"bytes".to_vec(),
        ));
        request.response_mode = GoogleResponseMode::Binary;

        let rendered_path =
            render_path_template(&request.method.canonical_path, &request.parameters)
                .expect("path");
        let mut url = build_url(request.base_url, &rendered_path).expect("url");
        append_query_parameters(&mut url, &request).expect("query append");
        let query = url.query().unwrap_or_default().to_string();

        assert!(query.contains("maxResults=10"));
        assert!(query.contains("uploadType=media"));
        assert!(query.contains("alt=media"));
    }

    #[test]
    fn resolve_upload_path_uses_media_upload_metadata() {
        let mut method = method_fixture("POST", "drive/v3/files", BTreeMap::new());
        method.request_ref = Some("FileMetadata".to_string());
        method.supports_media_upload = true;
        method.media_upload = Some(crate::DiscoveryMediaUpload {
            accept: vec!["*/*".to_string()],
            max_size: None,
            simple_path: Some("upload/drive/v3/files".to_string()),
            resumable_path: Some("upload/drive/v3/files/resumable".to_string()),
        });

        let simple = resolve_path_template(
            &method,
            Some(&GoogleUploadPayload::simple(
                "application/octet-stream",
                vec![1, 2, 3],
            )),
        )
        .expect("simple path");
        let resumable = resolve_path_template(
            &method,
            Some(&GoogleUploadPayload::resumable(
                "application/octet-stream",
                vec![1, 2, 3],
                serde_json::json!({"name": "demo"}),
            )),
        )
        .expect("resumable path");

        assert_eq!(simple, "upload/drive/v3/files");
        assert_eq!(resumable, "upload/drive/v3/files/resumable");
    }

    #[test]
    fn decode_response_body_auto_extracts_json_and_binary_modes() {
        let json_body = serde_json::json!({"nextPageToken":"page-2","items":[]});
        let json_bytes = serde_json::to_vec(&json_body).expect("serialize json");
        let decoded_json = decode_response_body(
            &json_bytes,
            Some("application/json; charset=utf-8"),
            GoogleResponseMode::Auto,
        )
        .expect("decode json");
        assert!(matches!(decoded_json, GoogleResponseBody::Json(_)));
        assert_eq!(
            extract_next_page_token(decoded_json.as_json().expect("json")),
            Some("page-2")
        );

        let decoded_binary = decode_response_body(
            b"raw-bytes",
            Some("application/octet-stream"),
            GoogleResponseMode::Binary,
        )
        .expect("decode binary");
        assert_eq!(decoded_binary.as_bytes(), Some(&b"raw-bytes"[..]));
    }

    #[fcp_async_core::runtime::test]
    async fn execute_validates_body_required_fields() {
        let mut method = method_fixture("POST", "gmail/v1/users/me/messages/send", BTreeMap::new());
        method.request_ref = Some("SendRequest".to_string());

        let schemas = BTreeMap::from([("SendRequest".to_string(), schema_object(vec!["raw"]))]);

        let mut request =
            GoogleExecuteRequest::new(&method, &schemas, "https://gmail.googleapis.com/");
        request.body = Some(serde_json::json!({}));

        let error = GoogleRestExecutor::new()
            .execute(&request)
            .await
            .expect_err("missing required schema field should fail");

        assert!(matches!(
            error,
            GoogleRestError::RequestBodyValidation {
                schema,
                path,
                message,
            } if schema == "SendRequest" && path == "$.raw" && message == "missing required field"
        ));
    }

    #[test]
    fn parse_google_error_extracts_access_not_configured_hint() {
        let body = serde_json::json!({
            "error": {
                "code": 403,
                "message": "Access Not Configured. Gmail API has not been used in project 123 before or it is disabled.",
                "status": "PERMISSION_DENIED",
                "errors": [{
                    "reason": "accessNotConfigured",
                    "domain": "usageLimits"
                }]
            }
        });
        let bytes = serde_json::to_vec(&body).expect("serialize");
        let parsed = parse_google_api_error(StatusCode::FORBIDDEN, &bytes);

        assert_eq!(parsed.status_code, 403);
        assert_eq!(parsed.reason.as_deref(), Some("accessNotConfigured"));
        assert_eq!(parsed.domain.as_deref(), Some("usageLimits"));
        assert_eq!(parsed.status.as_deref(), Some("PERMISSION_DENIED"));
        assert!(parsed.access_not_configured_hint);
    }

    // ── GoogleUploadMode ──────────────────────────────────────────────

    #[test]
    fn upload_mode_simple_type() {
        assert_eq!(GoogleUploadMode::Simple.upload_type(), "media");
    }

    #[test]
    fn upload_mode_multipart_type() {
        assert_eq!(GoogleUploadMode::Multipart.upload_type(), "multipart");
    }

    #[test]
    fn upload_mode_resumable_type() {
        assert_eq!(GoogleUploadMode::Resumable.upload_type(), "resumable");
    }

    // ── GoogleUploadPayload ───────────────────────────────────────────

    #[test]
    fn upload_payload_simple_constructor() {
        let payload = GoogleUploadPayload::simple("image/png", vec![0x89, 0x50, 0x4e, 0x47]);
        assert_eq!(payload.mode, GoogleUploadMode::Simple);
        assert_eq!(payload.content_type, "image/png");
        assert_eq!(payload.bytes, vec![0x89, 0x50, 0x4e, 0x47]);
        assert!(payload.metadata.is_none());
    }

    #[test]
    fn upload_payload_multipart_constructor() {
        let meta = serde_json::json!({"name": "file.txt"});
        let payload =
            GoogleUploadPayload::multipart("text/plain", b"hello world".to_vec(), meta.clone());
        assert_eq!(payload.mode, GoogleUploadMode::Multipart);
        assert_eq!(payload.content_type, "text/plain");
        assert_eq!(payload.bytes, b"hello world");
        assert_eq!(payload.metadata, Some(meta));
    }

    #[test]
    fn upload_payload_resumable_constructor() {
        let meta = serde_json::json!({"title": "doc.pdf"});
        let payload = GoogleUploadPayload::resumable(
            "application/pdf",
            vec![0x25, 0x50, 0x44, 0x46],
            meta.clone(),
        );
        assert_eq!(payload.mode, GoogleUploadMode::Resumable);
        assert_eq!(payload.content_type, "application/pdf");
        assert_eq!(payload.bytes, vec![0x25, 0x50, 0x44, 0x46]);
        assert_eq!(payload.metadata, Some(meta));
    }

    // ── GoogleResponseBody ────────────────────────────────────────────

    #[test]
    fn response_body_empty_variant() {
        let body = GoogleResponseBody::Empty;
        assert!(body.as_json().is_none());
        assert!(body.as_bytes().is_none());
    }

    #[test]
    fn response_body_json_variant() {
        let val = serde_json::json!({"ok": true});
        let body = GoogleResponseBody::Json(val.clone());
        assert_eq!(body.as_json(), Some(&val));
        assert!(body.as_bytes().is_none());
    }

    #[test]
    fn response_body_binary_variant() {
        let data = vec![1, 2, 3, 4, 5];
        let body = GoogleResponseBody::Binary(data.clone());
        assert_eq!(body.as_bytes(), Some(data.as_slice()));
        assert!(body.as_json().is_none());
    }

    // ── GoogleApiError fields ─────────────────────────────────────────

    #[test]
    fn api_error_fields_accessible() {
        let error = GoogleApiError {
            status_code: 404,
            message: "Not Found".to_string(),
            status: Some("NOT_FOUND".to_string()),
            reason: Some("notFound".to_string()),
            domain: Some("global".to_string()),
            access_not_configured_hint: false,
            retry_after_ms: None,
        };
        assert_eq!(error.status_code, 404);
        assert_eq!(error.message, "Not Found");
        assert_eq!(error.status.as_deref(), Some("NOT_FOUND"));
        assert_eq!(error.reason.as_deref(), Some("notFound"));
        assert_eq!(error.domain.as_deref(), Some("global"));
        assert!(!error.access_not_configured_hint);
    }

    #[test]
    fn api_error_access_not_configured_hint_via_reason() {
        let body = serde_json::json!({
            "error": {
                "code": 403,
                "message": "Some other message",
                "errors": [{"reason": "accessNotConfigured", "domain": "usageLimits"}]
            }
        });
        let bytes = serde_json::to_vec(&body).expect("serialize");
        let parsed = parse_google_api_error(StatusCode::FORBIDDEN, &bytes);
        assert!(parsed.access_not_configured_hint);
    }

    #[test]
    fn api_error_access_not_configured_hint_via_message() {
        let body = serde_json::json!({
            "error": {
                "code": 403,
                "message": "Calendar API has not been used in project 999 before or it is disabled.",
                "errors": [{"reason": "forbidden", "domain": "global"}]
            }
        });
        let bytes = serde_json::to_vec(&body).expect("serialize");
        let parsed = parse_google_api_error(StatusCode::FORBIDDEN, &bytes);
        assert!(parsed.access_not_configured_hint);
    }

    // ── GoogleApiError::is_retryable ─────────────────────────────────

    #[test]
    fn api_error_is_retryable_429() {
        let error = GoogleApiError {
            status_code: 429,
            message: "rate limited".to_string(),
            status: None,
            reason: None,
            domain: None,
            access_not_configured_hint: false,
            retry_after_ms: None,
        };
        assert!(error.is_retryable());
    }

    #[test]
    fn api_error_is_retryable_500() {
        let error = GoogleApiError {
            status_code: 500,
            message: "internal".to_string(),
            status: None,
            reason: None,
            domain: None,
            access_not_configured_hint: false,
            retry_after_ms: None,
        };
        assert!(error.is_retryable());
    }

    #[test]
    fn api_error_is_retryable_503() {
        let error = GoogleApiError {
            status_code: 503,
            message: "unavailable".to_string(),
            status: None,
            reason: None,
            domain: None,
            access_not_configured_hint: false,
            retry_after_ms: None,
        };
        assert!(error.is_retryable());
    }

    #[test]
    fn api_error_not_retryable_400() {
        let error = GoogleApiError {
            status_code: 400,
            message: "bad request".to_string(),
            status: None,
            reason: None,
            domain: None,
            access_not_configured_hint: false,
            retry_after_ms: None,
        };
        assert!(!error.is_retryable());
    }

    #[test]
    fn api_error_not_retryable_401() {
        let error = GoogleApiError {
            status_code: 401,
            message: "unauthorized".to_string(),
            status: None,
            reason: None,
            domain: None,
            access_not_configured_hint: false,
            retry_after_ms: None,
        };
        assert!(!error.is_retryable());
    }

    #[test]
    fn api_error_not_retryable_404() {
        let error = GoogleApiError {
            status_code: 404,
            message: "not found".to_string(),
            status: None,
            reason: None,
            domain: None,
            access_not_configured_hint: false,
            retry_after_ms: None,
        };
        assert!(!error.is_retryable());
    }

    // ── GoogleApiError::to_fcp_error ─────────────────────────────────

    #[test]
    fn api_error_to_fcp_error_401_unauthorized() {
        let error = GoogleApiError {
            status_code: 401,
            message: "bad key".to_string(),
            status: None,
            reason: None,
            domain: None,
            access_not_configured_hint: false,
            retry_after_ms: None,
        };
        match error.to_fcp_error("google-ai") {
            fcp_core::FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 2001);
                assert_eq!(message, "bad key");
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn api_error_to_fcp_error_403_unauthorized() {
        let error = GoogleApiError {
            status_code: 403,
            message: "forbidden".to_string(),
            status: Some("PERMISSION_DENIED".to_string()),
            reason: None,
            domain: None,
            access_not_configured_hint: false,
            retry_after_ms: None,
        };
        match error.to_fcp_error("bigquery") {
            fcp_core::FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 2001);
                assert_eq!(message, "forbidden");
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn api_error_to_fcp_error_429_rate_limited() {
        let error = GoogleApiError {
            status_code: 429,
            message: "rate limited".to_string(),
            status: None,
            reason: None,
            domain: None,
            access_not_configured_hint: false,
            retry_after_ms: None,
        };
        match error.to_fcp_error("google-ai") {
            fcp_core::FcpError::RateLimited {
                retry_after_ms,
                violation,
            } => {
                assert_eq!(retry_after_ms, 60_000);
                assert!(violation.is_none());
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn api_error_to_fcp_error_429_uses_parsed_retry_after() {
        let error = GoogleApiError {
            status_code: 429,
            message: "rate limited".to_string(),
            status: None,
            reason: None,
            domain: None,
            access_not_configured_hint: false,
            retry_after_ms: Some(5_000),
        };
        match error.to_fcp_error("google-ai") {
            fcp_core::FcpError::RateLimited {
                retry_after_ms,
                violation,
            } => {
                assert_eq!(retry_after_ms, 5_000);
                assert!(violation.is_none());
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn parse_retry_after_header_seconds() {
        let headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Retry-After".to_string(), "30".to_string()),
        ];
        assert_eq!(parse_retry_after_header(&headers), Some(30_000));
    }

    #[test]
    fn parse_retry_after_header_missing() {
        let headers = vec![("Content-Type".to_string(), "text/plain".to_string())];
        assert_eq!(parse_retry_after_header(&headers), None);
    }

    #[test]
    fn parse_retry_after_header_case_insensitive() {
        let headers = vec![("retry-after".to_string(), "10".to_string())];
        assert_eq!(parse_retry_after_header(&headers), Some(10_000));
    }

    #[test]
    fn parse_retry_after_header_http_date() {
        let retry_at = (chrono::Utc::now() + chrono::Duration::seconds(120))
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string();
        let headers = vec![("Retry-After".to_string(), retry_at)];

        let retry_after =
            parse_retry_after_header(&headers).expect("future Retry-After date should parse");
        assert!(
            (118_000..=121_000).contains(&retry_after),
            "retry_after={retry_after}"
        );
    }

    #[test]
    fn parse_retry_after_header_past_http_date_is_zero() {
        let retry_at = (chrono::Utc::now() - chrono::Duration::seconds(30))
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string();
        let headers = vec![("Retry-After".to_string(), retry_at)];

        assert_eq!(parse_retry_after_header(&headers), Some(0));
    }

    #[test]
    fn parse_retry_after_header_invalid_value_ignored() {
        let headers = vec![("Retry-After".to_string(), "not-a-date".to_string())];
        assert_eq!(parse_retry_after_header(&headers), None);
    }

    #[test]
    fn api_error_to_fcp_error_500_retryable_external() {
        let error = GoogleApiError {
            status_code: 500,
            message: "internal".to_string(),
            status: None,
            reason: None,
            domain: None,
            access_not_configured_hint: false,
            retry_after_ms: None,
        };
        match error.to_fcp_error("bigquery") {
            fcp_core::FcpError::External {
                service,
                message,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "bigquery");
                assert_eq!(message, "internal");
                assert_eq!(status_code, Some(500));
                assert!(retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn api_error_to_fcp_error_400_not_retryable() {
        let error = GoogleApiError {
            status_code: 400,
            message: "bad request".to_string(),
            status: None,
            reason: None,
            domain: None,
            access_not_configured_hint: false,
            retry_after_ms: None,
        };
        match error.to_fcp_error("google-calendar") {
            fcp_core::FcpError::External {
                service,
                retryable,
                status_code,
                ..
            } => {
                assert_eq!(service, "google-calendar");
                assert!(!retryable);
                assert_eq!(status_code, Some(400));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn api_error_to_fcp_error_preserves_service_name() {
        let error = GoogleApiError {
            status_code: 502,
            message: "bad gateway".to_string(),
            status: None,
            reason: None,
            domain: None,
            access_not_configured_hint: false,
            retry_after_ms: None,
        };
        match error.to_fcp_error("my-custom-service") {
            fcp_core::FcpError::External { service, .. } => {
                assert_eq!(service, "my-custom-service");
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    // ── GoogleExecuteRequest ──────────────────────────────────────────

    #[test]
    fn execute_request_new_sets_defaults() {
        let method = method_fixture("GET", "v1/items", BTreeMap::new());
        let schemas = BTreeMap::new();
        let request = GoogleExecuteRequest::new(&method, &schemas, "https://example.com/");
        assert!(request.parameters.is_empty());
        assert!(request.body.is_none());
        assert!(request.upload.is_none());
        assert_eq!(request.response_mode, GoogleResponseMode::Auto);
        assert!(request.auth.is_none());
        assert!(request.extra_headers.is_empty());
        assert_eq!(request.base_url, "https://example.com/");
    }

    #[test]
    fn execute_request_field_assignment() {
        let method = method_fixture("POST", "v1/items", BTreeMap::new());
        let schemas = BTreeMap::new();
        let mut request = GoogleExecuteRequest::new(&method, &schemas, "https://example.com/");

        request.body = Some(serde_json::json!({"key": "value"}));
        request.response_mode = GoogleResponseMode::Json;
        request
            .extra_headers
            .push(("X-Custom".to_string(), "val".to_string()));
        request
            .parameters
            .insert("q".to_string(), vec!["search".to_string()]);

        assert!(request.body.is_some());
        assert_eq!(request.response_mode, GoogleResponseMode::Json);
        assert_eq!(request.extra_headers.len(), 1);
        assert_eq!(request.parameters.len(), 1);
    }

    #[test]
    fn execute_request_parameter_setting() {
        let mut params_meta = BTreeMap::new();
        params_meta.insert("q".to_string(), query_parameter_meta(false, true));
        params_meta.insert("maxResults".to_string(), query_parameter_meta(false, false));
        let method = method_fixture("GET", "v1/items", params_meta);
        let schemas = BTreeMap::new();
        let mut request = GoogleExecuteRequest::new(&method, &schemas, "https://example.com/");

        request
            .parameters
            .insert("q".to_string(), vec!["a".to_string(), "b".to_string()]);
        request
            .parameters
            .insert("maxResults".to_string(), vec!["10".to_string()]);

        assert_eq!(request.parameters["q"].len(), 2);
        assert_eq!(request.parameters["maxResults"], vec!["10"]);
    }

    // ── GoogleRestError Display ───────────────────────────────────────

    #[test]
    fn rest_error_display_validation() {
        let error = GoogleRestError::RequestBodyValidation {
            schema: "Message".to_string(),
            path: "$.raw".to_string(),
            message: "missing required field".to_string(),
        };
        let display = error.to_string();
        assert!(display.contains("Message"));
        assert!(display.contains("$.raw"));
        assert!(display.contains("missing required field"));
    }

    #[test]
    fn rest_error_display_request_failed() {
        let error = GoogleRestError::UnsupportedHttpMethod {
            method: "TRACE".to_string(),
        };
        let display = error.to_string();
        assert!(display.contains("TRACE"));
    }

    #[test]
    fn rest_error_display_api_error() {
        let api_error = GoogleApiError {
            status_code: 500,
            message: "Internal Server Error".to_string(),
            status: None,
            reason: None,
            domain: None,
            access_not_configured_hint: false,
            retry_after_ms: None,
        };
        let error = GoogleRestError::Api {
            status_code: 500,
            message: "Internal Server Error".to_string(),
            error: api_error,
        };
        let display = error.to_string();
        assert!(display.contains("500"));
        assert!(display.contains("Internal Server Error"));
    }

    #[test]
    fn rest_error_display_body_decode() {
        let json_err = serde_json::from_str::<serde_json::Value>("not-json").unwrap_err();
        let error = GoogleRestError::JsonDecode { source: json_err };
        let display = error.to_string();
        assert!(display.contains("decode response json"));
    }

    #[test]
    fn rest_error_display_missing_required_parameter() {
        let error = GoogleRestError::MissingRequiredParameter {
            name: "userId".to_string(),
            location: Some("path".to_string()),
            location_suffix: " in `path`".to_string(),
        };
        let display = error.to_string();
        assert!(display.contains("userId"));
        assert!(display.contains("in `path`"));
    }

    #[test]
    fn rest_error_display_unknown_parameter() {
        let error = GoogleRestError::UnknownParameter {
            method_key: "users.list".to_string(),
            name: "bogus".to_string(),
        };
        let display = error.to_string();
        assert!(display.contains("bogus"));
        assert!(display.contains("users.list"));
    }

    #[test]
    fn rest_error_display_empty_parameter_value() {
        let error = GoogleRestError::EmptyParameterValue {
            name: "q".to_string(),
        };
        let display = error.to_string();
        assert!(display.contains('q'));
        assert!(display.contains("at least one value"));
    }

    #[test]
    fn rest_error_display_invalid_parameter_multiplicity() {
        let error = GoogleRestError::InvalidParameterMultiplicity {
            name: "id".to_string(),
        };
        let display = error.to_string();
        assert!(display.contains("id"));
        assert!(display.contains("not repeatable"));
    }

    #[test]
    fn rest_error_display_invalid_path_template() {
        let error = GoogleRestError::InvalidPathTemplate {
            template: "v1/{".to_string(),
            message: "missing closing `}`".to_string(),
        };
        let display = error.to_string();
        assert!(display.contains("v1/{"));
        assert!(display.contains("missing closing"));
    }

    #[test]
    fn rest_error_display_missing_path_parameter() {
        let error = GoogleRestError::MissingPathParameter {
            name: "fileId".to_string(),
            template: "v1/files/{fileId}".to_string(),
        };
        let display = error.to_string();
        assert!(display.contains("fileId"));
        assert!(display.contains("v1/files/{fileId}"));
    }

    #[test]
    fn rest_error_display_path_traversal() {
        let error = GoogleRestError::PathTraversalRejected {
            name: "path".to_string(),
            segment: "..".to_string(),
        };
        let display = error.to_string();
        assert!(display.contains("path"));
        assert!(display.contains(".."));
    }

    #[test]
    fn rest_error_display_invalid_base_url() {
        let error = GoogleRestError::InvalidBaseUrl {
            base_url: "not-a-url".to_string(),
            message: "relative URL without a base".to_string(),
        };
        let display = error.to_string();
        assert!(display.contains("not-a-url"));
    }

    #[test]
    fn rest_error_display_missing_request_body() {
        let error = GoogleRestError::MissingRequestBody {
            schema: "Message".to_string(),
        };
        let display = error.to_string();
        assert!(display.contains("Message"));
        assert!(display.contains("required"));
    }

    #[test]
    fn rest_error_display_body_not_allowed() {
        let error = GoogleRestError::BodyNotAllowed {
            http_method: "GET".to_string(),
        };
        let display = error.to_string();
        assert!(display.contains("GET"));
        assert!(display.contains("not allowed"));
    }

    #[test]
    fn rest_error_display_unknown_schema_reference() {
        let error = GoogleRestError::UnknownSchemaReference {
            schema: "FakeSchema".to_string(),
        };
        let display = error.to_string();
        assert!(display.contains("FakeSchema"));
    }

    #[test]
    fn rest_error_display_invalid_upload_configuration() {
        let error = GoogleRestError::InvalidUploadConfiguration {
            message: "method does not expose mediaUpload metadata".to_string(),
        };
        let display = error.to_string();
        assert!(display.contains("mediaUpload"));
    }

    #[test]
    fn rest_error_display_invalid_upload_content_type() {
        let error = GoogleRestError::InvalidUploadContentType {
            content_type: "bad/type".to_string(),
            message: "parse error".to_string(),
        };
        let display = error.to_string();
        assert!(display.contains("bad/type"));
    }

    // ── GoogleResponseMode ────────────────────────────────────────────

    #[test]
    fn response_mode_all_variants() {
        let auto = GoogleResponseMode::Auto;
        let json = GoogleResponseMode::Json;
        let binary = GoogleResponseMode::Binary;

        // Distinct variants
        assert_ne!(auto, json);
        assert_ne!(json, binary);
        assert_ne!(auto, binary);

        // Self-equality
        assert_eq!(auto, GoogleResponseMode::Auto);
        assert_eq!(json, GoogleResponseMode::Json);
        assert_eq!(binary, GoogleResponseMode::Binary);
    }

    // ── GoogleExecuteResponse ─────────────────────────────────────────

    #[test]
    fn execute_response_fields() {
        let response = GoogleExecuteResponse {
            status_code: 200,
            headers: vec![("content-type".to_string(), "application/json".to_string())],
            body: GoogleResponseBody::Json(serde_json::json!({"id": "abc"})),
            next_page_token: Some("token-2".to_string()),
        };
        assert_eq!(response.status_code, 200);
        assert_eq!(response.headers.len(), 1);
        assert_eq!(response.headers[0].0, "content-type");
        assert!(response.body.as_json().is_some());
        assert_eq!(response.next_page_token.as_deref(), Some("token-2"));
    }

    #[test]
    fn execute_response_no_pagination_token() {
        let response = GoogleExecuteResponse {
            status_code: 204,
            headers: Vec::new(),
            body: GoogleResponseBody::Empty,
            next_page_token: None,
        };
        assert_eq!(response.status_code, 204);
        assert!(response.headers.is_empty());
        assert!(response.next_page_token.is_none());
    }

    // ── render_path_template edge cases ───────────────────────────────

    #[test]
    fn render_path_no_params_passthrough() {
        let params = BTreeMap::new();
        let rendered =
            render_path_template("gmail/v1/users/me/profile", &params).expect("no placeholders");
        assert_eq!(rendered, "gmail/v1/users/me/profile");
    }

    #[test]
    fn render_path_percent_encodes_special_chars() {
        let params = BTreeMap::from([("id".to_string(), vec!["hello world".to_string()])]);
        let rendered = render_path_template("v1/items/{id}", &params).expect("rendered");
        assert!(rendered.contains("hello%20world"));
        assert!(!rendered.contains(' '));
    }

    #[test]
    fn render_path_encodes_at_sign_and_slash_in_normal_expansion() {
        let params = BTreeMap::from([("email".to_string(), vec!["a@b.com".to_string()])]);
        let rendered = render_path_template("v1/users/{email}", &params).expect("rendered");
        assert!(rendered.contains("a%40b.com"));
    }

    #[test]
    fn render_path_reserved_expansion_preserves_slashes() {
        let params =
            BTreeMap::from([("name".to_string(), vec!["projects/p/topics/t".to_string()])]);
        let rendered = render_path_template("v1/{+name}", &params).expect("rendered");
        assert_eq!(rendered, "v1/projects/p/topics/t");
    }

    #[test]
    fn render_path_empty_template_rejected() {
        let params = BTreeMap::new();
        let error = render_path_template("", &params).expect_err("empty template");
        assert!(matches!(error, GoogleRestError::InvalidPathTemplate { .. }));
    }

    #[test]
    fn render_path_whitespace_only_template_rejected() {
        let params = BTreeMap::new();
        let error = render_path_template("   ", &params).expect_err("whitespace template");
        assert!(matches!(error, GoogleRestError::InvalidPathTemplate { .. }));
    }

    #[test]
    fn render_path_unmatched_close_brace_rejected() {
        let params = BTreeMap::new();
        let error =
            render_path_template("v1/items}/list", &params).expect_err("unmatched close brace");
        assert!(matches!(error, GoogleRestError::InvalidPathTemplate { .. }));
    }

    #[test]
    fn render_path_missing_close_brace_rejected() {
        let params = BTreeMap::new();
        let error = render_path_template("v1/items/{id", &params).expect_err("missing close brace");
        assert!(matches!(error, GoogleRestError::InvalidPathTemplate { .. }));
    }

    #[test]
    fn render_path_empty_placeholder_token_rejected() {
        let params = BTreeMap::new();
        let error = render_path_template("v1/items/{}", &params).expect_err("empty placeholder");
        assert!(matches!(error, GoogleRestError::InvalidPathTemplate { .. }));
    }

    #[test]
    fn render_path_empty_plus_name_rejected() {
        let params = BTreeMap::new();
        let error = render_path_template("v1/items/{+}", &params).expect_err("empty plus name");
        assert!(matches!(error, GoogleRestError::InvalidPathTemplate { .. }));
    }

    #[test]
    fn render_path_missing_parameter_value() {
        let params = BTreeMap::new();
        let error = render_path_template("v1/items/{id}", &params).expect_err("missing param");
        assert!(matches!(
            error,
            GoogleRestError::MissingPathParameter { .. }
        ));
    }

    #[test]
    fn render_path_empty_string_parameter_value() {
        let params = BTreeMap::from([("id".to_string(), vec![String::new()])]);
        let error = render_path_template("v1/items/{id}", &params).expect_err("empty value");
        assert!(matches!(
            error,
            GoogleRestError::MissingPathParameter { .. }
        ));
    }

    #[test]
    fn render_path_multiple_placeholders() {
        let params = BTreeMap::from([
            ("userId".to_string(), vec!["me".to_string()]),
            ("messageId".to_string(), vec!["abc123".to_string()]),
        ]);
        let rendered =
            render_path_template("gmail/v1/users/{userId}/messages/{messageId}", &params)
                .expect("rendered");
        assert_eq!(rendered, "gmail/v1/users/me/messages/abc123");
    }

    #[test]
    fn render_path_traversal_dot_in_normal_expansion() {
        let params = BTreeMap::from([("id".to_string(), vec!["..".to_string()])]);
        let error = render_path_template("v1/{id}", &params).expect_err("dot-dot traversal");
        assert!(matches!(
            error,
            GoogleRestError::PathTraversalRejected { .. }
        ));
    }

    #[test]
    fn render_path_traversal_single_dot_in_normal_expansion() {
        let params = BTreeMap::from([("id".to_string(), vec![".".to_string()])]);
        let error = render_path_template("v1/{id}", &params).expect_err("single dot traversal");
        assert!(matches!(
            error,
            GoogleRestError::PathTraversalRejected { .. }
        ));
    }

    #[test]
    fn render_path_non_traversal_dot_in_normal_expansion() {
        // "a.b" is not "." or ".." — should be allowed
        let params = BTreeMap::from([("id".to_string(), vec!["a.b".to_string()])]);
        let rendered = render_path_template("v1/{id}", &params).expect("allowed");
        assert!(rendered.contains("a.b"));
    }

    // ── Query parameter edge cases ────────────────────────────────────

    #[test]
    fn query_params_multiple_values() {
        let mut method_params = BTreeMap::new();
        method_params.insert("labels".to_string(), query_parameter_meta(false, true));
        let method = method_fixture("GET", "v1/items", method_params);
        let schemas = BTreeMap::new();
        let mut request = GoogleExecuteRequest::new(&method, &schemas, "https://example.com/");
        request.parameters.insert(
            "labels".to_string(),
            vec!["a".to_string(), "b".to_string(), "c".to_string()],
        );

        let rendered_path =
            render_path_template(&method.canonical_path, &request.parameters).expect("path");
        let mut url = build_url(request.base_url, &rendered_path).expect("url");
        append_query_parameters(&mut url, &request).expect("query");
        let query = url.query().unwrap_or_default().to_string();

        assert!(query.contains("labels=a"));
        assert!(query.contains("labels=b"));
        assert!(query.contains("labels=c"));
    }

    #[test]
    fn query_params_empty_value_string() {
        let mut method_params = BTreeMap::new();
        method_params.insert("filter".to_string(), query_parameter_meta(false, false));
        let method = method_fixture("GET", "v1/items", method_params);
        let schemas = BTreeMap::new();
        let mut request = GoogleExecuteRequest::new(&method, &schemas, "https://example.com/");
        request
            .parameters
            .insert("filter".to_string(), vec![String::new()]);

        let rendered_path =
            render_path_template(&method.canonical_path, &request.parameters).expect("path");
        let mut url = build_url(request.base_url, &rendered_path).expect("url");
        append_query_parameters(&mut url, &request).expect("query");
        let query = url.query().unwrap_or_default().to_string();

        assert!(query.contains("filter="));
    }

    // ── Schema validation ─────────────────────────────────────────────

    fn schema_with_properties(
        required: Vec<&str>,
        properties: Vec<(&str, DiscoverySchema)>,
    ) -> DiscoverySchema {
        DiscoverySchema {
            type_name: Some("object".to_string()),
            format: None,
            description: None,
            required: required.into_iter().map(str::to_string).collect(),
            enum_values: Vec::new(),
            properties: properties
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
            items: None,
            ref_name: None,
            additional_properties: None,
        }
    }

    fn schema_typed(type_name: &str) -> DiscoverySchema {
        DiscoverySchema {
            type_name: Some(type_name.to_string()),
            format: None,
            description: None,
            required: Vec::new(),
            enum_values: Vec::new(),
            properties: BTreeMap::new(),
            items: None,
            ref_name: None,
            additional_properties: None,
        }
    }

    #[test]
    fn validate_schema_accepts_valid_body() {
        let schema = schema_with_properties(
            vec!["name"],
            vec![
                ("name", schema_typed("string")),
                ("age", schema_typed("integer")),
            ],
        );
        let schemas = BTreeMap::new();
        let body = serde_json::json!({"name": "Alice", "age": 30});
        let result = validate_schema_value("TestSchema", &schema, &body, &schemas, "$", 0);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_schema_rejects_wrong_type() {
        let schema = schema_with_properties(vec![], vec![("count", schema_typed("integer"))]);
        let schemas = BTreeMap::new();
        let body = serde_json::json!({"count": "not-a-number"});
        let result = validate_schema_value("TestSchema", &schema, &body, &schemas, "$", 0);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(matches!(
            error,
            GoogleRestError::RequestBodyValidation { ref message, .. }
                if message == "expected integer"
        ));
    }

    #[test]
    fn validate_schema_missing_required_field() {
        let schema = schema_with_properties(vec!["email"], vec![("email", schema_typed("string"))]);
        let schemas = BTreeMap::new();
        let body = serde_json::json!({});
        let result = validate_schema_value("TestSchema", &schema, &body, &schemas, "$", 0);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(matches!(
            error,
            GoogleRestError::RequestBodyValidation { ref path, ref message, .. }
                if path == "$.email" && message == "missing required field"
        ));
    }

    #[test]
    fn validate_schema_additional_properties_validated() {
        let additional = schema_typed("string");
        let schema = DiscoverySchema {
            type_name: Some("object".to_string()),
            format: None,
            description: None,
            required: Vec::new(),
            enum_values: Vec::new(),
            properties: BTreeMap::new(),
            items: None,
            ref_name: None,
            additional_properties: Some(Box::new(additional)),
        };
        let schemas = BTreeMap::new();

        // Valid: additional property is a string
        let body_ok = serde_json::json!({"key": "value"});
        assert!(validate_schema_value("TestSchema", &schema, &body_ok, &schemas, "$", 0).is_ok());

        // Invalid: additional property is not a string
        let body_bad = serde_json::json!({"key": 42});
        let result = validate_schema_value("TestSchema", &schema, &body_bad, &schemas, "$", 0);
        assert!(result.is_err());
    }

    #[test]
    fn validate_schema_rejects_non_object_for_object_schema() {
        let schema = schema_object(vec![]);
        let schemas = BTreeMap::new();
        let body = serde_json::json!("not-an-object");
        let result = validate_schema_value("TestSchema", &schema, &body, &schemas, "$", 0);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GoogleRestError::RequestBodyValidation { ref message, .. }
                if message == "expected object"
        ));
    }

    #[test]
    fn validate_schema_array_type() {
        let item_schema = schema_typed("string");
        let array_schema = DiscoverySchema {
            type_name: Some("array".to_string()),
            format: None,
            description: None,
            required: Vec::new(),
            enum_values: Vec::new(),
            properties: BTreeMap::new(),
            items: Some(Box::new(item_schema)),
            ref_name: None,
            additional_properties: None,
        };
        let schemas = BTreeMap::new();

        // Valid array of strings
        let body_ok = serde_json::json!(["a", "b", "c"]);
        assert!(
            validate_schema_value("TestSchema", &array_schema, &body_ok, &schemas, "$", 0).is_ok()
        );

        // Invalid: array containing non-strings
        let body_bad = serde_json::json!(["a", 42]);
        let result =
            validate_schema_value("TestSchema", &array_schema, &body_bad, &schemas, "$", 0);
        assert!(result.is_err());
    }

    #[test]
    fn validate_schema_rejects_non_array_for_array_schema() {
        let array_schema = DiscoverySchema {
            type_name: Some("array".to_string()),
            format: None,
            description: None,
            required: Vec::new(),
            enum_values: Vec::new(),
            properties: BTreeMap::new(),
            items: None,
            ref_name: None,
            additional_properties: None,
        };
        let schemas = BTreeMap::new();
        let body = serde_json::json!("not-an-array");
        let result = validate_schema_value("TestSchema", &array_schema, &body, &schemas, "$", 0);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GoogleRestError::RequestBodyValidation { ref message, .. }
                if message == "expected array"
        ));
    }

    #[test]
    fn validate_schema_string_type() {
        let schema = schema_typed("string");
        let schemas = BTreeMap::new();

        assert!(
            validate_schema_value("S", &schema, &serde_json::json!("hello"), &schemas, "$", 0)
                .is_ok()
        );
        assert!(
            validate_schema_value("S", &schema, &serde_json::json!(42), &schemas, "$", 0).is_err()
        );
    }

    #[test]
    fn validate_schema_number_type() {
        let schema = schema_typed("number");
        let schemas = BTreeMap::new();

        assert!(
            validate_schema_value("S", &schema, &serde_json::json!(2.5), &schemas, "$", 0).is_ok()
        );
        assert!(
            validate_schema_value("S", &schema, &serde_json::json!(42), &schemas, "$", 0).is_ok()
        );
        assert!(
            validate_schema_value("S", &schema, &serde_json::json!("nan"), &schemas, "$", 0)
                .is_err()
        );
    }

    #[test]
    fn validate_schema_boolean_type() {
        let schema = schema_typed("boolean");
        let schemas = BTreeMap::new();

        assert!(
            validate_schema_value("S", &schema, &serde_json::json!(true), &schemas, "$", 0).is_ok()
        );
        assert!(
            validate_schema_value("S", &schema, &serde_json::json!(false), &schemas, "$", 0)
                .is_ok()
        );
        assert!(
            validate_schema_value("S", &schema, &serde_json::json!("true"), &schemas, "$", 0)
                .is_err()
        );
    }

    #[test]
    fn validate_schema_ref_name_resolves() {
        let ref_schema = DiscoverySchema {
            type_name: None,
            format: None,
            description: None,
            required: Vec::new(),
            enum_values: Vec::new(),
            properties: BTreeMap::new(),
            items: None,
            ref_name: Some("Actual".to_string()),
            additional_properties: None,
        };
        let actual_schema = schema_typed("string");
        let schemas = BTreeMap::from([("Actual".to_string(), actual_schema)]);

        assert!(
            validate_schema_value(
                "Root",
                &ref_schema,
                &serde_json::json!("ok"),
                &schemas,
                "$",
                0
            )
            .is_ok()
        );
        assert!(
            validate_schema_value(
                "Root",
                &ref_schema,
                &serde_json::json!(42),
                &schemas,
                "$",
                0
            )
            .is_err()
        );
    }

    #[test]
    fn validate_schema_ref_name_unknown_rejects() {
        let ref_schema = DiscoverySchema {
            type_name: None,
            format: None,
            description: None,
            required: Vec::new(),
            enum_values: Vec::new(),
            properties: BTreeMap::new(),
            items: None,
            ref_name: Some("Missing".to_string()),
            additional_properties: None,
        };
        let schemas = BTreeMap::new();
        let result = validate_schema_value(
            "Root",
            &ref_schema,
            &serde_json::json!("x"),
            &schemas,
            "$",
            0,
        );
        assert!(matches!(
            result.unwrap_err(),
            GoogleRestError::UnknownSchemaReference { ref schema }
                if schema == "Missing"
        ));
    }

    #[test]
    fn validate_schema_depth_limit_exceeded() {
        let schema = schema_typed("string");
        let schemas = BTreeMap::new();
        let result = validate_schema_value(
            "Deep",
            &schema,
            &serde_json::json!("x"),
            &schemas,
            "$",
            MAX_SCHEMA_VALIDATION_DEPTH + 1,
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GoogleRestError::RequestBodyValidation { ref message, .. }
                if message.contains("depth limit")
        ));
    }

    // ── GoogleRestExecutor ────────────────────────────────────────────

    #[test]
    fn rest_executor_new_creates_instance() {
        let executor = GoogleRestExecutor::new();
        // Debug impl should succeed without panic
        let debug = format!("{executor:?}");
        assert!(debug.contains("GoogleRestExecutor"));
    }

    #[test]
    fn rest_executor_default_creates_instance() {
        let executor = GoogleRestExecutor::default();
        let debug = format!("{executor:?}");
        assert!(debug.contains("GoogleRestExecutor"));
    }

    #[test]
    fn rest_executor_with_client() {
        let client = reqwest::Client::new();
        let executor = GoogleRestExecutor::new().with_client(client);
        let debug = format!("{executor:?}");
        assert!(debug.contains("GoogleRestExecutor"));
    }

    // ── parse_http_method ─────────────────────────────────────────────

    #[test]
    fn parse_http_method_valid_verbs() {
        assert_eq!(parse_http_method("GET").unwrap(), Method::GET);
        assert_eq!(parse_http_method("POST").unwrap(), Method::POST);
        assert_eq!(parse_http_method("PUT").unwrap(), Method::PUT);
        assert_eq!(parse_http_method("PATCH").unwrap(), Method::PATCH);
        assert_eq!(parse_http_method("DELETE").unwrap(), Method::DELETE);
    }

    #[test]
    fn parse_http_method_case_insensitive() {
        assert_eq!(parse_http_method("get").unwrap(), Method::GET);
        assert_eq!(parse_http_method("Post").unwrap(), Method::POST);
        assert_eq!(parse_http_method(" patch ").unwrap(), Method::PATCH);
    }

    #[test]
    fn parse_http_method_unsupported() {
        let error = parse_http_method("TRACE").unwrap_err();
        assert!(matches!(
            error,
            GoogleRestError::UnsupportedHttpMethod { ref method }
                if method == "TRACE"
        ));
    }

    // ── validate_parameters ───────────────────────────────────────────

    #[test]
    fn validate_parameters_unknown_parameter() {
        let method = method_fixture("GET", "v1/items", BTreeMap::new());
        let mut params = BTreeMap::new();
        params.insert("bogus".to_string(), vec!["value".to_string()]);
        let error = validate_parameters(&method, &params).unwrap_err();
        assert!(matches!(error, GoogleRestError::UnknownParameter { .. }));
    }

    #[test]
    fn validate_parameters_empty_values_rejected() {
        let mut method_params = BTreeMap::new();
        method_params.insert("q".to_string(), query_parameter_meta(false, false));
        let method = method_fixture("GET", "v1/items", method_params);
        let mut params = BTreeMap::new();
        params.insert("q".to_string(), Vec::new());
        let error = validate_parameters(&method, &params).unwrap_err();
        assert!(matches!(error, GoogleRestError::EmptyParameterValue { .. }));
    }

    #[test]
    fn validate_parameters_non_repeated_rejects_multiple() {
        let mut method_params = BTreeMap::new();
        method_params.insert("q".to_string(), query_parameter_meta(false, false));
        let method = method_fixture("GET", "v1/items", method_params);
        let mut params = BTreeMap::new();
        params.insert("q".to_string(), vec!["a".to_string(), "b".to_string()]);
        let error = validate_parameters(&method, &params).unwrap_err();
        assert!(matches!(
            error,
            GoogleRestError::InvalidParameterMultiplicity { .. }
        ));
    }

    #[test]
    fn validate_parameters_required_missing() {
        let mut method_params = BTreeMap::new();
        method_params.insert("userId".to_string(), path_param(true));
        let method = method_fixture("GET", "v1/users/{userId}", method_params);
        let params = BTreeMap::new();
        let error = validate_parameters(&method, &params).unwrap_err();
        assert!(matches!(
            error,
            GoogleRestError::MissingRequiredParameter { ref name, .. }
                if name == "userId"
        ));
    }

    #[test]
    fn validate_parameters_required_with_blank_values() {
        let mut method_params = BTreeMap::new();
        method_params.insert("userId".to_string(), path_param(true));
        let method = method_fixture("GET", "v1/users/{userId}", method_params);
        let mut params = BTreeMap::new();
        params.insert("userId".to_string(), vec!["  ".to_string()]);
        let error = validate_parameters(&method, &params).unwrap_err();
        assert!(matches!(
            error,
            GoogleRestError::MissingRequiredParameter { .. }
        ));
    }

    #[test]
    fn validate_parameters_repeated_allows_multiple() {
        let mut method_params = BTreeMap::new();
        method_params.insert("labels".to_string(), query_parameter_meta(false, true));
        let method = method_fixture("GET", "v1/items", method_params);
        let mut params = BTreeMap::new();
        params.insert(
            "labels".to_string(),
            vec!["a".to_string(), "b".to_string(), "c".to_string()],
        );
        assert!(validate_parameters(&method, &params).is_ok());
    }

    #[test]
    fn validate_parameters_optional_can_be_absent() {
        let mut method_params = BTreeMap::new();
        method_params.insert("q".to_string(), query_parameter_meta(false, false));
        let method = method_fixture("GET", "v1/items", method_params);
        let params = BTreeMap::new();
        assert!(validate_parameters(&method, &params).is_ok());
    }

    // ── location_suffix ───────────────────────────────────────────────

    #[test]
    fn location_suffix_some_value() {
        assert_eq!(location_suffix(Some("path")), " in `path`");
        assert_eq!(location_suffix(Some("query")), " in `query`");
    }

    #[test]
    fn location_suffix_none_value() {
        assert_eq!(location_suffix(None), String::new());
    }

    // ── decode_response_body ──────────────────────────────────────────

    #[test]
    fn decode_response_body_empty_bytes_returns_empty() {
        let result = decode_response_body(b"", None, GoogleResponseMode::Auto).expect("decode");
        assert!(matches!(result, GoogleResponseBody::Empty));
    }

    #[test]
    fn decode_response_body_json_mode_valid() {
        let bytes = serde_json::to_vec(&serde_json::json!({"ok": true})).expect("serialize");
        let result = decode_response_body(&bytes, None, GoogleResponseMode::Json).expect("decode");
        assert!(result.as_json().is_some());
    }

    #[test]
    fn decode_response_body_json_mode_invalid_fails() {
        let result = decode_response_body(b"not-json", None, GoogleResponseMode::Json);
        assert!(result.is_err());
    }

    #[test]
    fn decode_response_body_binary_mode() {
        let result = decode_response_body(b"raw", Some("text/plain"), GoogleResponseMode::Binary)
            .expect("decode");
        assert_eq!(result.as_bytes(), Some(&b"raw"[..]));
    }

    #[test]
    fn decode_response_body_auto_json_by_content_type() {
        let bytes = serde_json::to_vec(&serde_json::json!({"x": 1})).expect("serialize");
        let result =
            decode_response_body(&bytes, Some("application/json"), GoogleResponseMode::Auto)
                .expect("decode");
        assert!(result.as_json().is_some());
    }

    #[test]
    fn decode_response_body_auto_json_by_leading_brace() {
        let bytes = b"{\"x\":1}";
        let result = decode_response_body(bytes, Some("text/plain"), GoogleResponseMode::Auto)
            .expect("decode");
        assert!(result.as_json().is_some());
    }

    #[test]
    fn decode_response_body_auto_json_by_leading_bracket() {
        let bytes = b"[1,2,3]";
        let result = decode_response_body(bytes, Some("text/plain"), GoogleResponseMode::Auto)
            .expect("decode");
        assert!(result.as_json().is_some());
    }

    #[test]
    fn decode_response_body_auto_binary_fallback() {
        let result = decode_response_body(
            b"raw-binary",
            Some("application/octet-stream"),
            GoogleResponseMode::Auto,
        )
        .expect("decode");
        assert!(result.as_bytes().is_some());
    }

    #[test]
    fn decode_response_body_auto_invalid_json_falls_back_to_binary() {
        // Starts with '{' but is not valid JSON — should fall back to binary
        let result = decode_response_body(
            b"{not valid json",
            Some("text/plain"),
            GoogleResponseMode::Auto,
        )
        .expect("decode");
        assert!(result.as_bytes().is_some());
    }

    // ── extract_next_page_token ───────────────────────────────────────

    #[test]
    fn extract_next_page_token_camel_case() {
        let body = serde_json::json!({"nextPageToken": "abc"});
        assert_eq!(extract_next_page_token(&body), Some("abc"));
    }

    #[test]
    fn extract_next_page_token_snake_case() {
        let body = serde_json::json!({"next_page_token": "def"});
        assert_eq!(extract_next_page_token(&body), Some("def"));
    }

    #[test]
    fn extract_next_page_token_missing() {
        let body = serde_json::json!({"items": []});
        assert_eq!(extract_next_page_token(&body), None);
    }

    #[test]
    fn extract_next_page_token_non_string() {
        let body = serde_json::json!({"nextPageToken": 42});
        assert_eq!(extract_next_page_token(&body), None);
    }

    // ── parse_google_api_error ────────────────────────────────────────

    #[test]
    fn parse_google_api_error_non_json_body() {
        let parsed = parse_google_api_error(StatusCode::INTERNAL_SERVER_ERROR, b"Server Error");
        assert_eq!(parsed.status_code, 500);
        assert!(parsed.message.contains("Server Error"));
        assert!(!parsed.access_not_configured_hint);
    }

    #[test]
    fn parse_google_api_error_empty_body() {
        let parsed = parse_google_api_error(StatusCode::BAD_GATEWAY, b"");
        assert_eq!(parsed.status_code, 502);
        assert!(parsed.message.contains("502"));
        assert!(parsed.status.is_none());
    }

    #[test]
    fn parse_google_api_error_valid_envelope() {
        let body = serde_json::json!({
            "error": {
                "code": 429,
                "message": "Rate limit exceeded",
                "status": "RESOURCE_EXHAUSTED",
                "errors": [{"reason": "rateLimitExceeded", "domain": "usageLimits"}]
            }
        });
        let bytes = serde_json::to_vec(&body).expect("serialize");
        let parsed = parse_google_api_error(StatusCode::TOO_MANY_REQUESTS, &bytes);
        assert_eq!(parsed.status_code, 429);
        assert_eq!(parsed.message, "Rate limit exceeded");
        assert_eq!(parsed.status.as_deref(), Some("RESOURCE_EXHAUSTED"));
        assert_eq!(parsed.reason.as_deref(), Some("rateLimitExceeded"));
        assert_eq!(parsed.domain.as_deref(), Some("usageLimits"));
        assert!(!parsed.access_not_configured_hint);
    }

    #[test]
    fn parse_google_api_error_envelope_no_code_falls_back_to_status() {
        let body = serde_json::json!({
            "error": {
                "message": "Something went wrong"
            }
        });
        let bytes = serde_json::to_vec(&body).expect("serialize");
        let parsed = parse_google_api_error(StatusCode::BAD_REQUEST, &bytes);
        assert_eq!(parsed.status_code, 400);
        assert_eq!(parsed.message, "Something went wrong");
    }

    #[test]
    fn parse_google_api_error_envelope_empty_message_uses_http_code() {
        let body = serde_json::json!({
            "error": {
                "code": 404,
                "message": "   "
            }
        });
        let bytes = serde_json::to_vec(&body).expect("serialize");
        let parsed = parse_google_api_error(StatusCode::NOT_FOUND, &bytes);
        assert_eq!(parsed.status_code, 404);
        assert!(parsed.message.contains("404"));
    }

    // ── build_url ─────────────────────────────────────────────────────

    #[test]
    fn build_url_valid_join() {
        let url = build_url("https://example.com/", "v1/items").expect("url");
        assert_eq!(url.as_str(), "https://example.com/v1/items");
    }

    #[test]
    fn build_url_strips_leading_slash() {
        let url = build_url("https://example.com/", "/v1/items").expect("url");
        assert_eq!(url.as_str(), "https://example.com/v1/items");
    }

    #[test]
    fn build_url_invalid_base() {
        let error = build_url("not-a-url", "v1/items").unwrap_err();
        assert!(matches!(error, GoogleRestError::InvalidBaseUrl { .. }));
    }

    // ── resolve_path_template (method-level) ──────────────────────────

    #[test]
    fn resolve_path_template_no_upload_uses_canonical() {
        let method = method_fixture("GET", "gmail/v1/users/me/profile", BTreeMap::new());
        let resolved = resolve_path_template(&method, None).expect("resolved");
        assert_eq!(resolved, "gmail/v1/users/me/profile");
    }

    #[test]
    fn resolve_path_template_upload_without_media_metadata_fails() {
        let method = method_fixture("POST", "v1/files", BTreeMap::new());
        let upload = GoogleUploadPayload::simple("application/octet-stream", vec![]);
        let error = resolve_path_template(&method, Some(&upload)).unwrap_err();
        assert!(matches!(
            error,
            GoogleRestError::InvalidUploadConfiguration { .. }
        ));
    }

    #[test]
    fn resolve_path_template_multipart_uses_simple_path() {
        let mut method = method_fixture("POST", "v1/files", BTreeMap::new());
        method.media_upload = Some(crate::DiscoveryMediaUpload {
            accept: vec!["*/*".to_string()],
            max_size: None,
            simple_path: Some("upload/v1/files".to_string()),
            resumable_path: Some("upload/v1/files/resumable".to_string()),
        });
        let upload = GoogleUploadPayload::multipart(
            "application/octet-stream",
            vec![1],
            serde_json::json!({}),
        );
        let resolved = resolve_path_template(&method, Some(&upload)).expect("resolved");
        assert_eq!(resolved, "upload/v1/files");
    }

    #[test]
    fn resolve_path_template_missing_simple_path_fails() {
        let mut method = method_fixture("POST", "v1/files", BTreeMap::new());
        method.media_upload = Some(crate::DiscoveryMediaUpload {
            accept: vec!["*/*".to_string()],
            max_size: None,
            simple_path: None,
            resumable_path: Some("upload/v1/files/resumable".to_string()),
        });
        let upload = GoogleUploadPayload::simple("application/octet-stream", vec![]);
        let error = resolve_path_template(&method, Some(&upload)).unwrap_err();
        assert!(matches!(
            error,
            GoogleRestError::InvalidUploadConfiguration { .. }
        ));
    }

    #[test]
    fn resolve_path_template_missing_resumable_path_fails() {
        let mut method = method_fixture("POST", "v1/files", BTreeMap::new());
        method.media_upload = Some(crate::DiscoveryMediaUpload {
            accept: vec!["*/*".to_string()],
            max_size: None,
            simple_path: Some("upload/v1/files".to_string()),
            resumable_path: None,
        });
        let upload = GoogleUploadPayload::resumable(
            "application/octet-stream",
            vec![],
            serde_json::json!({}),
        );
        let error = resolve_path_template(&method, Some(&upload)).unwrap_err();
        assert!(matches!(
            error,
            GoogleRestError::InvalidUploadConfiguration { .. }
        ));
    }

    // ── validate_request_body (method-level) ──────────────────────────

    #[test]
    fn validate_request_body_no_schema_ref_always_ok() {
        let method = method_fixture("GET", "v1/items", BTreeMap::new());
        let schemas = BTreeMap::new();
        assert!(validate_request_body(&method, &schemas, None, None).is_ok());
        assert!(
            validate_request_body(&method, &schemas, Some(&serde_json::json!({})), None,).is_ok()
        );
    }

    #[test]
    fn validate_request_body_missing_for_post_with_schema() {
        let mut method = method_fixture("POST", "v1/items", BTreeMap::new());
        method.request_ref = Some("Item".to_string());
        let schemas = BTreeMap::from([("Item".to_string(), schema_object(vec![]))]);
        let error = validate_request_body(&method, &schemas, None, None).unwrap_err();
        assert!(matches!(error, GoogleRestError::MissingRequestBody { .. }));
    }

    #[test]
    fn validate_request_body_missing_schema_in_map() {
        let mut method = method_fixture("POST", "v1/items", BTreeMap::new());
        method.request_ref = Some("NonExistent".to_string());
        let schemas = BTreeMap::new();
        let body = serde_json::json!({});
        let error = validate_request_body(&method, &schemas, Some(&body), None).unwrap_err();
        assert!(matches!(
            error,
            GoogleRestError::UnknownSchemaReference { .. }
        ));
    }

    #[test]
    fn validate_request_body_get_with_schema_ref_no_body_ok() {
        // GET methods with schema_ref but no body should be OK (not required for GET)
        let mut method = method_fixture("GET", "v1/items", BTreeMap::new());
        method.request_ref = Some("Item".to_string());
        let schemas = BTreeMap::from([("Item".to_string(), schema_object(vec![]))]);
        assert!(validate_request_body(&method, &schemas, None, None).is_ok());
    }

    // ── encode_path_value / encode_path_segment ───────────────────────

    #[test]
    fn encode_path_segment_preserves_unreserved() {
        let encoded = encode_path_segment("hello-world_test.file~name");
        assert_eq!(encoded, "hello-world_test.file~name");
    }

    #[test]
    fn encode_path_segment_encodes_special() {
        let encoded = encode_path_segment("a@b c/d");
        assert!(encoded.contains("%40"));
        assert!(encoded.contains("%20"));
        assert!(encoded.contains("%2F"));
    }

    #[test]
    fn encode_path_value_reserved_preserves_slashes() {
        let encoded = encode_path_value("projects/p/topics/t", true);
        assert_eq!(encoded, "projects/p/topics/t");
    }

    #[test]
    fn encode_path_value_non_reserved_encodes_slashes() {
        let encoded = encode_path_value("a/b", false);
        assert!(encoded.contains("%2F"));
    }

    // ── GoogleUploadPayload clone and eq ──────────────────────────────

    #[test]
    fn upload_payload_clone_and_eq() {
        let payload = GoogleUploadPayload::simple("text/plain", b"data".to_vec());
        let cloned = payload.clone();
        assert_eq!(payload, cloned);
    }

    #[test]
    fn upload_mode_clone_copy_eq() {
        let mode = GoogleUploadMode::Resumable;
        let copied = mode;
        assert_eq!(mode, copied);
        // Verify all variants are distinct via Copy
        let a = GoogleUploadMode::Simple;
        let b = GoogleUploadMode::Multipart;
        let c = GoogleUploadMode::Resumable;
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }

    #[test]
    fn response_body_clone_and_eq() {
        let body = GoogleResponseBody::Json(serde_json::json!({"a": 1}));
        let cloned = body.clone();
        assert_eq!(body, cloned);
    }

    #[test]
    fn api_error_clone_and_eq() {
        let error = GoogleApiError {
            status_code: 401,
            message: "Unauthorized".to_string(),
            status: None,
            reason: None,
            domain: None,
            access_not_configured_hint: false,
            retry_after_ms: None,
        };
        let cloned = error.clone();
        assert_eq!(error, cloned);
    }

    #[test]
    fn execute_response_clone_and_eq() {
        let response = GoogleExecuteResponse {
            status_code: 200,
            headers: Vec::new(),
            body: GoogleResponseBody::Empty,
            next_page_token: None,
        };
        let cloned = response.clone();
        assert_eq!(response, cloned);
    }

    // ── body_for_validation ───────────────────────────────────────────

    #[test]
    fn body_for_validation_prefers_upload_metadata() {
        let method = method_fixture("POST", "v1/items", BTreeMap::new());
        let schemas = BTreeMap::new();
        let mut request = GoogleExecuteRequest::new(&method, &schemas, "https://example.com/");
        request.body = Some(serde_json::json!({"from_body": true}));
        request.upload = Some(GoogleUploadPayload::multipart(
            "text/plain",
            vec![],
            serde_json::json!({"from_upload": true}),
        ));

        let result = body_for_validation(&request);
        assert_eq!(result, Some(serde_json::json!({"from_upload": true})));
    }

    #[test]
    fn body_for_validation_falls_back_to_body() {
        let method = method_fixture("POST", "v1/items", BTreeMap::new());
        let schemas = BTreeMap::new();
        let mut request = GoogleExecuteRequest::new(&method, &schemas, "https://example.com/");
        request.body = Some(serde_json::json!({"from_body": true}));

        let result = body_for_validation(&request);
        assert_eq!(result, Some(serde_json::json!({"from_body": true})));
    }

    #[test]
    fn body_for_validation_simple_upload_no_metadata() {
        let method = method_fixture("POST", "v1/items", BTreeMap::new());
        let schemas = BTreeMap::new();
        let mut request = GoogleExecuteRequest::new(&method, &schemas, "https://example.com/");
        request.upload = Some(GoogleUploadPayload::simple("text/plain", vec![]));

        let result = body_for_validation(&request);
        assert!(result.is_none());
    }

    #[test]
    fn body_for_validation_none_when_both_absent() {
        let method = method_fixture("GET", "v1/items", BTreeMap::new());
        let schemas = BTreeMap::new();
        let request = GoogleExecuteRequest::new(&method, &schemas, "https://example.com/");

        let result = body_for_validation(&request);
        assert!(result.is_none());
    }

    // ── reject_path_traversal ─────────────────────────────────────────

    #[test]
    fn reject_path_traversal_normal_safe_values() {
        assert!(reject_path_traversal("id", "normal-value", false).is_ok());
        assert!(reject_path_traversal("id", "a.b.c", false).is_ok());
        assert!(reject_path_traversal("id", "../etc", false).is_ok()); // not "." or ".."
    }

    #[test]
    fn reject_path_traversal_normal_dotdot() {
        assert!(reject_path_traversal("id", "..", false).is_err());
        assert!(reject_path_traversal("id", ".", false).is_err());
    }

    #[test]
    fn reject_path_traversal_reserved_checks_segments() {
        assert!(reject_path_traversal("name", "a/../b", true).is_err());
        assert!(reject_path_traversal("name", "a/./b", true).is_err());
        assert!(reject_path_traversal("name", "a/b/c", true).is_ok());
    }
}
