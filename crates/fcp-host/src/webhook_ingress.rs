//! Bounded translation from public webhook HTTP requests to FCP invocations.
//!
//! The operator chooses the receiver, zone, public URL and capability token.
//! HTTP headers and bodies are provider data, never FCP execution authority.
//! The HTTP runtime owns body-read deadlines and concurrent admission; this
//! module validates request heads before collection and preserves signed bytes.

use std::fmt;
use std::net::IpAddr;

use axum::http::{HeaderMap, StatusCode, Uri};
use fcp_crypto::Ed25519SigningKey;
use fcp_prelude::{
    CapabilityToken, ConnectorId, CorrelationId, FcpError, HolderProof, InvokeRequest,
    InvokeResponse, InvokeStatus, OperationId, Provenance, ProvenanceStep, RequestId,
    TailscaleNodeId, ZoneId,
};
use serde_json::{Map, Value, json};
use thiserror::Error;
use url::Url;

/// The host route reserved for explicitly configured webhook intake.
pub const WEBHOOK_INGRESS_ROUTE: &str = "/webhooks/{*path}";
/// Every HTTP delivery invokes this one receiver operation.
pub const WEBHOOK_INGRESS_OPERATION: &str = "webhook.events.ingest";
/// Default maximum HTTP body size, before JSON transport encoding.
pub const DEFAULT_WEBHOOK_INGRESS_MAX_BODY_BYTES: usize = 1024 * 1024;
/// Hard upper bound for one HTTP delivery body.
pub const MAX_WEBHOOK_INGRESS_BODY_BYTES: usize = 16 * 1024 * 1024;
/// Default total body-read and invocation budget.
pub const DEFAULT_WEBHOOK_INGRESS_TIMEOUT_MS: u64 = 15_000;
/// Hard upper bound for a delivery's total time budget.
pub const MAX_WEBHOOK_INGRESS_TIMEOUT_MS: u64 = 120_000;
/// Default number of simultaneously admitted HTTP deliveries.
pub const DEFAULT_WEBHOOK_INGRESS_MAX_IN_FLIGHT: usize = 8;
/// Hard upper bound for simultaneous deliveries.
pub const MAX_WEBHOOK_INGRESS_IN_FLIGHT: usize = 64;
/// Aggregate admitted raw body bytes, excluding encoding/allocation overhead.
pub const MAX_WEBHOOK_INGRESS_RETAINED_BODY_BYTES: usize = 64 * 1024 * 1024;
/// Maximum header entries, including fields suppressed before dispatch.
pub const MAX_WEBHOOK_INGRESS_HEADERS: usize = 100;
/// Maximum combined header-name and value bytes before dispatch.
pub const MAX_WEBHOOK_INGRESS_HEADER_BYTES: usize = 32 * 1024;
/// Maximum raw path and query length; no URI normalization is performed.
pub const MAX_WEBHOOK_INGRESS_TARGET_BYTES: usize = 8192;

const WEBHOOK_PREFIX: &str = "/webhooks";
const RECEIVER_ID: &str = "fcp.webhook-receiver";
const MAX_PUBLIC_BASE_URL_BYTES: usize = 2048;
// A verification challenge is a bounded control reply, never an arbitrary
// receiver-selected HTTP response or a reflection of the unverified request.
const MAX_SLACK_CHALLENGE_BYTES: usize = 4096;

/// Immutable, validated operator authority and resource limits for intake.
///
/// The token remains unverified here: the host and receiver perform normal
/// cryptographic, zone, operation and instance admission on every invocation.
/// This type neither infers a zone nor borrows authority from an HTTP caller.
#[derive(Clone)]
pub struct WebhookIngressConfig {
    connector_id: ConnectorId,
    zone_id: ZoneId,
    capability_token: Option<CapabilityToken>,
    holder_signer: Option<WebhookHolderSigner>,
    public_base_url: String,
    max_body_bytes: usize,
    timeout_ms: u64,
    max_in_flight: usize,
}

#[derive(Clone)]
struct WebhookHolderSigner {
    key: Ed25519SigningKey,
    holder_node: TailscaleNodeId,
    token_jti: Vec<u8>,
}

impl fmt::Debug for WebhookIngressConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebhookIngressConfig")
            .field("connector_id", &self.connector_id)
            .field("zone_id", &self.zone_id)
            .field("capability_token", &"[redacted]")
            .field(
                "holder_signer",
                &self.holder_signer.as_ref().map(|_| "[redacted]"),
            )
            .field("public_base_url", &self.public_base_url)
            .field("max_body_bytes", &self.max_body_bytes)
            .field("timeout_ms", &self.timeout_ms)
            .field("max_in_flight", &self.max_in_flight)
            .finish()
    }
}

impl WebhookIngressConfig {
    /// Construct intake authority with explicit, independently bounded limits.
    ///
    /// The public base must be an HTTP(S) origin followed by /webhooks,
    /// without a trailing slash, userinfo, query or fragment. HTTP is permitted
    /// only for localhost or literal loopback addresses. The original base
    /// string is retained for providers whose signatures include the URL.
    ///
    /// # Errors
    /// Rejects another connector family, ambiguous URLs, insecure public URLs,
    /// zero limits or limits above the host's hard ceilings.
    pub fn new(
        connector_id: ConnectorId,
        zone_id: ZoneId,
        capability_token: CapabilityToken,
        public_base_url: String,
        max_body_bytes: usize,
        timeout_ms: u64,
        max_in_flight: usize,
    ) -> Result<Self, WebhookIngressError> {
        Self::without_capability_token(
            connector_id,
            zone_id,
            public_base_url,
            max_body_bytes,
            timeout_ms,
            max_in_flight,
        )
        .map(|config| config.with_capability_token(capability_token))
    }

    /// Validate a fixed ingress binding before a receiver token is available.
    ///
    /// The host may start this inactive binding, prepare the real native
    /// connector session, and let an operator issue a token for that instance.
    /// Building an invocation fails closed until a token is supplied.
    ///
    /// # Errors
    /// Rejects invalid receiver identities, public URLs and resource limits
    /// identically to the configured constructor.
    pub fn without_capability_token(
        connector_id: ConnectorId,
        zone_id: ZoneId,
        public_base_url: String,
        max_body_bytes: usize,
        timeout_ms: u64,
        max_in_flight: usize,
    ) -> Result<Self, WebhookIngressError> {
        if !is_receiver_id(connector_id.as_str()) {
            return Err(WebhookIngressError::InvalidConfiguration(
                "connector_id must identify the webhook receiver",
            ));
        }
        validate_public_base_url(&public_base_url)?;
        if !(1..=MAX_WEBHOOK_INGRESS_BODY_BYTES).contains(&max_body_bytes) {
            return Err(WebhookIngressError::InvalidConfiguration(
                "max_body_bytes is outside the permitted range",
            ));
        }
        if !(1..=MAX_WEBHOOK_INGRESS_TIMEOUT_MS).contains(&timeout_ms) {
            return Err(WebhookIngressError::InvalidConfiguration(
                "timeout_ms is outside the permitted range",
            ));
        }
        if !(1..=MAX_WEBHOOK_INGRESS_IN_FLIGHT).contains(&max_in_flight) {
            return Err(WebhookIngressError::InvalidConfiguration(
                "max_in_flight is outside the permitted range",
            ));
        }
        if max_body_bytes
            .checked_mul(max_in_flight)
            .is_none_or(|bytes| bytes > MAX_WEBHOOK_INGRESS_RETAINED_BODY_BYTES)
        {
            return Err(WebhookIngressError::InvalidConfiguration(
                "max_body_bytes times max_in_flight exceeds the host's aggregate body budget",
            ));
        }
        Ok(Self {
            connector_id,
            zone_id,
            capability_token: None,
            holder_signer: None,
            public_base_url,
            max_body_bytes,
            timeout_ms,
            max_in_flight,
        })
    }

    /// Supply a token for one attempt without changing the validated binding.
    ///
    /// This does not authenticate the token or extend its lifetime. The host
    /// and receiver still verify it, including the receiver's current instance.
    #[must_use]
    pub fn with_capability_token(mut self, capability_token: CapabilityToken) -> Self {
        self.capability_token = Some(capability_token);
        // A proof context is bound to one token's holder and JTI. Replacing the
        // token must never retain the previous signing context.
        self.holder_signer = None;
        self
    }

    /// Supply one attempt's capability and optional operator-owned holder key.
    ///
    /// Unverified claims select signing context only. The ordinary host path
    /// still verifies the token and resolves the holder's public key from
    /// owner-authenticated membership, including immediately before dispatch.
    /// No signing key is generated or inferred from provider request data.
    ///
    /// # Errors
    /// Rejects malformed claims, a holder-bound token without a key or nonempty
    /// JTI, and a key supplied for a bearer token. Errors expose no key material.
    pub fn with_execution_authority(
        self,
        capability_token: CapabilityToken,
        holder_key: Option<Ed25519SigningKey>,
    ) -> Result<Self, WebhookIngressError> {
        let claims = capability_token
            .raw()
            .claims_unverified()
            .map_err(|_| WebhookIngressError::Unavailable)?;
        let holder_signer = match (claims.get_holder_node(), holder_key) {
            (Some(holder), Some(key)) => {
                let holder_node = TailscaleNodeId::try_new(holder)
                    .map_err(|_| WebhookIngressError::Unavailable)?;
                let token_jti = claims
                    .get_jti()
                    .filter(|jti| !jti.is_empty())
                    .ok_or(WebhookIngressError::Unavailable)?;
                Some(WebhookHolderSigner {
                    key,
                    holder_node,
                    token_jti: token_jti.to_vec(),
                })
            }
            (None, None)
                if claims
                    .get(fcp_crypto::cose::fcp2_claims::HOLDER_NODE)
                    .is_none() =>
            {
                None
            }
            _ => return Err(WebhookIngressError::Unavailable),
        };
        let mut config = self.with_capability_token(capability_token);
        config.holder_signer = holder_signer;
        Ok(config)
    }

    fn holder_proof_for(
        &self,
        request_id: &RequestId,
        operation: &OperationId,
    ) -> Result<Option<HolderProof>, WebhookIngressError> {
        if let Some(signer) = &self.holder_signer {
            let signable = HolderProof::signable_bytes(request_id, operation, &signer.token_jti);
            return Ok(Some(HolderProof::new(
                signer.key.sign(&signable).to_bytes(),
                signer.holder_node.clone(),
            )));
        }
        let claims = self
            .capability_token
            .as_ref()
            .ok_or(WebhookIngressError::Unavailable)?
            .raw()
            .claims_unverified()
            .map_err(|_| WebhookIngressError::Unavailable)?;
        // A present but non-text holder claim is malformed, not bearer
        // authority. Token-only replacement cannot bypass this requirement.
        if claims
            .get(fcp_crypto::cose::fcp2_claims::HOLDER_NODE)
            .is_some()
        {
            return Err(WebhookIngressError::Unavailable);
        }
        Ok(None)
    }

    /// Receiver identity selected by the operator.
    #[must_use]
    pub const fn connector_id(&self) -> &ConnectorId {
        &self.connector_id
    }

    /// Explicit execution zone; this is never inferred from an HTTP request.
    #[must_use]
    pub const fn zone_id(&self) -> &ZoneId {
        &self.zone_id
    }

    /// Exact operator-provisioned public origin and route prefix.
    #[must_use]
    pub fn public_base_url(&self) -> &str {
        &self.public_base_url
    }

    /// Maximum body bytes to collect before invoking the receiver.
    #[must_use]
    pub const fn max_body_bytes(&self) -> usize {
        self.max_body_bytes
    }

    /// Total request budget, including body collection and invocation.
    #[must_use]
    pub const fn timeout_ms(&self) -> u64 {
        self.timeout_ms
    }

    /// Maximum concurrent deliveries admitted by the HTTP runtime.
    #[must_use]
    pub const fn max_in_flight(&self) -> usize {
        self.max_in_flight
    }

    /// Reject invalid or ambiguous request metadata before reading the body.
    ///
    /// Header bounds include all fields, even ones that are never forwarded.
    /// Duplicate names are rejected rather than joining signature values.
    ///
    /// # Errors
    /// Rejects excessive, duplicated or non-text headers, absolute-form targets,
    /// malformed percent escapes and path aliases that could change endpoint
    /// selection when a proxy or URL parser normalizes them.
    #[allow(clippy::unused_self)] // All configured intake routes share the same head policy.
    pub fn validate_request_head(
        &self,
        headers: &HeaderMap,
        uri: &Uri,
    ) -> Result<(), WebhookIngressError> {
        validate_headers(headers)?;
        endpoint_path(uri)?;
        Ok(())
    }

    /// Build a capability-gated invocation from one public POST delivery.
    ///
    /// The body is copied byte for byte, without parsing or serializing provider
    /// JSON or form data. The URI must be the original, undecoded request target.
    /// The peer IP must come from the HTTP connection, never a forwarding header.
    /// The configured public base and raw suffix/query construct the signed URL.
    ///
    /// Every attempt receives a new OS-random request, idempotency and
    /// delivery identity. Unsigned provider delivery labels cannot occupy the
    /// host's idempotency cache or the receiver's public-ID replay index. The
    /// receiver confirms previously accepted authenticated-content digests
    /// without recording another event or reserving the retry's unsigned ID.
    ///
    /// The operator's fixed intake command originates in the configured zone;
    /// the provider supplies only opaque payload data. Public-input taint is
    /// retained without elevation, and the typed provenance chain records the
    /// public payload's exact-byte digest separately from the fixed command.
    /// Normal zone policy still decides whether this command may run.
    ///
    /// # Errors
    /// Returns request-head failures, an oversized-body failure, or unavailable
    /// authority when a holder-bound capability has no matching signing context.
    pub fn build_request(
        &self,
        headers: &HeaderMap,
        uri: &Uri,
        body: &str,
        peer_ip: Option<IpAddr>,
    ) -> Result<InvokeRequest, WebhookIngressError> {
        let capability_token = self
            .capability_token
            .as_ref()
            .ok_or(WebhookIngressError::Unavailable)?;
        self.validate_request_head(headers, uri)?;
        if body.len() > self.max_body_bytes {
            return Err(WebhookIngressError::PayloadTooLarge);
        }
        let path = endpoint_path(uri)?;
        let mut provider_headers = Map::new();
        for (name, value) in headers {
            if !is_authority_header(name.as_str()) {
                provider_headers.insert(
                    name.as_str().to_string(),
                    Value::String(
                        value
                            .to_str()
                            .map_err(|_| WebhookIngressError::InvalidHeaders)?
                            .to_string(),
                    ),
                );
            }
        }

        // RequestId::random() is a process-local counter. Durable delivery
        // identities must also remain distinct after a host process restart.
        let delivery_id = format!(
            "webhook-http-{}",
            hex::encode(fcp_crypto::aead::XChaCha20Nonce::generate().as_bytes())
        );
        let id = RequestId::new(delivery_id.clone());
        let operation = OperationId::from_static(WEBHOOK_INGRESS_OPERATION);
        let holder_proof = self.holder_proof_for(&id, &operation)?;
        let mut signed_url = format!("{}{path}", self.public_base_url);
        if let Some(query) = uri.query() {
            signed_url.push('?');
            signed_url.push_str(query);
        }
        let mut input = json!({
            "method": "POST",
            "path": path,
            "url": signed_url,
            "headers": provider_headers,
            "body": body,
            "body_size_bytes": body.len(),
            "delivery_id": delivery_id,
        });
        if let Some(peer_ip) = peer_ip {
            let source = peer_ip.to_string();
            input["source_ip"] = Value::String(source.clone());
            input["client_id"] = Value::String(source);
        }

        let timestamp_ms = u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(0);
        let provenance = Provenance::tainted(self.zone_id.clone())
            .with_step(ProvenanceStep {
                timestamp_ms,
                zone: ZoneId::public(),
                actor: "external.webhook-provider".to_string(),
                action: "webhook.payload.received".to_string(),
                resource: format!("urn:blake3:{}", blake3::hash(body.as_bytes()).to_hex()),
            })
            .with_step(ProvenanceStep {
                timestamp_ms,
                zone: self.zone_id.clone(),
                actor: "fcp-host.webhook-ingress".to_string(),
                action: WEBHOOK_INGRESS_OPERATION.to_string(),
                resource: self.connector_id.as_str().to_string(),
            });

        Ok(InvokeRequest {
            r#type: "invoke".to_string(),
            id,
            connector_id: self.connector_id.clone(),
            operation,
            zone_id: self.zone_id.clone(),
            input,
            capability_token: capability_token.clone(),
            holder_proof,
            context: None,
            idempotency_key: Some(delivery_id),
            lease_seq: None,
            deadline_ms: Some(self.timeout_ms),
            correlation_id: Some(CorrelationId::new()),
            provenance: Some(provenance),
            approval_tokens: Vec::new(),
        })
    }
}

/// Admission failures with fixed public status and reason codes.
///
/// Detailed static messages are operator diagnostics only; the public response
/// never reflects input, provider errors, configured URLs or capability material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum WebhookIngressError {
    /// An operator setting failed validation.
    #[error("invalid webhook ingress configuration: {0}")]
    InvalidConfiguration(&'static str),
    /// The body or other request metadata is malformed.
    #[error("invalid webhook ingress input: {0}")]
    InvalidInput(&'static str),
    /// The path is outside the intake prefix or has ambiguous encoding.
    #[error("invalid webhook ingress path")]
    InvalidPath,
    /// The raw path and query exceed the fixed host limit.
    #[error("webhook ingress request target is too long")]
    UriTooLong,
    /// Duplicated or non-text headers could change signature interpretation.
    #[error("invalid webhook ingress headers")]
    InvalidHeaders,
    /// Too many headers or excessive aggregate header bytes.
    #[error("webhook ingress headers exceed host limits")]
    HeadersTooLarge,
    /// The actual HTTP body exceeds its configured limit.
    #[error("webhook ingress payload exceeds host limits")]
    PayloadTooLarge,
    /// The host has no configured, usable intake authority.
    #[error("webhook ingress is unavailable")]
    Unavailable,
    /// A receiver response cannot be bound to the request or its admission contract.
    #[error("invalid webhook receiver response")]
    InvalidResponse,
    /// The complete request budget elapsed.
    #[error("webhook ingress request timed out")]
    Timeout,
    /// All configured concurrent delivery slots are occupied.
    #[error("webhook ingress is at capacity")]
    TooManyRequests,
    /// Public webhook intake accepts only POST deliveries.
    #[error("webhook ingress requires POST")]
    MethodNotAllowed,
}

impl WebhookIngressError {
    /// Return a minimal, redaction-safe HTTP admission response.
    #[must_use]
    pub fn response(&self) -> (StatusCode, Value) {
        let (status, reason) = match self {
            Self::InvalidConfiguration(_) | Self::Unavailable => {
                (StatusCode::SERVICE_UNAVAILABLE, "ingress_unavailable")
            }
            Self::InvalidInput(_) => (StatusCode::BAD_REQUEST, "invalid_request"),
            Self::InvalidPath => (StatusCode::BAD_REQUEST, "invalid_path"),
            Self::UriTooLong => (StatusCode::URI_TOO_LONG, "uri_too_long"),
            Self::InvalidHeaders => (StatusCode::BAD_REQUEST, "invalid_headers"),
            Self::HeadersTooLarge => (
                StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                "headers_too_large",
            ),
            Self::PayloadTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large"),
            Self::InvalidResponse => (StatusCode::BAD_GATEWAY, "invalid_receiver_response"),
            Self::Timeout => (StatusCode::GATEWAY_TIMEOUT, "ingress_timeout"),
            Self::TooManyRequests => (StatusCode::TOO_MANY_REQUESTS, "ingress_at_capacity"),
            Self::MethodNotAllowed => (StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed"),
        };
        public_response(status, false, reason)
    }
}

/// Convert a canonical receiver invocation outcome into a minimal HTTP reply.
///
/// Only the receiver's positive admission contract earns a successful response.
/// Known receiver error statuses are mapped without reflecting their messages.
/// Only an explicit authenticated duplicate outcome earns an idempotent 200.
/// A receiver conflict remains 409; an unsigned ID match does not prove success.
/// FCP authority/lifecycle failures describe unusable host provisioning and are
/// 503; malformed outcomes and unrelated external failures are 502.
/// A successfully authenticated Slack URL-verification result may return only
/// its bounded challenge as HTTP 200 JSON. No other provider data is reflected.
#[must_use]
pub fn response_for(response: &InvokeResponse) -> (StatusCode, Value) {
    if response.r#type != "response" {
        return WebhookIngressError::InvalidResponse.response();
    }
    match response.status {
        InvokeStatus::Ok if response.error.is_none() => response
            .result
            .as_ref()
            .and_then(admitted_response)
            .unwrap_or_else(|| WebhookIngressError::InvalidResponse.response()),
        InvokeStatus::Error if response.result.is_none() => {
            let Some(error) = &response.error else {
                return WebhookIngressError::InvalidResponse.response();
            };
            let (status, reason) = match error {
                FcpError::External {
                    service,
                    status_code: Some(status),
                    ..
                } if service == "webhook-receiver" => match *status {
                    400 => (StatusCode::BAD_REQUEST, "invalid_request"),
                    401 => (StatusCode::UNAUTHORIZED, "signature_invalid"),
                    403 => (StatusCode::FORBIDDEN, "source_forbidden"),
                    404 => (StatusCode::NOT_FOUND, "endpoint_not_found"),
                    405 => (StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed"),
                    408 => (StatusCode::REQUEST_TIMEOUT, "request_timeout"),
                    409 => (StatusCode::CONFLICT, "duplicate_delivery"),
                    413 => (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large"),
                    415 => (StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type"),
                    429 => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
                    507 => (
                        StatusCode::INSUFFICIENT_STORAGE,
                        "replay_capacity_exhausted",
                    ),
                    _ => (StatusCode::BAD_GATEWAY, "receiver_error"),
                },
                FcpError::UpstreamTimeout { .. } => {
                    (StatusCode::GATEWAY_TIMEOUT, "ingress_timeout")
                }
                FcpError::External { .. } | FcpError::Internal { .. } => {
                    (StatusCode::BAD_GATEWAY, "receiver_error")
                }
                _ => (StatusCode::SERVICE_UNAVAILABLE, "ingress_unavailable"),
            };
            public_response(status, false, reason)
        }
        _ => WebhookIngressError::InvalidResponse.response(),
    }
}

fn admitted_response(result: &Value) -> Option<(StatusCode, Value)> {
    if result.get("accepted").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    match result.get("status_code").and_then(Value::as_u64)? {
        202 if result.get("verification").is_none() && result.get("duplicate").is_none() => {
            Some(public_response(StatusCode::ACCEPTED, true, "accepted"))
        }
        200 if result.get("duplicate").is_some() => {
            if result.get("duplicate").and_then(Value::as_bool) != Some(true)
                || result.as_object()?.len() != 3
            {
                return None;
            }
            Some(public_response(StatusCode::OK, true, "already_accepted"))
        }
        200 => {
            let verification = result.get("verification")?.as_object()?;
            if verification.len() != 3
                || verification.get("provider")?.as_str()? != "slack"
                || verification.get("kind")?.as_str()? != "url_verification"
            {
                return None;
            }
            let challenge = verification.get("challenge")?.as_str()?;
            if challenge.is_empty()
                || challenge.len() > MAX_SLACK_CHALLENGE_BYTES
                || challenge.chars().any(char::is_control)
            {
                return None;
            }
            Some((StatusCode::OK, json!({ "challenge": challenge })))
        }
        _ => None,
    }
}

fn public_response(
    status: StatusCode,
    accepted: bool,
    reason: &'static str,
) -> (StatusCode, Value) {
    (
        status,
        json!({
            "accepted": accepted,
            "status_code": status.as_u16(),
            "reason_code": reason,
        }),
    )
}

fn is_receiver_id(id: &str) -> bool {
    if id == RECEIVER_ID {
        return true;
    }
    id.strip_prefix("fcp.webhook-receiver:webhook:")
        .is_some_and(|version| semver::Version::parse(version).is_ok())
}

fn validate_public_base_url(base: &str) -> Result<(), WebhookIngressError> {
    let invalid = || {
        WebhookIngressError::InvalidConfiguration(
            "public_base_url must be an unambiguous origin followed by /webhooks",
        )
    };
    if base.len() > MAX_PUBLIC_BASE_URL_BYTES
        || !base.is_ascii()
        || base
            .bytes()
            .any(|byte| byte <= b' ' || byte == 0x7f || byte == b'\\')
    {
        return Err(invalid());
    }
    let url = Url::parse(base).map_err(|_| invalid())?;
    let uri = base.parse::<Uri>().map_err(|_| invalid())?;
    let authority = uri.authority().ok_or_else(invalid)?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || authority.as_str().contains(['@', '%'])
        || uri.path() != WEBHOOK_PREFIX
        || url.path() != WEBHOOK_PREFIX
        || uri.query().is_some()
        || !base.starts_with(&format!("{}://", url.scheme()))
    {
        return Err(invalid());
    }
    if url.scheme() == "http" {
        let host = authority.host();
        let host = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host);
        if !host.eq_ignore_ascii_case("localhost")
            && !host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
        {
            return Err(WebhookIngressError::InvalidConfiguration(
                "public_base_url requires HTTPS outside localhost or literal loopback",
            ));
        }
    }
    Ok(())
}

fn validate_headers(headers: &HeaderMap) -> Result<(), WebhookIngressError> {
    if headers.len() > MAX_WEBHOOK_INGRESS_HEADERS {
        return Err(WebhookIngressError::HeadersTooLarge);
    }
    let mut bytes = 0_usize;
    for name in headers.keys() {
        if headers.get_all(name).iter().count() != 1 {
            return Err(WebhookIngressError::InvalidHeaders);
        }
    }
    for (name, value) in headers {
        bytes = bytes
            .saturating_add(name.as_str().len())
            .saturating_add(value.as_bytes().len());
        if bytes > MAX_WEBHOOK_INGRESS_HEADER_BYTES {
            return Err(WebhookIngressError::HeadersTooLarge);
        }
        value
            .to_str()
            .map_err(|_| WebhookIngressError::InvalidHeaders)?;
    }
    Ok(())
}

fn endpoint_path(uri: &Uri) -> Result<&str, WebhookIngressError> {
    if uri.scheme().is_some() || uri.authority().is_some() {
        return Err(WebhookIngressError::InvalidPath);
    }
    let target = uri
        .path_and_query()
        .ok_or(WebhookIngressError::InvalidPath)?;
    if target.as_str().len() > MAX_WEBHOOK_INGRESS_TARGET_BYTES {
        return Err(WebhookIngressError::UriTooLong);
    }
    if target
        .as_str()
        .bytes()
        .any(|byte| byte <= b' ' || matches!(byte, 0x7f | b'\\' | b'#'))
    {
        return Err(WebhookIngressError::InvalidPath);
    }
    let path = uri
        .path()
        .strip_prefix(WEBHOOK_PREFIX)
        .filter(|path| path.starts_with('/') && path.len() > 1)
        .ok_or(WebhookIngressError::InvalidPath)?;
    for segment in path[1..].split('/') {
        if segment.is_empty() {
            return Err(WebhookIngressError::InvalidPath);
        }
        let mut length = 0_usize;
        let mut only_dots = true;
        let mut bytes = segment.bytes();
        while let Some(byte) = bytes.next() {
            let decoded = if byte == b'%' {
                decode_escape(&mut bytes)?
            } else {
                byte
            };
            // Reject nested escapes and decoded delimiters as well as literal
            // dot segments. The endpoint itself always receives the raw path.
            if decoded <= b' ' || matches!(decoded, 0x7f | b'/' | b'\\' | b'?' | b'#' | b'%') {
                return Err(WebhookIngressError::InvalidPath);
            }
            length += 1;
            only_dots &= decoded == b'.';
        }
        if only_dots && length <= 2 {
            return Err(WebhookIngressError::InvalidPath);
        }
    }
    if let Some(query) = uri.query() {
        let mut bytes = query.bytes();
        while let Some(byte) = bytes.next() {
            if byte == b'%' {
                decode_escape(&mut bytes)?;
            }
        }
    }
    Ok(path)
}

fn decode_escape(bytes: &mut std::str::Bytes<'_>) -> Result<u8, WebhookIngressError> {
    let high = bytes
        .next()
        .and_then(|byte| char::from(byte).to_digit(16))
        .ok_or(WebhookIngressError::InvalidPath)?;
    let low = bytes
        .next()
        .and_then(|byte| char::from(byte).to_digit(16))
        .ok_or(WebhookIngressError::InvalidPath)?;
    u8::try_from(high * 16 + low).map_err(|_| WebhookIngressError::InvalidPath)
}

fn is_authority_header(name: &str) -> bool {
    matches!(
        name,
        "forwarded" | "x-real-ip" | "x-principal" | "x-principal-id" | "x-zone-id"
    ) || name.starts_with("x-forwarded-")
        || name.starts_with("x-fcp-")
        || name.starts_with("fcp-")
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderName, HeaderValue};
    use fcp_crypto::{
        cose::{CoseToken, CwtClaims},
        ed25519::Ed25519SigningKey,
    };
    use fcp_prelude::{
        CapabilityId, DecisionReasonCode, DecisionReceiptPolicy, ObjectHeader, PolicyPattern,
        PolicySimulationInput, SafetyTier, TaintLevel, TransportMode, ZonePolicyObject,
        ZoneTransportPolicy, simulate_policy_decision,
    };

    use super::*;

    fn config(base: &str) -> Result<WebhookIngressConfig, WebhookIngressError> {
        WebhookIngressConfig::new(
            ConnectorId::from_static(RECEIVER_ID),
            ZoneId::work(),
            CapabilityToken::test_token(),
            base.to_string(),
            DEFAULT_WEBHOOK_INGRESS_MAX_BODY_BYTES,
            DEFAULT_WEBHOOK_INGRESS_TIMEOUT_MS,
            DEFAULT_WEBHOOK_INGRESS_MAX_IN_FLIGHT,
        )
    }

    fn request(
        config: &WebhookIngressConfig,
        target: &str,
    ) -> Result<InvokeRequest, WebhookIngressError> {
        let uri = target
            .parse()
            .map_err(|_| WebhookIngressError::InvalidPath)?;
        config.build_request(&HeaderMap::new(), &uri, "{}", None)
    }

    fn receiver_error(status_code: u16) -> InvokeResponse {
        InvokeResponse::error(
            RequestId::random(),
            FcpError::External {
                service: "webhook-receiver".into(),
                message: "secret-signing-key and private payload must not escape".into(),
                status_code: Some(status_code),
                retryable: false,
                retry_after: None,
            },
        )
    }

    fn policy_token(capability: &str, operation: &str) -> CapabilityToken {
        let now = chrono::Utc::now();
        let signing_key = Ed25519SigningKey::from_bytes(&[53; 32]).unwrap();
        // Policy simulation consumes CWT sub, while native admission consumes
        // the typed FCP principal claim. Include both with the same identity.
        let claims = CwtClaims::new()
            .capability_id(capability)
            .zone_id("z:work")
            .principal_id("user:webhook-ingress")
            .subject("user:webhook-ingress")
            .operations(&[operation])
            .issuer("node:webhook-ingress")
            .not_before(now)
            .expiration(now + chrono::Duration::hours(1));
        CapabilityToken::from_raw(CoseToken::sign(&signing_key, &claims).unwrap())
    }

    fn holder_token(holder: Option<&str>, jti: Option<&[u8]>) -> CapabilityToken {
        let mut claims = CwtClaims::new()
            .capability_id("webhook.events.write")
            .zone_id("z:work")
            .operations(&[WEBHOOK_INGRESS_OPERATION]);
        if let Some(holder) = holder {
            claims = claims.holder_node(holder);
        }
        if let Some(jti) = jti {
            claims = claims.token_id(jti);
        }
        let issuer = Ed25519SigningKey::from_bytes(&[58; 32]).unwrap();
        CapabilityToken::from_raw(CoseToken::sign(&issuer, &claims).unwrap())
    }

    #[test]
    fn holder_proofs_bind_each_fresh_delivery_operation_and_current_token() {
        let holder_key = Ed25519SigningKey::from_bytes(&[59; 32]).unwrap();
        let verifier = holder_key.verifying_key();
        let config = config("https://hooks.example.test/webhooks")
            .unwrap()
            .with_execution_authority(
                holder_token(Some("node:ingress"), Some(b"ingress-token-one")),
                Some(holder_key),
            )
            .unwrap();
        let headers = HeaderMap::from_iter([
            (
                HeaderName::from_static("x-fcp-holder-proof"),
                HeaderValue::from_static("public-forged-proof"),
            ),
            (
                HeaderName::from_static("x-fcp-lease-seq"),
                HeaderValue::from_static("999999"),
            ),
        ]);
        let uri = "/webhooks/github".parse().unwrap();
        let body = r#"{"holder_node":"node:attacker","lease_seq":999999}"#;
        let first = config.build_request(&headers, &uri, body, None).unwrap();
        let second = config.build_request(&headers, &uri, body, None).unwrap();
        let proof = first.holder_proof.as_ref().unwrap();
        assert_eq!(proof.holder_node.as_str(), "node:ingress");
        assert_eq!(first.input["body"], body);
        assert!(first.input["headers"].get("x-fcp-holder-proof").is_none());
        assert!(first.input["headers"].get("x-fcp-lease-seq").is_none());
        assert!(first.lease_seq.is_none());
        let signature = fcp_crypto::Ed25519Signature::from_bytes(&proof.signature);
        let signable =
            HolderProof::signable_bytes(&first.id, &first.operation, b"ingress-token-one");
        verifier.verify(&signable, &signature).unwrap();
        let wrong_key = Ed25519SigningKey::from_bytes(&[60; 32]).unwrap();
        assert!(
            wrong_key
                .verifying_key()
                .verify(&signable, &signature)
                .is_err()
        );
        for changed in [
            HolderProof::signable_bytes(&second.id, &first.operation, b"ingress-token-one"),
            HolderProof::signable_bytes(
                &first.id,
                &OperationId::from_static("webhook.endpoints.create"),
                b"ingress-token-one",
            ),
            HolderProof::signable_bytes(&first.id, &first.operation, b"ingress-token-two"),
        ] {
            assert!(verifier.verify(&changed, &signature).is_err());
        }
        assert_ne!(proof.signature, second.holder_proof.unwrap().signature);
    }

    #[test]
    fn holder_authority_requires_an_explicit_key_holder_and_nonempty_jti() {
        let config = config("https://hooks.example.test/webhooks").unwrap();
        let key = Ed25519SigningKey::from_bytes(&[59; 32]).unwrap();
        for (token, key) in [
            (holder_token(Some("node:ingress"), Some(b"jti")), None),
            (holder_token(None, Some(b"jti")), Some(key.clone())),
            (holder_token(Some(""), Some(b"jti")), Some(key.clone())),
            (holder_token(Some("node:ingress"), None), Some(key.clone())),
            (
                holder_token(Some("node:ingress"), Some(b"")),
                Some(key.clone()),
            ),
        ] {
            assert!(matches!(
                config.clone().with_execution_authority(token, key),
                Err(WebhookIngressError::Unavailable)
            ));
        }
        let oversized_holder = "n".repeat(129);
        for holder in [
            "Node:ingress",
            "node holder",
            "node\ncontrol",
            "node:é",
            oversized_holder.as_str(),
        ] {
            assert!(matches!(
                config.clone().with_execution_authority(
                    holder_token(Some(holder), Some(b"jti")),
                    Some(key.clone()),
                ),
                Err(WebhookIngressError::Unavailable)
            ));
        }
        let malformed_claims = CwtClaims::new().token_id(b"malformed-holder-jti").custom(
            fcp_crypto::cose::fcp2_claims::HOLDER_NODE,
            ciborium::Value::Integer(7.into()),
        );
        let issuer = Ed25519SigningKey::from_bytes(&[58; 32]).unwrap();
        let malformed =
            CapabilityToken::from_raw(CoseToken::sign(&issuer, &malformed_claims).unwrap());
        for signer in [None, Some(key)] {
            assert!(matches!(
                config
                    .clone()
                    .with_execution_authority(malformed.clone(), signer),
                Err(WebhookIngressError::Unavailable)
            ));
        }
        assert!(matches!(
            request(
                &config.clone().with_capability_token(malformed),
                "/webhooks/github",
            ),
            Err(WebhookIngressError::Unavailable)
        ));
        let without_key = config
            .clone()
            .with_capability_token(holder_token(Some("node:ingress"), Some(b"jti")));
        assert!(matches!(
            request(&without_key, "/webhooks/github"),
            Err(WebhookIngressError::Unavailable)
        ));
        let bearer = config
            .with_execution_authority(holder_token(None, Some(b"jti")), None)
            .unwrap();
        assert!(
            request(&bearer, "/webhooks/github")
                .unwrap()
                .holder_proof
                .is_none()
        );
    }

    #[test]
    fn holder_context_is_cleared_on_capability_replacement_and_rebound_on_rotation() {
        let first_key = Ed25519SigningKey::from_bytes(&[59; 32]).unwrap();
        let next_key = Ed25519SigningKey::from_bytes(&[60; 32]).unwrap();
        let original = config("https://hooks.example.test/webhooks")
            .unwrap()
            .with_execution_authority(
                holder_token(Some("node:ingress"), Some(b"first-jti")),
                Some(first_key.clone()),
            )
            .unwrap();
        let next_token = holder_token(Some("node:successor"), Some(b"next-jti"));
        let without_replacement_key = original.clone().with_capability_token(next_token.clone());
        assert!(matches!(
            request(&without_replacement_key, "/webhooks/github"),
            Err(WebhookIngressError::Unavailable)
        ));
        let rotated = original
            .clone()
            .with_execution_authority(next_token, Some(next_key.clone()))
            .unwrap();
        let invocation = request(&rotated, "/webhooks/github").unwrap();
        let proof = invocation.holder_proof.unwrap();
        assert_eq!(proof.holder_node.as_str(), "node:successor");
        let signature = fcp_crypto::Ed25519Signature::from_bytes(&proof.signature);
        let bytes = HolderProof::signable_bytes(&invocation.id, &invocation.operation, b"next-jti");
        next_key.verifying_key().verify(&bytes, &signature).unwrap();
        assert!(
            first_key
                .verifying_key()
                .verify(&bytes, &signature)
                .is_err()
        );
        let bearer = original.with_capability_token(holder_token(None, Some(b"bearer-jti")));
        assert!(
            request(&bearer, "/webhooks/github")
                .unwrap()
                .holder_proof
                .is_none()
        );
    }

    #[test]
    fn holder_authority_debug_redacts_key_and_token_context() {
        let key = Ed25519SigningKey::from_bytes(&[59; 32]).unwrap();
        let config = config("https://hooks.example.test/webhooks")
            .unwrap()
            .with_execution_authority(
                holder_token(
                    Some("node:private-ingress-holder"),
                    Some(b"private-token-jti"),
                ),
                Some(key.clone()),
            )
            .unwrap();
        let debug = format!("{config:?}");
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("private-ingress-holder"));
        assert!(!debug.contains("private-token-jti"));
        assert!(!debug.contains(&hex::encode(key.to_bytes())));
    }

    fn policy_input(request: InvokeRequest, capability: &str) -> PolicySimulationInput {
        let zone = request.zone_id.clone();
        PolicySimulationInput {
            zone_policy: ZonePolicyObject {
                header: ObjectHeader {
                    encryption_kind: Default::default(),
                    schema: fcp_cbor::SchemaId::new(
                        "fcp.core",
                        "ZonePolicyObject",
                        semver::Version::new(1, 0, 0),
                    ),
                    zone_id: zone.clone(),
                    created_at: 1_000,
                    provenance: Provenance::new(zone.clone()),
                    refs: Vec::new(),
                    foreign_refs: Vec::new(),
                    ttl_secs: None,
                    placement: None,
                },
                zone_id: zone,
                principal_allow: vec![PolicyPattern {
                    pattern: "user:webhook-ingress".to_string(),
                }],
                principal_deny: Vec::new(),
                connector_allow: vec![PolicyPattern {
                    pattern: RECEIVER_ID.to_string(),
                }],
                connector_deny: Vec::new(),
                capability_allow: vec![PolicyPattern {
                    pattern: capability.to_string(),
                }],
                capability_deny: Vec::new(),
                capability_ceiling: vec![CapabilityId::new(capability).unwrap()],
                transport_policy: ZoneTransportPolicy {
                    allow_lan: true,
                    allow_derp: false,
                    allow_funnel: false,
                },
                decision_receipts: DecisionReceiptPolicy::default(),
                usage_budget: None,
                requires_posture: None,
            },
            invoke_request: request,
            transport: TransportMode::Lan,
            checkpoint_fresh: true,
            revocation_fresh: true,
            execution_approval_required: false,
            sanitizer_receipts: Vec::new(),
            related_object_ids: Vec::new(),
            request_object_id: None,
            request_input_hash: None,
            safety_tier: SafetyTier::Risky,
            principal: None,
            capability_id: None,
            provenance_record: None,
            now_ms: None,
            posture_attestation: None,
        }
    }

    #[test]
    fn configuration_accepts_public_https_and_literal_loopback_http() {
        for base in [
            "https://hooks.example.test/webhooks",
            "https://hooks.example.test:443/webhooks",
            "https://hooks.example.test:8443/webhooks",
            "http://localhost:8080/webhooks",
            "http://127.0.0.1:8080/webhooks",
            "http://127.1.2.3/webhooks",
            "http://[::1]:8080/webhooks",
        ] {
            let config = config(base).unwrap();
            assert_eq!(config.public_base_url(), base);
            assert_eq!(
                config.max_body_bytes(),
                DEFAULT_WEBHOOK_INGRESS_MAX_BODY_BYTES
            );
            assert_eq!(config.timeout_ms(), DEFAULT_WEBHOOK_INGRESS_TIMEOUT_MS);
            assert_eq!(
                config.max_in_flight(),
                DEFAULT_WEBHOOK_INGRESS_MAX_IN_FLIGHT
            );
        }
    }

    #[test]
    fn configuration_rejects_ambiguous_or_insecure_public_urls() {
        for base in [
            "https://hooks.example.test",
            "https://hooks.example.test/webhooks/",
            "https://hooks.example.test/a/../webhooks",
            "https://hooks.example.test/%77ebhooks",
            "https://hooks.example.test/webhooks?",
            "https://hooks.example.test/webhooks?token=secret",
            "https://hooks.example.test/webhooks#fragment",
            "https://@hooks.example.test/webhooks",
            "https://user:secret@hooks.example.test/webhooks",
            "https://hooks.example.test\\webhooks",
            " https://hooks.example.test/webhooks",
            "https://hooks.example.test/webhooks\n",
            "HTTPS://hooks.example.test/webhooks",
            "http://hooks.example.test/webhooks",
            "http://localhost.example.test/webhooks",
            "http://0.0.0.0/webhooks",
            "http://[::]/webhooks",
            "http://127.1/webhooks",
            "http://2130706433/webhooks",
            "http://0x7f000001/webhooks",
            "file:///webhooks",
        ] {
            assert!(config(base).is_err(), "accepted {base:?}");
        }
        let oversized = format!(
            "https://{}.test/webhooks",
            "x".repeat(MAX_PUBLIC_BASE_URL_BYTES)
        );
        assert!(config(&oversized).is_err());
    }

    #[test]
    fn configuration_binds_receiver_family_and_explicit_zone() {
        for id in [RECEIVER_ID, "fcp.webhook-receiver:webhook:1.0.0"] {
            let config = WebhookIngressConfig::new(
                id.parse().unwrap(),
                ZoneId::public(),
                CapabilityToken::test_token(),
                "https://hooks.example.test/webhooks".into(),
                MAX_WEBHOOK_INGRESS_BODY_BYTES,
                MAX_WEBHOOK_INGRESS_TIMEOUT_MS,
                MAX_WEBHOOK_INGRESS_RETAINED_BODY_BYTES / MAX_WEBHOOK_INGRESS_BODY_BYTES,
            )
            .unwrap();
            assert_eq!(config.connector_id().as_str(), id);
            assert_eq!(config.zone_id(), &ZoneId::public());
        }
        for id in [
            "fcp.slack",
            "fcp.webhook-receiver-evil",
            "fcp.webhook-receiver:webhook:unknown",
        ] {
            assert!(
                WebhookIngressConfig::new(
                    id.parse().unwrap(),
                    ZoneId::work(),
                    CapabilityToken::test_token(),
                    "https://hooks.example.test/webhooks".into(),
                    1,
                    1,
                    1,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn configuration_never_clamps_invalid_limits() {
        for (body, timeout, in_flight) in [
            (0, 1, 1),
            (MAX_WEBHOOK_INGRESS_BODY_BYTES + 1, 1, 1),
            (1, 0, 1),
            (1, MAX_WEBHOOK_INGRESS_TIMEOUT_MS + 1, 1),
            (1, 1, 0),
            (1, 1, MAX_WEBHOOK_INGRESS_IN_FLIGHT + 1),
        ] {
            assert!(
                WebhookIngressConfig::new(
                    ConnectorId::from_static(RECEIVER_ID),
                    ZoneId::work(),
                    CapabilityToken::test_token(),
                    "https://hooks.example.test/webhooks".into(),
                    body,
                    timeout,
                    in_flight,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn unprovisioned_binding_requires_current_authority_before_building() {
        let binding = WebhookIngressConfig::without_capability_token(
            ConnectorId::from_static(RECEIVER_ID),
            ZoneId::work(),
            "https://hooks.example.test/webhooks".into(),
            DEFAULT_WEBHOOK_INGRESS_MAX_BODY_BYTES,
            DEFAULT_WEBHOOK_INGRESS_TIMEOUT_MS,
            DEFAULT_WEBHOOK_INGRESS_MAX_IN_FLIGHT,
        )
        .unwrap();
        let headers = HeaderMap::new();
        let uri = "/webhooks/test".parse().unwrap();
        assert!(binding.validate_request_head(&headers, &uri).is_ok());
        assert!(matches!(
            binding.build_request(&headers, &uri, "{}", None),
            Err(WebhookIngressError::Unavailable)
        ));

        let token = CapabilityToken::test_token();
        let configured = binding.clone().with_capability_token(token.clone());
        let request = configured
            .build_request(&headers, &uri, "{}", None)
            .unwrap();
        assert_eq!(
            request.capability_token.raw().to_cbor().unwrap(),
            token.raw().to_cbor().unwrap()
        );
        assert_eq!(configured.connector_id(), binding.connector_id());
        assert_eq!(configured.zone_id(), binding.zone_id());
        assert_eq!(configured.public_base_url(), binding.public_base_url());
        assert_eq!(configured.max_body_bytes(), binding.max_body_bytes());
        assert_eq!(configured.timeout_ms(), binding.timeout_ms());
        assert_eq!(configured.max_in_flight(), binding.max_in_flight());
        // The template remains inactive: one request's authority is never a
        // fallback credential for a later failed token-file refresh.
        assert!(matches!(
            binding.build_request(&headers, &uri, "{}", None),
            Err(WebhookIngressError::Unavailable)
        ));
    }

    #[test]
    fn inactive_bindings_do_not_bypass_configuration_validation() {
        assert!(
            WebhookIngressConfig::without_capability_token(
                ConnectorId::from_static(RECEIVER_ID),
                ZoneId::work(),
                "http://public.example.test/webhooks".into(),
                DEFAULT_WEBHOOK_INGRESS_MAX_BODY_BYTES,
                DEFAULT_WEBHOOK_INGRESS_TIMEOUT_MS,
                DEFAULT_WEBHOOK_INGRESS_MAX_IN_FLIGHT,
            )
            .is_err()
        );
    }

    #[test]
    fn configuration_bounds_the_product_of_body_and_concurrency_limits() {
        for (body, in_flight, accepted) in [
            (MAX_WEBHOOK_INGRESS_BODY_BYTES, 4, true),
            (MAX_WEBHOOK_INGRESS_BODY_BYTES, 5, false),
            (1024 * 1024, MAX_WEBHOOK_INGRESS_IN_FLIGHT, true),
            (1024 * 1024 + 1, MAX_WEBHOOK_INGRESS_IN_FLIGHT, false),
        ] {
            let result = WebhookIngressConfig::new(
                ConnectorId::from_static(RECEIVER_ID),
                ZoneId::work(),
                CapabilityToken::test_token(),
                "https://hooks.example.test/webhooks".into(),
                body,
                DEFAULT_WEBHOOK_INGRESS_TIMEOUT_MS,
                in_flight,
            );
            assert_eq!(
                result.is_ok(),
                accepted,
                "body={body}, in_flight={in_flight}"
            );
        }
    }

    #[test]
    fn builder_preserves_raw_json_and_form_bodies_and_signed_url() {
        let config = config("https://hooks.example.test:443/webhooks").unwrap();
        for body in [
            "{ \"text\" : \"雪\", \"n\": 1e0 }\n",
            "Body=hello+world&Tag=a&Tag=b%2B",
        ] {
            let request = config
                .build_request(
                    &HeaderMap::new(),
                    &"/webhooks/twilio%2Bhook?bodySHA256=abc&x=a%2fb+x&x=two"
                        .parse()
                        .unwrap(),
                    body,
                    None,
                )
                .unwrap();
            assert_eq!(
                request.input["body"].as_str().unwrap().as_bytes(),
                body.as_bytes()
            );
            assert_eq!(request.input["body_size_bytes"], body.len());
            assert_eq!(request.input["path"], "/twilio%2Bhook");
            assert_eq!(
                request.input["url"],
                "https://hooks.example.test:443/webhooks/twilio%2Bhook?bodySHA256=abc&x=a%2fb+x&x=two"
            );
            assert!(request.input.get("payload").is_none());
            assert!(request.input.get("params").is_none());
        }
    }

    #[test]
    fn builder_ignores_public_authority_and_uses_connection_identity() {
        let config = config("https://hooks.example.test/webhooks").unwrap();
        let headers: HeaderMap = [
            ("host", "attacker.test"),
            ("forwarded", "for=192.0.2.99;proto=http;host=evil.test"),
            ("x-forwarded-for", "192.0.2.99"),
            ("x-forwarded-proto", "http"),
            ("x-real-ip", "192.0.2.99"),
            ("x-principal", "owner"),
            ("x-zone-id", "z:owner"),
            ("x-fcp-capability-token", "forged"),
            ("x-github-delivery", "public-chosen-id"),
            ("idempotency-key", "public-chosen-cache-key"),
            ("authorization", "provider-signature-not-fcp-authority"),
            ("x-hub-signature-256", "sha256=signature"),
            ("content-type", "application/json"),
        ]
        .into_iter()
        .map(|(name, value)| {
            (
                HeaderName::from_static(name),
                HeaderValue::from_static(value),
            )
        })
        .collect();
        let peer_ip = "192.0.2.10".parse::<IpAddr>().unwrap();
        let uri = "/webhooks/github".parse().unwrap();
        let first = config
            .build_request(&headers, &uri, "{}", Some(peer_ip))
            .unwrap();
        let second = config
            .build_request(&headers, &uri, "{}", Some(peer_ip))
            .unwrap();
        assert_eq!(first.connector_id, config.connector_id);
        assert_eq!(first.zone_id, ZoneId::work());
        assert_eq!(first.operation.as_str(), WEBHOOK_INGRESS_OPERATION);
        assert_eq!(first.input["source_ip"], "192.0.2.10");
        assert_eq!(first.input["client_id"], "192.0.2.10");
        assert_eq!(
            first.input["url"],
            "https://hooks.example.test/webhooks/github"
        );
        assert_eq!(
            first.input["headers"]["authorization"],
            "provider-signature-not-fcp-authority"
        );
        assert_eq!(
            first.input["headers"]["x-github-delivery"],
            "public-chosen-id"
        );
        for name in [
            "forwarded",
            "x-forwarded-for",
            "x-forwarded-proto",
            "x-real-ip",
            "x-principal",
            "x-zone-id",
            "x-fcp-capability-token",
        ] {
            assert!(first.input["headers"].get(name).is_none());
        }
        assert_ne!(first.id, second.id);
        assert_ne!(first.idempotency_key, second.idempotency_key);
        assert_ne!(first.input["delivery_id"], second.input["delivery_id"]);
        for attempt in [&first, &second] {
            let delivery = attempt.input["delivery_id"].as_str().unwrap();
            let nonce = delivery.strip_prefix("webhook-http-").unwrap();
            assert_eq!(hex::decode(nonce).unwrap().len(), 24);
            assert_eq!(attempt.id.0, delivery);
            assert_eq!(attempt.idempotency_key.as_deref(), Some(delivery));
        }
        assert_ne!(first.input["delivery_id"], "public-chosen-id");
        assert_ne!(
            first.idempotency_key.as_deref(),
            Some("public-chosen-cache-key")
        );
        assert!(first.holder_proof.is_none());
        assert!(first.context.is_none());
        assert!(first.approval_tokens.is_empty());
        let provenance = first.provenance.unwrap();
        assert_eq!(provenance.origin_zone, config.zone_id);
        assert_eq!(provenance.taint, TaintLevel::Tainted);
        assert!(!provenance.elevated);
        assert!(provenance.elevation_token.is_none());
        assert_eq!(provenance.chain.len(), 2);
        assert_eq!(provenance.chain[0].zone, ZoneId::public());
        assert_eq!(provenance.chain[0].action, "webhook.payload.received");
        assert_eq!(
            provenance.chain[0].resource,
            format!("urn:blake3:{}", blake3::hash(b"{}").to_hex())
        );
        assert_eq!(provenance.chain[1].zone, config.zone_id);
        assert_eq!(provenance.chain[1].actor, "fcp-host.webhook-ingress");
        assert_eq!(provenance.chain[1].action, WEBHOOK_INGRESS_OPERATION);
        assert_eq!(provenance.chain[1].resource, RECEIVER_ID);
        assert_eq!(
            provenance.chain[0].timestamp_ms,
            provenance.chain[1].timestamp_ms
        );
    }

    #[test]
    fn fixed_intake_command_with_public_data_obeys_explicit_zone_policy() {
        let config = config("https://hooks.example.test/webhooks")
            .unwrap()
            .with_capability_token(policy_token(
                "webhook.events.write",
                WEBHOOK_INGRESS_OPERATION,
            ));
        let body = r#"{"connector_id":"fcp.evil","operation":"webhook.endpoints.delete","zone_id":"z:owner","provenance":{"origin_zone":"z:owner","taint":"untainted","elevated":true}}"#;
        let mut headers = HeaderMap::new();
        headers.insert("x-principal", HeaderValue::from_static("owner"));
        headers.insert("x-fcp-zone-id", HeaderValue::from_static("z:owner"));
        let request = config
            .build_request(&headers, &"/webhooks/github".parse().unwrap(), body, None)
            .unwrap();
        assert_eq!(request.connector_id.as_str(), RECEIVER_ID);
        assert_eq!(request.operation.as_str(), WEBHOOK_INGRESS_OPERATION);
        assert_eq!(request.zone_id, ZoneId::work());
        assert_eq!(request.input["body"], body);
        let provenance = request.provenance.as_ref().unwrap();
        assert_eq!(provenance.origin_zone, ZoneId::work());
        assert_eq!(provenance.taint, TaintLevel::Tainted);
        assert!(!provenance.elevated);
        assert!(provenance.elevation_token.is_none());
        assert_eq!(provenance.chain[0].zone, ZoneId::public());
        assert_eq!(
            provenance.chain[0].resource,
            format!("urn:blake3:{}", blake3::hash(body.as_bytes()).to_hex())
        );

        // The real policy engine derives principal/capability from the signed
        // fixture and provenance from the built request, without overrides.
        // Cryptographic authorization is exercised by the host/receiver tests.
        let mut input = policy_input(request, "webhook.events.write");
        let allowed = simulate_policy_decision(&input).unwrap();
        assert!(allowed.is_allow(), "{allowed:?}");
        assert_eq!(allowed.reason_code, DecisionReasonCode::Allow.as_str());

        input.invoke_request.connector_id = ConnectorId::from_static("fcp.evil");
        let denied = simulate_policy_decision(&input).unwrap();
        assert!(denied.is_deny());
        assert_eq!(
            denied.reason_code,
            DecisionReasonCode::ZonePolicyConnectorNotAllowed.as_str()
        );
    }

    #[test]
    fn public_payload_taint_still_denies_dangerous_command() {
        let config = config("https://hooks.example.test/webhooks").unwrap();
        let mut request = request(&config, "/webhooks/github").unwrap();
        request.operation = OperationId::from_static("webhook.endpoints.delete");
        request.capability_token =
            policy_token("webhook.endpoints.write", "webhook.endpoints.delete");
        let mut input = policy_input(request, "webhook.endpoints.write");
        input.safety_tier = SafetyTier::Dangerous;
        let decision = simulate_policy_decision(&input).unwrap();
        assert!(decision.is_deny());
        assert_eq!(
            decision.reason_code,
            DecisionReasonCode::TaintPublicInputDangerous.as_str()
        );
    }

    #[test]
    fn public_origin_commands_still_require_elevation_into_work_zone() {
        let config = config("https://hooks.example.test/webhooks")
            .unwrap()
            .with_capability_token(policy_token(
                "webhook.events.write",
                WEBHOOK_INGRESS_OPERATION,
            ));
        let mut request = request(&config, "/webhooks/github").unwrap();
        request.provenance.as_mut().unwrap().origin_zone = ZoneId::public();
        let decision =
            simulate_policy_decision(&policy_input(request, "webhook.events.write")).unwrap();
        assert!(decision.is_deny());
        assert_eq!(
            decision.reason_code,
            DecisionReasonCode::ApprovalMissingElevation.as_str()
        );
    }

    #[test]
    fn absent_connection_address_does_not_use_forwarded_address() {
        let config = config("https://hooks.example.test/webhooks").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("127.0.0.1"));
        let request = config
            .build_request(&headers, &"/webhooks/github".parse().unwrap(), "{}", None)
            .unwrap();
        assert!(request.input.get("source_ip").is_none());
        assert!(request.input.get("client_id").is_none());
    }

    #[test]
    fn body_limit_counts_actual_utf8_bytes() {
        let config = WebhookIngressConfig::new(
            ConnectorId::from_static(RECEIVER_ID),
            ZoneId::work(),
            CapabilityToken::test_token(),
            "https://hooks.example.test/webhooks".into(),
            3,
            1,
            1,
        )
        .unwrap();
        let uri = "/webhooks/test".parse().unwrap();
        assert!(
            config
                .build_request(&HeaderMap::new(), &uri, "雪", None)
                .is_ok()
        );
        assert!(matches!(
            config.build_request(&HeaderMap::new(), &uri, "雪a", None),
            Err(WebhookIngressError::PayloadTooLarge)
        ));
    }

    #[test]
    fn path_aliases_are_rejected_without_normalization() {
        let config = config("https://hooks.example.test/webhooks").unwrap();
        for target in [
            "/webhooks",
            "/webhooks/",
            "/webhooks-evil/github",
            "/webhooks//github",
            "/webhooks/github/",
            "/webhooks/./github",
            "/webhooks/a/../github",
            "/webhooks/%2e/github",
            "/webhooks/%2E%2e/github",
            "/webhooks/a%2fb",
            "/webhooks/a%2Fb",
            "/webhooks/a%5cb",
            "/webhooks/a%252fb",
            "/webhooks/a%3fb",
            "/webhooks/a%23b",
            "/webhooks/a%00b",
            "/webhooks/%",
            "/webhooks/%2",
            "/webhooks/%zz",
            "/webhooks/a?x=%",
            "https://hooks.example.test/webhooks/github",
            "//hooks.example.test/webhooks/github",
        ] {
            assert!(request(&config, target).is_err(), "accepted {target}");
        }
        for target in [
            "/webhooks/a.b",
            "/webhooks/%7Ehook",
            "/webhooks/a/b",
            "/webhooks/a?x=%2f",
        ] {
            assert!(request(&config, target).is_ok(), "rejected {target}");
        }
    }

    #[test]
    fn empty_query_is_preserved_for_url_signatures() {
        let config = config("https://hooks.example.test/webhooks").unwrap();
        let request = request(&config, "/webhooks/twilio?").unwrap();
        assert_eq!(
            request.input["url"],
            "https://hooks.example.test/webhooks/twilio?"
        );
    }

    #[test]
    fn raw_target_limit_includes_query() {
        let config = config("https://hooks.example.test/webhooks").unwrap();
        let prefix = "/webhooks/a?x=";
        let target = format!(
            "{prefix}{}",
            "a".repeat(MAX_WEBHOOK_INGRESS_TARGET_BYTES - prefix.len())
        );
        assert!(request(&config, &target).is_ok());
        assert!(matches!(
            request(&config, &format!("{target}a")),
            Err(WebhookIngressError::UriTooLong)
        ));
    }

    #[test]
    fn duplicate_headers_fail_even_when_values_match_or_are_ignored() {
        let config = config("https://hooks.example.test/webhooks").unwrap();
        let uri = "/webhooks/github".parse().unwrap();
        for name in ["x-hub-signature-256", "content-type", "forwarded"] {
            let mut headers = HeaderMap::new();
            headers.append(name, HeaderValue::from_static("same"));
            headers.append(name, HeaderValue::from_static("same"));
            assert_eq!(
                config.validate_request_head(&headers, &uri),
                Err(WebhookIngressError::InvalidHeaders)
            );
        }
    }

    #[test]
    fn header_limits_include_suppressed_fields_and_match_boundary() {
        let config = config("https://hooks.example.test/webhooks").unwrap();
        let uri = "/webhooks/github".parse().unwrap();
        let mut headers = HeaderMap::new();
        let name = "forwarded";
        headers.insert(
            name,
            HeaderValue::from_str(&"a".repeat(MAX_WEBHOOK_INGRESS_HEADER_BYTES - name.len()))
                .unwrap(),
        );
        assert!(config.validate_request_head(&headers, &uri).is_ok());
        headers.insert("x", HeaderValue::from_static(""));
        assert_eq!(
            config.validate_request_head(&headers, &uri),
            Err(WebhookIngressError::HeadersTooLarge)
        );
        let mut headers = HeaderMap::new();
        for index in 0..MAX_WEBHOOK_INGRESS_HEADERS {
            headers.insert(
                HeaderName::from_bytes(format!("x-test-{index}").as_bytes()).unwrap(),
                HeaderValue::from_static("a"),
            );
        }
        assert!(config.validate_request_head(&headers, &uri).is_ok());
        headers.insert("one-too-many", HeaderValue::from_static("a"));
        assert_eq!(
            config.validate_request_head(&headers, &uri),
            Err(WebhookIngressError::HeadersTooLarge)
        );
    }

    #[test]
    fn non_text_header_is_rejected_before_dispatch() {
        let config = config("https://hooks.example.test/webhooks").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-signature", HeaderValue::from_bytes(&[0xff]).unwrap());
        assert_eq!(
            config.validate_request_head(&headers, &"/webhooks/a".parse().unwrap()),
            Err(WebhookIngressError::InvalidHeaders)
        );
    }

    #[test]
    fn response_returns_only_admission_fields() {
        let response = InvokeResponse::ok(
            RequestId::random(),
            json!({
                "accepted": true, "status_code": 202,
                "event": { "payload": "private" },
                "ingest_log": { "secret": "hidden" },
            }),
        );
        let (status, body) = response_for(&response);
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(
            body,
            json!({"accepted":true,"status_code":202,"reason_code":"accepted"})
        );
    }

    #[test]
    fn authenticated_duplicate_returns_only_fixed_success_fields() {
        let response = InvokeResponse::ok(
            RequestId::random(),
            json!({"accepted": true, "status_code": 200, "duplicate": true}),
        );
        let (status, body) = response_for(&response);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            json!({"accepted": true, "status_code": 200, "reason_code": "already_accepted"}),
        );
        // An ordinary receiver conflict still proves no accepted content.
        assert_eq!(response_for(&receiver_error(409)).0, StatusCode::CONFLICT);
    }

    #[test]
    fn malformed_duplicate_outcomes_cannot_acknowledge_or_reflect_metadata() {
        for result in [
            json!({"accepted": true, "status_code": 200, "duplicate": false}),
            json!({"accepted": true, "status_code": 200, "duplicate": "true"}),
            json!({"accepted": true, "status_code": 202, "duplicate": true}),
            json!({"accepted": false, "status_code": 200, "duplicate": true}),
            json!({"accepted": true, "status_code": 200, "duplicate": true,
                "event": {"payload": "private-duplicate-payload"}}),
            json!({"accepted": true, "status_code": 200, "duplicate": true,
                "verification": {"provider": "slack", "kind": "url_verification",
                    "challenge": "private-duplicate-challenge"}}),
        ] {
            let (status, body) = response_for(&InvokeResponse::ok(RequestId::random(), result));
            assert_eq!(status, StatusCode::BAD_GATEWAY);
            assert!(!body.to_string().contains("private-duplicate"));
        }
        let mut inconsistent = InvokeResponse::ok(
            RequestId::random(),
            json!({"accepted": true, "status_code": 200, "duplicate": true}),
        );
        inconsistent.error = Some(FcpError::InvalidSignature);
        assert_eq!(response_for(&inconsistent).0, StatusCode::BAD_GATEWAY);
    }

    fn slack_verification_result(challenge: Value) -> Value {
        json!({
            "accepted": true,
            "status_code": 200,
            "verification": {
                "provider": "slack",
                "kind": "url_verification",
                "challenge": challenge,
            },
        })
    }

    #[test]
    fn slack_verification_returns_only_authenticated_bounded_challenge() {
        for challenge in ["a".to_owned(), "x".repeat(MAX_SLACK_CHALLENGE_BYTES)] {
            let mut result = slack_verification_result(json!(challenge));
            result["token"] = json!("private-legacy-token");
            result["ingest_log"] = json!({"secret": "private-signature-evidence"});
            result["event"] = json!({"payload": "private-event"});
            let (status, body) = response_for(&InvokeResponse::ok(RequestId::random(), result));
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body, json!({"challenge": challenge}));
            assert!(!body.to_string().contains("private-"));
        }
    }

    #[test]
    fn malformed_verification_cannot_select_a_public_response() {
        for challenge in [
            Value::Null,
            json!(true),
            json!(42),
            json!({"challenge": "nested"}),
            json!(""),
            json!("x".repeat(MAX_SLACK_CHALLENGE_BYTES + 1)),
            json!("é".repeat(MAX_SLACK_CHALLENGE_BYTES / 2 + 1)),
            json!("challenge\nresponse"),
            json!("challenge\u{0085}response"),
        ] {
            let response =
                InvokeResponse::ok(RequestId::random(), slack_verification_result(challenge));
            let (status, body) = response_for(&response);
            assert_eq!(status, StatusCode::BAD_GATEWAY);
            assert_eq!(body["reason_code"], "invalid_receiver_response");
            assert!(body.get("challenge").is_none());
        }
        for (pointer, replacement) in [
            ("/accepted", json!(false)),
            ("/status_code", json!(202)),
            ("/verification", Value::Null),
            ("/verification/provider", json!("github")),
            ("/verification/kind", json!("redirect")),
            ("/verification/challenge", json!(["challenge"])),
        ] {
            let mut result = slack_verification_result(json!("private-challenge"));
            *result.pointer_mut(pointer).expect("fixture field") = replacement;
            let (status, body) = response_for(&InvokeResponse::ok(RequestId::random(), result));
            assert_eq!(status, StatusCode::BAD_GATEWAY, "{pointer}");
            assert!(!body.to_string().contains("private-challenge"));
        }
        let mut result = slack_verification_result(json!("challenge"));
        result["verification"]["headers"] = json!({"location": "https://attacker.test"});
        assert_eq!(
            response_for(&InvokeResponse::ok(RequestId::random(), result)).0,
            StatusCode::BAD_GATEWAY,
        );
    }

    #[test]
    fn verification_requires_a_successful_canonical_invocation() {
        let mut response = InvokeResponse::ok(
            RequestId::random(),
            slack_verification_result(json!("private-challenge")),
        );
        response.error = Some(FcpError::InvalidSignature);
        let (status, body) = response_for(&response);
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(body.get("challenge").is_none());
        response.error = None;
        response.status = InvokeStatus::Error;
        assert_eq!(response_for(&response).0, StatusCode::BAD_GATEWAY);
        response.status = InvokeStatus::Ok;
        response.r#type = "event".to_owned();
        assert_eq!(response_for(&response).0, StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn receiver_failure_statuses_are_allowlisted_and_redacted() {
        for code in [400, 401, 403, 404, 405, 408, 409, 413, 415, 429, 507] {
            let (status, body) = response_for(&receiver_error(code));
            assert_eq!(status.as_u16(), code);
            assert_eq!(body["accepted"], false);
            assert_eq!(body.as_object().unwrap().len(), 3);
            assert!(!body.to_string().contains("secret"));
        }
        for code in [200, 202, 301, 4040, 500, 599] {
            assert_eq!(
                response_for(&receiver_error(code)).0,
                StatusCode::BAD_GATEWAY
            );
        }
    }

    #[test]
    fn malformed_success_never_acknowledges_delivery() {
        for result in [
            Value::Null,
            json!({}),
            json!({"accepted":false,"status_code":202}),
            json!({"accepted":true,"status_code":200}),
            json!({"accepted":"true","status_code":202}),
        ] {
            let response = InvokeResponse::ok(RequestId::random(), result);
            assert_eq!(response_for(&response).0, StatusCode::BAD_GATEWAY);
        }
        let mut response = InvokeResponse::ok(
            RequestId::random(),
            json!({"accepted":true,"status_code":202}),
        );
        response.error = Some(FcpError::InvalidSignature);
        assert_eq!(response_for(&response).0, StatusCode::BAD_GATEWAY);
        response.error = None;
        response.r#type = "other".into();
        assert_eq!(response_for(&response).0, StatusCode::BAD_GATEWAY);
        response.r#type = "response".into();
        response.status = InvokeStatus::Error;
        assert_eq!(response_for(&response).0, StatusCode::BAD_GATEWAY);
        response.result = None;
        assert_eq!(response_for(&response).0, StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn unrelated_errors_and_host_authority_failures_cannot_acknowledge() {
        let response = InvokeResponse::error(
            RequestId::random(),
            FcpError::External {
                service: "different-service".into(),
                message: "secret".into(),
                status_code: Some(202),
                retryable: false,
                retry_after: None,
            },
        );
        assert_eq!(response_for(&response).0, StatusCode::BAD_GATEWAY);
        for error in [
            FcpError::InvalidSignature,
            FcpError::TokenExpired,
            FcpError::NotConfigured,
            FcpError::NotHandshaken,
            FcpError::CapabilityDenied {
                capability: "secret".into(),
                reason: "secret".into(),
            },
        ] {
            let (status, body) = response_for(&InvokeResponse::error(RequestId::random(), error));
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(body["accepted"], false);
            assert!(!body.to_string().contains("secret"));
        }
    }

    #[test]
    fn admission_error_diagnostics_never_reach_public_body() {
        for error in [
            WebhookIngressError::InvalidConfiguration("secret-diagnostic"),
            WebhookIngressError::InvalidInput("secret-diagnostic"),
            WebhookIngressError::InvalidPath,
            WebhookIngressError::UriTooLong,
            WebhookIngressError::InvalidHeaders,
            WebhookIngressError::HeadersTooLarge,
            WebhookIngressError::PayloadTooLarge,
            WebhookIngressError::Unavailable,
            WebhookIngressError::InvalidResponse,
            WebhookIngressError::Timeout,
            WebhookIngressError::TooManyRequests,
            WebhookIngressError::MethodNotAllowed,
        ] {
            let (status, body) = error.response();
            assert!(status.is_client_error() || status.is_server_error());
            assert_eq!(body["accepted"], false);
            assert_eq!(body["status_code"], status.as_u16());
            assert_eq!(body.as_object().unwrap().len(), 3);
            assert!(!body.to_string().contains("secret"));
        }
    }

    #[test]
    fn configuration_debug_omits_token_contents() {
        let config = config("https://hooks.example.test/webhooks").unwrap();
        let debug = format!("{config:?}");
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("CoseToken"));
        assert!(!debug.contains("claims"));
    }
}
