//! Provider authentication profiles and method selection for FCP connectors.
//!
//! This crate owns the provider/profile layer above raw credential leasing and
//! OAuth primitives. Host admin routes, CLI helpers, provider-specific imports,
//! and credential-pool integration are intentionally kept outside this crate's
//! core primitives.

#![forbid(unsafe_code)]
// Lint groups come from [workspace.lints.clippy]; duplicating them here would
// override that table and defeat its allow entries.
#![allow(clippy::module_name_repetitions)]
// nursery/pedantic style lints newer nightlies fire on this unchanged code; the crate
// re-enables the groups in source, which overrides the workspace lint table.
#![allow(clippy::collapsible_if)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::duration_suboptimal_units)]

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, TimeDelta, Utc};
use hmac::{Hmac, Mac};
use parking_lot::RwLock;
use rand::RngCore;
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// AWS `SigV4` algorithm label.
pub const SIGV4_ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// `SigV4` payload sentinel for services that permit unsigned payloads.
pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";

/// SHA-256 hash of an empty payload.
pub const EMPTY_PAYLOAD_SHA256: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Result type for provider-auth operations.
pub type AuthResult<T> = Result<T, AuthError>;

/// Provider-auth errors. All variants are safe to render in logs.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AuthError {
    /// Caller supplied an invalid static configuration value.
    #[error("invalid auth configuration for {field}: {reason}")]
    InvalidConfig {
        /// Field name.
        field: &'static str,
        /// Redaction-safe validation reason.
        reason: String,
    },

    /// A request header name or value contained invalid bytes.
    #[error("invalid auth header {field}: {reason}")]
    InvalidHeader {
        /// Header field being validated.
        field: &'static str,
        /// Redaction-safe validation reason.
        reason: String,
    },

    /// The auth method cannot build request auth without token material.
    #[error("auth method {method} has no usable token material")]
    MissingToken {
        /// Auth method id.
        method: &'static str,
    },

    /// The auth method needs request-signing fields that were not supplied.
    #[error("auth method {method} needs request signing context")]
    MissingSigningContext {
        /// Auth method id.
        method: &'static str,
    },

    /// The auth method's token material has expired.
    #[error("auth method {method} token expired at {expires_at}")]
    Expired {
        /// Auth method id.
        method: &'static str,
        /// Expiration timestamp.
        expires_at: DateTime<Utc>,
    },

    /// The requested provider profile does not exist.
    #[error("auth profile {profile_id} for provider {provider} not found")]
    ProfileNotFound {
        /// Canonical provider id.
        provider: String,
        /// Profile id.
        profile_id: String,
    },

    /// No profiles exist for the requested provider.
    #[error("provider {provider} has no auth profiles")]
    ProviderNotFound {
        /// Canonical provider id.
        provider: String,
    },

    /// Method surface is declared but intentionally deferred to a later slice.
    #[error("auth method {method} does not support {operation} in this slice")]
    UnsupportedMethod {
        /// Auth method id.
        method: &'static str,
        /// Operation name.
        operation: &'static str,
    },

    /// Provider returned a terminal OAuth error.
    #[error("auth method {method} rejected by provider with {code}: {reason}")]
    ProviderRejected {
        /// Auth method id.
        method: &'static str,
        /// Provider error code.
        code: String,
        /// Redaction-safe provider reason.
        reason: String,
    },

    /// Provider response was missing a field required by the OAuth state machine.
    #[error("auth method {method} got invalid provider response: {reason}")]
    InvalidProviderResponse {
        /// Auth method id.
        method: &'static str,
        /// Redaction-safe response validation reason.
        reason: String,
    },
}

fn invalid_config(field: &'static str, reason: impl Into<String>) -> AuthError {
    AuthError::InvalidConfig {
        field,
        reason: reason.into(),
    }
}

fn validate_non_empty(value: &str, field: &'static str) -> AuthResult<()> {
    if value.trim().is_empty() {
        return Err(invalid_config(field, "must not be empty"));
    }
    Ok(())
}

fn canonical_provider(provider: &str) -> AuthResult<String> {
    validate_non_empty(provider, "provider")?;
    Ok(provider.trim().to_ascii_lowercase())
}

fn validate_header_name(name: &str) -> AuthResult<()> {
    validate_non_empty(name, "header_name")?;
    if name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        Ok(())
    } else {
        Err(AuthError::InvalidHeader {
            field: "header_name",
            reason: "only ASCII alphanumeric characters and '-' are allowed".to_string(),
        })
    }
}

fn validate_header_value(value: &str) -> AuthResult<()> {
    if value.contains('\r') || value.contains('\n') {
        return Err(AuthError::InvalidHeader {
            field: "header_value",
            reason: "CR/LF bytes are not allowed".to_string(),
        });
    }
    validate_non_empty(value, "header_value")
}

fn validate_no_crlf(value: &str, field: &'static str) -> AuthResult<()> {
    if value.contains('\r') || value.contains('\n') {
        return Err(AuthError::InvalidConfig {
            field,
            reason: "CR/LF bytes are not allowed".to_string(),
        });
    }
    Ok(())
}

fn validate_payload_hash(value: &str) -> AuthResult<()> {
    if value == UNSIGNED_PAYLOAD {
        return Ok(());
    }
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(invalid_config(
            "payload_hash",
            "must be a SHA-256 hex digest or UNSIGNED-PAYLOAD",
        ))
    }
}

fn validate_oauth_endpoint(value: &str, field: &'static str) -> AuthResult<()> {
    validate_non_empty(value, field)?;
    validate_no_crlf(value, field)
}

fn parse_oauth_url(value: &str, field: &'static str) -> AuthResult<Url> {
    validate_oauth_endpoint(value, field)?;
    let parsed = Url::parse(value).map_err(|error| invalid_config(field, error.to_string()))?;
    match parsed.scheme() {
        "http" | "https" => Ok(parsed),
        _ => Err(invalid_config(field, "must use http or https scheme")),
    }
}

fn validate_oauth_error(code: &str, reason: &str) -> AuthResult<()> {
    validate_non_empty(code, "oauth_error_code")?;
    validate_no_crlf(code, "oauth_error_code")?;
    validate_non_empty(reason, "oauth_error_reason")?;
    validate_no_crlf(reason, "oauth_error_reason")
}

fn validate_oauth_state(state: &str) -> AuthResult<()> {
    validate_non_empty(state, "state")?;
    validate_no_crlf(state, "state")
}

fn validate_pkce_verifier(verifier: &str) -> AuthResult<()> {
    if !(43..=128).contains(&verifier.len()) {
        return Err(invalid_config("pkce_verifier", "must be 43-128 characters"));
    }
    if verifier
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
    {
        Ok(())
    } else {
        Err(invalid_config(
            "pkce_verifier",
            "must contain only RFC 7636 unreserved characters",
        ))
    }
}

fn pkce_s256_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

fn generate_url_safe_secret() -> String {
    let mut bytes = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn build_authorization_request(
    config: &OAuthAuthCodeConfig,
    state: RedactedSecret,
    pkce: Option<OAuthPkce>,
) -> AuthResult<OAuthAuthCodeRequest> {
    let mut url = parse_oauth_url(&config.authorize_url, "authorize_url")?;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("response_type", "code");
        query.append_pair("client_id", &config.client_id);
        query.append_pair("redirect_uri", &config.redirect_uri);
        if !config.scope.trim().is_empty() {
            query.append_pair("scope", &config.scope);
        }
        query.append_pair("state", state.expose_secret());
        if let Some(pkce) = pkce.as_ref() {
            query.append_pair("code_challenge", &pkce.challenge);
            query.append_pair("code_challenge_method", &pkce.method.to_string());
        }
        for (name, value) in &config.extra_authorize_params {
            query.append_pair(name, value);
        }
    }
    Ok(OAuthAuthCodeRequest {
        authorization_url: url.to_string(),
        state,
        pkce,
    })
}

fn std_duration_until(expires_at: DateTime<Utc>) -> StdDuration {
    let remaining = expires_at.signed_duration_since(Utc::now());
    remaining.to_std().unwrap_or(StdDuration::ZERO)
}

fn chrono_duration(duration: StdDuration) -> AuthResult<TimeDelta> {
    TimeDelta::from_std(duration)
        .map_err(|_| invalid_config("ttl", "duration is outside chrono range"))
}

/// Resolve a TTL into an absolute expiry, rejecting values that would overflow
/// the timestamp instead of panicking.
///
/// `TimeDelta::from_std` only rejects durations outside `TimeDelta`'s own range
/// (~9.2e15 s), but `DateTime<Utc>` tops out near year 262143 (~8.2e12 s from
/// now) and `DateTime + TimeDelta` is an `expect` internally. Everything in the
/// gap between those two bounds passed validation and then panicked. Since
/// `expires_in` comes straight off a provider token response — a `u64` parsed
/// from attacker-influenceable JSON — `{"expires_in": 9000000000000000}` was
/// enough to panic the handler task. Fail closed with a typed error instead.
/// Whether a refreshed scope string stays within the originally granted set.
///
/// RFC 6749 §6: a refresh response MUST NOT include any scope the resource
/// owner did not originally grant. An empty `granted` means the grant scope was
/// never observed (the provider omitted it on the original exchange), which
/// cannot be meaningfully narrowed, so it accepts rather than failing closed on
/// missing information.
fn refreshed_scope_is_subset(granted: &str, refreshed: &str) -> bool {
    let granted_scopes: HashSet<&str> = granted.split_whitespace().collect();
    if granted_scopes.is_empty() {
        return true;
    }
    refreshed
        .split_whitespace()
        .all(|scope| granted_scopes.contains(scope))
}

/// Decide the granted scope to keep after a refresh response.
///
/// Two failure modes this closes, both mirroring the fcp-oauth production path:
/// - An OMITTED scope must preserve the previously granted one rather than
///   dropping it, otherwise the next refresh has nothing to narrow against and
///   the widening guard below is permanently disarmed.
/// - A WIDENED scope is rejected: a compromised or misbehaving token endpoint
///   answering `read` with `read write admin` must not silently escalate what
///   the profile is authorized for.
fn resolve_refreshed_scope(
    granted: Option<&str>,
    refreshed: Option<String>,
) -> AuthResult<Option<String>> {
    match refreshed {
        None => Ok(granted.map(ToString::to_string)),
        Some(refreshed) => {
            if let Some(granted) = granted {
                if !refreshed_scope_is_subset(granted, &refreshed) {
                    return Err(invalid_config(
                        "scope",
                        "refresh response expanded the granted scope",
                    ));
                }
            }
            Ok(Some(refreshed))
        }
    }
}

fn expiry_from_ttl(duration: StdDuration, field: &'static str) -> AuthResult<DateTime<Utc>> {
    let delta = chrono_duration(duration)?;
    Utc::now()
        .checked_add_signed(delta)
        .ok_or_else(|| invalid_config(field, "expiry overflows the representable timestamp range"))
}

/// Secret string wrapper that redacts every formatting path and zeroizes on drop.
#[derive(Eq)]
pub struct RedactedSecret(Zeroizing<String>);

impl RedactedSecret {
    /// Construct a non-empty secret wrapper.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when the secret is empty.
    pub fn new(material: impl Into<String>) -> AuthResult<Self> {
        let material = material.into();
        validate_non_empty(&material, "credential_material")?;
        Ok(Self(Zeroizing::new(material)))
    }

    /// Borrow the raw secret for the narrow boundary that applies auth.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        self.0.as_str()
    }

    /// Return a redaction-safe stable hint for diagnostics.
    #[must_use]
    pub fn redacted_token_first8(&self) -> String {
        let prefix: String = self.expose_secret().chars().take(8).collect();
        if prefix.is_empty() {
            "[REDACTED]".to_string()
        } else {
            format!("{prefix}...")
        }
    }
}

impl Clone for RedactedSecret {
    fn clone(&self) -> Self {
        Self(Zeroizing::new(self.expose_secret().to_string()))
    }
}

impl PartialEq for RedactedSecret {
    fn eq(&self, other: &Self) -> bool {
        self.expose_secret() == other.expose_secret()
    }
}

impl fmt::Debug for RedactedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RedactedSecret([REDACTED])")
    }
}

impl fmt::Display for RedactedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Signable request context for AWS `SigV4` auth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigV4SigningContext {
    /// HTTP method such as `GET` or `POST`.
    pub method: String,
    /// **Wire** path component — the absolute path exactly as it will appear in
    /// the request line, percent-encoded (`url::Url::path()` produces it
    /// directly, as `/bucket/my%20key`). Empty paths are canonicalized to `/`.
    ///
    /// The signer percent-DECODES this before building the canonical URI,
    /// because that is what the service does with what it receives. Passing an
    /// already-decoded path here signs a different resource than the one the
    /// request targets whenever the path contains anything needing an escape.
    ///
    /// This matches `fcp_sdk::sigv4::SignableRequest::uri`; the two crates
    /// must not diverge.
    pub uri_path: String,
    /// Query parameters before `SigV4` URI encoding.
    pub query_params: BTreeMap<String, String>,
    /// SHA-256 payload hash or [`UNSIGNED_PAYLOAD`].
    pub payload_hash: String,
    /// Optional fixed timestamp for deterministic tests.
    pub signing_time: Option<DateTime<Utc>>,
}

impl SigV4SigningContext {
    /// Construct a `SigV4` signing context without query parameters.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] for invalid method, path, or payload hash.
    pub fn new(
        method: impl Into<String>,
        uri_path: impl Into<String>,
        payload_hash: impl Into<String>,
    ) -> AuthResult<Self> {
        let method = method.into().trim().to_ascii_uppercase();
        let mut uri_path = uri_path.into();
        let payload_hash = payload_hash.into();
        validate_non_empty(&method, "method")?;
        validate_no_crlf(&method, "method")?;
        validate_no_crlf(&uri_path, "uri_path")?;
        validate_payload_hash(&payload_hash)?;
        if uri_path.is_empty() {
            uri_path.push('/');
        }
        let payload_hash = if payload_hash == UNSIGNED_PAYLOAD {
            payload_hash
        } else {
            payload_hash.to_ascii_lowercase()
        };
        Ok(Self {
            method,
            uri_path,
            query_params: BTreeMap::new(),
            payload_hash,
            signing_time: None,
        })
    }

    /// Add a query parameter to this signing context.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] if the key is empty or either field contains CR/LF.
    pub fn with_query_param(
        mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> AuthResult<Self> {
        let key = key.into();
        let value = value.into();
        validate_non_empty(&key, "query_param")?;
        validate_no_crlf(&key, "query_param")?;
        validate_no_crlf(&value, "query_value")?;
        self.query_params.insert(key, value);
        Ok(self)
    }

    /// Use a deterministic signing timestamp.
    #[must_use]
    pub const fn with_signing_time(mut self, signing_time: DateTime<Utc>) -> Self {
        self.signing_time = Some(signing_time);
        self
    }
}

/// Minimal request-auth target used by connector clients and tests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthRequest {
    headers: BTreeMap<String, String>,
    sigv4_context: Option<SigV4SigningContext>,
}

impl AuthRequest {
    /// Construct an empty request-auth target.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            headers: BTreeMap::new(),
            sigv4_context: None,
        }
    }

    /// Set a validated header.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidHeader`] when the header name or value is
    /// empty or contains bytes unsafe for outbound HTTP headers.
    pub fn set_header(
        &mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> AuthResult<()> {
        let name = name.into();
        let value = value.into();
        validate_header_name(&name)?;
        validate_header_value(&value)?;
        self.headers.insert(name, value);
        Ok(())
    }

    /// Read a header value by exact name.
    #[must_use]
    pub fn value_for(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }

    /// Borrow all request auth headers.
    #[must_use]
    pub const fn headers(&self) -> &BTreeMap<String, String> {
        &self.headers
    }

    /// Attach `SigV4` signing context for methods that need full request details.
    pub fn set_sigv4_context(&mut self, context: SigV4SigningContext) {
        self.sigv4_context = Some(context);
    }

    /// Borrow `SigV4` signing context, if present.
    #[must_use]
    pub const fn sigv4_context(&self) -> Option<&SigV4SigningContext> {
        self.sigv4_context.as_ref()
    }
}

/// Shared behavior for provider auth methods.
#[async_trait]
pub trait AuthMethod: Send + Sync {
    /// Stable method id, for example `api_key` or `oauth_device`.
    fn id(&self) -> &'static str;

    /// Validate method configuration and current token state.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthError`] when the method cannot be used safely.
    async fn validate(&self, cx: &fcp_async_core::Cx) -> AuthResult<()>;

    /// Apply auth material to a request.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthError`] when the method is missing token material,
    /// expired, unsupported in this slice, or would produce an unsafe header.
    async fn build_request_auth(
        &self,
        cx: &fcp_async_core::Cx,
        request: &mut AuthRequest,
    ) -> AuthResult<()>;

    /// Return time until refresh is needed, if this method is TTL-bounded.
    fn requires_refresh_in(&self) -> Option<StdDuration>;

    /// Refresh token material.
    ///
    /// # Errors
    ///
    /// The default implementation returns [`AuthError::UnsupportedMethod`].
    async fn refresh(&mut self, _cx: &fcp_async_core::Cx) -> AuthResult<()> {
        Err(AuthError::UnsupportedMethod {
            method: self.id(),
            operation: "refresh",
        })
    }
}

/// Static API-key authentication.
#[derive(Clone, PartialEq, Eq)]
pub struct ApiKeyAuth {
    /// Secret API key.
    pub key: RedactedSecret,
    /// Header that receives the credential.
    pub header_name: String,
    /// Optional value prefix such as `Bearer`.
    pub value_prefix: Option<String>,
}

impl ApiKeyAuth {
    /// Construct bearer-token API-key auth using the `Authorization` header.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when the key is empty.
    pub fn bearer(key: impl Into<String>) -> AuthResult<Self> {
        Self::new(key, "Authorization", Some("Bearer"))
    }

    /// Construct API-key auth with a custom header and optional value prefix.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthError`] when the key, header name, or prefix is invalid.
    pub fn new(
        key: impl Into<String>,
        header_name: impl Into<String>,
        value_prefix: Option<impl Into<String>>,
    ) -> AuthResult<Self> {
        let header_name = header_name.into();
        validate_header_name(&header_name)?;
        let value_prefix = value_prefix.map(Into::into);
        if let Some(prefix) = value_prefix.as_deref() {
            validate_non_empty(prefix, "value_prefix")?;
            validate_header_value(prefix)?;
        }
        Ok(Self {
            key: RedactedSecret::new(key)?,
            header_name,
            value_prefix,
        })
    }

    fn header_value(&self) -> String {
        self.value_prefix.as_deref().map_or_else(
            || self.key.expose_secret().to_string(),
            |prefix| format!("{prefix} {}", self.key.expose_secret()),
        )
    }
}

impl fmt::Debug for ApiKeyAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiKeyAuth")
            .field("key", &self.key)
            .field("header_name", &self.header_name)
            .field("value_prefix", &self.value_prefix)
            .finish()
    }
}

#[async_trait]
impl AuthMethod for ApiKeyAuth {
    fn id(&self) -> &'static str {
        "api_key"
    }

    async fn validate(&self, _cx: &fcp_async_core::Cx) -> AuthResult<()> {
        validate_header_name(&self.header_name)?;
        validate_header_value(&self.header_value())
    }

    async fn build_request_auth(
        &self,
        cx: &fcp_async_core::Cx,
        request: &mut AuthRequest,
    ) -> AuthResult<()> {
        self.validate(cx).await?;
        request.set_header(self.header_name.clone(), self.header_value())
    }

    fn requires_refresh_in(&self) -> Option<StdDuration> {
        None
    }
}

/// OAuth device-code auth state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthDeviceCodeAuth {
    /// OAuth client id.
    pub client_id: String,
    /// Device-code endpoint URL.
    pub device_code_url: String,
    /// Token endpoint URL.
    pub token_url: String,
    /// Requested scope string.
    pub scope: String,
    /// Scope the provider actually GRANTED, as reported on the token response.
    ///
    /// Distinct from [`Self::scope`], which is only what was *requested*.
    /// Refreshes are issued against this value so a user who consented to a
    /// narrower set (or later revoked part of it) is not silently re-asked for
    /// the full original scope on every refresh — RFC 6749 §6 forbids
    /// requesting a scope that was never granted.
    pub granted_scope: Option<String>,
    /// Current access token, if the flow has completed.
    pub access_token: Option<RedactedSecret>,
    /// Current refresh token, if the provider issued one.
    pub refresh_token: Option<RedactedSecret>,
    /// Access-token expiration time.
    pub expires_at: Option<DateTime<Utc>>,
}

impl OAuthDeviceCodeAuth {
    /// Construct OAuth device-code auth state without token material.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when required OAuth fields are empty
    /// or contain bytes unsafe for logs/HTTP form fields.
    pub fn new(
        client_id: impl Into<String>,
        device_code_url: impl Into<String>,
        token_url: impl Into<String>,
        scope: impl Into<String>,
    ) -> AuthResult<Self> {
        let config = OAuthDeviceCodeConfig::new(client_id, device_code_url, token_url, scope)?;
        Ok(Self::from_config(config))
    }

    /// Construct auth state from a validated flow config.
    #[must_use]
    pub fn from_config(config: OAuthDeviceCodeConfig) -> Self {
        Self {
            client_id: config.client_id,
            device_code_url: config.device_code_url,
            token_url: config.token_url,
            scope: config.scope,
            granted_scope: None,
            access_token: None,
            refresh_token: None,
            expires_at: None,
        }
    }

    /// Replace cached token material after a completed device-code flow.
    pub fn apply_tokens(&mut self, tokens: OAuthTokens) {
        let OAuthTokens {
            access_token,
            refresh_token,
            expires_at,
            scope,
            ..
        } = tokens;
        let access_slot = &mut self.access_token;
        *access_slot = Some(access_token);
        let refresh_slot = &mut self.refresh_token;
        *refresh_slot = refresh_token;
        self.expires_at = expires_at;
        // Record what was actually granted; the token response is the only
        // place this is ever observable.
        self.granted_scope = scope;
    }

    /// Build refresh-token flow configuration from this auth state.
    ///
    /// Refreshes are issued against the GRANTED scope when one was observed,
    /// falling back to the configured request scope only when the provider
    /// never reported one.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when stored OAuth fields are invalid.
    pub fn refresh_config(&self) -> AuthResult<OAuthRefreshTokenConfig> {
        let effective = self.granted_scope.as_deref().unwrap_or(&self.scope);
        let scope = if effective.is_empty() {
            None
        } else {
            Some(effective.to_string())
        };
        OAuthRefreshTokenConfig::public_client(
            self.client_id.clone(),
            self.token_url.clone(),
            scope,
        )
    }

    /// Build a refresh-token grant from cached refresh-token material.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::MissingToken`] when the provider has not issued a refresh token.
    pub fn refresh_grant(&self) -> AuthResult<OAuthRefreshTokenGrant> {
        let Some(refresh_token) = &self.refresh_token else {
            return Err(AuthError::MissingToken {
                method: "oauth_device",
            });
        };
        OAuthRefreshTokenGrant::new(refresh_token.expose_secret().to_string())
    }

    /// Refresh cached bearer tokens through an injectable refresh-token transport.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthError`] for invalid stored config, missing refresh-token
    /// material, transport failures, provider rejections, or malformed refreshed tokens.
    pub async fn refresh_with_transport<T>(
        &mut self,
        cx: &fcp_async_core::Cx,
        transport: &T,
    ) -> AuthResult<()>
    where
        T: OAuthRefreshTokenTransport + ?Sized,
    {
        self.validate_config()?;
        let config = self.refresh_config()?;
        let grant = self.refresh_grant()?;
        let tokens = OAuthRefreshTokenFlow::refresh(cx, &config, &grant, transport).await?;
        self.apply_refreshed_tokens(tokens)
    }

    fn apply_refreshed_tokens(&mut self, tokens: OAuthTokens) -> AuthResult<()> {
        let OAuthTokens {
            access_token: fresh_access,
            refresh_token: fresh_refresh,
            expires_at,
            scope,
            ..
        } = tokens;
        // Scope first: a widening response must be rejected BEFORE any state is
        // mutated, so a refused refresh cannot leave half-applied material.
        let granted_scope = resolve_refreshed_scope(self.granted_scope.as_deref(), scope)?;

        let access_slot = &mut self.access_token;
        *access_slot = Some(fresh_access);
        if let Some(material) = fresh_refresh {
            let refresh_slot = &mut self.refresh_token;
            *refresh_slot = Some(material);
        }
        // Preserve a known expiry when the provider omits `expires_in`.
        // RFC 6749 §5.1 makes `expires_in` RECOMMENDED, not required, and
        // several providers omit it on refresh. Clobbering a known TTL to
        // `None` turned the profile into a never-expiring one:
        // `requires_refresh_in()` then returned `None`, the refresh policy
        // classified it `NotRefreshable`, and every expiry gate
        // (`apply_bearer_token`, the host's egress injector) is written as
        // `if let Some(expires_at)` — so the stale bearer was injected
        // indefinitely and never refreshed again. Same bug class already
        // fixed on the fcp-oauth production path (br-62b0adc34).
        self.expires_at = expires_at.or(self.expires_at);
        self.granted_scope = granted_scope;
        Ok(())
    }

    fn validate_config(&self) -> AuthResult<()> {
        validate_non_empty(&self.client_id, "client_id")?;
        validate_no_crlf(&self.client_id, "client_id")?;
        parse_oauth_url(&self.device_code_url, "device_code_url")?;
        parse_oauth_url(&self.token_url, "token_url")?;
        validate_no_crlf(&self.scope, "scope")
    }
}

#[async_trait]
impl AuthMethod for OAuthDeviceCodeAuth {
    fn id(&self) -> &'static str {
        "oauth_device"
    }

    async fn validate(&self, _cx: &fcp_async_core::Cx) -> AuthResult<()> {
        self.validate_config()
    }

    async fn build_request_auth(
        &self,
        cx: &fcp_async_core::Cx,
        request: &mut AuthRequest,
    ) -> AuthResult<()> {
        self.validate(cx).await?;
        apply_bearer_token(
            self.id(),
            self.access_token.as_ref(),
            self.expires_at,
            request,
        )
    }

    fn requires_refresh_in(&self) -> Option<StdDuration> {
        self.expires_at.map(std_duration_until)
    }
}

/// OAuth device-code flow configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthDeviceCodeConfig {
    /// OAuth client id.
    pub client_id: String,
    /// Device-code endpoint URL.
    pub device_code_url: String,
    /// Token endpoint URL.
    pub token_url: String,
    /// Requested scope string. Empty scope is allowed for providers that infer defaults.
    pub scope: String,
    /// Initial provider polling interval.
    pub default_poll_interval: StdDuration,
}

impl OAuthDeviceCodeConfig {
    /// Construct device-code flow configuration.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when required fields are empty or unsafe.
    pub fn new(
        client_id: impl Into<String>,
        device_code_url: impl Into<String>,
        token_url: impl Into<String>,
        scope: impl Into<String>,
    ) -> AuthResult<Self> {
        let client_id = client_id.into();
        let device_code_url = device_code_url.into();
        let token_url = token_url.into();
        let scope = scope.into();
        validate_non_empty(&client_id, "client_id")?;
        validate_no_crlf(&client_id, "client_id")?;
        validate_oauth_endpoint(&device_code_url, "device_code_url")?;
        validate_oauth_endpoint(&token_url, "token_url")?;
        validate_no_crlf(&scope, "scope")?;
        Ok(Self {
            client_id,
            device_code_url,
            token_url,
            scope,
            default_poll_interval: StdDuration::from_secs(5),
        })
    }

    /// Override the provider polling interval used before a challenge is issued.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when the interval is zero.
    pub fn with_default_poll_interval(mut self, interval: StdDuration) -> AuthResult<Self> {
        if interval.is_zero() {
            return Err(invalid_config(
                "default_poll_interval",
                "must be greater than zero",
            ));
        }
        self.default_poll_interval = interval;
        Ok(self)
    }

    fn validate(&self) -> AuthResult<()> {
        validate_non_empty(&self.client_id, "client_id")?;
        validate_no_crlf(&self.client_id, "client_id")?;
        validate_oauth_endpoint(&self.device_code_url, "device_code_url")?;
        validate_oauth_endpoint(&self.token_url, "token_url")?;
        validate_no_crlf(&self.scope, "scope")?;
        if self.default_poll_interval.is_zero() {
            return Err(invalid_config(
                "default_poll_interval",
                "must be greater than zero",
            ));
        }
        Ok(())
    }
}

/// Device-code challenge returned by an OAuth provider.
#[derive(Clone, PartialEq, Eq)]
pub struct OAuthDeviceCodeChallenge {
    /// Provider device code. Treated as secret because it authorizes polling.
    pub device_code: RedactedSecret,
    /// User-facing short code to enter in a browser.
    pub user_code: String,
    /// Browser verification URL.
    pub verification_uri: String,
    /// Optional complete verification URL with the user code embedded.
    pub verification_uri_complete: Option<String>,
    /// Challenge expiration timestamp.
    pub expires_at: DateTime<Utc>,
    /// Provider-requested polling interval.
    pub interval: StdDuration,
}

impl OAuthDeviceCodeChallenge {
    /// Construct a device-code challenge.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when required fields are empty or unsafe.
    pub fn new(
        device_code: impl Into<String>,
        user_code: impl Into<String>,
        verification_uri: impl Into<String>,
        verification_uri_complete: Option<impl Into<String>>,
        expires_at: DateTime<Utc>,
        interval: StdDuration,
    ) -> AuthResult<Self> {
        let challenge = Self {
            device_code: RedactedSecret::new(device_code)?,
            user_code: user_code.into(),
            verification_uri: verification_uri.into(),
            verification_uri_complete: verification_uri_complete.map(Into::into),
            expires_at,
            interval,
        };
        challenge.validate()?;
        Ok(challenge)
    }

    fn validate(&self) -> AuthResult<()> {
        validate_no_crlf(self.device_code.expose_secret(), "device_code")?;
        validate_non_empty(&self.user_code, "user_code")?;
        validate_no_crlf(&self.user_code, "user_code")?;
        // These two are the least-trusted inputs in the whole flow — they come
        // verbatim from the provider's device-code response and are handed to
        // an operator (or a browser) to open. A non-empty/no-CRLF check is not
        // enough: it accepted `javascript:` and other non-HTTP schemes, and
        // the host echoes the value straight back in its API response. Parse
        // them and pin the scheme like every operator-supplied endpoint.
        parse_oauth_url(&self.verification_uri, "verification_uri")?;
        if let Some(uri) = self.verification_uri_complete.as_deref() {
            parse_oauth_url(uri, "verification_uri_complete")?;
        }
        if self.interval.is_zero() {
            return Err(invalid_config("interval", "must be greater than zero"));
        }
        Ok(())
    }
}

impl fmt::Debug for OAuthDeviceCodeChallenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthDeviceCodeChallenge")
            .field("device_code", &self.device_code)
            .field("user_code", &self.user_code)
            .field("verification_uri", &self.verification_uri)
            .field("verification_uri_complete", &self.verification_uri_complete)
            .field("expires_at", &self.expires_at)
            .field("interval", &self.interval)
            .finish()
    }
}

/// OAuth token set returned by a completed flow.
#[derive(Clone, PartialEq, Eq)]
pub struct OAuthTokens {
    /// Access token used for bearer request auth.
    pub access_token: RedactedSecret,
    /// Token type. This slice supports bearer tokens.
    pub token_type: String,
    /// Optional refresh token.
    pub refresh_token: Option<RedactedSecret>,
    /// Optional expiration timestamp.
    pub expires_at: Option<DateTime<Utc>>,
    /// Optional granted scope.
    pub scope: Option<String>,
}

impl OAuthTokens {
    /// Construct a bearer token set.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when token fields are empty or unsafe.
    pub fn bearer(
        access_token: impl Into<String>,
        expires_in: Option<StdDuration>,
        refresh_token: Option<impl Into<String>>,
        scope: Option<impl Into<String>>,
    ) -> AuthResult<Self> {
        let scope = scope.map(Into::into);
        if let Some(scope) = scope.as_deref() {
            validate_no_crlf(scope, "scope")?;
        }
        Ok(Self {
            access_token: RedactedSecret::new(access_token)?,
            token_type: "Bearer".to_string(),
            refresh_token: refresh_token.map(RedactedSecret::new).transpose()?,
            expires_at: expires_in
                .map(|ttl| expiry_from_ttl(ttl, "expires_in"))
                .transpose()?,
            scope,
        })
    }

    fn validate(&self) -> AuthResult<()> {
        validate_non_empty(&self.token_type, "token_type")?;
        validate_no_crlf(&self.token_type, "token_type")?;
        if !self.token_type.eq_ignore_ascii_case("bearer") {
            return Err(invalid_config(
                "token_type",
                "only bearer tokens are supported in this slice",
            ));
        }
        if let Some(scope) = self.scope.as_deref() {
            validate_no_crlf(scope, "scope")?;
        }
        Ok(())
    }
}

impl fmt::Debug for OAuthTokens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthTokens")
            .field("access_token", &self.access_token)
            .field("token_type", &self.token_type)
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("expires_at", &self.expires_at)
            .field("scope", &self.scope)
            .finish()
    }
}

/// OAuth refresh-token grant configuration.
#[derive(Clone, PartialEq, Eq)]
pub struct OAuthRefreshTokenConfig {
    /// OAuth client id.
    pub client_id: String,
    /// Optional client secret for confidential clients.
    pub client_secret: Option<RedactedSecret>,
    /// Token endpoint URL.
    pub token_url: String,
    /// Optional requested scope for providers that require scope on refresh.
    pub scope: Option<String>,
}

impl OAuthRefreshTokenConfig {
    /// Construct public-client refresh-token configuration.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when required fields are empty or unsafe.
    pub fn public_client(
        client_id: impl Into<String>,
        token_url: impl Into<String>,
        scope: Option<impl Into<String>>,
    ) -> AuthResult<Self> {
        Self::new(client_id, Option::<String>::None, token_url, scope)
    }

    /// Construct confidential-client refresh-token configuration.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when required fields are empty or unsafe.
    pub fn confidential_client(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        token_url: impl Into<String>,
        scope: Option<impl Into<String>>,
    ) -> AuthResult<Self> {
        Self::new(client_id, Some(client_secret.into()), token_url, scope)
    }

    /// Construct refresh-token configuration.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when required fields are empty or unsafe.
    pub fn new(
        client_id: impl Into<String>,
        client_secret: Option<impl Into<String>>,
        token_url: impl Into<String>,
        scope: Option<impl Into<String>>,
    ) -> AuthResult<Self> {
        let config = Self {
            client_id: client_id.into(),
            client_secret: client_secret.map(RedactedSecret::new).transpose()?,
            token_url: token_url.into(),
            scope: scope.map(Into::into),
        };
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> AuthResult<()> {
        validate_non_empty(&self.client_id, "client_id")?;
        validate_no_crlf(&self.client_id, "client_id")?;
        if let Some(secret) = &self.client_secret {
            validate_no_crlf(secret.expose_secret(), "client_secret")?;
        }
        parse_oauth_url(&self.token_url, "token_url")?;
        if let Some(scope) = self.scope.as_deref() {
            validate_non_empty(scope, "scope")?;
            validate_no_crlf(scope, "scope")?;
        }
        Ok(())
    }
}

impl fmt::Debug for OAuthRefreshTokenConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthRefreshTokenConfig")
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("token_url", &self.token_url)
            .field("scope", &self.scope)
            .finish()
    }
}

/// OAuth refresh-token grant.
#[derive(Clone, PartialEq, Eq)]
pub struct OAuthRefreshTokenGrant {
    /// Refresh token presented to the provider token endpoint.
    pub refresh_token: RedactedSecret,
}

impl OAuthRefreshTokenGrant {
    /// Construct a refresh-token grant.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when refresh-token material is empty or unsafe.
    pub fn new(refresh_token: impl Into<String>) -> AuthResult<Self> {
        let grant = Self {
            refresh_token: RedactedSecret::new(refresh_token)?,
        };
        grant.validate()?;
        Ok(grant)
    }

    fn validate(&self) -> AuthResult<()> {
        validate_no_crlf(self.refresh_token.expose_secret(), "refresh_token")
    }
}

impl fmt::Debug for OAuthRefreshTokenGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthRefreshTokenGrant")
            .field("refresh_token", &self.refresh_token)
            .finish()
    }
}

/// Provider response returned by a refresh-token request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OAuthRefreshProviderResponse {
    /// Refresh succeeded and returned a new token set.
    Authorized(OAuthTokens),
    /// Refresh failed with a terminal provider error.
    Rejected {
        /// Provider error code.
        code: String,
        /// Redaction-safe provider reason.
        reason: String,
    },
}

/// Transport boundary for OAuth refresh-token providers.
#[async_trait]
pub trait OAuthRefreshTokenTransport: Send + Sync {
    /// Exchange a refresh token for a fresh provider token set.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthError`] for transport failures or invalid provider responses.
    async fn refresh(
        &self,
        config: &OAuthRefreshTokenConfig,
        grant: &OAuthRefreshTokenGrant,
    ) -> AuthResult<OAuthRefreshProviderResponse>;
}

/// OAuth refresh-token flow primitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OAuthRefreshTokenFlow;

impl OAuthRefreshTokenFlow {
    /// Exchange a refresh-token grant for fresh bearer tokens.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthError`] for invalid config/grant data, transport failures,
    /// provider rejections, or malformed refreshed tokens.
    pub async fn refresh<T>(
        cx: &fcp_async_core::Cx,
        config: &OAuthRefreshTokenConfig,
        grant: &OAuthRefreshTokenGrant,
        transport: &T,
    ) -> AuthResult<OAuthTokens>
    where
        T: OAuthRefreshTokenTransport + ?Sized,
    {
        let _ = cx;
        config.validate()?;
        grant.validate()?;
        match transport.refresh(config, grant).await? {
            OAuthRefreshProviderResponse::Authorized(tokens) => {
                tokens.validate()?;
                Ok(tokens)
            }
            OAuthRefreshProviderResponse::Rejected { code, reason } => {
                validate_oauth_error(&code, &reason)?;
                Err(AuthError::ProviderRejected {
                    method: "oauth_refresh",
                    code,
                    reason,
                })
            }
        }
    }
}

/// Provider status returned when polling a device-code token endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OAuthDeviceCodeProviderResponse {
    /// User has not completed browser authorization yet.
    AuthorizationPending,
    /// Provider asked the client to increase the polling interval.
    SlowDown,
    /// User completed authorization and the provider returned tokens.
    Authorized(OAuthTokens),
    /// User denied authorization.
    AccessDenied {
        /// Redaction-safe denial reason.
        reason: String,
    },
    /// Device code expired before authorization completed.
    ExpiredToken {
        /// Redaction-safe expiry reason.
        reason: String,
    },
}

/// Public polling result returned by [`OAuthDeviceCodeFlow::poll`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OAuthDeviceCodePoll {
    /// Authorization is still pending. Caller should wait `retry_after`.
    Pending {
        /// Current retry interval.
        retry_after: StdDuration,
    },
    /// Authorization succeeded.
    Authorized(OAuthTokens),
}

/// Transport boundary for OAuth device-code providers.
#[async_trait]
pub trait OAuthDeviceCodeTransport: Send + Sync {
    /// Start a provider device-code flow.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthError`] for transport failures or invalid provider responses.
    async fn start(&self, config: &OAuthDeviceCodeConfig) -> AuthResult<OAuthDeviceCodeChallenge>;

    /// Poll a provider token endpoint.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthError`] for transport failures or invalid provider responses.
    async fn poll(
        &self,
        config: &OAuthDeviceCodeConfig,
        challenge: &OAuthDeviceCodeChallenge,
    ) -> AuthResult<OAuthDeviceCodeProviderResponse>;
}

/// OAuth device-code state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthDeviceCodeFlow {
    config: OAuthDeviceCodeConfig,
    challenge: OAuthDeviceCodeChallenge,
    poll_interval: StdDuration,
}

impl OAuthDeviceCodeFlow {
    /// Start a device-code flow through the supplied transport.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthError`] when static config is invalid or the provider
    /// returns an invalid challenge.
    pub async fn start<T>(
        cx: &fcp_async_core::Cx,
        config: OAuthDeviceCodeConfig,
        transport: &T,
    ) -> AuthResult<Self>
    where
        T: OAuthDeviceCodeTransport + ?Sized,
    {
        let _ = cx;
        config.validate()?;
        let challenge = transport.start(&config).await?;
        challenge
            .validate()
            .map_err(|error| AuthError::InvalidProviderResponse {
                method: "oauth_device",
                reason: error.to_string(),
            })?;
        if Utc::now() >= challenge.expires_at {
            return Err(AuthError::Expired {
                method: "oauth_device",
                expires_at: challenge.expires_at,
            });
        }
        Ok(Self {
            poll_interval: challenge.interval,
            config,
            challenge,
        })
    }

    /// Borrow the user-facing challenge.
    #[must_use]
    pub const fn challenge(&self) -> &OAuthDeviceCodeChallenge {
        &self.challenge
    }

    /// Return the current polling interval.
    #[must_use]
    pub const fn poll_interval(&self) -> StdDuration {
        self.poll_interval
    }

    /// Poll for authorization completion.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthError`] for terminal provider failures, expired
    /// challenges, or malformed token responses.
    pub async fn poll<T>(
        &mut self,
        cx: &fcp_async_core::Cx,
        transport: &T,
    ) -> AuthResult<OAuthDeviceCodePoll>
    where
        T: OAuthDeviceCodeTransport + ?Sized,
    {
        let _ = cx;
        if Utc::now() >= self.challenge.expires_at {
            return Err(AuthError::Expired {
                method: "oauth_device",
                expires_at: self.challenge.expires_at,
            });
        }
        match transport.poll(&self.config, &self.challenge).await? {
            OAuthDeviceCodeProviderResponse::AuthorizationPending => {
                Ok(OAuthDeviceCodePoll::Pending {
                    retry_after: self.poll_interval,
                })
            }
            OAuthDeviceCodeProviderResponse::SlowDown => {
                self.poll_interval = self
                    .poll_interval
                    .checked_add(StdDuration::from_secs(5))
                    .unwrap_or(StdDuration::MAX);
                Ok(OAuthDeviceCodePoll::Pending {
                    retry_after: self.poll_interval,
                })
            }
            OAuthDeviceCodeProviderResponse::Authorized(tokens) => {
                tokens.validate()?;
                Ok(OAuthDeviceCodePoll::Authorized(tokens))
            }
            OAuthDeviceCodeProviderResponse::AccessDenied { reason } => {
                validate_oauth_error("access_denied", &reason)?;
                Err(AuthError::ProviderRejected {
                    method: "oauth_device",
                    code: "access_denied".to_string(),
                    reason,
                })
            }
            OAuthDeviceCodeProviderResponse::ExpiredToken { reason } => {
                validate_oauth_error("expired_token", &reason)?;
                Err(AuthError::ProviderRejected {
                    method: "oauth_device",
                    code: "expired_token".to_string(),
                    reason,
                })
            }
        }
    }
}

/// OAuth authorization-code auth state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthAuthCodeAuth {
    /// OAuth client id.
    pub client_id: String,
    /// Optional client secret for confidential clients.
    pub client_secret: Option<RedactedSecret>,
    /// Authorization endpoint URL.
    pub authorize_url: String,
    /// Token endpoint URL.
    pub token_url: String,
    /// Registered redirect URI.
    pub redirect_uri: String,
    /// Requested scope string.
    pub scope: String,
    /// Whether PKCE must be used.
    pub use_pkce: bool,
    /// Extra provider-specific authorization URL parameters.
    pub extra_authorize_params: BTreeMap<String, String>,
    /// Scope the provider actually GRANTED, as reported on the token response.
    ///
    /// See [`OAuthDeviceCodeAuth::granted_scope`] for why refreshes are issued
    /// against this rather than the requested [`Self::scope`].
    pub granted_scope: Option<String>,
    /// Current access token, if the flow has completed.
    pub access_token: Option<RedactedSecret>,
    /// Current refresh token, if the provider issued one.
    pub refresh_token: Option<RedactedSecret>,
    /// Access-token expiration time.
    pub expires_at: Option<DateTime<Utc>>,
}

impl OAuthAuthCodeAuth {
    /// Construct public-client OAuth authorization-code auth state.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when OAuth fields are empty or unsafe.
    pub fn public_client(
        client_id: impl Into<String>,
        authorize_url: impl Into<String>,
        token_url: impl Into<String>,
        redirect_uri: impl Into<String>,
        scope: impl Into<String>,
        use_pkce: bool,
    ) -> AuthResult<Self> {
        let config = OAuthAuthCodeConfig::public_client(
            client_id,
            authorize_url,
            token_url,
            redirect_uri,
            scope,
            use_pkce,
        )?;
        Ok(Self::from_config(config))
    }

    /// Construct confidential-client OAuth authorization-code auth state.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when OAuth fields are empty or unsafe.
    pub fn confidential_client(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        authorize_url: impl Into<String>,
        token_url: impl Into<String>,
        redirect_uri: impl Into<String>,
        scope: impl Into<String>,
        use_pkce: bool,
    ) -> AuthResult<Self> {
        let config = OAuthAuthCodeConfig::confidential_client(
            client_id,
            client_secret,
            authorize_url,
            token_url,
            redirect_uri,
            scope,
            use_pkce,
        )?;
        Ok(Self::from_config(config))
    }

    /// Construct auth state from a validated flow config.
    #[must_use]
    pub fn from_config(config: OAuthAuthCodeConfig) -> Self {
        Self {
            client_id: config.client_id,
            client_secret: config.client_secret,
            authorize_url: config.authorize_url,
            token_url: config.token_url,
            redirect_uri: config.redirect_uri,
            scope: config.scope,
            use_pkce: config.use_pkce,
            extra_authorize_params: config.extra_authorize_params,
            granted_scope: None,
            access_token: None,
            refresh_token: None,
            expires_at: None,
        }
    }

    /// Replace cached token material after a completed auth-code exchange.
    pub fn apply_tokens(&mut self, tokens: OAuthTokens) {
        let OAuthTokens {
            access_token,
            refresh_token,
            expires_at,
            scope,
            ..
        } = tokens;
        let access_slot = &mut self.access_token;
        *access_slot = Some(access_token);
        let refresh_slot = &mut self.refresh_token;
        *refresh_slot = refresh_token;
        self.expires_at = expires_at;
        self.granted_scope = scope;
    }

    /// Build refresh-token flow configuration from this auth state.
    ///
    /// Refreshes are issued against the GRANTED scope when one was observed —
    /// see [`OAuthDeviceCodeAuth::refresh_config`].
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when stored OAuth fields are invalid.
    pub fn refresh_config(&self) -> AuthResult<OAuthRefreshTokenConfig> {
        let effective = self.granted_scope.as_deref().unwrap_or(&self.scope);
        let scope = if effective.is_empty() {
            None
        } else {
            Some(effective.to_string())
        };
        let secret_material = self
            .client_secret
            .as_ref()
            .map(|secret| secret.expose_secret().to_string());
        OAuthRefreshTokenConfig::new(
            self.client_id.clone(),
            secret_material,
            self.token_url.clone(),
            scope,
        )
    }

    /// Build a refresh-token grant from cached refresh-token material.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::MissingToken`] when the provider has not issued a refresh token.
    pub fn refresh_grant(&self) -> AuthResult<OAuthRefreshTokenGrant> {
        let Some(refresh_token) = &self.refresh_token else {
            return Err(AuthError::MissingToken {
                method: "oauth_auth_code",
            });
        };
        OAuthRefreshTokenGrant::new(refresh_token.expose_secret().to_string())
    }

    /// Refresh cached bearer tokens through an injectable refresh-token transport.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthError`] for invalid stored config, missing refresh-token
    /// material, transport failures, provider rejections, or malformed refreshed tokens.
    pub async fn refresh_with_transport<T>(
        &mut self,
        cx: &fcp_async_core::Cx,
        transport: &T,
    ) -> AuthResult<()>
    where
        T: OAuthRefreshTokenTransport + ?Sized,
    {
        self.validate_config()?;
        let config = self.refresh_config()?;
        let grant = self.refresh_grant()?;
        let tokens = OAuthRefreshTokenFlow::refresh(cx, &config, &grant, transport).await?;
        self.apply_refreshed_tokens(tokens)
    }

    fn apply_refreshed_tokens(&mut self, tokens: OAuthTokens) -> AuthResult<()> {
        let OAuthTokens {
            access_token: fresh_access,
            refresh_token: fresh_refresh,
            expires_at,
            scope,
            ..
        } = tokens;
        // Reject a widening scope before mutating anything — see
        // `OAuthDeviceCodeAuth::apply_refreshed_tokens`.
        let granted_scope = resolve_refreshed_scope(self.granted_scope.as_deref(), scope)?;

        let access_slot = &mut self.access_token;
        *access_slot = Some(fresh_access);
        if let Some(material) = fresh_refresh {
            let refresh_slot = &mut self.refresh_token;
            *refresh_slot = Some(material);
        }
        // Preserve a known expiry when the provider omits `expires_in` —
        // see the identical guard on `OAuthDeviceCodeAuth::apply_refreshed_tokens`
        // for why clobbering it to `None` silently disables both the refresh
        // loop and every downstream expiry gate.
        self.expires_at = expires_at.or(self.expires_at);
        self.granted_scope = granted_scope;
        Ok(())
    }

    fn validate_config(&self) -> AuthResult<()> {
        let config = OAuthAuthCodeConfig {
            client_id: self.client_id.clone(),
            client_secret: self.client_secret.clone(),
            authorize_url: self.authorize_url.clone(),
            token_url: self.token_url.clone(),
            redirect_uri: self.redirect_uri.clone(),
            scope: self.scope.clone(),
            use_pkce: self.use_pkce,
            extra_authorize_params: self.extra_authorize_params.clone(),
        };
        config.validate()
    }
}

#[async_trait]
impl AuthMethod for OAuthAuthCodeAuth {
    fn id(&self) -> &'static str {
        "oauth_auth_code"
    }

    async fn validate(&self, _cx: &fcp_async_core::Cx) -> AuthResult<()> {
        self.validate_config()
    }

    async fn build_request_auth(
        &self,
        cx: &fcp_async_core::Cx,
        request: &mut AuthRequest,
    ) -> AuthResult<()> {
        self.validate(cx).await?;
        apply_bearer_token(
            self.id(),
            self.access_token.as_ref(),
            self.expires_at,
            request,
        )
    }

    fn requires_refresh_in(&self) -> Option<StdDuration> {
        self.expires_at.map(std_duration_until)
    }
}

/// OAuth authorization-code flow configuration.
#[derive(Clone, PartialEq, Eq)]
pub struct OAuthAuthCodeConfig {
    /// OAuth client id.
    pub client_id: String,
    /// Optional client secret for confidential clients.
    pub client_secret: Option<RedactedSecret>,
    /// Authorization endpoint URL.
    pub authorize_url: String,
    /// Token endpoint URL.
    pub token_url: String,
    /// Registered redirect URI.
    pub redirect_uri: String,
    /// Requested scope string. Empty scope is allowed for provider defaults.
    pub scope: String,
    /// Whether to include S256 PKCE in the authorization request and exchange.
    pub use_pkce: bool,
    /// Extra provider-specific authorization URL parameters.
    pub extra_authorize_params: BTreeMap<String, String>,
}

impl OAuthAuthCodeConfig {
    /// Construct public-client authorization-code flow configuration.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when required fields are empty or unsafe.
    pub fn public_client(
        client_id: impl Into<String>,
        authorize_url: impl Into<String>,
        token_url: impl Into<String>,
        redirect_uri: impl Into<String>,
        scope: impl Into<String>,
        use_pkce: bool,
    ) -> AuthResult<Self> {
        Self::new(
            client_id,
            Option::<String>::None,
            authorize_url,
            token_url,
            redirect_uri,
            scope,
            use_pkce,
        )
    }

    /// Construct confidential-client authorization-code flow configuration.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when required fields are empty or unsafe.
    pub fn confidential_client(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        authorize_url: impl Into<String>,
        token_url: impl Into<String>,
        redirect_uri: impl Into<String>,
        scope: impl Into<String>,
        use_pkce: bool,
    ) -> AuthResult<Self> {
        Self::new(
            client_id,
            Some(client_secret.into()),
            authorize_url,
            token_url,
            redirect_uri,
            scope,
            use_pkce,
        )
    }

    /// Construct authorization-code flow configuration.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when required fields are empty or unsafe.
    pub fn new(
        client_id: impl Into<String>,
        client_secret: Option<impl Into<String>>,
        authorize_url: impl Into<String>,
        token_url: impl Into<String>,
        redirect_uri: impl Into<String>,
        scope: impl Into<String>,
        use_pkce: bool,
    ) -> AuthResult<Self> {
        let config = Self {
            client_id: client_id.into(),
            client_secret: client_secret.map(RedactedSecret::new).transpose()?,
            authorize_url: authorize_url.into(),
            token_url: token_url.into(),
            redirect_uri: redirect_uri.into(),
            scope: scope.into(),
            use_pkce,
            extra_authorize_params: BTreeMap::new(),
        };
        config.validate()?;
        Ok(config)
    }

    /// Add one provider-specific authorization URL parameter.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when the parameter is empty, unsafe,
    /// or attempts to override a standard OAuth field owned by this config.
    pub fn with_authorize_param(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> AuthResult<Self> {
        let name = name.into();
        let value = value.into();
        validate_authorize_param(&name, &value)?;
        self.extra_authorize_params.insert(name, value);
        Ok(self)
    }

    fn validate(&self) -> AuthResult<()> {
        validate_non_empty(&self.client_id, "client_id")?;
        validate_no_crlf(&self.client_id, "client_id")?;
        if let Some(secret) = &self.client_secret {
            validate_no_crlf(secret.expose_secret(), "client_secret")?;
        }
        parse_oauth_url(&self.authorize_url, "authorize_url")?;
        parse_oauth_url(&self.token_url, "token_url")?;
        parse_oauth_url(&self.redirect_uri, "redirect_uri")?;
        validate_no_crlf(&self.scope, "scope")?;
        for (name, value) in &self.extra_authorize_params {
            validate_authorize_param(name, value)?;
        }
        Ok(())
    }
}

fn validate_authorize_param(name: &str, value: &str) -> AuthResult<()> {
    validate_non_empty(name, "authorize_param")?;
    validate_no_crlf(name, "authorize_param")?;
    validate_non_empty(value, "authorize_param")?;
    validate_no_crlf(value, "authorize_param")?;
    match name {
        "response_type"
        | "client_id"
        | "redirect_uri"
        | "scope"
        | "state"
        | "code_challenge"
        | "code_challenge_method" => Err(invalid_config(
            "authorize_param",
            "must not override standard OAuth authorization parameters",
        )),
        _ => Ok(()),
    }
}

impl fmt::Debug for OAuthAuthCodeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthAuthCodeConfig")
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("authorize_url", &self.authorize_url)
            .field("token_url", &self.token_url)
            .field("redirect_uri", &self.redirect_uri)
            .field("scope", &self.scope)
            .field("use_pkce", &self.use_pkce)
            .field("extra_authorize_params", &self.extra_authorize_params)
            .finish()
    }
}

/// PKCE code-challenge method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthPkceChallengeMethod {
    /// SHA-256 based `S256` challenge.
    S256,
}

impl fmt::Display for OAuthPkceChallengeMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::S256 => f.write_str("S256"),
        }
    }
}

/// Redaction-safe PKCE verifier/challenge pair.
#[derive(Clone, PartialEq, Eq)]
pub struct OAuthPkce {
    /// Secret code verifier used at token exchange.
    pub verifier: RedactedSecret,
    /// Public code challenge sent in the authorization URL.
    pub challenge: String,
    /// Challenge method.
    pub method: OAuthPkceChallengeMethod,
}

impl OAuthPkce {
    /// Generate a random S256 PKCE verifier and challenge.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] if generated material fails validation.
    pub fn generate() -> AuthResult<Self> {
        let mut bytes = [0_u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self::from_verifier(URL_SAFE_NO_PAD.encode(bytes))
    }

    /// Build S256 PKCE material from an existing verifier.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when the verifier violates RFC 7636
    /// length or character constraints.
    pub fn from_verifier(verifier: impl Into<String>) -> AuthResult<Self> {
        let verifier = verifier.into();
        validate_pkce_verifier(&verifier)?;
        let challenge = pkce_s256_challenge(&verifier);
        Ok(Self {
            verifier: RedactedSecret::new(verifier)?,
            challenge,
            method: OAuthPkceChallengeMethod::S256,
        })
    }
}

impl fmt::Debug for OAuthPkce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthPkce")
            .field("verifier", &self.verifier)
            .field("challenge", &self.challenge)
            .field("method", &self.method)
            .finish()
    }
}

/// Authorization URL plus callback validation state.
#[derive(Clone, PartialEq, Eq)]
pub struct OAuthAuthCodeRequest {
    authorization_url: String,
    state: RedactedSecret,
    pkce: Option<OAuthPkce>,
}

impl OAuthAuthCodeRequest {
    /// Borrow the user-facing authorization URL.
    #[must_use]
    pub fn authorization_url(&self) -> &str {
        &self.authorization_url
    }

    /// Borrow the expected callback state.
    #[must_use]
    pub const fn state(&self) -> &RedactedSecret {
        &self.state
    }

    /// Borrow PKCE material, when enabled.
    #[must_use]
    pub const fn pkce(&self) -> Option<&OAuthPkce> {
        self.pkce.as_ref()
    }
}

impl fmt::Debug for OAuthAuthCodeRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthAuthCodeRequest")
            .field("authorization_url", &"[REDACTED]")
            .field("state", &self.state)
            .field("pkce", &self.pkce.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

/// OAuth authorization-code callback payload.
#[derive(Clone, PartialEq, Eq)]
pub enum OAuthAuthCodeCallback {
    /// Provider returned an authorization code.
    Authorized {
        /// Secret authorization code.
        code: RedactedSecret,
        /// Callback state.
        state: String,
    },
    /// Provider returned an OAuth error.
    Rejected {
        /// Provider error code.
        error: String,
        /// Optional redaction-safe error description.
        description: Option<String>,
        /// Optional callback state.
        state: Option<String>,
    },
}

impl OAuthAuthCodeCallback {
    /// Construct an authorized callback.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when the code or state is empty or unsafe.
    pub fn authorized(code: impl Into<String>, state: impl Into<String>) -> AuthResult<Self> {
        let state = state.into();
        validate_oauth_state(&state)?;
        Ok(Self::Authorized {
            code: RedactedSecret::new(code)?,
            state,
        })
    }

    /// Construct a rejected callback.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when provider fields are empty or unsafe.
    pub fn rejected(
        error: impl Into<String>,
        description: Option<impl Into<String>>,
        state: Option<impl Into<String>>,
    ) -> AuthResult<Self> {
        let error = error.into();
        validate_non_empty(&error, "oauth_error_code")?;
        validate_no_crlf(&error, "oauth_error_code")?;
        let description = description.map(Into::into);
        if let Some(description) = description.as_deref() {
            validate_no_crlf(description, "oauth_error_reason")?;
        }
        let state = state.map(Into::into);
        if let Some(state) = state.as_deref() {
            validate_oauth_state(state)?;
        }
        Ok(Self::Rejected {
            error,
            description,
            state,
        })
    }
}

impl fmt::Debug for OAuthAuthCodeCallback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authorized { code, state: _ } => f
                .debug_struct("OAuthAuthCodeCallback::Authorized")
                .field("code", code)
                .field("state", &"[REDACTED]")
                .finish(),
            Self::Rejected {
                error,
                description,
                state,
            } => f
                .debug_struct("OAuthAuthCodeCallback::Rejected")
                .field("error", error)
                .field("description", description)
                .field("state", &state.as_ref().map(|_| "[REDACTED]"))
                .finish(),
        }
    }
}

/// Validated authorization code ready for token exchange.
#[derive(Clone, PartialEq, Eq)]
pub struct OAuthAuthCodeGrant {
    /// Secret authorization code.
    pub code: RedactedSecret,
    /// Callback state that matched the request state.
    pub state: RedactedSecret,
}

impl fmt::Debug for OAuthAuthCodeGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthAuthCodeGrant")
            .field("code", &self.code)
            .field("state", &self.state)
            .finish()
    }
}

/// Provider response returned by an authorization-code token endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OAuthAuthCodeProviderResponse {
    /// Token exchange succeeded.
    Authorized(OAuthTokens),
    /// Token exchange failed with a terminal provider error.
    Rejected {
        /// Provider error code.
        code: String,
        /// Redaction-safe provider reason.
        reason: String,
    },
}

/// Transport boundary for OAuth authorization-code providers.
#[async_trait]
pub trait OAuthAuthCodeTransport: Send + Sync {
    /// Exchange an authorization code for tokens.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthError`] for transport failures or invalid provider responses.
    async fn exchange(
        &self,
        config: &OAuthAuthCodeConfig,
        grant: &OAuthAuthCodeGrant,
        pkce: Option<&OAuthPkce>,
    ) -> AuthResult<OAuthAuthCodeProviderResponse>;
}

/// OAuth authorization-code state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthAuthCodeFlow {
    config: OAuthAuthCodeConfig,
    request: OAuthAuthCodeRequest,
}

impl OAuthAuthCodeFlow {
    /// Start an authorization-code flow with generated state and optional PKCE.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthError`] when static config or generated PKCE material is invalid.
    pub fn start(config: OAuthAuthCodeConfig) -> AuthResult<Self> {
        Self::start_with_state(config, generate_url_safe_secret())
    }

    /// Start an authorization-code flow with caller-supplied state.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthError`] when static config, state, or generated PKCE material is invalid.
    pub fn start_with_state(
        config: OAuthAuthCodeConfig,
        state: impl Into<String>,
    ) -> AuthResult<Self> {
        let pkce = if config.use_pkce {
            Some(OAuthPkce::generate()?)
        } else {
            None
        };
        Self::start_with_state_and_pkce(config, state, pkce)
    }

    /// Start an authorization-code flow with caller-supplied state and PKCE material.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthError`] when static config, state, or PKCE state is invalid.
    pub fn start_with_state_and_pkce(
        config: OAuthAuthCodeConfig,
        state: impl Into<String>,
        pkce: Option<OAuthPkce>,
    ) -> AuthResult<Self> {
        config.validate()?;
        if config.use_pkce && pkce.is_none() {
            return Err(invalid_config("pkce", "PKCE material is required"));
        }
        if !config.use_pkce && pkce.is_some() {
            return Err(invalid_config(
                "pkce",
                "PKCE material supplied while PKCE is disabled",
            ));
        }
        let state = state.into();
        validate_oauth_state(&state)?;
        let request = build_authorization_request(&config, RedactedSecret::new(state)?, pkce)?;
        Ok(Self { config, request })
    }

    /// Borrow the authorization request.
    #[must_use]
    pub const fn request(&self) -> &OAuthAuthCodeRequest {
        &self.request
    }

    /// Validate a provider callback and extract the authorization grant.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthError`] for provider rejection, state mismatch, or unsafe callback fields.
    pub fn complete_callback(
        &self,
        callback: OAuthAuthCodeCallback,
    ) -> AuthResult<OAuthAuthCodeGrant> {
        match callback {
            OAuthAuthCodeCallback::Authorized { code, state } => {
                self.ensure_state_matches(Some(&state))?;
                validate_no_crlf(code.expose_secret(), "authorization_code")?;
                Ok(OAuthAuthCodeGrant {
                    code,
                    state: RedactedSecret::new(state)?,
                })
            }
            OAuthAuthCodeCallback::Rejected {
                error,
                description,
                state,
            } => {
                self.ensure_state_matches(state.as_deref())?;
                let reason = description.unwrap_or_else(|| error.clone());
                validate_oauth_error(&error, &reason)?;
                Err(AuthError::ProviderRejected {
                    method: "oauth_auth_code",
                    code: error,
                    reason,
                })
            }
        }
    }

    /// Exchange an authorization grant for tokens.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthError`] for transport failures, provider rejections, or malformed tokens.
    pub async fn exchange<T>(
        &self,
        cx: &fcp_async_core::Cx,
        transport: &T,
        grant: &OAuthAuthCodeGrant,
    ) -> AuthResult<OAuthTokens>
    where
        T: OAuthAuthCodeTransport + ?Sized,
    {
        let _ = cx;
        match transport
            .exchange(&self.config, grant, self.request.pkce())
            .await?
        {
            OAuthAuthCodeProviderResponse::Authorized(tokens) => {
                tokens.validate()?;
                Ok(tokens)
            }
            OAuthAuthCodeProviderResponse::Rejected { code, reason } => {
                validate_oauth_error(&code, &reason)?;
                Err(AuthError::ProviderRejected {
                    method: "oauth_auth_code",
                    code,
                    reason,
                })
            }
        }
    }

    fn ensure_state_matches(&self, state: Option<&str>) -> AuthResult<()> {
        let Some(state) = state else {
            return Err(AuthError::InvalidProviderResponse {
                method: "oauth_auth_code",
                reason: "callback state missing".to_string(),
            });
        };
        validate_oauth_state(state)?;
        if state != self.request.state.expose_secret() {
            return Err(AuthError::InvalidProviderResponse {
                method: "oauth_auth_code",
                reason: "callback state mismatch".to_string(),
            });
        }
        Ok(())
    }
}

/// Short-lived setup-token auth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupTokenAuth {
    /// Setup token.
    pub token: RedactedSecret,
    /// Expiration timestamp.
    pub expires_at: DateTime<Utc>,
    /// Header that receives the token.
    pub header_name: String,
}

impl SetupTokenAuth {
    /// Construct setup-token auth using bearer `Authorization`.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when the token or header is invalid.
    pub fn bearer(token: impl Into<String>, expires_at: DateTime<Utc>) -> AuthResult<Self> {
        Self::new(token, expires_at, "Authorization")
    }

    /// Construct setup-token auth with a custom header.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when the token or header is invalid.
    pub fn new(
        token: impl Into<String>,
        expires_at: DateTime<Utc>,
        header_name: impl Into<String>,
    ) -> AuthResult<Self> {
        let header_name = header_name.into();
        validate_header_name(&header_name)?;
        Ok(Self {
            token: RedactedSecret::new(token)?,
            expires_at,
            header_name,
        })
    }

    fn ensure_live(&self) -> AuthResult<()> {
        if Utc::now() >= self.expires_at {
            return Err(AuthError::Expired {
                method: "setup_token",
                expires_at: self.expires_at,
            });
        }
        Ok(())
    }
}

#[async_trait]
impl AuthMethod for SetupTokenAuth {
    fn id(&self) -> &'static str {
        "setup_token"
    }

    async fn validate(&self, _cx: &fcp_async_core::Cx) -> AuthResult<()> {
        self.ensure_live()
    }

    async fn build_request_auth(
        &self,
        cx: &fcp_async_core::Cx,
        request: &mut AuthRequest,
    ) -> AuthResult<()> {
        self.validate(cx).await?;
        request.set_header(
            self.header_name.clone(),
            format!("Bearer {}", self.token.expose_secret()),
        )
    }

    fn requires_refresh_in(&self) -> Option<StdDuration> {
        Some(std_duration_until(self.expires_at))
    }
}

/// Cached JWT token plus expiration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwtCachedToken {
    /// Generated JWT.
    pub token: RedactedSecret,
    /// Expiration timestamp.
    pub expires_at: DateTime<Utc>,
}

/// JWT generator auth.
#[derive(Clone)]
pub struct JwtAuth {
    /// Stable method id suffix for diagnostics.
    pub id: String,
    /// Token TTL.
    pub ttl: StdDuration,
    generator: Arc<dyn Fn() -> AuthResult<String> + Send + Sync>,
    cached_token: Arc<RwLock<Option<JwtCachedToken>>>,
}

impl JwtAuth {
    /// Construct a JWT auth method from a token generator.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when `id` is empty or `ttl` is zero.
    pub fn new(
        id: impl Into<String>,
        ttl: StdDuration,
        generator: impl Fn() -> AuthResult<String> + Send + Sync + 'static,
    ) -> AuthResult<Self> {
        let id = id.into();
        validate_non_empty(&id, "jwt_id")?;
        if ttl.is_zero() {
            return Err(invalid_config("ttl", "must be greater than zero"));
        }
        Ok(Self {
            id,
            ttl,
            generator: Arc::new(generator),
            cached_token: Arc::new(RwLock::new(None)),
        })
    }

    /// Return the cached token snapshot, if present.
    #[must_use]
    pub fn cached_token(&self) -> Option<JwtCachedToken> {
        self.cached_token.read().clone()
    }

    fn regenerate_jwt(&self) -> AuthResult<JwtCachedToken> {
        let jwt = RedactedSecret::new((self.generator)()?)?;
        let expires_at = expiry_from_ttl(self.ttl, "ttl")?;
        let cached = JwtCachedToken {
            token: jwt,
            expires_at,
        };
        *self.cached_token.write() = Some(cached.clone());
        Ok(cached)
    }

    fn jwt_material(&self) -> AuthResult<RedactedSecret> {
        if let Some(cached) = self.cached_token.read().as_ref() {
            if Utc::now() < cached.expires_at {
                return Ok(cached.token.clone());
            }
        }

        Ok(self.regenerate_jwt()?.token)
    }
}

impl fmt::Debug for JwtAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwtAuth")
            .field("id", &self.id)
            .field("ttl", &self.ttl)
            .field("cached_token", &self.cached_token())
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl AuthMethod for JwtAuth {
    fn id(&self) -> &'static str {
        "jwt"
    }

    async fn validate(&self, _cx: &fcp_async_core::Cx) -> AuthResult<()> {
        validate_non_empty(&self.id, "jwt_id")?;
        if self.ttl.is_zero() {
            return Err(invalid_config("ttl", "must be greater than zero"));
        }
        Ok(())
    }

    async fn build_request_auth(
        &self,
        cx: &fcp_async_core::Cx,
        request: &mut AuthRequest,
    ) -> AuthResult<()> {
        self.validate(cx).await?;
        let jwt = self.jwt_material()?;
        request.set_header("Authorization", format!("Bearer {}", jwt.expose_secret()))
    }

    fn requires_refresh_in(&self) -> Option<StdDuration> {
        self.cached_token()
            .map(|cached| std_duration_until(cached.expires_at))
    }

    async fn refresh(&mut self, cx: &fcp_async_core::Cx) -> AuthResult<()> {
        self.validate(cx).await?;
        self.regenerate_jwt()?;
        Ok(())
    }
}

/// Result of applying AWS `SigV4` signing to request headers.
#[derive(Clone, PartialEq, Eq)]
pub struct SigV4SignedAuth {
    /// Authorization header value.
    pub authorization: String,
    /// Timestamp used for `x-amz-date`.
    pub x_amz_date: String,
    /// Payload hash used for `x-amz-content-sha256`.
    pub x_amz_content_sha256: String,
    /// Optional temporary-security session token header.
    pub x_amz_security_token: Option<String>,
    /// Semicolon-separated canonical signed header names.
    pub signed_headers: String,
}

impl fmt::Debug for SigV4SignedAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `authorization` embeds `Credential=<ACCESS_KEY_ID>/<scope>` plus the
        // request signature. `SigV4Auth` keeps `access_key` in a
        // `RedactedSecret` precisely so it never reaches a log line, so
        // printing the header verbatim here would have leaked it right back
        // out through any `format!("{signed:?}")`.
        f.debug_struct("SigV4SignedAuth")
            .field("authorization", &"[REDACTED]")
            .field("x_amz_date", &self.x_amz_date)
            .field("x_amz_content_sha256", &self.x_amz_content_sha256)
            .field(
                "x_amz_security_token",
                &self.x_amz_security_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("signed_headers", &self.signed_headers)
            .finish()
    }
}

/// Number of URI-encoding passes applied to the canonical request's path.
///
/// Mirrors `fcp_sdk::sigv4::CanonicalPathEncoding`; the two crates sign the
/// same resource and must agree byte-for-byte on how the path is rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalPathEncoding {
    /// Encode each path segment once — Amazon S3.
    Single,
    /// Encode each path segment twice — every other AWS service.
    Double,
}

/// Whether the canonical URI path has RFC 3986 dot segments resolved.
///
/// A second, independent axis from [`CanonicalPathEncoding`], and independent in
/// AWS's own signer too: `aws-c-auth` carries `should_normalize_uri_path` and
/// `use_double_uri_encode` as separate flags.
///
/// S3 treats the path as an opaque object key, so `/a/../b` names a literal key
/// containing `..` and must be signed as written; every other service resolves it
/// to `/b` before signing.
///
/// Mirrors `fcp_sdk::sigv4::CanonicalPathNormalization`; the two crates sign the
/// same resource and must agree byte-for-byte on how the path is rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalPathNormalization {
    /// Resolve `.` / `..` and collapse duplicate slashes — every service but S3.
    RemoveDotSegments,
    /// Sign the path exactly as supplied — Amazon S3.
    Preserve,
}

/// Per-call overrides for [`SigV4Auth::sign_traced`].
///
/// These are signing-call options, deliberately NOT fields on [`SigV4Auth`].
/// `SigV4Auth` is a credential/config value that derives `PartialEq`, so folding
/// behaviour knobs into it would make two otherwise-identical auth
/// configurations compare unequal over a difference that is not part of the
/// credential at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigV4SigningOptions {
    /// Overrides the service-derived path-normalisation profile when set.
    ///
    /// Production callers should leave this `None`:
    /// [`SigV4Auth::canonical_path_normalization`] derives it from the service
    /// name. It exists so the signer can be driven per case against AWS's
    /// published vectors, which carry the profile in each case's
    /// `context.normalize` while every case names the same service.
    pub path_normalization: Option<CanonicalPathNormalization>,
    /// Whether `x-amz-content-sha256` joins the signed header set. Default
    /// `true`.
    ///
    /// Set `false` to sign exactly the headers supplied. AWS's published vectors
    /// sign a service that does not carry the header, so leaving it in makes
    /// every vector mismatch for a reason unrelated to the canonicalisation
    /// rules they exist to pin.
    pub sign_content_sha256_header: bool,
    /// Sign without `x-amz-security-token`, leaving the caller to add the token
    /// to the request *after* signing. Default `false`.
    ///
    /// This is AWS's own `omit_session_token` signing flag. The token is omitted
    /// from the *signature*, not from the request:
    /// [`SigV4SignedAuth::x_amz_security_token`] is still populated.
    pub omit_session_token: bool,
}

impl Default for SigV4SigningOptions {
    fn default() -> Self {
        Self {
            path_normalization: None,
            sign_content_sha256_header: true,
            omit_session_token: false,
        }
    }
}

/// Intermediate artifacts produced by one `SigV4` signing pass.
///
/// `SigV4` is a pipeline — canonical request, then string-to-sign, then
/// signature — and each stage hashes into the next. Comparing only the final
/// signature against a reference tells you *that* a signer diverged but not
/// *where*, because every stage collapses into an opaque hex digest.
///
/// Mirrors `fcp_sdk::sigv4::SigV4Trace`, so one differential harness can drive
/// both signers and localise a mismatch to a single stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigV4Trace {
    /// Canonical request (AWS "Task 1").
    pub canonical_request: String,
    /// String to sign (AWS "Task 2").
    pub string_to_sign: String,
    /// Hex-encoded signature (AWS "Task 3").
    pub signature: String,
    /// Semicolon-joined lowercase signed header names.
    pub signed_headers: String,
    /// `<date>/<region>/<service>/aws4_request`.
    pub credential_scope: String,
}

/// AWS `SigV4` auth configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigV4Auth {
    /// Access key id.
    pub access_key: RedactedSecret,
    /// Secret access key.
    pub secret_key: RedactedSecret,
    /// Optional session token.
    pub session_token: Option<RedactedSecret>,
    /// AWS region.
    pub region: String,
    /// AWS service id.
    pub service: String,
}

impl SigV4Auth {
    /// Construct `SigV4` auth configuration.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when any required field is empty.
    pub fn new(
        access_key: impl Into<String>,
        signing_key: impl Into<String>,
        session_token: Option<impl Into<String>>,
        region: impl Into<String>,
        service: impl Into<String>,
    ) -> AuthResult<Self> {
        let region = region.into();
        let service = service.into();
        validate_non_empty(&region, "region")?;
        validate_non_empty(&service, "service")?;
        Ok(Self {
            access_key: RedactedSecret::new(access_key)?,
            secret_key: RedactedSecret::new(signing_key)?,
            session_token: session_token.map(RedactedSecret::new).transpose()?,
            region: region.to_ascii_lowercase(),
            service: service.to_ascii_lowercase(),
        })
    }

    /// How many times this service's canonical URI path is encoded.
    ///
    /// `SigV4` requires each path segment to be URI-encoded **twice** for every
    /// service except Amazon S3, which requires exactly **once**. Signing S3
    /// with the double-encoded form (or anything else with the single-encoded
    /// form) produces a canonical request the service will not reproduce, and
    /// the request is rejected with `SignatureDoesNotMatch`.
    ///
    /// The comparison is case-insensitive because `service` is a public field:
    /// [`SigV4Auth::new`] lowercases it, but a struct literal does not.
    #[must_use]
    pub fn canonical_path_encoding(&self) -> CanonicalPathEncoding {
        if self.service.eq_ignore_ascii_case("s3") {
            CanonicalPathEncoding::Single
        } else {
            CanonicalPathEncoding::Double
        }
    }

    /// Whether this service's canonical URI has dot segments resolved.
    ///
    /// Same S3-vs-everything-else split as [`Self::canonical_path_encoding`], and
    /// case-insensitive for the same reason.
    ///
    /// S3 stays on `Preserve` and that is the point of the split, not an
    /// optimisation: an S3 object key may legitimately contain `..` or a double
    /// slash, so `/a/../b` names a literal key there while every other service
    /// resolves it to `/b`.
    #[must_use]
    pub fn canonical_path_normalization(&self) -> CanonicalPathNormalization {
        if self.service.eq_ignore_ascii_case("s3") {
            CanonicalPathNormalization::Preserve
        } else {
            CanonicalPathNormalization::RemoveDotSegments
        }
    }

    /// Sign a request context and return the headers `SigV4` must apply.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthError`] when required request context or headers are invalid.
    pub fn sign(
        &self,
        context: &SigV4SigningContext,
        request_headers: &BTreeMap<String, String>,
    ) -> AuthResult<SigV4SignedAuth> {
        self.sign_traced(context, request_headers, SigV4SigningOptions::default())
            .map(|(signed, _trace)| signed)
    }

    /// Sign a request context, additionally returning every intermediate
    /// artifact.
    ///
    /// Same computation as [`Self::sign`], which delegates here with
    /// [`SigV4SigningOptions::default`]; see [`SigV4Trace`] for why the
    /// intermediates are worth surfacing.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthError`] when required request context or headers are invalid.
    pub fn sign_traced(
        &self,
        context: &SigV4SigningContext,
        request_headers: &BTreeMap<String, String>,
        options: SigV4SigningOptions,
    ) -> AuthResult<(SigV4SignedAuth, SigV4Trace)> {
        validate_non_empty(&self.region, "region")?;
        validate_non_empty(&self.service, "service")?;
        let signing_time = context.signing_time.unwrap_or_else(Utc::now);
        let date_stamp = signing_time.format("%Y%m%d").to_string();
        let amz_date = signing_time.format("%Y%m%dT%H%M%SZ").to_string();
        let credential_scope =
            format!("{date_stamp}/{}/{}/aws4_request", self.region, self.service);

        let mut headers = request_headers.clone();
        headers.insert("x-amz-date".to_string(), amz_date.clone());
        if options.sign_content_sha256_header {
            headers.insert(
                "x-amz-content-sha256".to_string(),
                context.payload_hash.clone(),
            );
        }
        if let Some(session_token) = &self.session_token {
            if !options.omit_session_token {
                headers.insert(
                    "x-amz-security-token".to_string(),
                    session_token.expose_secret().to_string(),
                );
            }
        }

        let (canonical_headers, signed_headers) = canonical_headers(&headers)?;
        let canonical_request = canonical_request(
            context,
            &canonical_headers,
            &signed_headers,
            self.canonical_path_encoding(),
            options
                .path_normalization
                .unwrap_or_else(|| self.canonical_path_normalization()),
        );
        let canonical_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));
        let string_to_sign =
            format!("{SIGV4_ALGORITHM}\n{amz_date}\n{credential_scope}\n{canonical_hash}");
        let signing_key = self.derive_signing_key(&date_stamp);
        let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));
        // `", "` after each comma, matching AWS's own documented examples and
        // `fcp_sdk::sigv4`. Both spacings are accepted by AWS — the Authorization
        // header is not part of the signed material — but the two crates emitting
        // different bytes meant a golden header captured from one could not be
        // reused against the other, which is a trap for exactly the kind of
        // cross-crate fixture sharing this parity work exists to enable.
        let authorization = format!(
            "{SIGV4_ALGORITHM} Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
            self.access_key.expose_secret(),
        );

        Ok((
            SigV4SignedAuth {
                authorization,
                x_amz_date: amz_date,
                x_amz_content_sha256: context.payload_hash.clone(),
                // Populated even when `omit_session_token` is set: the token is
                // omitted from the signature, not from the request.
                x_amz_security_token: self
                    .session_token
                    .as_ref()
                    .map(|token| token.expose_secret().to_string()),
                signed_headers: signed_headers.clone(),
            },
            SigV4Trace {
                canonical_request,
                string_to_sign,
                signature,
                signed_headers,
                credential_scope,
            },
        ))
    }

    fn derive_signing_key(&self, date_stamp: &str) -> Vec<u8> {
        let key_for_date = hmac_sha256(
            format!("AWS4{}", self.secret_key.expose_secret()).as_bytes(),
            date_stamp.as_bytes(),
        );
        let key_for_region = hmac_sha256(&key_for_date, self.region.as_bytes());
        let key_for_service = hmac_sha256(&key_for_region, self.service.as_bytes());
        hmac_sha256(&key_for_service, b"aws4_request")
    }
}

#[async_trait]
impl AuthMethod for SigV4Auth {
    fn id(&self) -> &'static str {
        "sigv4"
    }

    async fn validate(&self, _cx: &fcp_async_core::Cx) -> AuthResult<()> {
        validate_non_empty(&self.region, "region")?;
        validate_non_empty(&self.service, "service")
    }

    async fn build_request_auth(
        &self,
        _cx: &fcp_async_core::Cx,
        request: &mut AuthRequest,
    ) -> AuthResult<()> {
        let context = request
            .sigv4_context()
            .ok_or_else(|| AuthError::MissingSigningContext { method: self.id() })?;
        let signed = self.sign(context, request.headers())?;
        request.set_header("x-amz-date", signed.x_amz_date)?;
        request.set_header("x-amz-content-sha256", signed.x_amz_content_sha256)?;
        if let Some(session_token) = signed.x_amz_security_token {
            request.set_header("x-amz-security-token", session_token)?;
        }
        request.set_header("Authorization", signed.authorization)
    }

    fn requires_refresh_in(&self) -> Option<StdDuration> {
        None
    }
}

/// Hash request payload bytes as lowercase SHA-256 hex.
#[must_use]
pub fn sha256_payload_hex(payload: &[u8]) -> String {
    hex::encode(Sha256::digest(payload))
}

/// Provider-specific constructors for common auth profile shapes.
///
/// These helpers compose the core auth primitives without performing network
/// I/O or reading provider-local credential files.
pub mod providers {
    use std::time::Duration as StdDuration;

    use super::{
        ApiKeyAuth, AuthMethodKind, AuthProfile, AuthResult, JwtAuth, OAuthAuthCodeAuth,
        OAuthAuthCodeConfig, OAuthDeviceCodeAuth, OAuthDeviceCodeConfig, RedactedSecret, SigV4Auth,
    };

    fn profile(
        provider: &'static str,
        profile_id: impl Into<String>,
        method: AuthMethodKind,
        label: impl Into<String>,
        priority: i32,
    ) -> AuthResult<AuthProfile> {
        AuthProfile::new(profile_id, provider, method, label, priority)
    }

    /// Anthropic provider helpers.
    pub mod anthropic {
        use super::{
            ApiKeyAuth, AuthMethodKind, AuthProfile, AuthResult, OAuthDeviceCodeAuth,
            OAuthDeviceCodeConfig, profile,
        };

        /// Canonical provider id for Anthropic profiles.
        pub const PROVIDER_ID: &str = "anthropic";
        /// Anthropic API-key header.
        pub const API_KEY_HEADER: &str = "x-api-key";

        /// Build an Anthropic API-key method.
        ///
        /// # Errors
        ///
        /// Returns [`crate::AuthError`] when API-key material or headers are invalid.
        pub fn api_key_method(api_key: impl Into<String>) -> AuthResult<AuthMethodKind> {
            Ok(AuthMethodKind::ApiKey(ApiKeyAuth::new(
                api_key,
                API_KEY_HEADER,
                Option::<String>::None,
            )?))
        }

        /// Build an Anthropic API-key auth profile.
        ///
        /// # Errors
        ///
        /// Returns [`crate::AuthError`] when profile or API-key fields are invalid.
        pub fn api_key_profile(
            profile_id: impl Into<String>,
            label: impl Into<String>,
            priority: i32,
            api_key: impl Into<String>,
        ) -> AuthResult<AuthProfile> {
            profile(
                PROVIDER_ID,
                profile_id,
                api_key_method(api_key)?,
                label,
                priority,
            )
        }

        /// Build Anthropic device-code flow config from caller-supplied endpoints.
        ///
        /// # Errors
        ///
        /// Returns [`crate::AuthError`] when OAuth config fields are invalid.
        pub fn device_code_config(
            client_id: impl Into<String>,
            device_code_url: impl Into<String>,
            token_url: impl Into<String>,
            scope: impl Into<String>,
        ) -> AuthResult<OAuthDeviceCodeConfig> {
            OAuthDeviceCodeConfig::new(client_id, device_code_url, token_url, scope)
        }

        /// Build an Anthropic OAuth device-code method.
        ///
        /// # Errors
        ///
        /// Returns [`crate::AuthError`] when OAuth config fields are invalid.
        pub fn device_code_method(
            client_id: impl Into<String>,
            device_code_url: impl Into<String>,
            token_url: impl Into<String>,
            scope: impl Into<String>,
        ) -> AuthResult<AuthMethodKind> {
            Ok(AuthMethodKind::OAuthDeviceCode(
                OAuthDeviceCodeAuth::from_config(device_code_config(
                    client_id,
                    device_code_url,
                    token_url,
                    scope,
                )?),
            ))
        }

        /// Build an Anthropic OAuth device-code auth profile.
        ///
        /// # Errors
        ///
        /// Returns [`crate::AuthError`] when profile or OAuth fields are invalid.
        pub fn device_code_profile(
            profile_id: impl Into<String>,
            label: impl Into<String>,
            priority: i32,
            client_id: impl Into<String>,
            device_code_url: impl Into<String>,
            token_url: impl Into<String>,
            scope: impl Into<String>,
        ) -> AuthResult<AuthProfile> {
            profile(
                PROVIDER_ID,
                profile_id,
                device_code_method(client_id, device_code_url, token_url, scope)?,
                label,
                priority,
            )
        }
    }

    /// `OpenAI` Codex provider helpers.
    pub mod openai_codex {
        use super::{
            ApiKeyAuth, AuthMethodKind, AuthProfile, AuthResult, OAuthDeviceCodeAuth,
            OAuthDeviceCodeConfig, profile,
        };

        /// Canonical provider id for `OpenAI` profiles.
        pub const PROVIDER_ID: &str = "openai";

        /// Build an `OpenAI` API-key method.
        ///
        /// # Errors
        ///
        /// Returns [`crate::AuthError`] when API-key material is invalid.
        pub fn api_key_method(api_key: impl Into<String>) -> AuthResult<AuthMethodKind> {
            Ok(AuthMethodKind::ApiKey(ApiKeyAuth::bearer(api_key)?))
        }

        /// Build an `OpenAI` API-key auth profile.
        ///
        /// # Errors
        ///
        /// Returns [`crate::AuthError`] when profile or API-key fields are invalid.
        pub fn api_key_profile(
            profile_id: impl Into<String>,
            label: impl Into<String>,
            priority: i32,
            api_key: impl Into<String>,
        ) -> AuthResult<AuthProfile> {
            profile(
                PROVIDER_ID,
                profile_id,
                api_key_method(api_key)?,
                label,
                priority,
            )
        }

        /// Build `OpenAI` Codex device-code flow config from caller-supplied endpoints.
        ///
        /// # Errors
        ///
        /// Returns [`crate::AuthError`] when OAuth config fields are invalid.
        pub fn device_code_config(
            client_id: impl Into<String>,
            device_code_url: impl Into<String>,
            token_url: impl Into<String>,
            scope: impl Into<String>,
        ) -> AuthResult<OAuthDeviceCodeConfig> {
            OAuthDeviceCodeConfig::new(client_id, device_code_url, token_url, scope)
        }

        /// Build an `OpenAI` Codex OAuth device-code method.
        ///
        /// # Errors
        ///
        /// Returns [`crate::AuthError`] when OAuth config fields are invalid.
        pub fn device_code_method(
            client_id: impl Into<String>,
            device_code_url: impl Into<String>,
            token_url: impl Into<String>,
            scope: impl Into<String>,
        ) -> AuthResult<AuthMethodKind> {
            Ok(AuthMethodKind::OAuthDeviceCode(
                OAuthDeviceCodeAuth::from_config(device_code_config(
                    client_id,
                    device_code_url,
                    token_url,
                    scope,
                )?),
            ))
        }

        /// Build an `OpenAI` Codex OAuth device-code auth profile.
        ///
        /// # Errors
        ///
        /// Returns [`crate::AuthError`] when profile or OAuth fields are invalid.
        pub fn device_code_profile(
            profile_id: impl Into<String>,
            label: impl Into<String>,
            priority: i32,
            client_id: impl Into<String>,
            device_code_url: impl Into<String>,
            token_url: impl Into<String>,
            scope: impl Into<String>,
        ) -> AuthResult<AuthProfile> {
            profile(
                PROVIDER_ID,
                profile_id,
                device_code_method(client_id, device_code_url, token_url, scope)?,
                label,
                priority,
            )
        }
    }

    /// Google OAuth provider helpers.
    pub mod google {
        use super::{
            AuthMethodKind, AuthProfile, AuthResult, OAuthAuthCodeAuth, OAuthAuthCodeConfig,
            profile,
        };

        /// Canonical provider id for Google profiles.
        pub const PROVIDER_ID: &str = "google";
        /// Google OAuth authorization endpoint.
        pub const AUTHORIZE_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
        /// Google OAuth token endpoint.
        pub const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

        /// Build Google public-client auth-code config with offline access.
        ///
        /// # Errors
        ///
        /// Returns [`crate::AuthError`] when OAuth config fields are invalid.
        pub fn offline_public_auth_code_config(
            client_id: impl Into<String>,
            redirect_uri: impl Into<String>,
            scope: impl Into<String>,
        ) -> AuthResult<OAuthAuthCodeConfig> {
            OAuthAuthCodeConfig::public_client(
                client_id,
                AUTHORIZE_URL,
                TOKEN_URL,
                redirect_uri,
                scope,
                true,
            )?
            .with_authorize_param("access_type", "offline")?
            .with_authorize_param("prompt", "consent")
        }

        /// Build Google confidential-client auth-code config with offline access.
        ///
        /// # Errors
        ///
        /// Returns [`crate::AuthError`] when OAuth config fields are invalid.
        pub fn offline_confidential_auth_code_config(
            client_id: impl Into<String>,
            client_secret: impl Into<String>,
            redirect_uri: impl Into<String>,
            scope: impl Into<String>,
        ) -> AuthResult<OAuthAuthCodeConfig> {
            OAuthAuthCodeConfig::confidential_client(
                client_id,
                client_secret,
                AUTHORIZE_URL,
                TOKEN_URL,
                redirect_uri,
                scope,
                true,
            )?
            .with_authorize_param("access_type", "offline")?
            .with_authorize_param("prompt", "consent")
        }

        /// Build a Google public-client OAuth auth-code method.
        ///
        /// # Errors
        ///
        /// Returns [`crate::AuthError`] when OAuth config fields are invalid.
        pub fn offline_public_auth_code_method(
            client_id: impl Into<String>,
            redirect_uri: impl Into<String>,
            scope: impl Into<String>,
        ) -> AuthResult<AuthMethodKind> {
            Ok(AuthMethodKind::OAuthAuthCode(
                OAuthAuthCodeAuth::from_config(offline_public_auth_code_config(
                    client_id,
                    redirect_uri,
                    scope,
                )?),
            ))
        }

        /// Build a Google confidential-client OAuth auth-code method.
        ///
        /// # Errors
        ///
        /// Returns [`crate::AuthError`] when OAuth config fields are invalid.
        pub fn offline_confidential_auth_code_method(
            client_id: impl Into<String>,
            client_secret: impl Into<String>,
            redirect_uri: impl Into<String>,
            scope: impl Into<String>,
        ) -> AuthResult<AuthMethodKind> {
            Ok(AuthMethodKind::OAuthAuthCode(
                OAuthAuthCodeAuth::from_config(offline_confidential_auth_code_config(
                    client_id,
                    client_secret,
                    redirect_uri,
                    scope,
                )?),
            ))
        }

        /// Build a Google public-client OAuth auth-code profile.
        ///
        /// # Errors
        ///
        /// Returns [`crate::AuthError`] when profile or OAuth fields are invalid.
        pub fn offline_public_auth_code_profile(
            profile_id: impl Into<String>,
            label: impl Into<String>,
            priority: i32,
            client_id: impl Into<String>,
            redirect_uri: impl Into<String>,
            scope: impl Into<String>,
        ) -> AuthResult<AuthProfile> {
            profile(
                PROVIDER_ID,
                profile_id,
                offline_public_auth_code_method(client_id, redirect_uri, scope)?,
                label,
                priority,
            )
        }
    }

    /// AWS provider helpers.
    pub mod aws {
        use super::{AuthMethodKind, AuthProfile, AuthResult, SigV4Auth, profile};

        /// Canonical provider id for AWS profiles.
        pub const PROVIDER_ID: &str = "aws";

        /// Build AWS `SigV4` auth config.
        ///
        /// # Errors
        ///
        /// Returns [`crate::AuthError`] when signing fields are invalid.
        pub fn sigv4_auth(
            access_key: impl Into<String>,
            signing_key: impl Into<String>,
            session_token: Option<impl Into<String>>,
            region: impl Into<String>,
            service: impl Into<String>,
        ) -> AuthResult<SigV4Auth> {
            SigV4Auth::new(access_key, signing_key, session_token, region, service)
        }

        /// Build an AWS `SigV4` method.
        ///
        /// # Errors
        ///
        /// Returns [`crate::AuthError`] when signing fields are invalid.
        pub fn sigv4_method(
            access_key: impl Into<String>,
            signing_key: impl Into<String>,
            session_token: Option<impl Into<String>>,
            region: impl Into<String>,
            service: impl Into<String>,
        ) -> AuthResult<AuthMethodKind> {
            Ok(AuthMethodKind::SigV4(sigv4_auth(
                access_key,
                signing_key,
                session_token,
                region,
                service,
            )?))
        }

        /// Build an AWS `SigV4` auth profile.
        ///
        /// # Errors
        ///
        /// Returns [`crate::AuthError`] when profile fields are invalid.
        pub fn sigv4_profile(
            profile_id: impl Into<String>,
            label: impl Into<String>,
            priority: i32,
            auth: SigV4Auth,
        ) -> AuthResult<AuthProfile> {
            profile(
                PROVIDER_ID,
                profile_id,
                AuthMethodKind::SigV4(auth),
                label,
                priority,
            )
        }
    }

    /// GLM/Zhipu provider helpers.
    pub mod glm {
        use super::{AuthMethodKind, AuthProfile, AuthResult, JwtAuth, StdDuration, profile};

        /// Canonical provider id for GLM profiles.
        pub const PROVIDER_ID: &str = "glm";

        /// Build a GLM JWT method from a caller-supplied generator.
        ///
        /// # Errors
        ///
        /// Returns [`crate::AuthError`] when JWT metadata is invalid.
        pub fn jwt_method(
            ttl: StdDuration,
            generator: impl Fn() -> AuthResult<String> + Send + Sync + 'static,
        ) -> AuthResult<AuthMethodKind> {
            Ok(AuthMethodKind::Jwt(JwtAuth::new(
                PROVIDER_ID,
                ttl,
                generator,
            )?))
        }

        /// Build a GLM JWT auth profile.
        ///
        /// # Errors
        ///
        /// Returns [`crate::AuthError`] when profile or JWT metadata is invalid.
        pub fn jwt_profile(
            profile_id: impl Into<String>,
            label: impl Into<String>,
            priority: i32,
            ttl: StdDuration,
            generator: impl Fn() -> AuthResult<String> + Send + Sync + 'static,
        ) -> AuthResult<AuthProfile> {
            profile(
                PROVIDER_ID,
                profile_id,
                jwt_method(ttl, generator)?,
                label,
                priority,
            )
        }
    }

    /// Build a redacted token from provider helper callers that need direct material.
    ///
    /// # Errors
    ///
    /// Returns [`crate::AuthError`] when token material is empty.
    pub fn redacted_secret(material: impl Into<String>) -> AuthResult<RedactedSecret> {
        RedactedSecret::new(material)
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn canonical_request(
    context: &SigV4SigningContext,
    canonical_headers: &str,
    signed_headers: &str,
    path_encoding: CanonicalPathEncoding,
    path_normalization: CanonicalPathNormalization,
) -> String {
    format!(
        "{}\n{}\n{}\n{}\n{signed_headers}\n{}",
        context.method,
        canonical_uri(&context.uri_path, path_encoding, path_normalization),
        canonical_query(&context.query_params),
        canonical_headers,
        context.payload_hash,
    )
}

fn canonical_headers(headers: &BTreeMap<String, String>) -> AuthResult<(String, String)> {
    let mut normalized = BTreeMap::new();
    for (name, value) in headers {
        let name = name.to_ascii_lowercase();
        if name == "authorization" {
            continue;
        }
        validate_header_name(&name)?;
        validate_header_value(value)?;
        normalized.insert(name, normalize_header_value(value));
    }
    if !normalized.contains_key("host") {
        return Err(invalid_config("host_header", "SigV4 signing requires host"));
    }

    let mut canonical = String::new();
    for (name, value) in &normalized {
        let _ = writeln!(&mut canonical, "{name}:{value}");
    }
    let signed = normalized.keys().cloned().collect::<Vec<_>>().join(";");
    Ok((canonical, signed))
}

fn normalize_header_value(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn canonical_query(params: &BTreeMap<String, String>) -> String {
    let mut encoded = params
        .iter()
        .map(|(key, value)| (uri_encode(key), uri_encode(value)))
        .collect::<Vec<_>>();
    encoded.sort();
    encoded
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// Percent-decode a wire path back to the raw bytes the service will see.
///
/// Invalid UTF-8 is replaced rather than rejected: the canonical URI is only
/// ever compared against the service's own rendering, and a request whose path
/// is not valid UTF-8 will fail on its own merits rather than here.
fn percent_decode_path(path: &str) -> String {
    percent_encoding::percent_decode_str(path)
        .decode_utf8_lossy()
        .into_owned()
}

fn uri_encode_path(path: &str) -> String {
    path.split('/')
        .map(uri_encode)
        .collect::<Vec<_>>()
        .join("/")
}

/// Build the canonical URI for a request.
///
/// The service percent-decodes the path it receives and then re-encodes it to
/// canonicalize, so the signer has to do the same thing: decode the wire path,
/// then apply the service's required number of encoding passes. Encoding the
/// wire path directly (the previous behaviour) is only equivalent when the path
/// contains nothing that needed escaping in the first place — which is why
/// plain ASCII keys signed correctly while a key with a space, a literal `%`,
/// or any non-ASCII character produced `SignatureDoesNotMatch`.
///
/// Ported verbatim from `fcp_sdk::sigv4`; see br-1nqg7 and br-0lsi3.
fn canonical_uri(
    wire_path: &str,
    encoding: CanonicalPathEncoding,
    normalization: CanonicalPathNormalization,
) -> String {
    let wire_path = if wire_path.starts_with('/') {
        wire_path.to_string()
    } else {
        format!("/{wire_path}")
    };
    // Normalise the WIRE path, before decoding. Order matters, and matches both
    // `fcp_sdk::sigv4` and AWS's own signer (`aws-c-auth` normalises the URI path
    // it was handed and only then encodes). Decoding first would turn an encoded
    // `%2F` inside a segment into a real separator, and normalisation would then
    // treat it as one — silently signing a different resource than the request
    // targets. Dot segments are unreserved and so are never percent-encoded on
    // the wire, which is why normalising first loses nothing.
    let normalized = match normalization {
        CanonicalPathNormalization::RemoveDotSegments => remove_dot_segments(&wire_path),
        CanonicalPathNormalization::Preserve => wire_path,
    };
    let once = uri_encode_path(&percent_decode_path(&normalized));
    match encoding {
        CanonicalPathEncoding::Single => once,
        CanonicalPathEncoding::Double => uri_encode_path(&once),
    }
}

/// Resolve `.` and `..` segments and collapse duplicate slashes, per RFC 3986
/// §6.2.2.3 plus AWS's additional empty-segment collapsing.
///
/// Verified against AWS's published vectors: `/example/..`, `//` and `/./` all
/// canonicalise to `/`; `/./example` to `/example`; `//example//` to `/example/`.
/// A trailing slash on the input is preserved when any segment survives.
///
/// Ported from `fcp_sdk::sigv4` so both signers render a joined path the same
/// way. Its absence here was a live `SignatureDoesNotMatch` for every non-S3
/// caller that built a path by joining segments and landed a `//`, `.` or `..`.
fn remove_dot_segments(path: &str) -> String {
    let mut resolved: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            // An empty segment is a duplicate (or leading/trailing) slash.
            "" | "." => {}
            ".." => {
                resolved.pop();
            }
            other => resolved.push(other),
        }
    }
    if resolved.is_empty() {
        return "/".to_string();
    }
    let trailing = if path.ends_with('/') { "/" } else { "" };
    format!("/{}{trailing}", resolved.join("/"))
}

fn uri_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(char::from(byte));
            }
            _ => {
                let _ = write!(&mut encoded, "%{byte:02X}");
            }
        }
    }
    encoded
}

fn apply_bearer_token(
    method: &'static str,
    access_token: Option<&RedactedSecret>,
    expires_at: Option<DateTime<Utc>>,
    request: &mut AuthRequest,
) -> AuthResult<()> {
    if let Some(expires_at) = expires_at {
        if Utc::now() >= expires_at {
            return Err(AuthError::Expired { method, expires_at });
        }
    }
    let bearer_material = access_token.ok_or(AuthError::MissingToken { method })?;
    request.set_header(
        "Authorization",
        format!("Bearer {}", bearer_material.expose_secret()),
    )
}

/// Supported auth method variants.
#[derive(Debug, Clone)]
pub enum AuthMethodKind {
    /// Static API-key auth.
    ApiKey(ApiKeyAuth),
    /// OAuth device-code auth.
    OAuthDeviceCode(OAuthDeviceCodeAuth),
    /// OAuth authorization-code auth.
    OAuthAuthCode(OAuthAuthCodeAuth),
    /// Short-lived setup-token auth.
    SetupToken(SetupTokenAuth),
    /// JWT generator auth.
    Jwt(JwtAuth),
    /// AWS `SigV4` auth config.
    SigV4(SigV4Auth),
}

impl AuthMethodKind {
    /// The refresh token this method currently holds, if any.
    ///
    /// Used as the compare-and-swap witness for store-backed refreshes: it is
    /// the one piece of state a provider rotates, so a mismatch is proof that
    /// another refresh already landed and this response is stale.
    #[must_use]
    pub fn refresh_token_material(&self) -> Option<&str> {
        match self {
            Self::OAuthDeviceCode(method) => method
                .refresh_token
                .as_ref()
                .map(RedactedSecret::expose_secret),
            Self::OAuthAuthCode(method) => method
                .refresh_token
                .as_ref()
                .map(RedactedSecret::expose_secret),
            Self::ApiKey(_) | Self::SetupToken(_) | Self::Jwt(_) | Self::SigV4(_) => None,
        }
    }
}

#[async_trait]
impl AuthMethod for AuthMethodKind {
    fn id(&self) -> &'static str {
        match self {
            Self::ApiKey(method) => method.id(),
            Self::OAuthDeviceCode(_) => "oauth_device",
            Self::OAuthAuthCode(_) => "oauth_auth_code",
            Self::SetupToken(method) => method.id(),
            Self::Jwt(method) => method.id(),
            Self::SigV4(method) => method.id(),
        }
    }

    async fn validate(&self, cx: &fcp_async_core::Cx) -> AuthResult<()> {
        match self {
            Self::ApiKey(method) => method.validate(cx).await,
            Self::OAuthDeviceCode(method) => method.validate(cx).await,
            Self::OAuthAuthCode(method) => method.validate(cx).await,
            Self::SetupToken(method) => method.validate(cx).await,
            Self::Jwt(method) => method.validate(cx).await,
            Self::SigV4(method) => method.validate(cx).await,
        }
    }

    async fn build_request_auth(
        &self,
        cx: &fcp_async_core::Cx,
        request: &mut AuthRequest,
    ) -> AuthResult<()> {
        self.validate(cx).await?;
        match self {
            Self::ApiKey(method) => method.build_request_auth(cx, request).await,
            Self::OAuthDeviceCode(method) => method.build_request_auth(cx, request).await,
            Self::OAuthAuthCode(method) => method.build_request_auth(cx, request).await,
            Self::SetupToken(method) => method.build_request_auth(cx, request).await,
            Self::Jwt(method) => method.build_request_auth(cx, request).await,
            Self::SigV4(method) => method.build_request_auth(cx, request).await,
        }
    }

    fn requires_refresh_in(&self) -> Option<StdDuration> {
        match self {
            Self::ApiKey(method) => method.requires_refresh_in(),
            Self::OAuthDeviceCode(method) => method.requires_refresh_in(),
            Self::OAuthAuthCode(method) => method.requires_refresh_in(),
            Self::SetupToken(method) => method.requires_refresh_in(),
            Self::Jwt(method) => method.requires_refresh_in(),
            Self::SigV4(method) => method.requires_refresh_in(),
        }
    }

    async fn refresh(&mut self, cx: &fcp_async_core::Cx) -> AuthResult<()> {
        match self {
            Self::ApiKey(method) => method.refresh(cx).await,
            Self::OAuthDeviceCode(method) => method.refresh(cx).await,
            Self::OAuthAuthCode(method) => method.refresh(cx).await,
            Self::SetupToken(method) => method.refresh(cx).await,
            Self::Jwt(method) => method.refresh(cx).await,
            Self::SigV4(method) => method.refresh(cx).await,
        }
    }
}

/// One provider auth profile.
#[derive(Debug, Clone)]
pub struct AuthProfile {
    /// Opaque profile id.
    pub id: String,
    /// Canonical provider id.
    pub provider: String,
    /// Concrete auth method.
    pub method: AuthMethodKind,
    /// Redaction-safe operator label.
    pub label: String,
    /// Lower values are preferred.
    pub priority: i32,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last use timestamp.
    pub last_used_at: Option<DateTime<Utc>>,
}

impl AuthProfile {
    /// Construct an auth profile.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when id, provider, or label is empty.
    pub fn new(
        id: impl Into<String>,
        provider: impl Into<String>,
        method: AuthMethodKind,
        label: impl Into<String>,
        priority: i32,
    ) -> AuthResult<Self> {
        let id = id.into();
        let provider = canonical_provider(&provider.into())?;
        let label = label.into();
        validate_non_empty(&id, "profile_id")?;
        validate_non_empty(&label, "label")?;
        Ok(Self {
            id,
            provider,
            method,
            label,
            priority,
            created_at: Utc::now(),
            last_used_at: None,
        })
    }
}

/// Refresh scheduling policy for TTL-bounded auth methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenRefreshPolicy {
    /// Refresh a token when its remaining lifetime is less than or equal to this duration.
    pub refresh_before: StdDuration,
}

impl TokenRefreshPolicy {
    /// Construct a refresh policy.
    #[must_use]
    pub const fn new(refresh_before: StdDuration) -> Self {
        Self { refresh_before }
    }

    fn decide(self, refresh_in: Option<StdDuration>) -> TokenRefreshAction {
        match refresh_in {
            None => TokenRefreshAction::NotRefreshable,
            Some(remaining) if remaining.is_zero() => TokenRefreshAction::Expired,
            Some(remaining) if remaining <= self.refresh_before => TokenRefreshAction::Due,
            Some(_) => TokenRefreshAction::Fresh,
        }
    }
}

impl Default for TokenRefreshPolicy {
    fn default() -> Self {
        Self::new(StdDuration::from_secs(300))
    }
}

/// Refresh decision for one provider profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenRefreshDecision {
    /// Canonical provider id.
    pub provider: String,
    /// Opaque profile id.
    pub profile_id: String,
    /// Auth method id.
    pub method: &'static str,
    /// Remaining token lifetime, if the method is TTL-bounded.
    pub refresh_in: Option<StdDuration>,
    /// Action selected by the refresh policy.
    pub action: TokenRefreshAction,
}

impl TokenRefreshDecision {
    /// Build a refresh decision for one profile.
    #[must_use]
    pub fn for_profile(profile: &AuthProfile, policy: TokenRefreshPolicy) -> Self {
        let refresh_in = profile.method.requires_refresh_in();
        Self {
            provider: profile.provider.clone(),
            profile_id: profile.id.clone(),
            method: profile.method.id(),
            refresh_in,
            action: policy.decide(refresh_in),
        }
    }

    /// Return true when the profile should be refreshed now.
    #[must_use]
    pub const fn should_refresh(&self) -> bool {
        self.action.should_refresh()
    }
}

/// Refresh action selected by [`TokenRefreshPolicy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenRefreshAction {
    /// Method has no TTL metadata.
    NotRefreshable,
    /// Token is TTL-bounded but outside the proactive refresh window.
    Fresh,
    /// Token is inside the proactive refresh window.
    Due,
    /// Token has no remaining lifetime.
    Expired,
}

impl TokenRefreshAction {
    /// Return true when this action requires a refresh attempt.
    #[must_use]
    pub const fn should_refresh(self) -> bool {
        matches!(self, Self::Due | Self::Expired)
    }
}

/// Result of refreshing or skipping one profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenRefreshOutcome {
    /// Profile refresh succeeded and was persisted through the profile store.
    Refreshed(TokenRefreshDecision),
    /// Profile did not require a refresh attempt.
    Skipped(TokenRefreshDecision),
    /// Profile needed refresh but the refresh or persistence failed.
    Failed {
        /// Refresh decision that led to the attempt.
        decision: TokenRefreshDecision,
        /// Redaction-safe error from refresh or persistence.
        error: AuthError,
    },
}

impl TokenRefreshOutcome {
    /// Borrow the decision associated with this outcome.
    #[must_use]
    pub const fn decision(&self) -> &TokenRefreshDecision {
        match self {
            Self::Refreshed(decision) | Self::Skipped(decision) | Self::Failed { decision, .. } => {
                decision
            }
        }
    }
}

/// Batch refresh report for one provider.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TokenRefreshReport {
    /// Per-profile refresh outcomes.
    pub outcomes: Vec<TokenRefreshOutcome>,
}

impl TokenRefreshReport {
    fn push(&mut self, outcome: TokenRefreshOutcome) {
        self.outcomes.push(outcome);
    }

    /// Count successful refreshes.
    #[must_use]
    pub fn refreshed_count(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|outcome| matches!(outcome, TokenRefreshOutcome::Refreshed(_)))
            .count()
    }

    /// Count skipped profiles.
    #[must_use]
    pub fn skipped_count(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|outcome| matches!(outcome, TokenRefreshOutcome::Skipped(_)))
            .count()
    }

    /// Count failed refresh attempts.
    #[must_use]
    pub fn failed_count(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|outcome| matches!(outcome, TokenRefreshOutcome::Failed { .. }))
            .count()
    }
}

/// Storage boundary for provider auth profiles.
#[async_trait]
pub trait AuthProfileStore: Send + Sync {
    /// List provider profiles in active-selection order.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthError`] when the provider id is invalid.
    async fn list_profiles(&self, provider: &str) -> AuthResult<Vec<AuthProfile>>;

    /// Get one provider profile.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::ProfileNotFound`] when no matching profile exists.
    async fn get_profile(&self, provider: &str, profile_id: &str) -> AuthResult<AuthProfile>;

    /// Save or replace a provider profile.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthError`] when profile identity fields are invalid.
    async fn save_profile(&self, profile: AuthProfile) -> AuthResult<()>;

    /// Save a profile only if the stored refresh token still matches
    /// `expected_refresh_token`.
    ///
    /// Returns `Ok(false)` — leaving the store untouched — when it does not,
    /// which means another refresh already rotated the credential and this
    /// response is stale.
    ///
    /// Store-backed refresh is otherwise a read-modify-write with no lock held
    /// across the provider round trip: two concurrent refreshes both snapshot
    /// the same profile, both present the same refresh token, and the later
    /// save wins. With refresh-token rotation (Google, Okta, Auth0) the
    /// winner's exchange has already invalidated the loser's token, so the
    /// value that lands in the store is dead and every later refresh fails
    /// `invalid_grant` until an operator re-runs the login flow.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthError`] when profile identity fields are invalid, or
    /// [`AuthError::ProfileNotFound`] when the profile no longer exists.
    async fn save_profile_if_unchanged(
        &self,
        profile: AuthProfile,
        expected_refresh_token: Option<&str>,
    ) -> AuthResult<bool>;

    /// Delete one provider profile.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::ProfileNotFound`] when no matching profile exists.
    async fn delete_profile(&self, provider: &str, profile_id: &str) -> AuthResult<()>;

    /// Pick the active provider profile.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::ProviderNotFound`] when the provider has no profiles.
    async fn pick_active(&self, provider: &str) -> AuthResult<AuthProfile>;
}

/// Store-backed token refresh runner for provider profiles.
pub struct TokenRefreshActor<S: AuthProfileStore + ?Sized> {
    store: Arc<S>,
    policy: TokenRefreshPolicy,
}

impl<S> TokenRefreshActor<S>
where
    S: AuthProfileStore,
{
    /// Construct a token refresh actor over an auth profile store.
    #[must_use]
    pub const fn new(store: Arc<S>, policy: TokenRefreshPolicy) -> Self {
        Self { store, policy }
    }
}

impl<S> TokenRefreshActor<S>
where
    S: AuthProfileStore + ?Sized,
{
    /// Borrow the refresh policy.
    #[must_use]
    pub const fn policy(&self) -> TokenRefreshPolicy {
        self.policy
    }

    /// Borrow the backing profile store.
    #[must_use]
    pub const fn store(&self) -> &Arc<S> {
        &self.store
    }

    /// Refresh every due profile for a provider.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthError`] when the provider id is invalid or profiles cannot be listed.
    pub async fn refresh_provider(
        &self,
        cx: &fcp_async_core::Cx,
        provider: &str,
    ) -> AuthResult<TokenRefreshReport> {
        let profiles = self.store.list_profiles(provider).await?;
        let mut report = TokenRefreshReport::default();
        for profile in profiles {
            report.push(self.refresh_profile_snapshot(cx, profile).await);
        }
        Ok(report)
    }

    /// Refresh one profile when the policy says it is due.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthError`] when the provider/profile id is invalid or the profile is missing.
    pub async fn refresh_profile(
        &self,
        cx: &fcp_async_core::Cx,
        provider: &str,
        profile_id: &str,
    ) -> AuthResult<TokenRefreshOutcome> {
        let profile = self.store.get_profile(provider, profile_id).await?;
        Ok(self.refresh_profile_snapshot(cx, profile).await)
    }

    async fn refresh_profile_snapshot(
        &self,
        cx: &fcp_async_core::Cx,
        mut profile: AuthProfile,
    ) -> TokenRefreshOutcome {
        let decision = TokenRefreshDecision::for_profile(&profile, self.policy);
        if !decision.should_refresh() {
            return TokenRefreshOutcome::Skipped(decision);
        }

        // Capture the refresh token we are about to spend, BEFORE the provider
        // round trip rotates it. It is the compare-and-swap witness: if the
        // stored value has moved on by the time we write back, another refresh
        // already landed and ours is stale.
        let expected_refresh_token = profile
            .method
            .refresh_token_material()
            .map(ToString::to_string);

        if let Err(error) = profile.method.refresh(cx).await {
            return TokenRefreshOutcome::Failed { decision, error };
        }

        match self
            .store
            .save_profile_if_unchanged(profile, expected_refresh_token.as_deref())
            .await
        {
            // Losing the race is not a failure: the winner's result is already
            // stored and is strictly fresher than ours. Discarding our response
            // is the whole point — writing it would install a refresh token the
            // provider already invalidated.
            Ok(true) => TokenRefreshOutcome::Refreshed(decision),
            Ok(false) => TokenRefreshOutcome::Skipped(decision),
            Err(error) => TokenRefreshOutcome::Failed { decision, error },
        }
    }
}

impl<S> Clone for TokenRefreshActor<S>
where
    S: AuthProfileStore + ?Sized,
{
    fn clone(&self) -> Self {
        Self {
            store: Arc::clone(&self.store),
            policy: self.policy,
        }
    }
}

impl<S> fmt::Debug for TokenRefreshActor<S>
where
    S: AuthProfileStore + ?Sized,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenRefreshActor")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

/// Concurrency-safe in-memory auth profile store.
#[derive(Debug, Default)]
pub struct InMemoryAuthProfileStore {
    profiles: RwLock<BTreeMap<(String, String), AuthProfile>>,
}

impl InMemoryAuthProfileStore {
    /// Construct an empty in-memory profile store.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            profiles: RwLock::new(BTreeMap::new()),
        }
    }
}

fn profile_sort_key(profile: &AuthProfile) -> (i32, &str, DateTime<Utc>) {
    (profile.priority, profile.id.as_str(), profile.created_at)
}

#[async_trait]
impl AuthProfileStore for InMemoryAuthProfileStore {
    async fn list_profiles(&self, provider: &str) -> AuthResult<Vec<AuthProfile>> {
        let provider = canonical_provider(provider)?;
        let mut profiles = self
            .profiles
            .read()
            .values()
            .filter(|profile| profile.provider == provider)
            .cloned()
            .collect::<Vec<_>>();
        profiles.sort_by(|left, right| profile_sort_key(left).cmp(&profile_sort_key(right)));
        Ok(profiles)
    }

    async fn get_profile(&self, provider: &str, profile_id: &str) -> AuthResult<AuthProfile> {
        let provider = canonical_provider(provider)?;
        validate_non_empty(profile_id, "profile_id")?;
        self.profiles
            .read()
            .get(&(provider.clone(), profile_id.to_string()))
            .cloned()
            .ok_or_else(|| AuthError::ProfileNotFound {
                provider,
                profile_id: profile_id.to_string(),
            })
    }

    async fn save_profile(&self, mut profile: AuthProfile) -> AuthResult<()> {
        validate_non_empty(&profile.id, "profile_id")?;
        validate_non_empty(&profile.label, "label")?;
        profile.provider = canonical_provider(&profile.provider)?;
        self.profiles
            .write()
            .insert((profile.provider.clone(), profile.id.clone()), profile);
        Ok(())
    }

    async fn save_profile_if_unchanged(
        &self,
        mut profile: AuthProfile,
        expected_refresh_token: Option<&str>,
    ) -> AuthResult<bool> {
        validate_non_empty(&profile.id, "profile_id")?;
        validate_non_empty(&profile.label, "label")?;
        profile.provider = canonical_provider(&profile.provider)?;

        // The compare and the swap happen under ONE write guard — taking a read
        // guard to compare and then a write guard to store would reintroduce
        // the race this method exists to close.
        let mut profiles = self.profiles.write();
        let key = (profile.provider.clone(), profile.id.clone());
        let outcome = match profiles.get(&key) {
            None => Err(AuthError::ProfileNotFound {
                provider: profile.provider.clone(),
                profile_id: profile.id.clone(),
            }),
            Some(stored) => Ok(stored.method.refresh_token_material() == expected_refresh_token),
        };
        if matches!(outcome, Ok(true)) {
            profiles.insert(key, profile);
        }
        drop(profiles);
        outcome
    }

    async fn delete_profile(&self, provider: &str, profile_id: &str) -> AuthResult<()> {
        let provider = canonical_provider(provider)?;
        validate_non_empty(profile_id, "profile_id")?;
        let removed = self
            .profiles
            .write()
            .remove(&(provider.clone(), profile_id.to_string()));
        if removed.is_some() {
            Ok(())
        } else {
            Err(AuthError::ProfileNotFound {
                provider,
                profile_id: profile_id.to_string(),
            })
        }
    }

    async fn pick_active(&self, provider: &str) -> AuthResult<AuthProfile> {
        let provider = canonical_provider(provider)?;
        self.list_profiles(&provider)
            .await?
            .into_iter()
            .next()
            .ok_or(AuthError::ProviderNotFound { provider })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use parking_lot::Mutex;

    // asupersync 0.3.2 gates `Cx::for_testing` out of non-test builds
    // (cap-mask bypass hardening). `compatibility_cx()` reads the ambient
    // runtime context, so it must be evaluated *inside* the future that
    // `run`/`block_on_sync` drives — hence each `run(..)` site that needs a
    // cx wraps its future in `async { ..await }` so `cx()` executes after the
    // runtime context is installed, not as an eager argument.
    fn cx() -> fcp_async_core::Cx {
        fcp_async_core::compatibility_cx()
    }

    fn sigv4_time() -> DateTime<Utc> {
        "2013-05-24T00:00:00Z".parse().unwrap()
    }

    fn aws_example_access_key() -> String {
        ["AKIAIOSFODNN7", "EXAMPLE"].concat()
    }

    fn sigv4_auth(session_token: Option<&str>) -> SigV4Auth {
        SigV4Auth::new(
            aws_example_access_key(),
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            session_token.map(str::to_string),
            "us-east-1",
            "s3",
        )
        .unwrap()
    }

    fn sigv4_auth_for_service(service: &str) -> SigV4Auth {
        SigV4Auth::new(
            aws_example_access_key(),
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            None::<String>,
            "us-east-1",
            service,
        )
        .unwrap()
    }

    fn run<T>(future: impl std::future::Future<Output = T>) -> T {
        fcp_async_core::runtime::block_on_sync(future).unwrap()
    }

    fn api_profile(id: &str, provider: &str, priority: i32) -> AuthProfile {
        AuthProfile::new(
            id,
            provider,
            AuthMethodKind::ApiKey(ApiKeyAuth::bearer(format!("fixture-{id}")).unwrap()),
            id,
            priority,
        )
        .unwrap()
    }

    fn oauth_config() -> OAuthDeviceCodeConfig {
        OAuthDeviceCodeConfig::new(
            "fixture-client",
            "https://auth.example.test/device",
            "https://auth.example.test/token",
            "chat messages",
        )
        .unwrap()
    }

    fn oauth_challenge() -> OAuthDeviceCodeChallenge {
        OAuthDeviceCodeChallenge::new(
            "fixture-device-code",
            "ABCD-EFGH",
            "https://auth.example.test/verify",
            Some("https://auth.example.test/verify?user_code=ABCD-EFGH"),
            Utc::now() + TimeDelta::minutes(5),
            StdDuration::from_secs(5),
        )
        .unwrap()
    }

    fn oauth_tokens() -> OAuthTokens {
        OAuthTokens::bearer(
            "fixture-access-token",
            Some(StdDuration::from_secs(3_600)),
            Some("fixture-refresh-token"),
            Some("chat messages"),
        )
        .unwrap()
    }

    fn auth_code_config() -> OAuthAuthCodeConfig {
        OAuthAuthCodeConfig::public_client(
            "fixture-client",
            "https://auth.example.test/authorize",
            "https://auth.example.test/token",
            "https://agent.example.test/oauth/callback",
            "chat messages",
            true,
        )
        .unwrap()
    }

    fn auth_code_pkce() -> OAuthPkce {
        OAuthPkce::from_verifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk").unwrap()
    }

    #[derive(Debug)]
    struct ScriptedDeviceTransport {
        challenge: OAuthDeviceCodeChallenge,
        responses: Mutex<VecDeque<OAuthDeviceCodeProviderResponse>>,
    }

    impl ScriptedDeviceTransport {
        fn new(responses: impl IntoIterator<Item = OAuthDeviceCodeProviderResponse>) -> Self {
            Self {
                challenge: oauth_challenge(),
                responses: Mutex::new(responses.into_iter().collect()),
            }
        }

        fn with_challenge(mut self, challenge: OAuthDeviceCodeChallenge) -> Self {
            self.challenge = challenge;
            self
        }
    }

    #[async_trait]
    impl OAuthDeviceCodeTransport for ScriptedDeviceTransport {
        async fn start(
            &self,
            _config: &OAuthDeviceCodeConfig,
        ) -> AuthResult<OAuthDeviceCodeChallenge> {
            Ok(self.challenge.clone())
        }

        async fn poll(
            &self,
            _config: &OAuthDeviceCodeConfig,
            _challenge: &OAuthDeviceCodeChallenge,
        ) -> AuthResult<OAuthDeviceCodeProviderResponse> {
            self.responses
                .lock()
                .pop_front()
                .ok_or_else(|| AuthError::InvalidProviderResponse {
                    method: "oauth_device",
                    reason: "scripted transport had no response".to_string(),
                })
        }
    }

    #[derive(Debug)]
    struct ScriptedAuthCodeTransport {
        responses: Mutex<VecDeque<OAuthAuthCodeProviderResponse>>,
        seen_pkce_challenges: Mutex<Vec<Option<String>>>,
    }

    impl ScriptedAuthCodeTransport {
        fn new(responses: impl IntoIterator<Item = OAuthAuthCodeProviderResponse>) -> Self {
            Self {
                responses: Mutex::new(responses.into_iter().collect()),
                seen_pkce_challenges: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl OAuthAuthCodeTransport for ScriptedAuthCodeTransport {
        async fn exchange(
            &self,
            config: &OAuthAuthCodeConfig,
            grant: &OAuthAuthCodeGrant,
            pkce: Option<&OAuthPkce>,
        ) -> AuthResult<OAuthAuthCodeProviderResponse> {
            assert_eq!(config.client_id, "fixture-client");
            assert_eq!(grant.code.expose_secret(), "fixture-auth-code");
            self.seen_pkce_challenges
                .lock()
                .push(pkce.map(|pkce| pkce.challenge.clone()));
            self.responses
                .lock()
                .pop_front()
                .ok_or_else(|| AuthError::InvalidProviderResponse {
                    method: "oauth_auth_code",
                    reason: "scripted transport had no response".to_string(),
                })
        }
    }

    #[derive(Debug)]
    struct ScriptedRefreshTransport {
        responses: Mutex<VecDeque<OAuthRefreshProviderResponse>>,
        seen_client_secrets: Mutex<Vec<bool>>,
        seen_refresh_tokens: Mutex<Vec<String>>,
    }

    impl ScriptedRefreshTransport {
        fn new(responses: impl IntoIterator<Item = OAuthRefreshProviderResponse>) -> Self {
            Self {
                responses: Mutex::new(responses.into_iter().collect()),
                seen_client_secrets: Mutex::new(Vec::new()),
                seen_refresh_tokens: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl OAuthRefreshTokenTransport for ScriptedRefreshTransport {
        async fn refresh(
            &self,
            config: &OAuthRefreshTokenConfig,
            grant: &OAuthRefreshTokenGrant,
        ) -> AuthResult<OAuthRefreshProviderResponse> {
            assert_eq!(config.client_id, "fixture-client");
            assert_eq!(config.token_url, "https://auth.example.test/token");
            self.seen_client_secrets
                .lock()
                .push(config.client_secret.is_some());
            self.seen_refresh_tokens
                .lock()
                .push(grant.refresh_token.expose_secret().to_string());
            self.responses
                .lock()
                .pop_front()
                .ok_or_else(|| AuthError::InvalidProviderResponse {
                    method: "oauth_refresh",
                    reason: "scripted transport had no response".to_string(),
                })
        }
    }

    #[test]
    fn api_key_auth_sets_bearer_header_and_redacts_debug() {
        let auth = ApiKeyAuth::bearer("fixture-api-key-value").unwrap();
        let mut request = AuthRequest::new();

        run(async { auth.build_request_auth(&cx(), &mut request).await }).unwrap();

        assert_eq!(
            request.value_for("Authorization"),
            Some("Bearer fixture-api-key-value")
        );
        let debug = format!("{auth:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("fixture-api-key-value"));
    }

    #[test]
    fn auth_request_rejects_header_injection() {
        let mut request = AuthRequest::new();

        let error = request
            .set_header("Authorization", "Bearer good\nX-Injected: bad")
            .unwrap_err();

        assert!(matches!(
            error,
            AuthError::InvalidHeader {
                field: "header_value",
                ..
            }
        ));
    }

    #[test]
    fn setup_token_refuses_expired_token() {
        let auth =
            SetupTokenAuth::bearer("setup-token", Utc::now() - TimeDelta::seconds(1)).unwrap();
        let mut request = AuthRequest::new();

        let error = run(async { auth.build_request_auth(&cx(), &mut request).await }).unwrap_err();

        assert!(matches!(
            error,
            AuthError::Expired {
                method: "setup_token",
                ..
            }
        ));
        assert!(request.headers().is_empty());
    }

    #[test]
    fn method_kind_delegates_api_key_auth() {
        let auth = AuthMethodKind::ApiKey(ApiKeyAuth::bearer("fixture-kind").unwrap());
        let mut request = AuthRequest::new();

        run(async { auth.build_request_auth(&cx(), &mut request).await }).unwrap();

        assert_eq!(auth.id(), "api_key");
        assert_eq!(
            request.value_for("Authorization"),
            Some("Bearer fixture-kind")
        );
    }

    #[test]
    fn provider_helpers_build_api_key_profiles_with_provider_headers() {
        let anthropic = providers::anthropic::api_key_profile(
            "personal",
            "Personal Claude",
            10,
            "fixture-anthropic-key",
        )
        .unwrap();
        let openai =
            providers::openai_codex::api_key_profile("codex", "Codex", 20, "fixture-openai-key")
                .unwrap();

        assert_eq!(anthropic.provider, providers::anthropic::PROVIDER_ID);
        assert_eq!(anthropic.label, "Personal Claude");
        assert_eq!(anthropic.priority, 10);
        assert_eq!(openai.provider, providers::openai_codex::PROVIDER_ID);

        let mut anthropic_request = AuthRequest::new();
        run(async {
            anthropic
                .method
                .build_request_auth(&cx(), &mut anthropic_request)
                .await
        })
        .unwrap();
        assert_eq!(
            anthropic_request.value_for(providers::anthropic::API_KEY_HEADER),
            Some("fixture-anthropic-key")
        );

        let mut openai_request = AuthRequest::new();
        run(async {
            openai
                .method
                .build_request_auth(&cx(), &mut openai_request)
                .await
        })
        .unwrap();
        assert_eq!(
            openai_request.value_for("Authorization"),
            Some("Bearer fixture-openai-key")
        );
        assert!(!format!("{:?}", anthropic.method).contains("fixture-anthropic-key"));
        assert!(!format!("{:?}", openai.method).contains("fixture-openai-key"));
    }

    #[test]
    fn provider_helpers_build_device_code_profiles_and_validate_inputs() {
        let anthropic = providers::anthropic::device_code_profile(
            "work",
            "Work Claude",
            0,
            "anthropic-client",
            "https://auth.anthropic.example/device",
            "https://auth.anthropic.example/token",
            "claude-code",
        )
        .unwrap();
        let openai = providers::openai_codex::device_code_profile(
            "codex",
            "Codex",
            5,
            "openai-client",
            "https://auth.openai.example/device",
            "https://auth.openai.example/token",
            "codex",
        )
        .unwrap();

        assert!(matches!(
            anthropic.method,
            AuthMethodKind::OAuthDeviceCode(_)
        ));
        let AuthMethodKind::OAuthDeviceCode(anthropic_method) = anthropic.method else {
            return;
        };
        assert_eq!(anthropic_method.client_id, "anthropic-client");
        assert_eq!(anthropic_method.scope, "claude-code");

        assert!(matches!(openai.method, AuthMethodKind::OAuthDeviceCode(_)));
        let AuthMethodKind::OAuthDeviceCode(openai_method) = openai.method else {
            return;
        };
        assert_eq!(openai_method.client_id, "openai-client");
        assert_eq!(openai_method.scope, "codex");

        let error = providers::openai_codex::device_code_config(
            "bad\nclient",
            "https://auth.openai.example/device",
            "https://auth.openai.example/token",
            "codex",
        )
        .unwrap_err();
        assert_eq!(
            error,
            AuthError::InvalidConfig {
                field: "client_id",
                reason: "CR/LF bytes are not allowed".to_string()
            }
        );
    }

    #[test]
    fn google_helper_adds_offline_authorization_params() {
        let config = providers::google::offline_confidential_auth_code_config(
            "google-client",
            "google-client-secret",
            "https://agent.example.test/google/callback",
            "openid email profile",
        )
        .unwrap();
        assert_eq!(config.authorize_url, providers::google::AUTHORIZE_URL);
        assert_eq!(config.token_url, providers::google::TOKEN_URL);
        assert_eq!(
            config
                .extra_authorize_params
                .get("access_type")
                .map(String::as_str),
            Some("offline")
        );
        assert_eq!(
            config
                .extra_authorize_params
                .get("prompt")
                .map(String::as_str),
            Some("consent")
        );
        assert!(!format!("{config:?}").contains("google-client-secret"));

        let flow = OAuthAuthCodeFlow::start_with_state(config, "fixed-google-state").unwrap();
        let url = Url::parse(flow.request().authorization_url()).unwrap();
        let params = url
            .query_pairs()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect::<BTreeMap<_, _>>();

        assert_eq!(
            url.as_str().split('?').next(),
            Some(providers::google::AUTHORIZE_URL)
        );
        assert_eq!(
            params.get("access_type").map(String::as_str),
            Some("offline")
        );
        assert_eq!(params.get("prompt").map(String::as_str), Some("consent"));
        assert_eq!(
            params.get("scope").map(String::as_str),
            Some("openid email profile")
        );
    }

    #[test]
    fn auth_code_config_rejects_reserved_or_unsafe_extra_params() {
        let reserved = auth_code_config()
            .with_authorize_param("state", "malicious-state")
            .unwrap_err();
        assert_eq!(
            reserved,
            AuthError::InvalidConfig {
                field: "authorize_param",
                reason: "must not override standard OAuth authorization parameters".to_string()
            }
        );

        let unsafe_value = auth_code_config()
            .with_authorize_param("prompt", "consent\nadmin")
            .unwrap_err();
        assert_eq!(
            unsafe_value,
            AuthError::InvalidConfig {
                field: "authorize_param",
                reason: "CR/LF bytes are not allowed".to_string()
            }
        );
    }

    #[test]
    fn aws_and_glm_helpers_build_redaction_safe_methods() {
        let aws_auth = providers::aws::sigv4_auth(
            aws_example_access_key(),
            "fixture-aws-secret",
            Some("fixture-session-token"),
            "US-EAST-1",
            "Bedrock",
        )
        .unwrap();
        let aws = providers::aws::sigv4_profile("bedrock", "Bedrock", 0, aws_auth).unwrap();
        assert_eq!(aws.provider, providers::aws::PROVIDER_ID);
        assert!(matches!(aws.method, AuthMethodKind::SigV4(_)));
        let AuthMethodKind::SigV4(method) = aws.method else {
            return;
        };
        assert_eq!(method.region, "us-east-1");
        assert_eq!(method.service, "bedrock");
        let debug = format!("{method:?}");
        assert!(!debug.contains("fixture-aws-secret"));
        assert!(!debug.contains("fixture-session-token"));

        let counter = Arc::new(AtomicUsize::new(0));
        let generator_counter = Arc::clone(&counter);
        let glm = providers::glm::jwt_profile(
            "glm-work",
            "GLM Work",
            0,
            StdDuration::from_secs(60),
            move || {
                Ok(format!(
                    "fixture-glm-jwt-{}",
                    generator_counter.fetch_add(1, Ordering::SeqCst)
                ))
            },
        )
        .unwrap();
        assert_eq!(glm.provider, providers::glm::PROVIDER_ID);

        let mut request = AuthRequest::new();
        run(async { glm.method.build_request_auth(&cx(), &mut request).await }).unwrap();
        assert_eq!(
            request.value_for("Authorization"),
            Some("Bearer fixture-glm-jwt-0")
        );
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert!(!format!("{:?}", glm.method).contains("fixture-glm-jwt-0"));
    }

    #[test]
    fn oauth_device_flow_handles_pending_slow_down_and_success() {
        let expected_tokens = oauth_tokens();
        let transport = ScriptedDeviceTransport::new([
            OAuthDeviceCodeProviderResponse::AuthorizationPending,
            OAuthDeviceCodeProviderResponse::SlowDown,
            OAuthDeviceCodeProviderResponse::Authorized(expected_tokens.clone()),
        ]);
        let mut flow =
            run(async { OAuthDeviceCodeFlow::start(&cx(), oauth_config(), &transport).await })
                .unwrap();

        assert_eq!(flow.challenge().user_code, "ABCD-EFGH");
        assert_eq!(flow.poll_interval(), StdDuration::from_secs(5));
        assert_eq!(
            run(async { flow.poll(&cx(), &transport).await }).unwrap(),
            OAuthDeviceCodePoll::Pending {
                retry_after: StdDuration::from_secs(5)
            }
        );
        assert_eq!(
            run(async { flow.poll(&cx(), &transport).await }).unwrap(),
            OAuthDeviceCodePoll::Pending {
                retry_after: StdDuration::from_secs(10)
            }
        );

        assert_eq!(
            run(async { flow.poll(&cx(), &transport).await }).unwrap(),
            OAuthDeviceCodePoll::Authorized(expected_tokens.clone())
        );
        assert_eq!(
            expected_tokens.access_token.expose_secret(),
            "fixture-access-token"
        );
        assert_eq!(
            expected_tokens
                .refresh_token
                .as_ref()
                .map(RedactedSecret::expose_secret),
            Some("fixture-refresh-token")
        );
    }

    #[test]
    fn oauth_device_flow_maps_denied_and_expired_responses() {
        let denied =
            ScriptedDeviceTransport::new([OAuthDeviceCodeProviderResponse::AccessDenied {
                reason: "operator denied browser authorization".to_string(),
            }]);
        let mut denied_flow =
            run(async { OAuthDeviceCodeFlow::start(&cx(), oauth_config(), &denied).await })
                .unwrap();

        let denied_error = run(async { denied_flow.poll(&cx(), &denied).await }).unwrap_err();
        assert_eq!(
            denied_error,
            AuthError::ProviderRejected {
                method: "oauth_device",
                code: "access_denied".to_string(),
                reason: "operator denied browser authorization".to_string(),
            }
        );

        let expired =
            ScriptedDeviceTransport::new([OAuthDeviceCodeProviderResponse::ExpiredToken {
                reason: "device code expired".to_string(),
            }]);
        let mut expired_flow =
            run(async { OAuthDeviceCodeFlow::start(&cx(), oauth_config(), &expired).await })
                .unwrap();

        let expired_error = run(async { expired_flow.poll(&cx(), &expired).await }).unwrap_err();
        assert_eq!(
            expired_error,
            AuthError::ProviderRejected {
                method: "oauth_device",
                code: "expired_token".to_string(),
                reason: "device code expired".to_string(),
            }
        );
    }

    #[test]
    fn oauth_device_flow_rejects_malformed_provider_challenge() {
        let mut challenge = oauth_challenge();
        challenge.interval = StdDuration::ZERO;
        let transport = ScriptedDeviceTransport::new([]).with_challenge(challenge);

        let error =
            run(async { OAuthDeviceCodeFlow::start(&cx(), oauth_config(), &transport).await })
                .unwrap_err();

        assert_eq!(
            error,
            AuthError::InvalidProviderResponse {
                method: "oauth_device",
                reason: "invalid auth configuration for interval: must be greater than zero"
                    .to_string(),
            }
        );
    }

    #[test]
    fn oauth_device_auth_builds_bearer_header_and_redacts_debug() {
        let mut auth = OAuthDeviceCodeAuth::new(
            "fixture-client",
            "https://auth.example.test/device",
            "https://auth.example.test/token",
            "chat messages",
        )
        .unwrap();
        auth.apply_tokens(oauth_tokens());
        let mut request = AuthRequest::new();

        run(async { auth.build_request_auth(&cx(), &mut request).await }).unwrap();

        assert_eq!(
            request.value_for("Authorization"),
            Some("Bearer fixture-access-token")
        );
        assert!(auth.requires_refresh_in().is_some());
        let debug = format!("{auth:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("fixture-access-token"));
        assert!(!debug.contains("fixture-refresh-token"));
    }

    #[test]
    fn oauth_device_debug_redacts_polling_device_code() {
        let challenge = oauth_challenge();
        let tokens = oauth_tokens();

        let challenge_debug = format!("{challenge:?}");
        let tokens_debug = format!("{tokens:?}");

        assert!(challenge_debug.contains("ABCD-EFGH"));
        assert!(!challenge_debug.contains("fixture-device-code"));
        assert!(!tokens_debug.contains("fixture-access-token"));
        assert!(!tokens_debug.contains("fixture-refresh-token"));
    }

    #[test]
    fn auth_code_flow_builds_authorize_url_with_pkce_vector() {
        let pkce = auth_code_pkce();
        let flow = OAuthAuthCodeFlow::start_with_state_and_pkce(
            auth_code_config(),
            "fixed-state",
            Some(pkce),
        )
        .unwrap();
        let url = Url::parse(flow.request().authorization_url()).unwrap();
        let params = url
            .query_pairs()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect::<BTreeMap<_, _>>();

        assert_eq!(
            url.as_str().split('?').next(),
            Some("https://auth.example.test/authorize")
        );
        assert_eq!(
            params.get("response_type").map(String::as_str),
            Some("code")
        );
        assert_eq!(
            params.get("client_id").map(String::as_str),
            Some("fixture-client")
        );
        assert_eq!(
            params.get("redirect_uri").map(String::as_str),
            Some("https://agent.example.test/oauth/callback")
        );
        assert_eq!(
            params.get("scope").map(String::as_str),
            Some("chat messages")
        );
        assert_eq!(params.get("state").map(String::as_str), Some("fixed-state"));
        assert_eq!(
            params.get("code_challenge").map(String::as_str),
            Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
        );
        assert_eq!(
            params.get("code_challenge_method").map(String::as_str),
            Some("S256")
        );

        let debug = format!("{:?}", flow.request());
        assert!(!debug.contains("fixed-state"));
        assert!(!debug.contains("dBjftJeZ4"));
    }

    #[test]
    fn auth_code_flow_validates_callback_state_and_provider_error() {
        let flow = OAuthAuthCodeFlow::start_with_state_and_pkce(
            auth_code_config(),
            "fixed-state",
            Some(auth_code_pkce()),
        )
        .unwrap();

        let mismatch = flow
            .complete_callback(
                OAuthAuthCodeCallback::authorized("fixture-auth-code", "wrong-state").unwrap(),
            )
            .unwrap_err();
        assert_eq!(
            mismatch,
            AuthError::InvalidProviderResponse {
                method: "oauth_auth_code",
                reason: "callback state mismatch".to_string(),
            }
        );

        let denied = flow
            .complete_callback(
                OAuthAuthCodeCallback::rejected(
                    "access_denied",
                    Some("operator denied browser authorization"),
                    Some("fixed-state"),
                )
                .unwrap(),
            )
            .unwrap_err();
        assert_eq!(
            denied,
            AuthError::ProviderRejected {
                method: "oauth_auth_code",
                code: "access_denied".to_string(),
                reason: "operator denied browser authorization".to_string(),
            }
        );
    }

    #[test]
    fn auth_code_flow_exchanges_grant_for_tokens() {
        let expected_tokens = oauth_tokens();
        let flow = OAuthAuthCodeFlow::start_with_state_and_pkce(
            auth_code_config(),
            "fixed-state",
            Some(auth_code_pkce()),
        )
        .unwrap();
        let grant = flow
            .complete_callback(
                OAuthAuthCodeCallback::authorized("fixture-auth-code", "fixed-state").unwrap(),
            )
            .unwrap();
        let transport =
            ScriptedAuthCodeTransport::new([OAuthAuthCodeProviderResponse::Authorized(
                expected_tokens.clone(),
            )]);

        let tokens = run(async { flow.exchange(&cx(), &transport, &grant).await }).unwrap();

        assert_eq!(tokens, expected_tokens);
        assert_eq!(
            transport.seen_pkce_challenges.lock().as_slice(),
            &[Some(
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string()
            )]
        );
    }

    #[test]
    fn auth_code_flow_maps_exchange_rejection_and_malformed_token() {
        let flow = OAuthAuthCodeFlow::start_with_state_and_pkce(
            auth_code_config(),
            "fixed-state",
            Some(auth_code_pkce()),
        )
        .unwrap();
        let grant = flow
            .complete_callback(
                OAuthAuthCodeCallback::authorized("fixture-auth-code", "fixed-state").unwrap(),
            )
            .unwrap();
        let rejected = ScriptedAuthCodeTransport::new([OAuthAuthCodeProviderResponse::Rejected {
            code: "invalid_grant".to_string(),
            reason: "authorization code expired".to_string(),
        }]);

        let error = run(async { flow.exchange(&cx(), &rejected, &grant).await }).unwrap_err();
        assert_eq!(
            error,
            AuthError::ProviderRejected {
                method: "oauth_auth_code",
                code: "invalid_grant".to_string(),
                reason: "authorization code expired".to_string(),
            }
        );

        let bad_tokens = OAuthTokens {
            access_token: RedactedSecret::new("fixture-access-token").unwrap(),
            token_type: "mac".to_string(),
            refresh_token: None,
            expires_at: None,
            scope: None,
        };
        let malformed =
            ScriptedAuthCodeTransport::new([OAuthAuthCodeProviderResponse::Authorized(bad_tokens)]);

        let error = run(async { flow.exchange(&cx(), &malformed, &grant).await }).unwrap_err();
        assert_eq!(
            error,
            AuthError::InvalidConfig {
                field: "token_type",
                reason: "only bearer tokens are supported in this slice".to_string(),
            }
        );
    }

    #[test]
    fn auth_code_auth_builds_bearer_header_and_redacts_debug() {
        let mut auth = OAuthAuthCodeAuth::confidential_client(
            "fixture-client",
            "fixture-client-secret",
            "https://auth.example.test/authorize",
            "https://auth.example.test/token",
            "https://agent.example.test/oauth/callback",
            "chat messages",
            true,
        )
        .unwrap();
        auth.apply_tokens(oauth_tokens());
        let mut request = AuthRequest::new();

        run(async { auth.build_request_auth(&cx(), &mut request).await }).unwrap();

        assert_eq!(
            request.value_for("Authorization"),
            Some("Bearer fixture-access-token")
        );
        assert!(auth.requires_refresh_in().is_some());
        let debug = format!("{auth:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("fixture-client-secret"));
        assert!(!debug.contains("fixture-access-token"));
        assert!(!debug.contains("fixture-refresh-token"));
    }

    #[test]
    fn oauth_device_refresh_preserves_existing_refresh_token_without_rotation() {
        let mut auth = OAuthDeviceCodeAuth::from_config(oauth_config());
        auth.apply_tokens(oauth_tokens());
        let transport = ScriptedRefreshTransport::new([OAuthRefreshProviderResponse::Authorized(
            OAuthTokens::bearer(
                "refreshed-access-token",
                Some(StdDuration::from_secs(7_200)),
                Option::<String>::None,
                Some("chat messages".to_string()),
            )
            .unwrap(),
        )]);

        run(async { auth.refresh_with_transport(&cx(), &transport).await }).unwrap();

        let mut request = AuthRequest::new();
        run(async { auth.build_request_auth(&cx(), &mut request).await }).unwrap();
        assert_eq!(
            request.value_for("Authorization"),
            Some("Bearer refreshed-access-token")
        );
        assert_eq!(
            auth.refresh_grant().unwrap().refresh_token.expose_secret(),
            "fixture-refresh-token"
        );
        assert_eq!(transport.seen_client_secrets.lock().as_slice(), &[false]);
        assert_eq!(
            transport.seen_refresh_tokens.lock().as_slice(),
            &["fixture-refresh-token".to_string()]
        );
    }

    /// RFC 6749 §5.1 makes `expires_in` RECOMMENDED, not required, and several
    /// providers omit it on refresh. Clobbering a known expiry to `None` made
    /// the profile never-expiring: `requires_refresh_in()` returned `None`, the
    /// refresh loop classified it not-refreshable, and every downstream expiry
    /// gate is `if let Some(expires_at)` — so the stale bearer would be
    /// injected forever. The prior expiry must survive an omitted `expires_in`.
    #[test]
    fn oauth_refresh_preserves_expiry_when_provider_omits_expires_in() {
        let mut auth = OAuthDeviceCodeAuth::from_config(oauth_config());
        auth.apply_tokens(oauth_tokens());
        let before = auth
            .requires_refresh_in()
            .expect("fixture tokens carry an expiry");

        let transport = ScriptedRefreshTransport::new([OAuthRefreshProviderResponse::Authorized(
            OAuthTokens::bearer(
                "refreshed-access-token",
                None, // provider omitted `expires_in`
                Option::<String>::None,
                Option::<String>::None,
            )
            .unwrap(),
        )]);
        run(async { auth.refresh_with_transport(&cx(), &transport).await }).unwrap();

        let after = auth
            .requires_refresh_in()
            .expect("an omitted expires_in must not turn the profile never-expiring");
        assert!(
            after <= before,
            "preserved expiry should still be counting down: before={before:?} after={after:?}"
        );

        // Same guard on the authorization-code path.
        let mut auth = OAuthAuthCodeAuth::confidential_client(
            "fixture-client",
            "fixture-client-secret",
            "https://auth.example.test/authorize",
            "https://auth.example.test/token",
            "https://agent.example.test/oauth/callback",
            "chat messages",
            true,
        )
        .unwrap();
        auth.apply_tokens(oauth_tokens());
        assert!(auth.requires_refresh_in().is_some());
        let transport = ScriptedRefreshTransport::new([OAuthRefreshProviderResponse::Authorized(
            OAuthTokens::bearer(
                "refreshed-access-token",
                None,
                Option::<String>::None,
                Option::<String>::None,
            )
            .unwrap(),
        )]);
        run(async { auth.refresh_with_transport(&cx(), &transport).await }).unwrap();
        assert!(
            auth.requires_refresh_in().is_some(),
            "auth-code path must preserve the expiry too"
        );
    }

    /// RFC 6749 §6: a refresh MUST NOT request a scope that was never granted.
    /// The granted scope was being discarded entirely, so every refresh
    /// re-requested the originally CONFIGURED scope — which a user who
    /// consented to less (or later revoked part of it) never authorized.
    #[test]
    fn oauth_refresh_requests_the_granted_scope_not_the_configured_one() {
        let mut auth = OAuthDeviceCodeAuth::from_config(oauth_config());
        // Configured scope is "chat messages"; the provider granted only "chat".
        assert_eq!(auth.scope, "chat messages");
        auth.apply_tokens(
            OAuthTokens::bearer(
                "access-token",
                Some(StdDuration::from_secs(3_600)),
                Some("refresh-token"),
                Some("chat"),
            )
            .unwrap(),
        );
        assert_eq!(auth.granted_scope.as_deref(), Some("chat"));

        let config = auth.refresh_config().unwrap();
        assert_eq!(
            config.scope.as_deref(),
            Some("chat"),
            "refresh must ask for what was granted, not what was configured"
        );
    }

    /// An omitted scope on refresh must preserve the recorded grant. Dropping it
    /// would leave nothing to narrow against, permanently disarming the
    /// widening guard below.
    #[test]
    fn oauth_refresh_preserves_granted_scope_when_provider_omits_it() {
        let mut auth = OAuthDeviceCodeAuth::from_config(oauth_config());
        auth.apply_tokens(
            OAuthTokens::bearer(
                "access-token",
                Some(StdDuration::from_secs(3_600)),
                Some("refresh-token"),
                Some("chat"),
            )
            .unwrap(),
        );

        let transport = ScriptedRefreshTransport::new([OAuthRefreshProviderResponse::Authorized(
            OAuthTokens::bearer(
                "refreshed-access-token",
                Some(StdDuration::from_secs(3_600)),
                Option::<String>::None,
                Option::<String>::None,
            )
            .unwrap(),
        )]);
        run(async { auth.refresh_with_transport(&cx(), &transport).await }).unwrap();

        assert_eq!(auth.granted_scope.as_deref(), Some("chat"));
    }

    /// A token endpoint answering a `chat` refresh with `chat admin` must be
    /// refused rather than silently escalating what the profile can do.
    #[test]
    fn oauth_refresh_rejects_a_widened_scope() {
        let mut auth = OAuthDeviceCodeAuth::from_config(oauth_config());
        auth.apply_tokens(
            OAuthTokens::bearer(
                "access-token",
                Some(StdDuration::from_secs(3_600)),
                Some("refresh-token"),
                Some("chat"),
            )
            .unwrap(),
        );

        let transport = ScriptedRefreshTransport::new([OAuthRefreshProviderResponse::Authorized(
            OAuthTokens::bearer(
                "escalated-access-token",
                Some(StdDuration::from_secs(3_600)),
                Option::<String>::None,
                Some("chat admin"),
            )
            .unwrap(),
        )]);
        let err = run(async { auth.refresh_with_transport(&cx(), &transport).await })
            .expect_err("a widened scope must be refused");
        assert!(
            matches!(err, AuthError::InvalidConfig { .. }),
            "expected InvalidConfig, got {err:?}"
        );
        // Nothing was applied: the scope check runs before any mutation.
        assert_eq!(auth.granted_scope.as_deref(), Some("chat"));
        assert_eq!(
            auth.access_token
                .as_ref()
                .map(RedactedSecret::expose_secret),
            Some("access-token"),
            "a refused refresh must not leave half-applied token material"
        );

        // Narrowing is legitimate and must be accepted.
        let mut narrowing = OAuthDeviceCodeAuth::from_config(oauth_config());
        narrowing.apply_tokens(
            OAuthTokens::bearer(
                "access-token",
                Some(StdDuration::from_secs(3_600)),
                Some("refresh-token"),
                Some("chat messages"),
            )
            .unwrap(),
        );
        let transport = ScriptedRefreshTransport::new([OAuthRefreshProviderResponse::Authorized(
            OAuthTokens::bearer(
                "narrowed-access-token",
                Some(StdDuration::from_secs(3_600)),
                Option::<String>::None,
                Some("chat"),
            )
            .unwrap(),
        )]);
        run(async { narrowing.refresh_with_transport(&cx(), &transport).await }).unwrap();
        assert_eq!(narrowing.granted_scope.as_deref(), Some("chat"));
    }

    /// Store-backed refresh is a read-modify-write across a provider round
    /// trip. Without a compare-and-swap the later save wins, and with
    /// refresh-token rotation the loser's token was already invalidated by the
    /// winner's exchange — so the value that lands is dead.
    #[test]
    fn store_refresh_rejects_a_stale_write_after_a_concurrent_rotation() {
        let store = InMemoryAuthProfileStore::new();

        let mut auth = OAuthDeviceCodeAuth::from_config(oauth_config());
        auth.apply_tokens(
            OAuthTokens::bearer(
                "access-token",
                Some(StdDuration::from_secs(3_600)),
                Some("refresh-token-v1"),
                Option::<String>::None,
            )
            .unwrap(),
        );
        let profile = AuthProfile::new(
            "p1",
            "example",
            AuthMethodKind::OAuthDeviceCode(auth.clone()),
            "label",
            0,
        )
        .unwrap();
        run(async { store.save_profile(profile.clone()).await }).unwrap();

        // A concurrent refresh lands first, rotating the stored token to v2.
        let mut winner = auth.clone();
        winner.apply_tokens(
            OAuthTokens::bearer(
                "access-token-v2",
                Some(StdDuration::from_secs(3_600)),
                Some("refresh-token-v2"),
                Option::<String>::None,
            )
            .unwrap(),
        );
        let winner_profile = AuthProfile::new(
            "p1",
            "example",
            AuthMethodKind::OAuthDeviceCode(winner),
            "label",
            0,
        )
        .unwrap();
        assert!(
            run(async {
                store
                    .save_profile_if_unchanged(winner_profile, Some("refresh-token-v1"))
                    .await
            })
            .unwrap(),
            "the first writer holds the expected token and must win"
        );

        // Our in-flight refresh still believes the stored token is v1.
        let mut loser = auth;
        loser.apply_tokens(
            OAuthTokens::bearer(
                "access-token-stale",
                Some(StdDuration::from_secs(3_600)),
                Some("refresh-token-stale"),
                Option::<String>::None,
            )
            .unwrap(),
        );
        let loser_profile = AuthProfile::new(
            "p1",
            "example",
            AuthMethodKind::OAuthDeviceCode(loser),
            "label",
            0,
        )
        .unwrap();
        assert!(
            !run(async {
                store
                    .save_profile_if_unchanged(loser_profile, Some("refresh-token-v1"))
                    .await
            })
            .unwrap(),
            "a stale writer must be refused, not silently clobber the winner"
        );

        let stored = run(async { store.get_profile("example", "p1").await }).unwrap();
        assert_eq!(
            stored.method.refresh_token_material(),
            Some("refresh-token-v2"),
            "the winner's rotated token must survive"
        );
    }

    /// `expires_in` arrives as a `u64` from a provider JSON body. `TimeDelta`
    /// accepts values far beyond what `DateTime<Utc>` can represent, and
    /// `DateTime + TimeDelta` panics internally — so a hostile token response
    /// used to abort the handler task instead of failing closed.
    #[test]
    fn oauth_tokens_reject_expires_in_that_overflows_the_timestamp_range() {
        let err = OAuthTokens::bearer(
            "access-token",
            Some(StdDuration::from_secs(9_000_000_000_000_000)),
            Option::<String>::None,
            Option::<String>::None,
        )
        .expect_err("an overflowing expires_in must be rejected, not panic");
        assert!(
            matches!(err, AuthError::InvalidConfig { .. }),
            "expected InvalidConfig, got {err:?}"
        );

        // A sane TTL still works.
        assert!(
            OAuthTokens::bearer(
                "access-token",
                Some(StdDuration::from_secs(3_600)),
                Option::<String>::None,
                Option::<String>::None,
            )
            .is_ok()
        );
    }

    /// `verification_uri` is provider-controlled and is handed to an operator
    /// or browser to open, so it must be scheme-pinned like every other
    /// endpoint rather than merely non-empty and CRLF-free.
    #[test]
    fn device_code_challenge_rejects_non_http_verification_uri() {
        let err = OAuthDeviceCodeChallenge::new(
            "device-code",
            "USER-CODE",
            "javascript:fetch('https://evil.example')",
            Option::<String>::None,
            Utc::now() + TimeDelta::minutes(5),
            StdDuration::from_secs(5),
        )
        .expect_err("non-http verification_uri must be refused");
        assert!(
            matches!(err, AuthError::InvalidConfig { .. }),
            "expected InvalidConfig, got {err:?}"
        );

        assert!(
            OAuthDeviceCodeChallenge::new(
                "device-code",
                "USER-CODE",
                "https://auth.example.test/device",
                Option::<String>::None,
                Utc::now() + TimeDelta::minutes(5),
                StdDuration::from_secs(5),
            )
            .is_ok()
        );
    }

    #[test]
    fn oauth_auth_code_refresh_rotates_refresh_token_and_redacts_config_debug() {
        let mut auth = OAuthAuthCodeAuth::confidential_client(
            "fixture-client",
            "fixture-client-secret",
            "https://auth.example.test/authorize",
            "https://auth.example.test/token",
            "https://agent.example.test/oauth/callback",
            "chat messages",
            true,
        )
        .unwrap();
        auth.apply_tokens(oauth_tokens());
        let refresh_config = auth.refresh_config().unwrap();
        let debug = format!("{refresh_config:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("fixture-client-secret"));
        let transport = ScriptedRefreshTransport::new([OAuthRefreshProviderResponse::Authorized(
            OAuthTokens::bearer(
                "refreshed-access-token",
                Some(StdDuration::from_secs(7_200)),
                Some("rotated-refresh-token"),
                Some("chat messages"),
            )
            .unwrap(),
        )]);

        run(async { auth.refresh_with_transport(&cx(), &transport).await }).unwrap();

        let mut request = AuthRequest::new();
        run(async { auth.build_request_auth(&cx(), &mut request).await }).unwrap();
        assert_eq!(
            request.value_for("Authorization"),
            Some("Bearer refreshed-access-token")
        );
        assert_eq!(
            auth.refresh_grant().unwrap().refresh_token.expose_secret(),
            "rotated-refresh-token"
        );
        assert_eq!(transport.seen_client_secrets.lock().as_slice(), &[true]);
        assert_eq!(
            transport.seen_refresh_tokens.lock().as_slice(),
            &["fixture-refresh-token".to_string()]
        );
    }

    #[test]
    fn oauth_refresh_flow_maps_provider_rejection_and_malformed_token() {
        let config = OAuthRefreshTokenConfig::public_client(
            "fixture-client",
            "https://auth.example.test/token",
            Some("chat messages"),
        )
        .unwrap();
        let grant = OAuthRefreshTokenGrant::new("fixture-refresh-token").unwrap();
        let rejected = ScriptedRefreshTransport::new([OAuthRefreshProviderResponse::Rejected {
            code: "invalid_grant".to_string(),
            reason: "refresh token expired".to_string(),
        }]);

        let error =
            run(async { OAuthRefreshTokenFlow::refresh(&cx(), &config, &grant, &rejected).await })
                .unwrap_err();
        assert_eq!(
            error,
            AuthError::ProviderRejected {
                method: "oauth_refresh",
                code: "invalid_grant".to_string(),
                reason: "refresh token expired".to_string(),
            }
        );

        let bad_tokens = OAuthTokens {
            access_token: RedactedSecret::new("fixture-access-token").unwrap(),
            token_type: "mac".to_string(),
            refresh_token: None,
            expires_at: None,
            scope: None,
        };
        let malformed =
            ScriptedRefreshTransport::new([OAuthRefreshProviderResponse::Authorized(bad_tokens)]);

        let error =
            run(async { OAuthRefreshTokenFlow::refresh(&cx(), &config, &grant, &malformed).await })
                .unwrap_err();
        assert_eq!(
            error,
            AuthError::InvalidConfig {
                field: "token_type",
                reason: "only bearer tokens are supported in this slice".to_string(),
            }
        );
    }

    #[test]
    fn oauth_refresh_requires_cached_refresh_token() {
        let mut auth = OAuthDeviceCodeAuth::from_config(oauth_config());
        let transport = ScriptedRefreshTransport::new([]);

        let error =
            run(async { auth.refresh_with_transport(&cx(), &transport).await }).unwrap_err();

        assert_eq!(
            error,
            AuthError::MissingToken {
                method: "oauth_device"
            }
        );
        assert!(transport.seen_refresh_tokens.lock().is_empty());
    }

    #[test]
    fn jwt_auth_caches_generated_token() {
        let auth = JwtAuth::new("glm", StdDuration::from_secs(60), || {
            Ok("fixture-jwt-value".to_string())
        })
        .unwrap();
        let mut request = AuthRequest::new();

        run(async { auth.build_request_auth(&cx(), &mut request).await }).unwrap();

        assert_eq!(
            request.value_for("Authorization"),
            Some("Bearer fixture-jwt-value")
        );
        assert!(auth.cached_token().is_some());
        assert!(!format!("{auth:?}").contains("fixture-jwt-value"));
    }

    #[test]
    fn jwt_refresh_regenerates_cached_token() {
        let counter = Arc::new(AtomicUsize::new(0));
        let generator_counter = Arc::clone(&counter);
        let mut auth = JwtAuth::new("glm", StdDuration::from_secs(60), move || {
            Ok(format!(
                "fixture-jwt-{}",
                generator_counter.fetch_add(1, Ordering::SeqCst)
            ))
        })
        .unwrap();
        let mut request = AuthRequest::new();

        run(async { auth.build_request_auth(&cx(), &mut request).await }).unwrap();
        assert_eq!(
            request.value_for("Authorization"),
            Some("Bearer fixture-jwt-0")
        );

        run(async { auth.refresh(&cx()).await }).unwrap();
        let cached = auth.cached_token().unwrap();
        assert_eq!(cached.token.expose_secret(), "fixture-jwt-1");
        assert!(auth.requires_refresh_in().is_some());

        let mut refreshed_request = AuthRequest::new();
        run(async { auth.build_request_auth(&cx(), &mut refreshed_request).await }).unwrap();
        assert_eq!(
            refreshed_request.value_for("Authorization"),
            Some("Bearer fixture-jwt-1")
        );
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    // ── Canonical URI encoding (br-0lsi3, porting br-1nqg7) ──────────

    /// Canonical URI under the real S3 profile: single-encode, preserve dot
    /// segments.
    fn canonical_uri_s3(path: &str) -> String {
        canonical_uri(
            path,
            CanonicalPathEncoding::Single,
            CanonicalPathNormalization::Preserve,
        )
    }

    /// Canonical URI under the real non-S3 profile: double-encode, resolve dot
    /// segments. Both axes move together in production, so tests pair them the
    /// same way rather than exercising combinations no service uses.
    fn canonical_uri_other(path: &str) -> String {
        canonical_uri(
            path,
            CanonicalPathEncoding::Double,
            CanonicalPathNormalization::RemoveDotSegments,
        )
    }

    /// S3 requires exactly ONE encoding pass; every other service requires two.
    /// `canonical_uri` previously encoded the wire path once regardless of
    /// service, which is correct only for a path that needed no escaping.
    #[test]
    fn canonical_uri_encodes_once_for_s3_and_twice_for_other_services() {
        // `%20` on the wire decodes to a space, which S3 canonicalizes back to
        // `%20` — not `%2520`.
        assert_eq!(
            canonical_uri_s3("/bucket/my%20report.pdf"),
            "/bucket/my%20report.pdf"
        );
        assert_eq!(
            canonical_uri_other("/bucket/my%20report.pdf"),
            "/bucket/my%2520report.pdf"
        );
    }

    /// The port of `remove_dot_segments` into this crate.
    ///
    /// This was a LIVE `SignatureDoesNotMatch` bug, not a cosmetic gap: this
    /// signer had no normalisation at all, so any non-S3 caller that built a path
    /// by joining segments and landed a `//`, `/./` or `/../` signed the literal
    /// path while the service signed the resolved one. `fcp-sdk` was fixed first;
    /// this crate carries an independent signer and was still exposed.
    #[test]
    fn non_s3_resolves_dot_segments_and_s3_preserves_them() {
        for (input, resolved) in [
            ("/example/..", "/"),
            ("/example1/example2/../..", "/"),
            ("//", "/"),
            ("/./", "/"),
            ("/./example", "/example"),
            ("//example//", "/example/"),
        ] {
            assert_eq!(
                canonical_uri_other(input),
                resolved,
                "non-S3 must resolve {input}"
            );
        }

        // S3 must NOT normalise: an object key may legitimately contain `..` or
        // a double slash, so `/a/../b` names a literal key there. One input, two
        // different canonical URIs — so a future refactor cannot collapse the two
        // axes into one.
        assert_eq!(canonical_uri_s3("/bucket/a/../b"), "/bucket/a/../b");
        assert_eq!(canonical_uri_other("/bucket/a/../b"), "/bucket/b");
    }

    /// The normalisation profile must be threaded into the string that is
    /// actually signed, not merely exist as an unused selector.
    ///
    /// Asserting on the canonical request is what makes this meaningful:
    /// comparing two `Authorization` headers would differ anyway, because the
    /// service name also feeds the credential scope.
    #[test]
    fn path_normalization_reaches_the_canonical_request() {
        let context = SigV4SigningContext::new("GET", "/example/..", EMPTY_PAYLOAD_SHA256).unwrap();
        let uri_line = |normalization| {
            canonical_request(
                &context,
                "host:e\n",
                "host",
                CanonicalPathEncoding::Single,
                normalization,
            )
            .lines()
            .nth(1)
            .unwrap()
            .to_string()
        };

        assert_eq!(uri_line(CanonicalPathNormalization::RemoveDotSegments), "/");
        assert_eq!(
            uri_line(CanonicalPathNormalization::Preserve),
            "/example/.."
        );
    }

    /// The selector must key off the service, and must not be defeated by a
    /// struct literal that skips `SigV4Auth::new`'s lowercasing.
    #[test]
    fn canonical_path_normalization_preserves_only_for_s3() {
        assert_eq!(
            sigv4_auth(None).canonical_path_normalization(),
            CanonicalPathNormalization::Preserve
        );
        assert_eq!(
            sigv4_auth_for_service("execute-api").canonical_path_normalization(),
            CanonicalPathNormalization::RemoveDotSegments
        );
        let uppercase = SigV4Auth {
            service: "S3".to_string(),
            ..sigv4_auth(None)
        };
        assert_eq!(
            uppercase.canonical_path_normalization(),
            CanonicalPathNormalization::Preserve
        );
    }

    /// `omit_session_token` keeps the token off the SIGNATURE, not off the wire.
    #[test]
    fn omit_session_token_drops_the_token_from_the_signed_set_only() {
        let auth = sigv4_auth(Some("AQoDYXdzEXAMPLETOKEN"));
        let context = SigV4SigningContext::new("POST", "/", EMPTY_PAYLOAD_SHA256)
            .unwrap()
            .with_signing_time(sigv4_time());
        let headers = BTreeMap::from([("host".to_string(), "example.amazonaws.com".to_string())]);

        let options = SigV4SigningOptions {
            sign_content_sha256_header: false,
            omit_session_token: true,
            ..SigV4SigningOptions::default()
        };
        let (signed, trace) = auth.sign_traced(&context, &headers, options).unwrap();

        assert_eq!(trace.signed_headers, "host;x-amz-date");
        assert!(!trace.canonical_request.contains("x-amz-security-token"));
        assert_eq!(
            signed.x_amz_security_token.as_deref(),
            Some("AQoDYXdzEXAMPLETOKEN"),
            "the token is omitted from the signature, NOT from the request"
        );

        // The default signs it, and the two shapes must differ.
        let (_, default_trace) = auth
            .sign_traced(
                &context,
                &headers,
                SigV4SigningOptions {
                    sign_content_sha256_header: false,
                    ..SigV4SigningOptions::default()
                },
            )
            .unwrap();
        assert_eq!(
            default_trace.signed_headers,
            "host;x-amz-date;x-amz-security-token"
        );
        assert_ne!(
            trace.signature, default_trace.signature,
            "omitting the token must change the signature, or the flag is inert"
        );
    }

    /// `sign` must stay a pure delegation to `sign_traced`, or the traced path
    /// could drift from the production one and the vector harness would be
    /// checking something nothing ships.
    #[test]
    fn sign_and_sign_traced_agree() {
        let auth = sigv4_auth(None);
        let context = SigV4SigningContext::new("GET", "/bucket/key.txt", EMPTY_PAYLOAD_SHA256)
            .unwrap()
            .with_signing_time(sigv4_time());
        let headers = BTreeMap::from([("host".to_string(), "e.amazonaws.com".to_string())]);

        let plain = auth.sign(&context, &headers).unwrap();
        let (traced, trace) = auth
            .sign_traced(&context, &headers, SigV4SigningOptions::default())
            .unwrap();

        assert_eq!(plain, traced);
        assert!(plain.authorization.contains(&trace.signature));
        assert!(plain.authorization.contains(&trace.credential_scope));
        assert_eq!(plain.signed_headers, trace.signed_headers);
    }

    /// The property that makes this change safe to land without live AWS
    /// access: for a path built only from unreserved characters, BOTH the new
    /// single- and double-pass forms equal the old single-encode-the-wire-path
    /// behaviour. Every caller in the workspace today passes such a path, so
    /// no signature that verifies now stops verifying.
    #[test]
    fn canonical_uri_is_unchanged_for_paths_needing_no_escape() {
        for path in [
            "/",
            "/bucket/plain.pdf",
            "/model/invoke",
            "/path/to/file.txt",
        ] {
            let legacy = uri_encode_path(path);
            assert_eq!(
                canonical_uri_s3(path),
                legacy,
                "single-pass encoding must be a no-op change for {path}"
            );
            assert_eq!(
                canonical_uri_other(path),
                legacy,
                "double-pass encoding must also be a no-op change for {path}"
            );
        }
    }

    /// Characters the URL parser leaves unescaped (`&`, `+`, `:`) still get
    /// encoded by the canonicalizer, matching what the service computes after
    /// decoding. The widely-repeated claim that a raw `&` breaks S3 signing is
    /// false — it round-trips; see br-1nqg7.
    #[test]
    fn canonical_uri_encodes_aws_reserved_characters_left_raw_by_the_url_parser() {
        assert_eq!(canonical_uri_s3("/bucket/Q&A.pdf"), "/bucket/Q%26A.pdf");
        assert_eq!(canonical_uri_s3("/bucket/a+b.pdf"), "/bucket/a%2Bb.pdf");
        assert_eq!(canonical_uri_s3("/bucket/a:b.pdf"), "/bucket/a%3Ab.pdf");
    }

    /// A literal `%` in the key arrives as `%25` and must survive the
    /// decode/re-encode round trip rather than becoming `%2525`.
    #[test]
    fn canonical_uri_round_trips_a_literal_percent() {
        assert_eq!(canonical_uri_s3("/bucket/50%25.pdf"), "/bucket/50%25.pdf");
    }

    /// Non-ASCII keys are the most common real-world trigger — any accented or
    /// CJK filename arrives percent-encoded and was double-encoded before.
    #[test]
    fn canonical_uri_handles_non_ascii_keys() {
        assert_eq!(
            canonical_uri_s3("/bucket/e%C3%B1e.pdf"),
            "/bucket/e%C3%B1e.pdf"
        );
    }

    /// The selector must key off the service, and must not be defeated by a
    /// struct literal that skips `SigV4Auth::new`'s lowercasing.
    #[test]
    fn canonical_path_encoding_selects_single_only_for_s3() {
        assert_eq!(
            sigv4_auth(None).canonical_path_encoding(),
            CanonicalPathEncoding::Single
        );
        assert_eq!(
            sigv4_auth_for_service("execute-api").canonical_path_encoding(),
            CanonicalPathEncoding::Double
        );
        let uppercase = SigV4Auth {
            service: "S3".to_string(),
            ..sigv4_auth(None)
        };
        assert_eq!(
            uppercase.canonical_path_encoding(),
            CanonicalPathEncoding::Single
        );
    }

    /// Proves the mode is actually threaded into the string that gets signed,
    /// rather than merely existing as an unused selector. Asserting on the
    /// canonical request is what makes this meaningful — comparing two
    /// `Authorization` headers would differ anyway, because the service name
    /// also appears in the credential scope.
    #[test]
    fn path_encoding_reaches_the_canonical_request() {
        let context =
            SigV4SigningContext::new("GET", "/bucket/my%20report.pdf", EMPTY_PAYLOAD_SHA256)
                .unwrap();

        let s3_line = canonical_request(
            &context,
            "host:e\n",
            "host",
            CanonicalPathEncoding::Single,
            CanonicalPathNormalization::Preserve,
        )
        .lines()
        .nth(1)
        .unwrap()
        .to_string();
        let other_line = canonical_request(
            &context,
            "host:e\n",
            "host",
            CanonicalPathEncoding::Double,
            CanonicalPathNormalization::RemoveDotSegments,
        )
        .lines()
        .nth(1)
        .unwrap()
        .to_string();

        assert_eq!(s3_line, "/bucket/my%20report.pdf");
        assert_eq!(other_line, "/bucket/my%2520report.pdf");
    }

    #[test]
    fn sigv4_signs_aws_get_bucket_lifecycle_vector() {
        let auth = sigv4_auth(None);
        let context = SigV4SigningContext::new("GET", "/", EMPTY_PAYLOAD_SHA256)
            .unwrap()
            .with_query_param("lifecycle", "")
            .unwrap()
            .with_signing_time(sigv4_time());
        let mut request = AuthRequest::new();
        request
            .set_header("Host", "examplebucket.s3.amazonaws.com")
            .unwrap();
        request.set_sigv4_context(context);

        run(async { auth.build_request_auth(&cx(), &mut request).await }).unwrap();

        assert_eq!(request.value_for("x-amz-date"), Some("20130524T000000Z"));
        assert_eq!(
            request.value_for("x-amz-content-sha256"),
            Some(EMPTY_PAYLOAD_SHA256)
        );
        // `", "` after each comma, matching AWS's documented examples and
        // `fcp_sdk::sigv4`. The SIGNATURE below is byte-identical to what this test
        // asserted under the old comma-only spacing, which is the proof that the
        // Authorization header's formatting is outside the signed material — only
        // the canonical request is hashed.
        let expected_authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543",
            aws_example_access_key()
        );
        assert_eq!(
            request.value_for("Authorization"),
            Some(expected_authorization.as_str())
        );
    }

    #[test]
    fn sigv4_includes_session_token_and_redacts_debug() {
        let auth = sigv4_auth(Some("fixture-session-token"));
        let context = SigV4SigningContext::new("POST", "/model/invoke", sha256_payload_hex(b"{}"))
            .unwrap()
            .with_signing_time(sigv4_time());
        let mut request = AuthRequest::new();
        request.set_header("Host", "bedrock.amazonaws.com").unwrap();
        request.set_sigv4_context(context);

        run(async { auth.build_request_auth(&cx(), &mut request).await }).unwrap();

        assert_eq!(
            request.value_for("x-amz-security-token"),
            Some("fixture-session-token")
        );
        assert!(
            request
                .value_for("Authorization")
                .unwrap()
                .contains("x-amz-security-token")
        );
        assert!(!format!("{auth:?}").contains("fixture-session-token"));
        let signed = auth
            .sign(request.sigv4_context().unwrap(), request.headers())
            .unwrap();
        assert!(!format!("{signed:?}").contains("fixture-session-token"));
    }

    #[test]
    fn sigv4_requires_signing_context() {
        let auth = sigv4_auth(None);
        let mut request = AuthRequest::new();
        request
            .set_header("Host", "examplebucket.s3.amazonaws.com")
            .unwrap();

        let error = run(async { auth.build_request_auth(&cx(), &mut request).await }).unwrap_err();

        assert_eq!(error, AuthError::MissingSigningContext { method: "sigv4" });
    }

    #[test]
    fn profile_store_orders_by_priority_then_id() {
        let store = InMemoryAuthProfileStore::new();
        let later = api_profile("later", "Anthropic", 20);
        let tie_b = api_profile("tie-b", "anthropic", 10);
        let tie_a = api_profile("tie-a", "anthropic", 10);

        run(store.save_profile(later)).unwrap();
        run(store.save_profile(tie_b)).unwrap();
        run(store.save_profile(tie_a)).unwrap();

        let profiles = run(store.list_profiles("ANTHROPIC")).unwrap();
        let ids = profiles
            .iter()
            .map(|profile| profile.id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(ids, ["tie-a", "tie-b", "later"]);

        let active = run(store.pick_active("anthropic")).unwrap();
        assert_eq!(active.id, "tie-a");
    }

    #[test]
    fn profile_store_reports_missing_provider_and_profile() {
        let store = InMemoryAuthProfileStore::new();

        let missing_provider = run(store.pick_active("openai")).unwrap_err();
        assert_eq!(
            missing_provider,
            AuthError::ProviderNotFound {
                provider: "openai".to_string()
            }
        );

        let missing_profile = run(store.get_profile("openai", "work")).unwrap_err();
        assert_eq!(
            missing_profile,
            AuthError::ProfileNotFound {
                provider: "openai".to_string(),
                profile_id: "work".to_string()
            }
        );
    }

    #[test]
    fn profile_store_delete_removes_profile() {
        let store = InMemoryAuthProfileStore::new();

        run(store.save_profile(api_profile("work", "openai", 0))).unwrap();
        run(store.delete_profile("openai", "work")).unwrap();

        let error = run(store.get_profile("openai", "work")).unwrap_err();
        assert!(matches!(error, AuthError::ProfileNotFound { .. }));
    }

    #[test]
    fn token_refresh_actor_refreshes_due_jwt_profile_and_persists_it() {
        let counter = Arc::new(AtomicUsize::new(0));
        let generator_counter = Arc::clone(&counter);
        let auth = JwtAuth::new("glm", StdDuration::from_secs(3_600), move || {
            Ok(format!(
                "fixture-jwt-{}",
                generator_counter.fetch_add(1, Ordering::SeqCst)
            ))
        })
        .unwrap();
        let mut request = AuthRequest::new();
        run(async { auth.build_request_auth(&cx(), &mut request).await }).unwrap();
        assert_eq!(
            request.value_for("Authorization"),
            Some("Bearer fixture-jwt-0")
        );
        let profile =
            AuthProfile::new("work", "glm", AuthMethodKind::Jwt(auth), "work", 0).unwrap();
        let store = Arc::new(InMemoryAuthProfileStore::new());
        run(store.save_profile(profile)).unwrap();
        let actor = TokenRefreshActor::new(
            Arc::clone(&store),
            TokenRefreshPolicy::new(StdDuration::from_secs(7_200)),
        );

        let report = run(async { actor.refresh_provider(&cx(), "GLM").await }).unwrap();

        assert_eq!(report.refreshed_count(), 1);
        assert_eq!(report.skipped_count(), 0);
        assert_eq!(report.failed_count(), 0);
        assert!(matches!(
            report.outcomes.as_slice(),
            [TokenRefreshOutcome::Refreshed(TokenRefreshDecision {
                provider,
                profile_id,
                method: "jwt",
                action: TokenRefreshAction::Due,
                ..
            })] if provider == "glm" && profile_id == "work"
        ));
        let refreshed = run(store.get_profile("glm", "work")).unwrap();
        let mut refreshed_request = AuthRequest::new();
        run(async {
            refreshed
                .method
                .build_request_auth(&cx(), &mut refreshed_request)
                .await
        })
        .unwrap();
        assert_eq!(
            refreshed_request.value_for("Authorization"),
            Some("Bearer fixture-jwt-1")
        );
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn token_refresh_actor_skips_static_and_fresh_profiles() {
        let auth = JwtAuth::new("glm", StdDuration::from_secs(3_600), || {
            Ok("fixture-jwt-value".to_string())
        })
        .unwrap();
        let mut request = AuthRequest::new();
        run(async { auth.build_request_auth(&cx(), &mut request).await }).unwrap();
        let jwt_profile =
            AuthProfile::new("fresh", "glm", AuthMethodKind::Jwt(auth), "fresh", 10).unwrap();
        let api_profile = api_profile("static", "glm", 0);
        let store = Arc::new(InMemoryAuthProfileStore::new());
        run(store.save_profile(jwt_profile)).unwrap();
        run(store.save_profile(api_profile)).unwrap();
        let actor = TokenRefreshActor::new(
            Arc::clone(&store),
            TokenRefreshPolicy::new(StdDuration::from_secs(1)),
        );

        let report = run(async { actor.refresh_provider(&cx(), "glm").await }).unwrap();

        assert_eq!(report.refreshed_count(), 0);
        assert_eq!(report.skipped_count(), 2);
        assert_eq!(report.failed_count(), 0);
        let actions = report
            .outcomes
            .iter()
            .map(TokenRefreshOutcome::decision)
            .map(|decision| (decision.profile_id.as_str(), decision.action))
            .collect::<Vec<_>>();
        assert_eq!(
            actions,
            [
                ("static", TokenRefreshAction::NotRefreshable),
                ("fresh", TokenRefreshAction::Fresh)
            ]
        );
    }

    #[test]
    fn token_refresh_actor_reports_unsupported_refresh_failure() {
        let profile = AuthProfile::new(
            "setup",
            "bootstrap",
            AuthMethodKind::SetupToken(
                SetupTokenAuth::bearer("setup-token", Utc::now() + TimeDelta::minutes(1)).unwrap(),
            ),
            "setup",
            0,
        )
        .unwrap();
        let store = Arc::new(InMemoryAuthProfileStore::new());
        run(store.save_profile(profile)).unwrap();
        let actor = TokenRefreshActor::new(
            Arc::clone(&store),
            TokenRefreshPolicy::new(StdDuration::from_secs(3_600)),
        );

        let outcome =
            run(async { actor.refresh_profile(&cx(), "bootstrap", "setup").await }).unwrap();

        assert!(matches!(
            outcome,
            TokenRefreshOutcome::Failed {
                decision: TokenRefreshDecision {
                    provider,
                    profile_id,
                    method: "setup_token",
                    action: TokenRefreshAction::Due,
                    ..
                },
                error: AuthError::UnsupportedMethod {
                    method: "setup_token",
                    operation: "refresh"
                }
            } if provider == "bootstrap" && profile_id == "setup"
        ));
    }

    #[test]
    fn token_refresh_actor_reports_missing_profile_before_refresh() {
        let store = Arc::new(InMemoryAuthProfileStore::new());
        let actor = TokenRefreshActor::new(Arc::clone(&store), TokenRefreshPolicy::default());

        let error =
            run(async { actor.refresh_profile(&cx(), "openai", "work").await }).unwrap_err();

        assert_eq!(
            error,
            AuthError::ProfileNotFound {
                provider: "openai".to_string(),
                profile_id: "work".to_string(),
            }
        );
    }
}
