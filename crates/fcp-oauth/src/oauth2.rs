//! OAuth 2.0 implementation.
//!
//! Supports authorization code flow (with PKCE) and client credentials flow.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use base64::{Engine, engine::general_purpose::STANDARD};
use fcp_async_core::http::{HttpClient, HttpClientBuilder, HttpResponse, Method};
use fcp_async_core::time;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use url::Url;

use crate::{
    GrantType, OAuthError, OAuthResult, OAuthTokens, Pkce, PkceMethod, ResponseMode, TokenResponse,
    normalize_registered_redirect_uri, validate_oauth_endpoint_url,
};

const FORM_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";
const JSON_CONTENT_TYPE: &str = "application/json";
const EMPTY_AUTHORIZATION_CODE_MESSAGE: &str = "authorization code must not be empty or whitespace";

/// Encode a single OAuth credential component using Appendix B
/// `application/x-www-form-urlencoded` rules.
///
/// RFC 6749 Section 2.3.1 requires this encoding before concatenating
/// `client_id:client_secret` for HTTP Basic auth. This is not plain RFC 3986
/// percent-encoding because spaces must become `+`.
fn form_encode(s: &str) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair("", s)
        .finish()
        .strip_prefix('=')
        .unwrap_or_default()
        .to_string()
}

/// OAuth authentication style.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthStyle {
    /// HTTP Basic Authentication (Authorization header).
    Basic,
    /// Request body parameters (`client_id/client_secret`).
    #[default]
    Post,
}

impl std::fmt::Display for AuthStyle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Basic => write!(f, "basic"),
            Self::Post => write!(f, "post"),
        }
    }
}

/// OAuth 2.0 configuration.
#[derive(Clone)]
pub struct OAuth2Config {
    /// Client ID.
    pub client_id: String,
    /// Client secret (optional for public clients).
    pub client_secret: Option<String>,
    /// Authorization endpoint URL.
    pub authorization_url: String,
    /// Token endpoint URL.
    pub token_url: String,
    /// Redirect URI for authorization code flow.
    pub redirect_uri: Option<String>,
    /// Default scopes to request.
    pub default_scopes: Vec<String>,
    /// Whether to use PKCE.
    pub use_pkce: bool,
    /// PKCE method.
    pub pkce_method: PkceMethod,
    /// Response mode for authorization.
    pub response_mode: ResponseMode,
    /// Authentication style for token requests.
    pub auth_style: AuthStyle,
    /// Additional authorization parameters.
    pub extra_auth_params: HashMap<String, String>,
    /// Additional token parameters.
    pub extra_token_params: HashMap<String, String>,
    /// HTTP client timeout.
    pub timeout: Duration,
}

impl std::fmt::Debug for OAuth2Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuth2Config")
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("authorization_url", &self.authorization_url)
            .field("token_url", &self.token_url)
            .field("redirect_uri", &self.redirect_uri)
            .field("default_scopes", &self.default_scopes)
            .field("use_pkce", &self.use_pkce)
            .field("auth_style", &self.auth_style)
            .finish_non_exhaustive()
    }
}

impl OAuth2Config {
    /// Create a new OAuth 2.0 configuration.
    #[must_use]
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        authorization_url: impl Into<String>,
        token_url: impl Into<String>,
    ) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: Some(client_secret.into()),
            authorization_url: authorization_url.into(),
            token_url: token_url.into(),
            redirect_uri: None,
            default_scopes: Vec::new(),
            use_pkce: true,
            pkce_method: PkceMethod::S256,
            response_mode: ResponseMode::Query,
            auth_style: AuthStyle::Post,
            extra_auth_params: HashMap::new(),
            extra_token_params: HashMap::new(),
            timeout: Duration::from_secs(30),
        }
    }

    /// Create configuration for a public client (no secret).
    #[must_use]
    pub fn public_client(
        client_id: impl Into<String>,
        authorization_url: impl Into<String>,
        token_url: impl Into<String>,
    ) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: None,
            authorization_url: authorization_url.into(),
            token_url: token_url.into(),
            redirect_uri: None,
            default_scopes: Vec::new(),
            use_pkce: true, // PKCE is required for public clients
            pkce_method: PkceMethod::S256,
            response_mode: ResponseMode::Query,
            auth_style: AuthStyle::Post,
            extra_auth_params: HashMap::new(),
            extra_token_params: HashMap::new(),
            timeout: Duration::from_secs(30),
        }
    }

    /// Set the redirect URI.
    #[must_use]
    pub fn with_redirect_uri(mut self, uri: impl Into<String>) -> Self {
        self.redirect_uri = Some(uri.into());
        self
    }

    /// Set default scopes.
    #[must_use]
    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.default_scopes = scopes;
        self
    }

    /// Enable or disable PKCE.
    #[must_use]
    pub const fn with_pkce(mut self, enabled: bool) -> Self {
        self.use_pkce = enabled;
        self
    }

    /// Set PKCE method.
    #[must_use]
    pub const fn with_pkce_method(mut self, method: PkceMethod) -> Self {
        self.pkce_method = method;
        self
    }

    /// Set response mode.
    #[must_use]
    pub const fn with_response_mode(mut self, mode: ResponseMode) -> Self {
        self.response_mode = mode;
        self
    }

    /// Set authentication style.
    #[must_use]
    pub const fn with_auth_style(mut self, style: AuthStyle) -> Self {
        self.auth_style = style;
        self
    }

    /// Add extra authorization parameter.
    #[must_use]
    pub fn with_auth_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra_auth_params.insert(key.into(), value.into());
        self
    }

    /// Add extra token parameter.
    #[must_use]
    pub fn with_token_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra_token_params.insert(key.into(), value.into());
        self
    }

    /// Set timeout.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// OAuth 2.0 client.
#[derive(Clone)]
pub struct OAuth2Client {
    config: OAuth2Config,
    http_client: Arc<HttpClient>,
}

/// One-time authorization session tying together state and optional PKCE.
#[derive(Clone)]
pub struct AuthorizationSession {
    authorization_url: String,
    state: String,
    pkce: Option<Pkce>,
    consumed: Arc<AtomicBool>,
}

/// Validated authorization grant extracted from a callback.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthorizationGrant {
    code: String,
    pkce: Option<Pkce>,
}

impl AuthorizationSession {
    /// Get the authorization URL.
    #[must_use]
    pub fn authorization_url(&self) -> &str {
        &self.authorization_url
    }

    /// Get the CSRF state value.
    #[must_use]
    pub fn state(&self) -> &str {
        &self.state
    }

    /// Get the PKCE parameters for this session, if any.
    #[must_use]
    pub const fn pkce(&self) -> Option<&Pkce> {
        self.pkce.as_ref()
    }

    /// Validate a provider callback exactly once.
    ///
    /// On failure the session remains reusable only for validation failures
    /// before the callback is accepted. Once a callback validates successfully,
    /// the session is consumed and later reuse attempts are rejected.
    ///
    /// # Errors
    /// Returns [`OAuthError::AuthorizationSessionConsumed`] when called after a
    /// successful validation, or any callback validation error from
    /// [`AuthorizationCallback::validate`].
    pub fn validate_callback(
        &self,
        callback: &AuthorizationCallback,
    ) -> OAuthResult<AuthorizationGrant> {
        if self
            .consumed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(OAuthError::AuthorizationSessionConsumed);
        }

        match callback.validate(&self.state) {
            Ok(code) => Ok(AuthorizationGrant {
                code,
                pkce: self.pkce.clone(),
            }),
            Err(error) => {
                self.consumed.store(false, Ordering::Release);
                Err(error)
            }
        }
    }
}

impl fmt::Debug for AuthorizationSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorizationSession")
            .field(
                "authorization_url",
                &redacted_authorization_debug_url(&self.authorization_url),
            )
            .field("state", &"[REDACTED]")
            .field("pkce", &self.pkce)
            .field("consumed", &self.consumed.load(Ordering::Acquire))
            .finish()
    }
}

impl AuthorizationGrant {
    /// Get the authorization code.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Get the PKCE verifier/challenge associated with this grant.
    #[must_use]
    pub const fn pkce(&self) -> Option<&Pkce> {
        self.pkce.as_ref()
    }
}

impl fmt::Debug for AuthorizationGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorizationGrant")
            .field("code", &"[REDACTED]")
            .field("pkce", &self.pkce)
            .finish()
    }
}

impl std::fmt::Debug for OAuth2Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuth2Client")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

fn reserved_extra_auth_param(key: &str) -> bool {
    matches!(
        key,
        "response_type"
            | "client_id"
            | "state"
            | "redirect_uri"
            | "scope"
            | "code_challenge"
            | "code_challenge_method"
            | "response_mode"
    )
}

fn reserved_extra_token_param(key: &str) -> bool {
    matches!(
        key,
        "grant_type"
            | "code"
            | "redirect_uri"
            | "refresh_token"
            | "scope"
            | "client_id"
            | "client_secret"
            | "code_verifier"
    )
}

fn validate_oauth2_config(mut config: OAuth2Config) -> OAuthResult<OAuth2Config> {
    config.authorization_url =
        validate_oauth_endpoint_url(&config.authorization_url, "authorization_url")?;
    config.token_url = validate_oauth_endpoint_url(&config.token_url, "token_url")?;
    if let Some(redirect_uri) = config.redirect_uri.as_deref() {
        config.redirect_uri =
            Some(normalize_registered_redirect_uri(redirect_uri, "redirect_uri")?.into());
    }
    if let Some(key) = config
        .extra_auth_params
        .keys()
        .find(|key| reserved_extra_auth_param(key))
    {
        return Err(OAuthError::InvalidConfig(format!(
            "extra auth param `{key}` is reserved by the OAuth 2.0 flow"
        )));
    }
    if let Some(key) = config
        .extra_token_params
        .keys()
        .find(|key| reserved_extra_token_param(key))
    {
        return Err(OAuthError::InvalidConfig(format!(
            "extra token param `{key}` is reserved by the OAuth 2.0 flow"
        )));
    }
    Ok(config)
}

impl OAuth2Client {
    /// Create a new OAuth 2.0 client.
    ///
    /// # Errors
    /// Returns an error when the configured authorization URL, token URL,
    /// or redirect URI is invalid.
    pub fn new(config: OAuth2Config) -> OAuthResult<Self> {
        let config = validate_oauth2_config(config)?;

        Ok(Self {
            config,
            http_client: Arc::new(
                HttpClientBuilder::new()
                    .user_agent("fcp-oauth/0.1.0")
                    .build(),
            ),
        })
    }

    /// Create with a custom HTTP client.
    ///
    /// # Errors
    /// Returns an error when the configured authorization URL, token URL,
    /// or redirect URI is invalid.
    pub fn with_http_client(config: OAuth2Config, http_client: HttpClient) -> OAuthResult<Self> {
        let config = validate_oauth2_config(config)?;

        Ok(Self {
            config,
            http_client: Arc::new(http_client),
        })
    }

    /// Generate authorization URL.
    ///
    /// Returns (`authorization_url`, `state`).
    ///
    /// # Errors
    /// Returns an error when the configured authorization endpoint is invalid.
    pub fn authorization_url(&self, scopes: &[&str]) -> OAuthResult<(String, String)> {
        let session = self.authorization_session(scopes)?;
        Ok((
            session.authorization_url().to_string(),
            session.state().to_string(),
        ))
    }

    /// Generate authorization URL with PKCE.
    ///
    /// Returns (`authorization_url`, `state`, `pkce`).
    ///
    /// # Errors
    /// Returns an error when the configured authorization endpoint is invalid.
    pub fn authorization_url_with_pkce(
        &self,
        scopes: &[&str],
    ) -> OAuthResult<(String, String, Pkce)> {
        let session = self.authorization_session_with_pkce(scopes)?;
        let pkce = session.pkce().cloned().ok_or_else(|| {
            OAuthError::InvalidConfig(
                "authorization session did not include PKCE material".to_string(),
            )
        })?;
        Ok((
            session.authorization_url().to_string(),
            session.state().to_string(),
            pkce,
        ))
    }

    /// Build a one-time authorization session.
    ///
    /// # Errors
    /// Returns an error when the configured authorization endpoint is invalid.
    pub fn authorization_session(&self, scopes: &[&str]) -> OAuthResult<AuthorizationSession> {
        let state = generate_state();
        let pkce = self
            .config
            .use_pkce
            .then(|| Pkce::with_method(self.config.pkce_method));
        let authorization_url = self.build_auth_url(scopes, &state, pkce.as_ref())?;
        Ok(AuthorizationSession {
            authorization_url,
            state,
            pkce,
            consumed: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Build a one-time authorization session with PKCE.
    ///
    /// # Errors
    /// Returns an error when the configured authorization endpoint is invalid.
    pub fn authorization_session_with_pkce(
        &self,
        scopes: &[&str],
    ) -> OAuthResult<AuthorizationSession> {
        let state = generate_state();
        let pkce = Pkce::with_method(self.config.pkce_method);
        let authorization_url = self.build_auth_url(scopes, &state, Some(&pkce))?;
        Ok(AuthorizationSession {
            authorization_url,
            state,
            pkce: Some(pkce),
            consumed: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Build the authorization URL.
    fn build_auth_url(
        &self,
        scopes: &[&str],
        state: &str,
        pkce: Option<&Pkce>,
    ) -> OAuthResult<String> {
        let mut url = Url::parse(&self.config.authorization_url)?;

        {
            let mut params = url.query_pairs_mut();

            params.append_pair("response_type", "code");
            params.append_pair("client_id", &self.config.client_id);
            params.append_pair("state", state);

            if let Some(redirect_uri) = &self.config.redirect_uri {
                params.append_pair("redirect_uri", redirect_uri);
            }

            // Combine default scopes with requested scopes.
            // Build the space-joined string directly to avoid intermediate Vec allocation.
            let scope_iter = self
                .config
                .default_scopes
                .iter()
                .map(String::as_str)
                .chain(scopes.iter().copied());
            let mut scope_str = String::new();
            for (i, s) in scope_iter.enumerate() {
                if i > 0 {
                    scope_str.push(' ');
                }
                scope_str.push_str(s);
            }
            if !scope_str.is_empty() {
                params.append_pair("scope", &scope_str);
            }

            // PKCE parameters
            if let Some(pkce) = pkce {
                params.append_pair("code_challenge", pkce.challenge());
                params.append_pair("code_challenge_method", &pkce.method().to_string());
            }

            // Response mode (if not default)
            if self.config.response_mode != ResponseMode::Query {
                params.append_pair("response_mode", &self.config.response_mode.to_string());
            }

            // Extra parameters
            for (key, value) in &self.config.extra_auth_params {
                params.append_pair(key, value);
            }
        }

        Ok(url.to_string())
    }

    /// Exchange authorization code for tokens.
    ///
    /// # Errors
    /// Returns an error when token exchange fails or the response is invalid.
    pub async fn exchange_code(&self, code: &str) -> OAuthResult<OAuthTokens> {
        if self.config.use_pkce {
            return Err(OAuthError::InvalidConfig(
                "authorization_code flow requires PKCE; use exchange_code_with_pkce() with per-flow PKCE material"
                    .into(),
            ));
        }
        self.exchange_code_internal(code, None).await
    }

    /// Exchange authorization code for tokens with PKCE verification.
    ///
    /// # Errors
    /// Returns an error when token exchange fails or the response is invalid.
    pub async fn exchange_code_with_pkce(
        &self,
        code: &str,
        pkce: &Pkce,
    ) -> OAuthResult<OAuthTokens> {
        self.exchange_code_internal(code, Some(pkce)).await
    }

    /// Internal code exchange implementation.
    async fn exchange_code_internal(
        &self,
        code: &str,
        pkce: Option<&Pkce>,
    ) -> OAuthResult<OAuthTokens> {
        reject_empty_authorization_code(code)?;

        if self.config.use_pkce && pkce.is_none() {
            return Err(OAuthError::InvalidConfig(
                "authorization_code flow requires per-flow PKCE code_verifier".into(),
            ));
        }
        let mut params = HashMap::new();
        params.insert("grant_type", GrantType::AuthorizationCode.to_string());
        params.insert("code", code.to_string());

        if let Some(redirect_uri) = &self.config.redirect_uri {
            params.insert("redirect_uri", redirect_uri.clone());
        }

        // Extra parameters first — a real PKCE verifier (below) MUST win over
        // any `code_verifier` a caller accidentally left in
        // `extra_token_params`. Writing PKCE after the merge closes a latent
        // hole where an attacker-influenced extra_token_params entry would
        // overwrite the honest verifier produced by the authorization flow.
        for (key, value) in &self.config.extra_token_params {
            if key == "code_verifier" {
                continue;
            }
            params.insert(key, value.clone());
        }

        if let Some(pkce) = pkce {
            params.insert("code_verifier", pkce.verifier().to_string());
        }

        self.token_request(params).await
    }

    /// Get tokens using client credentials flow.
    ///
    /// # Errors
    /// Returns an error when client credentials are misconfigured, token exchange fails,
    /// or the token response is invalid.
    pub async fn client_credentials(&self, scopes: &[&str]) -> OAuthResult<OAuthTokens> {
        // Only require secret if not public client (though client creds usually implies confidential)
        // If public client tries client creds, it might fail at provider, but we shouldn't block it here if secret is None
        // But RFC says client credentials grant is for confidential clients.
        if self.config.client_secret.is_none() {
            return Err(OAuthError::InvalidConfig(
                "Client secret required for client credentials flow".into(),
            ));
        }

        let mut params = HashMap::new();
        params.insert("grant_type", GrantType::ClientCredentials.to_string());

        let all_scopes: Vec<&str> = self
            .config
            .default_scopes
            .iter()
            .map(String::as_str)
            .chain(scopes.iter().copied())
            .collect();

        if !all_scopes.is_empty() {
            params.insert("scope", all_scopes.join(" "));
        }

        // Extra parameters
        for (key, value) in &self.config.extra_token_params {
            params.insert(key, value.clone());
        }

        self.token_request(params).await
    }

    /// Refresh tokens using a refresh token.
    ///
    /// # Errors
    /// Returns an error when token refresh fails or the token response is invalid.
    pub async fn refresh_tokens(&self, refresh_token: &str) -> OAuthResult<OAuthTokens> {
        if refresh_token.is_empty() {
            return Err(OAuthError::InvalidTokenResponse(
                "refresh token cannot be empty".into(),
            ));
        }

        let mut params = HashMap::new();
        params.insert("grant_type", GrantType::RefreshToken.to_string());
        params.insert("refresh_token", refresh_token.to_string());

        if !self.config.default_scopes.is_empty() {
            params.insert("scope", self.config.default_scopes.join(" "));
        }

        // Extra parameters
        for (key, value) in &self.config.extra_token_params {
            params.insert(key, value.clone());
        }

        let mut tokens = self.token_request(params).await?;
        // RFC-compliant providers may omit refresh_token on refresh when the
        // existing refresh credential remains valid. Preserve the caller's
        // current refresh token so a successful refresh does not silently drop
        // future refresh capability.
        tokens.preserve_refresh_token_if_missing(refresh_token);
        Ok(tokens)
    }

    /// Make a token request.
    async fn token_request(&self, mut params: HashMap<&str, String>) -> OAuthResult<OAuthTokens> {
        let mut headers = vec![
            ("Content-Type".to_string(), FORM_CONTENT_TYPE.to_string()),
            ("Accept".to_string(), JSON_CONTENT_TYPE.to_string()),
        ];

        match self.config.auth_style {
            AuthStyle::Basic => {
                // RFC 6749 Section 2.3.1: client_id and client_secret MUST be
                // URL-encoded before concatenation with ':' in Basic auth.
                let credentials = format!(
                    "{}:{}",
                    form_encode(&self.config.client_id),
                    form_encode(self.config.client_secret.as_deref().unwrap_or(""))
                );
                headers.push((
                    "Authorization".to_string(),
                    format!("Basic {}", STANDARD.encode(credentials)),
                ));
            }
            AuthStyle::Post => {
                params.insert("client_id", self.config.client_id.clone());
                if let Some(secret) = &self.config.client_secret {
                    params.insert("client_secret", secret.clone());
                }
            }
        }

        let body = serde_urlencoded::to_string(&params)
            .map_err(|e| OAuthError::InvalidTokenResponse(e.to_string()))?;
        let response = self
            .send_request(
                Method::Post,
                &self.config.token_url,
                headers,
                body.into_bytes(),
            )
            .await?;

        if !response.is_success() {
            return Err(token_endpoint_unsuccessful_error(response.status));
        }

        let token_response: TokenResponse = response.json()?;

        // Defensive: a misbehaving or compromised OAuth server may return
        // {"access_token": "", "token_type": "Bearer", ...} with a 200
        // status. Storing that produces an unusable token and downstream
        // `authorization_header()` returns a bare "Bearer " that any
        // resource server will reject, burning a refresh cycle for no
        // reason. Fail fast here instead.
        if token_response.access_token.is_empty() {
            return Err(OAuthError::EmptyTokenField("access_token"));
        }
        if token_response.token_type.is_empty() {
            return Err(OAuthError::EmptyTokenField("token_type"));
        }

        OAuthTokens::from_response(token_response)
    }

    /// Get the configuration.
    #[must_use]
    pub const fn config(&self) -> &OAuth2Config {
        &self.config
    }

    async fn send_request(
        &self,
        method: Method,
        url: &str,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) -> OAuthResult<HttpResponse> {
        let cx = fcp_async_core::compatibility_cx();
        match time::timeout(
            self.config.timeout,
            self.http_client.request(&cx, method, url, headers, body),
        )
        .await
        {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(error)) => Err(OAuthError::from_http_client_error(&error)),
            Err(error) => Err(OAuthError::from_async_error(error, self.config.timeout)),
        }
    }
}

fn token_endpoint_unsuccessful_error(status: u16) -> OAuthError {
    OAuthError::TokenExchangeFailed(format!(
        "token endpoint returned an unsuccessful response (status {status})"
    ))
}

/// Authorization callback parameters.
#[derive(Clone, Serialize, Deserialize)]
pub struct AuthorizationCallback {
    /// Authorization code.
    pub code: Option<String>,
    /// State parameter.
    pub state: Option<String>,
    /// Error code.
    pub error: Option<String>,
    /// Error description.
    pub error_description: Option<String>,
    /// Error URI.
    pub error_uri: Option<String>,
}

impl fmt::Debug for AuthorizationCallback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorizationCallback")
            .field("code", &self.code.as_ref().map(|_| "[REDACTED]"))
            .field("state", &self.state.as_ref().map(|_| "[REDACTED]"))
            .field("error", &self.error)
            .field(
                "error_description",
                &self.error_description.as_ref().map(|_| "[REDACTED]"),
            )
            .field("error_uri", &self.error_uri.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

fn redacted_authorization_debug_url(url: &str) -> String {
    let Ok(mut parsed) = Url::parse(url) else {
        return "[REDACTED]".to_string();
    };
    parsed.set_query(None);
    parsed.set_fragment(None);
    parsed.to_string()
}

impl AuthorizationCallback {
    /// Parse callback from query string.
    ///
    /// # Errors
    /// Returns an error when the query string cannot be deserialized into callback fields.
    pub fn from_query(query: &str) -> OAuthResult<Self> {
        reject_duplicate_callback_params(query)?;
        serde_urlencoded::from_str(query)
            .map_err(|e| OAuthError::InvalidTokenResponse(e.to_string()))
    }

    /// Parse callback from URL.
    ///
    /// # Errors
    /// Returns an error when the URL is invalid or callback parameters cannot be parsed.
    pub fn from_url(url: &str) -> OAuthResult<Self> {
        let parsed = Url::parse(url)?;
        let encoded = parsed
            .query()
            .filter(|query| !query.is_empty())
            .or_else(|| parsed.fragment().filter(|fragment| !fragment.is_empty()))
            .unwrap_or("");
        Self::from_query(encoded)
    }

    /// Validate the callback and extract the code.
    ///
    /// # Errors
    /// Returns an error for ambiguous callbacks, provider error callbacks, state mismatches,
    /// or missing `code`.
    pub fn validate(&self, expected_state: &str) -> OAuthResult<String> {
        if self.code.is_some() && self.error.is_some() {
            return Err(OAuthError::InvalidTokenResponse(
                "callback must not include both code and error".into(),
            ));
        }

        if expected_state.is_empty() {
            return Err(OAuthError::InvalidState(
                "expected state must not be empty".into(),
            ));
        }

        // Validate state
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| OAuthError::InvalidTokenResponse("Missing state parameter".into()))?;
        if state.is_empty() {
            return Err(OAuthError::InvalidState(
                "callback state must not be empty".into(),
            ));
        }

        // Guard against length mismatch: ct_eq panics when slice lengths
        // differ.  Check lengths first (leaking only the length, which is
        // already observable from the URL) and fall through to constant-time
        // comparison only when lengths match.
        let state_matches = state.len() == expected_state.len()
            && state
                .as_bytes()
                .ct_eq(expected_state.as_bytes())
                .unwrap_u8()
                == 1;
        if !state_matches {
            return Err(OAuthError::StateMismatch {
                expected: expected_state.to_string(),
                actual: state.clone(),
            });
        }

        // Provider error callbacks still have to prove they belong to the
        // authorization session before their provider-controlled fields matter.
        if let Some(error) = &self.error {
            return Err(OAuthError::AuthorizationError {
                error: error.clone(),
                description: self.error_description.clone().unwrap_or_default(),
                error_uri: self.error_uri.clone(),
            });
        }

        let code = self
            .code
            .as_ref()
            .ok_or_else(|| OAuthError::InvalidTokenResponse("Missing authorization code".into()))?;
        reject_empty_authorization_code(code)?;
        Ok(code.clone())
    }
}

fn reject_empty_authorization_code(code: &str) -> OAuthResult<()> {
    if code.trim().is_empty() {
        return Err(OAuthError::InvalidTokenResponse(
            EMPTY_AUTHORIZATION_CODE_MESSAGE.into(),
        ));
    }
    Ok(())
}

fn reject_duplicate_callback_params(query: &str) -> OAuthResult<()> {
    let mut seen = HashSet::new();
    for (key, _) in url::form_urlencoded::parse(query.as_bytes()) {
        if matches!(
            key.as_ref(),
            "code" | "state" | "error" | "error_description" | "error_uri"
        ) {
            let key = key.into_owned();
            if !seen.insert(key.clone()) {
                return Err(OAuthError::InvalidTokenResponse(format!(
                    "duplicate OAuth callback parameter `{key}`"
                )));
            }
        }
    }
    Ok(())
}

/// Generate a cryptographically random state parameter.
fn generate_state() -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use rand::RngCore;

    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TokenStore;
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn run_with_test_runtime<F, T>(future: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        fcp_async_core::runtime::block_on_sync(future).expect("build sync test runtime")
    }

    fn test_config() -> OAuth2Config {
        OAuth2Config::new(
            "test_client_id",
            "test_client_secret",
            "https://auth.example.com/authorize",
            "https://auth.example.com/token",
        )
        .with_redirect_uri("https://localhost:3000/callback")
    }

    #[test]
    fn test_authorization_url() {
        let config = test_config();
        let client = OAuth2Client::new(config).unwrap();

        let (url, state) = client.authorization_url(&["read", "write"]).unwrap();

        assert!(url.contains("response_type=code"));
        assert!(url.contains("client_id=test_client_id"));
        assert!(url.contains(&format!("state={state}")));
        assert!(url.contains("scope=read+write"));
        assert!(url.contains("redirect_uri="));
    }

    #[test]
    fn test_authorization_url_with_pkce() {
        let config = test_config();
        let client = OAuth2Client::new(config).unwrap();

        let (url, _state, pkce) = client.authorization_url_with_pkce(&["read"]).unwrap();

        assert!(url.contains("code_challenge="));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(!pkce.verifier().is_empty());
    }

    #[test]
    fn test_callback_validation() {
        let callback = AuthorizationCallback {
            code: Some("auth_code_123".to_string()),
            state: Some("expected_state".to_string()),
            error: None,
            error_description: None,
            error_uri: None,
        };

        let code = callback.validate("expected_state").unwrap();
        assert_eq!(code, "auth_code_123");
    }

    #[test]
    fn test_callback_empty_code_rejected() {
        let callback = AuthorizationCallback {
            code: Some(String::new()),
            state: Some("expected_state".to_string()),
            error: None,
            error_description: None,
            error_uri: None,
        };

        let result = callback.validate("expected_state");
        assert!(
            matches!(result, Err(OAuthError::InvalidTokenResponse(ref msg)) if msg == EMPTY_AUTHORIZATION_CODE_MESSAGE),
            "empty code must fail closed, got {result:?}"
        );
    }

    #[test]
    fn test_callback_whitespace_code_rejected() {
        let callback = AuthorizationCallback {
            code: Some(" \t\n ".to_string()),
            state: Some("expected_state".to_string()),
            error: None,
            error_description: None,
            error_uri: None,
        };

        let result = callback.validate("expected_state");
        assert!(
            matches!(result, Err(OAuthError::InvalidTokenResponse(ref msg)) if msg == EMPTY_AUTHORIZATION_CODE_MESSAGE),
            "whitespace code must fail closed, got {result:?}"
        );
    }

    #[test]
    fn test_callback_state_mismatch() {
        let callback = AuthorizationCallback {
            code: Some("auth_code_123".to_string()),
            state: Some("wrong_state".to_string()),
            error: None,
            error_description: None,
            error_uri: None,
        };

        let result = callback.validate("expected_state");
        assert!(matches!(result, Err(OAuthError::StateMismatch { .. })));
    }

    #[test]
    fn test_callback_state_mismatch_different_lengths() {
        let callback = AuthorizationCallback {
            code: Some("auth_code_123".to_string()),
            state: Some("short".to_string()),
            error: None,
            error_description: None,
            error_uri: None,
        };

        let result = callback.validate("much_longer_expected_state");
        assert!(matches!(result, Err(OAuthError::StateMismatch { .. })));
    }

    #[test]
    fn test_callback_error() {
        let callback = AuthorizationCallback {
            code: None,
            state: Some("state".to_string()),
            error: Some("access_denied".to_string()),
            error_description: Some("User denied access".to_string()),
            error_uri: None,
        };

        let result = callback.validate("state");
        assert!(matches!(result, Err(OAuthError::AuthorizationError { .. })));
    }

    #[test]
    fn test_callback_error_requires_matching_state() {
        let callback = AuthorizationCallback {
            code: None,
            state: Some("attacker_state".to_string()),
            error: Some("access_denied".to_string()),
            error_description: Some("User denied access".to_string()),
            error_uri: None,
        };

        let result = callback.validate("expected_state");
        assert!(
            matches!(result, Err(OAuthError::StateMismatch { .. })),
            "provider errors must not bypass callback state validation: {result:?}"
        );
    }

    #[test]
    fn test_callback_error_requires_present_state() {
        let callback = AuthorizationCallback {
            code: None,
            state: None,
            error: Some("access_denied".to_string()),
            error_description: Some("User denied access".to_string()),
            error_uri: None,
        };

        let result = callback.validate("expected_state");
        assert!(
            matches!(result, Err(OAuthError::InvalidTokenResponse(ref msg)) if msg.contains("Missing state")),
            "provider errors must not bypass missing state validation: {result:?}"
        );
    }

    #[test]
    fn test_public_client_config() {
        let config = OAuth2Config::public_client(
            "public_client",
            "https://auth.example.com/authorize",
            "https://auth.example.com/token",
        );

        assert!(config.client_secret.is_none());
        assert!(config.use_pkce); // PKCE should be enabled by default for public clients
    }

    // ── New tests ──

    #[test]
    fn test_auth_style_display() {
        assert_eq!(AuthStyle::Basic.to_string(), "basic");
        assert_eq!(AuthStyle::Post.to_string(), "post");
    }

    #[test]
    fn test_auth_style_default_is_post() {
        assert_eq!(AuthStyle::default(), AuthStyle::Post);
    }

    #[test]
    fn test_oauth2_config_builder_chain() {
        let config = OAuth2Config::new(
            "id",
            "secret",
            "https://auth.example.com/authorize",
            "https://auth.example.com/token",
        )
        .with_redirect_uri("https://localhost/callback")
        .with_scopes(vec!["read".into(), "write".into()])
        .with_pkce(false)
        .with_pkce_method(PkceMethod::Plain)
        .with_response_mode(ResponseMode::FormPost)
        .with_auth_style(AuthStyle::Basic)
        .with_auth_param("prompt", "consent")
        .with_token_param("audience", "api")
        .with_timeout(Duration::from_secs(60));

        assert_eq!(
            config.redirect_uri,
            Some("https://localhost/callback".into())
        );
        assert_eq!(config.default_scopes, vec!["read", "write"]);
        assert!(!config.use_pkce);
        assert_eq!(config.pkce_method, PkceMethod::Plain);
        assert_eq!(config.response_mode, ResponseMode::FormPost);
        assert_eq!(config.auth_style, AuthStyle::Basic);
        assert_eq!(
            config.extra_auth_params.get("prompt"),
            Some(&"consent".to_string())
        );
        assert_eq!(
            config.extra_token_params.get("audience"),
            Some(&"api".to_string())
        );
        assert_eq!(config.timeout, Duration::from_secs(60));
    }

    #[test]
    fn test_callback_from_query() {
        let callback = AuthorizationCallback::from_query("code=abc&state=xyz").unwrap();
        assert_eq!(callback.code, Some("abc".to_string()));
        assert_eq!(callback.state, Some("xyz".to_string()));
    }

    #[test]
    fn test_callback_from_query_rejects_duplicate_state() {
        let err = AuthorizationCallback::from_query("code=abc&state=good&state=evil")
            .expect_err("duplicate state is parser-smuggling ambiguity");
        assert!(
            matches!(err, OAuthError::InvalidTokenResponse(ref msg) if msg.contains("duplicate OAuth callback parameter `state`"))
        );
    }

    #[test]
    fn test_callback_from_query_rejects_duplicate_code() {
        let err = AuthorizationCallback::from_query("code=first&code=second&state=xyz")
            .expect_err("duplicate code is parser-smuggling ambiguity");
        assert!(
            matches!(err, OAuthError::InvalidTokenResponse(ref msg) if msg.contains("duplicate OAuth callback parameter `code`"))
        );
    }

    #[test]
    fn test_callback_from_query_allows_duplicate_unknown_params() {
        let callback =
            AuthorizationCallback::from_query("code=abc&state=xyz&extra=one&extra=two").unwrap();
        assert_eq!(callback.code, Some("abc".to_string()));
        assert_eq!(callback.state, Some("xyz".to_string()));
    }

    #[test]
    fn test_callback_from_url() {
        let callback =
            AuthorizationCallback::from_url("https://localhost/callback?code=abc&state=xyz")
                .unwrap();
        assert_eq!(callback.code, Some("abc".to_string()));
        assert_eq!(callback.state, Some("xyz".to_string()));
    }

    #[test]
    fn test_callback_from_url_fragment_response_mode() {
        let callback =
            AuthorizationCallback::from_url("https://localhost/callback#code=abc&state=xyz")
                .unwrap();
        assert_eq!(callback.code, Some("abc".to_string()));
        assert_eq!(callback.state, Some("xyz".to_string()));
    }

    #[test]
    fn test_callback_missing_state() {
        let callback = AuthorizationCallback {
            code: Some("abc".into()),
            state: None,
            error: None,
            error_description: None,
            error_uri: None,
        };
        let result = callback.validate("expected");
        assert!(matches!(result, Err(OAuthError::InvalidTokenResponse(_))));
    }

    #[test]
    fn test_callback_missing_code() {
        let callback = AuthorizationCallback {
            code: None,
            state: Some("state".into()),
            error: None,
            error_description: None,
            error_uri: None,
        };
        let result = callback.validate("state");
        assert!(matches!(result, Err(OAuthError::InvalidTokenResponse(_))));
    }

    #[test]
    fn test_callback_from_query_empty_code_rejected() {
        let callback = AuthorizationCallback::from_query("code=&state=state").unwrap();
        let result = callback.validate("state");
        assert!(
            matches!(result, Err(OAuthError::InvalidTokenResponse(ref msg)) if msg == EMPTY_AUTHORIZATION_CODE_MESSAGE),
            "empty query code must fail closed, got {result:?}"
        );
    }

    #[test]
    fn test_authorization_url_with_default_scopes() {
        let config = test_config().with_scopes(vec!["profile".into()]);
        let client = OAuth2Client::new(config).unwrap();

        let (url, _) = client.authorization_url(&["email"]).unwrap();
        // Should contain both default and requested scopes
        assert!(url.contains("scope=profile+email"));
    }

    #[test]
    fn test_authorization_url_with_form_post_response_mode() {
        let config = test_config().with_response_mode(ResponseMode::FormPost);
        let client = OAuth2Client::new(config).unwrap();

        let (url, _) = client.authorization_url(&["read"]).unwrap();
        assert!(url.contains("response_mode=form_post"));
    }

    #[test]
    fn test_oauth2_client_config_accessor() {
        let config = test_config();
        let client = OAuth2Client::new(config).unwrap();
        assert_eq!(client.config().client_id, "test_client_id");
    }

    #[test]
    fn test_exchange_code_with_mock_server() {
        run_with_test_runtime(async {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/token"))
                .and(body_string_contains("grant_type=authorization_code"))
                .and(body_string_contains("code=auth-code-123"))
                .and(body_string_contains(
                    "redirect_uri=https%3A%2F%2Flocalhost%3A3000%2Fcallback",
                ))
                .and(body_string_contains("client_id=test_client_id"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "access-123",
                    "token_type": "Bearer",
                    "refresh_token": "refresh-123",
                    "expires_in": 3600,
                    "scope": "read write"
                })))
                .mount(&server)
                .await;

            let config = OAuth2Config::new(
                "test_client_id",
                "test_client_secret",
                format!("{}/authorize", server.uri()),
                format!("{}/token", server.uri()),
            )
            .with_redirect_uri("https://localhost:3000/callback")
            .with_pkce(false);
            let client = OAuth2Client::new(config).unwrap();

            let tokens = client.exchange_code("auth-code-123").await.unwrap();
            assert_eq!(tokens.access_token(), "access-123");
            assert_eq!(tokens.refresh_token(), Some("refresh-123"));
            assert_eq!(tokens.scopes(), &["read", "write"]);
        });
    }

    #[test]
    fn test_exchange_code_rejects_empty_code_before_token_request() {
        run_with_test_runtime(async {
            let server = MockServer::start().await;
            let config = OAuth2Config::new(
                "test_client_id",
                "test_client_secret",
                format!("{}/authorize", server.uri()),
                format!("{}/token", server.uri()),
            )
            .with_redirect_uri("https://localhost:3000/callback")
            .with_pkce(false);
            let client = OAuth2Client::new(config).unwrap();

            let err = client.exchange_code("").await.unwrap_err();
            assert!(
                matches!(err, OAuthError::InvalidTokenResponse(ref msg) if msg == EMPTY_AUTHORIZATION_CODE_MESSAGE),
                "empty code should be rejected before exchange, got {err:?}"
            );
            let requests = server.received_requests().await.unwrap_or_default();
            assert!(
                requests.is_empty(),
                "empty code must not reach token endpoint"
            );
        });
    }

    #[test]
    fn test_exchange_code_with_pkce_rejects_whitespace_code_before_token_request() {
        run_with_test_runtime(async {
            let server = MockServer::start().await;
            let config = OAuth2Config::new(
                "test_client_id",
                "test_client_secret",
                format!("{}/authorize", server.uri()),
                format!("{}/token", server.uri()),
            )
            .with_redirect_uri("https://localhost:3000/callback");
            let client = OAuth2Client::new(config).unwrap();
            let pkce = Pkce::with_method(PkceMethod::S256);

            let err = client
                .exchange_code_with_pkce(" \t\n ", &pkce)
                .await
                .unwrap_err();
            assert!(
                matches!(err, OAuthError::InvalidTokenResponse(ref msg) if msg == EMPTY_AUTHORIZATION_CODE_MESSAGE),
                "whitespace code should be rejected before exchange, got {err:?}"
            );
            let requests = server.received_requests().await.unwrap_or_default();
            assert!(
                requests.is_empty(),
                "whitespace code must not reach token endpoint"
            );
        });
    }

    #[test]
    fn test_exchange_code_rejects_empty_access_token() {
        // Defensive guard: a misbehaving/compromised OAuth server might
        // return 200 OK with {"access_token": "", ...}. Storing that
        // produces an unusable bearer token — fail the exchange fast
        // instead of silently burning a refresh cycle.
        run_with_test_runtime(async {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "",
                    "token_type": "Bearer",
                    "expires_in": 3600
                })))
                .mount(&server)
                .await;

            let config = OAuth2Config::new(
                "test_client_id",
                "test_client_secret",
                format!("{}/authorize", server.uri()),
                format!("{}/token", server.uri()),
            )
            .with_redirect_uri("https://localhost:3000/callback")
            .with_pkce(false);
            let client = OAuth2Client::new(config).unwrap();

            let err = client
                .exchange_code("auth-code-empty")
                .await
                .expect_err("empty access_token must be rejected");
            assert!(matches!(err, OAuthError::EmptyTokenField("access_token")));
        });
    }

    #[test]
    fn test_exchange_code_rejects_empty_token_type() {
        // Similarly, an empty token_type would produce a malformed
        // Authorization header like " <access>".
        run_with_test_runtime(async {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "ok",
                    "token_type": "",
                    "expires_in": 3600
                })))
                .mount(&server)
                .await;

            let config = OAuth2Config::new(
                "cid",
                "csec",
                format!("{}/authorize", server.uri()),
                format!("{}/token", server.uri()),
            )
            .with_redirect_uri("https://localhost:3000/callback")
            .with_pkce(false);
            let client = OAuth2Client::new(config).unwrap();

            let err = client
                .exchange_code("auth-code-no-type")
                .await
                .expect_err("empty token_type must be rejected");
            assert!(matches!(err, OAuthError::EmptyTokenField("token_type")));
        });
    }

    #[test]
    fn test_refresh_tokens_rejects_empty_refresh_token_argument() {
        run_with_test_runtime(async {
            let config = OAuth2Config::new(
                "cid",
                "csec",
                "https://example.com/authorize",
                "https://example.com/token",
            )
            .with_redirect_uri("https://localhost:3000/callback");
            let client = OAuth2Client::new(config).expect("client should construct");

            let err = client
                .refresh_tokens("")
                .await
                .expect_err("empty refresh token input must be rejected");
            assert!(
                matches!(err, OAuthError::InvalidTokenResponse(ref msg) if msg.contains("refresh token cannot be empty")),
                "expected InvalidTokenResponse for empty refresh token, got {err:?}"
            );
        });
    }

    #[test]
    fn test_token_store_get_or_refresh_refreshes_threshold_token() {
        run_with_test_runtime(async {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/token"))
                .and(body_string_contains("grant_type=refresh_token"))
                .and(body_string_contains("refresh_token=refresh-old"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "access-new",
                    "token_type": "Bearer",
                    "refresh_token": "refresh-new",
                    "expires_in": 3600
                })))
                .expect(1)
                .mount(&server)
                .await;

            let config = OAuth2Config::new(
                "cid",
                "csec",
                format!("{}/authorize", server.uri()),
                format!("{}/token", server.uri()),
            )
            .with_redirect_uri("https://localhost:3000/callback");
            let client = OAuth2Client::new(config).unwrap();
            let store = TokenStore::new();
            store.store(
                "user",
                OAuthTokens::from_response(TokenResponse {
                    access_token: "access-old".into(),
                    token_type: "Bearer".into(),
                    expires_in: Some(120),
                    refresh_token: Some("refresh-old".into()),
                    scope: None,
                    id_token: None,
                })
                .expect("valid token fixture must construct"),
            );

            let refreshed = store.get_or_refresh("user", &client).await.unwrap();
            assert_eq!(refreshed.access_token(), "access-new");
            assert_eq!(refreshed.refresh_token(), Some("refresh-new"));

            let stored = store.get("user").unwrap();
            assert_eq!(stored.access_token(), "access-new");
            assert_eq!(stored.refresh_token(), Some("refresh-new"));
            assert!(store.has_valid_token("user"));
            server.verify().await;
        });
    }

    #[test]
    fn test_token_store_get_or_refresh_preserves_refresh_token_when_provider_omits_rotation() {
        run_with_test_runtime(async {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/token"))
                .and(body_string_contains("grant_type=refresh_token"))
                .and(body_string_contains("refresh_token=refresh-steady"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "access-new",
                    "token_type": "Bearer",
                    "expires_in": 3600
                })))
                .expect(1)
                .mount(&server)
                .await;

            let config = OAuth2Config::new(
                "cid",
                "csec",
                format!("{}/authorize", server.uri()),
                format!("{}/token", server.uri()),
            )
            .with_redirect_uri("https://localhost:3000/callback");
            let client = OAuth2Client::new(config).unwrap();
            let store = TokenStore::new();
            store.store(
                "user",
                OAuthTokens::from_response(TokenResponse {
                    access_token: "access-old".into(),
                    token_type: "Bearer".into(),
                    expires_in: Some(120),
                    refresh_token: Some("refresh-steady".into()),
                    scope: None,
                    id_token: None,
                })
                .expect("valid token fixture must construct"),
            );

            let refreshed = store.get_or_refresh("user", &client).await.unwrap();
            assert_eq!(refreshed.access_token(), "access-new");
            assert_eq!(refreshed.refresh_token(), Some("refresh-steady"));

            let stored = store.get("user").unwrap();
            assert_eq!(stored.access_token(), "access-new");
            assert_eq!(stored.refresh_token(), Some("refresh-steady"));
            server.verify().await;
        });
    }

    #[test]
    fn test_token_store_get_or_refresh_keeps_valid_non_refreshable_token() {
        run_with_test_runtime(async {
            let config = OAuth2Config::new(
                "cid",
                "csec",
                "https://example.com/authorize",
                "https://example.com/token",
            )
            .with_redirect_uri("https://localhost:3000/callback");
            let client = OAuth2Client::new(config).unwrap();
            let store = TokenStore::new();
            store.store(
                "user",
                OAuthTokens::from_response(TokenResponse {
                    access_token: "access-still-valid".into(),
                    token_type: "Bearer".into(),
                    expires_in: Some(120),
                    refresh_token: None,
                    scope: None,
                    id_token: None,
                })
                .expect("valid token fixture must construct"),
            );

            let current = store.get_or_refresh("user", &client).await.unwrap();
            assert_eq!(current.access_token(), "access-still-valid");
            assert_eq!(current.refresh_token(), None);

            let stored = store.get("user").unwrap();
            assert_eq!(stored.access_token(), "access-still-valid");
            assert_eq!(stored.refresh_token(), None);
        });
    }

    #[test]
    fn test_token_store_get_or_refresh_is_single_flight_per_key() {
        run_with_test_runtime(async {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/token"))
                .and(body_string_contains("grant_type=refresh_token"))
                .and(body_string_contains("refresh_token=shared-refresh"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_delay(Duration::from_millis(25))
                        .set_body_json(serde_json::json!({
                            "access_token": "shared-access-new",
                            "token_type": "Bearer",
                            "refresh_token": "shared-refresh-new",
                            "expires_in": 3600
                        })),
                )
                .expect(1)
                .mount(&server)
                .await;

            let config = OAuth2Config::new(
                "cid",
                "csec",
                format!("{}/authorize", server.uri()),
                format!("{}/token", server.uri()),
            )
            .with_redirect_uri("https://localhost:3000/callback");
            let client = OAuth2Client::new(config).unwrap();
            let store = TokenStore::new();
            store.store(
                "user",
                OAuthTokens::from_response(TokenResponse {
                    access_token: "shared-access-old".into(),
                    token_type: "Bearer".into(),
                    expires_in: Some(1),
                    refresh_token: Some("shared-refresh".into()),
                    scope: None,
                    id_token: None,
                })
                .expect("valid token fixture must construct"),
            );

            let store_a = store.clone();
            let client_a = client.clone();
            let task_a = fcp_async_core::task::spawn(async move {
                store_a.get_or_refresh("user", &client_a).await
            });
            let store_b = store.clone();
            let client_b = client.clone();
            let task_b = fcp_async_core::task::spawn(async move {
                store_b.get_or_refresh("user", &client_b).await
            });

            let a = task_a.await.expect("task a should join").unwrap();
            let b = task_b.await.expect("task b should join").unwrap();
            assert_eq!(a.access_token(), "shared-access-new");
            assert_eq!(b.access_token(), "shared-access-new");

            let stored = store.get("user").unwrap();
            assert_eq!(stored.access_token(), "shared-access-new");
            assert_eq!(stored.refresh_token(), Some("shared-refresh-new"));
            server.verify().await;
        });
    }

    #[test]
    fn token_store_refresh_returns_the_exact_merged_credentials() {
        run_with_test_runtime(async {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/token"))
                .and(body_string_contains("refresh_token=refresh-steady"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "access-new",
                    "token_type": "Bearer"
                })))
                .expect(1)
                .mount(&server)
                .await;
            let client = OAuth2Client::new(OAuth2Config::new(
                "cid",
                "csec",
                format!("{}/authorize", server.uri()),
                format!("{}/token", server.uri()),
            ))
            .unwrap();
            let original = OAuthTokens::from_response(TokenResponse {
                access_token: "access-old".into(),
                token_type: "Bearer".into(),
                expires_in: Some(120),
                refresh_token: Some("refresh-steady".into()),
                scope: Some("read write".into()),
                id_token: Some("retained-id-token".into()),
            })
            .unwrap();
            let original_json = serde_json::to_value(&original).unwrap();
            let store = TokenStore::new();
            store.store("user", original);

            let returned = store.get_or_refresh("user", &client).await.unwrap();
            let stored = store.get("user").unwrap();
            let returned_json = serde_json::to_value(&returned).unwrap();
            assert_eq!(returned_json, serde_json::to_value(stored).unwrap());
            assert_eq!(returned.access_token(), "access-new");
            assert_eq!(returned.refresh_token(), Some("refresh-steady"));
            assert_eq!(returned.scopes(), &["read", "write"]);
            assert_eq!(returned.id_token(), Some("retained-id-token"));
            assert_eq!(returned_json["expires_at"], original_json["expires_at"]);
            assert!(returned.needs_refresh());
            server.verify().await;
        });
    }

    #[test]
    fn token_store_refresh_cannot_turn_an_expired_token_into_an_unbounded_bearer() {
        run_with_test_runtime(async {
            for expires_in in [None, Some(0)] {
                let server = MockServer::start().await;
                let mut response = serde_json::json!({
                    "access_token": "new-but-expired",
                    "token_type": "Bearer"
                });
                if let Some(seconds) = expires_in {
                    response["expires_in"] = serde_json::json!(seconds);
                }
                Mock::given(method("POST"))
                    .and(path("/token"))
                    .respond_with(ResponseTemplate::new(200).set_body_json(response))
                    .expect(1)
                    .mount(&server)
                    .await;
                let client = OAuth2Client::new(OAuth2Config::new(
                    "cid",
                    "csec",
                    format!("{}/authorize", server.uri()),
                    format!("{}/token", server.uri()),
                ))
                .unwrap();
                let store = TokenStore::new();
                store.store(
                    "user",
                    OAuthTokens::from_response(TokenResponse {
                        access_token: "expired-access".into(),
                        token_type: "Bearer".into(),
                        expires_in: Some(0),
                        refresh_token: Some("retained-refresh".into()),
                        scope: Some("read".into()),
                        id_token: None,
                    })
                    .unwrap(),
                );
                assert!(matches!(
                    store.get_or_refresh("user", &client).await,
                    Err(OAuthError::TokenExpired(_))
                ));
                let stored = store.get("user").unwrap();
                assert!(stored.is_expired());
                assert_eq!(stored.refresh_token(), Some("retained-refresh"));
                server.verify().await;
            }
        });
    }

    #[test]
    fn token_store_inflight_refresh_respects_administrative_replacement_and_removal() {
        run_with_test_runtime(async {
            for provider_succeeds in [true, false] {
                for mutation in [
                    "store",
                    "update",
                    "remove_reinsert",
                    "clear_reinsert",
                    "remove",
                    "clear",
                ] {
                    let server = MockServer::start().await;
                    let store = TokenStore::new();
                    let fixture = |access_token: &str, expires_in| {
                        OAuthTokens::from_response(TokenResponse {
                            access_token: access_token.into(),
                            token_type: "Bearer".into(),
                            expires_in: Some(expires_in),
                            refresh_token: Some("unchanged-refresh-token".into()),
                            scope: Some("read".into()),
                            id_token: None,
                        })
                        .unwrap()
                    };
                    store.store("user", fixture("old-access-token", 0));
                    let responding_store = store.clone();
                    Mock::given(method("POST"))
                        .and(path("/token"))
                        .and(body_string_contains("refresh_token=unchanged-refresh-token"))
                        .respond_with(move |_: &wiremock::Request| {
                            // Mutate after the real HTTP request arrives and
                            // before its response: admission has already run.
                            match mutation {
                                "store" => responding_store.store(
                                    "user",
                                    fixture("replacement-access-token", 3600),
                                ),
                                "update" => responding_store
                                    .update("user", fixture("replacement-access-token", 3600))
                                    .unwrap(),
                                "remove_reinsert" => {
                                    assert!(responding_store.remove("user").is_some());
                                    responding_store.store(
                                        "user",
                                        fixture("replacement-access-token", 3600),
                                    );
                                }
                                "clear_reinsert" => {
                                    responding_store.clear();
                                    responding_store.store(
                                        "user",
                                        fixture("replacement-access-token", 3600),
                                    );
                                }
                                "remove" => {
                                    assert!(responding_store.remove("user").is_some());
                                }
                                "clear" => responding_store.clear(),
                                _ => unreachable!(),
                            }
                            if provider_succeeds {
                                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                                    "access_token": "stale-provider-access-token",
                                    "token_type": "Bearer",
                                    "expires_in": 3600,
                                    "refresh_token": "stale-provider-refresh-token"
                                }))
                            } else {
                                ResponseTemplate::new(400).set_body_json(serde_json::json!({
                                    "error": "invalid_grant"
                                }))
                            }
                        })
                        .expect(1)
                        .mount(&server)
                        .await;
                    let client = OAuth2Client::new(OAuth2Config::new(
                        "cid",
                        "csec",
                        format!("{}/authorize", server.uri()),
                        format!("{}/token", server.uri()),
                    ))
                    .unwrap();
                    let result = store.get_or_refresh("user", &client).await;
                    if matches!(mutation, "remove" | "clear") {
                        assert!(
                            matches!(result, Err(OAuthError::TokenNotFound(_))),
                            "removed credentials must fail: {mutation}, success={provider_succeeds}"
                        );
                        assert!(store.get("user").is_none());
                    } else {
                        let current = result.unwrap();
                        assert_eq!(current.access_token(), "replacement-access-token");
                        assert_eq!(current.refresh_token(), Some("unchanged-refresh-token"));
                        assert_eq!(
                            serde_json::to_value(current).unwrap(),
                            serde_json::to_value(store.get("user").unwrap()).unwrap()
                        );
                    }
                    server.verify().await;
                }
            }
        });
    }

    #[test]
    fn test_exchange_code_with_pkce_sends_verifier() {
        run_with_test_runtime(async {
            let server = MockServer::start().await;
            let pkce = Pkce::with_method(PkceMethod::S256);
            let expected_verifier = pkce.verifier().to_string();

            Mock::given(method("POST"))
                .and(path("/token"))
                .and(body_string_contains("grant_type=authorization_code"))
                .and(body_string_contains("code=auth-code-pkce"))
                .and(body_string_contains(format!(
                    "code_verifier={expected_verifier}"
                )))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "pkce-access",
                    "token_type": "Bearer",
                    "refresh_token": "pkce-refresh",
                    "expires_in": 3600
                })))
                .mount(&server)
                .await;

            let config = OAuth2Config::public_client(
                "public-client",
                format!("{}/authorize", server.uri()),
                format!("{}/token", server.uri()),
            )
            .with_redirect_uri("https://localhost:3000/callback");
            let client = OAuth2Client::new(config).unwrap();

            let tokens = client
                .exchange_code_with_pkce("auth-code-pkce", &pkce)
                .await
                .unwrap();
            assert_eq!(tokens.access_token(), "pkce-access");
            assert_eq!(tokens.refresh_token(), Some("pkce-refresh"));
        });
    }

    #[test]
    fn test_refresh_tokens_with_mock_server() {
        run_with_test_runtime(async {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/token"))
                .and(body_string_contains("grant_type=refresh_token"))
                .and(body_string_contains("refresh_token=refresh-token-xyz"))
                .and(body_string_contains("client_id=test_client_id"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "fresh-access-token",
                    "token_type": "Bearer",
                    "refresh_token": "new-refresh-token",
                    "expires_in": 7200
                })))
                .mount(&server)
                .await;

            let config = OAuth2Config::new(
                "test_client_id",
                "test_client_secret",
                format!("{}/authorize", server.uri()),
                format!("{}/token", server.uri()),
            );
            let client = OAuth2Client::new(config).unwrap();

            let tokens = client.refresh_tokens("refresh-token-xyz").await.unwrap();
            assert_eq!(tokens.access_token(), "fresh-access-token");
            assert_eq!(tokens.refresh_token(), Some("new-refresh-token"));
        });
    }

    #[test]
    fn test_refresh_tokens_with_default_scopes() {
        run_with_test_runtime(async {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/token"))
                .and(body_string_contains("grant_type=refresh_token"))
                .and(body_string_contains("refresh_token=refresh-token-xyz"))
                .and(body_string_contains("scope=gmail.compose+gmail.modify"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "fresh-access-token",
                    "token_type": "Bearer",
                    "expires_in": 7200,
                    "scope": "gmail.compose gmail.modify"
                })))
                .mount(&server)
                .await;

            let config = OAuth2Config::new(
                "test_client_id",
                "test_client_secret",
                format!("{}/authorize", server.uri()),
                format!("{}/token", server.uri()),
            )
            .with_scopes(vec!["gmail.compose".into(), "gmail.modify".into()]);
            let client = OAuth2Client::new(config).unwrap();

            let tokens = client.refresh_tokens("refresh-token-xyz").await.unwrap();
            assert_eq!(tokens.access_token(), "fresh-access-token");
            assert_eq!(tokens.refresh_token(), Some("refresh-token-xyz"));
            assert_eq!(tokens.scopes(), &["gmail.compose", "gmail.modify"]);
        });
    }

    #[test]
    fn test_refresh_tokens_preserves_existing_refresh_token_when_provider_omits_rotation() {
        run_with_test_runtime(async {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/token"))
                .and(body_string_contains("grant_type=refresh_token"))
                .and(body_string_contains("refresh_token=refresh-token-xyz"))
                .and(body_string_contains("client_id=test_client_id"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "fresh-access-token",
                    "token_type": "Bearer",
                    "expires_in": 7200
                })))
                .mount(&server)
                .await;

            let config = OAuth2Config::new(
                "test_client_id",
                "test_client_secret",
                format!("{}/authorize", server.uri()),
                format!("{}/token", server.uri()),
            );
            let client = OAuth2Client::new(config).unwrap();

            let tokens = client.refresh_tokens("refresh-token-xyz").await.unwrap();
            assert_eq!(tokens.access_token(), "fresh-access-token");
            assert_eq!(tokens.refresh_token(), Some("refresh-token-xyz"));
        });
    }

    #[test]
    fn test_authorization_code_pkce_full_lifecycle_with_mock_server() {
        run_with_test_runtime(async {
            let server = MockServer::start().await;
            let config = OAuth2Config::public_client(
                "public-client",
                format!("{}/authorize", server.uri()),
                format!("{}/token", server.uri()),
            )
            .with_redirect_uri("https://localhost:3000/callback")
            .with_scopes(vec!["openid".into()]);
            let client = OAuth2Client::new(config).unwrap();

            let (authorization_url, state, pkce) = client
                .authorization_url_with_pkce(&["email", "profile"])
                .unwrap();
            assert!(
                authorization_url
                    .contains("redirect_uri=https%3A%2F%2Flocalhost%3A3000%2Fcallback")
            );
            assert!(authorization_url.contains("scope=openid+email+profile"));
            assert!(authorization_url.contains("code_challenge="));

            Mock::given(method("POST"))
                .and(path("/token"))
                .and(body_string_contains("grant_type=authorization_code"))
                .and(body_string_contains("code=auth-code-lifecycle"))
                .and(body_string_contains(format!(
                    "code_verifier={}",
                    pkce.verifier()
                )))
                .and(body_string_contains("client_id=public-client"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "access-stage-1",
                    "token_type": "Bearer",
                    "refresh_token": "refresh-stage-1",
                    "expires_in": 3600,
                    "scope": "openid email profile"
                })))
                .mount(&server)
                .await;

            Mock::given(method("POST"))
                .and(path("/token"))
                .and(body_string_contains("grant_type=refresh_token"))
                .and(body_string_contains("refresh_token=refresh-stage-1"))
                .and(body_string_contains("client_id=public-client"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "access-stage-2",
                    "token_type": "Bearer",
                    "refresh_token": "refresh-stage-2",
                    "expires_in": 7200,
                    "scope": "openid email profile"
                })))
                .mount(&server)
                .await;

            let callback = AuthorizationCallback::from_url(&format!(
                "https://localhost:3000/callback?code=auth-code-lifecycle&state={state}"
            ))
            .unwrap();
            let code = callback.validate(&state).unwrap();
            let tokens = client.exchange_code_with_pkce(&code, &pkce).await.unwrap();
            assert_eq!(tokens.access_token(), "access-stage-1");
            assert_eq!(tokens.refresh_token(), Some("refresh-stage-1"));
            assert_eq!(tokens.scopes(), &["openid", "email", "profile"]);

            let refreshed = client
                .refresh_tokens(tokens.refresh_token().expect("refresh token should exist"))
                .await
                .unwrap();
            assert_eq!(refreshed.access_token(), "access-stage-2");
            assert_eq!(refreshed.refresh_token(), Some("refresh-stage-2"));
            assert_eq!(refreshed.scopes(), &["openid", "email", "profile"]);
        });
    }

    #[test]
    fn test_exchange_code_redacts_token_error_response() {
        run_with_test_runtime(async {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/token"))
                .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                    "error": "invalid_grant",
                    "error_description": "authorization code expired\nleaked_secret=abc123"
                })))
                .mount(&server)
                .await;

            let config = OAuth2Config::new(
                "test_client_id",
                "test_client_secret",
                format!("{}/authorize", server.uri()),
                format!("{}/token", server.uri()),
            )
            .with_redirect_uri("https://localhost:3000/callback")
            .with_pkce(false);
            let client = OAuth2Client::new(config).unwrap();

            let error = client.exchange_code("expired-code").await.unwrap_err();
            assert!(
                matches!(&error, OAuthError::TokenExchangeFailed(_)),
                "expected token exchange error"
            );
            let OAuthError::TokenExchangeFailed(message) = error else {
                return;
            };
            assert_eq!(
                message,
                "token endpoint returned an unsuccessful response (status 400)"
            );
            assert!(!message.contains("invalid_grant"));
            assert!(!message.contains("authorization code expired"));
            assert!(!message.contains("leaked_secret"));
        });
    }

    // ── New batch: OAuth2Config construction and builder ──

    #[test]
    fn test_config_new_defaults() {
        let config = OAuth2Config::new("id", "secret", "https://a.com/auth", "https://a.com/tok");
        assert_eq!(config.client_id, "id");
        assert_eq!(config.client_secret, Some("secret".to_string()));
        assert_eq!(config.authorization_url, "https://a.com/auth");
        assert_eq!(config.token_url, "https://a.com/tok");
        assert!(config.redirect_uri.is_none());
        assert!(config.default_scopes.is_empty());
        assert!(config.use_pkce);
        assert_eq!(config.pkce_method, PkceMethod::S256);
        assert_eq!(config.response_mode, ResponseMode::Query);
        assert_eq!(config.auth_style, AuthStyle::Post);
        assert!(config.extra_auth_params.is_empty());
        assert!(config.extra_token_params.is_empty());
        assert_eq!(config.timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_config_public_client_defaults() {
        let config = OAuth2Config::public_client("pub", "https://a.com/auth", "https://a.com/tok");
        assert_eq!(config.client_id, "pub");
        assert!(config.client_secret.is_none());
        assert!(config.use_pkce);
        assert_eq!(config.pkce_method, PkceMethod::S256);
        assert_eq!(config.auth_style, AuthStyle::Post);
        assert_eq!(config.timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_config_clone() {
        let config = test_config()
            .with_scopes(vec!["read".into()])
            .with_auth_param("prompt", "login");
        let cloned = config.clone();
        assert_eq!(config.client_id, cloned.client_id);
        assert_eq!(config.client_secret, cloned.client_secret);
        assert_eq!(config.default_scopes, cloned.default_scopes);
        assert_eq!(
            config.extra_auth_params.get("prompt"),
            cloned.extra_auth_params.get("prompt")
        );
    }

    #[test]
    fn test_config_debug() {
        let config = test_config();
        let debug = format!("{config:?}");
        assert!(debug.contains("OAuth2Config"));
        assert!(debug.contains("test_client_id"));
    }

    #[test]
    fn test_config_with_multiple_auth_params() {
        let config = test_config()
            .with_auth_param("prompt", "consent")
            .with_auth_param("login_hint", "user@example.com")
            .with_auth_param("access_type", "offline");
        assert_eq!(config.extra_auth_params.len(), 3);
        assert_eq!(
            config.extra_auth_params.get("prompt"),
            Some(&"consent".to_string())
        );
        assert_eq!(
            config.extra_auth_params.get("login_hint"),
            Some(&"user@example.com".to_string())
        );
        assert_eq!(
            config.extra_auth_params.get("access_type"),
            Some(&"offline".to_string())
        );
    }

    #[test]
    fn test_config_with_multiple_token_params() {
        let config = test_config()
            .with_token_param("audience", "https://api.example.com")
            .with_token_param("resource", "urn:example:resource");
        assert_eq!(config.extra_token_params.len(), 2);
    }

    // ── New batch: OAuth2Client creation and validation ──

    #[test]
    fn test_client_rejects_invalid_authorization_url() {
        let config = OAuth2Config::new(
            "id",
            "secret",
            "not-a-url",
            "https://auth.example.com/token",
        );
        let result = OAuth2Client::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_client_rejects_invalid_token_url() {
        let config = OAuth2Config::new(
            "id",
            "secret",
            "https://auth.example.com/authorize",
            "not-a-url",
        );
        let result = OAuth2Client::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_client_rejects_non_loopback_http_authorization_url() {
        let config = OAuth2Config::new(
            "id",
            "secret",
            "http://auth.example.com/authorize",
            "https://auth.example.com/token",
        );
        let err = OAuth2Client::new(config).unwrap_err();
        assert!(matches!(
            err,
            OAuthError::InvalidConfig(ref m)
                if m.contains("authorization_url") && m.contains("https or loopback http")
        ));
    }

    #[test]
    fn test_client_rejects_non_loopback_http_token_url() {
        let config = OAuth2Config::new(
            "id",
            "secret",
            "https://auth.example.com/authorize",
            "http://auth.example.com/token",
        );
        let err = OAuth2Client::new(config).unwrap_err();
        assert!(matches!(
            err,
            OAuthError::InvalidConfig(ref m)
                if m.contains("token_url") && m.contains("https or loopback http")
        ));
    }

    #[test]
    fn test_client_rejects_oauth_endpoint_with_embedded_credentials() {
        let config = OAuth2Config::new(
            "id",
            "secret",
            "https://user:pass@auth.example.com/authorize",
            "https://auth.example.com/token",
        );
        let err = OAuth2Client::new(config).unwrap_err();
        assert!(matches!(
            err,
            OAuthError::InvalidConfig(ref m)
                if m.contains("authorization_url") && m.contains("embedded credentials")
        ));
    }

    #[test]
    fn test_client_rejects_oauth_endpoint_with_fragment() {
        let config = OAuth2Config::new(
            "id",
            "secret",
            "https://auth.example.com/authorize",
            "https://auth.example.com/token#frag",
        );
        let err = OAuth2Client::new(config).unwrap_err();
        assert!(matches!(
            err,
            OAuthError::InvalidConfig(ref m)
                if m.contains("token_url") && m.contains("fragment")
        ));
    }

    #[test]
    fn test_client_rejects_invalid_redirect_uri() {
        let config = OAuth2Config::new(
            "id",
            "secret",
            "https://auth.example.com/authorize",
            "https://auth.example.com/token",
        )
        .with_redirect_uri("://bad");
        let result = OAuth2Client::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_client_rejects_non_loopback_http_redirect_uri() {
        let config = OAuth2Config::new(
            "id",
            "secret",
            "https://auth.example.com/authorize",
            "https://auth.example.com/token",
        )
        .with_redirect_uri("http://attacker.example/callback");
        let err = OAuth2Client::new(config).unwrap_err();
        assert!(matches!(
            err,
            OAuthError::InvalidConfig(ref m) if m.contains("https or loopback http")
        ));
    }

    #[test]
    fn test_client_rejects_redirect_uri_with_embedded_credentials() {
        let config = OAuth2Config::new(
            "id",
            "secret",
            "https://auth.example.com/authorize",
            "https://auth.example.com/token",
        )
        .with_redirect_uri("https://user:pass@example.com/callback");
        let err = OAuth2Client::new(config).unwrap_err();
        assert!(matches!(
            err,
            OAuthError::InvalidConfig(ref m) if m.contains("embedded credentials")
        ));
    }

    #[test]
    fn test_client_accepts_redirect_uri_with_registered_query_component() {
        // br-i58yx: RFC 6749 §3.1.2 permits a pre-registered query
        // component on the redirection endpoint. A standards-compliant
        // tenant-aware URL must be accepted.
        let config = OAuth2Config::new(
            "id",
            "secret",
            "https://auth.example.com/authorize",
            "https://auth.example.com/token",
        )
        .with_redirect_uri("https://example.com/callback?tenant=acme");
        let client = OAuth2Client::new(config).expect("tenant-aware redirect must be accepted");
        assert_eq!(
            client.config.redirect_uri.as_deref(),
            Some("https://example.com/callback?tenant=acme")
        );
    }

    #[test]
    fn test_client_rejects_redirect_uri_with_oauth_response_param_in_query() {
        // Registered URIs MUST NOT collide with OAuth response
        // parameter names — callback parsing would become ambiguous.
        let config = OAuth2Config::new(
            "id",
            "secret",
            "https://auth.example.com/authorize",
            "https://auth.example.com/token",
        )
        .with_redirect_uri("https://example.com/callback?code=pwn");
        let err = OAuth2Client::new(config).unwrap_err();
        assert!(matches!(
            err,
            OAuthError::InvalidConfig(ref m) if m.contains("OAuth response parameter")
        ));
    }

    #[test]
    fn test_client_rejects_redirect_uri_with_fragment() {
        let config = OAuth2Config::new(
            "id",
            "secret",
            "https://auth.example.com/authorize",
            "https://auth.example.com/token",
        )
        .with_redirect_uri("https://example.com/callback#fragment");
        let err = OAuth2Client::new(config).unwrap_err();
        assert!(matches!(
            err,
            OAuthError::InvalidConfig(ref m) if m.contains("fragment")
        ));
    }

    #[test]
    fn test_client_rejects_static_code_verifier_token_param() {
        let config = OAuth2Config::new(
            "id",
            "secret",
            "https://auth.example.com/authorize",
            "https://auth.example.com/token",
        )
        .with_token_param("code_verifier", "static-verifier");
        let err = OAuth2Client::new(config).unwrap_err();
        assert!(matches!(
            err,
            OAuthError::InvalidConfig(ref m)
                if m.contains("extra token param `code_verifier` is reserved")
        ));
    }

    #[test]
    fn test_client_rejects_reserved_extra_auth_state_param() {
        let config = OAuth2Config::new(
            "id",
            "secret",
            "https://auth.example.com/authorize",
            "https://auth.example.com/token",
        )
        .with_auth_param("state", "attacker-controlled");
        let err = OAuth2Client::new(config).unwrap_err();
        assert!(matches!(
            err,
            OAuthError::InvalidConfig(ref m)
                if m.contains("extra auth param `state` is reserved")
        ));
    }

    #[test]
    fn test_client_rejects_reserved_extra_token_grant_type_param() {
        let config = OAuth2Config::new(
            "id",
            "secret",
            "https://auth.example.com/authorize",
            "https://auth.example.com/token",
        )
        .with_token_param("grant_type", "refresh_token");
        let err = OAuth2Client::new(config).unwrap_err();
        assert!(matches!(
            err,
            OAuthError::InvalidConfig(ref m)
                if m.contains("extra token param `grant_type` is reserved")
        ));
    }

    #[test]
    fn test_client_accepts_no_redirect_uri() {
        let config = OAuth2Config::new(
            "id",
            "secret",
            "https://auth.example.com/authorize",
            "https://auth.example.com/token",
        );
        // No redirect_uri set — should succeed
        assert!(OAuth2Client::new(config).is_ok());
    }

    #[test]
    fn test_client_debug() {
        let client = OAuth2Client::new(test_config()).unwrap();
        let debug = format!("{client:?}");
        assert!(debug.contains("OAuth2Client"));
        assert!(debug.contains("test_client_id"));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn test_client_clone() {
        let client = OAuth2Client::new(test_config()).unwrap();
        let cloned = client.clone();
        assert_eq!(cloned.config().client_id, "test_client_id");
    }

    // ── New batch: Authorization URL generation edge cases ──

    #[test]
    fn test_authorization_url_empty_scopes() {
        let config = test_config();
        let client = OAuth2Client::new(config).unwrap();
        let (url, _) = client.authorization_url(&[]).unwrap();
        // With no scopes, scope param should not appear
        assert!(!url.contains("scope="));
    }

    #[test]
    fn test_authorization_url_single_scope() {
        let config = test_config();
        let client = OAuth2Client::new(config).unwrap();
        let (url, _) = client.authorization_url(&["openid"]).unwrap();
        assert!(url.contains("scope=openid"));
    }

    #[test]
    fn test_authorization_url_many_scopes() {
        let config = test_config();
        let client = OAuth2Client::new(config).unwrap();
        let (url, _) = client
            .authorization_url(&["openid", "email", "profile", "offline_access"])
            .unwrap();
        assert!(url.contains("scope=openid+email+profile+offline_access"));
    }

    #[test]
    fn test_authorization_url_contains_redirect_uri() {
        let config = test_config();
        let client = OAuth2Client::new(config).unwrap();
        let (url, _) = client.authorization_url(&[]).unwrap();
        // redirect_uri should be URL-encoded
        assert!(url.contains("redirect_uri=https%3A%2F%2Flocalhost%3A3000%2Fcallback"));
    }

    #[test]
    fn test_authorization_url_without_redirect_uri() {
        let config = OAuth2Config::new(
            "id",
            "secret",
            "https://auth.example.com/authorize",
            "https://auth.example.com/token",
        );
        let client = OAuth2Client::new(config).unwrap();
        let (url, _) = client.authorization_url(&[]).unwrap();
        assert!(!url.contains("redirect_uri="));
    }

    #[test]
    fn test_authorization_url_state_is_unique() {
        let client = OAuth2Client::new(test_config()).unwrap();
        let (_, state1) = client.authorization_url(&[]).unwrap();
        let (_, state2) = client.authorization_url(&[]).unwrap();
        let (_, state3) = client.authorization_url(&[]).unwrap();
        assert_ne!(state1, state2);
        assert_ne!(state2, state3);
    }

    #[test]
    fn test_authorization_url_state_not_empty() {
        let client = OAuth2Client::new(test_config()).unwrap();
        let (_, state) = client.authorization_url(&[]).unwrap();
        assert!(!state.is_empty());
    }

    #[test]
    fn test_authorization_url_with_extra_auth_params() {
        let config = test_config()
            .with_auth_param("prompt", "consent")
            .with_auth_param("access_type", "offline");
        let client = OAuth2Client::new(config).unwrap();
        let (url, _) = client.authorization_url(&[]).unwrap();
        assert!(url.contains("prompt=consent"));
        assert!(url.contains("access_type=offline"));
    }

    #[test]
    fn test_authorization_url_query_response_mode_not_in_url() {
        // Default response_mode is Query; it should NOT be appended
        let config = test_config();
        let client = OAuth2Client::new(config).unwrap();
        let (url, _) = client.authorization_url(&[]).unwrap();
        assert!(!url.contains("response_mode="));
    }

    #[test]
    fn test_authorization_url_fragment_response_mode() {
        let config = test_config().with_response_mode(ResponseMode::Fragment);
        let client = OAuth2Client::new(config).unwrap();
        let (url, _) = client.authorization_url(&[]).unwrap();
        assert!(url.contains("response_mode=fragment"));
    }

    #[test]
    fn test_authorization_url_with_pkce_plain_method() {
        let config = test_config().with_pkce_method(PkceMethod::Plain);
        let client = OAuth2Client::new(config).unwrap();
        let (url, _, pkce) = client.authorization_url_with_pkce(&[]).unwrap();
        assert!(url.contains("code_challenge_method=plain"));
        // For plain method, challenge equals verifier
        assert_eq!(pkce.verifier(), pkce.challenge());
    }

    #[test]
    fn test_authorization_url_with_pkce_returns_unique_pkce() {
        let client = OAuth2Client::new(test_config()).unwrap();
        let (_, _, pkce1) = client.authorization_url_with_pkce(&[]).unwrap();
        let (_, _, pkce2) = client.authorization_url_with_pkce(&[]).unwrap();
        assert_ne!(pkce1.verifier(), pkce2.verifier());
    }

    // ── New batch: AuthorizationCallback edge cases ──

    #[test]
    fn test_callback_from_query_empty() {
        let callback = AuthorizationCallback::from_query("").unwrap();
        assert!(callback.code.is_none());
        assert!(callback.state.is_none());
        assert!(callback.error.is_none());
    }

    #[test]
    fn test_callback_from_url_no_query() {
        let callback = AuthorizationCallback::from_url("https://localhost/callback").unwrap();
        assert!(callback.code.is_none());
        assert!(callback.state.is_none());
    }

    #[test]
    fn test_callback_from_url_invalid_url() {
        let result = AuthorizationCallback::from_url("://bad");
        assert!(result.is_err());
    }

    #[test]
    fn test_callback_error_with_description_and_uri() {
        let callback = AuthorizationCallback {
            code: None,
            state: Some("state".into()),
            error: Some("server_error".into()),
            error_description: Some("Internal server error".into()),
            error_uri: Some("https://provider.com/errors/500".into()),
        };
        let err = callback
            .validate("state")
            .expect_err("callback error must produce AuthorizationError");
        assert!(
            matches!(&err, OAuthError::AuthorizationError { .. }),
            "expected AuthorizationError, got {err:?}"
        );
        if let OAuthError::AuthorizationError {
            error,
            description,
            error_uri,
        } = err
        {
            assert_eq!(error, "server_error");
            assert_eq!(description, "Internal server error");
            assert_eq!(
                error_uri,
                Some("https://provider.com/errors/500".to_string())
            );
        }
    }

    #[test]
    fn test_callback_rejects_mixed_success_and_error() {
        let callback = AuthorizationCallback {
            code: Some("code".into()),
            state: Some("state".into()),
            error: Some("access_denied".into()),
            error_description: None,
            error_uri: None,
        };
        let err = callback
            .validate("state")
            .expect_err("mixed success/error callbacks must fail closed");
        assert!(
            matches!(err, OAuthError::InvalidTokenResponse(ref msg) if msg.contains("both code and error")),
            "expected mixed callback rejection, got {err:?}"
        );
    }

    #[test]
    fn test_callback_serde_roundtrip() {
        let callback = AuthorizationCallback {
            code: Some("code123".into()),
            state: Some("state456".into()),
            error: None,
            error_description: None,
            error_uri: None,
        };
        let json = serde_json::to_string(&callback).unwrap();
        let roundtrip: AuthorizationCallback = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.code, Some("code123".to_string()));
        assert_eq!(roundtrip.state, Some("state456".to_string()));
    }

    #[test]
    fn test_callback_clone() {
        let callback = AuthorizationCallback {
            code: Some("c".into()),
            state: Some("s".into()),
            error: None,
            error_description: None,
            error_uri: None,
        };
        let cloned = callback.clone();
        assert_eq!(callback.code, cloned.code);
        assert_eq!(callback.state, cloned.state);
    }

    #[test]
    fn test_callback_debug() {
        // br-8i1x4: use distinctive multi-char sentinel values for
        // `code` and `state` so the `!contains(...)` assertions aren't
        // satisfied by coincidental single-letter overlap with other
        // fields (e.g., `error: access_denied` contains "c" and "s",
        // which defeated the old single-letter test values).
        let callback = AuthorizationCallback {
            code: Some("SECRET_CODE_7f4a".into()),
            state: Some("SECRET_STATE_b19c".into()),
            error: Some("access_denied".into()),
            error_description: Some("leaked description".into()),
            error_uri: Some("https://attacker.example/debug".into()),
        };
        let debug = format!("{callback:?}");
        assert!(debug.contains("AuthorizationCallback"));
        // `error` is the bounded RFC 6749 §4.1.2.1 enum-like token;
        // intentionally shown verbatim in Debug (matches the
        // AuthorizationError redaction policy pinned in 19487b91).
        assert!(debug.contains("access_denied"));
        assert!(debug.contains("[REDACTED]"));
        // Raw code + state must never reach Debug output.
        assert!(
            !debug.contains("SECRET_CODE_7f4a"),
            "authorization code leaked: {debug}"
        );
        assert!(
            !debug.contains("SECRET_STATE_b19c"),
            "authorization state leaked: {debug}"
        );
        // Attacker-controlled callback error fields (description + uri)
        // must not reach Debug either.
        assert!(!debug.contains("leaked description"));
        assert!(!debug.contains("attacker.example"));
    }

    #[test]
    fn test_authorization_session_debug_redacts_state_and_pkce() {
        let pkce = Pkce::from_verifier(
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            PkceMethod::S256,
        )
        .unwrap();
        let session = AuthorizationSession {
            authorization_url: format!(
                "https://example.com/oauth?client_id=demo&state=secret-state&code_challenge={}&redirect_uri=https%3A%2F%2Fapp.example%2Fcb#callback-fragment",
                pkce.challenge()
            ),
            state: "secret-state".into(),
            pkce: Some(pkce.clone()),
            consumed: Arc::new(AtomicBool::new(false)),
        };

        let debug = format!("{session:?}");
        assert!(debug.contains("AuthorizationSession"));
        assert!(debug.contains("https://example.com/oauth"));
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("secret-state"));
        assert!(!debug.contains(pkce.verifier()));
        assert!(!debug.contains(pkce.challenge()));
        assert!(!debug.contains("client_id=demo"));
        assert!(!debug.contains("callback-fragment"));
    }

    #[test]
    fn test_authorization_grant_debug_redacts_code_and_pkce() {
        let pkce = Pkce::from_verifier(
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            PkceMethod::S256,
        )
        .unwrap();
        let grant = AuthorizationGrant {
            code: "secret-code".into(),
            pkce: Some(pkce.clone()),
        };

        let debug = format!("{grant:?}");
        assert!(debug.contains("AuthorizationGrant"));
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("secret-code"));
        assert!(!debug.contains(pkce.verifier()));
        assert!(!debug.contains(pkce.challenge()));
    }

    // ── New batch: AuthStyle ──

    #[test]
    fn test_auth_style_eq() {
        assert_eq!(AuthStyle::Basic, AuthStyle::Basic);
        assert_eq!(AuthStyle::Post, AuthStyle::Post);
        assert_ne!(AuthStyle::Basic, AuthStyle::Post);
    }

    #[test]
    #[allow(clippy::clone_on_copy)]
    fn test_auth_style_clone_copy() {
        let style = AuthStyle::Basic;
        let copied = style;
        let cloned = style.clone();
        assert_eq!(style, copied);
        assert_eq!(style, cloned);
    }

    #[test]
    fn test_auth_style_debug() {
        let debug = format!("{:?}", AuthStyle::Basic);
        assert!(debug.contains("Basic"));
        let debug = format!("{:?}", AuthStyle::Post);
        assert!(debug.contains("Post"));
    }

    // ── New batch: Mock server flows ──

    #[test]
    fn test_client_credentials_requires_secret() {
        run_with_test_runtime(async {
            let config = OAuth2Config::public_client(
                "public",
                "https://auth.example.com/authorize",
                "https://auth.example.com/token",
            );
            let client = OAuth2Client::new(config).unwrap();
            let result = client.client_credentials(&["read"]).await;
            assert!(matches!(result, Err(OAuthError::InvalidConfig(_))));
        });
    }

    #[test]
    fn test_client_credentials_with_mock_server() {
        run_with_test_runtime(async {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/token"))
                .and(body_string_contains("grant_type=client_credentials"))
                .and(body_string_contains("client_id=cc_client"))
                .and(body_string_contains("scope=api.read+api.write"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "cc-access-tok",
                    "token_type": "Bearer",
                    "expires_in": 1800
                })))
                .mount(&server)
                .await;

            let config = OAuth2Config::new(
                "cc_client",
                "cc_secret",
                format!("{}/authorize", server.uri()),
                format!("{}/token", server.uri()),
            );
            let client = OAuth2Client::new(config).unwrap();
            let tokens = client
                .client_credentials(&["api.read", "api.write"])
                .await
                .unwrap();
            assert_eq!(tokens.access_token(), "cc-access-tok");
            assert!(tokens.refresh_token().is_none());
        });
    }

    #[test]
    fn test_client_credentials_with_default_scopes() {
        run_with_test_runtime(async {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/token"))
                .and(body_string_contains("grant_type=client_credentials"))
                .and(body_string_contains("scope=default.scope+extra.scope"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "tok",
                    "token_type": "Bearer",
                    "expires_in": 3600
                })))
                .mount(&server)
                .await;

            let config = OAuth2Config::new(
                "id",
                "secret",
                format!("{}/authorize", server.uri()),
                format!("{}/token", server.uri()),
            )
            .with_scopes(vec!["default.scope".into()]);
            let client = OAuth2Client::new(config).unwrap();
            let tokens = client.client_credentials(&["extra.scope"]).await.unwrap();
            assert_eq!(tokens.access_token(), "tok");
        });
    }

    #[test]
    fn test_exchange_code_error_non_json_body() {
        run_with_test_runtime(async {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/token"))
                .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
                .mount(&server)
                .await;

            let config = OAuth2Config::new(
                "id",
                "secret",
                format!("{}/authorize", server.uri()),
                format!("{}/token", server.uri()),
            )
            .with_pkce(false);
            let client = OAuth2Client::new(config).unwrap();
            let error = client.exchange_code("code").await.unwrap_err();
            assert!(
                matches!(&error, OAuthError::TokenExchangeFailed(_)),
                "expected token exchange error"
            );
            let OAuthError::TokenExchangeFailed(message) = error else {
                return;
            };
            assert_eq!(
                message,
                "token endpoint returned an unsuccessful response (status 500)"
            );
            assert!(!message.contains("Internal Server Error"));
        });
    }

    #[test]
    fn test_exchange_code_with_extra_token_params() {
        run_with_test_runtime(async {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/token"))
                .and(body_string_contains(
                    "audience=https%3A%2F%2Fapi.example.com",
                ))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "tok-extra",
                    "token_type": "Bearer",
                    "expires_in": 3600
                })))
                .mount(&server)
                .await;

            let config = OAuth2Config::new(
                "id",
                "secret",
                format!("{}/authorize", server.uri()),
                format!("{}/token", server.uri()),
            )
            .with_token_param("audience", "https://api.example.com")
            .with_pkce(false);
            let client = OAuth2Client::new(config).unwrap();
            let tokens = client.exchange_code("code").await.unwrap();
            assert_eq!(tokens.access_token(), "tok-extra");
        });
    }

    #[test]
    fn test_refresh_with_extra_token_params() {
        run_with_test_runtime(async {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/token"))
                .and(body_string_contains("grant_type=refresh_token"))
                .and(body_string_contains(
                    "audience=https%3A%2F%2Fapi.example.com",
                ))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "refreshed-tok",
                    "token_type": "Bearer",
                    "expires_in": 3600
                })))
                .mount(&server)
                .await;

            let config = OAuth2Config::new(
                "id",
                "secret",
                format!("{}/authorize", server.uri()),
                format!("{}/token", server.uri()),
            )
            .with_token_param("audience", "https://api.example.com");
            let client = OAuth2Client::new(config).unwrap();
            let tokens = client.refresh_tokens("old-refresh").await.unwrap();
            assert_eq!(tokens.access_token(), "refreshed-tok");
        });
    }

    #[test]
    fn test_token_response_without_refresh_token() {
        run_with_test_runtime(async {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "no-refresh-tok",
                    "token_type": "Bearer",
                    "expires_in": 3600
                })))
                .mount(&server)
                .await;

            let config = OAuth2Config::new(
                "id",
                "secret",
                format!("{}/authorize", server.uri()),
                format!("{}/token", server.uri()),
            )
            .with_pkce(false);
            let client = OAuth2Client::new(config).unwrap();
            let tokens = client.exchange_code("code").await.unwrap();
            assert!(tokens.refresh_token().is_none());
        });
    }

    #[test]
    fn test_token_response_with_scopes_parsed() {
        run_with_test_runtime(async {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "tok",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "scope": "openid email profile"
                })))
                .mount(&server)
                .await;

            let config = OAuth2Config::new(
                "id",
                "secret",
                format!("{}/authorize", server.uri()),
                format!("{}/token", server.uri()),
            )
            .with_pkce(false);
            let client = OAuth2Client::new(config).unwrap();
            let tokens = client.exchange_code("code").await.unwrap();
            assert_eq!(tokens.scopes(), &["openid", "email", "profile"]);
        });
    }

    #[test]
    fn test_basic_auth_style_sends_authorization_header() {
        run_with_test_runtime(async {
            let server = MockServer::start().await;
            // With Basic auth, client_id/secret should be in Authorization header, not body
            Mock::given(method("POST"))
                .and(path("/token"))
                .and(wiremock::matchers::header_exists("Authorization"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "basic-tok",
                    "token_type": "Bearer",
                    "expires_in": 3600
                })))
                .mount(&server)
                .await;

            let config = OAuth2Config::new(
                "id",
                "secret",
                format!("{}/authorize", server.uri()),
                format!("{}/token", server.uri()),
            )
            .with_auth_style(AuthStyle::Basic)
            .with_pkce(false);
            let client = OAuth2Client::new(config).unwrap();
            let tokens = client.exchange_code("code").await.unwrap();
            assert_eq!(tokens.access_token(), "basic-tok");
        });
    }

    #[test]
    fn test_form_encode_rfc6749_basic_auth() {
        // RFC 6749 Appendix B uses form encoding, so spaces become `+`.
        assert_eq!(form_encode("simple"), "simple");
        assert_eq!(form_encode("id:with:colons"), "id%3Awith%3Acolons");
        assert_eq!(form_encode("secret with spaces"), "secret+with+spaces");
        assert_eq!(form_encode("a+b&c=d"), "a%2Bb%26c%3Dd");
        assert_eq!(form_encode(""), "");
    }

    #[test]
    fn test_basic_auth_style_form_encodes_credentials_before_base64() {
        run_with_test_runtime(async {
            let server = MockServer::start().await;
            let expected_credentials = STANDARD.encode("client+id:secret+value%2B");

            Mock::given(method("POST"))
                .and(path("/token"))
                .and(wiremock::matchers::header(
                    "Authorization",
                    format!("Basic {expected_credentials}"),
                ))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "basic-tok",
                    "token_type": "Bearer",
                    "expires_in": 3600
                })))
                .mount(&server)
                .await;

            let config = OAuth2Config::new(
                "client id",
                "secret value+",
                format!("{}/authorize", server.uri()),
                format!("{}/token", server.uri()),
            )
            .with_auth_style(AuthStyle::Basic)
            .with_pkce(false);
            let client = OAuth2Client::new(config).unwrap();
            let tokens = client.exchange_code("code").await.unwrap();
            assert_eq!(tokens.access_token(), "basic-tok");
        });
    }

    // ── Expanded tests: OAuth2Config edge cases ──

    #[test]
    fn test_config_auth_param_overwrite() {
        let config = test_config()
            .with_auth_param("prompt", "login")
            .with_auth_param("prompt", "consent");
        assert_eq!(
            config.extra_auth_params.get("prompt"),
            Some(&"consent".to_string())
        );
    }

    #[test]
    fn test_config_token_param_overwrite() {
        let config = test_config()
            .with_token_param("audience", "v1")
            .with_token_param("audience", "v2");
        assert_eq!(
            config.extra_token_params.get("audience"),
            Some(&"v2".to_string())
        );
    }

    #[test]
    fn test_config_empty_scopes_vec() {
        let config = test_config().with_scopes(Vec::new());
        assert!(config.default_scopes.is_empty());
    }

    #[test]
    fn test_config_timeout_zero() {
        let config = test_config().with_timeout(Duration::from_secs(0));
        assert_eq!(config.timeout, Duration::from_secs(0));
    }

    #[test]
    fn test_config_timeout_large() {
        let config = test_config().with_timeout(Duration::from_secs(300));
        assert_eq!(config.timeout, Duration::from_secs(300));
    }

    // ── Expanded tests: AuthorizationCallback parsing ──

    #[test]
    fn test_callback_from_query_with_error() {
        let callback = AuthorizationCallback::from_query(
            "error=access_denied&error_description=User+denied&state=s",
        )
        .unwrap();
        assert_eq!(callback.error, Some("access_denied".to_string()));
        assert_eq!(callback.error_description, Some("User denied".to_string()));
        assert!(callback.code.is_none());
    }

    #[test]
    fn test_callback_from_query_url_encoded_values() {
        let callback =
            AuthorizationCallback::from_query("code=abc%20def&state=my%26state").unwrap();
        assert_eq!(callback.code, Some("abc def".to_string()));
        assert_eq!(callback.state, Some("my&state".to_string()));
    }

    #[test]
    fn test_callback_from_url_with_fragment_ignored() {
        // Fragments are not part of query string
        let callback =
            AuthorizationCallback::from_url("https://localhost/callback?code=abc&state=xyz#extra")
                .unwrap();
        assert_eq!(callback.code, Some("abc".to_string()));
    }

    #[test]
    fn test_callback_validate_error_without_description() {
        let callback = AuthorizationCallback {
            code: None,
            state: Some("state".into()),
            error: Some("invalid_scope".into()),
            error_description: None,
            error_uri: None,
        };
        let err = callback.validate("state").unwrap_err();
        assert!(
            matches!(err, OAuthError::AuthorizationError { ref description, .. } if description.is_empty()),
            "expected AuthorizationError without description, got {err:?}"
        );
    }

    // ── Expanded tests: generate_state ──

    #[test]
    fn test_generate_state_length() {
        let state = generate_state();
        // 32 bytes -> base64url no padding = 43 chars
        assert_eq!(state.len(), 43);
    }

    #[test]
    fn test_generate_state_valid_chars() {
        let state = generate_state();
        assert!(
            state
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
    }

    #[test]
    fn test_generate_state_uniqueness() {
        let s1 = generate_state();
        let s2 = generate_state();
        let s3 = generate_state();
        assert_ne!(s1, s2);
        assert_ne!(s2, s3);
    }

    // ── Expanded tests: OAuth2Client with custom HTTP client ──

    #[test]
    fn test_client_with_custom_http_client() {
        let config = test_config();
        let http_client = HttpClientBuilder::new().build();
        let client = OAuth2Client::with_http_client(config, http_client).unwrap();
        assert_eq!(client.config().client_id, "test_client_id");
    }

    #[test]
    fn test_client_with_custom_http_client_config_accessor() {
        let config = test_config()
            .with_scopes(vec!["admin".into()])
            .with_auth_style(AuthStyle::Basic);
        let http_client = HttpClientBuilder::new().build();
        let client = OAuth2Client::with_http_client(config, http_client).unwrap();
        assert_eq!(client.config().default_scopes, vec!["admin"]);
        assert_eq!(client.config().auth_style, AuthStyle::Basic);
    }

    #[test]
    fn test_client_with_custom_http_client_rejects_non_loopback_http_redirect_uri() {
        let config = OAuth2Config::new(
            "id",
            "secret",
            "https://auth.example.com/authorize",
            "https://auth.example.com/token",
        )
        .with_redirect_uri("http://attacker.example/callback");
        let http_client = HttpClientBuilder::new().build();
        let err = OAuth2Client::with_http_client(config, http_client).unwrap_err();
        assert!(matches!(
            err,
            OAuthError::InvalidConfig(ref m) if m.contains("https or loopback http")
        ));
    }

    // ── Expanded: config field defaults and combinations ──

    #[test]
    fn test_config_with_scopes_replaces_previous() {
        let config = test_config()
            .with_scopes(vec!["a".into()])
            .with_scopes(vec!["b".into(), "c".into()]);
        assert_eq!(config.default_scopes, vec!["b", "c"]);
    }

    #[test]
    fn test_config_with_redirect_uri_replaces_previous() {
        let config = test_config()
            .with_redirect_uri("https://first.com")
            .with_redirect_uri("https://second.com");
        assert_eq!(config.redirect_uri, Some("https://second.com".to_string()));
    }

    #[test]
    fn test_config_pkce_toggle() {
        let config = test_config()
            .with_pkce(true)
            .with_pkce(false)
            .with_pkce(true);
        assert!(config.use_pkce);
    }

    #[test]
    fn test_config_response_mode_all_variants() {
        for mode in [
            ResponseMode::Query,
            ResponseMode::Fragment,
            ResponseMode::FormPost,
        ] {
            let config = test_config().with_response_mode(mode);
            assert_eq!(config.response_mode, mode);
        }
    }

    #[test]
    fn test_config_auth_style_all_variants() {
        for style in [AuthStyle::Basic, AuthStyle::Post] {
            let config = test_config().with_auth_style(style);
            assert_eq!(config.auth_style, style);
        }
    }

    #[test]
    fn test_public_client_with_redirect_uri() {
        let config = OAuth2Config::public_client(
            "pub_id",
            "https://auth.example.com/authorize",
            "https://auth.example.com/token",
        )
        .with_redirect_uri("https://localhost:8080/cb");
        assert!(config.client_secret.is_none());
        assert_eq!(
            config.redirect_uri,
            Some("https://localhost:8080/cb".to_string())
        );
    }

    #[test]
    fn test_public_client_with_scopes() {
        let config = OAuth2Config::public_client(
            "pub_id",
            "https://auth.example.com/authorize",
            "https://auth.example.com/token",
        )
        .with_scopes(vec!["openid".into(), "profile".into()]);
        assert_eq!(config.default_scopes, vec!["openid", "profile"]);
    }

    // ── Expanded: authorization URL details ──

    #[test]
    fn test_authorization_url_starts_with_base() {
        let client = OAuth2Client::new(test_config()).unwrap();
        let (url, _) = client.authorization_url(&[]).unwrap();
        assert!(url.starts_with("https://auth.example.com/authorize?"));
    }

    #[test]
    fn test_authorization_url_with_pkce_contains_challenge() {
        let client = OAuth2Client::new(test_config()).unwrap();
        let (url, _, pkce) = client.authorization_url_with_pkce(&["read"]).unwrap();
        // The challenge value itself should appear in the URL
        assert!(url.contains(pkce.challenge()));
    }

    #[test]
    fn test_authorization_url_query_mode_no_response_mode_param() {
        let config = test_config().with_response_mode(ResponseMode::Query);
        let client = OAuth2Client::new(config).unwrap();
        let (url, _) = client.authorization_url(&[]).unwrap();
        assert!(!url.contains("response_mode"));
    }

    // ── Expanded: callback validation edge cases ──

    #[test]
    fn test_callback_validate_with_empty_state() {
        let callback = AuthorizationCallback {
            code: Some("code".into()),
            state: Some(String::new()),
            error: None,
            error_description: None,
            error_uri: None,
        };
        let err = callback
            .validate("")
            .expect_err("empty states must be rejected");
        assert!(matches!(err, OAuthError::InvalidState(_)));
    }

    #[test]
    fn test_callback_validate_state_whitespace_matters() {
        let callback = AuthorizationCallback {
            code: Some("code".into()),
            state: Some("state ".into()),
            error: None,
            error_description: None,
            error_uri: None,
        };
        let result = callback.validate("state");
        assert!(matches!(result, Err(OAuthError::StateMismatch { .. })));
    }

    #[test]
    fn test_authorization_session_is_single_use() {
        let client = OAuth2Client::new(test_config()).unwrap();
        let session = client.authorization_session(&["openid"]).unwrap();
        assert!(session.pkce().is_some());
        let callback = AuthorizationCallback {
            code: Some("auth-code".into()),
            state: Some(session.state().to_string()),
            error: None,
            error_description: None,
            error_uri: None,
        };

        let grant = session
            .validate_callback(&callback)
            .expect("first validation should succeed");
        assert_eq!(grant.code(), "auth-code");

        let err = session
            .validate_callback(&callback)
            .expect_err("validated session must not be reusable");
        assert!(matches!(err, OAuthError::AuthorizationSessionConsumed));
    }

    #[test]
    fn test_authorization_session_empty_code_does_not_consume_session() {
        let client = OAuth2Client::new(test_config()).unwrap();
        let session = client.authorization_session(&["openid"]).unwrap();
        let empty_code_callback = AuthorizationCallback {
            code: Some(String::new()),
            state: Some(session.state().to_string()),
            error: None,
            error_description: None,
            error_uri: None,
        };

        let err = session
            .validate_callback(&empty_code_callback)
            .expect_err("empty code must fail validation");
        assert!(
            matches!(err, OAuthError::InvalidTokenResponse(ref msg) if msg == EMPTY_AUTHORIZATION_CODE_MESSAGE),
            "empty code should be a validation failure, got {err:?}"
        );

        let valid_callback = AuthorizationCallback {
            code: Some("auth-code".into()),
            state: Some(session.state().to_string()),
            error: None,
            error_description: None,
            error_uri: None,
        };
        let grant = session
            .validate_callback(&valid_callback)
            .expect("failed validation must not consume the session");
        assert_eq!(grant.code(), "auth-code");
    }

    #[test]
    fn test_authorization_session_with_pkce_preserves_pkce() {
        let client = OAuth2Client::new(test_config()).unwrap();
        let session = client.authorization_session_with_pkce(&["read"]).unwrap();
        let callback = AuthorizationCallback {
            code: Some("auth-code".into()),
            state: Some(session.state().to_string()),
            error: None,
            error_description: None,
            error_uri: None,
        };

        let grant = session
            .validate_callback(&callback)
            .expect("callback should validate");
        assert_eq!(grant.code(), "auth-code");
        assert_eq!(grant.pkce(), session.pkce());
    }

    #[test]
    fn test_exchange_code_requires_pkce_when_enabled() {
        run_with_test_runtime(async {
            let server = MockServer::start().await;
            let config = OAuth2Config::new(
                "id",
                "secret",
                format!("{}/authorize", server.uri()),
                format!("{}/token", server.uri()),
            )
            .with_redirect_uri("https://localhost:3000/callback");
            let client = OAuth2Client::new(config).unwrap();

            let err = client
                .exchange_code("code-without-verifier")
                .await
                .expect_err("PKCE-enabled exchange must fail without per-flow PKCE");
            assert!(matches!(err, OAuthError::InvalidConfig(_)));
            assert!(
                err.to_string().contains("requires PKCE"),
                "unexpected error: {err}"
            );
        });
    }

    #[test]
    fn test_exchange_code_with_pkce_rejects_static_code_verifier_config() {
        let config = OAuth2Config::new(
            "id",
            "secret",
            "https://auth.example.com/authorize",
            "https://auth.example.com/token",
        )
        .with_redirect_uri("https://localhost:3000/callback")
        .with_token_param("code_verifier", "bogus-extra-verifier-that-must-not-win");
        let err = OAuth2Client::new(config).unwrap_err();
        assert!(matches!(
            err,
            OAuthError::InvalidConfig(ref m)
                if m.contains("extra token param `code_verifier` is reserved")
        ));
    }

    #[test]
    fn test_callback_from_query_preserves_special_chars() {
        let callback = AuthorizationCallback::from_query("code=abc%3Ddef&state=x%26y").unwrap();
        assert_eq!(callback.code, Some("abc=def".to_string()));
        assert_eq!(callback.state, Some("x&y".to_string()));
    }

    #[test]
    fn test_callback_from_url_with_port() {
        let callback =
            AuthorizationCallback::from_url("https://localhost:8443/callback?code=c&state=s")
                .unwrap();
        assert_eq!(callback.code, Some("c".to_string()));
        assert_eq!(callback.state, Some("s".to_string()));
    }

    #[test]
    fn test_callback_serde_all_fields() {
        let callback = AuthorizationCallback {
            code: Some("c".into()),
            state: Some("s".into()),
            error: Some("e".into()),
            error_description: Some("d".into()),
            error_uri: Some("https://err.com".into()),
        };
        let json = serde_json::to_string(&callback).unwrap();
        let rt: AuthorizationCallback = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.code, Some("c".to_string()));
        assert_eq!(rt.error, Some("e".to_string()));
        assert_eq!(rt.error_uri, Some("https://err.com".to_string()));
    }

    #[test]
    fn test_callback_serde_null_fields() {
        let json =
            r#"{"code":null,"state":null,"error":null,"error_description":null,"error_uri":null}"#;
        let callback: AuthorizationCallback = serde_json::from_str(json).unwrap();
        assert!(callback.code.is_none());
        assert!(callback.state.is_none());
        assert!(callback.error.is_none());
    }

    #[test]
    fn test_callback_serde_empty_json_object() {
        let json = "{}";
        let callback: AuthorizationCallback = serde_json::from_str(json).unwrap();
        assert!(callback.code.is_none());
        assert!(callback.state.is_none());
    }

    // ── Expanded: AuthStyle display and traits ──

    #[test]
    fn test_auth_style_display_all() {
        assert_eq!(format!("{}", AuthStyle::Basic), "basic");
        assert_eq!(format!("{}", AuthStyle::Post), "post");
    }

    #[test]
    fn test_auth_style_ne() {
        assert_ne!(AuthStyle::Basic, AuthStyle::Post);
        assert_ne!(AuthStyle::Post, AuthStyle::Basic);
    }

    // ── Expanded: generate_state properties ──

    #[test]
    fn test_generate_state_no_padding() {
        let state = generate_state();
        assert!(!state.contains('='));
    }

    #[test]
    fn test_generate_state_no_plus_no_slash() {
        let state = generate_state();
        assert!(!state.contains('+'));
        assert!(!state.contains('/'));
    }

    // ── New batch: OAuth2Config edge cases ──

    #[test]
    fn test_config_empty_client_id() {
        let config = OAuth2Config::new(
            "",
            "secret",
            "https://auth.example.com/authorize",
            "https://auth.example.com/token",
        );
        assert!(config.client_id.is_empty());
    }

    #[test]
    fn test_config_empty_client_secret() {
        let config = OAuth2Config::new(
            "id",
            "",
            "https://auth.example.com/authorize",
            "https://auth.example.com/token",
        );
        assert_eq!(config.client_secret, Some(String::new()));
    }

    #[test]
    fn test_config_unicode_client_id() {
        let config = OAuth2Config::new(
            "client_\u{00e9}tranger",
            "secret",
            "https://auth.example.com/authorize",
            "https://auth.example.com/token",
        );
        assert_eq!(config.client_id, "client_\u{00e9}tranger");
    }

    #[test]
    fn test_authorization_url_with_unicode_scope() {
        let config = test_config();
        let client = OAuth2Client::new(config).unwrap();
        let (url, _) = client
            .authorization_url(&["read", "profil\u{00e9}"])
            .unwrap();
        assert!(url.contains("scope=read"));
    }

    #[test]
    fn test_config_debug_contains_all_key_fields() {
        let config = test_config()
            .with_scopes(vec!["admin".into()])
            .with_auth_param("prompt", "login")
            .with_token_param("audience", "api");
        let debug = format!("{config:?}");
        assert!(debug.contains("client_id"));
        assert!(debug.contains("authorization_url"));
        assert!(debug.contains("token_url"));
        assert!(debug.contains("use_pkce"));
    }

    // ── New batch: AuthorizationCallback advanced ──

    #[test]
    fn test_callback_from_query_with_all_fields() {
        let callback = AuthorizationCallback::from_query(
            "code=c&state=s&error=e&error_description=d&error_uri=https://err.com",
        )
        .unwrap();
        assert_eq!(callback.code, Some("c".to_string()));
        assert_eq!(callback.state, Some("s".to_string()));
        assert_eq!(callback.error, Some("e".to_string()));
        assert_eq!(callback.error_description, Some("d".to_string()));
        assert_eq!(callback.error_uri, Some("https://err.com".to_string()));
    }

    #[test]
    fn test_callback_validate_error_with_uri_propagates() {
        let callback = AuthorizationCallback {
            code: None,
            state: Some("s".into()),
            error: Some("invalid_scope".into()),
            error_description: Some("Bad scope".into()),
            error_uri: Some("https://docs.example.com/scopes".into()),
        };
        let err = callback.validate("s").unwrap_err();
        assert!(
            matches!(&err, OAuthError::AuthorizationError { .. }),
            "expected AuthorizationError, got {err:?}"
        );
        if let OAuthError::AuthorizationError {
            error,
            description,
            error_uri,
        } = err
        {
            assert_eq!(error, "invalid_scope");
            assert_eq!(description, "Bad scope");
            assert_eq!(
                error_uri,
                Some("https://docs.example.com/scopes".to_string())
            );
        }
    }

    #[test]
    fn test_callback_from_url_with_multiple_query_params() {
        let callback = AuthorizationCallback::from_url(
            "https://localhost/cb?code=xyz&state=abc&extra=ignored",
        )
        .unwrap();
        assert_eq!(callback.code, Some("xyz".to_string()));
        assert_eq!(callback.state, Some("abc".to_string()));
    }

    #[test]
    fn test_callback_clone_independence() {
        let callback = AuthorizationCallback {
            code: Some("orig_code".into()),
            state: Some("orig_state".into()),
            error: None,
            error_description: None,
            error_uri: None,
        };
        let cloned = callback.clone();
        assert_eq!(callback.code, cloned.code);
        assert_eq!(callback.state, cloned.state);
        // Validate original still works after clone
        let code = callback.validate("orig_state").unwrap();
        assert_eq!(code, "orig_code");
    }

    // ── New batch: generate_state properties ──

    #[test]
    fn test_generate_state_ten_calls_all_unique() {
        let states: Vec<String> = (0..10).map(|_| generate_state()).collect();
        for i in 0..states.len() {
            for j in (i + 1)..states.len() {
                assert_ne!(states[i], states[j], "duplicate at {i} and {j}");
            }
        }
    }

    // ── New batch: OAuth2Client validation ──

    #[test]
    fn test_client_accepts_localhost_urls() {
        let config = OAuth2Config::new(
            "id",
            "secret",
            "http://localhost:8080/authorize",
            "http://localhost:8080/token",
        );
        assert!(OAuth2Client::new(config).is_ok());
    }

    #[test]
    fn test_client_accepts_ip_urls() {
        let config = OAuth2Config::new(
            "id",
            "secret",
            "http://127.0.0.1:9090/authorize",
            "http://127.0.0.1:9090/token",
        );
        assert!(OAuth2Client::new(config).is_ok());
    }

    #[test]
    fn test_client_rejects_empty_authorization_url() {
        let config = OAuth2Config::new("id", "secret", "", "https://auth.example.com/token");
        let result = OAuth2Client::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_client_rejects_empty_token_url() {
        let config = OAuth2Config::new("id", "secret", "https://auth.example.com/authorize", "");
        let result = OAuth2Client::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_authorization_url_default_scopes_only() {
        let config = test_config().with_scopes(vec!["default_scope".into()]);
        let client = OAuth2Client::new(config).unwrap();
        // No additional scopes passed
        let (url, _) = client.authorization_url(&[]).unwrap();
        assert!(url.contains("scope=default_scope"));
    }
}
