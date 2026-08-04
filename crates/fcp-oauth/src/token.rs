//! OAuth token types and management.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use fcp_async_core::channel::watch;
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};

use crate::{DEFAULT_REFRESH_THRESHOLD, OAuth2Client, OAuthError, OAuthResult};

/// OAuth token response from provider.
#[derive(Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    /// The access token.
    pub access_token: String,

    /// Token type (usually "Bearer").
    pub token_type: String,

    /// Lifetime in seconds.
    #[serde(default)]
    pub expires_in: Option<u64>,

    /// Refresh token (if provided).
    #[serde(default)]
    pub refresh_token: Option<String>,

    /// Granted scopes (space-separated).
    #[serde(default)]
    pub scope: Option<String>,

    /// ID token (`OpenID Connect`).
    #[serde(default)]
    pub id_token: Option<String>,
}

impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenResponse")
            .field("access_token", &"[REDACTED]")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("scope", &self.scope)
            .field("id_token", &self.id_token.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

impl TokenResponse {
    /// Validate response invariants that must hold before token promotion.
    ///
    /// # Errors
    ///
    /// Returns a dedicated error when `access_token` or `token_type` is empty.
    pub fn validate(self) -> OAuthResult<Self> {
        if self.access_token.is_empty() {
            return Err(OAuthError::EmptyTokenField("access_token"));
        }
        if self.token_type.is_empty() {
            return Err(OAuthError::EmptyTokenField("token_type"));
        }
        Ok(self)
    }
}

fn parse_scope_list(scope: &str) -> Vec<String> {
    scope.split_whitespace().map(String::from).collect()
}

fn refreshed_scopes_are_subset(original: &[String], refreshed: &[String]) -> bool {
    if original.is_empty() {
        return true;
    }
    let original_scopes: HashSet<&str> = original.iter().map(String::as_str).collect();
    refreshed
        .iter()
        .all(|scope| original_scopes.contains(scope.as_str()))
}

/// Stored OAuth tokens with metadata.
#[derive(Clone, Serialize)]
pub struct OAuthTokens {
    /// The access token.
    access_token: String,

    /// Token type (usually "Bearer").
    token_type: String,

    /// When the token expires.
    expires_at: Option<DateTime<Utc>>,

    /// Refresh token for obtaining new access tokens.
    refresh_token: Option<String>,

    /// Granted scopes.
    scopes: Vec<String>,

    /// ID token (`OpenID Connect`).
    id_token: Option<String>,

    /// When the tokens were issued.
    issued_at: DateTime<Utc>,
}

impl std::fmt::Debug for OAuthTokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthTokens")
            .field("access_token", &"[REDACTED]")
            .field("token_type", &self.token_type)
            .field("expires_at", &self.expires_at)
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("scopes", &self.scopes)
            .field("id_token", &self.id_token.as_ref().map(|_| "[REDACTED]"))
            .field("issued_at", &self.issued_at)
            .finish()
    }
}

impl OAuthTokens {
    /// Create tokens from a token response.
    ///
    /// # Errors
    ///
    /// Returns a dedicated error when the response contains an empty
    /// `access_token` or `token_type`.
    pub fn from_response(response: TokenResponse) -> OAuthResult<Self> {
        let response = response.validate()?;
        let now = Utc::now();
        let expires_at = response.expires_in.map(|secs| {
            now + chrono::Duration::seconds(
                i64::try_from(secs.min(u64::from(u32::MAX))).unwrap_or(i64::MAX),
            )
        });

        let scopes = response
            .scope
            .as_deref()
            .map(parse_scope_list)
            .unwrap_or_default();

        Ok(Self {
            access_token: response.access_token,
            token_type: response.token_type,
            expires_at,
            refresh_token: response.refresh_token.filter(|rt| !rt.is_empty()),
            scopes,
            id_token: response.id_token.filter(|id| !id.is_empty()),
            issued_at: now,
        })
    }

    /// Get the access token.
    #[must_use]
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    /// Get the token type.
    #[must_use]
    pub fn token_type(&self) -> &str {
        &self.token_type
    }

    /// Get the refresh token if available.
    #[must_use]
    pub fn refresh_token(&self) -> Option<&str> {
        self.refresh_token.as_deref()
    }

    /// Preserve the current refresh token when a successful refresh response
    /// omits rotation.
    pub(crate) fn preserve_refresh_token_if_missing(&mut self, refresh_token: &str) {
        if self.refresh_token.is_none() && !refresh_token.is_empty() {
            self.refresh_token = Some(refresh_token.to_string());
        }
    }

    /// Get the granted scopes.
    #[must_use]
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    /// Get the ID token if available.
    #[must_use]
    pub fn id_token(&self) -> Option<&str> {
        self.id_token.as_deref()
    }

    /// Check if the token has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.expires_at.is_some_and(|exp| Utc::now() >= exp)
    }

    /// Check if the token needs refresh (within threshold of expiry).
    #[must_use]
    pub fn needs_refresh(&self) -> bool {
        self.needs_refresh_within(DEFAULT_REFRESH_THRESHOLD)
    }

    /// Check if the token needs refresh within a given threshold.
    #[must_use]
    pub fn needs_refresh_within(&self, threshold: Duration) -> bool {
        self.expires_at.is_some_and(|exp| {
            // Use saturating conversion to avoid panic on extreme durations
            let threshold_chrono =
                chrono::Duration::from_std(threshold).unwrap_or(chrono::TimeDelta::MAX);
            let threshold_time = Utc::now() + threshold_chrono;
            threshold_time >= exp
        })
    }

    #[must_use]
    fn has_authorization_material(&self) -> bool {
        !self.access_token.is_empty() && !self.token_type.is_empty()
    }

    /// Get time until expiration.
    #[must_use]
    pub fn time_until_expiry(&self) -> Option<Duration> {
        self.expires_at.and_then(|exp| {
            let now = Utc::now();
            if exp > now {
                (exp - now).to_std().ok()
            } else {
                None
            }
        })
    }

    /// Get the authorization header value.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthError::EmptyTokenField`] when the stored token
    /// is missing `access_token` or `token_type` material.
    pub fn authorization_header(&self) -> OAuthResult<String> {
        if self.access_token.is_empty() {
            return Err(OAuthError::EmptyTokenField("access_token"));
        }
        if self.token_type.is_empty() {
            return Err(OAuthError::EmptyTokenField("token_type"));
        }

        Ok(format!("{} {}", self.token_type, self.access_token))
    }

    /// Update tokens from a refresh response.
    ///
    /// Validation is response-level and atomic: if the response has an
    /// empty `access_token` or `token_type`, the function returns
    /// `Err` without mutating any field on `self`.  This prevents a
    /// malformed refresh response from extending `expires_at` and
    /// `issued_at` while leaving the stale `access_token` in place,
    /// which would otherwise produce a Frankenstein state where
    /// `is_expired()` returns `false` for a token that no longer
    /// authenticates against the provider.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthError::EmptyTokenField`] when the refresh
    /// response carries an empty `access_token` or an empty `token_type`.
    /// Returns [`OAuthError::InvalidTokenResponse`] when the refresh response
    /// tries to widen the previously granted scope set.
    pub fn update_from_response(&mut self, response: TokenResponse) -> OAuthResult<()> {
        // Validate response-level invariants before any mutation so the
        // update is atomic.  An empty access_token with a fresh expires_in
        // would otherwise bump self.expires_at forward while leaving
        // self.access_token stale — see the Frankenstein hazard in the
        // doc comment above.
        if response.access_token.is_empty() {
            return Err(OAuthError::EmptyTokenField("access_token"));
        }
        if response.token_type.is_empty() {
            return Err(OAuthError::EmptyTokenField("token_type"));
        }

        let now = Utc::now();
        let refreshed_scopes = match response.scope.as_deref() {
            Some(scope) => {
                let parsed = parse_scope_list(scope);
                if !refreshed_scopes_are_subset(&self.scopes, &parsed) {
                    return Err(OAuthError::InvalidTokenResponse(
                        "refresh response expanded granted scopes".into(),
                    ));
                }
                Some(parsed)
            }
            None => None,
        };

        self.access_token = response.access_token;
        self.token_type = response.token_type;
        // Only update expires_at if the response provides expires_in.
        // Some providers omit expires_in on refresh responses; unconditionally
        // setting expires_at = None would silently clear the previous expiry,
        // making the token appear never-expiring and permanently stopping the
        // refresh loop.
        if let Some(secs) = response.expires_in {
            self.expires_at = Some(
                now + chrono::Duration::seconds(
                    i64::try_from(secs.min(u64::from(u32::MAX))).unwrap_or(i64::MAX),
                ),
            );
        }
        self.issued_at = now;

        // Only update refresh token if a new non-empty one is provided.
        // A malicious/compromised OAuth server could return refresh_token: ""
        // which would otherwise overwrite the valid refresh token with an
        // unusable empty string, permanently breaking the refresh loop.
        if let Some(rt) = response.refresh_token.filter(|rt| !rt.is_empty()) {
            self.refresh_token = Some(rt);
        }

        // Update scopes if provided
        if let Some(scopes) = refreshed_scopes {
            self.scopes = scopes;
        }

        // Update ID token if provided (same empty-string guard as refresh token).
        if let Some(id) = response.id_token.filter(|id| !id.is_empty()) {
            self.id_token = Some(id);
        }

        Ok(())
    }
}

/// In-memory token storage with automatic cleanup.
#[derive(Debug, Clone)]
pub struct TokenStore {
    tokens: Arc<RwLock<HashMap<String, StoredToken>>>,
    refresh_gates: Arc<Mutex<HashMap<String, Arc<RefreshGate>>>>,
    /// Time of last cleanup.
    last_cleanup: Arc<RwLock<Instant>>,
    /// Cleanup interval.
    cleanup_interval: Duration,
}

#[derive(Debug)]
struct StoredToken {
    tokens: OAuthTokens,
    /// Optional metadata for the stored token.
    metadata: HashMap<String, String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RefreshGateSnapshot {
    refresh_generation: u64,
    completed_generation: u64,
}

#[derive(Debug)]
struct RefreshGate {
    state: Mutex<RefreshGateState>,
}

#[derive(Debug)]
struct RefreshGateState {
    refreshing: bool,
    refresh_generation: u64,
    completed_generation: u64,
    sender: watch::Sender<RefreshGateSnapshot>,
    _keepalive: watch::Receiver<RefreshGateSnapshot>,
}

#[derive(Debug)]
struct RefreshGateWaiter {
    target_generation: u64,
    receiver: watch::Receiver<RefreshGateSnapshot>,
}

#[derive(Debug)]
struct RefreshGateLease {
    gate: Arc<RefreshGate>,
}

impl Default for RefreshGate {
    fn default() -> Self {
        let snapshot = RefreshGateSnapshot {
            refresh_generation: 0,
            completed_generation: 0,
        };
        let (sender, keepalive) = watch::channel(snapshot);
        Self {
            state: Mutex::new(RefreshGateState {
                refreshing: false,
                refresh_generation: 0,
                completed_generation: 0,
                sender,
                _keepalive: keepalive,
            }),
        }
    }
}

impl RefreshGateState {
    const fn snapshot(&self) -> RefreshGateSnapshot {
        RefreshGateSnapshot {
            refresh_generation: self.refresh_generation,
            completed_generation: self.completed_generation,
        }
    }

    fn publish(&self) {
        let _ = self.sender.send(self.snapshot());
    }
}

impl RefreshGateWaiter {
    async fn wait_until_refresh_completes(mut self) {
        loop {
            let snapshot = *self.receiver.borrow_and_update();
            if snapshot.completed_generation >= self.target_generation {
                return;
            }
            if self.receiver.changed().await.is_err() {
                return;
            }
        }
    }
}

impl RefreshGateLease {
    fn claim_or_subscribe(gate: &Arc<RefreshGate>) -> Result<Self, RefreshGateWaiter> {
        let mut state = gate.state.lock();
        if state.refreshing {
            return Err(RefreshGateWaiter {
                target_generation: state.refresh_generation,
                receiver: state.sender.subscribe(),
            });
        }

        state.refreshing = true;
        state.refresh_generation = state.refresh_generation.saturating_add(1);
        state.publish();
        drop(state);
        Ok(Self {
            gate: Arc::clone(gate),
        })
    }

    #[cfg(test)]
    fn try_acquire(gate: &Arc<RefreshGate>) -> Option<Self> {
        Self::claim_or_subscribe(gate).ok()
    }
}

impl RefreshGate {
    #[cfg(test)]
    fn is_refreshing(&self) -> bool {
        self.state.lock().refreshing
    }
}

impl Drop for RefreshGateLease {
    fn drop(&mut self) {
        let mut state = self.gate.state.lock();
        state.refreshing = false;
        state.completed_generation = state.refresh_generation;
        state.publish();
    }
}

impl Default for TokenStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenStore {
    /// Create a new token store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tokens: Arc::new(RwLock::new(HashMap::new())),
            refresh_gates: Arc::new(Mutex::new(HashMap::new())),
            last_cleanup: Arc::new(RwLock::new(Instant::now())),
            cleanup_interval: Duration::from_secs(60), // Cleanup every minute
        }
    }

    /// Create with custom cleanup interval.
    #[must_use]
    pub const fn with_cleanup_interval(mut self, interval: Duration) -> Self {
        self.cleanup_interval = interval;
        self
    }

    /// Store tokens with a key.
    pub fn store(&self, key: &str, tokens: OAuthTokens) {
        self.maybe_cleanup();
        let mut store = self.tokens.write();
        store.insert(
            key.to_string(),
            StoredToken {
                tokens,
                metadata: HashMap::new(),
            },
        );
    }

    /// Store tokens with metadata.
    pub fn store_with_metadata(
        &self,
        key: &str,
        tokens: OAuthTokens,
        metadata: HashMap<String, String>,
    ) {
        self.maybe_cleanup();
        let mut store = self.tokens.write();
        store.insert(key.to_string(), StoredToken { tokens, metadata });
    }

    /// Get tokens by key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<OAuthTokens> {
        let store = self.tokens.read();
        store.get(key).map(|s| s.tokens.clone())
    }

    /// Get tokens with metadata.
    #[must_use]
    pub fn get_with_metadata(&self, key: &str) -> Option<(OAuthTokens, HashMap<String, String>)> {
        let store = self.tokens.read();
        store
            .get(key)
            .map(|s| (s.tokens.clone(), s.metadata.clone()))
    }

    /// Check if tokens exist and are valid.
    ///
    /// "Valid" here means usable for a request without entering the proactive
    /// refresh window. A token that is within [`DEFAULT_REFRESH_THRESHOLD`] of
    /// expiry is treated as not valid so callers do not race the provider with
    /// an access token that may expire in-flight.
    #[must_use]
    pub fn has_valid_token(&self, key: &str) -> bool {
        self.get(key)
            .is_some_and(|t| t.has_authorization_material() && !t.needs_refresh())
    }

    /// Remove tokens by key.
    #[must_use]
    pub fn remove(&self, key: &str) -> Option<OAuthTokens> {
        let removed = {
            let mut store = self.tokens.write();
            store.remove(key).map(|s| s.tokens)
        };
        if removed.is_some() {
            self.refresh_gates.lock().remove(key);
        }
        removed
    }

    /// Update tokens (used after refresh).
    ///
    /// # Errors
    /// Returns [`OAuthError::TokenNotFound`] when no tokens are stored for `key`.
    pub fn update(&self, key: &str, tokens: OAuthTokens) -> OAuthResult<()> {
        let mut store = self.tokens.write();
        if let Some(stored) = store.get_mut(key) {
            stored.tokens = tokens;
            Ok(())
        } else {
            Err(OAuthError::TokenNotFound(key.to_string()))
        }
    }

    /// Update stored tokens only if the refresh token still matches the
    /// snapshot that triggered the refresh request.
    ///
    /// Returns `Ok(true)` when the update was applied. Returns `Ok(false)` when
    /// another refresh already rotated the stored refresh token, which means
    /// this response is stale and must not overwrite the newer credential set.
    ///
    /// # Errors
    /// Returns [`OAuthError::TokenNotFound`] when no tokens are stored for `key`.
    pub fn update_after_refresh(
        &self,
        key: &str,
        expected_refresh_token: Option<&str>,
        tokens: OAuthTokens,
    ) -> OAuthResult<bool> {
        let mut store = self.tokens.write();
        if let Some(stored) = store.get_mut(key) {
            if stored.tokens.refresh_token() != expected_refresh_token {
                return Ok(false);
            }

            // `tokens` was built by `OAuthTokens::from_response`, which
            // collapses an omitted `expires_in` to `None` and an omitted
            // `scope` to `[]`. A blind assignment would therefore
            // (a) clobber the previous expiry to never-expiring — silently
            //     stopping the refresh loop — when the provider omits
            //     `expires_in` on refresh, and
            // (b) drop the granted scope AND defeat the scope-narrowing
            //     guard below on the next refresh.
            // Preserve those fields when the refresh response omitted them,
            // and reject a refresh that WIDENS granted scopes (a compromised
            // token endpoint returning e.g. `read` -> `read write admin`).
            // This mirrors `OAuthTokens::update_from_response`, which the
            // `get_or_refresh` path does not route through.
            let mut tokens = tokens;
            if tokens.expires_at.is_none() {
                tokens.expires_at = stored.tokens.expires_at;
            }
            if tokens.scopes.is_empty() {
                tokens.scopes.clone_from(&stored.tokens.scopes);
            } else if !refreshed_scopes_are_subset(&stored.tokens.scopes, &tokens.scopes) {
                return Err(OAuthError::InvalidTokenResponse(
                    "refresh response expanded granted scopes".into(),
                ));
            }

            stored.tokens = tokens;
            Ok(true)
        } else {
            Err(OAuthError::TokenNotFound(key.to_string()))
        }
    }

    /// Return tokens that are safe to use for a request, refreshing them first
    /// when they are inside the proactive refresh window.
    ///
    /// Refreshes are single-flight per key: concurrent callers wait for the
    /// in-progress refresh instead of issuing parallel refresh requests with the
    /// same refresh token.
    ///
    /// # Errors
    /// Returns [`OAuthError::TokenNotFound`] when `key` is unknown,
    /// [`OAuthError::NoRefreshToken`] when an expired token must be refreshed
    /// but no refresh token is available,
    /// or [`OAuthError::RefreshFailed`] when the provider refresh request fails.
    pub async fn get_or_refresh(
        &self,
        key: &str,
        client: &OAuth2Client,
    ) -> OAuthResult<OAuthTokens> {
        loop {
            let snapshot = self
                .get(key)
                .ok_or_else(|| OAuthError::TokenNotFound(key.to_string()))?;
            if snapshot.has_authorization_material() && !snapshot.needs_refresh() {
                return Ok(snapshot);
            }
            if snapshot.has_authorization_material()
                && snapshot.refresh_token().is_none()
                && !snapshot.is_expired()
            {
                return Ok(snapshot);
            }

            if !snapshot.has_authorization_material() && snapshot.refresh_token().is_none() {
                return Err(OAuthError::InvalidTokenResponse(
                    "stored token is missing access_token or token_type".into(),
                ));
            }

            let refresh_token = snapshot
                .refresh_token()
                .ok_or(OAuthError::NoRefreshToken)?
                .to_string();
            let expected_refresh_token = snapshot.refresh_token().map(str::to_string);
            let gate = self.refresh_gate(key);

            let refresh_lease = match RefreshGateLease::claim_or_subscribe(&gate) {
                Ok(refresh_lease) => refresh_lease,
                Err(waiter) => {
                    waiter.wait_until_refresh_completes().await;
                    continue;
                }
            };

            let refresh_outcome = match client.refresh_tokens(&refresh_token).await {
                Ok(tokens) => match self.update_after_refresh(
                    key,
                    expected_refresh_token.as_deref(),
                    tokens.clone(),
                ) {
                    Ok(true) => Ok(Some(tokens)),
                    Ok(false) => Ok(None),
                    Err(error) => Err(error),
                },
                Err(error) => {
                    if self.get(key).is_some_and(|current| {
                        !current.needs_refresh()
                            || current.refresh_token() != expected_refresh_token.as_deref()
                    }) {
                        Ok(None)
                    } else {
                        Err(OAuthError::RefreshFailed(error.to_string()))
                    }
                }
            };
            drop(refresh_lease);

            if let Some(tokens) = refresh_outcome? {
                return Ok(tokens);
            }
        }
    }

    /// Get all stored keys.
    #[must_use]
    pub fn keys(&self) -> Vec<String> {
        self.tokens.read().keys().cloned().collect()
    }

    /// Clear all tokens.
    pub fn clear(&self) {
        self.tokens.write().clear();
        self.refresh_gates.lock().clear();
    }

    /// Cleanup expired tokens that cannot be refreshed.
    fn maybe_cleanup(&self) {
        let should_cleanup = {
            let last = self.last_cleanup.read();
            last.elapsed() >= self.cleanup_interval
        };

        if should_cleanup {
            // Re-check under write lock to prevent duplicate cleanups from
            // concurrent callers that both passed the read-lock check above.
            let mut last = self.last_cleanup.write();
            if last.elapsed() >= self.cleanup_interval {
                let mut expired_keys = Vec::new();
                self.tokens.write().retain(|key, value| {
                    let keep = !value.tokens.is_expired() || value.tokens.refresh_token().is_some();
                    if !keep {
                        expired_keys.push(key.clone());
                    }
                    keep
                });
                if !expired_keys.is_empty() {
                    let mut gates = self.refresh_gates.lock();
                    for key in expired_keys {
                        gates.remove(&key);
                    }
                }
                *last = Instant::now();
            }
        }
    }

    fn refresh_gate(&self, key: &str) -> Arc<RefreshGate> {
        let mut gates = self.refresh_gates.lock();
        Arc::clone(
            gates
                .entry(key.to_string())
                .or_insert_with(|| Arc::new(RefreshGate::default())),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_token_response(expires_in: Option<u64>) -> TokenResponse {
        TokenResponse {
            access_token: "test_access_token".to_string(),
            token_type: "Bearer".to_string(),
            expires_in,
            refresh_token: Some("test_refresh_token".to_string()),
            scope: Some("read write".to_string()),
            id_token: None,
        }
    }

    fn valid_tokens(response: TokenResponse) -> OAuthTokens {
        OAuthTokens::from_response(response).expect("valid token fixture must construct")
    }

    #[test]
    fn test_token_response_validate_rejects_empty_access_token() {
        let response = TokenResponse {
            access_token: String::new(),
            token_type: "Bearer".into(),
            expires_in: Some(3600),
            refresh_token: Some("test_refresh_token".into()),
            scope: None,
            id_token: None,
        };

        let err = response.validate().unwrap_err();
        assert!(matches!(err, OAuthError::EmptyTokenField("access_token")));
    }

    #[test]
    fn test_token_response_validate_rejects_empty_token_type() {
        let response = TokenResponse {
            access_token: "test_access_token".into(),
            token_type: String::new(),
            expires_in: Some(3600),
            refresh_token: Some("test_refresh_token".into()),
            scope: None,
            id_token: None,
        };

        let err = response.validate().unwrap_err();
        assert!(matches!(err, OAuthError::EmptyTokenField("token_type")));
    }

    #[test]
    fn test_token_from_response() {
        let response = mock_token_response(Some(3600));
        let tokens = valid_tokens(response);

        assert_eq!(tokens.access_token(), "test_access_token");
        assert_eq!(tokens.token_type(), "Bearer");
        assert_eq!(tokens.refresh_token(), Some("test_refresh_token"));
        assert_eq!(tokens.scopes(), &["read", "write"]);
        assert!(!tokens.is_expired());
    }

    #[test]
    fn test_from_response_rejects_empty_refresh_token() {
        // A malicious/compromised OAuth server returning refresh_token: ""
        // must not produce a stored Some("") refresh token — the empty string
        // would be useless on the wire and make is_refresh_valid() semantics
        // ambiguous.
        let response = TokenResponse {
            access_token: "at".into(),
            token_type: "Bearer".into(),
            expires_in: Some(3600),
            refresh_token: Some(String::new()),
            scope: None,
            id_token: Some(String::new()),
        };
        let tokens = valid_tokens(response);
        assert_eq!(tokens.refresh_token(), None);
        assert_eq!(tokens.id_token(), None);
    }

    #[test]
    fn test_update_from_response_rejects_empty_refresh_token() {
        // Starting from valid tokens, a refresh response returning
        // refresh_token: "" must NOT overwrite the existing refresh token.
        // Without this guard, a compromised OAuth server could permanently
        // break the client's refresh loop by returning an empty refresh token.
        let initial = mock_token_response(Some(3600));
        let mut tokens = valid_tokens(initial);
        assert_eq!(tokens.refresh_token(), Some("test_refresh_token"));

        let refresh_response = TokenResponse {
            access_token: "new_at".into(),
            token_type: "Bearer".into(),
            expires_in: Some(3600),
            refresh_token: Some(String::new()),
            scope: None,
            id_token: Some(String::new()),
        };
        tokens
            .update_from_response(refresh_response)
            .expect("non-empty access_token and token_type must succeed");

        assert_eq!(tokens.access_token(), "new_at");
        assert_eq!(
            tokens.refresh_token(),
            Some("test_refresh_token"),
            "empty refresh_token must not overwrite existing refresh token"
        );
        assert_eq!(tokens.id_token(), None);
    }

    #[test]
    fn test_update_from_response_preserves_expiry_when_omitted() {
        // Some OAuth providers omit expires_in on refresh responses.
        // The existing expiry must be preserved, not silently cleared to None
        // (which would make the token appear never-expiring).
        let initial = mock_token_response(Some(3600));
        let mut tokens = valid_tokens(initial);
        assert!(tokens.expires_at.is_some(), "initial expiry must be set");

        let refresh_response = TokenResponse {
            access_token: "refreshed_at".into(),
            token_type: "Bearer".into(),
            expires_in: None, // Provider omits expires_in
            refresh_token: Some("new_rt".into()),
            scope: None,
            id_token: None,
        };
        tokens
            .update_from_response(refresh_response)
            .expect("non-empty access_token and token_type must succeed");

        assert_eq!(tokens.access_token(), "refreshed_at");
        assert!(
            tokens.expires_at.is_some(),
            "expires_at must be preserved when refresh response omits expires_in"
        );
    }

    #[test]
    fn test_update_from_response_rejects_empty_access_token_without_mutating() {
        // An OAuth server returning access_token: "" with a valid expires_in
        // must NOT produce a Frankenstein token where the stale access_token
        // inherits a freshly-bumped expires_at.  Before the fix, the empty
        // access_token was silently skipped while expires_at and issued_at
        // were advanced, hiding token staleness from is_expired() and
        // needs_refresh() for up to the full expiry window.
        let initial = mock_token_response(Some(3600));
        let mut tokens = valid_tokens(initial);
        let original_access = tokens.access_token().to_string();
        let original_expires_at = tokens.expires_at;
        let original_issued_at = tokens.issued_at;
        let original_refresh = tokens.refresh_token().map(str::to_string);

        let malformed = TokenResponse {
            access_token: String::new(), // empty — must reject response-level
            token_type: "Bearer".into(),
            expires_in: Some(7200), // would otherwise bump expiry 2h forward
            refresh_token: Some("shouldnt_overwrite".into()),
            scope: Some("newscope".into()),
            id_token: None,
        };

        let result = tokens.update_from_response(malformed);

        assert!(
            matches!(result, Err(OAuthError::EmptyTokenField("access_token"))),
            "empty access_token must be rejected with EmptyTokenField(access_token), got {result:?}"
        );
        assert_eq!(
            tokens.access_token(),
            original_access,
            "access_token untouched"
        );
        assert_eq!(
            tokens.expires_at, original_expires_at,
            "expires_at untouched"
        );
        assert_eq!(tokens.issued_at, original_issued_at, "issued_at untouched");
        assert_eq!(
            tokens.refresh_token().map(str::to_string),
            original_refresh,
            "refresh_token untouched"
        );
    }

    #[test]
    fn test_update_from_response_rejects_empty_token_type_without_mutating() {
        // Symmetric guard: an empty token_type would produce a malformed
        // Authorization header.  The whole response must be rejected
        // atomically — no field on self changes.
        let mut tokens = valid_tokens(mock_token_response(Some(3600)));
        let original_token_type = tokens.token_type().to_string();
        let original_expires_at = tokens.expires_at;

        let malformed = TokenResponse {
            access_token: "nonempty_at".into(),
            token_type: String::new(), // empty — reject
            expires_in: Some(7200),
            refresh_token: None,
            scope: None,
            id_token: None,
        };

        let result = tokens.update_from_response(malformed);

        assert!(
            matches!(result, Err(OAuthError::EmptyTokenField("token_type"))),
            "empty token_type must be rejected, got {result:?}"
        );
        assert_eq!(tokens.token_type(), original_token_type);
        assert_eq!(tokens.expires_at, original_expires_at);
    }

    #[test]
    fn metamorphic_repeated_identical_refresh_is_observationally_idempotent() {
        let mut tokens = valid_tokens(mock_token_response(Some(3600)));
        let refresh_response = TokenResponse {
            access_token: "steady_access".into(),
            token_type: "Bearer".into(),
            expires_in: None,
            refresh_token: Some("steady_refresh".into()),
            scope: Some("read write".into()),
            id_token: Some("steady_id".into()),
        };

        tokens
            .update_from_response(refresh_response.clone())
            .expect("first refresh must succeed");
        let after_first = (
            tokens.access_token().to_string(),
            tokens.token_type().to_string(),
            tokens.refresh_token().map(str::to_string),
            tokens.scopes().to_vec(),
            tokens.id_token().map(str::to_string),
            tokens.expires_at,
        );

        tokens
            .update_from_response(refresh_response)
            .expect("second identical refresh must succeed");
        let after_second = (
            tokens.access_token().to_string(),
            tokens.token_type().to_string(),
            tokens.refresh_token().map(str::to_string),
            tokens.scopes().to_vec(),
            tokens.id_token().map(str::to_string),
            tokens.expires_at,
        );

        assert_eq!(after_second, after_first);
    }

    #[test]
    fn metamorphic_refresh_use_refresh_keeps_observable_auth_state_stable() {
        let mut tokens = valid_tokens(mock_token_response(Some(3600)));
        let refresh_response = TokenResponse {
            access_token: "steady_access".into(),
            token_type: "Bearer".into(),
            expires_in: Some(3600),
            refresh_token: Some("steady_refresh".into()),
            scope: Some("read write".into()),
            id_token: Some("steady_id".into()),
        };

        tokens
            .update_from_response(refresh_response.clone())
            .expect("first refresh must succeed");
        let observed_after_first = (
            tokens
                .authorization_header()
                .expect("steady token must format an authorization header"),
            tokens.scopes().to_vec(),
            tokens.id_token().map(str::to_string),
            tokens.needs_refresh(),
        );

        // "Use" the token through the same observable surface callers rely on.
        assert_eq!(
            tokens
                .authorization_header()
                .expect("steady token must format an authorization header"),
            "Bearer steady_access"
        );

        tokens
            .update_from_response(refresh_response)
            .expect("second identical refresh must succeed");
        let observed_after_second = (
            tokens
                .authorization_header()
                .expect("steady token must format an authorization header"),
            tokens.scopes().to_vec(),
            tokens.id_token().map(str::to_string),
            tokens.needs_refresh(),
        );

        assert_eq!(observed_after_second, observed_after_first);
    }

    #[test]
    fn test_expired_token_cannot_be_revived_by_empty_replacement() {
        // The canonical failure mode the fix closes: a token that has
        // already expired must stay expired when the refresh response is
        // malformed (empty access_token).  Before the fix, the stale
        // (expired) access_token would inherit a fresh expires_at from
        // the malformed response, and is_expired() would flip to false —
        // silently masking an expired credential as valid.
        let expired_resp = TokenResponse {
            access_token: "stale_at".into(),
            token_type: "Bearer".into(),
            expires_in: Some(0), // expire immediately
            refresh_token: Some("rt".into()),
            scope: None,
            id_token: None,
        };
        let mut tokens = valid_tokens(expired_resp);
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(tokens.is_expired(), "precondition: token must be expired");

        let malformed_refresh = TokenResponse {
            access_token: String::new(), // attempt to revive with bad response
            token_type: "Bearer".into(),
            expires_in: Some(3600), // would hide staleness for 1h
            refresh_token: None,
            scope: None,
            id_token: None,
        };

        let result = tokens.update_from_response(malformed_refresh);

        assert!(
            matches!(result, Err(OAuthError::EmptyTokenField("access_token"))),
            "expired token must not be revived by empty replacement, got {result:?}"
        );
        assert!(
            tokens.is_expired(),
            "is_expired() must still report expired after rejected refresh"
        );
        assert_eq!(tokens.access_token(), "stale_at");
    }

    #[test]
    fn test_token_expiration() {
        // Token that expires immediately
        let response = TokenResponse {
            access_token: "test".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: Some(0),
            refresh_token: None,
            scope: None,
            id_token: None,
        };
        let tokens = valid_tokens(response);
        assert!(tokens.is_expired());
    }

    #[test]
    fn test_token_needs_refresh() {
        // Token that expires in 2 minutes (below default 5 minute threshold)
        let response = mock_token_response(Some(120));
        let tokens = valid_tokens(response);
        assert!(tokens.needs_refresh());

        // Token that expires in 10 minutes (above threshold)
        let response = mock_token_response(Some(600));
        let tokens = valid_tokens(response);
        assert!(!tokens.needs_refresh());
    }

    #[test]
    fn test_authorization_header() {
        let response = mock_token_response(Some(3600));
        let tokens = valid_tokens(response);
        assert_eq!(
            tokens
                .authorization_header()
                .expect("token must format an authorization header"),
            "Bearer test_access_token"
        );
    }

    #[test]
    fn test_token_store() {
        let store = TokenStore::new();
        let tokens = valid_tokens(mock_token_response(Some(3600)));

        // Store and retrieve
        store.store("user1", tokens.clone());
        assert!(store.has_valid_token("user1"));

        let retrieved = store.get("user1").unwrap();
        assert_eq!(retrieved.access_token(), tokens.access_token());

        // Remove
        let _ = store.remove("user1");
        assert!(!store.has_valid_token("user1"));
    }

    // ── New tests ──

    #[test]
    fn test_token_response_serde_roundtrip() {
        let resp = mock_token_response(Some(3600));
        let json = serde_json::to_string(&resp).unwrap();
        let roundtrip: TokenResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.access_token, "test_access_token");
        assert_eq!(roundtrip.token_type, "Bearer");
        assert_eq!(roundtrip.expires_in, Some(3600));
        assert_eq!(
            roundtrip.refresh_token,
            Some("test_refresh_token".to_string())
        );
    }

    #[test]
    fn test_token_no_expiry_is_not_expired() {
        let tokens = valid_tokens(mock_token_response(None));
        assert!(!tokens.is_expired());
    }

    #[test]
    fn test_token_no_expiry_does_not_need_refresh() {
        let tokens = valid_tokens(mock_token_response(None));
        assert!(!tokens.needs_refresh());
    }

    #[test]
    fn test_token_time_until_expiry() {
        // Non-expired token should return Some
        let tokens = valid_tokens(mock_token_response(Some(3600)));
        assert!(tokens.time_until_expiry().is_some());

        // No expiry → None
        let tokens = valid_tokens(mock_token_response(None));
        assert!(tokens.time_until_expiry().is_none());

        // Expired → None
        let tokens = valid_tokens(mock_token_response(Some(0)));
        assert!(tokens.time_until_expiry().is_none());
    }

    #[test]
    fn test_token_id_token() {
        let mut resp = mock_token_response(Some(3600));
        resp.id_token = Some("id_tok_abc".into());
        let tokens = valid_tokens(resp);
        assert_eq!(tokens.id_token(), Some("id_tok_abc"));
    }

    #[test]
    fn test_token_update_from_response() {
        let mut tokens = valid_tokens(TokenResponse {
            access_token: "test_access_token".into(),
            token_type: "Bearer".into(),
            expires_in: Some(3600),
            refresh_token: Some("test_refresh_token".into()),
            scope: Some("read write admin".into()),
            id_token: None,
        });

        let new_resp = TokenResponse {
            access_token: "new_access".into(),
            token_type: "Bearer".into(),
            expires_in: Some(7200),
            refresh_token: Some("new_refresh".into()),
            scope: Some("read write".into()),
            id_token: Some("new_id".into()),
        };

        tokens
            .update_from_response(new_resp)
            .expect("non-empty access_token and token_type must succeed");
        assert_eq!(tokens.access_token(), "new_access");
        assert_eq!(tokens.refresh_token(), Some("new_refresh"));
        assert_eq!(tokens.scopes(), &["read", "write"]);
        assert_eq!(tokens.id_token(), Some("new_id"));
    }

    #[test]
    fn test_token_update_rejects_scope_expansion_atomically() {
        let mut tokens = valid_tokens(mock_token_response(Some(3600)));
        let original_access_token = tokens.access_token().to_string();
        let original_refresh_token = tokens.refresh_token().map(ToOwned::to_owned);
        let original_scopes = tokens.scopes().to_vec();
        let original_id_token = tokens.id_token().map(ToOwned::to_owned);
        let original_expiry = tokens.expires_at;
        let original_issued_at = tokens.issued_at;

        let err = tokens
            .update_from_response(TokenResponse {
                access_token: "new_access".into(),
                token_type: "Bearer".into(),
                expires_in: Some(7200),
                refresh_token: Some("rotated_refresh".into()),
                scope: Some("read write admin".into()),
                id_token: Some("new_id".into()),
            })
            .unwrap_err();

        assert!(matches!(err, OAuthError::InvalidTokenResponse(_)));
        assert_eq!(tokens.access_token(), original_access_token);
        assert_eq!(tokens.refresh_token(), original_refresh_token.as_deref());
        assert_eq!(tokens.scopes(), original_scopes.as_slice());
        assert_eq!(tokens.id_token(), original_id_token.as_deref());
        assert_eq!(tokens.expires_at, original_expiry);
        assert_eq!(tokens.issued_at, original_issued_at);
    }

    #[test]
    fn test_token_update_preserves_refresh_if_not_provided() {
        let mut tokens = valid_tokens(mock_token_response(Some(3600)));
        assert_eq!(tokens.refresh_token(), Some("test_refresh_token"));

        let new_resp = TokenResponse {
            access_token: "new_access".into(),
            token_type: "Bearer".into(),
            expires_in: Some(3600),
            refresh_token: None,
            scope: None,
            id_token: None,
        };

        tokens
            .update_from_response(new_resp)
            .expect("non-empty access_token and token_type must succeed");
        assert_eq!(tokens.access_token(), "new_access");
        // Original refresh token should be preserved
        assert_eq!(tokens.refresh_token(), Some("test_refresh_token"));
    }

    #[test]
    fn test_token_store_keys() {
        let store = TokenStore::new();
        store.store("user1", valid_tokens(mock_token_response(Some(3600))));
        store.store("user2", valid_tokens(mock_token_response(Some(3600))));

        let keys = store.keys();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&"user1".to_string()));
        assert!(keys.contains(&"user2".to_string()));
    }

    #[test]
    fn test_token_store_clear() {
        let store = TokenStore::new();
        store.store("user1", valid_tokens(mock_token_response(Some(3600))));
        store.clear();
        assert!(store.keys().is_empty());
    }

    #[test]
    fn test_token_store_update_nonexistent() {
        let store = TokenStore::new();
        let tokens = valid_tokens(mock_token_response(Some(3600)));
        let result = store.update("missing", tokens);
        assert!(matches!(result, Err(OAuthError::TokenNotFound(_))));
    }

    #[test]
    fn test_token_store_with_metadata() {
        let store = TokenStore::new();
        let tokens = valid_tokens(mock_token_response(Some(3600)));
        let mut metadata = HashMap::new();
        metadata.insert("provider".to_string(), "github".to_string());

        store.store_with_metadata("user1", tokens, metadata);

        let (_, meta) = store.get_with_metadata("user1").unwrap();
        assert_eq!(meta.get("provider"), Some(&"github".to_string()));
    }

    #[test]
    fn test_token_store_default() {
        let store = TokenStore::default();
        assert!(store.keys().is_empty());
    }

    // ── Batch: token response deserialization edge cases ──

    #[test]
    fn test_token_response_minimal_json() {
        // Only required fields
        let json = r#"{"access_token":"tok","token_type":"Bearer"}"#;
        let resp: TokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.access_token, "tok");
        assert_eq!(resp.token_type, "Bearer");
        assert!(resp.expires_in.is_none());
        assert!(resp.refresh_token.is_none());
        assert!(resp.scope.is_none());
        assert!(resp.id_token.is_none());
    }

    #[test]
    fn test_token_response_with_all_fields() {
        let json = r#"{
            "access_token": "at",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "rt",
            "scope": "openid email",
            "id_token": "eyJhbGciOiJSUzI1NiJ9.e30.sig"
        }"#;
        let resp: TokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.expires_in, Some(3600));
        assert_eq!(resp.refresh_token, Some("rt".into()));
        assert_eq!(resp.scope, Some("openid email".into()));
        assert!(resp.id_token.is_some());
    }

    #[test]
    fn test_token_response_clone() {
        let resp = mock_token_response(Some(3600));
        let cloned = resp.clone();
        assert_eq!(resp.access_token, cloned.access_token);
        assert_eq!(resp.expires_in, cloned.expires_in);
    }

    // ── Batch: OAuthTokens edge cases ──

    #[test]
    fn test_token_no_scopes() {
        let resp = TokenResponse {
            access_token: "tok".into(),
            token_type: "Bearer".into(),
            expires_in: None,
            refresh_token: None,
            scope: None,
            id_token: None,
        };
        let tokens = valid_tokens(resp);
        assert!(tokens.scopes().is_empty());
    }

    #[test]
    fn test_token_single_scope() {
        let resp = TokenResponse {
            access_token: "tok".into(),
            token_type: "Bearer".into(),
            expires_in: None,
            refresh_token: None,
            scope: Some("read".into()),
            id_token: None,
        };
        let tokens = valid_tokens(resp);
        assert_eq!(tokens.scopes(), &["read"]);
    }

    #[test]
    fn test_token_needs_refresh_within_custom_threshold() {
        // Token expires in 30 seconds
        let tokens = valid_tokens(mock_token_response(Some(30)));
        // With 60-second threshold → needs refresh
        assert!(tokens.needs_refresh_within(Duration::from_secs(60)));
        // With 10-second threshold → does not need refresh
        assert!(!tokens.needs_refresh_within(Duration::from_secs(10)));
    }

    #[test]
    fn test_token_clone() {
        let tokens = valid_tokens(mock_token_response(Some(3600)));
        let cloned = tokens.clone();
        assert_eq!(tokens.access_token(), cloned.access_token());
        assert_eq!(tokens.token_type(), cloned.token_type());
        assert_eq!(tokens.refresh_token(), cloned.refresh_token());
        assert_eq!(tokens.scopes(), cloned.scopes());
    }

    #[test]
    fn test_token_serialize() {
        let tokens = valid_tokens(mock_token_response(Some(3600)));
        let json = serde_json::to_string(&tokens).unwrap();
        assert!(json.contains("test_access_token"));
        assert!(json.contains("Bearer"));
    }

    #[test]
    fn test_token_debug_contains_type() {
        let tokens = valid_tokens(mock_token_response(Some(3600)));
        let debug = format!("{tokens:?}");
        assert!(debug.contains("OAuthTokens"));
    }

    // ── Security regression: Debug redaction (1fcd949) ──

    #[test]
    fn test_token_debug_redacts_access_token() {
        let tokens = valid_tokens(mock_token_response(Some(3600)));
        let debug = format!("{tokens:?}");
        // The actual token value must NOT appear in debug output
        assert!(
            !debug.contains("test_access_token"),
            "access_token leaked in Debug output"
        );
        // Instead, [REDACTED] should appear
        assert!(
            debug.contains("[REDACTED]"),
            "Debug output missing [REDACTED] placeholder"
        );
    }

    #[test]
    fn test_token_debug_redacts_refresh_token() {
        let tokens = valid_tokens(mock_token_response(Some(3600)));
        let debug = format!("{tokens:?}");
        assert!(
            !debug.contains("test_refresh_token"),
            "refresh_token leaked in Debug output"
        );
    }

    #[test]
    fn test_token_debug_redacts_id_token() {
        let mut resp = mock_token_response(Some(3600));
        resp.id_token = Some("super_secret_id_token_jwt".into());
        let tokens = valid_tokens(resp);
        let debug = format!("{tokens:?}");
        assert!(
            !debug.contains("super_secret_id_token_jwt"),
            "id_token leaked in Debug output"
        );
    }

    #[test]
    fn test_token_debug_preserves_non_sensitive_fields() {
        let tokens = valid_tokens(mock_token_response(Some(3600)));
        let debug = format!("{tokens:?}");
        // Non-sensitive fields should still be visible
        assert!(
            debug.contains("Bearer"),
            "token_type should be visible in Debug"
        );
        assert!(
            debug.contains("scopes"),
            "scopes field should be visible in Debug"
        );
        assert!(
            debug.contains("issued_at"),
            "issued_at field should be visible in Debug"
        );
    }

    // ── Batch: TokenStore advanced ──

    #[test]
    fn test_token_store_overwrite() {
        let store = TokenStore::new();
        let tokens1 = valid_tokens(mock_token_response(Some(3600)));
        store.store("key", tokens1);

        let new_resp = TokenResponse {
            access_token: "new_tok".into(),
            token_type: "Bearer".into(),
            expires_in: Some(7200),
            refresh_token: None,
            scope: None,
            id_token: None,
        };
        let tokens2 = valid_tokens(new_resp);
        store.store("key", tokens2);

        let retrieved = store.get("key").unwrap();
        assert_eq!(retrieved.access_token(), "new_tok");
    }

    #[test]
    fn test_token_store_update_existing() {
        let store = TokenStore::new();
        store.store("key", valid_tokens(mock_token_response(Some(3600))));

        let new_tokens = valid_tokens(TokenResponse {
            access_token: "updated".into(),
            token_type: "Bearer".into(),
            expires_in: Some(7200),
            refresh_token: None,
            scope: None,
            id_token: None,
        });

        assert!(store.update("key", new_tokens).is_ok());
        assert_eq!(store.get("key").unwrap().access_token(), "updated");
    }

    #[test]
    fn test_token_store_remove_nonexistent() {
        let store = TokenStore::new();
        assert!(store.remove("nonexistent").is_none());
    }

    #[test]
    fn test_token_store_get_nonexistent() {
        let store = TokenStore::new();
        assert!(store.get("missing").is_none());
    }

    #[test]
    fn test_token_store_get_with_metadata_nonexistent() {
        let store = TokenStore::new();
        assert!(store.get_with_metadata("missing").is_none());
    }

    #[test]
    fn test_token_store_has_valid_token_expired() {
        let store = TokenStore::new();
        store.store("expired", valid_tokens(mock_token_response(Some(0))));
        assert!(!store.has_valid_token("expired"));
    }

    #[test]
    fn test_token_store_has_valid_token_false_inside_refresh_window() {
        let store = TokenStore::new();
        store.store(
            "needs_refresh",
            valid_tokens(mock_token_response(Some(120))),
        );
        assert!(
            !store.has_valid_token("needs_refresh"),
            "tokens inside the proactive refresh window must not be treated as request-safe"
        );
    }

    #[test]
    fn test_token_store_has_valid_token_rejects_empty_access_token_material() {
        let store = TokenStore::new();
        let result = OAuthTokens::from_response(TokenResponse {
            access_token: String::new(),
            token_type: "Bearer".into(),
            expires_in: Some(3600),
            refresh_token: None,
            scope: None,
            id_token: None,
        });
        assert!(matches!(
            result,
            Err(OAuthError::EmptyTokenField("access_token"))
        ));
        assert!(!store.has_valid_token("invalid_material"));
    }

    #[test]
    fn test_token_store_has_valid_token_missing() {
        let store = TokenStore::new();
        assert!(!store.has_valid_token("missing"));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn test_token_store_clone() {
        let store = TokenStore::new();
        store.store("key", valid_tokens(mock_token_response(Some(3600))));
        let cloned = store.clone();
        assert!(cloned.has_valid_token("key"));
    }

    #[test]
    fn test_token_store_with_cleanup_interval() {
        let store = TokenStore::new().with_cleanup_interval(Duration::from_secs(120));
        // Should still work normally
        store.store("key", valid_tokens(mock_token_response(Some(3600))));
        assert!(store.has_valid_token("key"));
    }

    // ── Expanded tests: TokenResponse serde edge cases ──

    #[test]
    fn test_token_response_expires_in_zero() {
        let json = r#"{"access_token":"t","token_type":"Bearer","expires_in":0}"#;
        let resp: TokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.expires_in, Some(0));
    }

    #[test]
    fn test_token_response_expires_in_very_large() {
        let json = r#"{"access_token":"t","token_type":"Bearer","expires_in":999999999}"#;
        let resp: TokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.expires_in, Some(999_999_999));
    }

    #[test]
    fn test_token_response_debug() {
        let resp = mock_token_response(Some(3600));
        let debug = format!("{resp:?}");
        assert!(debug.contains("TokenResponse"));
        assert!(
            !debug.contains("test_access_token"),
            "access_token must be redacted in Debug output"
        );
        assert!(
            !debug.contains("test_refresh_token"),
            "refresh_token must be redacted in Debug output"
        );
        assert!(debug.contains("[REDACTED]"));
        assert!(debug.contains("Bearer"), "token_type should be visible");
    }

    #[test]
    fn test_token_response_empty_scope() {
        let json = r#"{"access_token":"t","token_type":"Bearer","scope":""}"#;
        let resp: TokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.scope, Some(String::new()));
        // Empty scope string should yield no scopes after splitting
        let tokens = valid_tokens(resp);
        assert!(tokens.scopes().is_empty());
    }

    // ── Expanded tests: OAuthTokens from_response details ──

    #[test]
    fn test_token_from_response_long_expiry() {
        let resp = mock_token_response(Some(86400)); // 24 hours
        let tokens = valid_tokens(resp);
        assert!(!tokens.is_expired());
        assert!(!tokens.needs_refresh());
        let ttl = tokens.time_until_expiry().unwrap();
        // Should be close to 24 hours (within a few seconds)
        assert!(ttl.as_secs() > 86300);
    }

    #[test]
    fn test_token_authorization_header_custom_type() {
        let resp = TokenResponse {
            access_token: "my_token".into(),
            token_type: "MAC".into(),
            expires_in: Some(3600),
            refresh_token: None,
            scope: None,
            id_token: None,
        };
        let tokens = valid_tokens(resp);
        assert_eq!(
            tokens
                .authorization_header()
                .expect("token must format an authorization header"),
            "MAC my_token"
        );
    }

    #[test]
    fn test_token_multiple_scopes_whitespace_variations() {
        let resp = TokenResponse {
            access_token: "t".into(),
            token_type: "Bearer".into(),
            expires_in: None,
            refresh_token: None,
            scope: Some("read  write\tmanage".into()),
            id_token: None,
        };
        let tokens = valid_tokens(resp);
        // split_whitespace handles multiple spaces and tabs
        assert_eq!(tokens.scopes(), &["read", "write", "manage"]);
    }

    #[test]
    fn test_token_update_does_not_overwrite_scopes_if_none() {
        let mut tokens = valid_tokens(TokenResponse {
            access_token: "t".into(),
            token_type: "Bearer".into(),
            expires_in: Some(3600),
            refresh_token: None,
            scope: Some("original".into()),
            id_token: None,
        });
        assert_eq!(tokens.scopes(), &["original"]);

        tokens
            .update_from_response(TokenResponse {
                access_token: "new_t".into(),
                token_type: "Bearer".into(),
                expires_in: Some(3600),
                refresh_token: None,
                scope: None, // not provided
                id_token: None,
            })
            .expect("non-empty access_token and token_type must succeed");
        // original scopes should be preserved
        assert_eq!(tokens.scopes(), &["original"]);
    }

    #[test]
    fn test_token_update_allows_same_scopes_if_provided() {
        let mut tokens = valid_tokens(TokenResponse {
            access_token: "t".into(),
            token_type: "Bearer".into(),
            expires_in: Some(3600),
            refresh_token: None,
            scope: Some("original".into()),
            id_token: None,
        });
        tokens
            .update_from_response(TokenResponse {
                access_token: "new_t".into(),
                token_type: "Bearer".into(),
                expires_in: Some(3600),
                refresh_token: None,
                scope: Some("original".into()),
                id_token: None,
            })
            .expect("non-empty access_token and token_type must succeed");
        assert_eq!(tokens.scopes(), &["original"]);
    }

    #[test]
    fn test_token_update_accepts_scope_when_original_response_omitted_it() {
        let mut tokens = valid_tokens(TokenResponse {
            access_token: "t".into(),
            token_type: "Bearer".into(),
            expires_in: Some(3600),
            refresh_token: Some("rt".into()),
            scope: None,
            id_token: None,
        });
        assert!(tokens.scopes().is_empty());

        tokens
            .update_from_response(TokenResponse {
                access_token: "new_t".into(),
                token_type: "Bearer".into(),
                expires_in: Some(3600),
                refresh_token: None,
                scope: Some("read write".into()),
                id_token: None,
            })
            .expect("refresh scope should be accepted when original scope was omitted");

        assert_eq!(tokens.access_token(), "new_t");
        assert_eq!(tokens.scopes(), &["read", "write"]);
    }

    #[test]
    fn test_token_update_does_not_overwrite_id_token_if_none() {
        let mut tokens = valid_tokens(TokenResponse {
            access_token: "t".into(),
            token_type: "Bearer".into(),
            expires_in: Some(3600),
            refresh_token: None,
            scope: None,
            id_token: Some("original_id".into()),
        });
        tokens
            .update_from_response(TokenResponse {
                access_token: "new_t".into(),
                token_type: "Bearer".into(),
                expires_in: Some(3600),
                refresh_token: None,
                scope: None,
                id_token: None,
            })
            .expect("non-empty access_token and token_type must succeed");
        assert_eq!(tokens.id_token(), Some("original_id"));
    }

    // ── Expanded tests: TokenStore advanced scenarios ──

    #[test]
    fn test_token_store_many_keys() {
        let store = TokenStore::new();
        for i in 0..20 {
            store.store(
                &format!("user_{i}"),
                valid_tokens(mock_token_response(Some(3600))),
            );
        }
        assert_eq!(store.keys().len(), 20);
        assert!(store.has_valid_token("user_0"));
        assert!(store.has_valid_token("user_19"));
    }

    #[test]
    fn test_token_store_remove_returns_tokens() {
        let store = TokenStore::new();
        store.store("key", valid_tokens(mock_token_response(Some(3600))));
        let removed = store.remove("key");
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().access_token(), "test_access_token");
    }

    #[test]
    fn test_token_store_update_preserves_metadata() {
        let store = TokenStore::new();
        let mut metadata = HashMap::new();
        metadata.insert("provider".to_string(), "google".to_string());
        store.store_with_metadata(
            "key",
            valid_tokens(mock_token_response(Some(3600))),
            metadata,
        );

        // Update the tokens
        let new_tokens = OAuthTokens::from_response(TokenResponse {
            access_token: "updated_tok".into(),
            token_type: "Bearer".into(),
            expires_in: Some(7200),
            refresh_token: None,
            scope: None,
            id_token: None,
        })
        .expect("valid token fixture must construct");
        store.update("key", new_tokens).unwrap();

        // Metadata should still be there
        let (tokens, meta) = store.get_with_metadata("key").unwrap();
        assert_eq!(tokens.access_token(), "updated_tok");
        assert_eq!(meta.get("provider"), Some(&"google".to_string()));
    }

    #[test]
    fn test_token_store_empty_key() {
        let store = TokenStore::new();
        store.store("", valid_tokens(mock_token_response(Some(3600))));
        assert!(store.has_valid_token(""));
        assert!(store.get("").is_some());
    }

    #[test]
    fn test_token_store_unicode_key() {
        let store = TokenStore::new();
        store.store(
            "usuario_\u{00e9}tranger",
            valid_tokens(mock_token_response(Some(3600))),
        );
        assert!(store.has_valid_token("usuario_\u{00e9}tranger"));
    }

    #[test]
    fn test_token_store_clear_then_add() {
        let store = TokenStore::new();
        store.store("key1", valid_tokens(mock_token_response(Some(3600))));
        store.clear();
        assert!(store.keys().is_empty());
        store.store("key2", valid_tokens(mock_token_response(Some(3600))));
        assert_eq!(store.keys().len(), 1);
        assert!(store.has_valid_token("key2"));
    }

    #[test]
    fn test_token_store_debug() {
        let store = TokenStore::new();
        let debug = format!("{store:?}");
        assert!(debug.contains("TokenStore"));
    }

    #[test]
    fn test_token_needs_refresh_within_zero_threshold() {
        let tokens = valid_tokens(mock_token_response(Some(3600)));
        // With zero threshold, only expired tokens need refresh
        assert!(!tokens.needs_refresh_within(Duration::from_secs(0)));
    }

    #[test]
    fn test_token_needs_refresh_within_huge_threshold() {
        let tokens = valid_tokens(mock_token_response(Some(3600)));
        // With very large threshold, any token with expiry needs refresh
        assert!(tokens.needs_refresh_within(Duration::from_secs(999_999)));
    }

    // ── Expanded: token lifecycle edge cases ──

    #[test]
    fn test_token_from_response_no_optional_fields() {
        let resp = TokenResponse {
            access_token: "minimal_tok".into(),
            token_type: "Bearer".into(),
            expires_in: None,
            refresh_token: None,
            scope: None,
            id_token: None,
        };
        let tokens = valid_tokens(resp);
        assert_eq!(tokens.access_token(), "minimal_tok");
        assert_eq!(tokens.token_type(), "Bearer");
        assert!(tokens.refresh_token().is_none());
        assert!(tokens.scopes().is_empty());
        assert!(tokens.id_token().is_none());
        assert!(!tokens.is_expired());
        assert!(!tokens.needs_refresh());
    }

    #[test]
    fn test_token_authorization_header_empty_type() {
        let resp = TokenResponse {
            access_token: "tok".into(),
            token_type: String::new(),
            expires_in: None,
            refresh_token: None,
            scope: None,
            id_token: None,
        };
        let err = OAuthTokens::from_response(resp).unwrap_err();
        assert!(matches!(err, OAuthError::EmptyTokenField("token_type")));
    }

    #[test]
    fn test_token_authorization_header_empty_access_token_errors() {
        let resp = TokenResponse {
            access_token: String::new(),
            token_type: "Bearer".into(),
            expires_in: None,
            refresh_token: None,
            scope: None,
            id_token: None,
        };
        let err = OAuthTokens::from_response(resp).unwrap_err();
        assert!(matches!(err, OAuthError::EmptyTokenField("access_token")));
    }

    #[test]
    fn test_token_multiple_whitespace_in_scope() {
        let resp = TokenResponse {
            access_token: "t".into(),
            token_type: "Bearer".into(),
            expires_in: None,
            refresh_token: None,
            scope: Some("  read   write   admin  ".into()),
            id_token: None,
        };
        let tokens = valid_tokens(resp);
        assert_eq!(tokens.scopes(), &["read", "write", "admin"]);
    }

    #[test]
    fn test_token_update_replaces_access_token_type() {
        let mut tokens = valid_tokens(mock_token_response(Some(3600)));
        assert_eq!(tokens.token_type(), "Bearer");

        tokens
            .update_from_response(TokenResponse {
                access_token: "new".into(),
                token_type: "MAC".into(),
                expires_in: Some(1800),
                refresh_token: None,
                scope: None,
                id_token: None,
            })
            .expect("non-empty access_token and token_type must succeed");
        assert_eq!(tokens.token_type(), "MAC");
        assert_eq!(tokens.access_token(), "new");
    }

    #[test]
    fn test_token_update_replaces_expiry() {
        let mut tokens = valid_tokens(mock_token_response(Some(3600)));
        assert!(!tokens.is_expired());

        tokens
            .update_from_response(TokenResponse {
                access_token: "new".into(),
                token_type: "Bearer".into(),
                expires_in: Some(0),
                refresh_token: None,
                scope: None,
                id_token: None,
            })
            .expect("non-empty access_token and token_type must succeed");
        assert!(tokens.is_expired());
    }

    #[test]
    fn test_token_time_until_expiry_long_lived() {
        let tokens = valid_tokens(mock_token_response(Some(86400)));
        let ttl = tokens.time_until_expiry().unwrap();
        assert!(ttl.as_secs() > 86000);
        assert!(ttl.as_secs() <= 86400);
    }

    #[test]
    fn test_token_serialize_contains_all_fields() {
        let mut resp = mock_token_response(Some(3600));
        resp.id_token = Some("id_jwt".into());
        let tokens = valid_tokens(resp);
        let json = serde_json::to_string(&tokens).unwrap();
        assert!(json.contains("access_token"));
        assert!(json.contains("token_type"));
        assert!(json.contains("scopes"));
        assert!(json.contains("id_token"));
        assert!(json.contains("issued_at"));
    }

    #[test]
    fn test_token_response_missing_access_token_rejected() {
        let json = r#"{"token_type":"Bearer"}"#;
        let result: Result<TokenResponse, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_token_response_missing_token_type_rejected() {
        let json = r#"{"access_token":"tok"}"#;
        let result: Result<TokenResponse, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_token_response_extra_fields_ignored() {
        let json = r#"{"access_token":"t","token_type":"Bearer","custom_field":"val"}"#;
        let resp: TokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.access_token, "t");
    }

    // ── Expanded: TokenStore operations ──

    #[test]
    fn test_token_store_store_and_remove_multiple() {
        let store = TokenStore::new();
        for i in 0..10 {
            store.store(
                &format!("key_{i}"),
                valid_tokens(mock_token_response(Some(3600))),
            );
        }
        assert_eq!(store.keys().len(), 10);

        for i in 0..5 {
            let _ = store.remove(&format!("key_{i}"));
        }
        assert_eq!(store.keys().len(), 5);
        assert!(!store.has_valid_token("key_0"));
        assert!(store.has_valid_token("key_5"));
    }

    #[test]
    fn test_token_store_overwrite_preserves_key_count() {
        let store = TokenStore::new();
        store.store("key", valid_tokens(mock_token_response(Some(3600))));
        store.store("key", valid_tokens(mock_token_response(Some(7200))));
        assert_eq!(store.keys().len(), 1);
    }

    #[test]
    fn test_token_store_metadata_empty_map() {
        let store = TokenStore::new();
        store.store_with_metadata(
            "key",
            valid_tokens(mock_token_response(Some(3600))),
            HashMap::new(),
        );
        let (_, meta) = store.get_with_metadata("key").unwrap();
        assert!(meta.is_empty());
    }

    #[test]
    fn test_token_store_metadata_multiple_entries() {
        let store = TokenStore::new();
        let mut metadata = HashMap::new();
        metadata.insert("provider".to_string(), "google".to_string());
        metadata.insert("tenant".to_string(), "org-123".to_string());
        metadata.insert("region".to_string(), "us-east-1".to_string());
        store.store_with_metadata(
            "key",
            valid_tokens(mock_token_response(Some(3600))),
            metadata,
        );
        let (_, meta) = store.get_with_metadata("key").unwrap();
        assert_eq!(meta.len(), 3);
        assert_eq!(meta.get("tenant"), Some(&"org-123".to_string()));
    }

    #[test]
    fn test_token_store_update_error_message_contains_key() {
        let store = TokenStore::new();
        let tokens = valid_tokens(mock_token_response(Some(3600)));
        let err = store.update("missing_key", tokens).unwrap_err();
        assert!(err.to_string().contains("missing_key"));
    }

    #[test]
    fn test_token_store_keys_order_independent() {
        let store = TokenStore::new();
        store.store("b", valid_tokens(mock_token_response(Some(3600))));
        store.store("a", valid_tokens(mock_token_response(Some(3600))));
        let keys = store.keys();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&"a".to_string()));
        assert!(keys.contains(&"b".to_string()));
    }

    #[test]
    fn test_token_store_remove_returns_correct_token() {
        let store = TokenStore::new();
        let resp = TokenResponse {
            access_token: "specific_tok".into(),
            token_type: "Bearer".into(),
            expires_in: Some(3600),
            refresh_token: None,
            scope: None,
            id_token: None,
        };
        store.store("key", valid_tokens(resp));
        let removed = store.remove("key").unwrap();
        assert_eq!(removed.access_token(), "specific_tok");
    }

    #[test]
    fn test_token_store_get_returns_clone_not_reference() {
        let store = TokenStore::new();
        store.store("key", valid_tokens(mock_token_response(Some(3600))));
        let t1 = store.get("key").unwrap();
        let t2 = store.get("key").unwrap();
        // Both should have the same access token
        assert_eq!(t1.access_token(), t2.access_token());
    }

    #[test]
    fn test_token_needs_refresh_within_no_expiry() {
        let tokens = valid_tokens(mock_token_response(None));
        assert!(!tokens.needs_refresh_within(Duration::from_secs(999_999)));
    }

    #[test]
    fn test_token_debug_shows_scopes() {
        let tokens = valid_tokens(mock_token_response(Some(3600)));
        let debug = format!("{tokens:?}");
        assert!(debug.contains("read"));
        assert!(debug.contains("write"));
    }

    // ── New batch: TokenResponse serde edge cases ──

    #[test]
    fn test_token_response_unicode_access_token() {
        let json = r#"{"access_token":"tok_\u00e9tranger","token_type":"Bearer"}"#;
        let resp: TokenResponse = serde_json::from_str(json).unwrap();
        assert!(resp.access_token.contains('\u{00e9}'));
    }

    #[test]
    fn test_token_response_empty_access_token() {
        let json = r#"{"access_token":"","token_type":"Bearer"}"#;
        let resp: TokenResponse = serde_json::from_str(json).unwrap();
        assert!(resp.access_token.is_empty());
        let err = OAuthTokens::from_response(resp).unwrap_err();
        assert!(matches!(err, OAuthError::EmptyTokenField("access_token")));
    }

    #[test]
    fn test_token_response_empty_token_type() {
        let json = r#"{"access_token":"tok","token_type":""}"#;
        let resp: TokenResponse = serde_json::from_str(json).unwrap();
        assert!(resp.token_type.is_empty());
    }

    #[test]
    fn test_token_response_scope_with_single_space() {
        let json = r#"{"access_token":"t","token_type":"B","scope":" "}"#;
        let resp: TokenResponse = serde_json::from_str(json).unwrap();
        let tokens = valid_tokens(resp);
        // Single space should yield empty scopes after split_whitespace
        assert!(tokens.scopes().is_empty());
    }

    #[test]
    fn test_token_response_serde_roundtrip_all_none() {
        let resp = TokenResponse {
            access_token: "min".into(),
            token_type: "Bearer".into(),
            expires_in: None,
            refresh_token: None,
            scope: None,
            id_token: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let rt: TokenResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.access_token, "min");
        assert!(rt.expires_in.is_none());
        assert!(rt.refresh_token.is_none());
        assert!(rt.scope.is_none());
        assert!(rt.id_token.is_none());
    }

    #[test]
    fn test_token_response_serde_roundtrip_all_some() {
        let resp = TokenResponse {
            access_token: "at".into(),
            token_type: "Bearer".into(),
            expires_in: Some(7200),
            refresh_token: Some("rt".into()),
            scope: Some("a b c".into()),
            id_token: Some("id".into()),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let rt: TokenResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.access_token, "at");
        assert_eq!(rt.expires_in, Some(7200));
        assert_eq!(rt.refresh_token.as_deref(), Some("rt"));
        assert_eq!(rt.scope.as_deref(), Some("a b c"));
        assert_eq!(rt.id_token.as_deref(), Some("id"));
    }

    // ── New batch: OAuthTokens advanced lifecycle ──

    #[test]
    fn test_token_update_replaces_id_token_when_provided() {
        let mut tokens = valid_tokens(TokenResponse {
            access_token: "t".into(),
            token_type: "Bearer".into(),
            expires_in: Some(3600),
            refresh_token: None,
            scope: None,
            id_token: Some("old_id".into()),
        });
        tokens
            .update_from_response(TokenResponse {
                access_token: "new_t".into(),
                token_type: "Bearer".into(),
                expires_in: Some(3600),
                refresh_token: None,
                scope: None,
                id_token: Some("new_id".into()),
            })
            .expect("non-empty access_token and token_type must succeed");
        assert_eq!(tokens.id_token(), Some("new_id"));
    }

    #[test]
    fn test_token_update_replaces_refresh_token_when_provided() {
        let mut tokens = valid_tokens(TokenResponse {
            access_token: "t".into(),
            token_type: "Bearer".into(),
            expires_in: Some(3600),
            refresh_token: Some("old_rt".into()),
            scope: None,
            id_token: None,
        });
        tokens
            .update_from_response(TokenResponse {
                access_token: "new_t".into(),
                token_type: "Bearer".into(),
                expires_in: Some(3600),
                refresh_token: Some("new_rt".into()),
                scope: None,
                id_token: None,
            })
            .expect("non-empty access_token and token_type must succeed");
        assert_eq!(tokens.refresh_token(), Some("new_rt"));
    }

    #[test]
    fn test_token_clone_preserves_all_fields() {
        let resp = TokenResponse {
            access_token: "at".into(),
            token_type: "MAC".into(),
            expires_in: Some(1800),
            refresh_token: Some("rt".into()),
            scope: Some("x y z".into()),
            id_token: Some("id_jwt".into()),
        };
        let tokens = valid_tokens(resp);
        let cloned = tokens.clone();
        assert_eq!(tokens.access_token(), cloned.access_token());
        assert_eq!(tokens.token_type(), cloned.token_type());
        assert_eq!(tokens.refresh_token(), cloned.refresh_token());
        assert_eq!(tokens.scopes(), cloned.scopes());
        assert_eq!(tokens.id_token(), cloned.id_token());
        assert_eq!(
            tokens
                .authorization_header()
                .expect("token must format an authorization header"),
            cloned
                .authorization_header()
                .expect("cloned token must format an authorization header")
        );
    }

    #[test]
    fn test_token_serialize_deserialize_preserves_access_token() {
        let tokens = valid_tokens(mock_token_response(Some(3600)));
        let json = serde_json::to_string(&tokens).unwrap();
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(val["access_token"].as_str(), Some("test_access_token"));
        assert_eq!(val["token_type"].as_str(), Some("Bearer"));
    }

    // ── New batch: TokenStore concurrent-style operations ──

    #[test]
    fn test_token_store_store_get_remove_cycle() {
        let store = TokenStore::new();
        let key = "cycle_key";

        // Initially empty
        assert!(store.get(key).is_none());
        assert!(!store.has_valid_token(key));

        // Store
        store.store(key, valid_tokens(mock_token_response(Some(3600))));
        assert!(store.get(key).is_some());
        assert!(store.has_valid_token(key));

        // Remove
        let removed = store.remove(key);
        assert!(removed.is_some());
        assert!(store.get(key).is_none());
        assert!(!store.has_valid_token(key));
    }

    #[test]
    fn test_token_store_update_then_get_with_metadata() {
        let store = TokenStore::new();
        let mut metadata = HashMap::new();
        metadata.insert("env".to_string(), "production".to_string());

        store.store_with_metadata("k", valid_tokens(mock_token_response(Some(3600))), metadata);

        let new_tokens = valid_tokens(TokenResponse {
            access_token: "updated_at".into(),
            token_type: "Bearer".into(),
            expires_in: Some(7200),
            refresh_token: None,
            scope: None,
            id_token: None,
        });
        store.update("k", new_tokens).unwrap();

        let (tokens, meta) = store.get_with_metadata("k").unwrap();
        assert_eq!(tokens.access_token(), "updated_at");
        // Metadata should still be preserved after update
        assert_eq!(meta.get("env"), Some(&"production".to_string()));
    }

    #[test]
    fn test_token_store_update_after_refresh_rejects_stale_overwrite() {
        let store = TokenStore::new();
        store.store(
            "k",
            valid_tokens(TokenResponse {
                access_token: "old_at".into(),
                token_type: "Bearer".into(),
                expires_in: Some(0),
                refresh_token: Some("old_rt".into()),
                scope: None,
                id_token: None,
            }),
        );

        let leader_tokens = valid_tokens(TokenResponse {
            access_token: "leader_at".into(),
            token_type: "Bearer".into(),
            expires_in: Some(3600),
            refresh_token: Some("new_rt".into()),
            scope: None,
            id_token: None,
        });
        assert!(
            store
                .update_after_refresh("k", Some("old_rt"), leader_tokens)
                .unwrap()
        );

        let stale_tokens = valid_tokens(TokenResponse {
            access_token: "stale_at".into(),
            token_type: "Bearer".into(),
            expires_in: Some(3600),
            refresh_token: Some("stale_rt".into()),
            scope: None,
            id_token: None,
        });
        assert!(
            !store
                .update_after_refresh("k", Some("old_rt"), stale_tokens)
                .unwrap(),
            "stale refresh response must not overwrite rotated credentials"
        );

        let stored = store.get("k").unwrap();
        assert_eq!(stored.access_token(), "leader_at");
        assert_eq!(stored.refresh_token(), Some("new_rt"));
    }

    #[test]
    fn test_update_after_refresh_preserves_expiry_when_omitted() {
        // A refresh response that omits `expires_in` must NOT clear the
        // prior expiry to never-expiring (which would silently stop the
        // refresh loop). from_response builds the new tokens with
        // expires_at=None; update_after_refresh must preserve the stored
        // expiry.
        let store = TokenStore::new();
        store.store(
            "k",
            valid_tokens(TokenResponse {
                access_token: "at".into(),
                token_type: "Bearer".into(),
                expires_in: Some(0), // at expiry
                refresh_token: Some("rt".into()),
                scope: Some("read".into()),
                id_token: None,
            }),
        );
        assert!(store.get("k").unwrap().is_expired());

        let refreshed = valid_tokens(TokenResponse {
            access_token: "at2".into(),
            token_type: "Bearer".into(),
            expires_in: None, // OMITTED
            refresh_token: Some("rt".into()),
            scope: Some("read".into()),
            id_token: None,
        });
        assert!(
            store
                .update_after_refresh("k", Some("rt"), refreshed)
                .unwrap()
        );

        let stored = store.get("k").unwrap();
        assert_eq!(stored.access_token(), "at2");
        assert!(
            stored.is_expired(),
            "omitted expires_in must preserve the prior expiry, not clear it to never-expiring"
        );
    }

    #[test]
    fn test_update_after_refresh_preserves_scopes_when_omitted() {
        let store = TokenStore::new();
        store.store(
            "k",
            valid_tokens(TokenResponse {
                access_token: "at".into(),
                token_type: "Bearer".into(),
                expires_in: Some(3600),
                refresh_token: Some("rt".into()),
                scope: Some("read write".into()),
                id_token: None,
            }),
        );

        let refreshed = valid_tokens(TokenResponse {
            access_token: "at2".into(),
            token_type: "Bearer".into(),
            expires_in: Some(3600),
            refresh_token: Some("rt".into()),
            scope: None, // OMITTED
            id_token: None,
        });
        assert!(
            store
                .update_after_refresh("k", Some("rt"), refreshed)
                .unwrap()
        );

        assert_eq!(
            store.get("k").unwrap().scopes().to_vec(),
            vec!["read".to_string(), "write".to_string()],
            "omitted scope must preserve the originally granted scopes"
        );
    }

    #[test]
    fn test_update_after_refresh_rejects_scope_expansion() {
        // A refresh must never WIDEN granted scopes (a compromised token
        // endpoint returning read -> read write admin), and must leave the
        // stored credential unchanged when it tries.
        let store = TokenStore::new();
        store.store(
            "k",
            valid_tokens(TokenResponse {
                access_token: "at".into(),
                token_type: "Bearer".into(),
                expires_in: Some(3600),
                refresh_token: Some("rt".into()),
                scope: Some("read".into()),
                id_token: None,
            }),
        );

        let widened = valid_tokens(TokenResponse {
            access_token: "at2".into(),
            token_type: "Bearer".into(),
            expires_in: Some(3600),
            refresh_token: Some("rt".into()),
            scope: Some("read write admin".into()),
            id_token: None,
        });
        let err = store
            .update_after_refresh("k", Some("rt"), widened)
            .unwrap_err();
        assert!(
            matches!(err, OAuthError::InvalidTokenResponse(_)),
            "a refresh that widens scopes must be rejected, got {err:?}"
        );

        let stored = store.get("k").unwrap();
        assert_eq!(
            stored.access_token(),
            "at",
            "rejected refresh must not mutate the stored token"
        );
        assert_eq!(stored.scopes().to_vec(), vec!["read".to_string()]);
    }

    #[test]
    fn test_refresh_gate_lease_releases_on_drop() {
        let store = TokenStore::new();
        let gate = store.refresh_gate("k");

        let lease = RefreshGateLease::try_acquire(&gate)
            .expect("first acquire should claim the refresh gate");
        assert!(gate.is_refreshing());
        assert!(
            RefreshGateLease::try_acquire(&gate).is_none(),
            "second acquire must observe the active single-flight refresh"
        );

        drop(lease);
        assert!(
            !gate.is_refreshing(),
            "dropping the lease must release the gate even if the refresh future is cancelled"
        );

        let reacquired = RefreshGateLease::try_acquire(&gate)
            .expect("gate should be reusable after the previous lease drops");
        drop(reacquired);
    }

    #[test]
    fn test_refresh_gate_waiter_wakes_on_completion() {
        fcp_async_core::runtime::block_on_sync(async {
            let store = TokenStore::new();
            let gate = store.refresh_gate("k");
            let lease = RefreshGateLease::try_acquire(&gate)
                .expect("first acquire should claim the refresh gate");

            let waiter = RefreshGateLease::claim_or_subscribe(&gate)
                .expect_err("second claim must subscribe while refresh is active");

            let join = fcp_async_core::task::spawn(waiter.wait_until_refresh_completes());
            fcp_async_core::task::yield_now().await;
            assert!(
                !join.is_finished(),
                "waiter should park while the refresh lease is active"
            );

            drop(lease);
            join.await.expect("waiter task should complete");
            assert!(!gate.is_refreshing());
        })
        .expect("build sync test runtime");
    }

    #[test]
    fn test_token_store_cleanup_keeps_expired_refreshable_tokens() {
        let store = TokenStore::new().with_cleanup_interval(Duration::ZERO);
        store.store(
            "refreshable",
            valid_tokens(TokenResponse {
                access_token: "expired_at".into(),
                token_type: "Bearer".into(),
                expires_in: Some(0),
                refresh_token: Some("refreshable_rt".into()),
                scope: None,
                id_token: None,
            }),
        );

        store.store("active", valid_tokens(mock_token_response(Some(3600))));

        let refreshable = store
            .get("refreshable")
            .expect("expired tokens with refresh credentials must remain refreshable");
        assert!(refreshable.is_expired());
        assert_eq!(refreshable.refresh_token(), Some("refreshable_rt"));
    }

    #[test]
    fn test_token_store_clear_does_not_affect_cleanup_interval() {
        let store = TokenStore::new().with_cleanup_interval(Duration::from_secs(999));
        store.store("k", valid_tokens(mock_token_response(Some(3600))));
        store.clear();
        // Should still be functional after clear
        store.store("k2", valid_tokens(mock_token_response(Some(3600))));
        assert!(store.has_valid_token("k2"));
    }
}
