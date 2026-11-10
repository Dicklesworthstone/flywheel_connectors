//! Deadline-bounded renewal of host-owned OAuth credentials before injection.
//!
//! A lease witnesses a pool and credential incarnation, not just an ID. Refresh
//! results are published only against that witness. The per-credential gate is
//! held across the asynchronous provider exchange; the pool lock is never held
//! across network I/O. Cancellation drops the exchange and releases the gate.

use super::{
    AppState, AuthError, AuthMethodKind, AuthorizedHostEgress, CredentialInjector, CredentialLease,
    CredentialPayload, Duration, EgressError, EgressGuard, EgressHttpRequest,
    HostCredentialInjector, HostEgressHttpRequest, HostError, HostResult, Instant,
    OAuthRefreshProviderResponse, OAuthRefreshTokenConfig, OAuthRefreshTokenGrant,
    OAuthRefreshTokenTransport, TokenRefreshDecision, TokenRefreshPolicy, Utc, Value,
    authorize_host_egress_context, invalid_oauth_provider_response, oauth_tokens_from_value,
};

const MAX_TOKEN_RESPONSE_BYTES: usize = 64 * 1024;

fn deadline_error() -> HostError {
    HostError::PreflightFailed("host-egress HTTP request deadline exhausted".to_owned())
}

pub(super) fn remaining_budget(
    authorized: &AuthorizedHostEgress,
    started_at: Instant,
) -> HostResult<Duration> {
    Duration::from_millis(u64::from(authorized.constraints.total_timeout_ms))
        .checked_sub(started_at.elapsed())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(deadline_error)
}

pub(super) fn retry_is_safe(method: &str) -> bool {
    // A credential renewal is not proof that a previous write had no effect.
    // Do not infer replay safety from connector metadata or an HTTP 401 alone.
    matches!(method, "GET" | "HEAD" | "OPTIONS")
}

fn requires_refresh(profile: &super::AuthProfile) -> bool {
    let token_missing = match &profile.method {
        AuthMethodKind::OAuthDeviceCode(method) => method.access_token.is_none(),
        AuthMethodKind::OAuthAuthCode(method) => method.access_token.is_none(),
        _ => return false,
    };
    token_missing
        || TokenRefreshDecision::for_profile(profile, TokenRefreshPolicy::default())
            .should_refresh()
}

/// Validate the destination and credential grant without materializing an
/// expired bearer. Denied requests must not reach even the token endpoint.
fn validate_destination(
    authorized: &AuthorizedHostEgress,
    request: &HostEgressHttpRequest,
    lease: &CredentialLease,
) -> HostResult<()> {
    authorized.require_current()?;
    let credential_id = request.credential_id.as_deref().ok_or_else(|| {
        HostError::PreflightFailed("host-egress credential reference is missing".to_owned())
    })?;
    if lease.pool_key.zone_id != authorized.zone_id {
        return Err(HostError::PreflightFailed(
            "host-egress credential lease belongs to another zone".to_owned(),
        ));
    }
    reqwest::Method::from_bytes(request.method.as_bytes())
        .map_err(|_| HostError::PreflightFailed("host-egress HTTP method is invalid".to_owned()))?;
    let decision = EgressGuard::new()
        .evaluate(
            &fcp_sandbox::EgressRequest::Http(EgressHttpRequest {
                url: request.url.clone(),
                method: request.method.clone(),
                headers: Vec::new(),
                body: None,
                credential_id: request.credential_id.clone(),
            }),
            &authorized.constraints,
        )
        .map_err(|error| match error {
            EgressError::Denied { code, .. } => {
                HostError::PreflightFailed(format!("host-egress destination is denied: {code:?}"))
            }
            // Parser diagnostics can contain userinfo or query secrets.
            _ => HostError::PreflightFailed(
                "host-egress destination is invalid or denied".to_owned(),
            ),
        })?;
    let injector = HostCredentialInjector::new(Some(lease.clone()));
    if !injector
        .is_authorized(
            credential_id,
            authorized.operation.as_str(),
            &authorized.credential_allow,
        )
        .unwrap_or(false)
        || !injector
            .is_host_allowed(credential_id, &decision.canonical_host)
            .unwrap_or(false)
    {
        return Err(HostError::PreflightFailed(
            "host-egress credential is not authorized for this destination".to_owned(),
        ));
    }
    Ok(())
}

fn lease_error() -> HostError {
    HostError::PreflightFailed(
        "host-egress credential lease was removed, replaced, released or disabled".to_owned(),
    )
}

pub(super) async fn prepare(
    state: &AppState,
    authorized: &AuthorizedHostEgress,
    request: &HostEgressHttpRequest,
    lease: &CredentialLease,
    unauthorized: bool,
    started_at: Instant,
) -> HostResult<CredentialLease> {
    let remaining = remaining_budget(authorized, started_at)?;
    fcp_async_core::time::timeout(remaining, async {
        let current = state
            .credential_pools
            .lock()
            .await
            .current_lease(lease, Utc::now())
            .map_err(|_| lease_error())?;
        validate_destination(authorized, request, &current)?;
        if !HostCredentialInjector::auth_profile_is_refreshable(&current.payload) {
            return Ok(current);
        }

        let gate = current.refresh_gate();
        let _refresh = gate.lock().await;
        // Recheck authority after waiting for another request's refresh.
        let fresh_authority =
            authorize_host_egress_context(state, &request.context, &request.url).await?;
        // Authorization can yield. Never send refresh material captured before
        // that wait: an administrator may have replaced or disabled it.
        let current = state
            .credential_pools
            .lock()
            .await
            .current_lease(lease, Utc::now())
            .map_err(|_| lease_error())?;
        authorized.require_current()?;
        validate_destination(&fresh_authority, request, &current)?;
        let mut profile = current
            .payload
            .as_auth_profile()
            .cloned()
            .ok_or_else(lease_error)?;
        if !current.same_payload_revision(lease) || (!unauthorized && !requires_refresh(&profile)) {
            // A successful refresh by another request is sufficient, even if
            // the provider issued a token shorter than the proactive window.
            return Ok(current);
        }

        let transport = RefreshTransport::new(remaining_budget(authorized, started_at)?)?;
        let cx = fcp_async_core::compatibility_cx();
        fresh_authority.require_current()?;
        authorized.require_current()?;
        let result = match &mut profile.method {
            AuthMethodKind::OAuthDeviceCode(method) => {
                method.refresh_with_transport(&cx, &transport).await
            }
            AuthMethodKind::OAuthAuthCode(method) => {
                method.refresh_with_transport(&cx, &transport).await
            }
            _ => return Err(lease_error()),
        };
        // Provider error descriptions can echo request secrets. Keep the host
        // boundary redacted even for malicious or malformed token responses.
        result.map_err(|_| {
            HostError::PreflightFailed("host-egress OAuth credential refresh failed".to_owned())
        })?;
        remaining_budget(authorized, started_at)?;
        let host_allow = current
            .payload
            .auth_profile_host_allow()
            .unwrap_or_default()
            .to_vec();
        let payload = CredentialPayload::auth_profile_with_allowed_hosts(profile, host_allow);
        let refreshed = state
            .credential_pools
            .lock()
            .await
            .replace_payload_if_current(&current, payload, Utc::now())
            .map_err(|_| lease_error())?
            .ok_or_else(lease_error)?;
        tracing::info!(
            event = "host_egress_oauth_refreshed",
            provider = %refreshed.pool_key.provider,
            zone_id = %refreshed.pool_key.zone_id,
            credential_id = %refreshed.credential_id,
            after_unauthorized = unauthorized,
            "host-owned OAuth credential renewed"
        );
        Ok(refreshed)
    })
    .await
    .map_err(|_| deadline_error())?
}

/// The egress path must yield while the provider is slow, so both the gate
/// wait and token exchange can be cancelled by the same request deadline.
struct RefreshTransport {
    client: reqwest::Client,
}

impl RefreshTransport {
    fn new(timeout: Duration) -> HostResult<Self> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent(concat!("fcp-host/", env!("CARGO_PKG_VERSION")))
            // A token endpoint redirect must never forward refresh material
            // to a destination that the operator did not configure.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| {
                HostError::PreflightFailed("host-egress OAuth transport unavailable".to_owned())
            })?;
        Ok(Self { client })
    }
}

#[async_trait::async_trait]
impl OAuthRefreshTokenTransport for RefreshTransport {
    async fn refresh(
        &self,
        config: &OAuthRefreshTokenConfig,
        grant: &OAuthRefreshTokenGrant,
    ) -> Result<OAuthRefreshProviderResponse, AuthError> {
        let mut form = vec![
            ("grant_type", "refresh_token"),
            ("refresh_token", grant.refresh_token.expose_secret()),
            ("client_id", config.client_id.as_str()),
        ];
        if let Some(secret) = config.client_secret.as_ref() {
            form.push(("client_secret", secret.expose_secret()));
        }
        if let Some(scope) = config.scope.as_deref() {
            form.push(("scope", scope));
        }
        let mut response = self
            .client
            .post(&config.token_url)
            .form(&form)
            .send()
            .await
            .map_err(|_| {
                invalid_oauth_provider_response("oauth_refresh", "token exchange failed")
            })?;
        if !response.status().is_success() {
            return Err(invalid_oauth_provider_response(
                "oauth_refresh",
                "token endpoint rejected refresh",
            ));
        }
        let mut body = zeroize::Zeroizing::new(Vec::new());
        while let Some(chunk) = response.chunk().await.map_err(|_| {
            invalid_oauth_provider_response("oauth_refresh", "token response read failed")
        })? {
            if chunk.len() > MAX_TOKEN_RESPONSE_BYTES.saturating_sub(body.len()) {
                return Err(invalid_oauth_provider_response(
                    "oauth_refresh",
                    "token response exceeds size limit",
                ));
            }
            body.extend_from_slice(&chunk);
        }
        let value: Value = serde_json::from_slice(body.as_slice()).map_err(|_| {
            invalid_oauth_provider_response("oauth_refresh", "token response is not valid JSON")
        })?;
        if value.get("error").is_some() {
            return Err(invalid_oauth_provider_response(
                "oauth_refresh",
                "provider refused refresh",
            ));
        }
        Ok(OAuthRefreshProviderResponse::Authorized(
            oauth_tokens_from_value("oauth_refresh", &value)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn automatic_unauthorized_replay_only_allows_safe_http_methods() {
        for method in ["GET", "HEAD", "OPTIONS"] {
            assert!(retry_is_safe(method), "{method}");
        }
        for method in ["POST", "PATCH", "PUT", "DELETE", "TRACE", "get", "CUSTOM"] {
            assert!(!retry_is_safe(method), "{method}");
        }
    }
}
