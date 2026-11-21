//! Pre-configured OAuth providers.
//!
//! Ready-to-use configurations for common OAuth providers.

use crate::{OAuth1Config, OAuth2Config, OAuthResult, PkceMethod, validate_oauth_endpoint_url};

/// Known OAuth provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthProvider {
    /// Google (OAuth 2.0 + PKCE).
    Google,
    /// GitHub (OAuth 2.0).
    GitHub,
    /// Twitter/X OAuth 2.0.
    Twitter,
    /// Twitter/X OAuth 1.0a (legacy).
    TwitterLegacy,
    /// Slack (OAuth 2.0).
    Slack,
    /// Notion (OAuth 2.0).
    Notion,
    /// Linear (OAuth 2.0).
    Linear,
    /// Discord (OAuth 2.0).
    Discord,
    /// Spotify (OAuth 2.0).
    Spotify,
    /// Microsoft/Azure AD (OAuth 2.0).
    Microsoft,
    /// Dropbox (OAuth 2.0).
    Dropbox,
}

impl OAuthProvider {
    /// Get OAuth 2.0 configuration for this provider.
    ///
    /// Returns `None` for OAuth 1.0a-only providers.
    #[must_use]
    pub fn oauth2_config(&self, client_id: &str, client_secret: &str) -> Option<OAuth2Config> {
        match self {
            Self::Google => Some(google_config(client_id, client_secret)),
            Self::GitHub => Some(github_config(client_id, client_secret)),
            Self::Twitter => Some(twitter_oauth2_config(client_id, client_secret)),
            Self::TwitterLegacy => None,
            Self::Slack => Some(slack_config(client_id, client_secret)),
            Self::Notion => Some(notion_config(client_id, client_secret)),
            Self::Linear => Some(linear_config(client_id, client_secret)),
            Self::Discord => Some(discord_config(client_id, client_secret)),
            Self::Spotify => Some(spotify_config(client_id, client_secret)),
            Self::Microsoft => Some(microsoft_config(client_id, client_secret)),
            Self::Dropbox => Some(dropbox_config(client_id, client_secret)),
        }
    }

    /// Get OAuth 1.0a configuration for this provider.
    ///
    /// Returns `None` for OAuth 2.0-only providers.
    #[must_use]
    pub fn oauth1_config(&self, consumer_key: &str, consumer_secret: &str) -> Option<OAuth1Config> {
        match self {
            Self::TwitterLegacy => Some(twitter_oauth1_config(consumer_key, consumer_secret)),
            _ => None,
        }
    }

    /// Check if this provider supports OAuth 2.0.
    #[must_use]
    pub const fn supports_oauth2(&self) -> bool {
        !matches!(self, Self::TwitterLegacy)
    }

    /// Check if this provider supports OAuth 1.0a.
    #[must_use]
    pub const fn supports_oauth1(&self) -> bool {
        matches!(self, Self::TwitterLegacy)
    }

    /// Check if this provider requires PKCE.
    #[must_use]
    pub const fn requires_pkce(&self) -> bool {
        matches!(self, Self::Google | Self::Twitter)
    }
}

// Provider-specific configurations

/// Google OAuth 2.0 configuration.
fn google_config(client_id: &str, client_secret: &str) -> OAuth2Config {
    OAuth2Config::new(
        client_id,
        client_secret,
        "https://accounts.google.com/o/oauth2/v2/auth",
        "https://oauth2.googleapis.com/token",
    )
    .with_pkce(true)
    .with_pkce_method(PkceMethod::S256)
    .with_auth_param("access_type", "offline")
    .with_auth_param("prompt", "consent")
}

/// GitHub OAuth 2.0 configuration.
fn github_config(client_id: &str, client_secret: &str) -> OAuth2Config {
    OAuth2Config::new(
        client_id,
        client_secret,
        "https://github.com/login/oauth/authorize",
        "https://github.com/login/oauth/access_token",
    )
    .with_pkce(false) // GitHub doesn't support PKCE
}

/// Twitter/X OAuth 2.0 configuration.
fn twitter_oauth2_config(client_id: &str, client_secret: &str) -> OAuth2Config {
    OAuth2Config::new(
        client_id,
        client_secret,
        "https://twitter.com/i/oauth2/authorize",
        "https://api.twitter.com/2/oauth2/token",
    )
    .with_pkce(true)
    .with_pkce_method(PkceMethod::S256)
}

/// Twitter/X OAuth 1.0a configuration (legacy).
fn twitter_oauth1_config(consumer_key: &str, consumer_secret: &str) -> OAuth1Config {
    OAuth1Config::new(
        consumer_key,
        consumer_secret,
        "https://api.twitter.com/oauth/request_token",
        "https://api.twitter.com/oauth/authorize",
        "https://api.twitter.com/oauth/access_token",
    )
}

/// Slack OAuth 2.0 configuration.
fn slack_config(client_id: &str, client_secret: &str) -> OAuth2Config {
    OAuth2Config::new(
        client_id,
        client_secret,
        "https://slack.com/oauth/v2/authorize",
        "https://slack.com/api/oauth.v2.access",
    )
    .with_pkce(false)
}

/// Notion OAuth 2.0 configuration.
fn notion_config(client_id: &str, client_secret: &str) -> OAuth2Config {
    OAuth2Config::new(
        client_id,
        client_secret,
        "https://api.notion.com/v1/oauth/authorize",
        "https://api.notion.com/v1/oauth/token",
    )
    .with_pkce(false)
    .with_auth_param("owner", "user")
}

/// Linear OAuth 2.0 configuration.
fn linear_config(client_id: &str, client_secret: &str) -> OAuth2Config {
    OAuth2Config::new(
        client_id,
        client_secret,
        "https://linear.app/oauth/authorize",
        "https://api.linear.app/oauth/token",
    )
    .with_pkce(false)
}

/// Discord OAuth 2.0 configuration.
fn discord_config(client_id: &str, client_secret: &str) -> OAuth2Config {
    OAuth2Config::new(
        client_id,
        client_secret,
        "https://discord.com/oauth2/authorize",
        "https://discord.com/api/oauth2/token",
    )
    .with_pkce(false)
}

/// Spotify OAuth 2.0 configuration.
fn spotify_config(client_id: &str, client_secret: &str) -> OAuth2Config {
    OAuth2Config::new(
        client_id,
        client_secret,
        "https://accounts.spotify.com/authorize",
        "https://accounts.spotify.com/api/token",
    )
    .with_pkce(true)
    .with_pkce_method(PkceMethod::S256)
}

/// Microsoft/Azure AD OAuth 2.0 configuration.
fn microsoft_config(client_id: &str, client_secret: &str) -> OAuth2Config {
    OAuth2Config::new(
        client_id,
        client_secret,
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    )
    .with_pkce(true)
    .with_pkce_method(PkceMethod::S256)
}

/// Dropbox OAuth 2.0 configuration.
fn dropbox_config(client_id: &str, client_secret: &str) -> OAuth2Config {
    OAuth2Config::new(
        client_id,
        client_secret,
        "https://www.dropbox.com/oauth2/authorize",
        "https://api.dropboxapi.com/oauth2/token",
    )
    .with_pkce(true)
    .with_pkce_method(PkceMethod::S256)
    .with_auth_param("token_access_type", "offline")
}

/// Provider endpoints for custom configuration.
#[derive(Debug, Clone)]
pub struct ProviderEndpoints {
    /// Authorization endpoint.
    pub authorization_url: String,
    /// Token endpoint.
    pub token_url: String,
    /// Revocation endpoint (optional).
    pub revocation_url: Option<String>,
    /// User info endpoint (optional).
    pub userinfo_url: Option<String>,
}

impl ProviderEndpoints {
    /// Create new provider endpoints.
    #[must_use]
    pub fn new(authorization_url: impl Into<String>, token_url: impl Into<String>) -> Self {
        Self {
            authorization_url: authorization_url.into(),
            token_url: token_url.into(),
            revocation_url: None,
            userinfo_url: None,
        }
    }

    /// Set revocation URL.
    #[must_use]
    pub fn with_revocation_url(mut self, url: impl Into<String>) -> Self {
        self.revocation_url = Some(url.into());
        self
    }

    /// Set userinfo URL.
    #[must_use]
    pub fn with_userinfo_url(mut self, url: impl Into<String>) -> Self {
        self.userinfo_url = Some(url.into());
        self
    }

    /// Validate every configured endpoint against the shared OAuth URL
    /// policy and return their canonical (post-parse-normalized) forms.
    ///
    /// This is the single source of truth for `ProviderEndpoints`
    /// validation: both `validate()` (predicate) and `to_oauth2_config()`
    /// (builder) flow through here so the two surfaces cannot drift.
    fn validated_endpoints(&self) -> OAuthResult<ValidatedEndpoints> {
        Ok(ValidatedEndpoints {
            authorization: validate_oauth_endpoint_url(
                &self.authorization_url,
                "authorization_url",
            )?,
            token: validate_oauth_endpoint_url(&self.token_url, "token_url")?,
            revocation: self
                .revocation_url
                .as_deref()
                .map(|url| validate_oauth_endpoint_url(url, "revocation_url"))
                .transpose()?,
            userinfo: self
                .userinfo_url
                .as_deref()
                .map(|url| validate_oauth_endpoint_url(url, "userinfo_url"))
                .transpose()?,
        })
    }

    /// Validate every configured endpoint against the shared OAuth URL policy.
    ///
    /// # Errors
    ///
    /// Returns an error when any custom endpoint is not HTTPS or loopback
    /// HTTP, is not an absolute network URL, embeds credentials, or includes a
    /// fragment.
    pub fn validate(&self) -> OAuthResult<()> {
        self.validated_endpoints().map(|_| ())
    }

    /// Build `OAuth2Config` from these endpoints.
    ///
    /// # Errors
    ///
    /// Returns an error when any custom provider endpoint violates the shared
    /// HTTPS-or-loopback URL policy.
    pub fn to_oauth2_config(
        &self,
        client_id: &str,
        client_secret: &str,
    ) -> OAuthResult<OAuth2Config> {
        let validated = self.validated_endpoints()?;
        Ok(OAuth2Config::new(
            client_id,
            client_secret,
            &validated.authorization,
            &validated.token,
        ))
    }
}

/// Canonical (post-parse-normalized) endpoint URLs from a successful
/// `ProviderEndpoints::validated_endpoints` pass.
///
/// `revocation_url` and `userinfo_url` are `Option` because the source
/// endpoints are optional; their `Some` arms have already been validated.
struct ValidatedEndpoints {
    authorization: String,
    token: String,
    #[allow(dead_code)] // surfaced via validate(); not used by to_oauth2_config builder
    revocation: Option<String>,
    #[allow(dead_code)]
    userinfo: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_google_config() {
        let config = OAuthProvider::Google
            .oauth2_config("client_id", "client_secret")
            .unwrap();

        assert!(config.use_pkce);
        assert_eq!(config.pkce_method, PkceMethod::S256);
        assert!(config.authorization_url.contains("google"));
    }

    #[test]
    fn test_github_config() {
        let config = OAuthProvider::GitHub
            .oauth2_config("client_id", "client_secret")
            .unwrap();

        assert!(!config.use_pkce); // GitHub doesn't support PKCE
        assert!(config.authorization_url.contains("github"));
    }

    #[test]
    fn test_twitter_oauth1() {
        let config = OAuthProvider::TwitterLegacy
            .oauth1_config("consumer_key", "consumer_secret")
            .unwrap();

        assert!(config.request_token_url.contains("twitter"));
    }

    #[test]
    fn test_provider_capabilities() {
        assert!(OAuthProvider::Google.supports_oauth2());
        assert!(!OAuthProvider::Google.supports_oauth1());
        assert!(OAuthProvider::Google.requires_pkce());

        assert!(!OAuthProvider::TwitterLegacy.supports_oauth2());
        assert!(OAuthProvider::TwitterLegacy.supports_oauth1());

        assert!(OAuthProvider::GitHub.supports_oauth2());
        assert!(!OAuthProvider::GitHub.requires_pkce());
    }

    #[test]
    fn test_custom_endpoints() {
        let endpoints = ProviderEndpoints::new(
            "https://custom.auth.com/authorize",
            "https://custom.auth.com/token",
        )
        .with_revocation_url("https://custom.auth.com/revoke")
        .with_userinfo_url("https://custom.auth.com/userinfo");

        let config = endpoints
            .to_oauth2_config("client_id", "client_secret")
            .unwrap();

        assert_eq!(
            config.authorization_url,
            "https://custom.auth.com/authorize"
        );
        assert_eq!(config.token_url, "https://custom.auth.com/token");
    }

    // ── New tests ──

    #[test]
    fn test_twitter_legacy_returns_none_for_oauth2() {
        let config = OAuthProvider::TwitterLegacy.oauth2_config("id", "secret");
        assert!(config.is_none());
    }

    #[test]
    fn test_non_legacy_returns_none_for_oauth1() {
        assert!(
            OAuthProvider::Google
                .oauth1_config("key", "secret")
                .is_none()
        );
        assert!(
            OAuthProvider::GitHub
                .oauth1_config("key", "secret")
                .is_none()
        );
        assert!(
            OAuthProvider::Slack
                .oauth1_config("key", "secret")
                .is_none()
        );
    }

    #[test]
    fn test_all_oauth2_providers_have_urls() {
        let providers = [
            OAuthProvider::Google,
            OAuthProvider::GitHub,
            OAuthProvider::Twitter,
            OAuthProvider::Slack,
            OAuthProvider::Notion,
            OAuthProvider::Linear,
            OAuthProvider::Discord,
            OAuthProvider::Spotify,
            OAuthProvider::Microsoft,
            OAuthProvider::Dropbox,
        ];

        for provider in providers {
            let config = provider.oauth2_config("id", "secret");
            assert!(
                config.is_some(),
                "Provider {provider:?} should return OAuth2 config"
            );
            let config = config.unwrap();
            assert!(!config.authorization_url.is_empty());
            assert!(!config.token_url.is_empty());
        }
    }

    #[test]
    fn test_provider_endpoints_defaults() {
        let endpoints = ProviderEndpoints::new(
            "https://auth.example.com/authorize",
            "https://auth.example.com/token",
        );
        assert!(endpoints.revocation_url.is_none());
        assert!(endpoints.userinfo_url.is_none());
    }

    #[test]
    fn test_pkce_required_providers() {
        assert!(OAuthProvider::Google.requires_pkce());
        assert!(OAuthProvider::Twitter.requires_pkce());
        assert!(!OAuthProvider::GitHub.requires_pkce());
        assert!(!OAuthProvider::Slack.requires_pkce());
    }

    // ── Batch: provider configuration details ──

    #[test]
    fn test_slack_config_urls() {
        let config = OAuthProvider::Slack.oauth2_config("id", "sec").unwrap();
        assert!(config.authorization_url.contains("slack.com"));
        assert!(config.token_url.contains("slack.com"));
        assert!(!config.use_pkce);
    }

    #[test]
    fn test_notion_config_urls() {
        let config = OAuthProvider::Notion.oauth2_config("id", "sec").unwrap();
        assert!(config.authorization_url.contains("notion.com"));
        assert!(config.token_url.contains("notion.com"));
    }

    #[test]
    fn test_linear_config_urls() {
        let config = OAuthProvider::Linear.oauth2_config("id", "sec").unwrap();
        assert!(config.authorization_url.contains("linear.app"));
        assert!(config.token_url.contains("linear.app"));
    }

    #[test]
    fn test_discord_config_urls() {
        let config = OAuthProvider::Discord.oauth2_config("id", "sec").unwrap();
        assert!(config.authorization_url.contains("discord.com"));
        assert!(config.token_url.contains("discord.com"));
    }

    #[test]
    fn test_spotify_config_pkce() {
        let config = OAuthProvider::Spotify.oauth2_config("id", "sec").unwrap();
        assert!(config.use_pkce);
        assert_eq!(config.pkce_method, PkceMethod::S256);
    }

    #[test]
    fn test_microsoft_config_pkce() {
        let config = OAuthProvider::Microsoft.oauth2_config("id", "sec").unwrap();
        assert!(config.use_pkce);
        assert_eq!(config.pkce_method, PkceMethod::S256);
        assert!(config.authorization_url.contains("microsoftonline.com"));
    }

    #[test]
    fn test_dropbox_config_pkce() {
        let config = OAuthProvider::Dropbox.oauth2_config("id", "sec").unwrap();
        assert!(config.use_pkce);
        assert!(config.authorization_url.contains("dropbox.com"));
    }

    #[test]
    fn test_twitter_oauth2_config_pkce() {
        let config = OAuthProvider::Twitter.oauth2_config("id", "sec").unwrap();
        assert!(config.use_pkce);
        assert_eq!(config.pkce_method, PkceMethod::S256);
        assert!(config.authorization_url.contains("twitter.com"));
    }

    #[test]
    fn test_google_config_has_offline_access_param() {
        let config = OAuthProvider::Google.oauth2_config("id", "sec").unwrap();
        // Google config should have access_type=offline
        assert!(config.extra_auth_params.contains_key("access_type"));
        assert_eq!(
            config.extra_auth_params.get("access_type").unwrap(),
            "offline"
        );
    }

    // ── Batch: OAuthProvider trait impls ──

    #[test]
    fn test_provider_clone() {
        let p = OAuthProvider::Google;
        let cloned = p;
        assert_eq!(p, cloned);
    }

    #[test]
    fn test_provider_debug() {
        let debug = format!("{:?}", OAuthProvider::Google);
        assert_eq!(debug, "Google");
    }

    #[test]
    fn test_provider_eq() {
        assert_eq!(OAuthProvider::Google, OAuthProvider::Google);
        assert_ne!(OAuthProvider::Google, OAuthProvider::GitHub);
    }

    #[test]
    fn test_all_providers_exhaustive_oauth2_support() {
        // Non-legacy providers should support OAuth2
        for provider in [
            OAuthProvider::Google,
            OAuthProvider::GitHub,
            OAuthProvider::Twitter,
            OAuthProvider::Slack,
            OAuthProvider::Notion,
            OAuthProvider::Linear,
            OAuthProvider::Discord,
            OAuthProvider::Spotify,
            OAuthProvider::Microsoft,
            OAuthProvider::Dropbox,
        ] {
            assert!(
                provider.supports_oauth2(),
                "{provider:?} should support oauth2"
            );
            assert!(
                !provider.supports_oauth1(),
                "{provider:?} should not support oauth1"
            );
        }
    }

    #[test]
    fn test_twitter_legacy_only_oauth1() {
        assert!(OAuthProvider::TwitterLegacy.supports_oauth1());
        assert!(!OAuthProvider::TwitterLegacy.supports_oauth2());
        assert!(!OAuthProvider::TwitterLegacy.requires_pkce());
    }

    // ── Batch: ProviderEndpoints ──

    #[test]
    #[allow(clippy::redundant_clone)]
    fn test_provider_endpoints_clone() {
        let endpoints = ProviderEndpoints::new("https://a.com/auth", "https://a.com/token")
            .with_revocation_url("https://a.com/revoke")
            .with_userinfo_url("https://a.com/userinfo");
        let cloned = endpoints.clone();
        assert_eq!(cloned.authorization_url, "https://a.com/auth");
        assert_eq!(cloned.token_url, "https://a.com/token");
        assert_eq!(
            cloned.revocation_url,
            Some("https://a.com/revoke".to_string())
        );
        assert_eq!(
            cloned.userinfo_url,
            Some("https://a.com/userinfo".to_string())
        );
    }

    #[test]
    fn test_provider_endpoints_debug() {
        let endpoints = ProviderEndpoints::new("https://a.com/auth", "https://a.com/token");
        let debug = format!("{endpoints:?}");
        assert!(debug.contains("ProviderEndpoints"));
    }

    #[test]
    fn test_provider_endpoints_to_oauth2_config_propagates_client_info() {
        let endpoints = ProviderEndpoints::new("https://a.com/auth", "https://a.com/token");
        let config = endpoints.to_oauth2_config("my_id", "my_secret").unwrap();
        assert_eq!(config.client_id, "my_id");
        assert_eq!(config.client_secret, Some("my_secret".to_string()));
    }

    #[test]
    fn test_twitter_oauth1_config_fields() {
        let config = OAuthProvider::TwitterLegacy
            .oauth1_config("my_key", "my_secret")
            .unwrap();
        assert_eq!(config.consumer_key, "my_key");
        assert_eq!(config.consumer_secret, "my_secret");
        assert!(config.request_token_url.contains("request_token"));
        assert!(config.authorization_url.contains("authorize"));
        assert!(config.access_token_url.contains("access_token"));
    }

    // ── Expanded tests: provider URL schemes ──

    #[test]
    fn test_all_oauth2_providers_use_https() {
        let providers = [
            OAuthProvider::Google,
            OAuthProvider::GitHub,
            OAuthProvider::Twitter,
            OAuthProvider::Slack,
            OAuthProvider::Notion,
            OAuthProvider::Linear,
            OAuthProvider::Discord,
            OAuthProvider::Spotify,
            OAuthProvider::Microsoft,
            OAuthProvider::Dropbox,
        ];

        for provider in providers {
            let config = provider.oauth2_config("id", "secret").unwrap();
            assert!(
                config.authorization_url.starts_with("https://"),
                "{provider:?} authorization_url should use HTTPS"
            );
            assert!(
                config.token_url.starts_with("https://"),
                "{provider:?} token_url should use HTTPS"
            );
        }
    }

    #[test]
    fn test_twitter_legacy_oauth1_urls_use_https() {
        let config = OAuthProvider::TwitterLegacy
            .oauth1_config("key", "secret")
            .unwrap();
        assert!(config.request_token_url.starts_with("https://"));
        assert!(config.authorization_url.starts_with("https://"));
        assert!(config.access_token_url.starts_with("https://"));
    }

    // ── Expanded tests: ProviderEndpoints builder ──

    #[test]
    fn test_provider_endpoints_with_only_revocation() {
        let endpoints = ProviderEndpoints::new("https://a.com/auth", "https://a.com/token")
            .with_revocation_url("https://a.com/revoke");
        assert!(endpoints.revocation_url.is_some());
        assert!(endpoints.userinfo_url.is_none());
    }

    #[test]
    fn test_provider_endpoints_with_only_userinfo() {
        let endpoints = ProviderEndpoints::new("https://a.com/auth", "https://a.com/token")
            .with_userinfo_url("https://a.com/userinfo");
        assert!(endpoints.revocation_url.is_none());
        assert!(endpoints.userinfo_url.is_some());
    }

    #[test]
    fn test_provider_endpoints_to_oauth2_config_urls() {
        let endpoints = ProviderEndpoints::new(
            "https://custom.example.com/authorize",
            "https://custom.example.com/token",
        );
        let config = endpoints.to_oauth2_config("cid", "csec").unwrap();
        assert_eq!(
            config.authorization_url,
            "https://custom.example.com/authorize"
        );
        assert_eq!(config.token_url, "https://custom.example.com/token");
    }

    #[test]
    fn test_provider_endpoints_accept_loopback_http_endpoints() {
        let endpoints = ProviderEndpoints::new(
            "http://localhost:3000/authorize",
            "http://127.0.0.1:3000/token",
        )
        .with_revocation_url("http://[::1]:3000/revoke")
        .with_userinfo_url("https://custom.example.com/userinfo");

        let config = endpoints
            .to_oauth2_config("cid", "csec")
            .expect("loopback http endpoints should be accepted");

        assert_eq!(config.authorization_url, "http://localhost:3000/authorize");
        assert_eq!(config.token_url, "http://127.0.0.1:3000/token");
    }

    #[test]
    fn test_provider_endpoints_reject_non_loopback_http_optional_endpoint() {
        let endpoints = ProviderEndpoints::new(
            "https://custom.example.com/authorize",
            "https://custom.example.com/token",
        )
        .with_revocation_url("http://attacker.example/revoke");

        let err = endpoints.to_oauth2_config("cid", "csec").unwrap_err();
        let message = err.to_string();
        assert!(message.contains("revocation_url"));
        assert!(message.contains("https or loopback http"));
    }

    #[test]
    fn test_provider_endpoints_reject_link_local_metadata_http_endpoint() {
        let endpoints = ProviderEndpoints::new(
            "http://169.254.169.254/latest/meta-data",
            "https://custom.example.com/token",
        );

        let err = endpoints.to_oauth2_config("cid", "csec").unwrap_err();
        let message = err.to_string();
        assert!(message.contains("authorization_url"));
        assert!(message.contains("https or loopback http"));
    }

    proptest! {
        #[test]
        fn provider_endpoints_reject_non_loopback_http_for_every_endpoint(
            host in "[a-z]{1,12}\\.example\\.com",
            path in "[a-z]{1,16}",
        ) {
            let plain_http = format!("http://{host}/{path}");
            let cases = [
                (
                    "authorization_url",
                    ProviderEndpoints::new(&plain_http, "https://custom.example.com/token"),
                ),
                (
                    "token_url",
                    ProviderEndpoints::new("https://custom.example.com/authorize", &plain_http),
                ),
                (
                    "revocation_url",
                    ProviderEndpoints::new(
                        "https://custom.example.com/authorize",
                        "https://custom.example.com/token",
                    )
                    .with_revocation_url(&plain_http),
                ),
                (
                    "userinfo_url",
                    ProviderEndpoints::new(
                        "https://custom.example.com/authorize",
                        "https://custom.example.com/token",
                    )
                    .with_userinfo_url(&plain_http),
                ),
            ];

            for (field, endpoints) in cases {
                let message = endpoints
                    .to_oauth2_config("cid", "csec")
                    .unwrap_err()
                    .to_string();
                prop_assert!(message.contains(field), "{message}");
                prop_assert!(message.contains("https or loopback http"), "{message}");
            }
        }
    }

    // ── Expanded tests: provider PKCE settings ──

    #[test]
    fn test_non_pkce_providers_have_pkce_disabled() {
        let non_pkce = [
            OAuthProvider::GitHub,
            OAuthProvider::Slack,
            OAuthProvider::Notion,
            OAuthProvider::Linear,
            OAuthProvider::Discord,
        ];
        for provider in non_pkce {
            let config = provider.oauth2_config("id", "sec").unwrap();
            assert!(!config.use_pkce, "{provider:?} should have PKCE disabled");
        }
    }

    #[test]
    fn test_pkce_providers_have_pkce_enabled() {
        let pkce_providers = [
            OAuthProvider::Google,
            OAuthProvider::Twitter,
            OAuthProvider::Spotify,
            OAuthProvider::Microsoft,
            OAuthProvider::Dropbox,
        ];
        for provider in pkce_providers {
            let config = provider.oauth2_config("id", "sec").unwrap();
            assert!(config.use_pkce, "{provider:?} should have PKCE enabled");
            assert_eq!(
                config.pkce_method,
                PkceMethod::S256,
                "{provider:?} should use S256"
            );
        }
    }

    // ── Expanded tests: notion has owner param ──

    #[test]
    fn test_notion_config_has_owner_param() {
        let config = OAuthProvider::Notion.oauth2_config("id", "sec").unwrap();
        assert_eq!(
            config.extra_auth_params.get("owner"),
            Some(&"user".to_string())
        );
    }

    #[test]
    fn test_linear_client_emits_one_authorization_response_type() {
        let config = OAuthProvider::Linear.oauth2_config("id", "sec").unwrap();
        let client = crate::OAuth2Client::new(config).expect("usable Linear provider config");
        let (authorization_url, _) = client.authorization_url(&[]).unwrap();
        let url = url::Url::parse(&authorization_url).unwrap();
        let response_types: Vec<_> = url
            .query_pairs()
            .filter(|(key, _)| key == "response_type")
            .map(|(_, value)| value.into_owned())
            .collect();
        assert_eq!(response_types, ["code"]);
    }

    #[test]
    fn test_all_oauth2_provider_configs_build_usable_clients() {
        for provider in [
            OAuthProvider::Google,
            OAuthProvider::GitHub,
            OAuthProvider::Twitter,
            OAuthProvider::Slack,
            OAuthProvider::Notion,
            OAuthProvider::Linear,
            OAuthProvider::Discord,
            OAuthProvider::Spotify,
            OAuthProvider::Microsoft,
            OAuthProvider::Dropbox,
        ] {
            let config = provider.oauth2_config("id", "secret").unwrap();
            let client = crate::OAuth2Client::new(config)
                .unwrap_or_else(|error| panic!("unusable {provider:?} config: {error}"));
            let session = client
                .authorization_session(&["read"])
                .expect("provider authorization session");
            let url = url::Url::parse(session.authorization_url()).unwrap();
            assert_eq!(url.scheme(), "https");
            assert!(!session.state().is_empty());
            assert_eq!(
                url.query_pairs()
                    .filter(|(name, _)| name == "state")
                    .count(),
                1,
                "{provider:?} state must come only from the session"
            );
        }
    }

    #[test]
    fn test_dropbox_config_has_offline_token_access() {
        let config = OAuthProvider::Dropbox.oauth2_config("id", "sec").unwrap();
        assert_eq!(
            config.extra_auth_params.get("token_access_type"),
            Some(&"offline".to_string())
        );
    }

    #[test]
    fn test_google_config_has_prompt_consent() {
        let config = OAuthProvider::Google.oauth2_config("id", "sec").unwrap();
        assert_eq!(
            config.extra_auth_params.get("prompt"),
            Some(&"consent".to_string())
        );
    }

    // ── Expanded: provider config propagation ──

    #[test]
    fn test_all_providers_set_client_id() {
        let providers = [
            OAuthProvider::Google,
            OAuthProvider::GitHub,
            OAuthProvider::Twitter,
            OAuthProvider::Slack,
            OAuthProvider::Notion,
            OAuthProvider::Linear,
            OAuthProvider::Discord,
            OAuthProvider::Spotify,
            OAuthProvider::Microsoft,
            OAuthProvider::Dropbox,
        ];
        for provider in providers {
            let config = provider.oauth2_config("my_client_id", "my_secret").unwrap();
            assert_eq!(
                config.client_id, "my_client_id",
                "{provider:?} should propagate client_id"
            );
            assert_eq!(
                config.client_secret,
                Some("my_secret".to_string()),
                "{provider:?} should propagate client_secret"
            );
        }
    }

    #[test]
    fn test_twitter_legacy_propagates_consumer_credentials() {
        let config = OAuthProvider::TwitterLegacy
            .oauth1_config("my_ck", "my_cs")
            .unwrap();
        assert_eq!(config.consumer_key, "my_ck");
        assert_eq!(config.consumer_secret, "my_cs");
    }

    #[test]
    fn test_provider_debug_all_variants() {
        let all = [
            OAuthProvider::Google,
            OAuthProvider::GitHub,
            OAuthProvider::Twitter,
            OAuthProvider::TwitterLegacy,
            OAuthProvider::Slack,
            OAuthProvider::Notion,
            OAuthProvider::Linear,
            OAuthProvider::Discord,
            OAuthProvider::Spotify,
            OAuthProvider::Microsoft,
            OAuthProvider::Dropbox,
        ];
        for provider in all {
            let debug = format!("{provider:?}");
            assert!(!debug.is_empty());
        }
    }

    #[test]
    fn test_provider_copy_semantics() {
        let p = OAuthProvider::Slack;
        let copy = p;
        assert_eq!(p, copy);
    }

    #[test]
    fn test_provider_endpoints_empty_urls() {
        let endpoints = ProviderEndpoints::new("", "");
        assert_eq!(endpoints.authorization_url, "");
        assert_eq!(endpoints.token_url, "");
    }

    #[test]
    fn test_provider_endpoints_builder_chaining_order_independent() {
        let ep1 = ProviderEndpoints::new("https://a/auth", "https://a/tok")
            .with_revocation_url("https://a/revoke")
            .with_userinfo_url("https://a/user");
        let ep2 = ProviderEndpoints::new("https://a/auth", "https://a/tok")
            .with_userinfo_url("https://a/user")
            .with_revocation_url("https://a/revoke");
        assert_eq!(ep1.revocation_url, ep2.revocation_url);
        assert_eq!(ep1.userinfo_url, ep2.userinfo_url);
    }

    #[test]
    fn test_google_authorization_url_exact() {
        let config = OAuthProvider::Google.oauth2_config("id", "sec").unwrap();
        assert_eq!(
            config.authorization_url,
            "https://accounts.google.com/o/oauth2/v2/auth"
        );
    }

    #[test]
    fn test_google_token_url_exact() {
        let config = OAuthProvider::Google.oauth2_config("id", "sec").unwrap();
        assert_eq!(config.token_url, "https://oauth2.googleapis.com/token");
    }

    #[test]
    fn test_github_authorization_url_exact() {
        let config = OAuthProvider::GitHub.oauth2_config("id", "sec").unwrap();
        assert_eq!(
            config.authorization_url,
            "https://github.com/login/oauth/authorize"
        );
    }

    #[test]
    fn test_github_token_url_exact() {
        let config = OAuthProvider::GitHub.oauth2_config("id", "sec").unwrap();
        assert_eq!(
            config.token_url,
            "https://github.com/login/oauth/access_token"
        );
    }

    #[test]
    fn test_spotify_urls_exact() {
        let config = OAuthProvider::Spotify.oauth2_config("id", "sec").unwrap();
        assert_eq!(
            config.authorization_url,
            "https://accounts.spotify.com/authorize"
        );
        assert_eq!(config.token_url, "https://accounts.spotify.com/api/token");
    }

    #[test]
    fn test_discord_urls_exact() {
        let config = OAuthProvider::Discord.oauth2_config("id", "sec").unwrap();
        assert_eq!(
            config.authorization_url,
            "https://discord.com/oauth2/authorize"
        );
        assert_eq!(config.token_url, "https://discord.com/api/oauth2/token");
    }

    #[test]
    fn test_microsoft_urls_contain_common_tenant() {
        let config = OAuthProvider::Microsoft.oauth2_config("id", "sec").unwrap();
        assert!(config.authorization_url.contains("/common/"));
        assert!(config.token_url.contains("/common/"));
    }

    #[test]
    fn test_dropbox_urls_exact() {
        let config = OAuthProvider::Dropbox.oauth2_config("id", "sec").unwrap();
        assert_eq!(
            config.authorization_url,
            "https://www.dropbox.com/oauth2/authorize"
        );
        assert_eq!(config.token_url, "https://api.dropboxapi.com/oauth2/token");
    }

    // ── New batch: ProviderEndpoints advanced ──

    #[test]
    fn test_provider_endpoints_unicode_urls() {
        let endpoints = ProviderEndpoints::new(
            "https://auth.\u{00e9}xample.com/authorize",
            "https://auth.\u{00e9}xample.com/token",
        );
        assert!(endpoints.authorization_url.contains('\u{00e9}'));
    }

    #[test]
    fn test_provider_endpoints_to_oauth2_config_has_defaults() {
        let endpoints = ProviderEndpoints::new("https://a.com/auth", "https://a.com/token");
        let config = endpoints.to_oauth2_config("cid", "csec").unwrap();
        // Should have all default values for non-URL fields
        assert!(config.use_pkce);
        assert_eq!(config.pkce_method, PkceMethod::S256);
        assert!(config.default_scopes.is_empty());
        assert!(config.redirect_uri.is_none());
    }

    #[test]
    fn test_provider_endpoints_revocation_url_overwrite() {
        let endpoints = ProviderEndpoints::new("https://a.com/auth", "https://a.com/token")
            .with_revocation_url("https://a.com/revoke1")
            .with_revocation_url("https://a.com/revoke2");
        assert_eq!(
            endpoints.revocation_url,
            Some("https://a.com/revoke2".to_string())
        );
    }

    #[test]
    fn test_provider_endpoints_userinfo_url_overwrite() {
        let endpoints = ProviderEndpoints::new("https://a.com/auth", "https://a.com/token")
            .with_userinfo_url("https://a.com/user1")
            .with_userinfo_url("https://a.com/user2");
        assert_eq!(
            endpoints.userinfo_url,
            Some("https://a.com/user2".to_string())
        );
    }

    // ── New batch: OAuthProvider all-variants exhaustive ──

    #[test]
    fn test_all_providers_not_equal_to_each_other() {
        let all = [
            OAuthProvider::Google,
            OAuthProvider::GitHub,
            OAuthProvider::Twitter,
            OAuthProvider::TwitterLegacy,
            OAuthProvider::Slack,
            OAuthProvider::Notion,
            OAuthProvider::Linear,
            OAuthProvider::Discord,
            OAuthProvider::Spotify,
            OAuthProvider::Microsoft,
            OAuthProvider::Dropbox,
        ];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j], "{:?} == {:?}", all[i], all[j]);
            }
        }
    }

    #[test]
    fn test_twitter_legacy_not_equal_to_twitter() {
        assert_ne!(OAuthProvider::Twitter, OAuthProvider::TwitterLegacy);
    }

    #[test]
    fn test_provider_oauth2_config_empty_credentials() {
        let config = OAuthProvider::Google.oauth2_config("", "").unwrap();
        assert!(config.client_id.is_empty());
        assert_eq!(config.client_secret, Some(String::new()));
    }

    #[test]
    fn test_provider_oauth1_config_empty_credentials() {
        let config = OAuthProvider::TwitterLegacy.oauth1_config("", "").unwrap();
        assert!(config.consumer_key.is_empty());
        assert!(config.consumer_secret.is_empty());
    }

    #[test]
    fn test_slack_config_no_extra_params() {
        let config = OAuthProvider::Slack.oauth2_config("id", "sec").unwrap();
        // Slack does not add extra auth params
        assert!(config.extra_auth_params.is_empty());
    }

    #[test]
    fn test_discord_config_no_pkce() {
        let config = OAuthProvider::Discord.oauth2_config("id", "sec").unwrap();
        assert!(!config.use_pkce);
        assert!(!OAuthProvider::Discord.requires_pkce());
    }
}
