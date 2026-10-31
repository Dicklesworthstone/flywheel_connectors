//! Discord connector configuration.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use url::{Host, Url};

use crate::error::{DiscordError, DiscordResult};

/// Configuration for the Discord connector.
#[derive(Clone, Serialize, Deserialize)]
pub struct DiscordConfig {
    /// Bot credential from Discord Developer Portal
    pub bot_credential: String,

    /// Application ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_id: Option<String>,

    /// Base URL for the Discord API (default: <https://discord.com/api/v10>)
    #[serde(default = "default_api_url")]
    pub api_url: String,

    /// Gateway URL (usually auto-detected)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_url: Option<String>,

    /// Request timeout
    #[serde(default = "default_timeout", with = "duration_secs")]
    pub timeout: Duration,

    /// Retry configuration
    #[serde(default)]
    pub retry: RetryConfig,

    /// Gateway intents
    #[serde(default = "default_intents")]
    pub intents: u64,

    /// Shard configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shard: Option<ShardConfig>,

    /// Discord gateway identify `max_concurrency` bucket count.
    ///
    /// Defaults to 1 unless the operator supplies the value from Discord's
    /// gateway bot metadata; this fails safe by serializing IDENTIFY frames.
    #[serde(default = "default_gateway_identify_max_concurrency")]
    pub gateway_identify_max_concurrency: u32,

    /// Minimum spacing between IDENTIFY frames in the same concurrency bucket,
    /// in milliseconds. Defaults to Discord's documented 5 s.
    ///
    /// Exposed as configuration rather than a `#[cfg(test)]` constant because
    /// `cfg(test)` does NOT apply to integration tests: those link the library
    /// built without it, so a shortened test-only window silently has no effect
    /// there. Loopback gateway tests set this low explicitly (br-x13q4).
    #[serde(default = "default_gateway_identify_window_ms")]
    pub gateway_identify_window_ms: u64,
}

impl DiscordConfig {
    /// Validate a configured, discovered, or persisted Gateway endpoint before
    /// sending an IDENTIFY or RESUME credential to it.
    pub(crate) fn validate_gateway_url(&self, raw: &str) -> DiscordResult<Url> {
        let url = parse_gateway_base_url(raw).ok_or_else(invalid_gateway_url)?;
        let official_gateway = url.scheme() == "wss"
            && url.port_or_known_default() == Some(443)
            && url.host_str().is_some_and(is_discord_gateway_host);
        // A provider response cannot authorize a new local destination. Debug
        // fixtures must explicitly configure the exact literal-IP origin first.
        let local_fixture = (cfg!(test) || cfg!(debug_assertions))
            && matches!(url.scheme(), "ws" | "wss")
            && match url.host() {
                Some(Host::Ipv4(address)) => address.is_loopback(),
                Some(Host::Ipv6(address)) => address.is_loopback(),
                _ => false,
            }
            && self
                .gateway_url
                .as_deref()
                .and_then(parse_gateway_base_url)
                .is_some_and(|configured| {
                    configured.scheme() == url.scheme()
                        && configured.host() == url.host()
                        && configured.port_or_known_default() == url.port_or_known_default()
                });
        if official_gateway || local_fixture {
            Ok(url)
        } else {
            Err(invalid_gateway_url())
        }
    }
}

fn parse_gateway_base_url(raw: &str) -> Option<Url> {
    if raw.len() > 2048
        || raw.trim() != raw
        || raw.chars().any(char::is_control)
        || raw.contains('@')
    {
        return None;
    }
    let url = Url::parse(raw).ok()?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return None;
    }
    Some(url)
}

fn is_discord_gateway_host(host: &str) -> bool {
    let Some(label) = host.strip_suffix(".discord.gg") else {
        return false;
    };
    label == "gateway"
        || label.strip_prefix("gateway-").is_some_and(|region| {
            !region.is_empty()
                && label.len() <= 63
                && !region.starts_with('-')
                && !region.ends_with('-')
                && region
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn invalid_gateway_url() -> DiscordError {
    // Never echo a rejected URL: it may carry a credential or capability value.
    DiscordError::InvalidInput(
        "Discord Gateway URL rejected: require a root WSS URL on port 443 at gateway.discord.gg or a regional gateway-*.discord.gg host; local test endpoints must match the explicitly configured literal-loopback origin".into(),
    )
}

impl std::fmt::Debug for DiscordConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiscordConfig")
            .field("bot_credential", &"[REDACTED]")
            .field("application_id", &self.application_id)
            .field("api_url", &self.api_url)
            .field("gateway_url", &self.gateway_url)
            .field("timeout", &self.timeout)
            .field("retry", &self.retry)
            .field("intents", &self.intents)
            .field("shard", &self.shard)
            .field(
                "gateway_identify_max_concurrency",
                &self.gateway_identify_max_concurrency,
            )
            .field(
                "gateway_identify_window_ms",
                &self.gateway_identify_window_ms,
            )
            .finish()
    }
}

fn default_api_url() -> String {
    "https://discord.com/api/v10".into()
}

const fn default_timeout() -> Duration {
    Duration::from_secs(30)
}

const fn default_intents() -> u64 {
    // Default intents: Guilds, GuildMessages, MessageContent, DirectMessages
    (1 << 0) | (1 << 9) | (1 << 15) | (1 << 12)
}

const fn default_gateway_identify_max_concurrency() -> u32 {
    1
}

/// Discord documents a 5 s minimum between IDENTIFY frames per bucket.
const fn default_gateway_identify_window_ms() -> u64 {
    5_000
}

mod duration_secs {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        duration.as_secs().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = u64::deserialize(deserializer)?;
        Ok(Duration::from_secs(secs))
    }
}

/// Retry configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum retry attempts
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,

    /// Initial delay between retries in milliseconds
    #[serde(default = "default_initial_delay_ms")]
    pub initial_delay_ms: u64,

    /// Maximum delay between retries in milliseconds
    #[serde(default = "default_max_delay_ms")]
    pub max_delay_ms: u64,

    /// Jitter factor (0.0-1.0)
    #[serde(default = "default_jitter")]
    pub jitter: f64,
}

const fn default_max_attempts() -> u32 {
    3
}

const fn default_initial_delay_ms() -> u64 {
    500
}

const fn default_max_delay_ms() -> u64 {
    30_000
}

const fn default_jitter() -> f64 {
    0.1
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: default_max_attempts(),
            initial_delay_ms: default_initial_delay_ms(),
            max_delay_ms: default_max_delay_ms(),
            jitter: default_jitter(),
        }
    }
}

/// Shard configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardConfig {
    /// Shard ID
    pub shard_id: u32,

    /// Total number of shards
    pub shard_count: u32,
}

impl Default for DiscordConfig {
    fn default() -> Self {
        Self {
            bot_credential: String::new(),
            application_id: None,
            api_url: default_api_url(),
            gateway_url: None,
            timeout: default_timeout(),
            retry: RetryConfig::default(),
            intents: default_intents(),
            shard: None,
            gateway_identify_max_concurrency: default_gateway_identify_max_concurrency(),
            gateway_identify_window_ms: default_gateway_identify_window_ms(),
        }
    }
}

#[cfg(test)]
mod gateway_endpoint_tests {
    use super::*;

    #[test]
    fn official_gateway_urls_allow_canonical_and_regional_resume_hosts() {
        let config = DiscordConfig::default();
        for raw in [
            "wss://gateway.discord.gg",
            "wss://gateway.discord.gg/",
            "wss://gateway.discord.gg:443/",
            "wss://GATEWAY.DISCORD.GG/",
            "wss://gateway-us-east1-b.discord.gg",
            "wss://gateway-eu-central1-b.discord.gg/",
        ] {
            let mut url = config
                .validate_gateway_url(raw)
                .expect("valid Discord Gateway");
            url.query_pairs_mut()
                .append_pair("v", "10")
                .append_pair("encoding", "json");
            assert_eq!(url.path(), "/");
            assert_eq!(url.query(), Some("v=10&encoding=json"));
        }
    }

    #[test]
    fn gateway_urls_reject_unapproved_origins_and_hidden_components_without_echoing_them() {
        let config = DiscordConfig::default();
        for raw in [
            "https://gateway.discord.gg/",
            "ws://gateway.discord.gg/",
            "wss://gateway.discord.gg:444/",
            "wss://discord.gg/",
            "wss://discord.com/",
            "wss://api.discord.gg/",
            "wss://gateway.discord.gg.attacker.invalid/",
            "wss://gateway-east.extra.discord.gg/",
            "wss://gateway-.discord.gg/",
            "wss://gateway--east.discord.gg/",
            "wss://gateway-east-.discord.gg/",
            "wss://gateway.discord.gg/private",
            "wss://gateway.discord.gg//",
            "wss://gateway.discord.gg/?capability=private-secret",
            "wss://gateway.discord.gg/#private-secret",
            "wss://private-secret@gateway.discord.gg/",
            "wss://@gateway.discord.gg/",
            "wss://user:private-secret@gateway.discord.gg/",
            "wss://gateway.dis\ncord.gg/",
            " wss://gateway.discord.gg/",
            "wss://gateway.discord.gg/\n",
            "ws://127.0.0.1:8765/",
            "wss://[::1]:8765/",
            "ws://localhost:8765/",
        ] {
            let error = config
                .validate_gateway_url(raw)
                .expect_err("must reject endpoint");
            assert!(!error.is_retryable());
            assert!(!error.to_string().contains("private-secret"));
            assert!(!error.to_string().contains("attacker.invalid"));
        }
        assert!(
            config
                .validate_gateway_url(&format!("wss://gateway-{}.discord.gg", "a".repeat(2048)))
                .is_err()
        );
    }

    #[test]
    fn local_gateway_exception_requires_exact_explicit_literal_ip_origin() {
        for (configured, equivalent) in [
            ("ws://127.0.0.1:8765", "ws://127.0.0.1:8765/"),
            ("ws://[::1]:8765/", "ws://[0:0:0:0:0:0:0:1]:8765/"),
            ("wss://127.0.0.1:443/", "wss://127.0.0.1/"),
        ] {
            let config = DiscordConfig {
                gateway_url: Some(configured.into()),
                ..DiscordConfig::default()
            };
            config
                .validate_gateway_url(equivalent)
                .expect("same parsed local origin");
            for other in [
                "ws://127.0.0.1:8766/",
                "ws://127.0.0.2:8765/",
                "wss://127.0.0.1:8765/",
                "ws://localhost:8765/",
                "ws://192.0.2.1:8765/",
            ] {
                assert!(
                    config.validate_gateway_url(other).is_err(),
                    "unapproved origin {other}"
                );
            }
        }
        let config = DiscordConfig {
            gateway_url: Some("ws://localhost:8765/".into()),
            ..DiscordConfig::default()
        };
        assert!(config.validate_gateway_url("ws://localhost:8765/").is_err());
        assert!(config.validate_gateway_url("ws://127.0.0.1:8765/").is_err());
        let config = DiscordConfig {
            gateway_url: Some("ws://127.0.0.1:8765/?private-secret".into()),
            ..DiscordConfig::default()
        };
        assert!(config.validate_gateway_url("ws://127.0.0.1:8765/").is_err());
    }
}
