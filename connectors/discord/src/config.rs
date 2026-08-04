//! Discord connector configuration.

use std::time::Duration;

use serde::{Deserialize, Serialize};

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
