//! FCP Webhook - Production webhook handling library
//!
//! This crate provides comprehensive webhook support:
//!
//! - **Signature Verification**: HMAC-SHA256, HMAC-SHA1, Ed25519
//! - **Provider Support**: GitHub, Stripe, Slack, Linear, Discord
//! - **Event Processing**: Type routing, filtering, priority queues
//! - **Delivery Management**: Idempotency, retries, dead letter queues
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use fcp_webhook::{WebhookHandler, GitHubSignature};
//!
//! // Create a webhook handler for GitHub
//! let handler = WebhookHandler::new(GitHubSignature::new("webhook_secret"));
//!
//! // Verify and process incoming webhook
//! let event = handler.verify_and_parse(headers, body).await?;
//! ```

#![forbid(unsafe_code)]
// Lint groups come from [workspace.lints.clippy]; duplicating them here would
// override that table and defeat its allow entries.
#![allow(clippy::module_name_repetitions)]

mod error;
mod event;
mod handler;
mod provider;
mod signature;

pub use error::*;
pub use event::*;
pub use handler::*;
pub use provider::*;
pub use signature::*;

use std::time::Duration;

/// Parse an environment variable, falling back to a default if unset or unparseable.
fn env_or<T: std::str::FromStr>(var: &str, default: T) -> T {
    std::env::var(var)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Default timestamp tolerance for replay protection.
pub const DEFAULT_TIMESTAMP_TOLERANCE: Duration = Duration::from_secs(300); // 5 minutes

/// Default maximum payload size.
pub const DEFAULT_MAX_PAYLOAD_SIZE: usize = 5 * 1024 * 1024; // 5MB

/// Compute the timestamp tolerance, allowing override via `FCP_WEBHOOK_TIMESTAMP_TOLERANCE_SECS`.
///
/// Falls back to [`DEFAULT_TIMESTAMP_TOLERANCE`] (300 s) when the variable is unset.
#[must_use]
pub fn default_timestamp_tolerance() -> Duration {
    Duration::from_secs(env_or("FCP_WEBHOOK_TIMESTAMP_TOLERANCE_SECS", 300))
}

/// Compute the maximum payload size, allowing override via `FCP_WEBHOOK_MAX_PAYLOAD_BYTES`.
///
/// Falls back to [`DEFAULT_MAX_PAYLOAD_SIZE`] (5 MiB) when the variable is unset.
#[must_use]
pub fn default_max_payload_size() -> usize {
    env_or("FCP_WEBHOOK_MAX_PAYLOAD_BYTES", 5 * 1024 * 1024)
}
