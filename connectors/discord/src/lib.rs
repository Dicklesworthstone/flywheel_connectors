//! FCP Discord Connector
//!
//! A Flywheel Connector Protocol implementation for the Discord Bot API.
//!
//! This connector implements the Bidirectional archetype, supporting:
//! - Sending messages, embeds, files
//! - Receiving events via Gateway WebSocket
//! - Managing channels, roles, and members
//! - Slash commands and interactions
//!
//! Based on clawdbot's Discord integration patterns.

#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]
#![allow(dead_code)] // Connector API types/methods wired incrementally
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::float_cmp,
    clippy::future_not_send,
    clippy::large_enum_variant,
    clippy::map_unwrap_or,
    clippy::match_same_arms,
    clippy::match_wildcard_for_single_variants,
    clippy::missing_errors_doc,
    clippy::option_if_let_else,
    clippy::or_fun_call,
    clippy::redundant_closure_for_method_calls,
    clippy::assertions_on_constants,
    clippy::struct_field_names,
    clippy::too_many_lines,
    clippy::unnecessary_wraps,
    clippy::unreadable_literal,
    clippy::unused_async,
    clippy::unused_async_trait_impl,
    clippy::wildcard_imports
)]

mod api;
pub mod client;
mod config;
mod connector;
mod error;
mod gateway;
pub mod limits;
pub mod types;

pub use client::DiscordClient;
pub use config::DiscordConfig;
pub use connector::DiscordConnector;
pub use error::DiscordError;

// Re-export for integration tests
pub use api::DiscordApiClient;

/// Fuzz-only entry points for Discord REST response parsers.
///
/// Exposed for `fuzz_discord_rest_error_response` so the fuzz crate can drive
/// the private parser boundary without constructing an HTTP client.
///
/// Bead flywheel_connectors-h5124.
#[doc(hidden)]
pub mod __fuzz {
    use crate::{
        api::{parse_api_error_response, parse_rate_limit_retry_after_seconds},
        error::DiscordError,
    };

    /// Parse a raw Discord API error body with a caller-supplied HTTP status.
    #[must_use]
    pub fn parse_rest_api_error_response(status_code: u16, body: &[u8]) -> DiscordError {
        parse_api_error_response(status_code, body)
    }

    /// Parse a Discord rate-limit delay from an optional header and raw body.
    #[must_use]
    pub fn parse_rest_retry_after_seconds(header_value: Option<&str>, body: &[u8]) -> f64 {
        parse_rate_limit_retry_after_seconds(header_value, body)
    }
}
