//! FCP Telegram Connector library.
//!
//! Implements the Flywheel Connector Protocol for the Telegram Bot API,
//! providing message sending, polling, and event streaming.

#![forbid(unsafe_code)]
#![recursion_limit = "256"]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::collapsible_if,
    clippy::doc_markdown,
    clippy::field_reassign_with_default,
    clippy::future_not_send,
    clippy::large_enum_variant,
    clippy::manual_let_else,
    clippy::map_unwrap_or,
    clippy::missing_const_for_fn,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::option_if_let_else,
    clippy::or_fun_call,
    clippy::redundant_closure_for_method_calls,
    clippy::single_match_else,
    clippy::single_match,
    clippy::assertions_on_constants,
    clippy::match_same_arms,
    clippy::struct_field_names,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async,
    clippy::use_self,
    clippy::wildcard_imports
)]

pub mod client;
pub mod connector;
pub mod error;
pub mod limits;
pub mod types;
