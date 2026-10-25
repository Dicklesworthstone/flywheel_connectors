#![forbid(unsafe_code)]
#![recursion_limit = "256"]
#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::option_if_let_else,
    clippy::struct_field_names,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unreadable_literal
)]

pub mod client;
pub mod connector;
pub mod error;
pub mod event_stream;
pub mod types;
