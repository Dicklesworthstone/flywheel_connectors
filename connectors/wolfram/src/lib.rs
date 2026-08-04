//! FCP Wolfram Alpha Connector
//!
//! Provides computational knowledge queries via the Wolfram Alpha API.

#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(
    clippy::module_name_repetitions,
    clippy::missing_errors_doc,
    clippy::too_many_lines,
    clippy::unused_async_trait_impl
)]

pub mod client;
pub mod connector;
pub mod error;
pub mod types;

pub use connector::WolframConnector;
