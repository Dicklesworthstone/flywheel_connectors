//! Coda document platform connector for FCP.

#![forbid(unsafe_code)]
#![recursion_limit = "256"]

pub mod client;
pub mod connector;
pub mod error;
pub mod types;

pub use connector::CodaConnector;
