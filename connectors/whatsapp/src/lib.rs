//! `WhatsApp` Business API connector for FCP.

#![forbid(unsafe_code)]
#![recursion_limit = "256"]

pub mod client;
pub mod connector;
pub mod error;
pub mod types;
pub mod webhook;

pub use connector::WhatsAppConnector;
pub use webhook::WhatsAppWebhook;
