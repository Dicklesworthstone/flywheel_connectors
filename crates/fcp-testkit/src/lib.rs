//! FCP Test Kit - Testing framework and mock infrastructure for FCP connectors
//!
//! This crate provides comprehensive testing utilities for building and testing
//! FCP connectors, including:
//!
//! - [`ConnectorTestHarness`] - A test harness that wraps connectors with assertions
//! - [`MockApiServer`] - HTTP mock server with request/response recording
//! - [`HttpFixtureServer`] - Real local HTTP fixture server for non-mock acceptance tests
//! - [`AsyncTestContext`] + async helpers for deterministic run/scenario correlation
//! - Test fixtures for common FCP types
//! - Assertion helpers for FCP responses
//! - Tracing configuration for test output
//!
//! # Example
//!
//! ```rust,ignore
//! use fcp_testkit::{AsyncTestContext, ConnectorTestHarness, MockApiServer, fixtures};
//!
//! #[fcp_async_core::runtime::test]
//! async fn test_my_connector() {
//!     // Initialize test tracing
//!     fcp_testkit::init_test_tracing();
//!     let scenario = AsyncTestContext::for_scenario("my_connector.happy_path");
//!
//!     // Create a mock server
//!     let mock = MockApiServer::start().await;
//!
//!     // Set up expected responses
//!     mock.expect_json("/api/messages", serde_json::json!({
//!         "messages": []
//!     })).await;
//!
//!     // Create your connector and wrap it
//!     let connector = MyConnector::new(mock.base_url());
//!     let mut harness = ConnectorTestHarness::new(connector);
//!
//!     // Configure
//!     harness.configure(fixtures::config::api_key("test-key")).await.unwrap();
//!     harness.assert_last_success();
//!
//!     // Verify health
//!     let health = harness.health().await;
//!     assert!(health.is_ready());
//!     assert!(!scenario.correlation_id().is_empty());
//! }
//! ```

#![forbid(unsafe_code)]
// Lint groups come from [workspace.lints.clippy]; duplicating them here would
// override that table and defeat its allow entries.
#![allow(clippy::module_name_repetitions)]

mod assertions;
mod async_harness;
pub mod bridge_helpers;
pub mod coverage_rules;
pub mod database_helpers;
pub mod differential;
pub mod differential_scrub;
pub mod evidence_helpers;
pub mod fixtures;
mod harness;
mod http_fixture;
pub mod live_suite;
pub mod local_mesh;
mod log_scan;
mod mock_server;
pub mod mutation;
pub mod mutation_kinds;
pub mod provider_contract;
pub mod readiness_helpers;
pub mod redacted_replay_bundle;
pub mod secret_taint;
pub mod secretless_replay;
pub mod session_script;
pub mod streaming_fixture;
pub mod supervisor_examples;
mod tracing_config;
pub mod webhook_helpers;

pub use assertions::*;
pub use async_harness::*;
pub use differential::*;
pub use differential_scrub::*;
pub use harness::*;
pub use http_fixture::*;
pub use log_scan::*;
pub use mock_server::*;
pub use mutation::*;
pub use mutation_kinds::*;
pub use secret_taint::*;
pub use secretless_replay::*;
pub use supervisor_examples::*;
pub use tracing_config::*;

// Re-export SDK-owned connector surface for convenience.
pub use fcp_sdk::{FcpConnector, FcpError, FcpResult, HealthSnapshot, HealthState};
