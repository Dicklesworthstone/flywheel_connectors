//! FCP Twitter/X Connector
//!
//! A Flywheel Connector Protocol implementation for the Twitter/X API.
//!
//! This connector implements three archetypes:
//! - Operational: REST actions (search, post, etc.)
//! - Streaming: Filtered stream ingestion
//! - Bidirectional: Read + publish workflows
//!
//! ## Capabilities
//!
//! ### Read Operations (Safe)
//! - `twitter.read.public` - Search and public tweets
//! - `twitter.read.account` - Timelines, mentions
//! - `twitter.read.dms` - Direct message inbox (Risky)
//!
//! ### Write Operations (Dangerous)
//! - `twitter.write.tweets` - Create, reply, thread, delete
//! - `twitter.write.dms` - Send direct messages
//!
//! ### Streaming (Safe)
//! - `twitter.stream.read` - Filtered stream ingestion

#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]
#![allow(dead_code)] // Connector API types/methods wired incrementally
#![allow(
    clippy::cast_possible_truncation,
    clippy::format_collect,
    clippy::future_not_send,
    clippy::large_enum_variant,
    clippy::map_unwrap_or,
    clippy::match_same_arms,
    clippy::missing_errors_doc,
    clippy::option_if_let_else,
    clippy::or_fun_call,
    clippy::struct_field_names,
    clippy::too_many_lines,
    clippy::unused_async,
    clippy::unused_async_trait_impl,
    clippy::wildcard_imports
)]

mod client;
mod config;
mod connector;
mod error;
pub mod limits;
mod oauth;
mod stream;
pub mod streaming;
mod types;

pub use client::TwitterAuth;
pub use config::TwitterConfig;
pub use connector::TwitterConnector;
pub use error::TwitterError;

#[cfg(test)]
mod tests {
    use fcp_manifest::ConnectorManifest;
    use std::path::PathBuf;

    #[test]
    fn manifest_interface_hash_is_deterministic() {
        let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("manifest.toml");
        if !manifest_path.exists() {
            eprintln!("manifest.toml missing; skipping interface_hash check");
            return;
        }
        let raw = std::fs::read_to_string(&manifest_path).expect("read manifest");

        let manifest = ConnectorManifest::parse_str(&raw).expect("manifest should validate");
        let computed = manifest
            .compute_interface_hash()
            .expect("compute interface hash");
        assert_eq!(manifest.manifest.interface_hash, computed);

        let manifest2 = ConnectorManifest::parse_str_unchecked(&raw).expect("parse unchecked");
        let computed2 = manifest2
            .compute_interface_hash()
            .expect("compute interface hash");
        assert_eq!(computed, computed2);
    }

    #[test]
    fn manifest_has_expected_connector_id() {
        let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("manifest.toml");
        let raw = std::fs::read_to_string(&manifest_path).expect("read manifest");
        let manifest = ConnectorManifest::parse_str(&raw).expect("manifest should validate");

        assert_eq!(manifest.connector.id.as_str(), "fcp.twitter");
    }

    #[test]
    fn manifest_declares_operations() {
        let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("manifest.toml");
        let raw = std::fs::read_to_string(&manifest_path).expect("read manifest");
        let manifest = ConnectorManifest::parse_str(&raw).expect("manifest should validate");

        let ops = &manifest.provides.operations;
        assert!(
            !ops.is_empty(),
            "manifest should declare at least one operation"
        );

        // Spot-check key operations exist
        assert!(
            ops.contains_key("twitter.tweet.search"),
            "manifest missing twitter.tweet.search"
        );
        assert!(
            ops.contains_key("twitter.tweet.create"),
            "manifest missing twitter.tweet.create"
        );
        assert!(
            ops.contains_key("twitter.stream.rules.add"),
            "manifest missing twitter.stream.rules.add"
        );
    }

    #[test]
    fn manifest_zones_configured() {
        let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("manifest.toml");
        let raw = std::fs::read_to_string(&manifest_path).expect("read manifest");
        let manifest = ConnectorManifest::parse_str(&raw).expect("manifest should validate");

        assert_eq!(manifest.zones.home.as_str(), "z:work");
        assert!(
            manifest
                .zones
                .forbidden
                .iter()
                .any(|z| z.as_str() == "z:public")
        );
    }

    #[test]
    fn manifest_has_required_capabilities() {
        let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("manifest.toml");
        let raw = std::fs::read_to_string(&manifest_path).expect("read manifest");
        let manifest = ConnectorManifest::parse_str(&raw).expect("manifest should validate");

        let required = &manifest.capabilities.required;
        assert!(
            required.iter().any(|c| c.as_str() == "network.egress"),
            "manifest should require network.egress"
        );
        assert!(
            required.iter().any(|c| c.as_str() == "network.tls.sni"),
            "manifest should require network.tls.sni"
        );
    }
}

#[cfg(test)]
mod connector_unit_tests {
    use super::*;
    use fcp_prelude::FcpError;
    use serde_json::json;

    fn make_connector() -> TwitterConnector {
        TwitterConnector::new()
    }

    // ── Schema completeness tests ────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn introspect_all_ops_have_input_and_output_schema() {
        let connector = make_connector();
        let result = connector.handle_introspect().await.expect("introspect");
        let ops = result["operations"].as_array().expect("operations array");

        for op in ops {
            let op_id = op["id"].as_str().unwrap_or("<missing>");
            assert!(
                op.get("input_schema").is_some(),
                "{op_id} missing input_schema"
            );
            assert!(
                op.get("output_schema").is_some(),
                "{op_id} missing output_schema"
            );
            assert_eq!(
                op["input_schema"]["type"].as_str(),
                Some("object"),
                "{op_id} input_schema type should be object"
            );
            assert_eq!(
                op["output_schema"]["type"].as_str(),
                Some("object"),
                "{op_id} output_schema type should be object"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn introspect_operation_ids_are_deterministic() {
        let c1 = make_connector();
        let c2 = make_connector();

        let r1 = c1.handle_introspect().await.expect("introspect 1");
        let r2 = c2.handle_introspect().await.expect("introspect 2");

        let ids1: Vec<&str> = r1["operations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o["id"].as_str().unwrap())
            .collect();
        let ids2: Vec<&str> = r2["operations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o["id"].as_str().unwrap())
            .collect();

        assert_eq!(
            ids1, ids2,
            "operation IDs should be deterministic across instances"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn introspect_op_count_matches_dispatch() {
        let connector = make_connector();
        let result = connector.handle_introspect().await.expect("introspect");
        let ops = result["operations"].as_array().expect("operations array");

        // dispatch_operation handles exactly 21 operation IDs
        assert_eq!(
            ops.len(),
            21,
            "introspect should declare exactly 21 operations"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn introspect_no_duplicate_operation_ids() {
        let connector = make_connector();
        let result = connector.handle_introspect().await.expect("introspect");
        let ops = result["operations"].as_array().expect("operations array");

        let mut seen = std::collections::HashSet::new();
        for op in ops {
            let id = op["id"].as_str().unwrap();
            assert!(seen.insert(id), "duplicate operation ID: {id}");
        }
    }

    // ── Introspection metadata tests ─────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn introspect_all_ops_have_required_metadata() {
        let connector = make_connector();
        let result = connector.handle_introspect().await.expect("introspect");
        let ops = result["operations"].as_array().expect("operations array");

        for op in ops {
            let id = op["id"].as_str().unwrap_or("<missing>");
            assert!(op.get("summary").is_some(), "{id} missing summary");
            assert!(op.get("risk_level").is_some(), "{id} missing risk_level");
            assert!(op.get("safety_tier").is_some(), "{id} missing safety_tier");
            assert!(op.get("capability").is_some(), "{id} missing capability");
            assert!(op.get("ai_hints").is_some(), "{id} missing ai_hints");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn introspect_valid_risk_levels() {
        let connector = make_connector();
        let result = connector.handle_introspect().await.expect("introspect");
        let ops = result["operations"].as_array().expect("operations array");

        let valid = ["low", "medium", "high", "critical"];
        for op in ops {
            let id = op["id"].as_str().unwrap();
            let risk = op["risk_level"].as_str().unwrap();
            assert!(valid.contains(&risk), "{id} has invalid risk_level: {risk}");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn introspect_valid_safety_tiers() {
        let connector = make_connector();
        let result = connector.handle_introspect().await.expect("introspect");
        let ops = result["operations"].as_array().expect("operations array");

        let valid = ["safe", "risky", "dangerous"];
        for op in ops {
            let id = op["id"].as_str().unwrap();
            let tier = op["safety_tier"].as_str().unwrap();
            assert!(
                valid.contains(&tier),
                "{id} has invalid safety_tier: {tier}"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn introspect_agent_hints_have_when_to_use() {
        let connector = make_connector();
        let result = connector.handle_introspect().await.expect("introspect");
        let ops = result["operations"].as_array().expect("operations array");

        for op in ops {
            let id = op["id"].as_str().unwrap();
            let hint = &op["ai_hints"];
            let when = hint["when_to_use"].as_str().unwrap_or("");
            assert!(!when.is_empty(), "{id} has empty ai_hints.when_to_use");
        }
    }

    // ── Required field validation via schema ──────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn introspect_required_fields_declared() {
        let connector = make_connector();
        let result = connector.handle_introspect().await.expect("introspect");
        let ops = result["operations"].as_array().expect("operations array");

        let expected_required: &[(&str, &[&str])] = &[
            ("twitter.user.get", &["user_id"]),
            ("twitter.user.by_username", &["username"]),
            ("twitter.tweet.get", &["tweet_id"]),
            ("twitter.tweet.get_many", &["tweet_ids"]),
            ("twitter.tweet.search", &["query"]),
            ("twitter.user.timeline", &["user_id"]),
            ("twitter.tweet.retweet", &["tweet_id"]),
            ("twitter.tweet.unretweet", &["tweet_id"]),
            ("twitter.tweet.like", &["tweet_id"]),
            ("twitter.tweet.unlike", &["tweet_id"]),
            ("twitter.tweet.create", &["text"]),
            ("twitter.tweet.reply", &["text", "reply_to"]),
            ("twitter.tweet.delete", &["tweet_id"]),
            ("twitter.stream.rules.add", &["rules"]),
            ("twitter.stream.rules.delete", &["rule_ids"]),
            ("twitter.dm.send", &["text"]),
            ("twitter.dm.events", &["conversation_id"]),
        ];

        for (op_id, required_fields) in expected_required {
            let op = ops
                .iter()
                .find(|o| o["id"].as_str() == Some(op_id))
                .unwrap_or_else(|| panic!("missing operation {op_id}"));
            let schema = &op["input_schema"];
            let req = schema["required"]
                .as_array()
                .unwrap_or_else(|| panic!("{op_id} missing required array"));
            for field in *required_fields {
                assert!(
                    req.iter().any(|r| r.as_str() == Some(field)),
                    "{op_id} missing required field '{field}'"
                );
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn introspect_unknown_op_not_present() {
        let connector = make_connector();
        let result = connector.handle_introspect().await.expect("introspect");
        let ops = result["operations"].as_array().expect("operations array");

        assert!(
            !ops.iter()
                .any(|o| o["id"].as_str() == Some("twitter.unknown.op")),
            "unknown operation should not be declared"
        );
    }

    // ── Redaction tests ──────────────────────────────────────────────────

    #[test]
    fn auth_redacted_label_hides_oauth_secrets() {
        let auth = TwitterAuth::OAuth {
            consumer_key: "ABCDEFGHIJ".into(),
            consumer_secret: "secret".into(),
            access_token: "token".into(),
            access_token_secret: "secret".into(),
            bearer_token: None,
        };
        let label = auth.redacted_label();
        assert!(
            label.starts_with("oauth:ABCD"),
            "label should show 4-char prefix"
        );
        assert!(label.ends_with("..."), "label should end with ...");
        assert!(!label.contains("secret"), "label must not contain secret");
    }

    #[test]
    fn auth_credential_id_redacted_label() {
        let auth = TwitterAuth::CredentialId(
            fcp_core::CredentialId::parse("550e8400-e29b-41d4-a716-446655440000")
                .expect("valid UUID"),
        );
        let label = auth.redacted_label();
        assert!(label.starts_with("credential:"), "credential_id label");
    }

    #[test]
    fn auth_is_secretless_flags() {
        let oauth = TwitterAuth::OAuth {
            consumer_key: "k".into(),
            consumer_secret: "s".into(),
            access_token: "t".into(),
            access_token_secret: "ts".into(),
            bearer_token: None,
        };
        assert!(!oauth.is_secretless());

        let cred = TwitterAuth::CredentialId(
            fcp_core::CredentialId::parse("550e8400-e29b-41d4-a716-446655440000")
                .expect("valid UUID"),
        );
        assert!(cred.is_secretless());
    }

    // ── Doctor tests ─────────────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn doctor_unconfigured_has_failures() {
        let connector = make_connector();
        let result = connector.handle_doctor().await.expect("doctor");

        assert_eq!(result["status"].as_str(), Some("fail"));
        let checks = result["checks"].as_array().expect("checks array");
        assert!(checks.len() >= 6, "doctor should have at least 6 checks");

        let config_check = checks
            .iter()
            .find(|c| c["name"].as_str() == Some("configuration"))
            .expect("configuration check");
        assert_eq!(config_check["status"].as_str(), Some("fail"));
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_configured_has_pass_or_warn() {
        let mut connector = make_connector();
        connector
            .handle_configure(json!({
                "consumer_key": "test_key",
                "consumer_secret": "test_secret",
                "access_token": "test_token",
                "access_token_secret": "test_token_secret"
            }))
            .await
            .expect("configure");

        let result = connector.handle_doctor().await.expect("doctor");
        let status = result["status"].as_str().unwrap();
        assert!(
            status == "pass" || status == "warn",
            "configured doctor should be pass or warn, got {status}"
        );

        let checks = result["checks"].as_array().expect("checks array");
        let config_check = checks
            .iter()
            .find(|c| c["name"].as_str() == Some("configuration"))
            .expect("configuration check");
        assert_eq!(config_check["status"].as_str(), Some("pass"));
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_http_url_warns() {
        let mut connector = make_connector();
        connector
            .handle_configure(json!({
                "consumer_key": "test_key",
                "consumer_secret": "test_secret",
                "access_token": "test_token",
                "access_token_secret": "test_token_secret",
                "api_url": "http://localhost:8080"
            }))
            .await
            .expect("configure");

        let result = connector.handle_doctor().await.expect("doctor");
        let checks = result["checks"].as_array().expect("checks array");
        let url_check = checks
            .iter()
            .find(|c| c["name"].as_str() == Some("api_url_scheme"))
            .expect("api_url_scheme check");
        assert_eq!(url_check["status"].as_str(), Some("warn"));
    }

    // ── Configure validation tests ───────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn configure_rejects_credential_id_plus_oauth() {
        let mut connector = make_connector();
        let result = connector
            .handle_configure(json!({
                "credential_id": "550e8400-e29b-41d4-a716-446655440000",
                "consumer_key": "also_provided"
            }))
            .await;

        assert!(
            result.is_err(),
            "should reject both credential_id and OAuth"
        );
        let err = result.unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn configure_rejects_missing_consumer_key() {
        let mut connector = make_connector();
        let result = connector.handle_configure(json!({})).await;
        assert!(
            result.is_err(),
            "should require consumer_key or credential_id"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn configure_rejects_empty_consumer_secret() {
        let mut connector = make_connector();
        let result = connector
            .handle_configure(json!({
                "consumer_key": "key",
                "consumer_secret": "",
                "access_token": "token",
                "access_token_secret": "secret"
            }))
            .await;
        assert!(result.is_err(), "should reject empty consumer_secret");
    }

    #[fcp_async_core::runtime::test]
    async fn configure_accepts_credential_id() {
        let mut connector = make_connector();
        let result = connector
            .handle_configure(json!({
                "credential_id": "550e8400-e29b-41d4-a716-446655440000"
            }))
            .await;
        assert!(result.is_ok(), "credential_id mode should succeed");
    }

    #[fcp_async_core::runtime::test]
    async fn configure_rejects_invalid_credential_id() {
        let mut connector = make_connector();
        let result = connector
            .handle_configure(json!({
                "credential_id": "not-a-uuid"
            }))
            .await;
        assert!(result.is_err(), "invalid UUID should be rejected");
    }

    // ── Self-check tests ─────────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn self_check_not_configured_returns_failed() {
        let connector = make_connector();
        let result = connector.handle_self_check().await.expect("self_check");
        assert_eq!(result["status"].as_str(), Some("failed"));
        assert_eq!(result["reason_code"].as_str(), Some("not_configured"));
    }

    // ── Health tests ─────────────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn health_includes_stream_metrics() {
        let connector = make_connector();
        let result = connector.handle_health().await.expect("health");

        assert!(result.get("status").is_some(), "health should have status");
        assert!(
            result.get("metrics").is_some(),
            "health should have metrics"
        );
        assert!(
            result.get("stream_active").is_some(),
            "health should have stream_active"
        );
        assert!(
            result.get("stream_subscribers").is_some(),
            "health should have stream_subscribers"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn health_not_ready_when_unconfigured() {
        let connector = make_connector();
        let result = connector.handle_health().await.expect("health");
        assert_eq!(result["status"].as_str(), Some("not_ready"));
    }

    // ── Simulate tests ───────────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn simulate_denies_when_not_configured() {
        use fcp_prelude::{CapabilityToken, ConnectorId, SimulateRequest, ZoneId};

        let connector = make_connector();
        let req = SimulateRequest::new(
            ConnectorId::from_static("fcp.twitter"),
            "twitter.tweet.create".parse().unwrap(),
            ZoneId::work(),
            json!({"text": "test"}),
            CapabilityToken::test_token(),
        );
        let params = serde_json::to_value(&req).expect("serialize");
        let result = connector.handle_simulate(params).await.expect("simulate");

        assert_eq!(result["would_succeed"].as_bool(), Some(false));
        let expected_code = fcp_core::FcpError::NotConfigured.error_code();
        assert_eq!(result["denial_code"].as_str(), Some(expected_code.as_str()));
    }

    // ── Capability mapping tests ─────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn read_ops_require_read_capabilities() {
        let connector = make_connector();
        let result = connector.handle_introspect().await.expect("introspect");
        let ops = result["operations"].as_array().unwrap();

        let read_ops = [
            "twitter.user.me",
            "twitter.user.get",
            "twitter.user.by_username",
            "twitter.tweet.get",
            "twitter.tweet.get_many",
            "twitter.tweet.search",
            "twitter.user.timeline",
            "twitter.user.mentions",
            "twitter.trends.place",
        ];

        for op_id in &read_ops {
            let op = ops
                .iter()
                .find(|o| o["id"].as_str() == Some(op_id))
                .unwrap_or_else(|| panic!("missing {op_id}"));
            let cap = op["capability"].as_str().unwrap();
            assert!(
                cap.starts_with("twitter.read.") || cap.starts_with("twitter.stream."),
                "{op_id} should have read/stream capability, got {cap}"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn write_ops_require_write_capabilities() {
        let connector = make_connector();
        let result = connector.handle_introspect().await.expect("introspect");
        let ops = result["operations"].as_array().unwrap();

        let write_ops = [
            "twitter.tweet.create",
            "twitter.tweet.reply",
            "twitter.tweet.delete",
            "twitter.tweet.retweet",
            "twitter.tweet.unretweet",
            "twitter.tweet.like",
            "twitter.tweet.unlike",
            "twitter.dm.send",
        ];

        for op_id in &write_ops {
            let op = ops
                .iter()
                .find(|o| o["id"].as_str() == Some(op_id))
                .unwrap_or_else(|| panic!("missing {op_id}"));
            let cap = op["capability"].as_str().unwrap();
            assert!(
                cap.starts_with("twitter.write."),
                "{op_id} should have write capability, got {cap}"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn stream_ops_require_stream_capabilities() {
        let connector = make_connector();
        let result = connector.handle_introspect().await.expect("introspect");
        let ops = result["operations"].as_array().unwrap();

        let stream_ops = [
            "twitter.stream.rules.list",
            "twitter.stream.rules.add",
            "twitter.stream.rules.delete",
        ];

        for op_id in &stream_ops {
            let op = ops
                .iter()
                .find(|o| o["id"].as_str() == Some(op_id))
                .unwrap_or_else(|| panic!("missing {op_id}"));
            let cap = op["capability"].as_str().unwrap();
            assert_eq!(
                cap, "twitter.stream.read",
                "{op_id} should use twitter.stream.read capability"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn dm_events_requires_read_dms() {
        let connector = make_connector();
        let result = connector.handle_introspect().await.expect("introspect");
        let ops = result["operations"].as_array().unwrap();

        let op = ops
            .iter()
            .find(|o| o["id"].as_str() == Some("twitter.dm.events"))
            .expect("dm.events");
        assert_eq!(
            op["capability"].as_str(),
            Some("twitter.read.dms"),
            "dm.events should use twitter.read.dms"
        );
    }

    // ── Event capabilities tests ─────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn event_caps_streaming_enabled() {
        let connector = make_connector();
        let result = connector.handle_introspect().await.expect("introspect");
        let event_caps = &result["event_caps"];

        assert_eq!(event_caps["streaming"].as_bool(), Some(true));
        assert_eq!(event_caps["replay"].as_bool(), Some(false));
    }

    // ── Shutdown tests ───────────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn shutdown_returns_status() {
        let mut connector = make_connector();
        let result = connector
            .handle_shutdown(json!({}))
            .await
            .expect("shutdown");
        assert_eq!(result["status"].as_str(), Some("shutdown"));
    }

    // ── Read operations should be safe ───────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn read_ops_are_safe() {
        let connector = make_connector();
        let result = connector.handle_introspect().await.expect("introspect");
        let ops = result["operations"].as_array().unwrap();

        let safe_read_ops = [
            "twitter.user.me",
            "twitter.user.get",
            "twitter.user.by_username",
            "twitter.tweet.get",
            "twitter.tweet.get_many",
            "twitter.tweet.search",
            "twitter.user.timeline",
            "twitter.user.mentions",
            "twitter.trends.place",
            "twitter.stream.rules.list",
        ];

        for op_id in &safe_read_ops {
            let op = ops
                .iter()
                .find(|o| o["id"].as_str() == Some(op_id))
                .unwrap_or_else(|| panic!("missing {op_id}"));
            assert_eq!(
                op["safety_tier"].as_str(),
                Some("safe"),
                "{op_id} should have safe safety tier"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn create_delete_ops_are_dangerous() {
        let connector = make_connector();
        let result = connector.handle_introspect().await.expect("introspect");
        let ops = result["operations"].as_array().unwrap();

        let dangerous_ops = [
            "twitter.tweet.create",
            "twitter.tweet.reply",
            "twitter.tweet.delete",
            "twitter.dm.send",
        ];

        for op_id in &dangerous_ops {
            let op = ops
                .iter()
                .find(|o| o["id"].as_str() == Some(op_id))
                .unwrap_or_else(|| panic!("missing {op_id}"));
            assert_eq!(
                op["safety_tier"].as_str(),
                Some("dangerous"),
                "{op_id} should have dangerous safety tier"
            );
        }
    }
}
