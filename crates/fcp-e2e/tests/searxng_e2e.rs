//! `SearXNG` connector e2e evidence.
//!
//! The default lane is deterministic and uses loopback HTTP fixtures. Set
//! `SEARXNG_E2E_URL` to enable the optional operator-host smoke path. Evidence
//! records base-url class, query hashes, filters, result counts, and hostnames
//! only; it never records query text, snippets, full URLs, auth values, or
//! response bodies.

#![cfg(feature = "searxng")]
#![allow(clippy::too_many_lines)]

use std::io::Write as _;
use std::time::Instant;

use fcp_prelude::FcpError;
use fcp_searxng::SearxngConnector;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path, query_param},
};

const OP_QUERY: &str = "searxng.search.query";
const OP_IMAGES: &str = "searxng.search.images";

const ARTIFACT_PATH: &str = "target/fcp-searxng/searxng-e2e.jsonl";

#[fcp_async_core::runtime::test]
async fn searxng_connector_emits_redacted_e2e_evidence() {
    let mut records = Vec::new();
    run_fixture_script(&mut records).await;
    run_operator_script_or_record_skip(&mut records).await;

    let jsonl = write_jsonl_artifact(&records);
    assert!(jsonl.contains("\"provider_mode\":\"fixture\""));
    assert!(jsonl.contains("\"provider_mode\":\"operator\"") || jsonl.contains("\"skip_reason\""));
    assert!(!jsonl.contains("rust privacy"));
    assert!(!jsonl.contains("filter query"));
    assert!(!jsonl.contains("fixture snippet"));
    assert!(!jsonl.contains("https://"));
    assert_eq!(fcp_e2e::scan_log_jsonl(&jsonl).error_count, 0);
}

async fn run_fixture_script(records: &mut Vec<Value>) {
    let server = MockServer::start().await;
    mount_text_success(&server).await;
    mount_filtered_success(&server).await;
    mount_image_success(&server).await;
    mount_zero_results(&server).await;
    mount_provider_error(&server).await;
    mount_malformed_response(&server).await;
    mount_timeout_response(&server).await;

    let mut connector = configured_connector(json!({
        "base_url": server.uri(),
        "allow_loopback": true,
        "request_timeout_ms": 5_000
    }))
    .await;

    let started = Instant::now();
    let text = invoke(&connector, OP_QUERY, json!({"query": "rust privacy"}))
        .await
        .expect("fixture text search should succeed");
    records.push(evidence_record(EvidenceInput {
        provider_mode: "fixture",
        operation: OP_QUERY,
        scenario_id: "fixture_text_success",
        latency_ms: started.elapsed().as_millis(),
        http_status: Some(200),
        retry_decision: "not_needed",
        fcp_error_mapping: "ok",
        skip_reason: None,
        details: json!({
            "base_url_class": text["base_url_class"].clone(),
            "query_hash": hash_label("rust privacy"),
            "filters": {"language": text["language"].clone(), "safe_search": text["safe_search"].clone()},
            "result_count": text["count"].as_u64(),
            "result_hosts": result_hosts(&text)
        }),
    }));

    let started = Instant::now();
    let filtered = invoke(
        &connector,
        OP_QUERY,
        json!({
            "query": "filter query",
            "categories": ["general", "it"],
            "engines": "duckduckgo,brave",
            "safe_search": "off",
            "page": 2,
            "time_range": "month"
        }),
    )
    .await
    .expect("filtered fixture should succeed");
    records.push(evidence_record(EvidenceInput {
        provider_mode: "fixture",
        operation: OP_QUERY,
        scenario_id: "fixture_engine_category_filters",
        latency_ms: started.elapsed().as_millis(),
        http_status: Some(200),
        retry_decision: "not_needed",
        fcp_error_mapping: "ok",
        skip_reason: None,
        details: json!({
            "base_url_class": filtered["base_url_class"].clone(),
            "query_hash": hash_label("filter query"),
            "filters": {
                "categories": filtered["categories"].clone(),
                "engines": filtered["engines"].clone(),
                "safe_search": filtered["safe_search"].clone(),
                "time_range": filtered["time_range"].clone(),
                "page": filtered["page"].clone()
            },
            "result_count": filtered["count"].as_u64(),
            "result_hosts": result_hosts(&filtered)
        }),
    }));

    let started = Instant::now();
    let images = invoke(&connector, OP_IMAGES, json!({"query": "image fixture"}))
        .await
        .expect("image fixture should succeed");
    records.push(evidence_record(EvidenceInput {
        provider_mode: "fixture",
        operation: OP_IMAGES,
        scenario_id: "fixture_images",
        latency_ms: started.elapsed().as_millis(),
        http_status: Some(200),
        retry_decision: "not_needed",
        fcp_error_mapping: "ok",
        skip_reason: None,
        details: json!({
            "base_url_class": images["base_url_class"].clone(),
            "query_hash": hash_label("image fixture"),
            "filters": {"categories": images["categories"].clone()},
            "result_count": images["count"].as_u64(),
            "result_hosts": result_hosts(&images)
        }),
    }));

    let started = Instant::now();
    let zero = invoke(&connector, OP_QUERY, json!({"query": "zero query"}))
        .await
        .expect("zero-results fixture should succeed");
    records.push(evidence_record(EvidenceInput {
        provider_mode: "fixture",
        operation: OP_QUERY,
        scenario_id: "fixture_zero_results",
        latency_ms: started.elapsed().as_millis(),
        http_status: Some(200),
        retry_decision: "not_needed",
        fcp_error_mapping: "ok",
        skip_reason: None,
        details: json!({
            "base_url_class": zero["base_url_class"].clone(),
            "query_hash": hash_label("zero query"),
            "result_count": zero["count"].as_u64(),
            "result_hosts": []
        }),
    }));

    let started = Instant::now();
    let denied_result = configured_connector_result(json!({
        "base_url": server.uri(),
        "request_timeout_ms": 5_000
    }))
    .await;
    assert!(
        denied_result.is_err(),
        "loopback without opt-in should be denied"
    );
    let denied = match denied_result {
        Ok(_) => FcpError::InvalidRequest {
            code: 1003,
            message: "loopback unexpectedly allowed".into(),
        },
        Err(error) => error,
    };
    records.push(evidence_record(EvidenceInput {
        provider_mode: "fixture",
        operation: "searxng.configure",
        scenario_id: "fixture_denied_loopback_config",
        latency_ms: started.elapsed().as_millis(),
        http_status: None,
        retry_decision: "not_retryable",
        fcp_error_mapping: classify_error(&denied),
        skip_reason: None,
        details: json!({
            "base_url_class": "loopback",
            "allowlist_decision": "denied"
        }),
    }));

    let started = Instant::now();
    let provider_error = invoke(&connector, OP_QUERY, json!({"query": "rate query"}))
        .await
        .expect_err("provider error should fail");
    records.push(evidence_record(EvidenceInput {
        provider_mode: "fixture",
        operation: OP_QUERY,
        scenario_id: "fixture_provider_error",
        latency_ms: started.elapsed().as_millis(),
        http_status: Some(503),
        retry_decision: "retryable_provider_error",
        fcp_error_mapping: classify_error(&provider_error),
        skip_reason: None,
        details: json!({
            "base_url_class": "loopback",
            "query_hash": hash_label("rate query"),
            "result_count": 0_u64,
            "result_hosts": []
        }),
    }));

    let started = Instant::now();
    let malformed = invoke(&connector, OP_QUERY, json!({"query": "malformed query"}))
        .await
        .expect_err("malformed response should fail");
    records.push(evidence_record(EvidenceInput {
        provider_mode: "fixture",
        operation: OP_QUERY,
        scenario_id: "fixture_malformed_response",
        latency_ms: started.elapsed().as_millis(),
        http_status: Some(200),
        retry_decision: "not_retryable",
        fcp_error_mapping: classify_error(&malformed),
        skip_reason: None,
        details: json!({
            "base_url_class": "loopback",
            "query_hash": hash_label("malformed query"),
            "result_count": 0_u64,
            "result_hosts": []
        }),
    }));

    let mut timeout_connector = configured_connector(json!({
        "base_url": server.uri(),
        "allow_loopback": true,
        "request_timeout_ms": 10
    }))
    .await;
    let started = Instant::now();
    let timeout = invoke(
        &timeout_connector,
        OP_QUERY,
        json!({"query": "timeout query"}),
    )
    .await
    .expect_err("timeout response should fail");
    records.push(evidence_record(EvidenceInput {
        provider_mode: "fixture",
        operation: OP_QUERY,
        scenario_id: "fixture_timeout_cancellation",
        latency_ms: started.elapsed().as_millis(),
        http_status: None,
        retry_decision: "deadline_exceeded",
        fcp_error_mapping: classify_error(&timeout),
        skip_reason: None,
        details: json!({
            "base_url_class": "loopback",
            "query_hash": hash_label("timeout query"),
            "result_count": 0_u64,
            "result_hosts": []
        }),
    }));

    let cleanup_result = connector
        .handle_shutdown(json!({"reason": "e2e complete"}))
        .await
        .map(|_| "shutdown_ok")
        .unwrap_or("shutdown_error");
    let timeout_cleanup = timeout_connector
        .handle_shutdown(json!({"reason": "e2e complete"}))
        .await
        .map(|_| "shutdown_ok")
        .unwrap_or("shutdown_error");
    records.push(evidence_record(EvidenceInput {
        provider_mode: "fixture",
        operation: "searxng.cleanup",
        scenario_id: "fixture_cleanup",
        latency_ms: 0,
        http_status: None,
        retry_decision: "not_needed",
        fcp_error_mapping: "ok",
        skip_reason: None,
        details: json!({
            "cleanup_result": cleanup_result,
            "timeout_cleanup_result": timeout_cleanup
        }),
    }));
}

async fn run_operator_script_or_record_skip(records: &mut Vec<Value>) {
    let Some(base_url) = std::env::var("SEARXNG_E2E_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
    else {
        records.push(evidence_record(EvidenceInput {
            provider_mode: "operator",
            operation: OP_QUERY,
            scenario_id: "operator_search",
            latency_ms: 0,
            http_status: None,
            retry_decision: "not_attempted",
            fcp_error_mapping: "skip",
            skip_reason: Some("SEARXNG_E2E_URL_not_set"),
            details: json!({"query_hash": hash_label("rust programming"), "result_count": 0_u64}),
        }));
        return;
    };

    let connector = match configured_connector_result(json!({
        "base_url": base_url,
        "allow_loopback": env_flag("SEARXNG_E2E_ALLOW_LOOPBACK"),
        "allow_private_ranges": env_flag("SEARXNG_E2E_ALLOW_PRIVATE"),
        "allow_tailnet_ranges": env_flag("SEARXNG_E2E_ALLOW_TAILNET"),
        "request_timeout_ms": 20_000
    }))
    .await
    {
        Ok(connector) => connector,
        Err(error) => {
            records.push(evidence_record(EvidenceInput {
                provider_mode: "operator",
                operation: "searxng.configure",
                scenario_id: "operator_config",
                latency_ms: 0,
                http_status: None,
                retry_decision: "operator_config_failed",
                fcp_error_mapping: classify_error(&error),
                skip_reason: Some("operator_config_failed"),
                details: json!({"query_hash": hash_label("rust programming"), "result_count": 0_u64}),
            }));
            return;
        }
    };
    let mut connector = connector;
    let started = Instant::now();
    let response = invoke(&connector, OP_QUERY, json!({"query": "rust programming"})).await;
    match response {
        Ok(payload) => records.push(evidence_record(EvidenceInput {
            provider_mode: "operator",
            operation: OP_QUERY,
            scenario_id: "operator_search",
            latency_ms: started.elapsed().as_millis(),
            http_status: Some(200),
            retry_decision: "not_needed",
            fcp_error_mapping: "ok",
            skip_reason: None,
            details: json!({
                "base_url_class": payload["base_url_class"].clone(),
                "query_hash": hash_label("rust programming"),
                "result_count": payload["count"].as_u64(),
                "result_hosts": result_hosts(&payload)
            }),
        })),
        Err(error) => records.push(evidence_record(EvidenceInput {
            provider_mode: "operator",
            operation: OP_QUERY,
            scenario_id: "operator_search",
            latency_ms: started.elapsed().as_millis(),
            http_status: None,
            retry_decision: "operator_surface_failed",
            fcp_error_mapping: classify_error(&error),
            skip_reason: Some("operator_search_failed"),
            details: json!({"query_hash": hash_label("rust programming"), "result_count": 0_u64}),
        })),
    }
    let _ = connector.handle_shutdown(json!({})).await;
}

async fn configured_connector(config: Value) -> SearxngConnector {
    configured_connector_result(config)
        .await
        .expect("configure should succeed")
}

async fn configured_connector_result(config: Value) -> Result<SearxngConnector, FcpError> {
    let mut connector = SearxngConnector::new();
    connector.handle_configure(config).await?;
    connector.handle_handshake(json!({})).await?;
    Ok(connector)
}

async fn invoke(
    connector: &SearxngConnector,
    operation: &str,
    input: Value,
) -> Result<Value, FcpError> {
    connector
        .handle_invoke(json!({"operation_id": operation, "input": input}))
        .await
}

async fn mount_text_success(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/search"))
        .and(query_param("q", "rust privacy"))
        .and(query_param("format", "json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(search_fixture()))
        .expect(1)
        .mount(server)
        .await;
}

async fn mount_filtered_success(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/search"))
        .and(query_param("q", "filter query"))
        .and(query_param("categories", "general,it"))
        .and(query_param("engines", "duckduckgo,brave"))
        .and(query_param("safesearch", "0"))
        .and(query_param("time_range", "month"))
        .and(query_param("pageno", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(search_fixture()))
        .expect(1)
        .mount(server)
        .await;
}

async fn mount_image_success(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/search"))
        .and(query_param("q", "image fixture"))
        .and(query_param("categories", "images"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{
                "title": "Rust image",
                "url": "https://rust-lang.org/logos",
                "img_src": "https://cdn.example.invalid/rust.png",
                "engine": "bing",
                "category": "images"
            }]
        })))
        .expect(1)
        .mount(server)
        .await;
}

async fn mount_zero_results(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/search"))
        .and(query_param("q", "zero query"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"results": []})))
        .expect(1)
        .mount(server)
        .await;
}

async fn mount_provider_error(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/search"))
        .and(query_param("q", "rate query"))
        .respond_with(ResponseTemplate::new(503).set_body_string("temporarily unavailable"))
        .expect(1)
        .mount(server)
        .await;
}

async fn mount_malformed_response(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/search"))
        .and(query_param("q", "malformed query"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"results": {}})))
        .expect(1)
        .mount(server)
        .await;
}

async fn mount_timeout_response(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/search"))
        .and(query_param("q", "timeout query"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(std::time::Duration::from_millis(250))
                .set_body_json(search_fixture()),
        )
        .expect(1)
        .mount(server)
        .await;
}

fn search_fixture() -> Value {
    json!({
        "results": [
            {
                "title": "Rust Programming Language",
                "url": "https://rust-lang.org/",
                "content": "fixture snippet",
                "engine": "duckduckgo",
                "category": "general"
            },
            {
                "title": "The Rust Book",
                "url": "https://doc.rust-lang.org/book/",
                "content": "fixture snippet",
                "engine": "brave",
                "category": "general"
            }
        ],
        "suggestions": ["rust book"]
    })
}

struct EvidenceInput {
    provider_mode: &'static str,
    operation: &'static str,
    scenario_id: &'static str,
    latency_ms: u128,
    http_status: Option<u16>,
    retry_decision: &'static str,
    fcp_error_mapping: &'static str,
    skip_reason: Option<&'static str>,
    details: Value,
}

fn evidence_record(input: EvidenceInput) -> Value {
    json!({
        "command_line": std::env::args().collect::<Vec<_>>(),
        "git_revision": option_env!("GIT_REVISION").unwrap_or("unknown"),
        "provider": "searxng",
        "provider_mode": input.provider_mode,
        "scenario_id": input.scenario_id,
        "operation": input.operation,
        "latency_ms": input.latency_ms,
        "http_status": input.http_status,
        "retry_decision": input.retry_decision,
        "fcp_error_mapping": input.fcp_error_mapping,
        "skip_reason": input.skip_reason,
        "details": input.details,
    })
}

fn write_jsonl_artifact(records: &[Value]) -> String {
    let mut jsonl = String::new();
    for record in records {
        jsonl.push_str(&serde_json::to_string(record).expect("record should serialize"));
        jsonl.push('\n');
    }
    if let Some(parent) = std::path::Path::new(ARTIFACT_PATH).parent() {
        std::fs::create_dir_all(parent).expect("artifact directory should be creatable");
    }
    let mut file = std::fs::File::create(ARTIFACT_PATH).expect("artifact should be writable");
    file.write_all(jsonl.as_bytes())
        .expect("artifact should be written");
    jsonl
}

fn result_hosts(payload: &Value) -> Vec<String> {
    payload["results"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|result| result["hostname"].as_str())
        .map(ToOwned::to_owned)
        .collect()
}

fn hash_label(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

fn classify_error(error: &FcpError) -> &'static str {
    match error {
        FcpError::External {
            status_code,
            retryable,
            ..
        } => match (*status_code, *retryable) {
            (Some(429), true) => "external_rate_limited_retryable",
            (Some(503), true) => "external_unavailable_retryable",
            (Some(200), false) => "external_malformed_response_terminal",
            _ => "external_error",
        },
        FcpError::UpstreamTimeout { .. } => "upstream_timeout",
        FcpError::InvalidRequest { .. } => "invalid_request",
        _ => "other_error",
    }
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "yes"))
}
