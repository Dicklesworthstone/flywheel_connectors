//! `DuckDuckGo` connector e2e evidence.
//!
//! The default lane is deterministic and uses loopback HTTP fixtures. Set
//! `DUCKDUCKGO_E2E=1` to enable the optional live smoke path. Evidence records
//! hash queries and include result hostnames only, never query text, snippets,
//! full URLs, or response bodies.

#![cfg(feature = "duckduckgo")]
#![allow(clippy::too_many_lines)]

use std::io::Write as _;
use std::time::Instant;

use fcp_duckduckgo::DuckDuckGoConnector;
use fcp_prelude::FcpError;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_string_contains, method, path, query_param},
};

const OP_TEXT: &str = "duckduckgo.search.text";
const OP_IMAGES: &str = "duckduckgo.search.images";
const OP_NEWS: &str = "duckduckgo.search.news";
const OP_SUGGESTIONS: &str = "duckduckgo.search.suggestions";

const ARTIFACT_PATH: &str = "target/fcp-duckduckgo/duckduckgo-e2e.jsonl";

#[fcp_async_core::runtime::test]
async fn duckduckgo_connector_emits_redacted_e2e_evidence() {
    let mut records = Vec::new();
    run_fixture_script(&mut records).await;
    run_live_script_or_record_skip(&mut records).await;

    let jsonl = write_jsonl_artifact(&records);
    assert!(jsonl.contains("\"provider_mode\":\"fixture\""));
    assert!(jsonl.contains("\"provider_mode\":\"live\"") || jsonl.contains("\"skip_reason\""));
    assert!(!jsonl.contains("rust privacy"));
    assert!(!jsonl.contains("duckduckgo privacy"));
    assert!(!jsonl.contains("fixture snippet"));
    assert!(!jsonl.contains("https://"));
    assert_eq!(fcp_e2e::scan_log_jsonl(&jsonl).error_count, 0);
}

async fn run_fixture_script(records: &mut Vec<Value>) {
    let server = MockServer::start().await;
    mount_text_success(&server).await;
    mount_zero_results(&server).await;
    mount_blocker_page(&server).await;
    mount_rate_limit(&server).await;
    mount_vqd_html(&server, "image fixture", 1).await;
    mount_vqd_html(&server, "news fixture", 1).await;
    mount_images(&server).await;
    mount_news(&server).await;
    mount_suggestions(&server).await;

    let mut connector = configured_connector(json!({
        "base_url": server.uri(),
        "request_timeout_ms": 5_000
    }))
    .await;

    let started = Instant::now();
    let text = invoke(&connector, OP_TEXT, json!({"query": "rust privacy"}))
        .await
        .expect("fixture text search should succeed");
    records.push(evidence_record(EvidenceInput {
        provider_mode: "fixture",
        operation: OP_TEXT,
        scenario_id: "fixture_text_success",
        latency_ms: started.elapsed().as_millis(),
        http_status: Some(200),
        retry_decision: "not_needed",
        fcp_error_mapping: "ok",
        skip_reason: None,
        details: json!({
            "query_hash": hash_label("rust privacy"),
            "result_count": text["count"].as_u64(),
            "result_hosts": result_hosts(&text),
            "region": text["region"].clone(),
            "time_range": text["time_range"].clone()
        }),
    }));

    let started = Instant::now();
    let suggestions = invoke(
        &connector,
        OP_SUGGESTIONS,
        json!({"query": "duckduckgo privacy"}),
    )
    .await
    .expect("fixture suggestions should succeed");
    records.push(evidence_record(EvidenceInput {
        provider_mode: "fixture",
        operation: OP_SUGGESTIONS,
        scenario_id: "fixture_suggestions",
        latency_ms: started.elapsed().as_millis(),
        http_status: Some(200),
        retry_decision: "not_needed",
        fcp_error_mapping: "ok",
        skip_reason: None,
        details: json!({
            "query_hash": hash_label("duckduckgo privacy"),
            "result_count": suggestions["count"].as_u64(),
            "result_hosts": [],
            "region": suggestions["region"].clone()
        }),
    }));

    let started = Instant::now();
    let images = invoke(
        &connector,
        OP_IMAGES,
        json!({"query": "image fixture", "max_results": 1}),
    )
    .await
    .expect("fixture image search should succeed");
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
            "query_hash": hash_label("image fixture"),
            "result_count": images["count"].as_u64(),
            "result_hosts": result_hosts(&images),
            "region": images["region"].clone()
        }),
    }));

    let started = Instant::now();
    let news = invoke(
        &connector,
        OP_NEWS,
        json!({"query": "news fixture", "time_range": "week"}),
    )
    .await
    .expect("fixture news search should succeed");
    records.push(evidence_record(EvidenceInput {
        provider_mode: "fixture",
        operation: OP_NEWS,
        scenario_id: "fixture_news",
        latency_ms: started.elapsed().as_millis(),
        http_status: Some(200),
        retry_decision: "not_needed",
        fcp_error_mapping: "ok",
        skip_reason: None,
        details: json!({
            "query_hash": hash_label("news fixture"),
            "result_count": news["count"].as_u64(),
            "result_hosts": result_hosts(&news),
            "region": news["region"].clone(),
            "time_range": news["time_range"].clone()
        }),
    }));

    let started = Instant::now();
    let zero = invoke(&connector, OP_TEXT, json!({"query": "zero query"}))
        .await
        .expect("zero-results fixture should succeed");
    records.push(evidence_record(EvidenceInput {
        provider_mode: "fixture",
        operation: OP_TEXT,
        scenario_id: "fixture_zero_results",
        latency_ms: started.elapsed().as_millis(),
        http_status: Some(200),
        retry_decision: "not_needed",
        fcp_error_mapping: "ok",
        skip_reason: None,
        details: json!({
            "query_hash": hash_label("zero query"),
            "result_count": zero["count"].as_u64(),
            "result_hosts": []
        }),
    }));

    let started = Instant::now();
    let blocked = invoke(&connector, OP_TEXT, json!({"query": "blocked query"}))
        .await
        .expect_err("blocker page should map to external error");
    records.push(evidence_record(EvidenceInput {
        provider_mode: "fixture",
        operation: OP_TEXT,
        scenario_id: "fixture_blocker_page",
        latency_ms: started.elapsed().as_millis(),
        http_status: Some(200),
        retry_decision: "not_retrying_in_fixture",
        fcp_error_mapping: classify_error(&blocked),
        skip_reason: None,
        details: json!({
            "query_hash": hash_label("blocked query"),
            "result_count": 0_u64,
            "result_hosts": []
        }),
    }));

    let started = Instant::now();
    let rate_limited = invoke(&connector, OP_TEXT, json!({"query": "rate query"}))
        .await
        .expect_err("rate limit fixture should fail");
    records.push(evidence_record(EvidenceInput {
        provider_mode: "fixture",
        operation: OP_TEXT,
        scenario_id: "fixture_rate_limit",
        latency_ms: started.elapsed().as_millis(),
        http_status: Some(429),
        retry_decision: "provider_returned_retry_after",
        fcp_error_mapping: classify_error(&rate_limited),
        skip_reason: None,
        details: json!({
            "query_hash": hash_label("rate query"),
            "result_count": 0_u64,
            "result_hosts": []
        }),
    }));

    let cleanup_result = connector
        .handle_shutdown(json!({ "reason": "e2e complete" }))
        .await
        .map(|_| "shutdown_ok")
        .unwrap_or("shutdown_error");
    records.push(evidence_record(EvidenceInput {
        provider_mode: "fixture",
        operation: "duckduckgo.cleanup",
        scenario_id: "fixture_cleanup",
        latency_ms: 0,
        http_status: None,
        retry_decision: "not_needed",
        fcp_error_mapping: "ok",
        skip_reason: None,
        details: json!({ "cleanup_result": cleanup_result }),
    }));
}

async fn run_live_script_or_record_skip(records: &mut Vec<Value>) {
    if std::env::var("DUCKDUCKGO_E2E").ok().as_deref() != Some("1") {
        records.push(evidence_record(EvidenceInput {
            provider_mode: "live",
            operation: OP_TEXT,
            scenario_id: "live_text_search",
            latency_ms: 0,
            http_status: None,
            retry_decision: "not_attempted",
            fcp_error_mapping: "skip",
            skip_reason: Some("DUCKDUCKGO_E2E_not_set"),
            details: json!({ "query_hash": hash_label("rust programming"), "result_count": 0_u64 }),
        }));
        return;
    }

    let mut connector = configured_connector(json!({"request_timeout_ms": 15_000})).await;
    let started = Instant::now();
    let response = invoke(&connector, OP_TEXT, json!({"query": "rust programming"})).await;
    match response {
        Ok(payload) => records.push(evidence_record(EvidenceInput {
            provider_mode: "live",
            operation: OP_TEXT,
            scenario_id: "live_text_search",
            latency_ms: started.elapsed().as_millis(),
            http_status: Some(200),
            retry_decision: "not_needed",
            fcp_error_mapping: "ok",
            skip_reason: None,
            details: json!({
                "query_hash": hash_label("rust programming"),
                "result_count": payload["count"].as_u64(),
                "result_hosts": result_hosts(&payload),
                "region": payload["region"].clone()
            }),
        })),
        Err(err) => {
            records.push(evidence_record(EvidenceInput {
                provider_mode: "live",
                operation: OP_TEXT,
                scenario_id: "live_text_search",
                latency_ms: started.elapsed().as_millis(),
                http_status: None,
                retry_decision: "provider_returned_error",
                fcp_error_mapping: classify_error(&err),
                skip_reason: None,
                details: json!({ "query_hash": hash_label("rust programming"), "result_count": 0_u64 }),
            }));
            assert_eq!(
                classify_error(&err),
                "ok",
                "live DuckDuckGo search failed after DUCKDUCKGO_E2E=1: {err}"
            );
        }
    }

    let _ = connector
        .handle_shutdown(json!({ "reason": "live e2e complete" }))
        .await;
}

async fn configured_connector(config: Value) -> DuckDuckGoConnector {
    let mut connector = DuckDuckGoConnector::new();
    connector
        .handle_configure(config)
        .await
        .expect("DuckDuckGo connector should configure");
    connector
        .handle_handshake(json!({}))
        .await
        .expect("DuckDuckGo connector handshake should succeed");
    connector
}

async fn invoke(
    connector: &DuckDuckGoConnector,
    operation: &'static str,
    input: Value,
) -> fcp_core::FcpResult<Value> {
    connector
        .handle_invoke(json!({"operation_id": operation, "input": input}))
        .await
}

struct EvidenceInput<'a> {
    provider_mode: &'a str,
    operation: &'a str,
    scenario_id: &'a str,
    latency_ms: u128,
    http_status: Option<u16>,
    retry_decision: &'a str,
    fcp_error_mapping: &'a str,
    skip_reason: Option<&'a str>,
    details: Value,
}

fn evidence_record(input: EvidenceInput<'_>) -> Value {
    let EvidenceInput {
        provider_mode,
        operation,
        scenario_id,
        latency_ms,
        http_status,
        retry_decision,
        fcp_error_mapping,
        skip_reason,
        details,
    } = input;
    json!({
        "schema": "fcp.duckduckgo.e2e.v1",
        "command_line": "cargo test -p fcp-e2e --no-default-features --features duckduckgo --test duckduckgo_e2e -- --nocapture",
        "git_revision": git_revision(),
        "provider_mode": provider_mode,
        "operation": operation,
        "scenario_id": scenario_id,
        "query_hash": details.get("query_hash").cloned().unwrap_or(Value::Null),
        "region": details.get("region").cloned().unwrap_or(Value::Null),
        "time_range": details.get("time_range").cloned().unwrap_or(Value::Null),
        "result_count": details.get("result_count").cloned().unwrap_or(Value::Null),
        "result_hosts": details.get("result_hosts").cloned().unwrap_or(Value::Array(Vec::new())),
        "http_status": http_status,
        "latency_ms": u64::try_from(latency_ms).unwrap_or(u64::MAX),
        "retry_decision": retry_decision,
        "fcp_error_mapping": fcp_error_mapping,
        "audit_receipt_id_hash": audit_receipt_id_hash(provider_mode, operation, scenario_id),
        "cleanup_result": details.get("cleanup_result").cloned().unwrap_or(json!("pending")),
        "skip_reason": skip_reason
    })
}

fn result_hosts(payload: &Value) -> Value {
    Value::Array(
        payload["results"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|result| result["hostname"].as_str())
            .filter(|host| !host.is_empty())
            .map(|host| Value::String(host.to_string()))
            .collect(),
    )
}

fn classify_error(error: &FcpError) -> &'static str {
    match error {
        FcpError::External {
            status_code: Some(429),
            ..
        } => "external.rate_limited",
        FcpError::External { .. } => "external.provider_error",
        FcpError::UpstreamTimeout { .. } => "external.timeout",
        FcpError::InvalidRequest { .. } => "protocol.invalid_request",
        _ => "other",
    }
}

fn audit_receipt_id_hash(provider_mode: &str, operation: &str, scenario_id: &str) -> String {
    let input = format!("{provider_mode}:{operation}:{scenario_id}");
    format!("sha256:{}", hex_lower(&Sha256::digest(input.as_bytes())))
}

fn hash_label(value: &str) -> String {
    format!("sha256:{}", hex_lower(&Sha256::digest(value.as_bytes())))
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn git_revision() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|revision| revision.trim().to_string())
        .filter(|revision| !revision.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn write_jsonl_artifact(records: &[Value]) -> String {
    let jsonl = records
        .iter()
        .map(|record| serde_json::to_string(record).expect("evidence record should serialize"))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::create_dir_all("target/fcp-duckduckgo")
        .expect("artifact directory should be writable");
    let mut file = std::fs::File::create(ARTIFACT_PATH).expect("artifact should be writable");
    file.write_all(jsonl.as_bytes())
        .expect("artifact should write");
    file.write_all(b"\n")
        .expect("artifact newline should write");
    jsonl
}

async fn mount_text_success(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/html/"))
        .and(body_string_contains("q=rust+privacy"))
        .respond_with(ResponseTemplate::new(200).set_body_string(text_html_fixture()))
        .expect(1)
        .mount(server)
        .await;
}

async fn mount_zero_results(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/html/"))
        .and(body_string_contains("q=zero+query"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "<html><body><div>No results.</div><input type=\"hidden\" name=\"vqd\" value=\"4-zero\" /></body></html>",
        ))
        .expect(1)
        .mount(server)
        .await;
}

async fn mount_blocker_page(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/html/"))
        .and(body_string_contains("q=blocked+query"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "<html><body><img src=\"//duckduckgo.com/t/tqadb?cc=botnet\" /></body></html>",
        ))
        .expect(1)
        .mount(server)
        .await;
}

async fn mount_rate_limit(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/html/"))
        .and(body_string_contains("q=rate+query"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "1")
                .set_body_string("rate limited"),
        )
        .expect(1)
        .mount(server)
        .await;
}

async fn mount_vqd_html(server: &MockServer, query: &str, expected: u64) {
    Mock::given(method("POST"))
        .and(path("/html/"))
        .and(body_string_contains(query.replace(' ', "+")))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "<html><body><input type=\"hidden\" name=\"vqd\" value=\"4-fixture\" /></body></html>",
        ))
        .expect(expected)
        .mount(server)
        .await;
}

async fn mount_images(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/i.js"))
        .and(query_param("q", "image fixture"))
        .and(query_param("vqd", "4-fixture"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{
                "title": "Image fixture title",
                "url": "https://images.example.test/item",
                "image": "https://cdn.example.test/image.png",
                "thumbnail": "https://cdn.example.test/thumb.png",
                "source": "Fixture",
                "width": 320,
                "height": 240
            }]
        })))
        .expect(1)
        .mount(server)
        .await;
}

async fn mount_news(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/news.js"))
        .and(query_param("q", "news fixture"))
        .and(query_param("vqd", "4-fixture"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{
                "title": "News fixture title",
                "url": "https://news.example.test/story",
                "excerpt": "fixture snippet",
                "source": "Fixture News",
                "date": "2026-05-06T00:00:00Z"
            }]
        })))
        .expect(1)
        .mount(server)
        .await;
}

async fn mount_suggestions(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/ac/"))
        .and(query_param("q", "duckduckgo privacy"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            "duckduckgo privacy",
            ["duckduckgo private search", "duckduckgo privacy policy"]
        ])))
        .expect(1)
        .mount(server)
        .await;
}

fn text_html_fixture() -> &'static str {
    r#"
      <html><body>
        <div class="result results_links web-result">
          <a rel="nofollow" class="result__a" href="https://privacy.example.test/one">Privacy result</a>
          <a class="result__snippet" href="https://privacy.example.test/one">fixture snippet one</a>
        </div>
        <div class="result results_links web-result">
          <a rel="nofollow" class="result__a" href="https://duckduckgo.com/l/?uddg=https%3A%2F%2Fdocs.example.test%2Ftwo">Docs result</a>
          <a class="result__snippet" href="https://docs.example.test/two">fixture snippet two</a>
        </div>
        <input type="hidden" name="vqd" value="4-fixture" />
      </body></html>
    "#
}
