//! SimulateRequest/Response Golden Vectors and Unit Tests (flywheel_connectors-r1sl)
//!
//! Tests for FCP Specification Section 9.4 Simulate operation:
//! - SimulateRequest/SimulateResponse canonical encoding round-trip
//! - `CostEstimate` deterministic population
//! - `ResourceAvailability` deterministic population
//! - Missing capability reporting stability
//!
//! # Test Categories
//!
//! 1. **Schema Validation**: Required fields, format checks
//! 2. **Encoding Round-trip**: JSON and CBOR serialization stability
//! 3. **Builder Patterns**: Fluent API for request/response construction
//! 4. **Golden Vectors**: CBOR test fixtures for cross-implementation verification

use std::fs;
use std::path::PathBuf;

use fcp_core::{
    CapabilityToken, ConnectorId, CorrelationId, CostEstimate, CurrencyCost, InvokeContext,
    OperationId, RequestId, ResourceAvailability, ResponseMetadata, SimulateRequest,
    SimulateResponse, ZoneId,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════════════════════════
// TEST INFRASTRUCTURE
// ═══════════════════════════════════════════════════════════════════════════════

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join("simulate")
}

/// FCP2-compliant structured log output.
fn log_test_event(test_name: &str, event: &str, details: &serde_json::Value) {
    let log = serde_json::json!({
        "event": event,
        "test": test_name,
        "module": "simulate_golden_vectors",
        "details": details
    });
    println!("{}", serde_json::to_string(&log).unwrap());
}

// ═══════════════════════════════════════════════════════════════════════════════
// GOLDEN VECTOR STRUCTURES
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[allow(clippy::struct_excessive_bools)]
struct SimulateRequestVector {
    description: String,
    request_id: String,
    connector_id: String,
    operation: String,
    zone_id: String,
    estimate_cost: bool,
    check_availability: bool,
    has_context: bool,
    has_correlation_id: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[allow(clippy::struct_excessive_bools)]
struct SimulateResponseVector {
    description: String,
    request_id: String,
    would_succeed: bool,
    has_failure_reason: bool,
    has_denial_code: bool,
    missing_capabilities_count: usize,
    has_cost_estimate: bool,
    has_availability: bool,
    has_metadata: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[allow(clippy::struct_excessive_bools)]
struct CostEstimateVector {
    description: String,
    has_api_credits: bool,
    api_credits: Option<u64>,
    has_duration_ms: bool,
    duration_ms: Option<u64>,
    has_bytes: bool,
    bytes: Option<u64>,
    has_currency: bool,
    currency_code: Option<String>,
    currency_cents: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[allow(clippy::struct_excessive_bools)]
struct ResourceAvailabilityVector {
    description: String,
    available: bool,
    has_rate_limit_remaining: bool,
    rate_limit_remaining: Option<u32>,
    has_rate_limit_reset_at: bool,
    rate_limit_reset_at: Option<u64>,
    has_details: bool,
}

// ═══════════════════════════════════════════════════════════════════════════════
// SCHEMA VALIDATION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod schema_validation {
    use super::*;

    /// Create a minimal valid `SimulateRequest` for testing.
    fn make_valid_request() -> SimulateRequest {
        SimulateRequest::new(
            ConnectorId::new("vendor", "test", "v1").unwrap(),
            OperationId::new("op.echo").unwrap(),
            ZoneId::work(),
            json!({"message": "hello"}),
            CapabilityToken::test_token(),
        )
    }

    #[test]
    fn valid_request_with_all_required_fields() {
        let req = make_valid_request();
        assert_eq!(req.r#type, "simulate");
        assert_eq!(req.connector_id.as_str(), "vendor:test:v1");
        assert_eq!(req.operation.as_str(), "op.echo");
        assert_eq!(req.zone_id.as_str(), "z:work");
        assert!(!req.estimate_cost);
        assert!(!req.check_availability);
    }

    #[test]
    fn request_with_cost_estimate_enabled() {
        let req = make_valid_request().with_cost_estimate();
        assert!(req.estimate_cost);
        assert!(!req.check_availability);
    }

    #[test]
    fn request_with_availability_check_enabled() {
        let req = make_valid_request().with_availability_check();
        assert!(!req.estimate_cost);
        assert!(req.check_availability);
    }

    #[test]
    fn request_with_both_flags_enabled() {
        let req = make_valid_request()
            .with_cost_estimate()
            .with_availability_check();
        assert!(req.estimate_cost);
        assert!(req.check_availability);
    }

    #[test]
    fn request_with_context() {
        let ctx = InvokeContext {
            locale: Some("en-US".into()),
            pagination: Some(json!({"limit": 100})),
            trace_id: Some("0123456789abcdef0123456789abcdef".into()),
            request_tags: HashMap::from([("priority".into(), "high".into())]),
        };
        let req = make_valid_request().with_context(ctx);
        assert!(req.context.is_some());
        let ctx = req.context.unwrap();
        assert_eq!(ctx.locale, Some("en-US".into()));
    }

    #[test]
    fn request_with_correlation_id() {
        let corr_id = CorrelationId::new();
        let req = make_valid_request().with_correlation_id(corr_id);
        assert!(req.correlation_id.is_some());
    }

    #[test]
    fn request_serialization_roundtrip_json() {
        let req = make_valid_request()
            .with_cost_estimate()
            .with_availability_check();

        let json_str = serde_json::to_string(&req).expect("JSON serialization should succeed");
        let parsed: SimulateRequest =
            serde_json::from_str(&json_str).expect("JSON deserialization should succeed");

        assert_eq!(req.r#type, parsed.r#type);
        assert_eq!(req.connector_id.as_str(), parsed.connector_id.as_str());
        assert_eq!(req.operation.as_str(), parsed.operation.as_str());
        assert_eq!(req.zone_id.as_str(), parsed.zone_id.as_str());
        assert_eq!(req.estimate_cost, parsed.estimate_cost);
        assert_eq!(req.check_availability, parsed.check_availability);
    }

    #[test]
    fn request_serialization_roundtrip_cbor() {
        let req = make_valid_request()
            .with_cost_estimate()
            .with_availability_check();

        let mut buffer = Vec::new();
        ciborium::into_writer(&req, &mut buffer).expect("CBOR serialization should succeed");

        let parsed: SimulateRequest =
            ciborium::from_reader(buffer.as_slice()).expect("CBOR deserialization should succeed");

        assert_eq!(req.r#type, parsed.r#type);
        assert_eq!(req.connector_id.as_str(), parsed.connector_id.as_str());
        assert_eq!(req.estimate_cost, parsed.estimate_cost);
        assert_eq!(req.check_availability, parsed.check_availability);
    }

    /// Simulate with a zone that is not the connector's home/authorized zone.
    ///
    /// A simulator consumer uses the request's `zone_id` to resolve policy;
    /// policy denies cross-zone operations unless explicitly allowed. This
    /// test locks down that (a) the request preserves a mismatched zone
    /// verbatim through CBOR round-trip (no silent rewriting), and (b)
    /// distinct zones produce distinct canonical bytes — otherwise a
    /// policy consumer could be fooled into granting based on a
    /// coincidentally-equivalent serialization.
    #[test]
    fn request_with_zone_mismatch_preserves_zone_verbatim() {
        // Build the same request with two different zones; the connector
        // and operation are identical, only zone differs.
        let conn = ConnectorId::new("vendor", "test", "v1").unwrap();
        let op = OperationId::new("op.echo").unwrap();
        let body = json!({"message": "hello"});
        let tok = CapabilityToken::test_token();

        let req_work = SimulateRequest::new(
            conn.clone(),
            op.clone(),
            ZoneId::work(),
            body.clone(),
            tok.clone(),
        );
        let req_public = SimulateRequest::new(conn, op, ZoneId::public(), body, tok);

        // Both requests are valid shape-wise.
        assert_eq!(req_work.r#type, "simulate");
        assert_eq!(req_public.r#type, "simulate");
        assert_ne!(
            req_work.zone_id.as_str(),
            req_public.zone_id.as_str(),
            "fixture must actually differ"
        );

        // CBOR bytes MUST differ — zone mismatch is not silently normalized.
        let mut work_bytes = Vec::new();
        ciborium::into_writer(&req_work, &mut work_bytes).unwrap();
        let mut public_bytes = Vec::new();
        ciborium::into_writer(&req_public, &mut public_bytes).unwrap();
        assert_ne!(
            work_bytes, public_bytes,
            "distinct zones must produce distinct canonical bytes"
        );

        // Round-trip preserves the zone verbatim; no sanitization/coercion.
        let parsed_work: SimulateRequest = ciborium::from_reader(work_bytes.as_slice()).unwrap();
        let parsed_public: SimulateRequest =
            ciborium::from_reader(public_bytes.as_slice()).unwrap();
        assert_eq!(parsed_work.zone_id.as_str(), "z:work");
        assert_eq!(parsed_public.zone_id.as_str(), "z:public");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// RESPONSE VALIDATION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod response_validation {
    use super::*;

    #[test]
    fn allowed_response_construction() {
        let resp = SimulateResponse::allowed(RequestId::new("req_001"));

        assert_eq!(resp.r#type, "simulate_response");
        assert_eq!(resp.id.0, "req_001");
        assert!(resp.would_succeed);
        assert!(resp.failure_reason.is_none());
        assert!(resp.denial_code.is_none());
        assert_eq!(resp.missing_capabilities, [] as [std::string::String; 0]);
        assert!(resp.estimated_cost.is_none());
        assert!(resp.availability.is_none());
    }

    #[test]
    fn denied_response_construction() {
        let resp = SimulateResponse::denied(
            RequestId::new("req_002"),
            "Missing required capability",
            "FCP-3001",
        );

        assert_eq!(resp.r#type, "simulate_response");
        assert_eq!(resp.id.0, "req_002");
        assert!(!resp.would_succeed);
        assert_eq!(
            resp.failure_reason,
            Some("Missing required capability".into())
        );
        assert_eq!(resp.denial_code, Some("FCP-3001".into()));
    }

    #[test]
    fn response_with_missing_capabilities() {
        let resp = SimulateResponse::denied(
            RequestId::new("req_003"),
            "Capabilities missing",
            "FCP-3001",
        )
        .with_missing_capabilities(vec!["cap.admin.write".into(), "cap.admin.delete".into()]);

        assert_eq!(resp.missing_capabilities.len(), 2);
        assert!(
            resp.missing_capabilities
                .contains(&"cap.admin.write".to_string())
        );
        assert!(
            resp.missing_capabilities
                .contains(&"cap.admin.delete".to_string())
        );
    }

    #[test]
    fn response_with_cost_estimate() {
        let cost = CostEstimate::with_credits(1000)
            .and_duration_ms(500)
            .and_bytes(4096);

        let resp = SimulateResponse::allowed(RequestId::new("req_004")).with_cost_estimate(cost);

        assert!(resp.estimated_cost.is_some());
        let cost = resp.estimated_cost.unwrap();
        assert_eq!(cost.api_credits, Some(1000));
        assert_eq!(cost.estimated_duration_ms, Some(500));
        assert_eq!(cost.estimated_bytes, Some(4096));
    }

    #[test]
    fn response_with_availability() {
        let avail = ResourceAvailability::available().with_rate_limit(100, Some(1_700_000_000));

        let resp = SimulateResponse::allowed(RequestId::new("req_005")).with_availability(avail);

        assert!(resp.availability.is_some());
        let avail = resp.availability.unwrap();
        assert!(avail.available);
        assert_eq!(avail.rate_limit_remaining, Some(100));
        assert_eq!(avail.rate_limit_reset_at, Some(1_700_000_000));
    }

    #[test]
    fn response_with_metadata() {
        let meta = ResponseMetadata {
            processing_time_ms: Some(25),
            cache_ttl_secs: Some(300),
            from_cache: false,
            retry_after_secs: None,
        };

        let resp = SimulateResponse::allowed(RequestId::new("req_006")).with_metadata(meta);

        assert!(resp.response_metadata.is_some());
        let meta = resp.response_metadata.unwrap();
        assert_eq!(meta.processing_time_ms, Some(25));
    }

    #[test]
    fn response_serialization_roundtrip_json() {
        let resp = SimulateResponse::allowed(RequestId::new("req_007"))
            .with_cost_estimate(CostEstimate::with_credits(500))
            .with_availability(ResourceAvailability::available());

        let json_str = serde_json::to_string(&resp).expect("JSON serialization should succeed");
        let parsed: SimulateResponse =
            serde_json::from_str(&json_str).expect("JSON deserialization should succeed");

        assert_eq!(resp.r#type, parsed.r#type);
        assert_eq!(resp.id.0, parsed.id.0);
        assert_eq!(resp.would_succeed, parsed.would_succeed);
        assert!(parsed.estimated_cost.is_some());
        assert!(parsed.availability.is_some());
    }

    #[test]
    fn response_serialization_roundtrip_cbor() {
        let resp = SimulateResponse::denied(RequestId::new("req_008"), "Test denial", "FCP-TEST")
            .with_missing_capabilities(vec!["cap.test".into()]);

        let mut buffer = Vec::new();
        ciborium::into_writer(&resp, &mut buffer).expect("CBOR serialization should succeed");

        let parsed: SimulateResponse =
            ciborium::from_reader(buffer.as_slice()).expect("CBOR deserialization should succeed");

        assert_eq!(resp.r#type, parsed.r#type);
        assert!(!parsed.would_succeed);
        assert_eq!(parsed.denial_code, Some("FCP-TEST".into()));
        assert_eq!(parsed.missing_capabilities, vec!["cap.test".to_string()]);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// COST ESTIMATE TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod cost_estimate {
    use super::*;

    #[test]
    fn default_cost_estimate() {
        let cost = CostEstimate::default();
        assert!(cost.api_credits.is_none());
        assert!(cost.estimated_duration_ms.is_none());
        assert!(cost.estimated_bytes.is_none());
        assert!(cost.currency.is_none());
    }

    #[test]
    fn cost_with_credits() {
        let cost = CostEstimate::with_credits(1500);
        assert_eq!(cost.api_credits, Some(1500));
        assert!(cost.estimated_duration_ms.is_none());
        assert!(cost.estimated_bytes.is_none());
    }

    #[test]
    fn cost_with_duration() {
        let cost = CostEstimate::with_duration_ms(250);
        assert!(cost.api_credits.is_none());
        assert_eq!(cost.estimated_duration_ms, Some(250));
        assert!(cost.estimated_bytes.is_none());
    }

    #[test]
    fn cost_with_bytes() {
        let cost = CostEstimate::with_bytes(8192);
        assert!(cost.api_credits.is_none());
        assert!(cost.estimated_duration_ms.is_none());
        assert_eq!(cost.estimated_bytes, Some(8192));
    }

    #[test]
    fn cost_builder_chain() {
        let cost = CostEstimate::with_credits(2000)
            .and_duration_ms(100)
            .and_bytes(1024)
            .and_currency(CurrencyCost::usd_cents(50));

        assert_eq!(cost.api_credits, Some(2000));
        assert_eq!(cost.estimated_duration_ms, Some(100));
        assert_eq!(cost.estimated_bytes, Some(1024));
        assert!(cost.currency.is_some());
        let currency = cost.currency.unwrap();
        assert_eq!(currency.amount_cents, 50);
        assert_eq!(currency.currency_code, "USD");
    }

    #[test]
    fn cost_estimate_serialization_roundtrip() {
        let cost = CostEstimate::with_credits(1000).and_duration_ms(500);

        let json_str = serde_json::to_string(&cost).expect("JSON serialization should succeed");
        let parsed: CostEstimate =
            serde_json::from_str(&json_str).expect("JSON deserialization should succeed");

        assert_eq!(cost.api_credits, parsed.api_credits);
        assert_eq!(cost.estimated_duration_ms, parsed.estimated_duration_ms);
    }

    #[test]
    fn cost_estimate_deterministic() {
        // Same inputs should produce same outputs
        let cost1 = CostEstimate::with_credits(1000).and_duration_ms(500);
        let cost2 = CostEstimate::with_credits(1000).and_duration_ms(500);

        let json1 = serde_json::to_string(&cost1).unwrap();
        let json2 = serde_json::to_string(&cost2).unwrap();

        assert_eq!(
            json1, json2,
            "CostEstimate serialization must be deterministic"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CURRENCY COST TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod currency_cost {
    use super::*;

    #[test]
    fn currency_cost_new() {
        let cost = CurrencyCost::new(999, "EUR");
        assert_eq!(cost.amount_cents, 999);
        assert_eq!(cost.currency_code, "EUR");
    }

    #[test]
    fn currency_cost_usd_cents() {
        let cost = CurrencyCost::usd_cents(150);
        assert_eq!(cost.amount_cents, 150);
        assert_eq!(cost.currency_code, "USD");
    }

    #[test]
    fn currency_cost_serialization() {
        let cost = CurrencyCost::new(2500, "GBP");
        let json_str = serde_json::to_string(&cost).expect("serialization should succeed");

        assert!(json_str.contains("2500"));
        assert!(json_str.contains("GBP"));

        let parsed: CurrencyCost = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed.amount_cents, 2500);
        assert_eq!(parsed.currency_code, "GBP");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// RESOURCE AVAILABILITY TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod resource_availability {
    use super::*;

    #[test]
    fn available_resource() {
        let avail = ResourceAvailability::available();
        assert!(avail.available);
        assert!(avail.rate_limit_remaining.is_none());
        assert!(avail.rate_limit_reset_at.is_none());
        assert!(avail.details.is_none());
    }

    #[test]
    fn unavailable_resource() {
        let avail = ResourceAvailability::unavailable("Resource not found");
        assert!(!avail.available);
        assert_eq!(avail.details, Some("Resource not found".into()));
    }

    #[test]
    fn resource_with_rate_limit() {
        let avail = ResourceAvailability::available().with_rate_limit(50, Some(1_700_000_000));

        assert!(avail.available);
        assert_eq!(avail.rate_limit_remaining, Some(50));
        assert_eq!(avail.rate_limit_reset_at, Some(1_700_000_000));
    }

    #[test]
    fn resource_with_details() {
        let avail = ResourceAvailability::available().with_details("Healthy");
        assert_eq!(avail.details, Some("Healthy".into()));
    }

    #[test]
    fn resource_availability_serialization_roundtrip() {
        let avail = ResourceAvailability::available()
            .with_rate_limit(100, Some(1_700_000_000))
            .with_details("API healthy");

        let json_str = serde_json::to_string(&avail).expect("serialization should succeed");
        let parsed: ResourceAvailability = serde_json::from_str(&json_str).unwrap();

        assert_eq!(avail.available, parsed.available);
        assert_eq!(avail.rate_limit_remaining, parsed.rate_limit_remaining);
        assert_eq!(avail.rate_limit_reset_at, parsed.rate_limit_reset_at);
        assert_eq!(avail.details, parsed.details);
    }

    #[test]
    fn resource_availability_deterministic() {
        let avail1 = ResourceAvailability::available().with_rate_limit(100, Some(1_700_000_000));
        let avail2 = ResourceAvailability::available().with_rate_limit(100, Some(1_700_000_000));

        let json1 = serde_json::to_string(&avail1).unwrap();
        let json2 = serde_json::to_string(&avail2).unwrap();

        assert_eq!(
            json1, json2,
            "ResourceAvailability serialization must be deterministic"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// GOLDEN VECTOR GENERATION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
#[allow(clippy::too_many_lines)]
fn generate_simulate_request_vectors() {
    log_test_event(
        "generate_simulate_request_vectors",
        "test_start",
        &serde_json::json!({"purpose": "Generate CBOR vectors for simulate requests"}),
    );

    let mut vectors: Vec<SimulateRequestVector> = Vec::new();

    // Vector 1: Basic simulate request
    let req1 = SimulateRequest::new(
        ConnectorId::new("anthropic", "claude", "v1").unwrap(),
        OperationId::new("messages.create").unwrap(),
        ZoneId::work(),
        json!({"model": "claude-3", "messages": []}),
        CapabilityToken::test_token(),
    );

    vectors.push(SimulateRequestVector {
        description: "Basic simulate request without cost/availability flags".to_string(),
        request_id: req1.id.0.clone(),
        connector_id: req1.connector_id.as_str().to_string(),
        operation: req1.operation.as_str().to_string(),
        zone_id: req1.zone_id.as_str().to_string(),
        estimate_cost: req1.estimate_cost,
        check_availability: req1.check_availability,
        has_context: req1.context.is_some(),
        has_correlation_id: req1.correlation_id.is_some(),
    });

    // Vector 2: Request with cost estimation
    let req2 = SimulateRequest::new(
        ConnectorId::new("openai", "gpt", "v1").unwrap(),
        OperationId::new("completions.create").unwrap(),
        ZoneId::private(),
        json!({"model": "gpt-4", "prompt": "test"}),
        CapabilityToken::test_token(),
    )
    .with_cost_estimate();

    vectors.push(SimulateRequestVector {
        description: "Simulate request with cost estimation enabled".to_string(),
        request_id: req2.id.0.clone(),
        connector_id: req2.connector_id.as_str().to_string(),
        operation: req2.operation.as_str().to_string(),
        zone_id: req2.zone_id.as_str().to_string(),
        estimate_cost: req2.estimate_cost,
        check_availability: req2.check_availability,
        has_context: req2.context.is_some(),
        has_correlation_id: req2.correlation_id.is_some(),
    });

    // Vector 3: Request with availability check
    let req3 = SimulateRequest::new(
        ConnectorId::new("discord", "bot", "v1").unwrap(),
        OperationId::new("messages.send").unwrap(),
        ZoneId::community(),
        json!({"channel_id": "123", "content": "test"}),
        CapabilityToken::test_token(),
    )
    .with_availability_check();

    vectors.push(SimulateRequestVector {
        description: "Simulate request with availability check enabled".to_string(),
        request_id: req3.id.0.clone(),
        connector_id: req3.connector_id.as_str().to_string(),
        operation: req3.operation.as_str().to_string(),
        zone_id: req3.zone_id.as_str().to_string(),
        estimate_cost: req3.estimate_cost,
        check_availability: req3.check_availability,
        has_context: req3.context.is_some(),
        has_correlation_id: req3.correlation_id.is_some(),
    });

    // Vector 4: Full request with all options
    let req4 = SimulateRequest::new(
        ConnectorId::new("twitter", "api", "v2").unwrap(),
        OperationId::new("tweets.create").unwrap(),
        ZoneId::public(),
        json!({"text": "Hello world"}),
        CapabilityToken::test_token(),
    )
    .with_cost_estimate()
    .with_availability_check()
    .with_context(InvokeContext {
        locale: Some("en-US".into()),
        pagination: None,
        trace_id: Some("trace123".into()),
        request_tags: HashMap::new(),
    })
    .with_correlation_id(CorrelationId::new());

    vectors.push(SimulateRequestVector {
        description: "Full simulate request with all options enabled".to_string(),
        request_id: req4.id.0.clone(),
        connector_id: req4.connector_id.as_str().to_string(),
        operation: req4.operation.as_str().to_string(),
        zone_id: req4.zone_id.as_str().to_string(),
        estimate_cost: req4.estimate_cost,
        check_availability: req4.check_availability,
        has_context: req4.context.is_some(),
        has_correlation_id: req4.correlation_id.is_some(),
    });

    // Ensure vectors directory exists
    let dir = vectors_dir();
    fs::create_dir_all(&dir).expect("Failed to create vectors directory");

    // Serialize to CBOR
    let path = dir.join("simulate_request_vectors.cbor");
    let mut buffer = Vec::new();
    ciborium::into_writer(&vectors, &mut buffer).expect("CBOR serialization failed");
    fs::write(&path, &buffer).expect("Failed to write CBOR file");

    log_test_event(
        "generate_simulate_request_vectors",
        "vector_written",
        &serde_json::json!({
            "path": path.display().to_string(),
            "size_bytes": buffer.len(),
            "vector_count": vectors.len()
        }),
    );

    // Verify round-trip
    let data = fs::read(&path).expect("Failed to read CBOR file");
    let loaded: Vec<SimulateRequestVector> =
        ciborium::from_reader(data.as_slice()).expect("CBOR deserialization failed");

    assert_eq!(loaded.len(), 4);
    assert_eq!(loaded, vectors);

    log_test_event(
        "generate_simulate_request_vectors",
        "test_complete",
        &serde_json::json!({"vectors_verified": vectors.len()}),
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn generate_simulate_response_vectors() {
    log_test_event(
        "generate_simulate_response_vectors",
        "test_start",
        &serde_json::json!({"purpose": "Generate CBOR vectors for simulate responses"}),
    );

    let mut vectors: Vec<SimulateResponseVector> = Vec::new();

    // Vector 1: Simple allowed response (simulate_preflight_allow)
    let resp1 = SimulateResponse::allowed(RequestId::new("req_allow_001"));

    vectors.push(SimulateResponseVector {
        description: "Simple allowed response - operation would succeed".to_string(),
        request_id: resp1.id.0.clone(),
        would_succeed: resp1.would_succeed,
        has_failure_reason: resp1.failure_reason.is_some(),
        has_denial_code: resp1.denial_code.is_some(),
        missing_capabilities_count: resp1.missing_capabilities.len(),
        has_cost_estimate: resp1.estimated_cost.is_some(),
        has_availability: resp1.availability.is_some(),
        has_metadata: resp1.response_metadata.is_some(),
    });

    // Vector 2: Denied response with missing capabilities (simulate_preflight_deny_capability)
    let resp2 = SimulateResponse::denied(
        RequestId::new("req_deny_002"),
        "Missing required capabilities for operation",
        "FCP-3001",
    )
    .with_missing_capabilities(vec![
        "cap.messages.write".into(),
        "cap.messages.delete".into(),
    ]);

    vectors.push(SimulateResponseVector {
        description: "Denied response - missing required capabilities".to_string(),
        request_id: resp2.id.0.clone(),
        would_succeed: resp2.would_succeed,
        has_failure_reason: resp2.failure_reason.is_some(),
        has_denial_code: resp2.denial_code.is_some(),
        missing_capabilities_count: resp2.missing_capabilities.len(),
        has_cost_estimate: resp2.estimated_cost.is_some(),
        has_availability: resp2.availability.is_some(),
        has_metadata: resp2.response_metadata.is_some(),
    });

    // Vector 3: Allowed with cost estimate
    let resp3 = SimulateResponse::allowed(RequestId::new("req_cost_003")).with_cost_estimate(
        CostEstimate::with_credits(1500)
            .and_duration_ms(250)
            .and_bytes(4096),
    );

    vectors.push(SimulateResponseVector {
        description: "Allowed response with cost estimate populated".to_string(),
        request_id: resp3.id.0.clone(),
        would_succeed: resp3.would_succeed,
        has_failure_reason: resp3.failure_reason.is_some(),
        has_denial_code: resp3.denial_code.is_some(),
        missing_capabilities_count: resp3.missing_capabilities.len(),
        has_cost_estimate: resp3.estimated_cost.is_some(),
        has_availability: resp3.availability.is_some(),
        has_metadata: resp3.response_metadata.is_some(),
    });

    // Vector 4: Allowed with availability
    let resp4 = SimulateResponse::allowed(RequestId::new("req_avail_004")).with_availability(
        ResourceAvailability::available()
            .with_rate_limit(100, Some(1_700_000_000))
            .with_details("API healthy, rate limit headroom available"),
    );

    vectors.push(SimulateResponseVector {
        description: "Allowed response with resource availability".to_string(),
        request_id: resp4.id.0.clone(),
        would_succeed: resp4.would_succeed,
        has_failure_reason: resp4.failure_reason.is_some(),
        has_denial_code: resp4.denial_code.is_some(),
        missing_capabilities_count: resp4.missing_capabilities.len(),
        has_cost_estimate: resp4.estimated_cost.is_some(),
        has_availability: resp4.availability.is_some(),
        has_metadata: resp4.response_metadata.is_some(),
    });

    // Vector 5: Full response with all fields
    let resp5 = SimulateResponse::allowed(RequestId::new("req_full_005"))
        .with_cost_estimate(
            CostEstimate::with_credits(2000)
                .and_duration_ms(500)
                .and_bytes(8192)
                .and_currency(CurrencyCost::usd_cents(25)),
        )
        .with_availability(ResourceAvailability::available().with_rate_limit(50, None))
        .with_metadata(ResponseMetadata {
            processing_time_ms: Some(15),
            cache_ttl_secs: Some(60),
            from_cache: false,
            retry_after_secs: None,
        });

    vectors.push(SimulateResponseVector {
        description: "Full allowed response with cost, availability, and metadata".to_string(),
        request_id: resp5.id.0.clone(),
        would_succeed: resp5.would_succeed,
        has_failure_reason: resp5.failure_reason.is_some(),
        has_denial_code: resp5.denial_code.is_some(),
        missing_capabilities_count: resp5.missing_capabilities.len(),
        has_cost_estimate: resp5.estimated_cost.is_some(),
        has_availability: resp5.availability.is_some(),
        has_metadata: resp5.response_metadata.is_some(),
    });

    // Vector 6: Denied due to rate limiting
    let resp6 = SimulateResponse::denied(
        RequestId::new("req_ratelimit_006"),
        "Rate limit exceeded",
        "FCP-4029",
    )
    .with_availability(
        ResourceAvailability::unavailable("Rate limit exhausted")
            .with_rate_limit(0, Some(1_700_001_000)),
    );

    vectors.push(SimulateResponseVector {
        description: "Denied response - rate limit exceeded".to_string(),
        request_id: resp6.id.0.clone(),
        would_succeed: resp6.would_succeed,
        has_failure_reason: resp6.failure_reason.is_some(),
        has_denial_code: resp6.denial_code.is_some(),
        missing_capabilities_count: resp6.missing_capabilities.len(),
        has_cost_estimate: resp6.estimated_cost.is_some(),
        has_availability: resp6.availability.is_some(),
        has_metadata: resp6.response_metadata.is_some(),
    });

    // Ensure vectors directory exists
    let dir = vectors_dir();
    fs::create_dir_all(&dir).expect("Failed to create vectors directory");

    // Serialize to CBOR
    let path = dir.join("simulate_response_vectors.cbor");
    let mut buffer = Vec::new();
    ciborium::into_writer(&vectors, &mut buffer).expect("CBOR serialization failed");
    fs::write(&path, &buffer).expect("Failed to write CBOR file");

    log_test_event(
        "generate_simulate_response_vectors",
        "vector_written",
        &serde_json::json!({
            "path": path.display().to_string(),
            "size_bytes": buffer.len(),
            "vector_count": vectors.len()
        }),
    );

    // Verify round-trip
    let data = fs::read(&path).expect("Failed to read CBOR file");
    let loaded: Vec<SimulateResponseVector> =
        ciborium::from_reader(data.as_slice()).expect("CBOR deserialization failed");

    assert_eq!(loaded.len(), 6);
    assert_eq!(loaded, vectors);

    log_test_event(
        "generate_simulate_response_vectors",
        "test_complete",
        &serde_json::json!({"vectors_verified": vectors.len()}),
    );
}

#[test]
fn generate_cost_estimate_vectors() {
    log_test_event(
        "generate_cost_estimate_vectors",
        "test_start",
        &serde_json::json!({"purpose": "Generate CBOR vectors for cost estimates"}),
    );

    let mut vectors: Vec<CostEstimateVector> = Vec::new();

    // Vector 1: Empty cost estimate
    let cost1 = CostEstimate::default();
    vectors.push(CostEstimateVector {
        description: "Empty cost estimate (all fields None)".to_string(),
        has_api_credits: cost1.api_credits.is_some(),
        api_credits: cost1.api_credits,
        has_duration_ms: cost1.estimated_duration_ms.is_some(),
        duration_ms: cost1.estimated_duration_ms,
        has_bytes: cost1.estimated_bytes.is_some(),
        bytes: cost1.estimated_bytes,
        has_currency: cost1.currency.is_some(),
        currency_code: None,
        currency_cents: None,
    });

    // Vector 2: Credits only
    let cost2 = CostEstimate::with_credits(1000);
    vectors.push(CostEstimateVector {
        description: "Cost estimate with API credits only".to_string(),
        has_api_credits: cost2.api_credits.is_some(),
        api_credits: cost2.api_credits,
        has_duration_ms: cost2.estimated_duration_ms.is_some(),
        duration_ms: cost2.estimated_duration_ms,
        has_bytes: cost2.estimated_bytes.is_some(),
        bytes: cost2.estimated_bytes,
        has_currency: cost2.currency.is_some(),
        currency_code: None,
        currency_cents: None,
    });

    // Vector 3: Full cost estimate with currency
    let cost3 = CostEstimate::with_credits(5000)
        .and_duration_ms(1000)
        .and_bytes(16384)
        .and_currency(CurrencyCost::usd_cents(100));
    vectors.push(CostEstimateVector {
        description: "Full cost estimate with all fields including currency".to_string(),
        has_api_credits: cost3.api_credits.is_some(),
        api_credits: cost3.api_credits,
        has_duration_ms: cost3.estimated_duration_ms.is_some(),
        duration_ms: cost3.estimated_duration_ms,
        has_bytes: cost3.estimated_bytes.is_some(),
        bytes: cost3.estimated_bytes,
        has_currency: cost3.currency.is_some(),
        currency_code: cost3.currency.as_ref().map(|c| c.currency_code.clone()),
        currency_cents: cost3.currency.as_ref().map(|c| c.amount_cents),
    });

    // Ensure vectors directory exists
    let dir = vectors_dir();
    fs::create_dir_all(&dir).expect("Failed to create vectors directory");

    // Serialize to CBOR
    let path = dir.join("cost_estimate_vectors.cbor");
    let mut buffer = Vec::new();
    ciborium::into_writer(&vectors, &mut buffer).expect("CBOR serialization failed");
    fs::write(&path, &buffer).expect("Failed to write CBOR file");

    log_test_event(
        "generate_cost_estimate_vectors",
        "vector_written",
        &serde_json::json!({
            "path": path.display().to_string(),
            "size_bytes": buffer.len(),
            "vector_count": vectors.len()
        }),
    );

    // Verify round-trip
    let data = fs::read(&path).expect("Failed to read CBOR file");
    let loaded: Vec<CostEstimateVector> =
        ciborium::from_reader(data.as_slice()).expect("CBOR deserialization failed");

    assert_eq!(loaded.len(), 3);
    assert_eq!(loaded, vectors);

    log_test_event(
        "generate_cost_estimate_vectors",
        "test_complete",
        &serde_json::json!({"vectors_verified": vectors.len()}),
    );
}

#[test]
fn generate_resource_availability_vectors() {
    log_test_event(
        "generate_resource_availability_vectors",
        "test_start",
        &serde_json::json!({"purpose": "Generate CBOR vectors for resource availability"}),
    );

    let mut vectors: Vec<ResourceAvailabilityVector> = Vec::new();

    // Vector 1: Simple available
    let avail1 = ResourceAvailability::available();
    vectors.push(ResourceAvailabilityVector {
        description: "Simple available resource".to_string(),
        available: avail1.available,
        has_rate_limit_remaining: avail1.rate_limit_remaining.is_some(),
        rate_limit_remaining: avail1.rate_limit_remaining,
        has_rate_limit_reset_at: avail1.rate_limit_reset_at.is_some(),
        rate_limit_reset_at: avail1.rate_limit_reset_at,
        has_details: avail1.details.is_some(),
    });

    // Vector 2: Unavailable with details
    let avail2 = ResourceAvailability::unavailable("Resource not found");
    vectors.push(ResourceAvailabilityVector {
        description: "Unavailable resource with details".to_string(),
        available: avail2.available,
        has_rate_limit_remaining: avail2.rate_limit_remaining.is_some(),
        rate_limit_remaining: avail2.rate_limit_remaining,
        has_rate_limit_reset_at: avail2.rate_limit_reset_at.is_some(),
        rate_limit_reset_at: avail2.rate_limit_reset_at,
        has_details: avail2.details.is_some(),
    });

    // Vector 3: Available with rate limit info
    let avail3 = ResourceAvailability::available()
        .with_rate_limit(100, Some(1_700_000_000))
        .with_details("API healthy");
    vectors.push(ResourceAvailabilityVector {
        description: "Available with rate limit and details".to_string(),
        available: avail3.available,
        has_rate_limit_remaining: avail3.rate_limit_remaining.is_some(),
        rate_limit_remaining: avail3.rate_limit_remaining,
        has_rate_limit_reset_at: avail3.rate_limit_reset_at.is_some(),
        rate_limit_reset_at: avail3.rate_limit_reset_at,
        has_details: avail3.details.is_some(),
    });

    // Vector 4: Rate limited (remaining = 0)
    let avail4 = ResourceAvailability::unavailable("Rate limit exceeded")
        .with_rate_limit(0, Some(1_700_001_000));
    vectors.push(ResourceAvailabilityVector {
        description: "Rate limited - remaining is zero".to_string(),
        available: avail4.available,
        has_rate_limit_remaining: avail4.rate_limit_remaining.is_some(),
        rate_limit_remaining: avail4.rate_limit_remaining,
        has_rate_limit_reset_at: avail4.rate_limit_reset_at.is_some(),
        rate_limit_reset_at: avail4.rate_limit_reset_at,
        has_details: avail4.details.is_some(),
    });

    // Ensure vectors directory exists
    let dir = vectors_dir();
    fs::create_dir_all(&dir).expect("Failed to create vectors directory");

    // Serialize to CBOR
    let path = dir.join("resource_availability_vectors.cbor");
    let mut buffer = Vec::new();
    ciborium::into_writer(&vectors, &mut buffer).expect("CBOR serialization failed");
    fs::write(&path, &buffer).expect("Failed to write CBOR file");

    log_test_event(
        "generate_resource_availability_vectors",
        "vector_written",
        &serde_json::json!({
            "path": path.display().to_string(),
            "size_bytes": buffer.len(),
            "vector_count": vectors.len()
        }),
    );

    // Verify round-trip
    let data = fs::read(&path).expect("Failed to read CBOR file");
    let loaded: Vec<ResourceAvailabilityVector> =
        ciborium::from_reader(data.as_slice()).expect("CBOR deserialization failed");

    assert_eq!(loaded.len(), 4);
    assert_eq!(loaded, vectors);

    log_test_event(
        "generate_resource_availability_vectors",
        "test_complete",
        &serde_json::json!({"vectors_verified": vectors.len()}),
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// MISSING CAPABILITY STABILITY TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod missing_capabilities {
    use super::*;

    #[test]
    fn missing_capabilities_order_preserved() {
        let caps = vec![
            "cap.admin.read".to_string(),
            "cap.admin.write".to_string(),
            "cap.admin.delete".to_string(),
        ];

        let resp = SimulateResponse::denied(RequestId::new("req_caps"), "Missing caps", "FCP-3001")
            .with_missing_capabilities(caps.clone());

        assert_eq!(resp.missing_capabilities, caps);

        // Verify serialization preserves order
        let json_str = serde_json::to_string(&resp).unwrap();
        let parsed: SimulateResponse = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed.missing_capabilities, caps);
    }

    #[test]
    fn missing_capabilities_empty_list() {
        let resp = SimulateResponse::allowed(RequestId::new("req_empty"));
        assert_eq!(resp.missing_capabilities, [] as [std::string::String; 0]);

        let json_str = serde_json::to_string(&resp).unwrap();
        let parsed: SimulateResponse = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed.missing_capabilities, [] as [std::string::String; 0]);
    }

    #[test]
    fn missing_capabilities_single_item() {
        let resp =
            SimulateResponse::denied(RequestId::new("req_single"), "Missing cap", "FCP-3001")
                .with_missing_capabilities(vec!["cap.only.one".into()]);

        assert_eq!(resp.missing_capabilities.len(), 1);
        assert_eq!(resp.missing_capabilities[0], "cap.only.one");
    }

    #[test]
    fn missing_capabilities_deterministic_serialization() {
        let caps = vec!["cap.a".into(), "cap.b".into(), "cap.c".into()];

        let resp1 = SimulateResponse::denied(RequestId::new("req_det"), "Test", "FCP-TEST")
            .with_missing_capabilities(caps.clone());
        let resp2 = SimulateResponse::denied(RequestId::new("req_det"), "Test", "FCP-TEST")
            .with_missing_capabilities(caps);

        let json1 = serde_json::to_string(&resp1).unwrap();
        let json2 = serde_json::to_string(&resp2).unwrap();

        assert_eq!(
            json1, json2,
            "Missing capabilities serialization must be deterministic"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ADVERSARIAL INPUT TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod adversarial {
    use super::*;

    #[test]
    fn extremely_long_failure_reason() {
        let long_reason = "x".repeat(10000);
        let resp = SimulateResponse::denied(RequestId::new("req_long"), long_reason, "FCP-TEST");

        assert_eq!(resp.failure_reason.unwrap().len(), 10000);
    }

    #[test]
    fn unicode_in_failure_reason() {
        let unicode_reason = "失败原因: Rate limit 🚫 exceeded مرحبا";
        let resp =
            SimulateResponse::denied(RequestId::new("req_unicode"), unicode_reason, "FCP-TEST");

        let json_str = serde_json::to_string(&resp).unwrap();
        let parsed: SimulateResponse = serde_json::from_str(&json_str).unwrap();

        assert_eq!(parsed.failure_reason.unwrap(), unicode_reason);
    }

    #[test]
    fn large_missing_capabilities_list() {
        let caps: Vec<String> = (0..1000).map(|i| format!("cap.test.{i}")).collect();

        let resp = SimulateResponse::denied(RequestId::new("req_many"), "Many caps", "FCP-3001")
            .with_missing_capabilities(caps);

        assert_eq!(resp.missing_capabilities.len(), 1000);

        // Verify serialization handles large lists
        let json_str = serde_json::to_string(&resp).unwrap();
        let parsed: SimulateResponse = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed.missing_capabilities.len(), 1000);
    }

    #[test]
    fn extremely_large_cost_values() {
        let cost = CostEstimate::with_credits(u64::MAX)
            .and_duration_ms(u64::MAX)
            .and_bytes(u64::MAX);

        let json_str = serde_json::to_string(&cost).unwrap();
        let parsed: CostEstimate = serde_json::from_str(&json_str).unwrap();

        assert_eq!(parsed.api_credits, Some(u64::MAX));
        assert_eq!(parsed.estimated_duration_ms, Some(u64::MAX));
        assert_eq!(parsed.estimated_bytes, Some(u64::MAX));
    }

    #[test]
    fn zero_cost_values() {
        let cost = CostEstimate::with_credits(0)
            .and_duration_ms(0)
            .and_bytes(0);

        assert_eq!(cost.api_credits, Some(0));
        assert_eq!(cost.estimated_duration_ms, Some(0));
        assert_eq!(cost.estimated_bytes, Some(0));
    }

    #[test]
    fn empty_denial_code() {
        let resp = SimulateResponse::denied(RequestId::new("req_empty_code"), "Reason", "");

        assert_eq!(resp.denial_code, Some(String::new()));
    }

    #[test]
    fn special_characters_in_details() {
        let details = r#"Details with "quotes", \backslashes\, and <tags>"#;
        let avail = ResourceAvailability::available().with_details(details);

        let json_str = serde_json::to_string(&avail).unwrap();
        let parsed: ResourceAvailability = serde_json::from_str(&json_str).unwrap();

        assert_eq!(parsed.details.unwrap(), details);
    }
}
