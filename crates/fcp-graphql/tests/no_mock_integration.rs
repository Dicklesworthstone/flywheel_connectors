//! No-mock integration tests for fcp-graphql.
//!
//! These tests exercise cross-module interactions without mocking frameworks,
//! verifying that client, error, retry, schema, operation, pagination, and
//! subscription modules compose correctly.

use std::time::Duration;

use fcp_async_core::http::StatusCode;
use fcp_graphql::{
    CursorPage, CursorPageInfo, GraphqlBatchItem, GraphqlClient, GraphqlClientBuilder,
    GraphqlClientError, GraphqlError, GraphqlErrorLocation, GraphqlOperation, GraphqlPathSegment,
    GraphqlQuery, GraphqlRequest, GraphqlResponse, GraphqlSubscriptionClient,
    GraphqlSubscriptionConfig, OffsetPage, PageLimit, PaginationError, RetryDecision, RetryPolicy,
    RetryStrategy, SchemaValidationMode,
};
use fcp_prelude::FcpError;
use serde::{Deserialize, Serialize};
use serde_json::json;

// ── Test operation type ──

#[derive(Debug, Serialize, Deserialize)]
struct GetUserVars {
    id: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct GetUserData {
    name: String,
    email: Option<String>,
}

struct GetUser;

impl GraphqlOperation for GetUser {
    type Variables = GetUserVars;
    type ResponseData = GetUserData;

    const QUERY: &'static str = "query GetUser($id: ID!) { user(id: $id) { name email } }";
    const OPERATION_NAME: &'static str = "GetUser";

    fn variables_schema() -> Option<&'static str> {
        Some(r#"{"type":"object","required":["id"],"properties":{"id":{"type":"string"}}}"#)
    }

    fn response_schema() -> Option<&'static str> {
        Some(
            r#"{"type":"object","required":["name"],"properties":{"name":{"type":"string"},"email":{"type":["string","null"]}}}"#,
        )
    }
}

struct CreatePost;

#[derive(Debug, Serialize, Deserialize)]
struct CreatePostVars {
    title: String,
    body: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CreatePostData {
    id: String,
}

impl GraphqlOperation for CreatePost {
    type Variables = CreatePostVars;
    type ResponseData = CreatePostData;

    const QUERY: &'static str = "mutation CreatePost($title: String!, $body: String!) { createPost(title: $title, body: $body) { id } }";
    const OPERATION_NAME: &'static str = "CreatePost";

    fn is_idempotent() -> bool {
        false
    }
}

// ═══════════════════════════════════════════════════════════════
// 1. Builder → Client → Config pipeline
// ═══════════════════════════════════════════════════════════════

#[test]
fn builder_full_chain_produces_configured_client() {
    let policy = RetryPolicy {
        max_attempts: 5,
        base_delay: Duration::from_millis(500),
        max_delay: Duration::from_secs(10),
        max_jitter: Duration::ZERO,
        strategy: RetryStrategy::Always,
    };

    let client = GraphqlClientBuilder::new("https://api.example.com/graphql")
        .with_service_name("test-svc")
        .with_bearer_token("tok_123")
        .with_header("X-Request-Id", "req-001")
        .with_timeout(Duration::from_secs(60))
        .with_retry_policy(policy)
        .with_dedup_in_flight(true)
        .with_validation_mode(SchemaValidationMode::VariablesAndResponse)
        .build()
        .unwrap();

    let snap = client.metrics();
    assert_eq!(snap.requests_total, 0);
    assert_eq!(snap.requests_success, 0);
    assert_eq!(snap.requests_error, 0);
    assert_eq!(snap.requests_retried, 0);
}

#[test]
fn builder_default_config_matches_expectations() {
    let client = GraphqlClient::new("https://graphql.test/v1");
    let debug = format!("{client:?}");
    assert!(debug.contains("GraphqlClient"));
    assert!(debug.contains("graphql.test"));
    assert!(debug.contains("dedup_in_flight"));
}

#[test]
fn client_clone_shares_metrics_arc() {
    let client = GraphqlClient::new("https://api.test.com/graphql");
    let cloned = client.clone();
    let s1 = client.metrics();
    let s2 = cloned.metrics();
    assert_eq!(s1, s2);
}

// ═══════════════════════════════════════════════════════════════
// 2. Error → is_retryable → RetryPolicy pipeline
// ═══════════════════════════════════════════════════════════════

fn server_error_500() -> GraphqlClientError {
    GraphqlClientError::HttpStatus {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        body: "internal error".into(),
        retry_after: None,
    }
}

fn server_error_503() -> GraphqlClientError {
    GraphqlClientError::HttpStatus {
        status: StatusCode::SERVICE_UNAVAILABLE,
        body: "service unavailable".into(),
        retry_after: None,
    }
}

fn rate_limit_error() -> GraphqlClientError {
    GraphqlClientError::HttpStatus {
        status: StatusCode::TOO_MANY_REQUESTS,
        body: "slow down".into(),
        retry_after: Some(Duration::from_secs(30)),
    }
}

fn auth_error_401() -> GraphqlClientError {
    GraphqlClientError::HttpStatus {
        status: StatusCode::UNAUTHORIZED,
        body: "bad token".into(),
        retry_after: None,
    }
}

fn json_parse_error() -> GraphqlClientError {
    GraphqlClientError::Json("unexpected token at position 0".into())
}

fn graphql_field_error() -> GraphqlClientError {
    GraphqlClientError::GraphqlErrors {
        errors: vec![
            GraphqlError {
                message: "Cannot query field 'x' on type 'User'".into(),
                locations: vec![GraphqlErrorLocation { line: 2, column: 5 }],
                path: vec![GraphqlPathSegment::Key("user".into())],
                extensions: Some(json!({"code": "GRAPHQL_VALIDATION_FAILED"})),
            },
            GraphqlError {
                message: "Variable $id is required".into(),
                locations: vec![],
                path: vec![],
                extensions: None,
            },
        ],
    }
}

#[test]
fn retryable_errors_allow_retry_with_always_strategy() {
    let policy = RetryPolicy {
        max_attempts: 3,
        base_delay: Duration::from_millis(100),
        max_delay: Duration::from_secs(5),
        max_jitter: Duration::ZERO,
        strategy: RetryStrategy::Always,
    };

    let retryable = [server_error_500(), server_error_503(), server_error_500()];

    for (i, err) in retryable.iter().enumerate() {
        assert!(err.is_retryable(), "error {i} should be retryable: {err}");
        let decision = policy.decide(err, 1, false);
        assert!(
            matches!(decision, RetryDecision::RetryAfter(_)),
            "error {i} should produce RetryAfter, got {decision:?}"
        );
    }
}

#[test]
fn non_retryable_errors_never_retry() {
    let policy = RetryPolicy {
        strategy: RetryStrategy::Always,
        ..RetryPolicy::default()
    };

    let non_retryable = [
        json_parse_error(),
        graphql_field_error(),
        GraphqlClientError::Protocol {
            message: "bad frame".into(),
        },
        GraphqlClientError::SchemaValidation {
            message: "type mismatch".into(),
            errors: vec!["field x wrong".into()],
        },
        GraphqlClientError::RetriesExhausted { attempts: 3 },
    ];

    for (i, err) in non_retryable.iter().enumerate() {
        assert!(
            !err.is_retryable(),
            "error {i} should not be retryable: {err}"
        );
        let decision = policy.decide(err, 1, true);
        assert_eq!(
            decision,
            RetryDecision::DoNotRetry,
            "error {i} should DoNotRetry"
        );
    }
}

#[test]
fn idempotent_only_blocks_non_idempotent_retries() {
    let policy = RetryPolicy {
        strategy: RetryStrategy::IdempotentOnly,
        max_jitter: Duration::ZERO,
        ..RetryPolicy::default()
    };

    let err = server_error_500();
    assert_eq!(
        policy.decide(&err, 1, false),
        RetryDecision::DoNotRetry,
        "non-idempotent + IdempotentOnly should not retry"
    );
    assert!(
        matches!(policy.decide(&err, 1, true), RetryDecision::RetryAfter(_)),
        "idempotent + IdempotentOnly should retry"
    );
}

#[test]
fn retry_backoff_exponential_with_cap() {
    let policy = RetryPolicy {
        max_attempts: 10,
        base_delay: Duration::from_millis(100),
        max_delay: Duration::from_millis(500),
        max_jitter: Duration::ZERO,
        strategy: RetryStrategy::Always,
    };

    let err = server_error_500();

    // attempt 1: 2^0 * 100 = 100
    match policy.decide(&err, 1, true) {
        RetryDecision::RetryAfter(d) => assert_eq!(d.as_millis(), 100),
        other => panic!("expected RetryAfter, got {other:?}"),
    }
    // attempt 2: 2^1 * 100 = 200
    match policy.decide(&err, 2, true) {
        RetryDecision::RetryAfter(d) => assert_eq!(d.as_millis(), 200),
        other => panic!("expected RetryAfter, got {other:?}"),
    }
    // attempt 3: 2^2 * 100 = 400
    match policy.decide(&err, 3, true) {
        RetryDecision::RetryAfter(d) => assert_eq!(d.as_millis(), 400),
        other => panic!("expected RetryAfter, got {other:?}"),
    }
    // attempt 4: 2^3 * 100 = 800 → capped at 500
    match policy.decide(&err, 4, true) {
        RetryDecision::RetryAfter(d) => assert_eq!(d.as_millis(), 500),
        other => panic!("expected RetryAfter, got {other:?}"),
    }
}

#[test]
fn retry_exhaustion_at_max_attempts() {
    let policy = RetryPolicy {
        max_attempts: 3,
        ..RetryPolicy::default()
    };
    let err = server_error_500();
    assert_eq!(policy.decide(&err, 3, true), RetryDecision::DoNotRetry);
    assert_eq!(policy.decide(&err, 4, true), RetryDecision::DoNotRetry);
}

// ═══════════════════════════════════════════════════════════════
// 3. Error → to_fcp_error mapping
// ═══════════════════════════════════════════════════════════════

#[test]
fn error_to_fcp_error_complete_mapping() {
    let service = "github";

    // 500 → External retryable
    match server_error_500().to_fcp_error(service) {
        FcpError::External {
            service: s,
            retryable,
            status_code,
            ..
        } => {
            assert_eq!(s, "github");
            assert!(retryable);
            assert_eq!(status_code, Some(500));
        }
        other => panic!("expected External, got {other:?}"),
    }

    // 503 → External retryable
    match server_error_503().to_fcp_error(service) {
        FcpError::External {
            retryable,
            status_code,
            ..
        } => {
            assert!(retryable);
            assert_eq!(status_code, Some(503));
        }
        other => panic!("expected External retryable, got {other:?}"),
    }

    // 429 with retry_after → RateLimited
    match rate_limit_error().to_fcp_error(service) {
        FcpError::RateLimited { retry_after_ms, .. } => assert_eq!(retry_after_ms, 30_000),
        other => panic!("expected RateLimited, got {other:?}"),
    }

    // 429 without retry_after → RateLimited with default 1000ms
    let err_429_no_retry = GraphqlClientError::HttpStatus {
        status: StatusCode::TOO_MANY_REQUESTS,
        body: String::new(),
        retry_after: None,
    };
    match err_429_no_retry.to_fcp_error(service) {
        FcpError::RateLimited { retry_after_ms, .. } => assert_eq!(retry_after_ms, 1000),
        other => panic!("expected RateLimited, got {other:?}"),
    }

    // 401 → Unauthorized
    match auth_error_401().to_fcp_error(service) {
        FcpError::Unauthorized { message, .. } => {
            assert!(message.contains("github unauthorized"));
        }
        other => panic!("expected Unauthorized, got {other:?}"),
    }

    // 403 → Unauthorized
    let err_403 = GraphqlClientError::HttpStatus {
        status: StatusCode::FORBIDDEN,
        body: "no access".into(),
        retry_after: None,
    };
    match err_403.to_fcp_error(service) {
        FcpError::Unauthorized { message, .. } => {
            assert!(message.contains("github unauthorized"));
        }
        other => panic!("expected Unauthorized, got {other:?}"),
    }

    // Json → MalformedFrame
    match json_parse_error().to_fcp_error(service) {
        FcpError::MalformedFrame { code, message } => {
            assert_eq!(code, 2004);
            assert!(message.contains("JSON parsing"));
        }
        other => panic!("expected MalformedFrame, got {other:?}"),
    }

    // GraphqlErrors → External (first error message)
    match graphql_field_error().to_fcp_error(service) {
        FcpError::External {
            message, retryable, ..
        } => {
            assert!(message.contains("Cannot query field"));
            assert!(!retryable);
        }
        other => panic!("expected External, got {other:?}"),
    }

    // Protocol → InvalidRequest code 1002
    let err_proto = GraphqlClientError::Protocol {
        message: "bad frame".into(),
    };
    match err_proto.to_fcp_error(service) {
        FcpError::InvalidRequest { code, message } => {
            assert_eq!(code, 1002);
            assert_eq!(message, "bad frame");
        }
        other => panic!("expected InvalidRequest, got {other:?}"),
    }

    // SchemaValidation → InvalidRequest code 1003
    let err_schema = GraphqlClientError::SchemaValidation {
        message: "type mismatch".into(),
        errors: vec!["field x".into()],
    };
    match err_schema.to_fcp_error(service) {
        FcpError::InvalidRequest { code, message } => {
            assert_eq!(code, 1003);
            assert_eq!(message, "type mismatch");
        }
        other => panic!("expected InvalidRequest, got {other:?}"),
    }

    // RetriesExhausted → External non-retryable
    let err_exhausted = GraphqlClientError::RetriesExhausted { attempts: 5 };
    match err_exhausted.to_fcp_error(service) {
        FcpError::External {
            retryable, message, ..
        } => {
            assert!(!retryable);
            assert!(message.contains("5 attempts"));
        }
        other => panic!("expected External, got {other:?}"),
    }
}

// ═══════════════════════════════════════════════════════════════
// 4. Operation + Request + Response serde roundtrips
// ═══════════════════════════════════════════════════════════════

#[test]
fn operation_request_serde_roundtrip() {
    let req = GraphqlRequest::new(
        GraphqlQuery::from_static(GetUser::QUERY),
        GetUserVars {
            id: "user-42".into(),
        },
    )
    .with_operation_name(GetUser::OPERATION_NAME);

    let json = serde_json::to_string(&req).unwrap();
    let parsed: GraphqlRequest<GetUserVars> = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.query.as_str(), GetUser::QUERY);
    assert_eq!(parsed.variables.id, "user-42");
    assert_eq!(parsed.operation_name.as_deref(), Some("GetUser"));
}

#[test]
fn response_with_data_and_no_errors_is_ok() {
    let json = r#"{"data":{"name":"Alice","email":"alice@test.com"},"errors":[]}"#;
    let resp: GraphqlResponse<GetUserData> = serde_json::from_str(json).unwrap();
    assert!(resp.is_ok());
    let data = resp.data.unwrap();
    assert_eq!(data.name, "Alice");
    assert_eq!(data.email.as_deref(), Some("alice@test.com"));
}

#[test]
fn response_with_errors_and_partial_data() {
    let json = r#"{
        "data": {"name": "Alice", "email": null},
        "errors": [
            {"message": "rate limited", "locations": [{"line": 1, "column": 1}], "path": ["user"]},
            {"message": "field deprecated"}
        ]
    }"#;
    let resp: GraphqlResponse<GetUserData> = serde_json::from_str(json).unwrap();
    assert!(!resp.is_ok());
    assert_eq!(resp.errors.len(), 2);
    assert!(resp.data.is_some());
    assert_eq!(resp.errors[0].locations.len(), 1);
    assert_eq!(resp.errors[0].locations[0].line, 1);
    assert_eq!(resp.errors[0].path.len(), 1);
    assert_eq!(
        resp.errors[0].path[0],
        GraphqlPathSegment::Key("user".into())
    );
}

#[test]
fn response_minimal_json_defaults() {
    let resp: GraphqlResponse<serde_json::Value> = serde_json::from_str("{}").unwrap();
    assert!(resp.data.is_none());
    assert!(resp.errors.is_empty());
    assert!(resp.extensions.is_none());
    assert!(resp.is_ok());
}

#[test]
fn batch_item_serde_roundtrip() {
    let item = GraphqlBatchItem::new(
        GraphqlQuery::from_static(GetUser::QUERY),
        GetUserVars {
            id: "user-1".into(),
        },
    )
    .with_operation_name("GetUser");

    let json = serde_json::to_string(&item).unwrap();
    assert!(json.contains("operationName"));
    assert!(!json.contains("operation_name"));
    let parsed: GraphqlBatchItem<GetUserVars> = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.query.as_str(), GetUser::QUERY);
    assert_eq!(parsed.variables.id, "user-1");
    assert_eq!(parsed.operation_name.as_deref(), Some("GetUser"));
}

#[test]
fn graphql_error_full_serde_with_extensions() {
    let err = GraphqlError {
        message: "Unauthorized".into(),
        locations: vec![
            GraphqlErrorLocation { line: 1, column: 1 },
            GraphqlErrorLocation { line: 3, column: 5 },
        ],
        path: vec![
            GraphqlPathSegment::Key("users".into()),
            GraphqlPathSegment::Index(0),
            GraphqlPathSegment::Key("name".into()),
        ],
        extensions: Some(json!({
            "code": "UNAUTHENTICATED",
            "timestamp": "2025-01-01T00:00:00Z"
        })),
    };

    let json_str = serde_json::to_string(&err).unwrap();
    let parsed: GraphqlError = serde_json::from_str(&json_str).unwrap();
    assert_eq!(parsed.message, "Unauthorized");
    assert_eq!(parsed.locations.len(), 2);
    assert_eq!(parsed.path.len(), 3);
    assert_eq!(
        parsed.extensions.as_ref().unwrap()["code"],
        "UNAUTHENTICATED"
    );
}

#[test]
fn graphql_errors_helper_wraps_vec() {
    let errors = vec![
        GraphqlError {
            message: "error 1".into(),
            locations: vec![],
            path: vec![],
            extensions: None,
        },
        GraphqlError {
            message: "error 2".into(),
            locations: vec![],
            path: vec![],
            extensions: None,
        },
    ];

    let client_err = GraphqlClient::graphql_errors(errors);
    match &client_err {
        GraphqlClientError::GraphqlErrors { errors } => {
            assert_eq!(errors.len(), 2);
        }
        other => panic!("expected GraphqlErrors, got {other:?}"),
    }

    // And mapping to FcpError uses the first error message
    match client_err.to_fcp_error("svc") {
        FcpError::External { message, .. } => {
            assert_eq!(message, "error 1");
        }
        other => panic!("expected External, got {other:?}"),
    }
}

// ═══════════════════════════════════════════════════════════════
// 5. Schema validation cross-module
// ═══════════════════════════════════════════════════════════════

#[test]
fn schema_validation_mode_variants() {
    assert_eq!(SchemaValidationMode::default(), SchemaValidationMode::Off);
    assert_ne!(
        SchemaValidationMode::Off,
        SchemaValidationMode::ResponseOnly
    );
    assert_ne!(
        SchemaValidationMode::ResponseOnly,
        SchemaValidationMode::VariablesAndResponse
    );

    let mode = SchemaValidationMode::VariablesAndResponse;
    let copied = mode;
    assert_eq!(mode, copied);
}

#[test]
fn builder_validation_mode_flows_to_client() {
    let client = GraphqlClientBuilder::new("https://api.test.com/graphql")
        .with_validation_mode(SchemaValidationMode::ResponseOnly)
        .build()
        .unwrap();
    let debug = format!("{client:?}");
    assert!(debug.contains("ResponseOnly"));
}

// ═══════════════════════════════════════════════════════════════
// 6. Pagination cross-module tests (async)
// ═══════════════════════════════════════════════════════════════

#[fcp_async_core::runtime::test]
async fn paginate_cursor_multi_page_aggregation() {
    let call_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    let cc = call_count.clone();

    let items = fcp_graphql::paginate_cursor(None, None, move |cursor| {
        let cc = cc.clone();
        async move {
            let n = cc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            match n {
                0 => {
                    assert!(cursor.is_none());
                    Ok(CursorPage {
                        items: vec!["alice", "bob"],
                        page_info: CursorPageInfo {
                            has_next_page: true,
                            end_cursor: Some("cursor-2".into()),
                            total_count: None,
                        },
                    })
                }
                1 => {
                    assert_eq!(cursor.as_deref(), Some("cursor-2"));
                    Ok(CursorPage {
                        items: vec!["carol"],
                        page_info: CursorPageInfo {
                            has_next_page: false,
                            end_cursor: None,
                            total_count: Some(3),
                        },
                    })
                }
                _ => panic!("unexpected page fetch"),
            }
        }
    })
    .await
    .unwrap();

    assert_eq!(items, vec!["alice", "bob", "carol"]);
    assert_eq!(call_count.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[fcp_async_core::runtime::test]
async fn paginate_cursor_limit_truncates() {
    let result: Result<Vec<i32>, _> =
        fcp_graphql::paginate_cursor(None, Some(PageLimit::new(3)), |_cursor| async {
            Ok(CursorPage {
                items: vec![1, 2, 3, 4, 5],
                page_info: CursorPageInfo {
                    has_next_page: true,
                    end_cursor: Some("next".into()),
                    total_count: None,
                },
            })
        })
        .await;

    match result {
        Err(PaginationError::LimitExceeded(_)) => {}
        other => panic!("expected LimitExceeded, got {other:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn paginate_cursor_exact_fit_succeeds() {
    let items = fcp_graphql::paginate_cursor(None, Some(PageLimit::new(3)), |_cursor| async {
        Ok(CursorPage {
            items: vec![1, 2, 3],
            page_info: CursorPageInfo {
                has_next_page: false,
                end_cursor: None,
                total_count: Some(3),
            },
        })
    })
    .await
    .unwrap();

    assert_eq!(items, vec![1, 2, 3]);
}

#[fcp_async_core::runtime::test]
async fn paginate_offset_multi_page_aggregation() {
    let call_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    let cc = call_count.clone();

    let items = fcp_graphql::paginate_offset(0, None, move |offset| {
        let cc = cc.clone();
        async move {
            let n = cc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            match n {
                0 => {
                    assert_eq!(offset, 0);
                    Ok(OffsetPage {
                        items: vec![10, 20],
                        next_offset: Some(2),
                        total_count: None,
                    })
                }
                1 => {
                    assert_eq!(offset, 2);
                    Ok(OffsetPage {
                        items: vec![30],
                        next_offset: None,
                        total_count: Some(3),
                    })
                }
                _ => panic!("unexpected fetch"),
            }
        }
    })
    .await
    .unwrap();

    assert_eq!(items, vec![10, 20, 30]);
}

#[fcp_async_core::runtime::test]
async fn paginate_offset_limit_truncates() {
    let result: Result<Vec<i32>, _> =
        fcp_graphql::paginate_offset(0, Some(PageLimit::new(2)), |_offset| async {
            Ok(OffsetPage {
                items: vec![1, 2, 3, 4],
                next_offset: Some(4),
                total_count: None,
            })
        })
        .await;

    match result {
        Err(PaginationError::LimitExceeded(_)) => {}
        other => panic!("expected LimitExceeded, got {other:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn paginate_cursor_stops_on_none_end_cursor() {
    let items = fcp_graphql::paginate_cursor(None, None, |_cursor| async {
        Ok(CursorPage {
            items: vec![1],
            page_info: CursorPageInfo {
                has_next_page: true,
                end_cursor: None, // no cursor → stop despite has_next_page
                total_count: None,
            },
        })
    })
    .await
    .unwrap();

    assert_eq!(items, vec![1]);
}

#[fcp_async_core::runtime::test]
async fn paginate_cursor_client_error_propagates() {
    let result: Result<Vec<i32>, _> = fcp_graphql::paginate_cursor(None, None, |_cursor| async {
        Err(GraphqlClientError::Protocol {
            message: "server gone".into(),
        })
    })
    .await;

    match result {
        Err(PaginationError::Client(GraphqlClientError::Protocol { message })) => {
            assert_eq!(message, "server gone");
        }
        other => panic!("expected Client(Protocol), got {other:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn paginate_offset_client_error_propagates() {
    let result: Result<Vec<i32>, _> = fcp_graphql::paginate_offset(0, None, |_offset| async {
        Err(GraphqlClientError::Json("bad json".into()))
    })
    .await;

    match result {
        Err(PaginationError::Client(GraphqlClientError::Json(msg))) => {
            assert_eq!(msg, "bad json");
        }
        other => panic!("expected Client(Json), got {other:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn paginate_cursor_empty_page() {
    let items: Vec<i32> = fcp_graphql::paginate_cursor(None, None, |_cursor| async {
        Ok(CursorPage {
            items: vec![],
            page_info: CursorPageInfo {
                has_next_page: false,
                end_cursor: None,
                total_count: Some(0),
            },
        })
    })
    .await
    .unwrap();

    assert!(items.is_empty());
}

// ═══════════════════════════════════════════════════════════════
// 7. Subscription client configuration
// ═══════════════════════════════════════════════════════════════

#[test]
fn subscription_client_builder_chain() {
    let config = GraphqlSubscriptionConfig {
        init_payload: Some(json!({"token": "abc123"})),
        ack_timeout: Duration::from_secs(30),
        ..GraphqlSubscriptionConfig::default()
    };

    let client = GraphqlSubscriptionClient::new("wss://api.github.com/graphql", "github")
        .with_config(config)
        .with_header("Authorization", "Bearer tok_xyz")
        .with_header("X-Custom", "value");

    let debug = format!("{client:?}");
    assert!(debug.contains("GraphqlSubscriptionClient"));
    assert!(debug.contains("github.com"));
    assert!(debug.contains("github"));
}

#[test]
fn subscription_config_defaults() {
    let config = GraphqlSubscriptionConfig::default();
    assert!(config.init_payload.is_none());
    assert_eq!(config.ack_timeout, Duration::from_secs(10));
}

#[test]
fn subscription_client_clone_preserves_state() {
    let client = GraphqlSubscriptionClient::new("wss://test.com/ws", "test")
        .with_header("Auth", "Bearer tok");

    let cloned = client.clone();
    let d1 = format!("{client:?}");
    let d2 = format!("{cloned:?}");
    assert_eq!(d1, d2);
}

// ═══════════════════════════════════════════════════════════════
// 8. Retry + error classification end-to-end
// ═══════════════════════════════════════════════════════════════

#[test]
fn retry_policy_never_never_retries() {
    let policy = RetryPolicy {
        strategy: RetryStrategy::Never,
        ..RetryPolicy::default()
    };

    let retryable_errors = [server_error_500(), server_error_503(), server_error_500()];

    for err in &retryable_errors {
        assert!(err.is_retryable());
        assert_eq!(policy.decide(err, 1, true), RetryDecision::DoNotRetry);
    }
}

#[test]
fn retry_with_jitter_stays_in_bounds() {
    let policy = RetryPolicy {
        max_attempts: 5,
        base_delay: Duration::from_millis(200),
        max_delay: Duration::from_secs(5),
        max_jitter: Duration::from_millis(100),
        strategy: RetryStrategy::Always,
    };

    let err = server_error_500();

    for _ in 0..20 {
        match policy.decide(&err, 1, true) {
            RetryDecision::RetryAfter(d) => {
                // base_delay * 2^0 = 200ms, jitter up to 100ms → [200, 300]
                assert!(d >= Duration::from_millis(200));
                assert!(d <= Duration::from_millis(300));
            }
            RetryDecision::DoNotRetry => panic!("should retry"),
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// 9. Operation trait type-level checks
// ═══════════════════════════════════════════════════════════════

#[test]
fn operation_trait_defaults() {
    assert!(GetUser::is_idempotent());
    assert!(!CreatePost::is_idempotent());

    assert!(GetUser::variables_schema().is_some());
    assert!(GetUser::response_schema().is_some());
    assert!(CreatePost::variables_schema().is_none());
    assert!(CreatePost::response_schema().is_none());
}

#[test]
fn operation_query_constants() {
    assert!(GetUser::QUERY.contains("GetUser"));
    assert_eq!(GetUser::OPERATION_NAME, "GetUser");
    assert!(CreatePost::QUERY.contains("CreatePost"));
    assert_eq!(CreatePost::OPERATION_NAME, "CreatePost");
}

// ═══════════════════════════════════════════════════════════════
// 10. GraphqlClientError display + clone coverage
// ═══════════════════════════════════════════════════════════════

#[test]
fn graphql_client_error_display_coverage() {
    let errors = [
        server_error_500(),
        server_error_503(),
        rate_limit_error(),
        auth_error_401(),
        json_parse_error(),
        graphql_field_error(),
        GraphqlClientError::Protocol {
            message: "frame".into(),
        },
        GraphqlClientError::SchemaValidation {
            message: "bad".into(),
            errors: vec![],
        },
        GraphqlClientError::RetriesExhausted { attempts: 3 },
    ];

    for err in &errors {
        let display = err.to_string();
        assert!(!display.is_empty(), "Display should not be empty: {err:?}");
    }
}

// ═══════════════════════════════════════════════════════════════
// 11. Pagination type construction
// ═══════════════════════════════════════════════════════════════

#[test]
fn cursor_page_info_all_fields() {
    let info = CursorPageInfo {
        has_next_page: true,
        end_cursor: Some("abc".into()),
        total_count: Some(100),
    };
    let cloned = info.clone();
    assert_eq!(info, cloned);
    assert!(info.has_next_page);
}

#[test]
fn cursor_page_construction() {
    let page = CursorPage {
        items: vec![1, 2, 3],
        page_info: CursorPageInfo {
            has_next_page: false,
            end_cursor: None,
            total_count: Some(3),
        },
    };
    assert_eq!(page.items.len(), 3);
    assert!(!page.page_info.has_next_page);
}

#[test]
fn offset_page_construction() {
    let page = OffsetPage {
        items: vec!["a", "b"],
        next_offset: Some(10),
        total_count: Some(20),
    };
    assert_eq!(page.items.len(), 2);
    assert_eq!(page.next_offset, Some(10));
}

#[test]
fn page_limit_construction() {
    let limit = PageLimit::new(50);
    assert_eq!(limit.max_items, 50);
    let copied = limit;
    assert_eq!(limit, copied);
}

#[test]
fn pagination_error_from_client_error() {
    let client_err = GraphqlClientError::Protocol {
        message: "broken".into(),
    };
    let pag_err: PaginationError = client_err.into();
    let display = pag_err.to_string();
    assert!(display.contains("pagination fetch"));
    assert!(display.contains("broken"));
}

// ═══════════════════════════════════════════════════════════════
// 12. Cross-module: retry policy + error + FCP mapping pipeline
// ═══════════════════════════════════════════════════════════════

#[test]
fn full_error_pipeline_server_error() {
    let err = server_error_500();

    // Step 1: error is retryable
    assert!(err.is_retryable());

    // Step 2: retry policy decides to retry
    let policy = RetryPolicy {
        max_jitter: Duration::ZERO,
        ..RetryPolicy::default()
    };
    match policy.decide(&err, 1, true) {
        RetryDecision::RetryAfter(d) => {
            assert_eq!(d, Duration::from_millis(200));
        }
        other => panic!("expected RetryAfter, got {other:?}"),
    }

    // Step 3: after exhaustion, map to FCP error
    match err.to_fcp_error("my-service") {
        FcpError::External {
            service, retryable, ..
        } => {
            assert_eq!(service, "my-service");
            assert!(retryable);
        }
        other => panic!("expected External, got {other:?}"),
    }
}

#[test]
fn full_error_pipeline_rate_limit() {
    let err = rate_limit_error();

    assert!(err.is_retryable());

    let policy = RetryPolicy {
        max_jitter: Duration::ZERO,
        strategy: RetryStrategy::Always,
        ..RetryPolicy::default()
    };
    assert_eq!(policy.decide(&err, 1, false), RetryDecision::DoNotRetry);

    match err.to_fcp_error("api") {
        FcpError::RateLimited { retry_after_ms, .. } => assert_eq!(retry_after_ms, 30_000),
        other => panic!("expected RateLimited, got {other:?}"),
    }
}

#[test]
fn full_error_pipeline_auth_failure() {
    let err = auth_error_401();

    // Auth errors are not retryable
    assert!(!err.is_retryable());

    let policy = RetryPolicy {
        strategy: RetryStrategy::Always,
        ..RetryPolicy::default()
    };
    assert_eq!(policy.decide(&err, 1, true), RetryDecision::DoNotRetry);

    match err.to_fcp_error("github") {
        FcpError::Unauthorized { message, code } => {
            assert_eq!(code, 2001);
            assert!(message.contains("github unauthorized"));
        }
        other => panic!("expected Unauthorized, got {other:?}"),
    }
}

// ═══════════════════════════════════════════════════════════════
// 13. Metrics + client interaction
// ═══════════════════════════════════════════════════════════════

#[test]
fn metrics_snapshot_equality_and_copy() {
    let client = GraphqlClient::new("https://api.test.com/graphql");
    let s1 = client.metrics();
    let s2 = client.metrics();
    assert_eq!(s1, s2);

    let s3 = s1;
    assert_eq!(s1, s3);
}

// ═══════════════════════════════════════════════════════════════
// 14. GraphqlQuery interop
// ═══════════════════════════════════════════════════════════════

#[test]
fn query_new_vs_from_static() {
    let q1 = GraphqlQuery::new("{ ping }");
    let q2 = GraphqlQuery::from_static("{ ping }");
    assert_eq!(q1, q2);
    assert_eq!(q1.as_str(), "{ ping }");
}

#[test]
fn query_serde_roundtrip() {
    let q = GraphqlQuery::new("query Foo($id: ID!) { user(id: $id) { name } }");
    let json = serde_json::to_string(&q).unwrap();
    assert_eq!(json, "\"query Foo($id: ID!) { user(id: $id) { name } }\"");
    let back: GraphqlQuery = serde_json::from_str(&json).unwrap();
    assert_eq!(q, back);
}

// ═══════════════════════════════════════════════════════════════
// 15. GraphqlPathSegment serde
// ═══════════════════════════════════════════════════════════════

#[test]
fn path_segment_key_serde() {
    let seg = GraphqlPathSegment::Key("users".into());
    let json = serde_json::to_string(&seg).unwrap();
    assert_eq!(json, "\"users\"");
    let back: GraphqlPathSegment = serde_json::from_str(&json).unwrap();
    assert_eq!(seg, back);
}

#[test]
fn path_segment_index_serde() {
    let seg = GraphqlPathSegment::Index(42);
    let json = serde_json::to_string(&seg).unwrap();
    assert_eq!(json, "42");
    let back: GraphqlPathSegment = serde_json::from_str(&json).unwrap();
    assert_eq!(seg, back);
}

#[test]
fn path_segment_mixed_array() {
    let path = vec![
        GraphqlPathSegment::Key("users".into()),
        GraphqlPathSegment::Index(0),
        GraphqlPathSegment::Key("name".into()),
    ];
    let json = serde_json::to_string(&path).unwrap();
    let back: Vec<GraphqlPathSegment> = serde_json::from_str(&json).unwrap();
    assert_eq!(path, back);
}

// ═══════════════════════════════════════════════════════════════
// 16. Error Clone + Debug
// ═══════════════════════════════════════════════════════════════

#[test]
fn graphql_client_error_clone() {
    let errors = [
        server_error_500(),
        server_error_503(),
        json_parse_error(),
        graphql_field_error(),
        GraphqlClientError::Protocol {
            message: "x".into(),
        },
        GraphqlClientError::SchemaValidation {
            message: "y".into(),
            errors: vec!["e".into()],
        },
        GraphqlClientError::RetriesExhausted { attempts: 1 },
    ];

    for err in &errors {
        let cloned = err.clone();
        assert_eq!(format!("{err:?}"), format!("{cloned:?}"));
    }
}

// ═══════════════════════════════════════════════════════════════
// 17. Builder with dedup + validation combined
// ═══════════════════════════════════════════════════════════════

#[test]
fn builder_dedup_and_validation_together() {
    let client = GraphqlClientBuilder::new("https://api.test.com/graphql")
        .with_dedup_in_flight(true)
        .with_validation_mode(SchemaValidationMode::VariablesAndResponse)
        .with_retry_policy(RetryPolicy {
            max_attempts: 5,
            strategy: RetryStrategy::Always,
            ..RetryPolicy::default()
        })
        .build()
        .unwrap();

    let debug = format!("{client:?}");
    assert!(debug.contains("dedup_in_flight: true"));
    assert!(debug.contains("VariablesAndResponse"));
}

// ═══════════════════════════════════════════════════════════════
// 18. Response extensions
// ═══════════════════════════════════════════════════════════════

#[test]
fn response_with_extensions() {
    let json = r#"{
        "data": {"name": "Alice"},
        "errors": [],
        "extensions": {"tracing": {"version": 1}, "requestId": "req-123"}
    }"#;
    let resp: GraphqlResponse<GetUserData> = serde_json::from_str(json).unwrap();
    assert!(resp.is_ok());
    let ext = resp.extensions.unwrap();
    assert_eq!(ext["tracing"]["version"], 1);
    assert_eq!(ext["requestId"], "req-123");
}

#[test]
fn response_without_extensions_serializes_cleanly() {
    let resp = GraphqlResponse {
        data: Some(json!({"count": 0})),
        errors: vec![],
        extensions: None,
    };
    let json = serde_json::to_string(&resp).unwrap();
    assert!(!json.contains("extensions"));
}
