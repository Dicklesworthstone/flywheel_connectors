use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use std::time::Duration;
use std::time::Instant;

use fcp_async_core::io::{AsyncRead, ReadBuf};
// ServerWebSocket and WebSocketAcceptor are test-server types not re-exported by
// fcp-async-core; direct import from asupersync is acceptable for test infrastructure.
use asupersync::net::websocket::{CloseReason, Message, ServerWebSocket, WebSocketAcceptor};
use chrono::Utc;
use fcp_async_core::net::{TcpListener, TcpStream};
use fcp_async_core::task;
use fcp_testkit::LogCapture;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

use fcp_graphql::{
    CursorPage, CursorPageInfo, GraphqlClientBuilder, GraphqlClientError, GraphqlErrorLocation,
    GraphqlIntrospectionPolicy, GraphqlLimitExceeded, GraphqlOperation, GraphqlPathSegment,
    GraphqlQuery, GraphqlQueryLimits, GraphqlRequest, GraphqlSubscriptionClient,
    GraphqlSubscriptionConfig, OffsetPage, PageLimit, PaginationError, RetryDecision, RetryPolicy,
    RetryStrategy, SchemaValidationMode, paginate_cursor, paginate_offset,
};
use fcp_streaming::WsConfig;

#[derive(Debug, Clone, Serialize)]
struct EmptyVars {}

#[derive(Debug, Serialize, Deserialize)]
struct ViewerResponse {
    viewer: Viewer,
}

#[derive(Debug, Serialize, Deserialize)]
struct Viewer {
    id: String,
}

#[derive(Debug, Serialize)]
struct IdVars {
    id: String,
}

#[derive(Debug, Serialize)]
struct BadVars {
    id: u64,
}

struct ViewerQuery;

impl GraphqlOperation for ViewerQuery {
    type Variables = EmptyVars;
    type ResponseData = ViewerResponse;

    const QUERY: &'static str = "query Viewer { viewer { id } }";
    const OPERATION_NAME: &'static str = "Viewer";

    fn response_schema() -> Option<&'static str> {
        Some(
            r#"{
                "type": "object",
                "required": ["viewer"],
                "properties": {
                    "viewer": {
                        "type": "object",
                        "required": ["id"],
                        "properties": {
                            "id": {"type": "string"}
                        }
                    }
                }
            }"#,
        )
    }
}

struct ViewerByIdQuery;

impl GraphqlOperation for ViewerByIdQuery {
    type Variables = IdVars;
    type ResponseData = ViewerResponse;

    const QUERY: &'static str = "query ViewerById($id: ID!) { viewer { id } }";
    const OPERATION_NAME: &'static str = "ViewerById";

    fn variables_schema() -> Option<&'static str> {
        Some(
            r#"{
                "type": "object",
                "required": ["id"],
                "properties": {
                    "id": { "type": "string" }
                }
            }"#,
        )
    }

    fn response_schema() -> Option<&'static str> {
        ViewerQuery::response_schema()
    }
}

struct BadVarsQuery;

impl GraphqlOperation for BadVarsQuery {
    type Variables = BadVars;
    type ResponseData = ViewerResponse;

    const QUERY: &'static str = ViewerByIdQuery::QUERY;
    const OPERATION_NAME: &'static str = ViewerByIdQuery::OPERATION_NAME;

    fn variables_schema() -> Option<&'static str> {
        ViewerByIdQuery::variables_schema()
    }
}

struct MutationQuery;

impl GraphqlOperation for MutationQuery {
    type Variables = IdVars;
    type ResponseData = ViewerResponse;

    const QUERY: &'static str = "mutation UpdateViewer($id: ID!) { viewer { id } }";
    const OPERATION_NAME: &'static str = "UpdateViewer";

    fn variables_schema() -> Option<&'static str> {
        ViewerByIdQuery::variables_schema()
    }

    fn response_schema() -> Option<&'static str> {
        ViewerQuery::response_schema()
    }

    fn is_idempotent() -> bool {
        false
    }
}

struct ViewerSchemaQuery;

impl GraphqlOperation for ViewerSchemaQuery {
    type Variables = EmptyVars;
    type ResponseData = serde_json::Value;

    const QUERY: &'static str = ViewerQuery::QUERY;
    const OPERATION_NAME: &'static str = ViewerQuery::OPERATION_NAME;

    fn response_schema() -> Option<&'static str> {
        ViewerQuery::response_schema()
    }
}

struct TooDeepSubscription;

impl GraphqlOperation for TooDeepSubscription {
    type Variables = EmptyVars;
    type ResponseData = ViewerResponse;

    const QUERY: &'static str =
        "subscription TooDeep { a { b { c { d { e { f { g { h { i { j { k } } } } } } } } } } }";
    const OPERATION_NAME: &'static str = "TooDeep";
}

struct SequenceResponder {
    counter: Arc<AtomicUsize>,
}

impl Respond for SequenceResponder {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        let attempt = self.counter.fetch_add(1, Ordering::SeqCst);
        if attempt == 0 {
            ResponseTemplate::new(500).set_body_json(serde_json::json!({"error": "fail"}))
        } else {
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {"viewer": {"id": "user-2"}}
            }))
        }
    }
}

struct CountingResponder {
    counter: Arc<AtomicUsize>,
    body: serde_json::Value,
    delay: Option<Duration>,
}

impl Respond for CountingResponder {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        self.counter.fetch_add(1, Ordering::SeqCst);
        let mut response = ResponseTemplate::new(200).set_body_json(self.body.clone());
        if let Some(delay) = self.delay {
            response = response.set_delay(delay);
        }
        response
    }
}

struct TestContext {
    test_name: String,
    module: String,
    correlation_id: String,
    capture: LogCapture,
    start_time: Instant,
    assertions_passed: u32,
    assertions_failed: u32,
}

impl TestContext {
    fn new(test_name: &str) -> Self {
        Self {
            test_name: test_name.to_string(),
            module: "fcp-graphql::client".to_string(),
            correlation_id: format!("graphql-{}", std::process::id()),
            capture: LogCapture::new(),
            start_time: Instant::now(),
            assertions_passed: 0,
            assertions_failed: 0,
        }
    }

    fn assert_true(&mut self, condition: bool, msg: &str) {
        if condition {
            self.assertions_passed += 1;
        } else {
            self.assertions_failed += 1;
            panic!("{}", msg);
        }
    }

    fn assert_eq<T: std::fmt::Debug + PartialEq>(&mut self, actual: T, expected: T, msg: &str) {
        if actual == expected {
            self.assertions_passed += 1;
        } else {
            self.assertions_failed += 1;
            panic!("{msg}: expected {expected:?}, got {actual:?}");
        }
    }

    fn finalize(&self, result: &str, details: Option<serde_json::Value>) {
        let duration_ms = u64::try_from(self.start_time.elapsed().as_millis()).unwrap_or(u64::MAX);
        let mut entry = serde_json::json!({
            "timestamp": Utc::now().to_rfc3339(),
            "level": "info",
            "test_name": self.test_name,
            "module": self.module,
            "phase": "verify",
            "correlation_id": self.correlation_id,
            "result": result,
            "duration_ms": duration_ms,
            "assertions": {
                "passed": self.assertions_passed,
                "failed": self.assertions_failed
            }
        });

        if let Some(extra) = details {
            entry["details"] = extra;
        }

        self.capture
            .push_value(&entry)
            .expect("structured test log entry");
        self.capture.assert_valid();
    }
}

fn limit_exceeded_kind(error: &GraphqlClientError) -> &GraphqlLimitExceeded {
    match error {
        GraphqlClientError::LimitExceeded(limit) => limit,
        other => panic!("expected query limit error, got {other:?}"),
    }
}

async fn assert_no_graphql_http_requests(server: &MockServer) {
    let requests = server.received_requests().await.expect("received requests");
    assert!(
        requests.is_empty(),
        "limit guard should reject before dispatch, got {} HTTP requests",
        requests.len()
    );
}

fn alias_bomb_query(alias_count: usize) -> String {
    let fields = (0..alias_count)
        .map(|index| format!("alias{index}: viewer {{ id }}"))
        .collect::<Vec<_>>()
        .join(" ");
    format!("query AliasBomb {{ {fields} }}")
}

fn root_field_bomb_query(root_field_count: usize) -> String {
    let fields = (0..root_field_count)
        .map(|index| format!("rootField{index}"))
        .collect::<Vec<_>>()
        .join(" ");
    format!("query RootFieldBomb {{ {fields} }}")
}

fn introspection_policy_cases() -> [(&'static str, &'static str); 3] {
    [
        (
            "query DirectIntrospection { __schema { types { name } } }",
            "__schema",
        ),
        (
            "query AliasedIntrospection { schemaAlias: __schema { types { name } } }",
            "__schema",
        ),
        (
            "query NestedIntrospection { viewer { __type(name: \"User\") { name } } }",
            "__type",
        ),
    ]
}

type TestServerWebSocket = ServerWebSocket<TcpStream>;

async fn read_http_headers<IO: AsyncRead + Unpin>(io: &mut IO) -> io::Result<Vec<u8>> {
    const MAX_HEADERS: usize = 16 * 1024;

    let mut buf = Vec::with_capacity(1024);
    let mut temp = [0u8; 256];

    loop {
        let read = poll_fn(|cx| {
            let mut read_buf = ReadBuf::new(&mut temp);
            match Pin::new(&mut *io).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await?;

        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF before websocket handshake completed",
            ));
        }

        buf.extend_from_slice(&temp[..read]);
        if buf.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(buf);
        }
        if buf.len() > MAX_HEADERS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "websocket handshake headers too large",
            ));
        }
    }
}

async fn accept_test_websocket(mut stream: TcpStream) -> TestServerWebSocket {
    let request = read_http_headers(&mut stream)
        .await
        .expect("read websocket handshake");
    WebSocketAcceptor::new()
        .accept(&fcp_async_core::compatibility_cx(), &request, stream)
        .await
        .expect("accept websocket")
}

fn expect_text_message(message: Message, context: &str) -> String {
    match message {
        Message::Text(text) => text,
        other => panic!("expected text frame for {context}, got {other:?}"),
    }
}

async fn recv_text(ws: &mut TestServerWebSocket, context: &str) -> String {
    let message = ws
        .recv(&fcp_async_core::compatibility_cx())
        .await
        .expect(context)
        .unwrap_or_else(|| panic!("{context} missing"));
    expect_text_message(message, context)
}

async fn send_json(ws: &mut TestServerWebSocket, value: serde_json::Value, context: &str) {
    ws.send(
        &fcp_async_core::compatibility_cx(),
        Message::text(value.to_string()),
    )
    .await
    .expect(context);
}

async fn close_test_websocket(ws: &mut TestServerWebSocket) {
    let _ = ws
        .close(&fcp_async_core::compatibility_cx(), CloseReason::normal())
        .await;
}

async fn subscription_wrong_id_error(frame: serde_json::Value) -> GraphqlClientError {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server_task = task::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let mut ws = accept_test_websocket(stream).await;

        let _init = recv_text(&mut ws, "init message").await;
        send_json(
            &mut ws,
            serde_json::json!({ "type": "connection_ack" }),
            "ack send",
        )
        .await;

        let _subscribe = recv_text(&mut ws, "subscribe message").await;
        send_json(&mut ws, frame, "wrong-id frame send").await;
    });

    let url = format!("ws://{}", addr);
    let client = GraphqlSubscriptionClient::new(url, "test");
    let mut stream = client
        .subscribe::<ViewerQuery>(EmptyVars {})
        .await
        .expect("subscribe");

    let err = stream
        .next()
        .await
        .expect("stream error item")
        .expect_err("expected protocol error");

    server_task.await.expect("server task");
    err
}

#[fcp_async_core::runtime::test]
async fn subscription_rejects_wrong_id_next_frame() {
    let err = subscription_wrong_id_error(serde_json::json!({
        "type": "next",
        "id": "stale-99",
        "payload": {
            "data": { "viewer": { "id": "wrong" } }
        }
    }))
    .await;

    match err {
        GraphqlClientError::Protocol { message } => {
            assert!(message.contains("next"));
            assert!(message.contains("1"));
            assert!(message.contains("stale-99"));
        }
        other => panic!("expected Protocol error, got {other:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn subscription_rejects_wrong_id_error_frame() {
    let err = subscription_wrong_id_error(serde_json::json!({
        "type": "error",
        "id": "stale-99",
        "payload": [
            { "message": "wrong subscription" }
        ]
    }))
    .await;

    match err {
        GraphqlClientError::Protocol { message } => {
            assert!(message.contains("error"));
            assert!(message.contains("1"));
            assert!(message.contains("stale-99"));
        }
        other => panic!("expected Protocol error, got {other:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn subscription_rejects_wrong_id_complete_frame() {
    let err = subscription_wrong_id_error(serde_json::json!({
        "type": "complete",
        "id": "stale-99"
    }))
    .await;

    match err {
        GraphqlClientError::Protocol { message } => {
            assert!(message.contains("complete"));
            assert!(message.contains("1"));
            assert!(message.contains("stale-99"));
        }
        other => panic!("expected Protocol error, got {other:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn rejects_deep_nested_introspection_before_http_dispatch() {
    let server = MockServer::start().await;
    let client = GraphqlClientBuilder::new(server.uri())
        .build()
        .expect("client");
    let query = "query DeepIntrospection { __schema { types { fields { type { ofType { ofType { ofType { ofType { ofType { ofType { ofType { name } } } } } } } } } } } }";
    let request = GraphqlRequest::new(GraphqlQuery::new(query), serde_json::json!({}));

    let err = client
        .execute_request::<_, serde_json::Value>(request, None, None, true)
        .await
        .expect_err("deep query should be rejected before dispatch");

    assert!(matches!(
        limit_exceeded_kind(&err),
        GraphqlLimitExceeded::DepthExceeded {
            actual_depth,
            max_depth: 10
        } if *actual_depth > 10
    ));
    assert_no_graphql_http_requests(&server).await;
}

#[fcp_async_core::runtime::test]
async fn rejects_alias_bomb_before_http_dispatch() {
    let server = MockServer::start().await;
    let client = GraphqlClientBuilder::new(server.uri())
        .build()
        .expect("client");
    let query = alias_bomb_query(GraphqlQueryLimits::default().max_aliases + 1);
    let request = GraphqlRequest::new(GraphqlQuery::new(query), serde_json::json!({}));

    let err = client
        .execute_request::<_, serde_json::Value>(request, None, None, true)
        .await
        .expect_err("alias bomb should be rejected before dispatch");

    assert_eq!(
        limit_exceeded_kind(&err),
        &GraphqlLimitExceeded::AliasLimitExceeded {
            actual_aliases: GraphqlQueryLimits::default().max_aliases + 1,
            max_aliases: GraphqlQueryLimits::default().max_aliases,
        }
    );
    assert_no_graphql_http_requests(&server).await;
}

#[fcp_async_core::runtime::test]
async fn rejects_oversized_payload_before_http_dispatch() {
    let server = MockServer::start().await;
    let client = GraphqlClientBuilder::new(server.uri())
        .build()
        .expect("client");
    let max_bytes = GraphqlQueryLimits::default().max_query_bytes;
    let request = GraphqlRequest::new(
        GraphqlQuery::new("x".repeat(max_bytes + 1)),
        serde_json::json!({}),
    );

    let err = client
        .execute_request::<_, serde_json::Value>(request, None, None, true)
        .await
        .expect_err("oversized query should be rejected before dispatch");

    assert_eq!(
        limit_exceeded_kind(&err),
        &GraphqlLimitExceeded::QueryTooLarge {
            actual_bytes: max_bytes + 1,
            max_bytes,
        }
    );
    assert_no_graphql_http_requests(&server).await;
}

#[fcp_async_core::runtime::test]
async fn rejects_root_field_bomb_before_http_dispatch() {
    let server = MockServer::start().await;
    let client = GraphqlClientBuilder::new(server.uri())
        .build()
        .expect("client");
    let query = root_field_bomb_query(GraphqlQueryLimits::default().max_root_fields + 1);
    let request = GraphqlRequest::new(GraphqlQuery::new(query), serde_json::json!({}));

    let err = client
        .execute_request::<_, serde_json::Value>(request, None, None, true)
        .await
        .expect_err("root-field bomb should be rejected before dispatch");

    assert_eq!(
        limit_exceeded_kind(&err),
        &GraphqlLimitExceeded::RootFieldLimitExceeded {
            actual_root_fields: GraphqlQueryLimits::default().max_root_fields + 1,
            max_root_fields: GraphqlQueryLimits::default().max_root_fields,
        }
    );
    assert_no_graphql_http_requests(&server).await;
}

#[fcp_async_core::runtime::test]
async fn rejects_disabled_introspection_before_http_dispatch() {
    let server = MockServer::start().await;
    let client = GraphqlClientBuilder::new(server.uri())
        .with_introspection_policy(GraphqlIntrospectionPolicy::Deny)
        .build()
        .expect("client");

    for (query, expected_field) in introspection_policy_cases() {
        let request = GraphqlRequest::new(GraphqlQuery::new(query), serde_json::json!({}));
        let result = client
            .execute_request::<_, serde_json::Value>(request, None, None, true)
            .await;

        assert!(
            result.as_ref().is_err_and(|err| matches!(
                limit_exceeded_kind(err),
                GraphqlLimitExceeded::IntrospectionDisabled { field_name }
                    if field_name == expected_field
            )),
            "introspection should be rejected before dispatch"
        );
    }

    assert_no_graphql_http_requests(&server).await;
}

#[fcp_async_core::runtime::test]
async fn rejects_batch_query_limit_violation_before_http_dispatch() {
    let server = MockServer::start().await;
    let client = GraphqlClientBuilder::new(server.uri())
        .build()
        .expect("client");
    let items = vec![
        fcp_graphql::GraphqlBatchItem::new(
            GraphqlQuery::new(ViewerQuery::QUERY),
            serde_json::json!({}),
        ),
        fcp_graphql::GraphqlBatchItem::new(
            GraphqlQuery::new(alias_bomb_query(
                GraphqlQueryLimits::default().max_aliases + 1,
            )),
            serde_json::json!({}),
        ),
    ];

    let err = client
        .execute_batch_request::<_, serde_json::Value>(items, None, None, true)
        .await
        .expect_err("batch limit violation should be rejected before dispatch");

    assert!(matches!(
        limit_exceeded_kind(&err),
        GraphqlLimitExceeded::AliasLimitExceeded { .. }
    ));
    assert_no_graphql_http_requests(&server).await;
}

#[fcp_async_core::runtime::test]
async fn rejects_disabled_introspection_in_batch_before_http_dispatch() {
    let server = MockServer::start().await;
    let client = GraphqlClientBuilder::new(server.uri())
        .with_introspection_policy(GraphqlIntrospectionPolicy::Deny)
        .build()
        .expect("client");

    for (query, expected_field) in introspection_policy_cases() {
        let items = vec![
            fcp_graphql::GraphqlBatchItem::new(
                GraphqlQuery::new(ViewerQuery::QUERY),
                serde_json::json!({}),
            ),
            fcp_graphql::GraphqlBatchItem::new(GraphqlQuery::new(query), serde_json::json!({})),
        ];
        let result = client
            .execute_batch_request::<_, serde_json::Value>(items, None, None, true)
            .await;

        assert!(
            result.as_ref().is_err_and(|err| matches!(
                limit_exceeded_kind(err),
                GraphqlLimitExceeded::IntrospectionDisabled { field_name }
                    if field_name == expected_field
            )),
            "batch introspection should be rejected before dispatch"
        );
    }

    assert_no_graphql_http_requests(&server).await;
}

#[fcp_async_core::runtime::test]
async fn rejects_oversized_batch_before_http_dispatch() {
    let server = MockServer::start().await;
    let client = GraphqlClientBuilder::new(server.uri())
        .with_max_batch_items(2)
        .build()
        .expect("client");
    let items = (0..3)
        .map(|_| {
            fcp_graphql::GraphqlBatchItem::new(
                GraphqlQuery::new(ViewerQuery::QUERY),
                serde_json::json!({}),
            )
        })
        .collect();

    let err = client
        .execute_batch_request::<_, serde_json::Value>(items, None, None, true)
        .await
        .expect_err("oversized batch should be rejected before dispatch");

    match err {
        GraphqlClientError::Protocol { message } => {
            assert!(message.contains("exceeding limit 2"), "got: {message}");
        }
        other => panic!("expected protocol error, got {other:?}"),
    }
    assert_no_graphql_http_requests(&server).await;
}

#[fcp_async_core::runtime::test]
async fn rejects_subscription_query_limit_violation_before_connect() {
    let client = GraphqlSubscriptionClient::new("ws://127.0.0.1:9/graphql", "test");
    let err = match client.subscribe::<TooDeepSubscription>(EmptyVars {}).await {
        Ok(_) => panic!("deep subscription should be rejected before connect"),
        Err(err) => err,
    };

    assert!(matches!(
        limit_exceeded_kind(&err),
        GraphqlLimitExceeded::DepthExceeded {
            actual_depth,
            max_depth: 10
        } if *actual_depth > 10
    ));
}

#[fcp_async_core::runtime::test]
async fn execute_query_success() {
    let mut ctx = TestContext::new("execute_query_success");
    let server = MockServer::start().await;

    let expected_body = serde_json::json!({
        "query": ViewerQuery::QUERY,
        "operationName": ViewerQuery::OPERATION_NAME,
        "variables": {},
    });

    let response_body = serde_json::json!({
        "data": {
            "viewer": {
                "id": "user-1"
            }
        }
    });

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_json(&expected_body))
        .respond_with(ResponseTemplate::new(200).set_body_json(response_body))
        .mount(&server)
        .await;

    let client = GraphqlClientBuilder::new(server.uri())
        .with_service_name("test")
        .build()
        .expect("client");

    let response = client
        .execute::<ViewerQuery>(EmptyVars {})
        .await
        .expect("query should succeed");

    ctx.assert_true(response.errors.is_empty(), "expected no GraphQL errors");
    let viewer = response.data.expect("missing data");
    ctx.assert_eq(viewer.viewer.id, "user-1".to_string(), "viewer id mismatch");
    ctx.finalize("pass", Some(serde_json::json!({"status": "ok"})));
}

#[fcp_async_core::runtime::test]
async fn execute_query_with_variables() {
    let mut ctx = TestContext::new("execute_query_with_variables");
    let server = MockServer::start().await;

    let expected_body = serde_json::json!({
        "query": ViewerByIdQuery::QUERY,
        "operationName": ViewerByIdQuery::OPERATION_NAME,
        "variables": { "id": "user-42" },
    });

    let response_body = serde_json::json!({
        "data": {
            "viewer": {
                "id": "user-42"
            }
        }
    });

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_json(&expected_body))
        .respond_with(ResponseTemplate::new(200).set_body_json(response_body))
        .mount(&server)
        .await;

    let client = GraphqlClientBuilder::new(server.uri())
        .with_validation_mode(SchemaValidationMode::VariablesAndResponse)
        .build()
        .expect("client");

    let response = client
        .execute::<ViewerByIdQuery>(IdVars {
            id: "user-42".to_string(),
        })
        .await
        .expect("query should succeed");

    ctx.assert_true(response.errors.is_empty(), "expected no GraphQL errors");
    let viewer = response.data.expect("missing data");
    ctx.assert_eq(
        viewer.viewer.id,
        "user-42".to_string(),
        "viewer id mismatch",
    );
    ctx.finalize(
        "pass",
        Some(serde_json::json!({"validation": "variables_and_response"})),
    );
}

#[fcp_async_core::runtime::test]
async fn execute_query_rejects_invalid_variables() {
    let mut ctx = TestContext::new("execute_query_rejects_invalid_variables");
    let server = MockServer::start().await;
    let counter = Arc::new(AtomicUsize::new(0));

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(CountingResponder {
            counter: counter.clone(),
            body: serde_json::json!({"data": {"viewer": {"id": "unused"}}}),
            delay: None,
        })
        .mount(&server)
        .await;

    let client = GraphqlClientBuilder::new(server.uri())
        .with_validation_mode(SchemaValidationMode::VariablesAndResponse)
        .build()
        .expect("client");

    let err = client
        .execute::<BadVarsQuery>(BadVars { id: 123 })
        .await
        .expect_err("should reject invalid variables");

    ctx.assert_true(
        matches!(err, GraphqlClientError::SchemaValidation { .. }),
        "expected schema validation error",
    );
    ctx.assert_eq(
        counter.load(Ordering::SeqCst),
        0_usize,
        "expected no request",
    );
    ctx.finalize("pass", Some(serde_json::json!({"validation": "variables"})));
}

#[fcp_async_core::runtime::test]
async fn execute_batch_rejects_invalid_variables() {
    let mut ctx = TestContext::new("execute_batch_rejects_invalid_variables");
    let server = MockServer::start().await;
    let counter = Arc::new(AtomicUsize::new(0));

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(CountingResponder {
            counter: counter.clone(),
            body: serde_json::json!([{"data": {"viewer": {"id": "unused"}}}]),
            delay: None,
        })
        .mount(&server)
        .await;

    let client = GraphqlClientBuilder::new(server.uri())
        .with_validation_mode(SchemaValidationMode::VariablesAndResponse)
        .build()
        .expect("client");

    let err = client
        .execute_batch::<BadVarsQuery>(vec![BadVars { id: 123 }])
        .await
        .expect_err("should reject invalid batch variables");

    ctx.assert_true(
        matches!(err, GraphqlClientError::SchemaValidation { .. }),
        "expected schema validation error",
    );
    ctx.assert_eq(
        counter.load(Ordering::SeqCst),
        0_usize,
        "expected no request",
    );
    ctx.finalize(
        "pass",
        Some(serde_json::json!({"validation": "batch_variables"})),
    );
}

#[fcp_async_core::runtime::test]
async fn execute_batch_empty_list_short_circuits_without_request() {
    let server = MockServer::start().await;
    let counter = Arc::new(AtomicUsize::new(0));

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(CountingResponder {
            counter: counter.clone(),
            body: serde_json::json!([]),
            delay: None,
        })
        .mount(&server)
        .await;

    let client = GraphqlClientBuilder::new(server.uri())
        .with_validation_mode(SchemaValidationMode::ResponseOnly)
        .build()
        .expect("client");

    let responses = client
        .execute_batch::<ViewerQuery>(Vec::<EmptyVars>::new())
        .await
        .expect("empty batch should succeed locally");

    assert!(responses.is_empty());
    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "empty batch must not emit an external request",
    );
}

#[fcp_async_core::runtime::test]
async fn execute_batch_single_item_success() {
    let mut ctx = TestContext::new("execute_batch_single_item_success");
    let server = MockServer::start().await;

    let expected_body = serde_json::json!([{
        "query": ViewerByIdQuery::QUERY,
        "operationName": ViewerByIdQuery::OPERATION_NAME,
        "variables": { "id": "user-1" }
    }]);

    let response_body = serde_json::json!([{"data": {"viewer": {"id": "user-1"}}}]);

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_json(&expected_body))
        .respond_with(ResponseTemplate::new(200).set_body_json(response_body))
        .mount(&server)
        .await;

    let client = GraphqlClientBuilder::new(server.uri())
        .with_validation_mode(SchemaValidationMode::ResponseOnly)
        .build()
        .expect("client");

    let responses = client
        .execute_batch::<ViewerByIdQuery>(vec![IdVars {
            id: "user-1".to_string(),
        }])
        .await
        .expect("batch should succeed");

    ctx.assert_eq(responses.len(), 1_usize, "expected one response");
    let first = responses[0].data.as_ref().expect("missing data");
    ctx.assert_eq(first.viewer.id.clone(), "user-1".to_string(), "viewer id");

    ctx.finalize("pass", Some(serde_json::json!({"batch_size": 1})));
}

#[fcp_async_core::runtime::test]
async fn execute_batch_multi_item_success_with_echoed_correlation() {
    let mut ctx = TestContext::new("execute_batch_multi_item_success_with_echoed_correlation");
    let server = MockServer::start().await;

    let expected_body = serde_json::json!([
        {
            "query": ViewerByIdQuery::QUERY,
            "operationName": ViewerByIdQuery::OPERATION_NAME,
            "variables": { "id": "user-1" },
            "extensions": { "fcpBatchIndex": 0 }
        },
        {
            "query": ViewerByIdQuery::QUERY,
            "operationName": ViewerByIdQuery::OPERATION_NAME,
            "variables": { "id": "user-2" },
            "extensions": { "fcpBatchIndex": 1 }
        }
    ]);

    let response_body = serde_json::json!([
        {
            "data": {"viewer": {"id": "user-1"}},
            "extensions": { "fcpBatchIndex": 0 }
        },
        {
            "data": {"viewer": {"id": "user-2"}},
            "extensions": { "fcpBatchIndex": 1 }
        }
    ]);

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_json(&expected_body))
        .respond_with(ResponseTemplate::new(200).set_body_json(response_body))
        .mount(&server)
        .await;

    let client = GraphqlClientBuilder::new(server.uri())
        .with_validation_mode(SchemaValidationMode::ResponseOnly)
        .build()
        .expect("client");

    let responses = client
        .execute_batch::<ViewerByIdQuery>(vec![
            IdVars {
                id: "user-1".to_string(),
            },
            IdVars {
                id: "user-2".to_string(),
            },
        ])
        .await
        .expect("batch should succeed");

    ctx.assert_eq(responses.len(), 2_usize, "expected two responses");
    let first = responses[0].data.as_ref().expect("missing data");
    let second = responses[1].data.as_ref().expect("missing data");
    ctx.assert_eq(
        first.viewer.id.clone(),
        "user-1".to_string(),
        "first viewer id",
    );
    ctx.assert_eq(
        second.viewer.id.clone(),
        "user-2".to_string(),
        "second viewer id",
    );
    ctx.assert_true(
        responses
            .iter()
            .all(|response| response.extensions.is_none()),
        "batch correlation metadata should not leak to callers",
    );

    ctx.finalize("pass", Some(serde_json::json!({"batch_size": 2})));
}

#[fcp_async_core::runtime::test]
async fn execute_batch_rejects_reordered_equal_length_response() {
    let mut ctx = TestContext::new("execute_batch_rejects_reordered_equal_length_response");
    let server = MockServer::start().await;

    let expected_body = serde_json::json!([
        {
            "query": ViewerByIdQuery::QUERY,
            "operationName": ViewerByIdQuery::OPERATION_NAME,
            "variables": { "id": "user-1" },
            "extensions": { "fcpBatchIndex": 0 }
        },
        {
            "query": ViewerByIdQuery::QUERY,
            "operationName": ViewerByIdQuery::OPERATION_NAME,
            "variables": { "id": "user-2" },
            "extensions": { "fcpBatchIndex": 1 }
        }
    ]);

    let response_body = serde_json::json!([
        {
            "data": {"viewer": {"id": "user-2"}},
            "extensions": { "fcpBatchIndex": 1 }
        },
        {
            "data": {"viewer": {"id": "user-1"}},
            "extensions": { "fcpBatchIndex": 0 }
        }
    ]);

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_json(&expected_body))
        .respond_with(ResponseTemplate::new(200).set_body_json(response_body))
        .mount(&server)
        .await;

    let client = GraphqlClientBuilder::new(server.uri())
        .with_validation_mode(SchemaValidationMode::ResponseOnly)
        .build()
        .expect("client");

    let err = client
        .execute_batch::<ViewerByIdQuery>(vec![
            IdVars {
                id: "user-1".to_string(),
            },
            IdVars {
                id: "user-2".to_string(),
            },
        ])
        .await
        .expect_err("reordered equal-length response should fail closed");

    match err {
        GraphqlClientError::Protocol { message } => {
            ctx.assert_true(
                message.contains("correlation mismatch at position 0"),
                "protocol error should mention batch correlation mismatch",
            );
        }
        other => panic!("expected Protocol error, got {other:?}"),
    }

    ctx.finalize(
        "pass",
        Some(serde_json::json!({"validation": "batch_correlation"})),
    );
}

#[fcp_async_core::runtime::test]
async fn execute_batch_rejects_response_count_mismatch() {
    let mut ctx = TestContext::new("execute_batch_rejects_response_count_mismatch");
    let server = MockServer::start().await;

    let response_body = serde_json::json!([
        {"data": {"viewer": {"id": "user-1"}}},
        {"data": {"viewer": {"id": "user-2"}}}
    ]);

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response_body))
        .mount(&server)
        .await;

    let client = GraphqlClientBuilder::new(server.uri())
        .with_validation_mode(SchemaValidationMode::ResponseOnly)
        .build()
        .expect("client");

    let err = client
        .execute_batch::<ViewerByIdQuery>(vec![IdVars {
            id: "user-1".to_string(),
        }])
        .await
        .expect_err("overlong batch response should fail closed");

    match err {
        GraphqlClientError::Protocol { message } => {
            ctx.assert_true(
                message.contains("expected 1, got 2"),
                "protocol error should mention batch count mismatch",
            );
        }
        other => panic!("expected Protocol error, got {other:?}"),
    }

    ctx.finalize(
        "pass",
        Some(serde_json::json!({"validation": "batch_count_mismatch"})),
    );
}

#[fcp_async_core::runtime::test]
async fn execute_batch_rejects_invalid_response_schema() {
    let mut ctx = TestContext::new("execute_batch_rejects_invalid_response_schema");
    let server = MockServer::start().await;

    let response_body = serde_json::json!([
        {"data": {"viewer": {"id": 123}}}
    ]);

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response_body))
        .mount(&server)
        .await;

    let client = GraphqlClientBuilder::new(server.uri())
        .with_validation_mode(SchemaValidationMode::ResponseOnly)
        .build()
        .expect("client");

    let err = client
        .execute_batch::<ViewerSchemaQuery>(vec![EmptyVars {}])
        .await
        .expect_err("invalid batch response schema should fail");

    ctx.assert_true(
        matches!(err, GraphqlClientError::SchemaValidation { .. }),
        "expected schema validation error",
    );
    ctx.finalize(
        "pass",
        Some(serde_json::json!({"validation": "batch_response"})),
    );
}

#[fcp_async_core::runtime::test]
async fn execute_query_dedup_in_flight() {
    let mut ctx = TestContext::new("execute_query_dedup_in_flight");
    let server = MockServer::start().await;
    let counter = Arc::new(AtomicUsize::new(0));

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(CountingResponder {
            counter: counter.clone(),
            body: serde_json::json!({
                "data": {
                    "viewer": {"id": "user-1"}
                }
            }),
            delay: Some(Duration::from_millis(50)),
        })
        .mount(&server)
        .await;

    let client = GraphqlClientBuilder::new(server.uri())
        .with_dedup_in_flight(true)
        .build()
        .expect("client");

    let (first, second) = futures_util::future::join(
        client.execute::<ViewerQuery>(EmptyVars {}),
        client.execute::<ViewerQuery>(EmptyVars {}),
    )
    .await;

    let first = first.expect("first response");
    let second = second.expect("second response");

    ctx.assert_true(first.errors.is_empty(), "first response errors");
    ctx.assert_true(second.errors.is_empty(), "second response errors");
    ctx.assert_eq(
        counter.load(Ordering::SeqCst),
        1_usize,
        "expected one HTTP request",
    );
    ctx.finalize("pass", Some(serde_json::json!({"dedup": true})));
}

#[fcp_async_core::runtime::test]
async fn execute_request_dedup_splits_by_idempotence() {
    let server = MockServer::start().await;
    let counter = Arc::new(AtomicUsize::new(0));

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(CountingResponder {
            counter: counter.clone(),
            body: serde_json::json!({
                "data": {
                    "viewer": {"id": "same-body"}
                }
            }),
            delay: Some(Duration::from_millis(50)),
        })
        .mount(&server)
        .await;

    let client = GraphqlClientBuilder::new(server.uri())
        .with_dedup_in_flight(true)
        .with_retry_policy(RetryPolicy {
            strategy: RetryStrategy::IdempotentOnly,
            ..RetryPolicy::default()
        })
        .build()
        .expect("client");

    let request = GraphqlRequest::new(GraphqlQuery::from_static(ViewerQuery::QUERY), EmptyVars {})
        .with_operation_name(ViewerQuery::OPERATION_NAME);

    let (first, second) = futures_util::future::join(
        client.execute_request::<_, ViewerResponse>(request.clone(), None, None, true),
        client.execute_request::<_, ViewerResponse>(request, None, None, false),
    )
    .await;

    first.expect("idempotent request should succeed");
    second.expect("non-idempotent request should succeed");
    assert_eq!(
        counter.load(Ordering::SeqCst),
        2,
        "same-body callers with different idempotence must not share one in-flight future",
    );
}

#[fcp_async_core::runtime::test]
async fn execute_query_graphql_errors() {
    let mut ctx = TestContext::new("execute_query_graphql_errors");
    let server = MockServer::start().await;

    let response_body = serde_json::json!({
        "errors": [
            {"message": "boom"}
        ]
    });

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response_body))
        .mount(&server)
        .await;

    let client = GraphqlClientBuilder::new(server.uri())
        .with_service_name("test")
        .build()
        .expect("client");

    let err = client
        .execute_strict::<ViewerQuery>(EmptyVars {})
        .await
        .expect_err("should return GraphQL errors");

    let error_len = match err {
        GraphqlClientError::GraphqlErrors { errors } => {
            ctx.assert_eq(errors.len(), 1_usize, "expected one GraphQL error");
            ctx.assert_eq(
                errors[0].message.clone(),
                "boom".to_string(),
                "error message mismatch",
            );
            errors.len()
        }
        other => panic!("unexpected error: {other:?}"),
    };

    ctx.finalize("pass", Some(serde_json::json!({ "errors": error_len })));
}

#[fcp_async_core::runtime::test]
async fn execute_query_retries_on_500() {
    let mut ctx = TestContext::new("execute_query_retries_on_500");
    let server = MockServer::start().await;
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_clone = counter.clone();

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(SequenceResponder {
            counter: counter_clone,
        })
        .mount(&server)
        .await;

    let retry = RetryPolicy {
        max_attempts: 2,
        base_delay: Duration::from_millis(10),
        max_delay: Duration::from_millis(20),
        max_jitter: Duration::from_millis(0),
        strategy: fcp_graphql::RetryStrategy::Always,
    };

    let client = GraphqlClientBuilder::new(server.uri())
        .with_retry_policy(retry)
        .build()
        .expect("client");

    let response = client
        .execute_strict::<ViewerQuery>(EmptyVars {})
        .await
        .expect("query should succeed after retry");

    ctx.assert_eq(
        response.viewer.id,
        "user-2".to_string(),
        "viewer id mismatch",
    );
    let attempts = counter.load(Ordering::SeqCst);
    ctx.assert_eq(attempts, 2_usize, "unexpected retry attempts");
    ctx.finalize("pass", Some(serde_json::json!({ "attempts": attempts })));
}

#[fcp_async_core::runtime::test]
async fn execute_query_non_idempotent_no_retry() {
    let mut ctx = TestContext::new("execute_query_non_idempotent_no_retry");
    let server = MockServer::start().await;
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_clone = counter.clone();

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(SequenceResponder {
            counter: counter_clone,
        })
        .mount(&server)
        .await;

    let retry = RetryPolicy {
        max_attempts: 2,
        base_delay: Duration::from_millis(5),
        max_delay: Duration::from_millis(10),
        max_jitter: Duration::from_millis(0),
        strategy: RetryStrategy::IdempotentOnly,
    };

    let client = GraphqlClientBuilder::new(server.uri())
        .with_retry_policy(retry)
        .build()
        .expect("client");

    let err = client
        .execute_strict::<MutationQuery>(IdVars {
            id: "user-9".to_string(),
        })
        .await
        .expect_err("mutation should not retry");

    ctx.assert_true(
        matches!(err, GraphqlClientError::HttpStatus { .. }),
        "expected HTTP status error",
    );
    let attempts = counter.load(Ordering::SeqCst);
    ctx.assert_eq(attempts, 1_usize, "mutation should not retry");
    ctx.finalize("pass", Some(serde_json::json!({ "attempts": attempts })));
}

#[fcp_async_core::runtime::test]
async fn schema_validation_rejects_invalid_response() {
    let mut ctx = TestContext::new("schema_validation_rejects_invalid_response");
    let server = MockServer::start().await;

    let response_body = serde_json::json!({
        "data": {
            "viewer": {
                "id": 123
            }
        }
    });

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response_body))
        .mount(&server)
        .await;

    let client = GraphqlClientBuilder::new(server.uri())
        .with_validation_mode(SchemaValidationMode::ResponseOnly)
        .build()
        .expect("client");

    let err = client
        .execute::<ViewerSchemaQuery>(EmptyVars {})
        .await
        .expect_err("should fail schema validation");

    ctx.assert_true(
        matches!(err, GraphqlClientError::SchemaValidation { .. }),
        "expected schema validation error",
    );
    ctx.finalize(
        "pass",
        Some(serde_json::json!({"validation_mode": "response"})),
    );
}

#[fcp_async_core::runtime::test]
async fn paginate_cursor_collects_items() {
    let mut ctx = TestContext::new("paginate_cursor_collects_items");
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_clone = counter.clone();

    let result = paginate_cursor(None, None, move |_cursor| {
        let counter = counter_clone.clone();
        async move {
            let step = counter.fetch_add(1, Ordering::SeqCst);
            if step == 0 {
                Ok(CursorPage {
                    items: vec![1, 2],
                    page_info: CursorPageInfo {
                        has_next_page: true,
                        end_cursor: Some("cursor-1".to_string()),
                        total_count: Some(3),
                    },
                })
            } else {
                Ok(CursorPage {
                    items: vec![3],
                    page_info: CursorPageInfo {
                        has_next_page: false,
                        end_cursor: None,
                        total_count: Some(3),
                    },
                })
            }
        }
    })
    .await;

    let items = result.expect("pagination should succeed");
    ctx.assert_eq(items, vec![1, 2, 3], "unexpected cursor items");
    ctx.assert_eq(
        counter.load(Ordering::SeqCst),
        2_usize,
        "expected two pages",
    );
    ctx.finalize("pass", Some(serde_json::json!({"pages": 2})));
}

#[fcp_async_core::runtime::test]
async fn paginate_cursor_limit_exceeded() {
    let mut ctx = TestContext::new("paginate_cursor_limit_exceeded");
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_clone = counter.clone();

    let result = paginate_cursor(
        Some("cursor-0".to_string()),
        Some(PageLimit::new(2)),
        move |_cursor| {
            let counter = counter_clone.clone();
            async move {
                let step = counter.fetch_add(1, Ordering::SeqCst);
                if step == 0 {
                    Ok(CursorPage {
                        items: vec![1, 2],
                        page_info: CursorPageInfo {
                            has_next_page: true,
                            end_cursor: Some("cursor-1".to_string()),
                            total_count: Some(4),
                        },
                    })
                } else {
                    Ok(CursorPage {
                        items: vec![3, 4],
                        page_info: CursorPageInfo {
                            has_next_page: false,
                            end_cursor: None,
                            total_count: Some(4),
                        },
                    })
                }
            }
        },
    )
    .await;

    ctx.assert_true(
        matches!(result, Err(PaginationError::LimitExceeded(_))),
        "expected pagination limit error",
    );
    ctx.assert_eq(
        counter.load(Ordering::SeqCst),
        1_usize,
        "expected one page fetch",
    );
    ctx.finalize("pass", Some(serde_json::json!({"limit": 2})));
}

#[fcp_async_core::runtime::test]
async fn paginate_offset_collects_items() {
    let mut ctx = TestContext::new("paginate_offset_collects_items");
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_clone = counter.clone();

    let result = paginate_offset(0, None, move |offset| {
        let counter = counter_clone.clone();
        async move {
            counter.fetch_add(1, Ordering::SeqCst);
            if offset == 0 {
                Ok(OffsetPage {
                    items: vec![10, 11],
                    next_offset: Some(2),
                    total_count: Some(3),
                })
            } else {
                Ok(OffsetPage {
                    items: vec![12],
                    next_offset: None,
                    total_count: Some(3),
                })
            }
        }
    })
    .await;

    let items = result.expect("offset pagination should succeed");
    ctx.assert_eq(items, vec![10, 11, 12], "unexpected offset items");
    ctx.assert_eq(
        counter.load(Ordering::SeqCst),
        2_usize,
        "expected two pages",
    );
    ctx.finalize("pass", Some(serde_json::json!({"pages": 2})));
}

#[fcp_async_core::runtime::test]
async fn paginate_offset_limit_exceeded() {
    let mut ctx = TestContext::new("paginate_offset_limit_exceeded");
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_clone = counter.clone();

    let result = paginate_offset(0, Some(PageLimit::new(2)), move |offset| {
        let counter = counter_clone.clone();
        async move {
            counter.fetch_add(1, Ordering::SeqCst);
            if offset == 0 {
                Ok(OffsetPage {
                    items: vec![20, 21],
                    next_offset: Some(2),
                    total_count: Some(4),
                })
            } else {
                Ok(OffsetPage {
                    items: vec![22, 23],
                    next_offset: None,
                    total_count: Some(4),
                })
            }
        }
    })
    .await;

    ctx.assert_true(
        matches!(result, Err(PaginationError::LimitExceeded(_))),
        "expected offset pagination limit error",
    );
    ctx.assert_eq(
        counter.load(Ordering::SeqCst),
        1_usize,
        "expected one page fetch",
    );
    ctx.finalize("pass", Some(serde_json::json!({"limit": 2})));
}

#[fcp_async_core::runtime::test]
async fn subscription_receives_next_message() {
    let mut ctx = TestContext::new("subscription_receives_next_message");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server_task = task::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let mut ws = accept_test_websocket(stream).await;

        let init_text = recv_text(&mut ws, "init message").await;
        let init_value: serde_json::Value = serde_json::from_str(&init_text).expect("init json");
        assert_eq!(
            init_value.get("type").and_then(serde_json::Value::as_str),
            Some("connection_init")
        );

        send_json(
            &mut ws,
            serde_json::json!({ "type": "connection_ack" }),
            "ack send",
        )
        .await;

        let subscribe_text = recv_text(&mut ws, "subscribe message").await;
        let subscribe_value: serde_json::Value =
            serde_json::from_str(&subscribe_text).expect("subscribe json");
        assert_eq!(
            subscribe_value
                .get("type")
                .and_then(serde_json::Value::as_str),
            Some("subscribe")
        );

        send_json(
            &mut ws,
            serde_json::json!({
                "type": "next",
                "id": "1",
                "payload": {
                    "data": { "viewer": { "id": "sub-1" } }
                }
            }),
            "next send",
        )
        .await;

        send_json(
            &mut ws,
            serde_json::json!({ "type": "complete", "id": "1" }),
            "complete send",
        )
        .await;
    });

    let url = format!("ws://{}", addr);
    let client = GraphqlSubscriptionClient::new(url, "test");
    let mut stream = client
        .subscribe::<ViewerQuery>(EmptyVars {})
        .await
        .expect("subscribe");

    let next = stream.next().await.expect("stream item");
    let response = next.expect("subscription response");
    ctx.assert_true(response.errors.is_empty(), "subscription errors");
    let viewer = response.data.expect("missing data");
    ctx.assert_eq(viewer.viewer.id, "sub-1".to_string(), "subscriber id");

    server_task.await.expect("server task");
    ctx.finalize("pass", Some(serde_json::json!({"subscription": "next"})));
}

#[fcp_async_core::runtime::test]
async fn subscription_full_result_buffer_handles_ping_then_closes_on_overflow() {
    let ctx =
        TestContext::new("subscription_full_result_buffer_handles_ping_then_closes_on_overflow");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server_task = task::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let mut ws = accept_test_websocket(stream).await;

        let _init = recv_text(&mut ws, "init message").await;
        send_json(
            &mut ws,
            serde_json::json!({ "type": "connection_ack" }),
            "ack send",
        )
        .await;

        let _subscribe = recv_text(&mut ws, "subscribe message").await;

        for index in 0..16 {
            send_json(
                &mut ws,
                serde_json::json!({
                    "type": "next",
                    "id": "1",
                    "payload": {
                        "data": { "viewer": { "id": format!("queued-{index}") } }
                    }
                }),
                "queued next send",
            )
            .await;
        }

        send_json(
            &mut ws,
            serde_json::json!({ "type": "ping", "payload": { "full": true } }),
            "ping send",
        )
        .await;
        let pong_text =
            fcp_async_core::time::timeout(Duration::from_secs(2), recv_text(&mut ws, "pong"))
                .await
                .expect("pong timeout");
        let pong_value: serde_json::Value = serde_json::from_str(&pong_text).expect("pong json");
        assert_eq!(
            pong_value.get("type").and_then(serde_json::Value::as_str),
            Some("pong")
        );

        send_json(
            &mut ws,
            serde_json::json!({
                "type": "next",
                "id": "1",
                "payload": {
                    "data": { "viewer": { "id": "overflow" } }
                }
            }),
            "overflow next send",
        )
        .await;

        let complete_text = fcp_async_core::time::timeout(
            Duration::from_secs(2),
            recv_text(&mut ws, "complete after overflow"),
        )
        .await
        .expect("overflow complete timeout");
        let complete_value: serde_json::Value =
            serde_json::from_str(&complete_text).expect("complete json");
        assert_eq!(
            complete_value
                .get("type")
                .and_then(serde_json::Value::as_str),
            Some("complete")
        );
    });

    let url = format!("ws://{}", addr);
    let client = GraphqlSubscriptionClient::new(url, "test");
    let mut stream = client
        .subscribe::<ViewerQuery>(EmptyVars {})
        .await
        .expect("subscribe");

    // Wait for the server to finish its scripted send sequence
    // BEFORE the consumer starts draining. The script (16 queued
    // next frames + ping/pong + 1 overflow next) deliberately
    // exceeds the 16-item buffer; the producer task will
    // `try_send` the 17th frame, hit `TrySendError::Full`, stage
    // the terminal `SubscriptionBufferOverflow` error, and send
    // `complete` upstream. server_task completes once it recv's
    // that complete frame.
    server_task.await.expect("server task");

    // br-xnroh: drain the consumer stream end-to-end and assert that
    // backpressure overflow surfaces as a TERMINAL Err item, not as
    // a clean stream end. Pre-fix the consumer would observe only
    // the queued Ok items followed by `None` — indistinguishable
    // from a server-initiated `complete`. Post-fix the consumer
    // observes the queued Ok items, then a
    // `SubscriptionBufferOverflow` Err, then `None`.
    let mut ok_items = 0_usize;
    let mut overflow_err_observed = false;
    let mut other_err_count = 0_usize;
    while let Some(item) = fcp_async_core::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("subscription stream did not yield in time")
    {
        match item {
            Ok(_) => {
                ok_items += 1;
            }
            Err(GraphqlClientError::SubscriptionBufferOverflow { capacity }) => {
                assert_eq!(
                    capacity, 16,
                    "br-xnroh: BufferOverflow capacity must report the producer-side \
                     channel buffer capacity"
                );
                assert!(
                    !overflow_err_observed,
                    "br-xnroh: terminal overflow Err must yield exactly once"
                );
                overflow_err_observed = true;
            }
            Err(other) => {
                other_err_count += 1;
                eprintln!("unexpected non-overflow err during drain: {other:?}");
            }
        }
    }
    assert!(
        ok_items > 0,
        "br-xnroh: drain must observe at least one queued Ok item before the overflow Err — got 0"
    );
    assert!(
        overflow_err_observed,
        "br-xnroh: drain MUST yield SubscriptionBufferOverflow as the terminal item; pre-fix \
         the stream ended cleanly and consumers could not distinguish overflow from a \
         server-initiated `complete` (got {ok_items} Ok items, {other_err_count} other Err items)"
    );

    ctx.finalize(
        "pass",
        Some(serde_json::json!({
            "overflow_policy": "terminal_err",
            "ok_items_before_overflow": ok_items,
            "overflow_err_observed": overflow_err_observed,
        })),
    );
}

#[fcp_async_core::runtime::test]
async fn subscription_reconnects_after_disconnect() {
    let mut ctx = TestContext::new("subscription_reconnects_after_disconnect");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server_task = task::spawn(async move {
        for connection_idx in 0..2 {
            let (stream, _) = listener.accept().await.expect("accept");
            let mut ws = accept_test_websocket(stream).await;

            let init_text = recv_text(&mut ws, "init message").await;
            let init_value: serde_json::Value =
                serde_json::from_str(&init_text).expect("init payload");
            assert_eq!(
                init_value.get("type").and_then(serde_json::Value::as_str),
                Some("connection_init")
            );

            send_json(
                &mut ws,
                serde_json::json!({ "type": "connection_ack" }),
                "ack send",
            )
            .await;

            let subscribe_text = recv_text(&mut ws, "subscribe message").await;
            let subscribe_value: serde_json::Value =
                serde_json::from_str(&subscribe_text).expect("subscribe payload");
            assert_eq!(
                subscribe_value
                    .get("type")
                    .and_then(serde_json::Value::as_str),
                Some("subscribe")
            );

            if connection_idx == 0 {
                close_test_websocket(&mut ws).await;
                continue;
            }

            send_json(
                &mut ws,
                serde_json::json!({
                    "type": "next",
                    "id": "1",
                    "payload": {
                        "data": { "viewer": { "id": "reconnect-1" } }
                    }
                }),
                "next send",
            )
            .await;

            send_json(
                &mut ws,
                serde_json::json!({ "type": "complete", "id": "1" }),
                "complete send",
            )
            .await;
        }
    });

    let url = format!("ws://{}", addr);
    let mut ws = WsConfig::new()
        .with_connect_timeout(Duration::from_secs(2))
        .with_auto_reconnect(true);
    ws.reconnect_delay = Duration::from_millis(20);
    ws.max_reconnect_attempts = Some(3);

    let client =
        GraphqlSubscriptionClient::new(url, "test").with_config(GraphqlSubscriptionConfig {
            ws,
            init_payload: None,
            ack_timeout: Duration::from_secs(2),
            query_limits: GraphqlQueryLimits::default(),
        });

    let mut stream = client
        .subscribe::<ViewerQuery>(EmptyVars {})
        .await
        .expect("subscribe");
    let response = stream
        .next()
        .await
        .expect("stream item")
        .expect("subscription response");
    let data = response.data.expect("missing data");
    ctx.assert_eq(
        data.viewer.id,
        "reconnect-1".to_string(),
        "unexpected id after reconnect",
    );

    server_task.await.expect("server task");
    ctx.finalize("pass", Some(serde_json::json!({ "reconnects": 1 })));
}

#[fcp_async_core::runtime::test]
async fn subscription_disconnect_without_reconnect_emits_error() {
    let mut ctx = TestContext::new("subscription_disconnect_without_reconnect_emits_error");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server_task = task::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let mut ws = accept_test_websocket(stream).await;

        let _init = recv_text(&mut ws, "init message").await;
        send_json(
            &mut ws,
            serde_json::json!({ "type": "connection_ack" }),
            "ack send",
        )
        .await;

        let _subscribe = recv_text(&mut ws, "subscribe message").await;
        close_test_websocket(&mut ws).await;
    });

    let url = format!("ws://{}", addr);
    let ws = WsConfig::new()
        .with_connect_timeout(Duration::from_secs(2))
        .with_auto_reconnect(false);
    let client =
        GraphqlSubscriptionClient::new(url, "test").with_config(GraphqlSubscriptionConfig {
            ws,
            init_payload: None,
            ack_timeout: Duration::from_secs(2),
            query_limits: GraphqlQueryLimits::default(),
        });

    let mut stream = client
        .subscribe::<ViewerQuery>(EmptyVars {})
        .await
        .expect("subscribe");
    let err = stream
        .next()
        .await
        .expect("stream error item")
        .expect_err("expected disconnect error");
    match err {
        GraphqlClientError::Protocol { message } => ctx.assert_true(
            message.contains("reconnect exhausted"),
            "expected reconnect exhaustion message",
        ),
        other => panic!("unexpected error: {other:?}"),
    }

    server_task.await.expect("server task");
    ctx.finalize("pass", Some(serde_json::json!({ "reconnect": "disabled" })));
}

#[fcp_async_core::runtime::test]
async fn subscription_drop_sends_complete_frame() {
    let ctx = TestContext::new("subscription_drop_sends_complete_frame");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server_task = task::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let mut ws = accept_test_websocket(stream).await;

        let _init = recv_text(&mut ws, "init message").await;
        send_json(
            &mut ws,
            serde_json::json!({ "type": "connection_ack" }),
            "ack send",
        )
        .await;

        let _subscribe = recv_text(&mut ws, "subscribe message").await;

        let complete_text = fcp_async_core::time::timeout(
            Duration::from_secs(2),
            recv_text(&mut ws, "complete frame"),
        )
        .await
        .expect("complete timeout");
        let complete_value: serde_json::Value =
            serde_json::from_str(&complete_text).expect("complete payload");
        assert_eq!(
            complete_value
                .get("type")
                .and_then(serde_json::Value::as_str),
            Some("complete")
        );
    });

    let url = format!("ws://{}", addr);
    let ws = WsConfig::new().with_connect_timeout(Duration::from_secs(2));
    let client =
        GraphqlSubscriptionClient::new(url, "test").with_config(GraphqlSubscriptionConfig {
            ws,
            init_payload: None,
            ack_timeout: Duration::from_secs(2),
            query_limits: GraphqlQueryLimits::default(),
        });

    let stream = client
        .subscribe::<ViewerQuery>(EmptyVars {})
        .await
        .expect("subscribe");
    drop(stream);

    server_task.await.expect("server task");
    ctx.finalize(
        "pass",
        Some(serde_json::json!({ "cancel": "complete-sent" })),
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 18. Metrics track success, error, and retry counts
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn metrics_track_success_and_error() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"data": {"viewer": {"id": "m1"}}})),
        )
        .mount(&server)
        .await;

    let client = GraphqlClientBuilder::new(server.uri())
        .with_service_name("metrics-test")
        .build()
        .expect("client");

    let m0 = client.metrics();
    assert_eq!(m0.requests_total, 0);

    client
        .execute::<ViewerQuery>(EmptyVars {})
        .await
        .expect("success");

    let m1 = client.metrics();
    assert_eq!(m1.requests_total, 1);
    assert_eq!(m1.requests_success, 1);
    assert_eq!(m1.requests_error, 0);
}

#[fcp_async_core::runtime::test]
async fn metrics_track_error_on_http_failure() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(500).set_body_string("oops"))
        .mount(&server)
        .await;

    let client = GraphqlClientBuilder::new(server.uri())
        .with_retry_policy(RetryPolicy {
            max_attempts: 1,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(1),
            max_jitter: Duration::ZERO,
            strategy: RetryStrategy::Never,
        })
        .build()
        .expect("client");

    let _ = client.execute_strict::<ViewerQuery>(EmptyVars {}).await;

    let m = client.metrics();
    assert_eq!(m.requests_total, 1);
    assert_eq!(m.requests_error, 1);
    assert_eq!(m.requests_success, 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// 19. Metrics track retry counts
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn metrics_track_retried_requests() {
    let server = MockServer::start().await;
    let counter = Arc::new(AtomicUsize::new(0));

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(SequenceResponder {
            counter: counter.clone(),
        })
        .mount(&server)
        .await;

    let client = GraphqlClientBuilder::new(server.uri())
        .with_retry_policy(RetryPolicy {
            max_attempts: 2,
            base_delay: Duration::from_millis(5),
            max_delay: Duration::from_millis(10),
            max_jitter: Duration::ZERO,
            strategy: RetryStrategy::Always,
        })
        .build()
        .expect("client");

    client
        .execute_strict::<ViewerQuery>(EmptyVars {})
        .await
        .expect("should succeed after retry");

    let m = client.metrics();
    // requests_total counts once per execute_bytes call (not per retry attempt)
    assert_eq!(m.requests_total, 1);
    assert_eq!(m.requests_retried, 1);
    assert_eq!(m.requests_success, 1);
}

// ─────────────────────────────────────────────────────────────────────────────
// 20. Bearer token sent in Authorization header
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn bearer_token_sent_in_authorization_header() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(wiremock::matchers::header(
            "Authorization",
            "Bearer tok-secret",
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"data": {"viewer": {"id": "auth-1"}}})),
        )
        .mount(&server)
        .await;

    let client = GraphqlClientBuilder::new(server.uri())
        .with_bearer_token("tok-secret")
        .build()
        .expect("client");

    let resp = client
        .execute::<ViewerQuery>(EmptyVars {})
        .await
        .expect("query with bearer token");
    assert_eq!(resp.data.unwrap().viewer.id, "auth-1");
}

// ─────────────────────────────────────────────────────────────────────────────
// 21. Custom headers sent with request
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn custom_headers_sent_with_request() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(wiremock::matchers::header("X-Custom-Key", "custom-value"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"data": {"viewer": {"id": "hdr-1"}}})),
        )
        .mount(&server)
        .await;

    let client = GraphqlClientBuilder::new(server.uri())
        .with_header("X-Custom-Key", "custom-value")
        .build()
        .expect("client");

    let resp = client
        .execute::<ViewerQuery>(EmptyVars {})
        .await
        .expect("query with custom header");
    assert_eq!(resp.data.unwrap().viewer.id, "hdr-1");
}

// ─────────────────────────────────────────────────────────────────────────────
// 22. Response extensions preserved
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn response_extensions_preserved() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"viewer": {"id": "ext-1"}},
            "extensions": {"cost": {"requestedQueryCost": 5, "throttleStatus": "ok"}}
        })))
        .mount(&server)
        .await;

    let client = GraphqlClientBuilder::new(server.uri())
        .build()
        .expect("client");

    let resp = client
        .execute::<ViewerQuery>(EmptyVars {})
        .await
        .expect("query with extensions");

    assert!(resp.is_ok());
    let ext = resp.extensions.expect("extensions should be present");
    assert_eq!(ext["cost"]["requestedQueryCost"], 5);
}

// ─────────────────────────────────────────────────────────────────────────────
// 23. Response is_ok integration
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn response_is_ok_with_partial_errors() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"viewer": {"id": "partial-1"}},
            "errors": [{"message": "field deprecation warning"}]
        })))
        .mount(&server)
        .await;

    let client = GraphqlClientBuilder::new(server.uri())
        .build()
        .expect("client");

    let resp = client
        .execute::<ViewerQuery>(EmptyVars {})
        .await
        .expect("query");

    assert!(!resp.is_ok(), "response with errors should not be is_ok");
    assert!(resp.data.is_some(), "partial data should still be present");
    assert_eq!(resp.errors.len(), 1);
}

// ─────────────────────────────────────────────────────────────────────────────
// 24. Retry exhaustion returns RetriesExhausted
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn retry_exhausted_returns_retries_exhausted_error() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(500).set_body_string("crash"))
        .mount(&server)
        .await;

    let client = GraphqlClientBuilder::new(server.uri())
        .with_retry_policy(RetryPolicy {
            max_attempts: 3,
            base_delay: Duration::from_millis(5),
            max_delay: Duration::from_millis(10),
            max_jitter: Duration::ZERO,
            strategy: RetryStrategy::Always,
        })
        .build()
        .expect("client");

    let err = client
        .execute_strict::<ViewerQuery>(EmptyVars {})
        .await
        .expect_err("should exhaust retries");

    // After exhausting retries, the client returns the last error (HttpStatus)
    assert!(
        matches!(err, GraphqlClientError::HttpStatus { .. }),
        "expected last HttpStatus error after retry exhaustion, got {err:?}"
    );

    let m = client.metrics();
    assert_eq!(m.requests_retried, 2, "two retries before giving up");
}

// ─────────────────────────────────────────────────────────────────────────────
// 25. Schema validation Off accepts any shape
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn schema_validation_off_accepts_any_response() {
    let server = MockServer::start().await;

    // Return a response with viewer.id as a number (not string) — would fail
    // ResponseOnly validation, but Off mode should accept it.
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"data": {"viewer": {"id": 999}}})),
        )
        .mount(&server)
        .await;

    let client = GraphqlClientBuilder::new(server.uri())
        .with_validation_mode(SchemaValidationMode::Off)
        .build()
        .expect("client");

    // Use ViewerSchemaQuery which HAS a response_schema — but Off mode skips it
    let resp = client
        .execute::<ViewerSchemaQuery>(EmptyVars {})
        .await
        .expect("Off mode should not validate");

    assert!(resp.is_ok());
}

// ─────────────────────────────────────────────────────────────────────────────
// 26. Dedup disabled sends multiple requests
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn dedup_disabled_sends_multiple_requests() {
    let server = MockServer::start().await;
    let counter = Arc::new(AtomicUsize::new(0));

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(CountingResponder {
            counter: counter.clone(),
            body: serde_json::json!({"data": {"viewer": {"id": "dup-1"}}}),
            delay: Some(Duration::from_millis(50)),
        })
        .mount(&server)
        .await;

    let client = GraphqlClientBuilder::new(server.uri())
        .with_dedup_in_flight(false)
        .build()
        .expect("client");

    let (r1, r2) = futures_util::future::join(
        client.execute::<ViewerQuery>(EmptyVars {}),
        client.execute::<ViewerQuery>(EmptyVars {}),
    )
    .await;

    r1.expect("first response");
    r2.expect("second response");
    assert_eq!(
        counter.load(Ordering::SeqCst),
        2,
        "without dedup, two HTTP requests should be sent"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 27. Paginate cursor: single page
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn paginate_cursor_single_page() {
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_clone = counter.clone();

    let result = paginate_cursor(None, None, move |_cursor| {
        let counter = counter_clone.clone();
        async move {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(CursorPage {
                items: vec![10, 20, 30],
                page_info: CursorPageInfo {
                    has_next_page: false,
                    end_cursor: None,
                    total_count: Some(3),
                },
            })
        }
    })
    .await;

    let items = result.expect("single page should succeed");
    assert_eq!(items, vec![10, 20, 30]);
    assert_eq!(counter.load(Ordering::SeqCst), 1, "only one page fetch");
}

// ─────────────────────────────────────────────────────────────────────────────
// 28. Paginate cursor: empty first page
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn paginate_cursor_empty_first_page() {
    let result = paginate_cursor(None, None, |_cursor| async move {
        Ok(CursorPage {
            items: Vec::<i32>::new(),
            page_info: CursorPageInfo {
                has_next_page: false,
                end_cursor: None,
                total_count: Some(0),
            },
        })
    })
    .await;

    let items = result.expect("empty page should succeed");
    assert!(items.is_empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// 29. Paginate offset: single page
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn paginate_offset_single_page() {
    let result = paginate_offset(0, None, |_offset| async move {
        Ok(OffsetPage {
            items: vec![100, 200],
            next_offset: None,
            total_count: Some(2),
        })
    })
    .await;

    let items = result.expect("single offset page should succeed");
    assert_eq!(items, vec![100, 200]);
}

// ─────────────────────────────────────────────────────────────────────────────
// 30. Paginate offset: empty page
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn paginate_offset_empty_first_page() {
    let result = paginate_offset(0, None, |_offset| async move {
        Ok(OffsetPage {
            items: Vec::<i32>::new(),
            next_offset: None,
            total_count: Some(0),
        })
    })
    .await;

    let items = result.expect("empty offset page should succeed");
    assert!(items.is_empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// 31. GraphQL error with locations and path preserved
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn graphql_error_locations_and_path_preserved() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "errors": [{
                "message": "Cannot query field 'email' on type 'Viewer'",
                "locations": [{"line": 2, "column": 5}],
                "path": ["viewer", 0, "email"],
                "extensions": {"code": "GRAPHQL_VALIDATION_FAILED"}
            }]
        })))
        .mount(&server)
        .await;

    let client = GraphqlClientBuilder::new(server.uri())
        .build()
        .expect("client");

    let err = client
        .execute_strict::<ViewerQuery>(EmptyVars {})
        .await
        .expect_err("should return GraphQL error");

    match err {
        GraphqlClientError::GraphqlErrors { errors } => {
            assert_eq!(errors.len(), 1);
            let e = &errors[0];
            assert_eq!(e.locations.len(), 1);
            assert_eq!(e.locations[0].line, 2);
            assert_eq!(e.locations[0].column, 5);
            assert_eq!(e.path.len(), 3);
            assert_eq!(e.path[0], GraphqlPathSegment::Key("viewer".into()));
            assert_eq!(e.path[1], GraphqlPathSegment::Index(0));
            assert_eq!(e.path[2], GraphqlPathSegment::Key("email".into()));
            assert_eq!(
                e.extensions.as_ref().unwrap()["code"],
                "GRAPHQL_VALIDATION_FAILED"
            );
        }
        other => panic!("expected GraphqlErrors, got {other:?}"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 32. to_fcp_error integration (cross-module)
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn to_fcp_error_maps_429_to_rate_limited() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_string("rate limited")
                .append_header("Retry-After", "30"),
        )
        .mount(&server)
        .await;

    let client = GraphqlClientBuilder::new(server.uri())
        .with_retry_policy(RetryPolicy {
            max_attempts: 1,
            strategy: RetryStrategy::Never,
            ..RetryPolicy::default()
        })
        .build()
        .expect("client");

    let err = client
        .execute_strict::<ViewerQuery>(EmptyVars {})
        .await
        .expect_err("should get 429");

    let fcp_err = err.to_fcp_error("test-svc");
    match fcp_err {
        fcp_core::FcpError::RateLimited { .. } => {}
        other => panic!("expected RateLimited, got {other:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn to_fcp_error_maps_401_to_unauthorized() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(401).set_body_string("invalid token"))
        .mount(&server)
        .await;

    let client = GraphqlClientBuilder::new(server.uri())
        .with_retry_policy(RetryPolicy {
            max_attempts: 1,
            strategy: RetryStrategy::Never,
            ..RetryPolicy::default()
        })
        .build()
        .expect("client");

    let err = client
        .execute_strict::<ViewerQuery>(EmptyVars {})
        .await
        .expect_err("should get 401");

    let fcp_err = err.to_fcp_error("github-api");
    match fcp_err {
        fcp_core::FcpError::Unauthorized { message, .. } => {
            assert!(message.contains("github-api"));
        }
        other => panic!("expected Unauthorized, got {other:?}"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 33. Client with_config constructor
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn client_with_config_constructor() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"data": {"viewer": {"id": "cfg-1"}}})),
        )
        .mount(&server)
        .await;

    let config = fcp_graphql::GraphqlClientConfig {
        service_name: "config-test".to_string(),
        ..Default::default()
    };

    let client = fcp_graphql::GraphqlClient::with_config(server.uri(), config).expect("client");

    let resp = client
        .execute::<ViewerQuery>(EmptyVars {})
        .await
        .expect("query via with_config");
    assert_eq!(resp.data.unwrap().viewer.id, "cfg-1");
}

// ─────────────────────────────────────────────────────────────────────────────
// 34. Subscription with init_payload
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn subscription_with_init_payload() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server_task = task::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let mut ws = accept_test_websocket(stream).await;

        let init_text = recv_text(&mut ws, "init message").await;
        let init_value: serde_json::Value = serde_json::from_str(&init_text).expect("init json");

        // Verify the init_payload is included
        assert_eq!(
            init_value.get("type").and_then(serde_json::Value::as_str),
            Some("connection_init")
        );
        let payload = init_value.get("payload").expect("payload present");
        assert_eq!(payload["token"], "my-auth-token");

        send_json(
            &mut ws,
            serde_json::json!({"type": "connection_ack"}),
            "ack send",
        )
        .await;

        let _subscribe = recv_text(&mut ws, "subscribe").await;

        send_json(
            &mut ws,
            serde_json::json!({
                "type": "next",
                "id": "1",
                "payload": { "data": {"viewer": {"id": "init-payload-1"}} }
            }),
            "next send",
        )
        .await;

        send_json(
            &mut ws,
            serde_json::json!({"type": "complete", "id": "1"}),
            "complete send",
        )
        .await;
    });

    let url = format!("ws://{}", addr);
    let config = GraphqlSubscriptionConfig {
        ws: WsConfig::new().with_connect_timeout(Duration::from_secs(2)),
        init_payload: Some(serde_json::json!({"token": "my-auth-token"})),
        ack_timeout: Duration::from_secs(2),
        query_limits: GraphqlQueryLimits::default(),
    };
    let client = GraphqlSubscriptionClient::new(url, "test").with_config(config);

    let mut stream = client
        .subscribe::<ViewerQuery>(EmptyVars {})
        .await
        .expect("subscribe");

    let response = stream
        .next()
        .await
        .expect("stream item")
        .expect("subscription response");
    assert_eq!(response.data.unwrap().viewer.id, "init-payload-1");

    server_task.await.expect("server task");
}

// ─────────────────────────────────────────────────────────────────────────────
// 35. Execute query with timeout via builder
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn execute_query_timeout() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"data": {"viewer": {"id": "slow"}}}))
                .set_delay(Duration::from_secs(5)),
        )
        .mount(&server)
        .await;

    let client = GraphqlClientBuilder::new(server.uri())
        .with_timeout(Duration::from_millis(50))
        .with_retry_policy(RetryPolicy {
            max_attempts: 1,
            strategy: RetryStrategy::Never,
            ..RetryPolicy::default()
        })
        .build()
        .expect("client");

    let err = client
        .execute_strict::<ViewerQuery>(EmptyVars {})
        .await
        .expect_err("should timeout");

    assert!(
        matches!(err, GraphqlClientError::Http(..)),
        "expected Http timeout error, got {err:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 36. Paginate cursor propagates fetch error
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn paginate_cursor_propagates_fetch_error() {
    let result = paginate_cursor(None, None, |_cursor| async move {
        Err::<CursorPage<i32>, _>(GraphqlClientError::Protocol {
            message: "upstream failure".into(),
        })
    })
    .await;

    match result {
        Err(PaginationError::Client(GraphqlClientError::Protocol { message })) => {
            assert_eq!(message, "upstream failure");
        }
        other => panic!("expected PaginationError::Client(Protocol), got {other:?}"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 37. Paginate offset propagates fetch error
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn paginate_offset_propagates_fetch_error() {
    let result = paginate_offset(0, None, |_offset| async move {
        Err::<OffsetPage<i32>, _>(GraphqlClientError::Json("bad payload".into()))
    })
    .await;

    match result {
        Err(PaginationError::Client(GraphqlClientError::Json(msg))) => {
            assert_eq!(msg, "bad payload");
        }
        other => panic!("expected PaginationError::Client(Json), got {other:?}"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 38. GraphqlClientError is Send + Sync
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn graphql_client_error_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<GraphqlClientError>();
}

// ─────────────────────────────────────────────────────────────────────────────
// 39. GraphqlClientError is std::error::Error
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn graphql_client_error_is_std_error() {
    fn assert_error<T: std::error::Error>() {}
    assert_error::<GraphqlClientError>();
}

// ─────────────────────────────────────────────────────────────────────────────
// 40. GraphqlQuery serde roundtrip in integration context
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn graphql_query_serde_roundtrip() {
    let q = GraphqlQuery::from_static("query Foo { bar { id } }");
    let json = serde_json::to_string(&q).unwrap();
    assert_eq!(json, "\"query Foo { bar { id } }\"");
    let back: GraphqlQuery = serde_json::from_str(&json).unwrap();
    assert_eq!(q.as_str(), back.as_str());
}

// ─────────────────────────────────────────────────────────────────────────────
// 41. GraphqlRequest serde skips None operation_name
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn graphql_request_serde_skips_none_op_name() {
    let req = GraphqlRequest::new(GraphqlQuery::new("{ users { id } }"), serde_json::json!({}));
    let json = serde_json::to_string(&req).unwrap();
    assert!(!json.contains("operation_name"));
    assert!(!json.contains("operationName"));
}

#[test]
fn graphql_request_serde_includes_op_name() {
    let req = GraphqlRequest::new(
        GraphqlQuery::new("{ users { id } }"),
        serde_json::json!({"limit": 10}),
    )
    .with_operation_name("GetUsers");
    let json = serde_json::to_string(&req).unwrap();
    assert!(json.contains("GetUsers"));
    assert!(json.contains("operationName"));
    assert!(!json.contains("operation_name"));
}

// ─────────────────────────────────────────────────────────────────────────────
// 42. RetryPolicy default values
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn retry_policy_default_values() {
    let p = RetryPolicy::default();
    assert_eq!(p.max_attempts, 3);
    assert_eq!(p.strategy, RetryStrategy::IdempotentOnly);
    assert!(p.base_delay > Duration::ZERO);
    assert!(p.max_delay > p.base_delay);
}

// ─────────────────────────────────────────────────────────────────────────────
// 43. RetryDecision equality
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn retry_decision_equality() {
    assert_eq!(RetryDecision::DoNotRetry, RetryDecision::DoNotRetry);
    assert_ne!(
        RetryDecision::RetryAfter(Duration::from_millis(100)),
        RetryDecision::DoNotRetry
    );
    assert_eq!(
        RetryDecision::RetryAfter(Duration::from_millis(50)),
        RetryDecision::RetryAfter(Duration::from_millis(50))
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 44. GraphqlErrorLocation equality
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn graphql_error_location_equality() {
    let a = GraphqlErrorLocation { line: 1, column: 5 };
    let b = GraphqlErrorLocation { line: 1, column: 5 };
    let c = GraphqlErrorLocation { line: 2, column: 3 };
    assert_eq!(a, b);
    assert_ne!(a, c);
}

// ─────────────────────────────────────────────────────────────────────────────
// 45. GraphqlPathSegment equality across variants
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn graphql_path_segment_cross_variant_ne() {
    let key = GraphqlPathSegment::Key("0".into());
    let index = GraphqlPathSegment::Index(0);
    assert_ne!(key, index);
}

// ─────────────────────────────────────────────────────────────────────────────
// 46. PaginationError trait bounds
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pagination_error_is_from_client_error() {
    let client_err = GraphqlClientError::Json("bad".into());
    let pag_err: PaginationError = client_err.into();
    match pag_err {
        PaginationError::Client(GraphqlClientError::Json(msg)) => {
            assert_eq!(msg, "bad");
        }
        other => panic!("expected Client(Json), got {other:?}"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 47. GraphqlClientConfig default
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn graphql_client_config_default() {
    let config = fcp_graphql::GraphqlClientConfig::default();
    // Default includes Content-Type: application/json
    assert!(!config.headers.is_empty());
    assert!(!config.dedup_in_flight);
    assert_eq!(config.validation, SchemaValidationMode::Off);
    assert_eq!(config.service_name, "graphql");
}

// ─────────────────────────────────────────────────────────────────────────────
// 48. execute_strict returns data directly on success
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn execute_strict_returns_data_directly() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"data": {"viewer": {"id": "strict-1"}}})),
        )
        .mount(&server)
        .await;

    let client = GraphqlClientBuilder::new(server.uri())
        .build()
        .expect("client");

    let data = client
        .execute_strict::<ViewerQuery>(EmptyVars {})
        .await
        .expect("strict query");

    assert_eq!(data.viewer.id, "strict-1");
}

// ─────────────────────────────────────────────────────────────────────────────
// 49. Multiple sequential queries use same client
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn multiple_sequential_queries_same_client() {
    let server = MockServer::start().await;
    let counter = Arc::new(AtomicUsize::new(0));

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(CountingResponder {
            counter: counter.clone(),
            body: serde_json::json!({"data": {"viewer": {"id": "seq-1"}}}),
            delay: None,
        })
        .mount(&server)
        .await;

    let client = GraphqlClientBuilder::new(server.uri())
        .build()
        .expect("client");

    for _ in 0..5 {
        client
            .execute::<ViewerQuery>(EmptyVars {})
            .await
            .expect("sequential query");
    }

    let m = client.metrics();
    assert_eq!(m.requests_total, 5);
    assert_eq!(m.requests_success, 5);
    assert_eq!(counter.load(Ordering::SeqCst), 5);
}
