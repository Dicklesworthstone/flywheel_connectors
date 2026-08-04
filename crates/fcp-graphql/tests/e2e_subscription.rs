use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::Duration;

use asupersync::net::websocket::{CloseReason, Message, ServerWebSocket, WebSocketAcceptor};
use fcp_async_core::io::{AsyncRead, ReadBuf};
use fcp_async_core::net::{TcpListener, TcpStream};
use fcp_async_core::task;
use fcp_graphql::{GraphqlOperation, GraphqlSubscriptionClient};
use futures_util::StreamExt as _;
use serde::{Deserialize, Serialize};
use tracing::Level;

type TraceSteps = Arc<Mutex<Vec<&'static str>>>;
type TestServerWebSocket = ServerWebSocket<TcpStream>;

#[derive(Debug, Clone, Serialize)]
struct EmptyVars {}

#[derive(Debug, Deserialize, Serialize)]
struct ViewerResponse {
    viewer: Viewer,
}

#[derive(Debug, Deserialize, Serialize)]
struct Viewer {
    id: String,
}

struct ViewerSubscription;

impl GraphqlOperation for ViewerSubscription {
    type Variables = EmptyVars;
    type ResponseData = ViewerResponse;

    const QUERY: &'static str = "subscription ViewerEvents { viewer { id } }";
    const OPERATION_NAME: &'static str = "ViewerEvents";
}

fn record_step(steps: &TraceSteps, step: &'static str) {
    let mut guard = steps.lock().expect("trace steps lock");
    let order = guard.len();
    let span = tracing::span!(
        Level::INFO,
        "delta_e2e_step",
        crate_name = "fcp-graphql",
        step,
        order
    );
    let _entered = span.enter();
    guard.push(step);
}

fn assert_step_order(steps: &TraceSteps, expected: &[&'static str]) {
    let observed = steps.lock().expect("trace steps lock");
    let mut cursor = 0;
    for expected_step in expected {
        let relative = observed[cursor..]
            .iter()
            .position(|step| step == expected_step);
        assert!(
            relative.is_some(),
            "missing trace step {expected_step}; observed {observed:?}"
        );
        let relative = relative.unwrap_or(0);
        cursor += relative + 1;
    }
}

async fn read_http_headers<IO: AsyncRead + Unpin>(io: &mut IO) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut temp = [0_u8; 256];
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
    }
}

async fn accept_websocket(mut stream: TcpStream) -> TestServerWebSocket {
    let request = read_http_headers(&mut stream)
        .await
        .expect("read websocket handshake");
    WebSocketAcceptor::new()
        .accept(&fcp_async_core::compatibility_cx(), &request, stream)
        .await
        .expect("accept websocket")
}

fn expect_text(message: Message, context: &str) -> String {
    if let Message::Text(text) = message {
        text
    } else {
        assert!(
            matches!(message, Message::Text(_)),
            "expected text frame for {context}, got {message:?}"
        );
        String::new()
    }
}

async fn recv_text(ws: &mut TestServerWebSocket, context: &str) -> String {
    let maybe_message = ws
        .recv(&fcp_async_core::compatibility_cx())
        .await
        .expect(context);
    assert!(maybe_message.is_some(), "{context} missing");
    let message = maybe_message.unwrap_or_else(|| Message::text(String::new()));
    expect_text(message, context)
}

async fn send_json(ws: &mut TestServerWebSocket, value: serde_json::Value, context: &str) {
    ws.send(
        &fcp_async_core::compatibility_cx(),
        Message::text(value.to_string()),
    )
    .await
    .expect(context);
}

async fn close_websocket(ws: &mut TestServerWebSocket) {
    let _ = ws
        .close(&fcp_async_core::compatibility_cx(), CloseReason::normal())
        .await;
}

#[fcp_async_core::runtime::test]
async fn e2e_subscription_emit_receive_and_backpressure_unsubscribe() {
    let steps = Arc::new(Mutex::new(Vec::new()));
    record_step(&steps, "server_start");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind ws");
    let addr = listener.local_addr().expect("ws addr");
    let server_steps = Arc::clone(&steps);

    let server_task = task::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept ws");
        record_step(&server_steps, "server_accept");
        let mut ws = accept_websocket(stream).await;

        let init = recv_text(&mut ws, "connection init").await;
        let init_json: serde_json::Value = serde_json::from_str(&init).expect("init json");
        assert_eq!(
            init_json.get("type").and_then(serde_json::Value::as_str),
            Some("connection_init")
        );
        record_step(&server_steps, "server_init");

        send_json(
            &mut ws,
            serde_json::json!({"type": "connection_ack"}),
            "connection ack",
        )
        .await;

        let subscribe = recv_text(&mut ws, "subscribe").await;
        let subscribe_json: serde_json::Value =
            serde_json::from_str(&subscribe).expect("subscribe json");
        assert_eq!(
            subscribe_json
                .get("type")
                .and_then(serde_json::Value::as_str),
            Some("subscribe")
        );
        record_step(&server_steps, "server_subscribe");

        send_json(
            &mut ws,
            serde_json::json!({
                "type": "next",
                "id": "1",
                "payload": {"data": {"viewer": {"id": "delta-first"}}}
            }),
            "first next",
        )
        .await;
        record_step(&server_steps, "server_emit");

        for index in 0..17 {
            send_json(
                &mut ws,
                serde_json::json!({
                    "type": "next",
                    "id": "1",
                    "payload": {"data": {"viewer": {"id": format!("queued-{index}")}}}
                }),
                "queued next",
            )
            .await;
        }
        record_step(&server_steps, "server_overfill");

        let complete = fcp_async_core::time::timeout(
            Duration::from_secs(5),
            recv_text(&mut ws, "complete after backpressure"),
        )
        .await
        .expect("complete timeout");
        let complete_json: serde_json::Value =
            serde_json::from_str(&complete).expect("complete json");
        assert_eq!(
            complete_json
                .get("type")
                .and_then(serde_json::Value::as_str),
            Some("complete")
        );
        assert_eq!(
            complete_json.get("id").and_then(serde_json::Value::as_str),
            Some("1")
        );
        record_step(&server_steps, "server_complete");
        close_websocket(&mut ws).await;
    });

    let client = GraphqlSubscriptionClient::new(format!("ws://{addr}"), "delta-e2e");
    record_step(&steps, "client_subscribe");
    let mut stream = client
        .subscribe::<ViewerSubscription>(EmptyVars {})
        .await
        .expect("subscribe");
    record_step(&steps, "client_subscribed");

    let first = fcp_async_core::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("first item timeout")
        .expect("first item")
        .expect("first response");
    let data = first.data.expect("first response data");
    assert_eq!(data.viewer.id, "delta-first");
    record_step(&steps, "client_receive");

    server_task.await.expect("server task");
    record_step(&steps, "verify");

    assert_step_order(
        &steps,
        &[
            "server_start",
            "client_subscribe",
            "client_subscribed",
            "client_receive",
            "verify",
        ],
    );
    assert_step_order(
        &steps,
        &[
            "server_start",
            "server_accept",
            "server_init",
            "server_subscribe",
            "server_emit",
            "server_overfill",
            "server_complete",
            "verify",
        ],
    );
}
