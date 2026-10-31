//! Discord Gateway (WebSocket) client.

use std::sync::{
    Arc, Mutex as StdMutex, OnceLock,
    atomic::{AtomicBool, Ordering},
};
use std::{
    collections::{BTreeMap, VecDeque},
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use fcp_async_core::channel::mpsc;
use fcp_async_core::sync::Mutex;
use fcp_sdk::runtime::StreamingError;
use fcp_streaming::{WsClient, WsConfig, WsConnection, WsMessage};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::{debug, error, info, instrument, warn};

use crate::{
    api::DiscordApiClient,
    config::DiscordConfig,
    error::{DiscordError, DiscordResult},
    types::{
        GatewayHello, GatewayIdentify, GatewayPayload, GatewayProperties, GatewayReady,
        GatewayResume, validate_gateway_hello,
    },
};

/// Discord Gateway opcodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum GatewayOpcode {
    /// Receive: An event was dispatched.
    Dispatch = 0,
    /// Send/Receive: Fired periodically to keep the connection alive.
    Heartbeat = 1,
    /// Send: Starts a new session.
    Identify = 2,
    /// Send: Update presence.
    PresenceUpdate = 3,
    /// Send: Join/leave or move between voice channels.
    VoiceStateUpdate = 4,
    /// Send: Resume a previous session.
    Resume = 6,
    /// Receive: Reconnect to the gateway.
    Reconnect = 7,
    /// Send: Request guild members.
    RequestGuildMembers = 8,
    /// Receive: Session invalidated.
    InvalidSession = 9,
    /// Receive: Sent after connecting.
    Hello = 10,
    /// Receive: Heartbeat acknowledged.
    HeartbeatAck = 11,
}

const GATEWAY_EVENT_BUFFER_CAPACITY: usize = 256;
const GATEWAY_PENDING_MAX_BYTES: usize = 16 * 1024 * 1024;
const GATEWAY_FRAME_MAX_BYTES: usize = 1024 * 1024;
const GATEWAY_STATE_MAX_BYTES: u64 = 64 * 1024;
const GATEWAY_STATE_VERSION: u32 = 2;
const GATEWAY_STOP_POLL: Duration = Duration::from_millis(100);
pub const DISCORD_GATEWAY_STATE_FILE: &str = "discord_gateway_state.json";
const GATEWAY_SEND_LIMIT: usize = 120;
const GATEWAY_SEND_WINDOW: Duration = Duration::from_secs(60);
// br-x13q4: the identify spacing used to be a `#[cfg(test)]` constant —
// 5 s normally, 5 ms under test. That gate does NOT reach integration tests,
// which link the library built without `cfg(test)`, so the loopback gateway
// tests were silently serialized behind the real 5 s window while asserting
// against a 3 s timeout. Exactly one of any two of them failed per run,
// depending on which identified second. The window now comes from config so
// tests set it explicitly and cannot be surprised by it again.

async fn connect_gateway_websocket(url: &str) -> DiscordResult<WsConnection> {
    WsClient::with_config(
        url,
        WsConfig::default().with_max_message_size(GATEWAY_FRAME_MAX_BYTES),
    )
    .connect()
    .await
    .map_err(DiscordError::from)
}

#[derive(Debug)]
struct GatewaySendLimiter {
    limit: usize,
    window: Duration,
    sent_at: VecDeque<Instant>,
}

impl GatewaySendLimiter {
    fn new(limit: usize, window: Duration) -> Self {
        Self {
            limit: limit.max(1),
            window,
            sent_at: VecDeque::new(),
        }
    }

    async fn wait_for_slot(&mut self, critical: bool) {
        if critical {
            return;
        }

        loop {
            let now = Instant::now();
            self.prune(now);
            if self.sent_at.len() < self.limit {
                self.sent_at.push_back(now);
                return;
            }

            let Some(oldest) = self.sent_at.front().copied() else {
                continue;
            };
            let wait = (oldest + self.window).saturating_duration_since(now);
            fcp_async_core::time::sleep(wait).await;
        }
    }

    fn status(&mut self) -> GatewaySendLimiterStatus {
        let now = Instant::now();
        self.prune(now);
        let reset_in = self
            .sent_at
            .front()
            .map(|oldest| (*oldest + self.window).saturating_duration_since(now))
            .unwrap_or(self.window);
        GatewaySendLimiterStatus {
            remaining_events: self.limit.saturating_sub(self.sent_at.len()),
            current_event_count: self.sent_at.len(),
            reset_in,
        }
    }

    fn prune(&mut self, now: Instant) {
        let window_start = now.checked_sub(self.window).unwrap_or(now);
        while self
            .sent_at
            .front()
            .is_some_and(|sent_at| *sent_at <= window_start)
        {
            let _ = self.sent_at.pop_front();
        }
    }
}

impl Default for GatewaySendLimiter {
    fn default() -> Self {
        Self::new(GATEWAY_SEND_LIMIT, GATEWAY_SEND_WINDOW)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GatewaySendLimiterStatus {
    remaining_events: usize,
    current_event_count: usize,
    reset_in: Duration,
}

#[derive(Debug)]
struct GatewayIdentifyLimiter {
    next_allowed_at_by_key: StdMutex<BTreeMap<u32, Instant>>,
}

impl GatewayIdentifyLimiter {
    const fn new() -> Self {
        Self {
            next_allowed_at_by_key: StdMutex::new(BTreeMap::new()),
        }
    }

    async fn wait(&self, config: &DiscordConfig) {
        let (shard_id, max_concurrency, window) = identify_limiter_params(config);
        self.wait_for(shard_id, max_concurrency, window).await;
    }

    async fn wait_for(&self, shard_id: u32, max_concurrency: u32, window: Duration) {
        let wait = self.reserve_wait(shard_id, max_concurrency, window);
        if !wait.is_zero() {
            fcp_async_core::time::sleep(wait).await;
        }
    }

    fn reserve_wait(&self, shard_id: u32, max_concurrency: u32, window: Duration) -> Duration {
        let key = shard_id % max_concurrency.max(1);
        let now = Instant::now();
        let mut next_allowed_at_by_key = self
            .next_allowed_at_by_key
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let next_allowed_at = next_allowed_at_by_key.get(&key).copied().unwrap_or(now);
        let wait = next_allowed_at.saturating_duration_since(now);
        next_allowed_at_by_key.insert(key, now.max(next_allowed_at) + window);
        wait
    }
}

fn identify_limiter_params(config: &DiscordConfig) -> (u32, u32, Duration) {
    let shard_id = config.shard.as_ref().map_or(0, |shard| shard.shard_id);
    (
        shard_id,
        config.gateway_identify_max_concurrency.max(1),
        Duration::from_millis(config.gateway_identify_window_ms),
    )
}

fn shared_gateway_identify_limiter() -> &'static GatewayIdentifyLimiter {
    static LIMITER: OnceLock<GatewayIdentifyLimiter> = OnceLock::new();
    LIMITER.get_or_init(GatewayIdentifyLimiter::new)
}

async fn send_gateway_payload(
    ws_stream: &mut WsConnection,
    send_limiter: &mut GatewaySendLimiter,
    payload: &GatewayPayload,
    critical: bool,
    context: &str,
) -> DiscordResult<()> {
    let serialized = serde_json::to_string(payload)?;
    send_limiter.wait_for_slot(critical).await;
    fcp_async_core::time::timeout(Duration::from_secs(1), ws_stream.send_text(serialized))
        .await
        .map_err(|_| gateway_failure(format!("Timed out sending Gateway {context}")))?
        .map_err(|error| DiscordError::Gateway(format!("Failed to send {context}: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync::io::{AsyncRead, ReadBuf};
    use asupersync::net::websocket::{
        CloseReason, Message as ServerWsMessage, ServerWebSocket, WebSocketAcceptor,
    };
    use fcp_async_core::net::TcpListener;
    use fcp_async_core::time::sleep;
    use serde_json::json;
    use std::{future::poll_fn, io, pin::Pin, task::Poll};

    type TestServerWebSocket = ServerWebSocket<fcp_async_core::net::TcpStream>;

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

    async fn accept_test_websocket(
        mut stream: fcp_async_core::net::TcpStream,
    ) -> TestServerWebSocket {
        let request = read_http_headers(&mut stream)
            .await
            .expect("read websocket handshake");
        WebSocketAcceptor::new()
            .accept(&fcp_async_core::compatibility_cx(), &request, stream)
            .await
            .expect("accept websocket")
    }

    async fn recv_message(ws: &mut TestServerWebSocket, context: &str) -> ServerWsMessage {
        ws.recv(&fcp_async_core::compatibility_cx())
            .await
            .expect(context)
            .unwrap_or_else(|| panic!("{context} missing"))
    }

    async fn recv_payload(ws: &mut TestServerWebSocket, context: &str) -> GatewayPayload {
        parse_payload(recv_message(ws, context).await)
    }

    async fn send_message(ws: &mut TestServerWebSocket, message: ServerWsMessage, context: &str) {
        ws.send(&fcp_async_core::compatibility_cx(), message)
            .await
            .expect(context);
    }

    async fn close_test_websocket(ws: &mut TestServerWebSocket) {
        let _ = ws
            .close(&fcp_async_core::compatibility_cx(), CloseReason::normal())
            .await;
    }

    fn parse_payload(msg: ServerWsMessage) -> GatewayPayload {
        match msg {
            ServerWsMessage::Text(text) => {
                serde_json::from_str(&text).expect("valid gateway payload")
            }
            other => panic!("expected text payload, got {other:?}"),
        }
    }

    fn hello_payload(interval_ms: u64) -> ServerWsMessage {
        let payload = json!({
            "op": GatewayOpcode::Hello as i32,
            "d": { "heartbeat_interval": interval_ms },
            "s": null,
            "t": null,
        });
        ServerWsMessage::Text(serde_json::to_string(&payload).expect("hello payload serializes"))
    }

    fn dispatch_payload(
        event_name: &str,
        sequence: u64,
        data: &serde_json::Value,
    ) -> ServerWsMessage {
        let payload = json!({
            "op": GatewayOpcode::Dispatch as i32,
            "d": data,
            "s": sequence,
            "t": event_name,
        });
        ServerWsMessage::Text(serde_json::to_string(&payload).expect("dispatch payload serializes"))
    }

    fn test_config(gateway_url: String) -> DiscordConfig {
        DiscordConfig {
            bot_credential: "test_token".into(),
            api_url: "https://discord.com/api/v10".into(),
            gateway_url: Some(gateway_url),
            intents: 513,
            gateway_identify_window_ms: 5,
            ..Default::default()
        }
    }

    fn unique_state_path(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        std::env::temp_dir().join(format!(
            "fcp-discord-gateway-{label}-{}-{nanos}.json",
            std::process::id()
        ))
    }

    fn test_checkpoint(label: &str) -> GatewayCheckpoint {
        let state_path = unique_state_path(label);
        let checkpoint = GatewayCheckpoint {
            lease_path: state_path.with_extension("lease.json"),
            state_path,
            holder_instance_id: "gateway-test-holder".into(),
            lease_seq: 1,
            scope: "gateway-test-scope".into(),
        };
        write_json_file_atomic(
            &checkpoint.lease_path,
            &json!({
                "holder_instance_id": checkpoint.holder_instance_id,
                "lease_seq": checkpoint.lease_seq,
                "expires_at": current_unix_timestamp_secs() + 60,
            }),
        )
        .expect("write lease fence");
        checkpoint
    }

    fn delivery_state(
        state: GatewayState,
        checkpoint: Option<GatewayCheckpoint>,
    ) -> Arc<Mutex<GatewayDeliveryState>> {
        Arc::new(Mutex::new(GatewayDeliveryState {
            committed: state,
            checkpoint,
            ..GatewayDeliveryState::default()
        }))
    }

    #[test]
    fn gateway_opcode_try_from_known_values() {
        assert_eq!(GatewayOpcode::try_from(0), Ok(GatewayOpcode::Dispatch));
        assert_eq!(GatewayOpcode::try_from(10), Ok(GatewayOpcode::Hello));
        assert_eq!(GatewayOpcode::try_from(11), Ok(GatewayOpcode::HeartbeatAck));
    }

    #[test]
    fn gateway_opcode_try_from_unknown_is_err() {
        assert!(GatewayOpcode::try_from(42).is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn gateway_send_limiter_waits_when_window_full() {
        let mut limiter = GatewaySendLimiter::new(1, Duration::from_millis(5));
        limiter.wait_for_slot(false).await;
        let full_status = limiter.status();
        assert_eq!(full_status.remaining_events, 0);
        assert_eq!(full_status.current_event_count, 1);

        let started = Instant::now();
        limiter.wait_for_slot(false).await;
        assert!(
            started.elapsed() >= Duration::from_millis(4),
            "second non-critical send should wait for the rate window"
        );

        let drained_status = limiter.status();
        assert_eq!(drained_status.current_event_count, 1);
    }

    #[fcp_async_core::runtime::test]
    async fn gateway_send_limiter_does_not_delay_critical_frames() {
        let mut limiter = GatewaySendLimiter::new(1, Duration::from_millis(50));
        limiter.wait_for_slot(false).await;

        let started = Instant::now();
        limiter.wait_for_slot(true).await;
        assert!(
            started.elapsed() < Duration::from_millis(10),
            "critical heartbeat/identify/resume frames should bypass the send bucket"
        );
        assert_eq!(
            limiter.status().current_event_count,
            1,
            "critical frames should not consume non-critical send quota"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn gateway_identify_limiter_spaces_same_bucket() {
        let limiter = GatewayIdentifyLimiter::new();
        let window = Duration::from_millis(5);
        limiter.wait_for(0, 1, window).await;

        let started = Instant::now();
        limiter.wait_for(0, 1, window).await;
        assert!(
            started.elapsed() >= Duration::from_millis(4),
            "same identify bucket should be spaced by the configured window"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn gateway_identify_limiter_allows_distinct_buckets() {
        let limiter = GatewayIdentifyLimiter::new();
        let window = Duration::from_millis(50);
        limiter.wait_for(0, 2, window).await;

        let started = Instant::now();
        limiter.wait_for(1, 2, window).await;
        assert!(
            started.elapsed() < Duration::from_millis(10),
            "different identify buckets should not block each other"
        );
    }

    #[test]
    fn gateway_identify_params_default_to_safe_single_bucket() {
        let mut config = test_config("ws://127.0.0.1:1".into());
        config.gateway_identify_window_ms = 5_000;
        config.shard = Some(crate::config::ShardConfig {
            shard_id: 7,
            shard_count: 16,
        });

        assert_eq!(
            identify_limiter_params(&config),
            (7, 1, Duration::from_millis(5_000)),
            "shard_count is not Discord gateway max_concurrency; default must serialize IDENTIFY"
        );

        config.gateway_identify_max_concurrency = 4;
        assert_eq!(
            identify_limiter_params(&config),
            (7, 4, Duration::from_millis(5_000))
        );

        // br-x13q4: the window is configuration, so a caller (notably an
        // integration test, which `cfg(test)` never reached) can shorten it.
        config.gateway_identify_window_ms = 5;
        assert_eq!(
            identify_limiter_params(&config),
            (7, 4, Duration::from_millis(5))
        );
    }

    #[test]
    fn dispatch_event_updates_state_on_ready() {
        let mut state = GatewayState::default();
        let data = json!({
            "v": 10,
            "user": { "id": "123", "username": "bot" },
            "session_id": "sess-1",
            "resume_gateway_url": "wss://gateway.discord.gg"
        });

        let event = dispatch_event("READY".to_string(), data, &mut state).unwrap();

        match event {
            GatewayEvent::Ready(ready) => {
                assert_eq!(ready.session_id, "sess-1");
            }
            _ => panic!("expected READY event"),
        }

        assert_eq!(state.session_id.as_deref(), Some("sess-1"));
        assert_eq!(
            state.resume_url.as_deref(),
            Some("wss://gateway.discord.gg")
        );
    }

    #[test]
    fn dispatch_event_maps_message_create() {
        let mut state = GatewayState::default();
        let data = json!({ "id": "msg-1" });

        let event = dispatch_event("MESSAGE_CREATE".to_string(), data.clone(), &mut state).unwrap();

        match event {
            GatewayEvent::MessageCreate(payload) => {
                assert_eq!(payload, data);
            }
            _ => panic!("expected MESSAGE_CREATE event"),
        }
    }

    #[test]
    fn dispatch_event_unknown_passthrough() {
        let mut state = GatewayState::default();
        let data = json!({ "foo": "bar" });

        let event = dispatch_event("SOMETHING_ELSE".to_string(), data.clone(), &mut state).unwrap();

        match event {
            GatewayEvent::Unknown {
                event_name,
                data: payload,
            } => {
                assert_eq!(event_name, "SOMETHING_ELSE");
                assert_eq!(payload, data);
            }
            _ => panic!("expected Unknown event"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn gateway_loop_identifies_emits_events_and_updates_state() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let ws_url = format!("ws://{addr}");

        let server = fcp_async_core::task::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept client");
            let mut ws = accept_test_websocket(socket).await;

            send_message(&mut ws, hello_payload(1_000), "send hello").await;

            let identify = recv_payload(&mut ws, "client identify frame").await;
            assert_eq!(identify.op, GatewayOpcode::Identify as i32);

            send_message(
                &mut ws,
                dispatch_payload(
                    "READY",
                    1,
                    &json!({
                        "v": 10,
                        "user": { "id": "123", "username": "bot" },
                        "session_id": "sess-identify",
                        "resume_gateway_url": "wss://gateway.discord.gg"
                    }),
                ),
                "send ready",
            )
            .await;

            send_message(
                &mut ws,
                dispatch_payload(
                    "MESSAGE_CREATE",
                    2,
                    &json!({ "id": "msg-1", "content": "hello" }),
                ),
                "send message create",
            )
            .await;

            close_test_websocket(&mut ws).await;
        });

        let client_ws = connect_gateway_websocket(&ws_url)
            .await
            .expect("connect websocket");
        let (event_tx, mut event_rx) = mpsc::channel(8);
        let mut state = GatewayState::default();
        let delivery = delivery_state(state.clone(), None);

        Box::pin(run_gateway_loop_inner(
            client_ws,
            test_config(ws_url),
            &event_tx,
            &mut state,
            &delivery,
            0,
            &AtomicBool::new(false),
        ))
        .await
        .expect("gateway loop success");

        let ready = event_rx.recv().await.expect("ready event");
        assert_eq!(delivery.lock().await.committed.sequence, None);
        ready.acknowledge().await.expect("acknowledge ready");
        match ready {
            GatewayEventFrame {
                seq: Some(1),
                event: GatewayEvent::Ready(ready),
                ..
            } => assert_eq!(ready.session_id, "sess-identify"),
            other => panic!("expected Ready event with seq=1, got {other:?}"),
        }

        let message = event_rx.recv().await.expect("message create event");
        assert_eq!(delivery.lock().await.committed.sequence, Some(1));
        message.acknowledge().await.expect("acknowledge message");
        match message {
            GatewayEventFrame {
                seq: Some(2),
                event: GatewayEvent::MessageCreate(message),
                ..
            } => assert_eq!(message["id"], "msg-1"),
            other => panic!("expected MessageCreate event with seq=2, got {other:?}"),
        }

        assert_eq!(state.session_id.as_deref(), Some("sess-identify"));
        assert_eq!(
            state.resume_url.as_deref(),
            Some("wss://gateway.discord.gg/")
        );
        assert_eq!(
            state.sequence, None,
            "received dispatches must not mutate the resume snapshot"
        );
        assert_eq!(delivery.lock().await.committed.sequence, Some(2));

        server.await.expect("server task should complete");
    }

    #[fcp_async_core::runtime::test]
    async fn gateway_loop_uses_resume_when_session_state_is_complete() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let ws_url = format!("ws://{addr}");

        let server = fcp_async_core::task::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept client");
            let mut ws = accept_test_websocket(socket).await;

            send_message(&mut ws, hello_payload(1_000), "send hello").await;

            let resume = recv_payload(&mut ws, "client resume frame").await;
            assert_eq!(resume.op, GatewayOpcode::Resume as i32);
            let payload = resume.d.expect("resume payload");
            assert_eq!(payload["session_id"], "sess-resume");
            assert_eq!(payload["seq"], 7);

            send_message(
                &mut ws,
                dispatch_payload("RESUMED", 8, &json!({})),
                "send resumed",
            )
            .await;
            close_test_websocket(&mut ws).await;
        });

        let client_ws = connect_gateway_websocket(&ws_url)
            .await
            .expect("connect websocket");
        let (event_tx, mut event_rx) = mpsc::channel(8);
        let mut state = GatewayState {
            session_id: Some("sess-resume".into()),
            resume_url: Some("wss://gateway.discord.gg".into()),
            sequence: Some(7),
            ..GatewayState::default()
        };
        let delivery = delivery_state(state.clone(), None);

        Box::pin(run_gateway_loop_inner(
            client_ws,
            test_config(ws_url),
            &event_tx,
            &mut state,
            &delivery,
            0,
            &AtomicBool::new(false),
        ))
        .await
        .expect("gateway loop success");

        let resumed = event_rx.recv().await.expect("resumed event");
        assert_eq!(delivery.lock().await.committed.sequence, Some(7));
        resumed.acknowledge().await.expect("acknowledge resumed");
        match resumed {
            GatewayEventFrame {
                seq: Some(8),
                event: GatewayEvent::Resumed,
                ..
            } => {}
            other => panic!("expected Resumed event with seq=8, got {other:?}"),
        }
        assert_eq!(state.sequence, Some(7));
        assert_eq!(delivery.lock().await.committed.sequence, Some(8));

        server.await.expect("server task should complete");
    }

    #[fcp_async_core::runtime::test]
    async fn gateway_loop_does_not_skip_malformed_dispatch_frames() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let ws_url = format!("ws://{addr}");

        let server = fcp_async_core::task::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept client");
            let mut ws = accept_test_websocket(socket).await;

            send_message(&mut ws, hello_payload(1_000), "send hello").await;
            let _ = recv_message(&mut ws, "identify frame").await;

            send_message(
                &mut ws,
                ServerWsMessage::Text("{ this is not json".into()),
                "send malformed frame",
            )
            .await;
            close_test_websocket(&mut ws).await;
        });

        let client_ws = connect_gateway_websocket(&ws_url)
            .await
            .expect("connect websocket");
        let (event_tx, mut event_rx) = mpsc::channel(8);
        let mut state = GatewayState::default();
        let delivery = delivery_state(state.clone(), None);

        Box::pin(run_gateway_loop_inner(
            client_ws,
            test_config(ws_url),
            &event_tx,
            &mut state,
            &delivery,
            0,
            &AtomicBool::new(false),
        ))
        .await
        .expect_err("malformed history must reconnect without skipping a dispatch");
        assert!(event_rx.try_recv().is_err());
        assert_eq!(delivery.lock().await.committed.sequence, None);

        server.await.expect("server task should complete");
    }

    #[test]
    fn gateway_loop_rejects_incomplete_resume_state() {
        let state = GatewayState {
            session_id: Some("sess-incomplete".into()),
            resume_url: Some("wss://stale.gateway.discord.gg".into()),
            sequence: None,
            ..GatewayState::default()
        };
        let error = validate_resume_state(&state)
            .expect_err("must not identify after an uncommitted READY");
        assert!(!error.is_retryable());
        assert_eq!(state.session_id.as_deref(), Some("sess-incomplete"));
        assert_eq!(state.sequence, None);
    }

    #[fcp_async_core::runtime::test]
    async fn gateway_connection_enforces_single_active_connection() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let ws_url = format!("ws://{addr}");

        let server = fcp_async_core::task::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept client");
            let mut ws = accept_test_websocket(socket).await;

            send_message(&mut ws, hello_payload(1_000), "send hello").await;
            let _ = recv_message(&mut ws, "identify frame").await;

            sleep(Duration::from_millis(50)).await;
            close_test_websocket(&mut ws).await;
        });

        let config = test_config(ws_url);
        let api_client = Arc::new(DiscordApiClient::new(&config).expect("create api client"));
        let connection = GatewayConnection::new(config, api_client);

        let stream = connection
            .connect_once()
            .await
            .expect("first connection should succeed");

        let second_attempt = connection.connect_once().await;
        assert!(second_attempt.is_err());
        match second_attempt.unwrap_err() {
            DiscordError::Gateway(message) => {
                assert!(message.contains("already active"));
            }
            other => panic!("expected gateway error, got {other:?}"),
        }

        let _ = stream.join_handle.await.expect("gateway loop task join");
        server.await.expect("server task should complete");
    }

    #[fcp_async_core::runtime::test]
    async fn gateway_connection_persists_resume_state_to_disk() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let ws_url = format!("ws://{addr}");
        let checkpoint = test_checkpoint("persist");
        let state_path = checkpoint.state_path.clone();

        let server = fcp_async_core::task::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept client");
            let mut ws = accept_test_websocket(socket).await;
            send_message(&mut ws, hello_payload(1_000), "send hello").await;
            let _ = recv_message(&mut ws, "identify frame").await;

            send_message(
                &mut ws,
                dispatch_payload(
                    "READY",
                    1,
                    &json!({
                        "v": 10,
                        "user": { "id": "321", "username": "persist-bot" },
                        "session_id": "sess-persist",
                        "resume_gateway_url": "wss://gateway.discord.gg"
                    }),
                ),
                "send ready",
            )
            .await;
            send_message(
                &mut ws,
                dispatch_payload("MESSAGE_CREATE", 2, &json!({ "id": "msg-persist" })),
                "send message",
            )
            .await;
            close_test_websocket(&mut ws).await;
        });

        let config = test_config(ws_url);
        let api_client = Arc::new(DiscordApiClient::new(&config).expect("create api client"));
        let connection = GatewayConnection::new(config, api_client);
        let mut stream = connection
            .connect_once_with_checkpoint(Some(checkpoint))
            .await
            .expect("connect with state path");

        let ready = stream.events.recv().await.expect("ready event");
        ready.acknowledge().await.expect("acknowledge ready");
        let message = stream.events.recv().await.expect("message event");
        let observed = read_json_file_if_exists::<GatewayStateRecord>(&state_path)
            .expect("state file read")
            .expect("state file exists");
        assert_eq!(observed.sequence, Some(1));
        message.acknowledge().await.expect("acknowledge message");
        stream
            .join_handle
            .await
            .expect("join")
            .expect("loop success");
        server.await.expect("server task");

        let persisted = read_json_file_if_exists::<GatewayStateRecord>(&state_path)
            .expect("state file read")
            .expect("state file exists");
        assert_eq!(persisted.session_id.as_deref(), Some("sess-persist"));
        assert_eq!(persisted.sequence, Some(2));
        assert_eq!(persisted.version, GATEWAY_STATE_VERSION);
        let _ = fs::remove_file(state_path);
    }

    #[fcp_async_core::runtime::test]
    async fn gateway_connection_loads_persisted_state_and_resumes() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let ws_url = format!("ws://{addr}");
        let checkpoint = test_checkpoint("resume");
        let state_path = checkpoint.state_path.clone();
        write_json_file_atomic(
            &state_path,
            &GatewayStateRecord {
                version: GATEWAY_STATE_VERSION,
                scope: checkpoint.scope.clone(),
                lease_seq: checkpoint.lease_seq,
                session_id: Some("sess-resume-file".into()),
                resume_url: Some(ws_url.clone()),
                sequence: Some(7),
                updated_at: current_unix_timestamp_secs(),
                ..GatewayStateRecord::default()
            },
        )
        .expect("write persisted state");

        let server = fcp_async_core::task::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept client");
            let mut ws = accept_test_websocket(socket).await;
            send_message(&mut ws, hello_payload(1_000), "send hello").await;

            let resume = recv_payload(&mut ws, "client resume frame").await;
            assert_eq!(resume.op, GatewayOpcode::Resume as i32);
            let payload = resume.d.expect("resume payload");
            assert_eq!(payload["session_id"], "sess-resume-file");
            assert_eq!(payload["seq"], 7);

            send_message(
                &mut ws,
                dispatch_payload("RESUMED", 8, &json!({})),
                "send resumed",
            )
            .await;
            close_test_websocket(&mut ws).await;
        });

        let config = test_config(ws_url);
        let api_client = Arc::new(DiscordApiClient::new(&config).expect("create api client"));
        let connection = GatewayConnection::new(config, api_client);
        let mut stream = connection
            .connect_once_with_checkpoint(Some(checkpoint))
            .await
            .expect("connect with persisted state");

        let resumed = stream.events.recv().await.expect("resumed event");
        resumed.acknowledge().await.expect("acknowledge resumed");
        match resumed {
            GatewayEventFrame {
                seq: Some(8),
                event: GatewayEvent::Resumed,
                ..
            } => {}
            other => panic!("expected Resumed event with seq=8, got {other:?}"),
        }
        stream
            .join_handle
            .await
            .expect("join")
            .expect("loop success");
        server.await.expect("server task");

        let persisted = read_json_file_if_exists::<GatewayStateRecord>(&state_path)
            .expect("state file read")
            .expect("state file exists");
        assert_eq!(persisted.sequence, Some(8));
        let _ = fs::remove_file(state_path);
    }

    #[fcp_async_core::runtime::test]
    async fn gateway_connection_fails_closed_on_incomplete_persisted_state() {
        let checkpoint = test_checkpoint("fail-closed");
        let state_path = checkpoint.state_path.clone();
        write_json_file_atomic(
            &state_path,
            &GatewayStateRecord {
                version: GATEWAY_STATE_VERSION,
                scope: checkpoint.scope.clone(),
                lease_seq: checkpoint.lease_seq,
                session_id: Some("sess-incomplete".into()),
                resume_url: Some("wss://stale.gateway.discord.gg".into()),
                sequence: None,
                updated_at: current_unix_timestamp_secs(),
                ..GatewayStateRecord::default()
            },
        )
        .expect("write persisted state");

        let original = fs::read(&state_path).expect("checkpoint bytes");
        let config = test_config("ws://127.0.0.1:1".into());
        let api_client = Arc::new(DiscordApiClient::new(&config).expect("create api client"));
        let connection = GatewayConnection::new(config, api_client);
        let error = connection
            .connect_once_with_checkpoint(Some(checkpoint.clone()))
            .await
            .expect_err("must fail before connecting or identifying");
        assert!(!error.is_retryable());
        let error = connection
            .connect_once_with_checkpoint(Some(checkpoint))
            .await
            .expect_err("failure must release the active-connection guard");
        assert!(!error.is_retryable());
        assert_eq!(fs::read(&state_path).expect("unchanged bytes"), original);

        let persisted = read_json_file_if_exists::<GatewayStateRecord>(&state_path)
            .expect("state file read")
            .expect("state file exists");
        assert_eq!(persisted.session_id.as_deref(), Some("sess-incomplete"));
        assert_eq!(persisted.sequence, None);
        let _ = fs::remove_file(state_path);
    }

    fn acknowledged_test_session() -> GatewayState {
        GatewayState {
            session_id: Some("private-session-identity".into()),
            resume_url: Some("wss://gateway.discord.gg".into()),
            sequence: Some(1),
            ..GatewayState::default()
        }
    }

    #[fcp_async_core::runtime::test]
    async fn gateway_acknowledgements_are_ordered_and_generation_bound() {
        let state = acknowledged_test_session();
        let delivery = delivery_state(state.clone(), None);
        let (tx, mut rx) = mpsc::channel(8);
        for sequence in [2, 3] {
            queue_dispatch(
                &tx,
                &state,
                GatewayEvent::Resumed,
                sequence,
                40,
                &delivery,
                0,
            )
            .await
            .expect("queue dispatch");
        }
        let first = rx.recv().await.expect("first");
        let second = rx.recv().await.expect("second");
        assert!(!first.cursor().unwrap().contains("private-session-identity"));
        assert_eq!(
            first.cursor(),
            Some(dispatch_cursor("private-session-identity", 2).as_str())
        );
        assert_ne!(first.cursor(), second.cursor());
        second
            .acknowledge()
            .await
            .expect_err("cannot skip pending first event");
        assert_eq!(delivery.lock().await.committed.sequence, Some(1));
        first.acknowledge().await.expect("first acknowledged");
        second.acknowledge().await.expect("second acknowledged");
        assert_eq!(delivery.lock().await.committed.sequence, Some(3));
        queue_dispatch(&tx, &state, GatewayEvent::Resumed, 4, 40, &delivery, 0)
            .await
            .expect("queue stale generation frame");
        let stale = rx.recv().await.expect("stale frame");
        delivery.lock().await.generation = 1;
        stale
            .acknowledge()
            .await
            .expect_err("old connection cannot commit");
        assert_eq!(delivery.lock().await.committed.sequence, Some(3));
    }

    #[fcp_async_core::runtime::test]
    async fn gateway_pending_buffer_is_bounded_until_acknowledgement() {
        let state = acknowledged_test_session();
        let delivery = delivery_state(state.clone(), None);
        let (tx, mut rx) = mpsc::channel(GATEWAY_EVENT_BUFFER_CAPACITY);
        for index in 0..GATEWAY_EVENT_BUFFER_CAPACITY {
            queue_dispatch(
                &tx,
                &state,
                GatewayEvent::Resumed,
                index as u64 + 2,
                1,
                &delivery,
                0,
            )
            .await
            .expect("queue within count budget");
            let _unacknowledged = rx.recv().await.expect("drain transport without ACK");
        }
        queue_dispatch(&tx, &state, GatewayEvent::Resumed, 999, 1, &delivery, 0)
            .await
            .expect_err("receiving a frame does not free pending capacity");
        assert_eq!(delivery.lock().await.committed.sequence, Some(1));
        assert_eq!(
            delivery.lock().await.pending.len(),
            GATEWAY_EVENT_BUFFER_CAPACITY
        );

        let delivery = delivery_state(state.clone(), None);
        for index in 0..(GATEWAY_PENDING_MAX_BYTES / GATEWAY_FRAME_MAX_BYTES) {
            queue_dispatch(
                &tx,
                &state,
                GatewayEvent::Resumed,
                index as u64 + 2,
                GATEWAY_FRAME_MAX_BYTES,
                &delivery,
                0,
            )
            .await
            .expect("queue within byte budget");
            let _unacknowledged = rx.recv().await.expect("drain byte-budget frame");
        }
        queue_dispatch(&tx, &state, GatewayEvent::Resumed, 999, 1, &delivery, 0)
            .await
            .expect_err("cumulative bytes must be bounded below the count limit");
        assert_eq!(
            delivery.lock().await.pending_bytes,
            GATEWAY_PENDING_MAX_BYTES
        );
        assert_eq!(delivery.lock().await.committed.sequence, Some(1));
    }

    #[fcp_async_core::runtime::test]
    async fn gateway_failed_or_stale_checkpoint_commit_keeps_pending_progress() {
        let checkpoint = test_checkpoint("ack-fence");
        let state = acknowledged_test_session();
        persist_checkpoint(Some(&checkpoint), &state).expect("initial checkpoint");
        let original = fs::read(&checkpoint.state_path).expect("checkpoint bytes");
        let delivery = delivery_state(state.clone(), Some(checkpoint.clone()));
        let (tx, mut rx) = mpsc::channel(8);
        queue_dispatch(&tx, &state, GatewayEvent::Resumed, 2, 40, &delivery, 0)
            .await
            .expect("queue dispatch");
        let frame = rx.recv().await.expect("pending frame");
        let lock = lock_gateway_lease(&checkpoint.lease_path).expect("concurrent lease writer");
        frame
            .acknowledge()
            .await
            .expect_err("commit must not bypass shared lock");
        assert_eq!(delivery.lock().await.committed.sequence, Some(1));
        assert_eq!(delivery.lock().await.pending.len(), 1);
        assert_eq!(fs::read(&checkpoint.state_path).unwrap(), original);
        drop(lock);

        write_json_file_atomic(
            &checkpoint.lease_path,
            &json!({
                "holder_instance_id": "new-lease-holder", "lease_seq": 2,
                "expires_at": current_unix_timestamp_secs() + 60,
            }),
        )
        .expect("replace lease after handoff");
        frame
            .acknowledge()
            .await
            .expect_err("former owner cannot advance checkpoint");
        assert_eq!(delivery.lock().await.committed.sequence, Some(1));
        assert_eq!(delivery.lock().await.pending.len(), 1);
        assert_eq!(fs::read(&checkpoint.state_path).unwrap(), original);
    }

    #[test]
    fn gateway_checkpoint_rejects_legacy_scope_mismatch_and_oversized_state() {
        let checkpoint = test_checkpoint("checkpoint-validation");
        let mut record = acknowledged_test_session().to_record(&checkpoint);
        for version in [0, 1, 99] {
            record.version = version;
            write_json_file_atomic(&checkpoint.state_path, &record).expect("write old version");
            let original = fs::read(&checkpoint.state_path).unwrap();
            let error =
                load_checkpoint(&checkpoint).expect_err("only consumer-committed v2 is valid");
            assert!(!error.is_retryable());
            assert_eq!(fs::read(&checkpoint.state_path).unwrap(), original);
        }
        record.version = GATEWAY_STATE_VERSION;
        record.scope = "different-subscription-policy".into();
        write_json_file_atomic(&checkpoint.state_path, &record).expect("write different scope");
        assert!(
            !load_checkpoint(&checkpoint)
                .expect_err("scope mismatch")
                .is_retryable()
        );
        fs::write(
            &checkpoint.state_path,
            vec![b' '; GATEWAY_STATE_MAX_BYTES as usize + 1],
        )
        .expect("write oversized fixture");
        assert!(
            !load_checkpoint(&checkpoint)
                .expect_err("bounded state read")
                .is_retryable()
        );
    }

    #[fcp_async_core::runtime::test]
    async fn gateway_invalid_session_persists_recovery_requirement_without_acknowledging() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let ws_url = format!("ws://{}", listener.local_addr().unwrap());
        let checkpoint = test_checkpoint("invalid-session");
        let state = acknowledged_test_session();
        persist_checkpoint(Some(&checkpoint), &state).expect("initial checkpoint");
        let delivery = delivery_state(state.clone(), Some(checkpoint.clone()));
        let server = fcp_async_core::task::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept client");
            let mut ws = accept_test_websocket(socket).await;
            send_message(&mut ws, hello_payload(1_000), "hello").await;
            assert_eq!(
                recv_payload(&mut ws, "resume").await.op,
                GatewayOpcode::Resume as i32
            );
            send_message(
                &mut ws,
                dispatch_payload("MESSAGE_CREATE", 2, &json!({"id":"pending"})),
                "pending message",
            )
            .await;
            send_message(
                &mut ws,
                ServerWsMessage::Text(json!({"op":9,"d":false}).to_string()),
                "invalidated session",
            )
            .await;
            close_test_websocket(&mut ws).await;
        });
        let socket = connect_gateway_websocket(&ws_url).await.expect("connect");
        let (tx, mut rx) = mpsc::channel(8);
        let error = run_gateway_loop(
            socket,
            test_config(ws_url),
            tx,
            state,
            Arc::clone(&delivery),
            0,
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .expect_err("unavailable replay must stop recovery");
        assert!(!error.is_retryable());
        let pending = rx.recv().await.expect("pending event");
        pending
            .acknowledge()
            .await
            .expect_err("invalidated session cannot commit");
        let persisted = load_checkpoint(&checkpoint).unwrap().unwrap();
        assert_eq!(persisted.sequence, Some(1));
        assert!(persisted.resume_invalidated);
        assert!(
            !validate_resume_state(&persisted)
                .expect_err("must never IDENTIFY automatically")
                .is_retryable()
        );
        assert!(delivery.lock().await.recovery_reason.is_some());
        server.await.expect("server task");
    }

    #[fcp_async_core::runtime::test]
    async fn gateway_failed_invalidation_write_still_fences_pending_acknowledgements() {
        let checkpoint = test_checkpoint("invalid-session-write-failure");
        let state = acknowledged_test_session();
        persist_checkpoint(Some(&checkpoint), &state).expect("initial checkpoint");
        let original = fs::read(&checkpoint.state_path).unwrap();
        let delivery = delivery_state(state.clone(), Some(checkpoint.clone()));
        let (tx, mut rx) = mpsc::channel(8);
        queue_dispatch(&tx, &state, GatewayEvent::Resumed, 2, 40, &delivery, 0)
            .await
            .expect("pending dispatch");
        let frame = rx.recv().await.expect("pending frame");
        let lock = lock_gateway_lease(&checkpoint.lease_path).expect("block marker write");
        let error = invalidate_resume(&delivery, "the provider can no longer replay this session")
            .await
            .expect_err("invalidated session is terminal");
        assert!(
            !error.is_retryable(),
            "write failure must not permit another session attempt"
        );
        drop(lock);
        assert!(
            !frame
                .acknowledge()
                .await
                .expect_err("late ACK cannot clear invalidation")
                .is_retryable()
        );
        let delivery = delivery.lock().await;
        assert_eq!(delivery.committed.sequence, Some(1));
        assert!(delivery.committed.resume_invalidated);
        assert!(delivery.recovery_reason.is_some());
        assert_eq!(fs::read(&checkpoint.state_path).unwrap(), original);
    }
}

impl TryFrom<i32> for GatewayOpcode {
    type Error = ();

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Dispatch),
            1 => Ok(Self::Heartbeat),
            2 => Ok(Self::Identify),
            3 => Ok(Self::PresenceUpdate),
            4 => Ok(Self::VoiceStateUpdate),
            6 => Ok(Self::Resume),
            7 => Ok(Self::Reconnect),
            8 => Ok(Self::RequestGuildMembers),
            9 => Ok(Self::InvalidSession),
            10 => Ok(Self::Hello),
            11 => Ok(Self::HeartbeatAck),
            _ => Err(()),
        }
    }
}

/// A gateway event received from Discord.
#[derive(Debug, Clone)]
pub enum GatewayEvent {
    /// Ready event - we're connected.
    Ready(GatewayReady),
    /// Resumed event - session successfully resumed.
    Resumed,
    /// Message created.
    MessageCreate(serde_json::Value),
    /// Message updated.
    MessageUpdate(serde_json::Value),
    /// Message deleted.
    MessageDelete(serde_json::Value),
    /// Guild created (we joined or became available).
    GuildCreate(serde_json::Value),
    /// Guild updated.
    GuildUpdate(serde_json::Value),
    /// Channel created.
    ChannelCreate(serde_json::Value),
    /// Channel updated.
    ChannelUpdate(serde_json::Value),
    /// Typing started.
    TypingStart(serde_json::Value),
    /// Unknown or unhandled event.
    Unknown {
        event_name: String,
        data: serde_json::Value,
    },
}

/// A gateway event plus the sequence observed on the dispatch frame.
#[derive(Clone, Debug)]
pub struct GatewayEventFrame {
    /// Discord gateway dispatch sequence.
    pub seq: Option<u64>,
    /// Parsed event payload.
    pub event: GatewayEvent,
    /// Authoritative acknowledgement handle; diagnostic envelopes never carry it.
    pub acknowledgement: Option<GatewayAcknowledgement>,
}

impl GatewayEventFrame {
    /// Stable opaque cursor across RESUME and process restart in this session.
    #[must_use]
    pub fn cursor(&self) -> Option<&str> {
        self.acknowledgement.as_ref().map(|ack| ack.cursor.as_str())
    }

    /// Commit this dispatch only after accepted downstream delivery or an
    /// authorized policy decision to discard it.
    ///
    /// # Errors
    /// Rejects missing authority, out-of-order or stale acknowledgements,
    /// expired/stale leases, and checkpoint persistence failures.
    pub async fn acknowledge(&self) -> DiscordResult<()> {
        self.acknowledgement
            .as_ref()
            .ok_or_else(|| gateway_failure("Gateway frame has no acknowledgement authority"))?
            .acknowledge()
            .await
    }
}

/// A fenced durable checkpoint owned by the connector's singleton lease.
#[derive(Clone, Debug)]
pub(crate) struct GatewayCheckpoint {
    pub state_path: PathBuf,
    pub lease_path: PathBuf,
    pub holder_instance_id: String,
    pub lease_seq: u64,
    pub scope: String,
}

#[derive(Clone, Debug)]
struct PendingDispatch {
    sequence: u64,
    session_id: String,
    resume_url: String,
    bytes: usize,
}

#[derive(Default)]
struct GatewayDeliveryState {
    committed: GatewayState,
    checkpoint: Option<GatewayCheckpoint>,
    generation: u64,
    pending: VecDeque<PendingDispatch>,
    pending_bytes: usize,
    recovery_reason: Option<String>,
}

/// An ordered acknowledgement bound to one Gateway connection generation.
#[derive(Clone)]
pub struct GatewayAcknowledgement {
    state: Arc<Mutex<GatewayDeliveryState>>,
    generation: u64,
    sequence: u64,
    session_id: String,
    cursor: String,
}

impl std::fmt::Debug for GatewayAcknowledgement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayAcknowledgement")
            .field("generation", &self.generation)
            .field("sequence", &self.sequence)
            .field("cursor", &self.cursor)
            .finish_non_exhaustive()
    }
}

impl GatewayAcknowledgement {
    async fn acknowledge(&self) -> DiscordResult<()> {
        let mut state = self.state.lock().await;
        if let Some(reason) = &state.recovery_reason {
            return Err(recovery_required(reason));
        }
        if state.generation != self.generation {
            return Err(gateway_failure(
                "Gateway acknowledgement belongs to a retired connection",
            ));
        }
        let pending = state
            .pending
            .front()
            .ok_or_else(|| gateway_failure("Gateway acknowledgement has no pending dispatch"))?;
        if pending.sequence != self.sequence || pending.session_id != self.session_id {
            return Err(gateway_failure(
                "Gateway acknowledgements must commit in dispatch order",
            ));
        }
        let candidate = GatewayState {
            session_id: Some(pending.session_id.clone()),
            resume_url: Some(pending.resume_url.clone()),
            sequence: Some(self.sequence),
            resume_invalidated: false,
        };
        if state.committed.resume_invalidated {
            return Err(gateway_failure(
                "Discord invalidated this resume session; reconcile before restarting",
            ));
        }
        let already_committed = state.committed.session_id == candidate.session_id
            && state
                .committed
                .sequence
                .is_some_and(|sequence| sequence >= self.sequence);
        if !already_committed {
            persist_checkpoint(state.checkpoint.as_ref(), &candidate)?;
            // No in-memory advancement is visible before durable persistence.
            state.committed = candidate;
        }
        let committed = state
            .pending
            .pop_front()
            .expect("pending dispatch checked above");
        state.pending_bytes = state.pending_bytes.saturating_sub(committed.bytes);
        Ok(())
    }
}

fn gateway_failure(message: impl Into<String>) -> DiscordError {
    DiscordError::Gateway(message.into())
}

fn recovery_required(message: &str) -> DiscordError {
    DiscordError::InvalidInput(format!(
        "Discord Gateway recovery required: {message}; reconcile unavailable events before using a new zone directory"
    ))
}

fn dispatch_cursor(session_id: &str, sequence: u64) -> String {
    let mut hash = Sha256::new();
    hash.update(b"fcp.discord.gateway.cursor.v2\0");
    hash.update(session_id.as_bytes());
    hash.update([0]);
    hash.update(sequence.to_be_bytes());
    format!("discord:{}", hex::encode(hash.finalize()))
}

struct GatewayActivityGuard(Arc<AtomicBool>);

impl Drop for GatewayActivityGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// Discord Gateway connection.
pub struct GatewayConnection {
    config: DiscordConfig,
    api_client: Arc<DiscordApiClient>,
    state: Arc<Mutex<GatewayDeliveryState>>,
    active_connection: Arc<AtomicBool>,
    shutdown_requested: Arc<AtomicBool>,
}

impl GatewayConnection {
    /// Create a new gateway connection.
    pub fn new(config: DiscordConfig, api_client: Arc<DiscordApiClient>) -> Self {
        Self {
            config,
            api_client,
            state: Arc::new(Mutex::new(GatewayDeliveryState::default())),
            active_connection: Arc::new(AtomicBool::new(false)),
            shutdown_requested: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Connect to the gateway once and return the event stream handle.
    /// If we have a previous session, will attempt to resume.
    ///
    /// # Errors
    /// Rejects concurrent connections and unsafe resume state, or returns the
    /// provider connection error.
    #[instrument(skip(self))]
    pub async fn connect_once(&self) -> DiscordResult<GatewayStream> {
        self.connect_once_with_checkpoint(None).await
    }

    /// Connect to the gateway once with optional persisted gateway state.
    #[instrument(skip(self))]
    pub(crate) async fn connect_once_with_checkpoint(
        &self,
        checkpoint: Option<GatewayCheckpoint>,
    ) -> DiscordResult<GatewayStream> {
        if self
            .active_connection
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(DiscordError::Gateway(
                "Gateway connection already active".into(),
            ));
        }
        let activity = GatewayActivityGuard(Arc::clone(&self.active_connection));
        self.shutdown_requested.store(false, Ordering::Release);

        let (event_tx, event_rx) = mpsc::channel(GATEWAY_EVENT_BUFFER_CAPACITY);

        let config = self.config.clone();
        let api_client = self.api_client.clone();
        let state_store = Arc::clone(&self.state);
        let (state_snapshot, generation) = {
            let mut state = state_store.lock().await;
            if let Some(reason) = &state.recovery_reason {
                return Err(recovery_required(reason));
            }
            if let (Some(old), Some(new)) = (&state.checkpoint, &checkpoint)
                && old.scope != new.scope
            {
                return Err(recovery_required("Gateway checkpoint scope changed"));
            }
            let snapshot = match checkpoint.as_ref() {
                Some(checkpoint) => {
                    load_checkpoint(checkpoint)?.unwrap_or_else(|| state.committed.clone())
                }
                None => state.committed.clone(),
            };
            validate_resume_state(&snapshot)?;
            state.generation = state
                .generation
                .checked_add(1)
                .ok_or_else(|| gateway_failure("Gateway connection generation exhausted"))?;
            state.pending.clear();
            state.pending_bytes = 0;
            state.checkpoint = checkpoint;
            state.committed = snapshot.clone();
            (snapshot, state.generation)
        };

        // Determine gateway URL
        let gateway_url = if let Some(ref url) = state_snapshot.resume_url {
            url.clone()
        } else if let Some(url) = &config.gateway_url {
            url.clone()
        } else {
            match gateway_operation(
                api_client.get_gateway(),
                &self.shutdown_requested,
                Duration::from_secs(30),
            )
            .await?
            {
                Ok(url) => url,
                Err(e) => {
                    return Err(e);
                }
            }
        };

        // Discovery and persisted resume metadata are untrusted routing input.
        // Validate before opening a socket that will receive the bot credential.
        let mut ws_url = config.validate_gateway_url(&gateway_url)?;
        ws_url
            .query_pairs_mut()
            .append_pair("v", "10")
            .append_pair("encoding", "json");
        info!(
            resuming = state_snapshot.session_id.is_some(),
            "Connecting to Discord gateway"
        );

        let ws_stream = match gateway_operation(
            connect_gateway_websocket(ws_url.as_str()),
            &self.shutdown_requested,
            Duration::from_secs(30),
        )
        .await?
        {
            Ok(stream) => stream,
            Err(e) => {
                return Err(DiscordError::Gateway(format!("Failed to connect WS: {e}")));
            }
        };

        let shutdown_requested = Arc::clone(&self.shutdown_requested);
        let join_handle = fcp_async_core::task::spawn(async move {
            let _activity = activity;
            let result = Box::pin(run_gateway_loop(
                ws_stream,
                config,
                event_tx,
                state_snapshot,
                state_store,
                generation,
                shutdown_requested,
            ))
            .await;
            result.map_err(|error| Box::new(error) as StreamingError)
        });

        Ok(GatewayStream {
            events: event_rx,
            join_handle,
        })
    }

    /// Signal the actual socket worker and wait for bounded drain before lease release.
    ///
    /// # Errors
    /// Returns an error if the socket worker does not stop within two seconds.
    pub async fn stop_active(&self) -> DiscordResult<()> {
        self.shutdown_requested.store(true, Ordering::Release);
        fcp_async_core::time::timeout(Duration::from_secs(2), async {
            while self.active_connection.load(Ordering::Acquire) {
                fcp_async_core::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| gateway_failure("Discord Gateway worker is still draining"))
    }
}

#[derive(Clone, Debug, Default)]
struct GatewayState {
    session_id: Option<String>,
    resume_url: Option<String>,
    sequence: Option<u64>,
    resume_invalidated: bool,
}

impl GatewayState {
    fn from_record(record: GatewayStateRecord) -> Self {
        Self {
            session_id: record.session_id,
            resume_url: record.resume_url,
            sequence: record.sequence,
            resume_invalidated: record.resume_invalidated,
        }
    }

    fn to_record(&self, checkpoint: &GatewayCheckpoint) -> GatewayStateRecord {
        GatewayStateRecord {
            version: GATEWAY_STATE_VERSION,
            scope: checkpoint.scope.clone(),
            lease_seq: checkpoint.lease_seq,
            session_id: self.session_id.clone(),
            resume_url: self.resume_url.clone(),
            sequence: self.sequence,
            resume_invalidated: self.resume_invalidated,
            updated_at: current_unix_timestamp_secs(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct GatewayStateRecord {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    scope: String,
    #[serde(default)]
    lease_seq: u64,
    session_id: Option<String>,
    resume_url: Option<String>,
    sequence: Option<u64>,
    #[serde(default)]
    resume_invalidated: bool,
    updated_at: u64,
}

fn current_unix_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn write_json_file_atomic<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let tmp_path = path.with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
    let payload = serde_json::to_vec(value).map_err(io::Error::other)?;
    if payload.len() as u64 > GATEWAY_STATE_MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Gateway state exceeds its byte limit",
        ));
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut temporary = options.open(&tmp_path)?;
    temporary.write_all(&payload)?;
    temporary.sync_all()?;
    drop(temporary);
    fs::rename(&tmp_path, path)?;
    #[cfg(unix)]
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn read_json_file_if_exists<T>(path: &Path) -> io::Result<Option<T>>
where
    T: for<'de> Deserialize<'de>,
{
    match File::open(path) {
        Ok(file) => {
            if file.metadata()?.len() > GATEWAY_STATE_MAX_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Gateway state exceeds its byte limit",
                ));
            }
            let mut bytes = Vec::new();
            file.take(GATEWAY_STATE_MAX_BYTES + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() as u64 > GATEWAY_STATE_MAX_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Gateway state exceeds its byte limit",
                ));
            }
            let value = serde_json::from_slice::<T>(&bytes).map_err(io::Error::other)?;
            Ok(Some(value))
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

/// Lock the stable sidecar shared by lease transitions and checkpoint writes.
/// The sidecar must never be unlinked while a zone directory is in use.
pub(crate) fn lock_gateway_lease(path: &Path) -> io::Result<File> {
    if let Some(parent) = path.parent().filter(|path| !path.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock = options.open(path.with_extension("lock"))?;
    lock.try_lock().map_err(|error| match error {
        fs::TryLockError::WouldBlock => io::Error::new(
            io::ErrorKind::WouldBlock,
            "Gateway lease/checkpoint update is in progress",
        ),
        fs::TryLockError::Error(error) => error,
    })?;
    Ok(lock)
}

#[derive(Deserialize)]
struct GatewayLeaseFence {
    holder_instance_id: String,
    lease_seq: u64,
    expires_at: u64,
}

fn verify_checkpoint_lease(checkpoint: &GatewayCheckpoint) -> DiscordResult<()> {
    let lease = read_json_file_if_exists::<GatewayLeaseFence>(&checkpoint.lease_path)
        .map_err(|error| gateway_failure(format!("Cannot read Gateway lease fence: {error}")))?
        .ok_or_else(|| gateway_failure("Gateway checkpoint lease is missing"))?;
    if lease.lease_seq != checkpoint.lease_seq
        || lease.holder_instance_id != checkpoint.holder_instance_id
        || lease.expires_at <= current_unix_timestamp_secs()
    {
        return Err(gateway_failure(
            "Gateway checkpoint lease is expired or belongs to another owner",
        ));
    }
    Ok(())
}

fn read_checkpoint_record(
    checkpoint: &GatewayCheckpoint,
) -> DiscordResult<Option<GatewayStateRecord>> {
    let record = read_json_file_if_exists::<GatewayStateRecord>(&checkpoint.state_path).map_err(
        |error| recovery_required(&format!("cannot read the existing checkpoint: {error}")),
    )?;
    if let Some(record) = &record {
        if record.version != GATEWAY_STATE_VERSION {
            return Err(recovery_required(
                "legacy or unsupported checkpoint version cannot establish consumer-confirmed progress",
            ));
        }
        if record.scope != checkpoint.scope || record.scope.is_empty() {
            return Err(recovery_required(
                "checkpoint scope differs from the credential, zone, subscription or policy",
            ));
        }
        if record.lease_seq > checkpoint.lease_seq {
            return Err(gateway_failure(
                "Gateway checkpoint is fenced by a newer lease",
            ));
        }
    }
    Ok(record)
}

fn validate_resume_state(state: &GatewayState) -> DiscordResult<()> {
    if state.resume_invalidated {
        return Err(recovery_required(
            "the provider invalidated this resume session",
        ));
    }
    match (&state.session_id, &state.resume_url, state.sequence) {
        (None, None, None) => Ok(()),
        (Some(session), Some(url), Some(_)) if !session.is_empty() && !url.is_empty() => Ok(()),
        _ => Err(recovery_required(
            "the stored session has no complete consumer-confirmed resume position",
        )),
    }
}

fn load_checkpoint(checkpoint: &GatewayCheckpoint) -> DiscordResult<Option<GatewayState>> {
    let _lock = lock_gateway_lease(&checkpoint.lease_path)
        .map_err(|error| gateway_failure(format!("Cannot lock Gateway checkpoint: {error}")))?;
    verify_checkpoint_lease(checkpoint)?;
    read_checkpoint_record(checkpoint).map(|record| record.map(GatewayState::from_record))
}

fn persist_checkpoint(
    checkpoint: Option<&GatewayCheckpoint>,
    state: &GatewayState,
) -> DiscordResult<()> {
    let Some(checkpoint) = checkpoint else {
        return Ok(());
    };
    let _lock = lock_gateway_lease(&checkpoint.lease_path)
        .map_err(|error| gateway_failure(format!("Cannot lock Gateway checkpoint: {error}")))?;
    verify_checkpoint_lease(checkpoint)?;
    if let Some(current) = read_checkpoint_record(checkpoint)? {
        if current.resume_invalidated && !state.resume_invalidated {
            return Err(recovery_required(
                "the provider invalidated the stored resume session",
            ));
        }
        if current.session_id.is_some() && current.session_id != state.session_id {
            return Err(recovery_required(
                "a different session cannot replace consumer-confirmed history",
            ));
        }
        if current.sequence > state.sequence {
            return Err(gateway_failure(
                "Gateway checkpoint would regress committed progress",
            ));
        }
    }
    write_json_file_atomic(&checkpoint.state_path, &state.to_record(checkpoint))
        .map_err(|error| gateway_failure(format!("Cannot persist Gateway checkpoint: {error}")))
}

fn dispatch_event(
    event_name: String,
    data: serde_json::Value,
    state: &mut GatewayState,
) -> DiscordResult<GatewayEvent> {
    let event = match event_name.as_str() {
        "READY" => {
            let ready: GatewayReady = serde_json::from_value(data)?;
            if ready.session_id.is_empty() || ready.resume_gateway_url.is_empty() {
                return Err(recovery_required("READY omitted its resume identity"));
            }
            if state
                .session_id
                .as_ref()
                .is_some_and(|session| session != &ready.session_id)
            {
                return Err(recovery_required(
                    "the provider replaced the previous session instead of resuming it",
                ));
            }
            state.session_id = Some(ready.session_id.clone());
            state.resume_url = Some(ready.resume_gateway_url.clone());
            info!("Gateway ready");
            GatewayEvent::Ready(ready)
        }
        "RESUMED" => {
            info!("Session resumed successfully");
            GatewayEvent::Resumed
        }
        "MESSAGE_CREATE" => GatewayEvent::MessageCreate(data),
        "MESSAGE_UPDATE" => GatewayEvent::MessageUpdate(data),
        "MESSAGE_DELETE" => GatewayEvent::MessageDelete(data),
        "GUILD_CREATE" => GatewayEvent::GuildCreate(data),
        "GUILD_UPDATE" => GatewayEvent::GuildUpdate(data),
        "CHANNEL_CREATE" => GatewayEvent::ChannelCreate(data),
        "CHANNEL_UPDATE" => GatewayEvent::ChannelUpdate(data),
        "TYPING_START" => GatewayEvent::TypingStart(data),
        _ => GatewayEvent::Unknown { event_name, data },
    };

    Ok(event)
}

/// Handle for a single gateway connection attempt.
pub struct GatewayStream {
    pub events: mpsc::Receiver<GatewayEventFrame>,
    pub join_handle: fcp_async_core::task::JoinHandle<Result<(), StreamingError>>,
}

impl std::fmt::Debug for GatewayStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayStream").finish_non_exhaustive()
    }
}

/// Run the gateway event loop.
async fn run_gateway_loop(
    ws_stream: WsConnection,
    config: DiscordConfig,
    event_tx: mpsc::Sender<GatewayEventFrame>,
    mut state: GatewayState,
    state_store: Arc<Mutex<GatewayDeliveryState>>,
    generation: u64,
    shutdown_requested: Arc<AtomicBool>,
) -> DiscordResult<()> {
    let result = Box::pin(run_gateway_loop_inner(
        ws_stream,
        config,
        &event_tx,
        &mut state,
        &state_store,
        generation,
        &shutdown_requested,
    ))
    .await;
    if let Err(error) = &result
        && !error.is_retryable()
    {
        state_store.lock().await.recovery_reason = Some(error.to_string());
    }
    result
}

async fn gateway_operation<F: std::future::Future>(
    operation: F,
    shutdown_requested: &AtomicBool,
    deadline: Duration,
) -> DiscordResult<F::Output> {
    let mut operation = Box::pin(operation);
    let started = Instant::now();
    loop {
        if shutdown_requested.load(Ordering::Acquire) {
            return Err(gateway_failure("Gateway worker was stopped"));
        }
        let remaining = deadline.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err(gateway_failure("Gateway operation timed out"));
        }
        if let Ok(value) =
            fcp_async_core::time::timeout(remaining.min(GATEWAY_STOP_POLL), &mut operation).await
        {
            return Ok(value);
        }
    }
}

async fn queue_dispatch(
    event_tx: &mpsc::Sender<GatewayEventFrame>,
    state: &GatewayState,
    event: GatewayEvent,
    sequence: u64,
    bytes: usize,
    state_store: &Arc<Mutex<GatewayDeliveryState>>,
    generation: u64,
) -> DiscordResult<()> {
    let session_id = state
        .session_id
        .as_ref()
        .ok_or_else(|| recovery_required("dispatch arrived before a valid READY session"))?;
    let resume_url = state
        .resume_url
        .as_ref()
        .ok_or_else(|| recovery_required("dispatch has no resume endpoint"))?;
    let mut delivery = state_store.lock().await;
    if generation != delivery.generation || delivery.committed.resume_invalidated {
        return Err(gateway_failure(
            "Gateway dispatch belongs to a retired connection",
        ));
    }
    if delivery.pending.len() >= GATEWAY_EVENT_BUFFER_CAPACITY
        || bytes > GATEWAY_PENDING_MAX_BYTES.saturating_sub(delivery.pending_bytes)
    {
        return Err(gateway_failure(
            "Gateway unacknowledged dispatch buffer is full; resume from the committed cursor",
        ));
    }
    if delivery.committed.session_id.is_none() {
        let provisional = GatewayState {
            session_id: Some(session_id.clone()),
            resume_url: Some(resume_url.clone()),
            sequence: None,
            resume_invalidated: false,
        };
        // Record that a session exists without claiming any dispatch was consumed.
        // An interrupted first READY must not silently become a fresh IDENTIFY.
        if let Err(error) = persist_checkpoint(delivery.checkpoint.as_ref(), &provisional) {
            let reason = format!("cannot record the first unacknowledged session: {error}");
            delivery.recovery_reason = Some(reason.clone());
            return Err(recovery_required(&reason));
        }
        delivery.committed = provisional;
    } else if delivery.committed.session_id.as_ref() != Some(session_id) {
        return Err(recovery_required(
            "dispatch session differs from the committed checkpoint",
        ));
    }
    let frame = GatewayEventFrame {
        seq: Some(sequence),
        event,
        acknowledgement: Some(GatewayAcknowledgement {
            state: Arc::clone(state_store),
            generation,
            sequence,
            session_id: session_id.clone(),
            cursor: dispatch_cursor(session_id, sequence),
        }),
    };
    // The pending queue includes the currently delivered frame. Capacity does not
    // become available merely because the downstream worker received a frame.
    delivery.pending.push_back(PendingDispatch {
        sequence,
        session_id: session_id.clone(),
        resume_url: resume_url.clone(),
        bytes,
    });
    delivery.pending_bytes += bytes;
    if event_tx.try_send(frame).is_err() {
        delivery.pending.pop_back();
        delivery.pending_bytes = delivery.pending_bytes.saturating_sub(bytes);
        return Err(gateway_failure(
            "Gateway consumer is unavailable; resume from the committed cursor",
        ));
    }
    Ok(())
}

async fn invalidate_resume(
    state_store: &Arc<Mutex<GatewayDeliveryState>>,
    reason: &str,
) -> DiscordResult<()> {
    let mut delivery = state_store.lock().await;
    let mut invalidated = delivery.committed.clone();
    invalidated.resume_invalidated = true;
    // This is a safety fence, not cursor advancement. Install it before I/O:
    // an unavailable disk must not let a late ACK undo known provider loss.
    delivery.recovery_reason = Some(reason.into());
    let persisted = persist_checkpoint(delivery.checkpoint.as_ref(), &invalidated);
    delivery.committed = invalidated;
    if let Err(error) = persisted {
        return Err(recovery_required(&format!(
            "{reason}; its recovery marker could not be persisted: {error}"
        )));
    }
    Err(recovery_required(reason))
}

#[allow(clippy::large_futures)]
async fn run_gateway_loop_inner(
    mut ws_stream: WsConnection,
    config: DiscordConfig,
    event_tx: &mpsc::Sender<GatewayEventFrame>,
    state: &mut GatewayState,
    state_store: &Arc<Mutex<GatewayDeliveryState>>,
    generation: u64,
    shutdown_requested: &AtomicBool,
) -> DiscordResult<()> {
    validate_resume_state(state)?;
    // Wait for Hello
    let hello = match gateway_operation(
        ws_stream.recv(),
        shutdown_requested,
        Duration::from_secs(10),
    )
    .await?
    {
        Ok(Some(WsMessage::Text(text))) => match serde_json::from_str::<GatewayPayload>(&text) {
            Ok(payload) => {
                if payload.op != GatewayOpcode::Hello as i32 {
                    return Err(DiscordError::Gateway("Expected Hello opcode".into()));
                }
                let hello =
                    match serde_json::from_value::<GatewayHello>(payload.d.unwrap_or_default()) {
                        Ok(h) => h,
                        Err(e) => return Err(e.into()),
                    };
                validate_gateway_hello(hello)
                    .map_err(|error| DiscordError::Gateway(error.to_string()))?
            }
            Err(e) => return Err(e.into()),
        },
        Ok(Some(_)) => {
            return Err(gateway_failure("Unexpected Gateway message before Hello"));
        }
        Ok(None) => {
            return Err(DiscordError::Gateway(
                "Connection closed before Hello".into(),
            ));
        }
        Err(e) => return Err(DiscordError::Gateway(format!("WebSocket error: {e}"))),
    };

    let heartbeat_interval = Duration::from_millis(hello.heartbeat_interval);
    debug!(interval_ms = hello.heartbeat_interval, "Received Hello");
    let mut send_limiter = GatewaySendLimiter::default();

    // Send Resume if we have a session, otherwise Identify
    if let (Some(sess_id), Some(seq)) = (&state.session_id, state.sequence) {
        // We have a session to resume
        info!(sequence = seq, "Attempting to resume session");

        let resume = GatewayResume {
            token: config.bot_credential.clone(),
            session_id: sess_id.clone(),
            seq,
        };

        let resume_payload = GatewayPayload {
            op: GatewayOpcode::Resume as i32,
            d: Some(match serde_json::to_value(&resume) {
                Ok(v) => v,
                Err(e) => return Err(e.into()),
            }),
            s: None,
            t: None,
        };

        send_gateway_payload(
            &mut ws_stream,
            &mut send_limiter,
            &resume_payload,
            true,
            "Resume",
        )
        .await?;
    } else {
        // Fresh connection - send Identify
        let identify = GatewayIdentify {
            token: config.bot_credential.clone(),
            intents: config.intents,
            properties: GatewayProperties {
                os: std::env::consts::OS.into(),
                browser: "fcp-discord".into(),
                device: "fcp-discord".into(),
            },
            shard: config.shard.as_ref().map(|s| [s.shard_id, s.shard_count]),
        };

        let identify_payload = GatewayPayload {
            op: GatewayOpcode::Identify as i32,
            d: Some(match serde_json::to_value(&identify) {
                Ok(v) => v,
                Err(e) => return Err(e.into()),
            }),
            s: None,
            t: None,
        };

        let (shard_id, max_concurrency, identify_window) = identify_limiter_params(&config);
        debug!(
            shard_id,
            max_concurrency,
            identify_window_ms = identify_window.as_millis() as u64,
            "Waiting for Discord gateway identify limiter"
        );
        gateway_operation(
            shared_gateway_identify_limiter().wait(&config),
            shutdown_requested,
            Duration::from_secs(60),
        )
        .await?;
        send_gateway_payload(
            &mut ws_stream,
            &mut send_limiter,
            &identify_payload,
            true,
            "Identify",
        )
        .await?;
    }

    // Main event loop
    let mut heartbeat_acked = true;
    let mut next_heartbeat_at = std::time::Instant::now() + heartbeat_interval;
    // The provider needs the most recently received sequence in heartbeat
    // packets. Only consumer acknowledgements advance the separate checkpoint.
    let mut received_sequence = state.sequence;

    loop {
        if shutdown_requested.load(Ordering::Acquire) || event_tx.is_closed() {
            return Ok(());
        }
        let now = std::time::Instant::now();
        // Check the deadline before polling the socket. A continuously ready
        // dispatch stream must not starve heartbeats by winning every timeout.
        if now >= next_heartbeat_at {
            if !heartbeat_acked {
                warn!("Heartbeat not acknowledged, connection zombied");
                return Err(gateway_failure("Heartbeat timeout (zombied)"));
            }
            let heartbeat = GatewayPayload {
                op: GatewayOpcode::Heartbeat as i32,
                d: Some(json!(received_sequence)),
                s: None,
                t: None,
            };
            send_gateway_payload(
                &mut ws_stream,
                &mut send_limiter,
                &heartbeat,
                true,
                "heartbeat",
            )
            .await?;
            heartbeat_acked = false;
            next_heartbeat_at = Instant::now() + heartbeat_interval;
            debug!("Sent heartbeat");
            continue;
        }
        let wait_for_message = next_heartbeat_at
            .saturating_duration_since(now)
            .min(GATEWAY_STOP_POLL);

        // asupersync WebSocket::recv is cancel-safe: partial frames and message
        // fragments live in the connection's codec/assembler, not this future.
        match fcp_async_core::time::timeout(wait_for_message, ws_stream.recv()).await {
            Err(_) => continue,
            Ok(Ok(Some(WsMessage::Text(text)))) => {
                let payload: GatewayPayload = serde_json::from_str(&text).map_err(|_| {
                    gateway_failure(
                        "Malformed Gateway payload; refusing to skip unconsumed history",
                    )
                })?;

                match GatewayOpcode::try_from(payload.op) {
                    Ok(GatewayOpcode::Dispatch) => {
                        let sequence = payload
                            .s
                            .ok_or_else(|| recovery_required("dispatch omitted its sequence"))?;
                        if received_sequence.is_some_and(|previous| sequence < previous) {
                            return Err(recovery_required(
                                "dispatch sequence regressed within the provider session",
                            ));
                        }
                        received_sequence = Some(sequence);
                        let event_name = payload
                            .t
                            .filter(|name| !name.is_empty())
                            .ok_or_else(|| recovery_required("dispatch omitted its event type"))?;
                        let data =
                            payload
                                .d
                                .filter(serde_json::Value::is_object)
                                .ok_or_else(|| {
                                    recovery_required("dispatch payload is not an object")
                                })?;
                        let is_ready = event_name == "READY";
                        let mut event = match dispatch_event(event_name, data, state) {
                            Ok(event) => event,
                            Err(_) if is_ready => {
                                return invalidate_resume(
                                    state_store,
                                    "READY did not establish a valid resumable session",
                                )
                                .await;
                            }
                            Err(error) => return Err(error),
                        };
                        if let GatewayEvent::Ready(ready) = &mut event {
                            let resume_url =
                                match config.validate_gateway_url(&ready.resume_gateway_url) {
                                    Ok(url) => url.to_string(),
                                    Err(_) => {
                                        // Persist only safe committed metadata (or an empty
                                        // invalidated marker before the first READY). Never
                                        // store a hostile endpoint or silently re-identify.
                                        return invalidate_resume(
                                            state_store,
                                            "READY supplied a rejected Gateway resume URL",
                                        )
                                        .await;
                                    }
                                };
                            ready.resume_gateway_url.clone_from(&resume_url);
                            state.resume_url = Some(resume_url);
                        }
                        queue_dispatch(
                            event_tx,
                            state,
                            event,
                            sequence,
                            text.len(),
                            state_store,
                            generation,
                        )
                        .await?;
                    }
                    Ok(GatewayOpcode::HeartbeatAck) => {
                        heartbeat_acked = true;
                        debug!("Heartbeat acknowledged");
                    }
                    Ok(GatewayOpcode::Reconnect) => {
                        info!("Received reconnect request");
                        return Ok(());
                    }
                    Ok(GatewayOpcode::InvalidSession) => {
                        let resumable = payload.d.and_then(|v| v.as_bool()).unwrap_or(false);
                        warn!(resumable, "Session invalidated");
                        if !resumable {
                            return invalidate_resume(
                                state_store,
                                "the provider can no longer replay this session",
                            )
                            .await;
                        }
                        return Ok(());
                    }
                    Ok(GatewayOpcode::Heartbeat) => {
                        let heartbeat = GatewayPayload {
                            op: GatewayOpcode::Heartbeat as i32,
                            d: Some(json!(received_sequence)),
                            s: None,
                            t: None,
                        };
                        if let Err(e) = send_gateway_payload(
                            &mut ws_stream,
                            &mut send_limiter,
                            &heartbeat,
                            true,
                            "heartbeat",
                        )
                        .await
                        {
                            error!(error = %e, "Failed to send heartbeat response");
                            return Err(e);
                        }
                    }
                    _ => {
                        debug!(op = payload.op, "Unhandled opcode");
                    }
                }
            }
            Ok(Ok(Some(WsMessage::Close(frame)))) => {
                if frame
                    .as_ref()
                    .is_some_and(|frame| matches!(frame.code, 4007 | 4009))
                {
                    return invalidate_resume(
                        state_store,
                        "the provider can no longer replay this session",
                    )
                    .await;
                }
                info!("Gateway connection closed");
                return Ok(());
            }
            Ok(Ok(Some(_))) => {
                // Ignore other message types (ping, pong, binary)
            }
            Ok(Ok(None)) => {
                info!("Gateway connection ended");
                return Ok(());
            }
            Ok(Err(e)) => {
                error!(error = %e, "WebSocket error");
                return Err(DiscordError::Gateway(format!("WebSocket error: {e}")));
            }
        }
    }
}
