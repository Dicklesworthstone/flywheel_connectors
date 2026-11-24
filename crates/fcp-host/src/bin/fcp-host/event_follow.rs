//! Bounded, resumable NDJSON observation of retained control-plane events.
//!
//! The response body owns the entire producer. Backpressure suspends polling;
//! dropping the body drops any pending store read or sleep, with no detached
//! task. One monotonic deadline bounds producer work whenever the body is
//! polled. It cannot force a blocked transport or an unpolled body to close.
//!
//! The byte limits bound encoded output, not the resident journal or a single
//! cloned event. Each store query clones at most one matching event, and the
//! capped serializer does not allocate an unbounded encoded copy of it.

use std::io::{self, Write};

use fcp_host::{HostEvent, HostEventKind};
use futures_util::Stream;

use super::*;

const ROUTE: &str = "/rpc/admin/events/follow";
const REQUEST_BYTES: usize = 16 * 1024;
const CURSOR_BYTES: usize = 1024;
const FRAME_BYTES: usize = 1024 * 1024;
const STREAM_BYTES: usize = 8 * 1024 * 1024;
const TERMINAL_BYTES: usize = 4 * 1024;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct FollowRequest {
    #[serde(default)]
    connector_id: Option<String>,
    #[serde(default)]
    kind: Option<HostEventKind>,
    #[serde(default)]
    unacknowledged_only: bool,
    #[serde(default)]
    after_event_id: Option<String>,
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,
    #[serde(default = "default_poll_interval_ms")]
    poll_interval_ms: u64,
    #[serde(default = "default_max_events")]
    max_events: usize,
}

const fn default_timeout_ms() -> u64 {
    30_000
}

const fn default_poll_interval_ms() -> u64 {
    1000
}

const fn default_max_events() -> usize {
    1000
}

fn valid_cursor(cursor: &str) -> bool {
    !cursor.is_empty() && cursor.len() <= CURSOR_BYTES && !cursor.chars().any(char::is_control)
}

impl FollowRequest {
    fn validate(&self) -> Result<(), (StatusCode, String)> {
        let invalid = if !(1..=60_000).contains(&self.timeout_ms) {
            Some("timeout_ms must be within 1..=60000")
        } else if !(10..=5000).contains(&self.poll_interval_ms) {
            Some("poll_interval_ms must be within 10..=5000")
        } else if self.max_events > 10_000 {
            Some("max_events must be within 0..=10000; zero follows until another bound")
        } else if self
            .after_event_id
            .as_deref()
            .is_some_and(|cursor| !valid_cursor(cursor))
        {
            Some("after_event_id must contain 1..=1024 bytes without control characters")
        } else if self
            .connector_id
            .as_deref()
            .is_some_and(|id| !valid_cursor(id))
        {
            Some("connector_id must contain 1..=1024 bytes without control characters")
        } else {
            None
        };
        invalid.map_or(Ok(()), |message| {
            Err((StatusCode::BAD_REQUEST, message.to_owned()))
        })
    }
}

/// The parent mounts this router before applying owner-zone admin middleware.
pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new().route(
        ROUTE,
        post(handler).layer(axum::extract::DefaultBodyLimit::max(REQUEST_BYTES)),
    )
}

async fn handler(
    State(state): State<Arc<AppState>>,
    Json(request): Json<FollowRequest>,
) -> Result<Response, (StatusCode, String)> {
    request.validate()?;
    let body = Body::from_stream(stream_with_limits(
        Arc::clone(&state.lifecycle),
        request,
        EncodingLimits::default(),
    ));
    let mut response = Response::new(body);
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-ndjson"),
    );
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Record<'a> {
    Start {
        source: &'static str,
        latest_cursor: Option<&'a str>,
        event_count: usize,
        timeout_ms: u64,
        poll_interval_ms: u64,
        max_events: usize,
    },
    Event {
        source: &'static str,
        latest_cursor: &'a str,
        event_count: usize,
        event: &'a HostEvent,
    },
    Checkpoint {
        source: &'static str,
        latest_cursor: Option<&'a str>,
        event_count: usize,
    },
    Complete {
        source: &'static str,
        latest_cursor: Option<&'a str>,
        event_count: usize,
        reason: &'static str,
    },
    Error {
        source: &'static str,
        latest_cursor: Option<&'a str>,
        event_count: usize,
        code: &'static str,
        message: &'static str,
    },
}

#[derive(Clone, Copy)]
struct EncodingLimits {
    frame: usize,
    total: usize,
    terminal: usize,
}

impl Default for EncodingLimits {
    fn default() -> Self {
        Self {
            frame: FRAME_BYTES,
            total: STREAM_BYTES,
            terminal: TERMINAL_BYTES,
        }
    }
}

enum Stop {
    Complete(&'static str),
    Error(&'static str, &'static str),
}

struct CappedWriter {
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
}

impl Write for CappedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            self.exceeded = true;
            return Err(io::Error::other("event stream encoding limit exceeded"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct FollowState {
    store: Arc<HostAdminStateStore>,
    request: FollowRequest,
    page: EventPageQueryRequest,
    deadline: Instant,
    event_count: usize,
    encoded_bytes: usize,
    pending_checkpoint: Option<String>,
    wait_before_poll: bool,
    started: bool,
    finished: bool,
    limits: EncodingLimits,
}

impl FollowState {
    fn encode(&self, record: &Record<'_>, terminal: bool) -> Result<Bytes, Stop> {
        let available = self
            .limits
            .total
            .saturating_sub(self.encoded_bytes)
            .saturating_sub(if terminal { 0 } else { self.limits.terminal });
        let capacity = available.min(self.limits.frame);
        if capacity == 0 {
            return Err(Stop::Complete("byte-limit"));
        }
        let mut writer = CappedWriter {
            bytes: Vec::with_capacity(capacity.min(1024)),
            limit: capacity - 1,
            exceeded: false,
        };
        if serde_json::to_writer(&mut writer, record).is_err() {
            return Err(if writer.exceeded && available < self.limits.frame {
                Stop::Complete("byte-limit")
            } else if writer.exceeded {
                Stop::Error(
                    "frame-too-large",
                    "an event exceeds the encoded frame limit",
                )
            } else {
                Stop::Error("encoding-failed", "an event could not be encoded")
            });
        }
        writer.bytes.push(b'\n');
        Ok(Bytes::from(writer.bytes))
    }

    fn prepare_data(&self, record: &Record<'_>) -> Result<Bytes, Stop> {
        if Instant::now() >= self.deadline {
            return Err(Stop::Complete("timeout"));
        }
        let bytes = self.encode(record, false)?;
        // Synchronous serialization cannot be preempted. Never emit or advance
        // a cursor if that work consumed the remaining producer deadline.
        if Instant::now() >= self.deadline {
            return Err(Stop::Complete("timeout"));
        }
        Ok(bytes)
    }

    fn finish(&mut self, stop: Stop) -> io::Result<Bytes> {
        self.finished = true;
        let latest_cursor = self.page.after_event_id.as_deref();
        let record = match stop {
            Stop::Complete(reason) => Record::Complete {
                source: "host-admin-api",
                latest_cursor,
                event_count: self.event_count,
                reason,
            },
            Stop::Error(code, message) => Record::Error {
                source: "host-admin-api",
                latest_cursor,
                event_count: self.event_count,
                code,
                message,
            },
        };
        let bytes = self.encode(&record, true).map_err(|_| {
            io::Error::other("event stream terminal record exceeded its reserved encoding budget")
        })?;
        self.encoded_bytes += bytes.len();
        Ok(bytes)
    }

    fn checkpoint(&mut self, cursor: Option<String>) -> io::Result<Bytes> {
        let record = Record::Checkpoint {
            source: "host-admin-api",
            latest_cursor: cursor.as_deref(),
            event_count: self.event_count,
        };
        match self.prepare_data(&record) {
            Ok(bytes) => {
                self.encoded_bytes += bytes.len();
                self.page.after_event_id = cursor;
                Ok(bytes)
            }
            Err(stop) => self.finish(stop),
        }
    }

    async fn next(&mut self) -> Option<io::Result<Bytes>> {
        if self.finished {
            return None;
        }
        if !self.started {
            self.started = true;
            let start = Record::Start {
                source: "host-admin-api",
                latest_cursor: self.page.after_event_id.as_deref(),
                event_count: 0,
                timeout_ms: self.request.timeout_ms,
                poll_interval_ms: self.request.poll_interval_ms,
                max_events: self.request.max_events,
            };
            // A delayed first poll still establishes the frame contract before
            // the next poll reports timeout; no journal read happens here.
            return Some(match self.encode(&start, false) {
                Ok(bytes) => {
                    self.encoded_bytes += bytes.len();
                    Ok(bytes)
                }
                Err(stop) => self.finish(stop),
            });
        }
        if self.request.max_events != 0 && self.event_count >= self.request.max_events {
            return Some(self.finish(Stop::Complete("event-limit")));
        }
        if Instant::now() >= self.deadline {
            return Some(self.finish(Stop::Complete("timeout")));
        }
        // A limit reached on the last event wins over this checkpoint. A
        // consumer stopping mid-page resumes from exactly its last event.
        if let Some(cursor) = self.pending_checkpoint.take() {
            return Some(self.checkpoint(Some(cursor)));
        }
        if self.wait_before_poll {
            self.wait_before_poll = false;
            if fcp_async_core::time::timeout(
                self.deadline.saturating_duration_since(Instant::now()),
                fcp_async_core::time::sleep(Duration::from_millis(self.request.poll_interval_ms)),
            )
            .await
            .is_err()
                || Instant::now() >= self.deadline
            {
                return Some(self.finish(Stop::Complete("timeout")));
            }
        }
        let page = match fcp_async_core::time::timeout(
            self.deadline.saturating_duration_since(Instant::now()),
            self.store.query_events_page(&self.page),
        )
        .await
        {
            Ok(page) => page,
            Err(_) => return Some(self.finish(Stop::Complete("timeout"))),
        };
        if Instant::now() >= self.deadline {
            return Some(self.finish(Stop::Complete("timeout")));
        }
        if page.cursor_found == Some(false) {
            return Some(self.finish(Stop::Error(
                "cursor-not-found",
                "the resume cursor is absent from the retained host journal; choose a new start explicitly",
            )));
        }
        if page.after_event_id != self.page.after_event_id
            || page.cursor_found != self.page.after_event_id.as_ref().map(|_| true)
            || page
                .next_cursor
                .as_deref()
                .is_some_and(|cursor| !valid_cursor(cursor))
            || page.events.len() > 1
            || page.events.iter().any(|event| {
                !valid_cursor(&event.event_id)
                    || Some(event.event_id.as_str()) == self.page.after_event_id.as_deref()
            })
            || (page.has_more
                && (page.events.is_empty()
                    || page.next_cursor.as_deref()
                        != page.events.last().map(|event| event.event_id.as_str())))
        {
            return Some(self.finish(Stop::Error(
                "invalid-page",
                "the retained journal returned an invalid cursor page",
            )));
        }
        self.wait_before_poll = !page.has_more;
        let Some(event) = page.events.into_iter().next() else {
            return Some(self.checkpoint(page.next_cursor));
        };
        let record = Record::Event {
            source: "host-admin-api",
            latest_cursor: &event.event_id,
            event_count: self.event_count + 1,
            event: &event,
        };
        let bytes = match self.prepare_data(&record) {
            Ok(bytes) => bytes,
            Err(stop) => return Some(self.finish(stop)),
        };
        // Publication follows successful bounded encoding. The body yields
        // exactly this frame before polling the state machine again.
        self.encoded_bytes += bytes.len();
        self.event_count += 1;
        self.page.after_event_id = Some(event.event_id.clone());
        if !page.has_more && page.next_cursor != self.page.after_event_id {
            self.pending_checkpoint = page.next_cursor;
        }
        Some(Ok(bytes))
    }
}

fn stream_with_limits(
    store: Arc<HostAdminStateStore>,
    request: FollowRequest,
    limits: EncodingLimits,
) -> impl Stream<Item = io::Result<Bytes>> + Send + 'static {
    let state = FollowState {
        page: EventPageQueryRequest {
            query: EventQueryRequest {
                connector_id: request.connector_id.clone(),
                kind: request.kind,
                unacknowledged_only: request.unacknowledged_only,
                limit: 1,
            },
            after_event_id: request.after_event_id.clone(),
        },
        deadline: Instant::now() + Duration::from_millis(request.timeout_ms),
        store,
        request,
        event_count: 0,
        encoded_bytes: 0,
        pending_checkpoint: None,
        wait_before_poll: false,
        started: false,
        finished: false,
        limits,
    };
    futures_util::stream::unfold(state, |mut state| async move {
        state.next().await.map(|frame| (frame, state))
    })
}

#[cfg(test)]
mod tests {
    use futures_util::{StreamExt, poll};
    use tower::util::ServiceExt;

    use super::*;

    fn request() -> FollowRequest {
        serde_json::from_value(json!({
            "timeout_ms": 1000,
            "poll_interval_ms": 10,
            "max_events": 0,
        }))
        .unwrap()
    }

    fn app(state: Arc<AppState>) -> Router {
        routes()
            .route_layer(from_fn_with_state(
                Arc::clone(&state),
                admin_auth_middleware,
            ))
            .with_state(state)
    }

    async fn post_json(app: Router, body: Value, headers: &[(&str, &str)]) -> Response {
        let mut builder = Request::builder()
            .method("POST")
            .uri(ROUTE)
            .header(axum::http::header::CONTENT_TYPE, "application/json");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        app.oneshot(builder.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap()
    }

    async fn record<S, E>(stream: &mut S) -> Value
    where
        S: Stream<Item = Result<Bytes, E>> + Unpin,
        E: fmt::Debug,
    {
        let bytes = stream
            .next()
            .await
            .expect("next frame")
            .expect("encoded frame");
        assert_eq!(bytes.last(), Some(&b'\n'));
        serde_json::from_slice(&bytes).unwrap()
    }

    async fn emit(
        store: &HostAdminStateStore,
        connector: &str,
        summary: &str,
        payload: Option<Value>,
    ) {
        store
            .emit_event(
                HostEventKind::HealthCheck,
                Some(connector),
                summary.to_owned(),
                payload,
            )
            .await;
    }

    #[fcp_async_core::runtime::test]
    async fn event_follow_route_requires_owner_admin_and_validates_bounded_inputs() {
        let app = app(super::super::tests::cancel_route_test_state());
        for headers in [
            vec![],
            vec![("authorization", "Bearer topsecret")],
            vec![
                ("authorization", "Bearer wrong"),
                (ADMIN_ZONE_HEADER, "z:owner"),
            ],
            vec![
                ("authorization", "Bearer topsecret"),
                (ADMIN_ZONE_HEADER, "z:work"),
            ],
        ] {
            let response = post_json(app.clone(), json!({ "timeout_ms": 0 }), &headers).await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }
        let headers = [
            ("authorization", "Bearer topsecret"),
            (ADMIN_ZONE_HEADER, "z:owner"),
        ];
        for body in [
            json!({ "timeout_ms": 0 }),
            json!({ "timeout_ms": 60_001 }),
            json!({ "poll_interval_ms": 9 }),
            json!({ "poll_interval_ms": 5001 }),
            json!({ "max_events": 10_001 }),
            json!({ "after_event_id": "" }),
            json!({ "after_event_id": "cursor\n" }),
            json!({ "after_event_id": "x".repeat(CURSOR_BYTES + 1) }),
            json!({ "connector_id": "x".repeat(CURSOR_BYTES + 1) }),
        ] {
            let response = post_json(app.clone(), body, &headers).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
        let oversized = post_json(
            app.clone(),
            json!({ "connector_id": "x".repeat(REQUEST_BYTES) }),
            &headers,
        )
        .await;
        assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let response = post_json(app, json!({}), &headers).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[axum::http::header::CONTENT_TYPE],
            "application/x-ndjson"
        );
        assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
    }

    #[fcp_async_core::runtime::test]
    async fn event_follow_route_catches_up_checkpoints_and_delivers_new_arrivals() {
        let state = super::super::tests::cancel_route_test_state();
        for (connector, summary) in [
            ("alpha", "first"),
            ("beta", "skip"),
            ("alpha", "second"),
            ("beta", "filtered suffix"),
        ] {
            emit(&state.lifecycle, connector, summary, None).await;
        }
        let response = post_json(
            app(Arc::clone(&state)),
            json!({ "connector_id": "alpha", "max_events": 3, "poll_interval_ms": 10 }),
            &[
                ("authorization", "Bearer topsecret"),
                (ADMIN_ZONE_HEADER, "z:owner"),
            ],
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let mut records = Box::pin(response.into_body().into_data_stream());
        assert_eq!(record(&mut records).await["type"], "start");
        for (cursor, summary) in [("evt-1", "first"), ("evt-3", "second")] {
            let event = record(&mut records).await;
            assert_eq!(event["type"], "event");
            assert_eq!(event["latest_cursor"], cursor);
            assert_eq!(event["event"]["summary"], summary);
        }
        let checkpoint = record(&mut records).await;
        assert_eq!(checkpoint["type"], "checkpoint");
        assert_eq!(checkpoint["latest_cursor"], "evt-4");
        assert_eq!(checkpoint["event_count"], 2);
        emit(&state.lifecycle, "alpha", "arrived after catch-up", None).await;
        let event = record(&mut records).await;
        assert_eq!(event["type"], "event");
        assert_eq!(event["latest_cursor"], "evt-5");
        assert_eq!(event["event"]["summary"], "arrived after catch-up");
        let complete = record(&mut records).await;
        assert_eq!(complete["type"], "complete");
        assert_eq!(complete["reason"], "event-limit");
        assert_eq!(complete["latest_cursor"], "evt-5");
        assert_eq!(complete["event_count"], 3);
        assert!(records.next().await.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn event_follow_missing_cursor_never_replays_history() {
        let store = Arc::new(HostAdminStateStore::new());
        emit(&store, "alpha", "retained", None).await;
        let mut request = request();
        request.after_event_id = Some("missing".to_owned());
        let mut records = Box::pin(stream_with_limits(
            store,
            request,
            EncodingLimits::default(),
        ));
        assert_eq!(record(&mut records).await["type"], "start");
        let error = record(&mut records).await;
        assert_eq!(error["type"], "error");
        assert_eq!(error["code"], "cursor-not-found");
        assert_eq!(error["latest_cursor"], "missing");
        assert_eq!(error["event_count"], 0);
        assert!(records.next().await.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn event_follow_event_limit_keeps_exact_cursor_before_filtered_suffix() {
        let store = Arc::new(HostAdminStateStore::new());
        emit(&store, "alpha", "retained", None).await;
        emit(&store, "beta", "filtered suffix", None).await;
        let mut request = request();
        request.connector_id = Some("alpha".to_owned());
        request.max_events = 1;
        let mut records = Box::pin(stream_with_limits(
            store,
            request,
            EncodingLimits::default(),
        ));
        assert_eq!(record(&mut records).await["type"], "start");
        assert_eq!(record(&mut records).await["latest_cursor"], "evt-1");
        let complete = record(&mut records).await;
        assert_eq!(complete["type"], "complete");
        assert_eq!(complete["latest_cursor"], "evt-1");
        assert_eq!(complete["reason"], "event-limit");
        assert!(records.next().await.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn event_follow_frame_budget_preserves_the_last_encoded_cursor() {
        let store = Arc::new(HostAdminStateStore::new());
        emit(&store, "alpha", "small", None).await;
        emit(
            &store,
            "alpha",
            "large",
            Some(json!({ "text": "x".repeat(2048) })),
        )
        .await;
        let limits = EncodingLimits {
            frame: 1024,
            total: STREAM_BYTES,
            terminal: TERMINAL_BYTES,
        };
        let mut records = Box::pin(stream_with_limits(store, request(), limits));
        assert_eq!(record(&mut records).await["type"], "start");
        assert_eq!(record(&mut records).await["latest_cursor"], "evt-1");
        let error = record(&mut records).await;
        assert_eq!(error["type"], "error");
        assert_eq!(error["code"], "frame-too-large");
        assert_eq!(error["latest_cursor"], "evt-1");
        assert_eq!(error["event_count"], 1);
        assert!(records.next().await.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn event_follow_total_budget_reserves_terminal_evidence_and_resume_position() {
        let store = Arc::new(HostAdminStateStore::new());
        emit(&store, "alpha", "first", None).await;
        emit(&store, "alpha", "second", None).await;
        let mut probe = Box::pin(stream_with_limits(
            Arc::clone(&store),
            request(),
            EncodingLimits::default(),
        ));
        let start_bytes = probe.next().await.unwrap().unwrap().len();
        let event_bytes = probe.next().await.unwrap().unwrap().len();
        drop(probe);
        let total = start_bytes + event_bytes + TERMINAL_BYTES;
        let limits = EncodingLimits {
            frame: FRAME_BYTES,
            total,
            terminal: TERMINAL_BYTES,
        };
        let mut records = Box::pin(stream_with_limits(store, request(), limits));
        let mut bytes = 0;
        let mut frames = Vec::new();
        while let Some(frame) = records.next().await {
            let frame = frame.unwrap();
            bytes += frame.len();
            frames.push(serde_json::from_slice::<Value>(&frame).unwrap());
        }
        assert!(bytes <= total);
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[1]["type"], "event");
        assert_eq!(frames[2]["type"], "complete");
        assert_eq!(frames[2]["reason"], "byte-limit");
        assert_eq!(frames[2]["latest_cursor"], "evt-1");
        assert_eq!(frames[2]["event_count"], 1);
    }

    #[fcp_async_core::runtime::test]
    async fn event_follow_idle_wait_uses_the_original_deadline() {
        let mut request = request();
        request.timeout_ms = 30;
        request.poll_interval_ms = 5000;
        let mut records = Box::pin(stream_with_limits(
            Arc::new(HostAdminStateStore::new()),
            request,
            EncodingLimits::default(),
        ));
        assert_eq!(record(&mut records).await["type"], "start");
        let terminal = fcp_async_core::time::timeout(Duration::from_secs(1), async {
            loop {
                let frame = record(&mut records).await;
                if frame["type"] == "complete" {
                    break frame;
                }
                assert_eq!(frame["type"], "checkpoint");
            }
        })
        .await
        .expect("five-second poll interval must not renew the thirty-millisecond deadline");
        assert_eq!(terminal["reason"], "timeout");
        assert_eq!(terminal["event_count"], 0);
        assert!(terminal["latest_cursor"].is_null());
        assert!(records.next().await.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn event_follow_dropped_body_owns_and_releases_its_pending_producer() {
        let store = Arc::new(HostAdminStateStore::new());
        let unpolled = stream_with_limits(Arc::clone(&store), request(), EncodingLimits::default());
        assert_eq!(Arc::strong_count(&store), 2);
        drop(unpolled);
        assert_eq!(Arc::strong_count(&store), 1);

        let mut request = request();
        request.timeout_ms = 60_000;
        request.poll_interval_ms = 5000;
        let mut records = Box::pin(stream_with_limits(
            Arc::clone(&store),
            request,
            EncodingLimits::default(),
        ));
        assert_eq!(record(&mut records).await["type"], "start");
        assert_eq!(record(&mut records).await["type"], "checkpoint");
        assert!(poll!(records.next()).is_pending());
        assert_eq!(Arc::strong_count(&store), 2);
        drop(records);
        assert_eq!(Arc::strong_count(&store), 1);
    }
}
