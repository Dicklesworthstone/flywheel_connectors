//! Continuous native stdout demultiplexing and an independent control writer.
//!
//! Events never enter the RPC reply queue. The host-owned sink decides whether
//! a stream may retain an event; successful admission does not acknowledge it.
//! Consumer acknowledgements use the same serialized stdin writer as RPCs,
//! without waiting behind the invocation whose event they may acknowledge.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::Duration;

use fcp_async_core::CancellationToken;
use fcp_async_core::channel::mpsc;
use fcp_async_core::io::{AsyncBufRead, AsyncReadExt, AsyncWriteExt, BufReader};
use fcp_async_core::process::{ChildStdin, ChildStdout};
use fcp_async_core::task::{self, JoinHandle};
use fcp_core::{EventAck, EventEnvelope};
use serde::Deserialize;
use serde_json::{Value, json};

use super::native_framing::{CONTROL_RESPONSE_BYTES, MAX_RESPONSE_BYTES, ResponseFrame};
use super::{CONNECTOR_RPC_IO_TIMEOUT, connector_io_timeout_error};

pub(super) const MAX_EVENT_FRAME_BYTES: usize = 256 * 1024;
const REPLY_QUEUE_CAPACITY: usize = 2;
const MAX_STREAM_ID_BYTES: usize = 128;
const FRAME_ASSEMBLY_TIMEOUT: Duration = Duration::from_secs(60);

pub(super) type NativeEventSink = Arc<dyn Fn(&str, EventEnvelope) -> io::Result<()> + Send + Sync>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeEventParams {
    stream_id: String,
    event: EventEnvelope,
}

enum NativeOutput {
    Reply(Value),
    Event(NativeEventParams),
}

pub(super) struct NativeReply {
    pub(super) value: Value,
    pub(super) frame_bytes: usize,
}

pub(super) struct NativeResponseBudget(Arc<AtomicUsize>);

impl Drop for NativeResponseBudget {
    fn drop(&mut self) {
        self.0.store(CONTROL_RESPONSE_BYTES, Ordering::Release);
    }
}

fn classify_output(
    mut value: Value,
    frame_bytes: usize,
    response_limit: usize,
) -> io::Result<NativeOutput> {
    if value.get("method").is_some() {
        if frame_bytes > MAX_EVENT_FRAME_BYTES {
            return Err(io::Error::other(
                "native event frame exceeded its byte limit",
            ));
        }
        let object = value
            .as_object()
            .ok_or_else(|| io::Error::other("native notification must be an object"))?;
        if object.len() != 3
            || object.get("jsonrpc") != Some(&Value::String("2.0".to_string()))
            || object.get("method") != Some(&Value::String("event".to_string()))
            || !object.contains_key("params")
        {
            return Err(io::Error::other(
                "invalid native event notification envelope",
            ));
        }
        let params: NativeEventParams = serde_json::from_value(value["params"].take())
            .map_err(|_| io::Error::other("invalid native event notification parameters"))?;
        validate_stream_id(&params.stream_id)?;
        return Ok(NativeOutput::Event(params));
    }
    if frame_bytes > response_limit {
        return Err(io::Error::other(format!(
            "stdout frame exceeded {response_limit} bytes"
        )));
    }
    Ok(NativeOutput::Reply(value))
}

fn validate_stream_id(stream_id: &str) -> io::Result<()> {
    if stream_id.is_empty()
        || stream_id.len() > MAX_STREAM_ID_BYTES
        || !stream_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(io::Error::other("invalid native stream identifier"));
    }
    Ok(())
}

/// Shared controls for one physical subprocess, never a replacement worker.
#[derive(Clone)]
pub(super) struct NativeEventTransport {
    writer: Arc<futures_util::lock::Mutex<ChildStdin>>,
    sink: Arc<Mutex<Option<NativeEventSink>>>,
    failure: Arc<Mutex<Option<(io::ErrorKind, String)>>>,
    failed: CancellationToken,
    response_limit: Arc<AtomicUsize>,
}

impl NativeEventTransport {
    pub(super) fn new(stdin: ChildStdin) -> Self {
        Self {
            writer: Arc::new(futures_util::lock::Mutex::new(stdin)),
            sink: Arc::new(Mutex::new(None)),
            failure: Arc::new(Mutex::new(None)),
            failed: CancellationToken::new(),
            response_limit: Arc::new(AtomicUsize::new(CONTROL_RESPONSE_BYTES)),
        }
    }

    /// Install the host authority/durability boundary before subscribing.
    pub(super) fn install_sink(&self, sink: NativeEventSink) -> io::Result<()> {
        let mut current = self
            .sink
            .lock()
            .map_err(|_| io::Error::other("native event sink lock poisoned"))?;
        if current.is_some() {
            return Err(io::Error::other("native event sink is already installed"));
        }
        *current = Some(sink);
        Ok(())
    }

    pub(super) fn response_budget(&self, limit: usize) -> NativeResponseBudget {
        self.response_limit
            .store(limit.min(MAX_RESPONSE_BYTES), Ordering::Release);
        NativeResponseBudget(Arc::clone(&self.response_limit))
    }

    pub(super) fn fail(&self, error: &io::Error) {
        let mut failure = self.failure.lock().expect("native transport failure lock");
        if failure.is_none() {
            *failure = Some((error.kind(), error.to_string()));
        }
        drop(failure);
        self.failed.cancel();
    }

    pub(super) fn failure_error(&self) -> io::Error {
        self.failure
            .lock()
            .expect("native transport failure lock")
            .as_ref()
            .map_or_else(
                || io::Error::new(io::ErrorKind::BrokenPipe, "native stdout reader stopped"),
                |(kind, message)| io::Error::new(*kind, message.clone()),
            )
    }

    pub(super) fn is_failed(&self) -> bool {
        self.failed.is_cancelled()
    }

    pub(super) async fn failed(&self) {
        let mut listener = self.failed.subscribe();
        let _ = listener.cancelled().await;
    }

    pub(super) async fn write_json(&self, value: &Value, timeout: Duration) -> io::Result<()> {
        let line = serde_json::to_vec(value)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let result = fcp_async_core::time::timeout(timeout, async {
            let mut writer = self.writer.lock().await;
            if self.failed.is_cancelled() {
                return Err(self.failure_error());
            }
            let mut pending = NativeWriteGuard {
                transport: self,
                completed: false,
            };
            writer.write_all(&line).await?;
            writer.write_all(b"\n").await?;
            writer.flush().await?;
            pending.completed = true;
            Ok(())
        })
        .await
        .map_err(|_| connector_io_timeout_error("stdin write", timeout))
        .and_then(std::convert::identity);
        if let Err(error) = &result {
            self.fail(error);
        }
        result
    }

    /// Credits only come from the host's consumer acknowledgement boundary.
    pub(super) async fn acknowledge(&self, stream_id: &str, ack: &EventAck) -> io::Result<()> {
        validate_stream_id(stream_id)?;
        let notification = json!({
            "jsonrpc": "2.0",
            "method": "ack",
            "params": {"stream_id": stream_id, "ack": ack},
        });
        if serde_json::to_vec(&notification)
            .map_err(io::Error::other)?
            .len()
            >= CONTROL_RESPONSE_BYTES
        {
            return Err(io::Error::other(
                "native acknowledgement exceeded its byte limit",
            ));
        }
        self.write_json(&notification, CONNECTOR_RPC_IO_TIMEOUT)
            .await
    }

    pub(super) async fn close_stream(&self, stream_id: &str) -> io::Result<()> {
        validate_stream_id(stream_id)?;
        self.write_json(
            &json!({
                "jsonrpc": "2.0",
                "method": "stream_close",
                "params": {"stream_id": stream_id},
            }),
            CONNECTOR_RPC_IO_TIMEOUT,
        )
        .await
    }

    pub(super) fn spawn_reader(
        &self,
        stdout: ChildStdout,
    ) -> io::Result<(mpsc::Receiver<io::Result<NativeReply>>, JoinHandle<()>)> {
        let (responses, receiver) = mpsc::channel(REPLY_QUEUE_CAPACITY);
        let transport = self.clone();
        let reader_guard = NativeReaderGuard(self.clone());
        let task = task::try_spawn(async move {
            let _reader_guard = reader_guard;
            let mut stdout = BufReader::new(stdout);
            let result = transport.read_output(&mut stdout, &responses).await;
            if let Err(error) = result {
                transport.fail(&error);
                // Preserve an already queued reply, but never wait for queue
                // capacity after transport failure. The sticky error is also
                // observable by the RPC waiter and the idle dispatcher.
                let _ = responses.try_send(Err(error));
            }
        })
        .map_err(|error| {
            io::Error::other(format!("native stdout task admission failed: {error}"))
        })?;
        Ok((receiver, task))
    }

    async fn read_output(
        &self,
        stdout: &mut BufReader<ChildStdout>,
        responses: &mpsc::Sender<io::Result<NativeReply>>,
    ) -> io::Result<()> {
        loop {
            let (value, frame_bytes, response_limit) =
                read_frame(stdout, &self.response_limit).await?;
            match classify_output(value, frame_bytes, response_limit)? {
                NativeOutput::Reply(value) => {
                    responses
                        .try_send(Ok(NativeReply { value, frame_bytes }))
                        .map_err(|_| {
                            io::Error::other(
                                "native connector exceeded the pending RPC reply bound",
                            )
                        })?;
                }
                NativeOutput::Event(params) => {
                    let sink = self
                        .sink
                        .lock()
                        .map_err(|_| io::Error::other("native event sink lock poisoned"))?
                        .clone()
                        .ok_or_else(|| {
                            io::Error::other(
                                "native connector emitted an event without an authorized sink",
                            )
                        })?;
                    sink(&params.stream_id, params.event)?;
                }
            }
        }
    }
}

struct NativeReaderGuard(NativeEventTransport);

impl Drop for NativeReaderGuard {
    fn drop(&mut self) {
        // An aborted or panicked reader must wake an idle dispatcher as well
        // as an RPC already waiting on its now-disconnected reply channel.
        self.0.fail(&io::Error::new(
            io::ErrorKind::BrokenPipe,
            "native stdout reader stopped",
        ));
    }
}

struct NativeWriteGuard<'a> {
    transport: &'a NativeEventTransport,
    completed: bool,
}

impl Drop for NativeWriteGuard<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.transport.fail(&io::Error::new(
                io::ErrorKind::BrokenPipe,
                "native control write interrupted before frame completion",
            ));
        }
    }
}

async fn read_frame(
    stdout: &mut BufReader<ChildStdout>,
    response_limit: &AtomicUsize,
) -> io::Result<(Value, usize, usize)> {
    // No timer runs while the stream is idle. Once a frame begins, its
    // assembly has a fixed bound even if there is no ordinary RPC pending.
    let first_byte = stdout.read_u8().await.map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            io::Error::new(io::ErrorKind::UnexpectedEof, "connector closed stdout")
        } else {
            error
        }
    })?;
    let selected_response_limit = response_limit.load(Ordering::Acquire);
    let mut frame = ResponseFrame::new(selected_response_limit.max(MAX_EVENT_FRAME_BYTES));
    let (_, complete) = frame.append(&[first_byte])?;
    if !complete {
        fcp_async_core::time::timeout(
            FRAME_ASSEMBLY_TIMEOUT,
            std::future::poll_fn(|cx| {
                const BYTES_PER_POLL: usize = 64 * 1024;
                let mut scanned = 0;
                loop {
                    let chunk = std::task::ready!(Pin::new(&mut *stdout).poll_fill_buf(cx))?;
                    if chunk.is_empty() {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "connector closed stdout in an incomplete frame",
                        )));
                    }
                    let available = chunk.len().min(BYTES_PER_POLL - scanned);
                    let (consumed, complete) = frame.append(&chunk[..available])?;
                    Pin::new(&mut *stdout).consume(consumed);
                    if complete {
                        return Poll::Ready(Ok(()));
                    }
                    scanned += consumed;
                    if scanned == BYTES_PER_POLL {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
            }),
        )
        .await
        .map_err(|_| {
            connector_io_timeout_error("stdout frame assembly", FRAME_ASSEMBLY_TIMEOUT)
        })??;
    }
    let value = serde_json::from_slice(frame.bytes()).map_err(|error| {
        if frame.bytes().len() > selected_response_limit {
            io::Error::other(format!(
                "stdout frame exceeded {selected_response_limit} bytes"
            ))
        } else {
            io::Error::new(io::ErrorKind::InvalidData, error)
        }
    })?;
    Ok((value, frame.bytes().len(), selected_response_limit))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::atomic::AtomicU64;

    use fcp_core::{ConnectorId, EventData, InstanceId, Principal, TrustLevel, ZoneId};
    use proptest::prelude::*;

    use super::*;
    use crate::ConnectorProcessRunner;

    fn notification(sequence: u64) -> Value {
        let event = EventEnvelope::new(
            "telegram.message",
            EventData::new(
                ConnectorId::from_static("telegram:messaging:1.0.0"),
                InstanceId::new(),
                ZoneId::work(),
                Principal {
                    kind: "user".to_string(),
                    id: "fixture-user".to_string(),
                    trust: TrustLevel::Paired,
                    display: None,
                },
                json!({"text": "event payload"}),
            ),
        )
        .with_seq(sequence)
        .with_cursor(sequence.to_string())
        .requiring_ack();
        json!({
            "jsonrpc": "2.0",
            "method": "event",
            "params": {"stream_id": "stream-123", "event": event},
        })
    }

    #[test]
    fn event_notifications_and_provider_method_fields_are_not_rpc_ids() {
        let value = notification(4);
        let size = serde_json::to_vec(&value).unwrap().len() + 1;
        match classify_output(value, size, CONTROL_RESPONSE_BYTES).unwrap() {
            NativeOutput::Event(params) => {
                assert_eq!(params.stream_id, "stream-123");
                assert_eq!(params.event.seq, 4);
            }
            NativeOutput::Reply(_) => panic!("event became an RPC reply"),
        }
        let reply = json!({
            "jsonrpc": "2.0", "id": "0:0",
            "result": {"method": "event", "params": {"private": "provider payload"}},
        });
        match classify_output(reply.clone(), 128, CONTROL_RESPONSE_BYTES).unwrap() {
            NativeOutput::Reply(actual) => assert_eq!(actual, reply),
            NativeOutput::Event(_) => panic!("provider payload became an event"),
        }
    }

    #[test]
    fn events_have_an_independent_cap_even_during_large_invocations() {
        assert!(
            classify_output(notification(1), MAX_EVENT_FRAME_BYTES, MAX_RESPONSE_BYTES,).is_ok()
        );
        assert!(
            classify_output(
                notification(1),
                MAX_EVENT_FRAME_BYTES + 1,
                MAX_RESPONSE_BYTES,
            )
            .is_err()
        );
        assert!(
            classify_output(
                json!({"id": "0:0", "result": {}}),
                CONTROL_RESPONSE_BYTES + 1,
                CONTROL_RESPONSE_BYTES,
            )
            .is_err()
        );
    }

    #[test]
    fn event_envelopes_reject_ambiguous_requests_and_unknown_fields() {
        for field in ["id", "result", "error", "unexpected"] {
            let mut value = notification(1);
            value[field] = Value::Null;
            assert!(classify_output(value, 1024, CONTROL_RESPONSE_BYTES).is_err());
        }
        for method in ["ack", "health", "", "EVENT"] {
            let mut value = notification(1);
            value["method"] = json!(method);
            assert!(classify_output(value, 1024, CONTROL_RESPONSE_BYTES).is_err());
        }
        let mut value = notification(1);
        value["params"]["extra"] = json!(true);
        assert!(classify_output(value, 1024, CONTROL_RESPONSE_BYTES).is_err());
    }

    proptest! {
        #[test]
        fn wire_roundtrips_preserve_payload_and_never_accept_an_rpc_id(
            sequence in any::<u64>(),
            text in ".{0,2048}",
            outer_id in prop::option::of(any::<u64>()),
        ) {
            let mut value = notification(sequence);
            let payload = json!({"method": "ack", "id": outer_id, "result": text});
            value["params"]["event"]["data"]["payload"] = payload.clone();
            let wire = serde_json::to_vec(&value).unwrap();
            let decoded: Value = serde_json::from_slice(&wire).unwrap();
            match classify_output(decoded, wire.len() + 1, CONTROL_RESPONSE_BYTES).unwrap() {
                NativeOutput::Event(params) => {
                    prop_assert_eq!(params.event.seq, sequence);
                    prop_assert_eq!(params.event.data.payload, payload);
                }
                NativeOutput::Reply(_) => prop_assert!(false, "event was routed as a reply"),
            }
            // A nullable, numeric, or absent-looking outer ID must not turn
            // an RPC request into an independently delivered notification.
            value["id"] = json!(outer_id);
            let wire = serde_json::to_vec(&value).unwrap();
            let decoded: Value = serde_json::from_slice(&wire).unwrap();
            prop_assert!(classify_output(decoded, wire.len() + 1, CONTROL_RESPONSE_BYTES).is_err());
        }
    }

    #[cfg(unix)]
    async fn spawn_fixture(script: &str, events: &[Value]) -> ConnectorProcessRunner {
        let mut environment = BTreeMap::new();
        for (index, event) in events.iter().enumerate() {
            environment.insert(format!("NATIVE_EVENT_{index}"), event.to_string());
        }
        ConnectorProcessRunner::spawn(
            "/bin/sh",
            &["-c".to_string(), script.to_string()],
            &environment,
        )
        .await
        .unwrap()
    }

    #[cfg(unix)]
    #[fcp_async_core::runtime::test]
    async fn stdout_delivers_events_during_rpc_and_while_no_rpc_is_pending() {
        let script = r#"
IFS= read -r _request || exit 1
printf '%s\n' "$NATIVE_EVENT_0"
printf '%s\n' '{"jsonrpc":"2.0","id":"0:0","result":{"first":true}}'
printf '%s\n' "$NATIVE_EVENT_1"
IFS= read -r _request || exit 1
printf '%s\n' '{"jsonrpc":"2.0","id":"0:1","result":{"second":true}}'
while IFS= read -r _request; do :; done
"#;
        let mut runner = spawn_fixture(script, &[notification(1), notification(2)]).await;
        let (events_tx, mut events_rx) = mpsc::channel(2);
        runner
            .event_transport
            .install_sink(Arc::new(move |stream, event| {
                assert_eq!(stream, "stream-123");
                events_tx
                    .try_send(event.seq)
                    .map_err(|_| io::Error::other("fixture sink full"))
            }))
            .unwrap();
        let first = runner.request("health", json!({})).await.unwrap();
        assert_eq!(first["result"]["first"], true);
        for sequence in [1, 2] {
            let received = fcp_async_core::time::timeout(Duration::from_secs(2), events_rx.recv())
                .await
                .expect("idle stdout reader must deliver without another RPC");
            assert_eq!(received, Some(sequence));
        }
        let second = runner.request("health", json!({})).await.unwrap();
        assert_eq!(second["result"]["second"], true);
    }

    #[cfg(unix)]
    #[fcp_async_core::runtime::test]
    async fn acknowledgement_bypasses_a_provider_call_waiting_for_that_ack() {
        let script = r#"
IFS= read -r _request || exit 1
printf '%s\n' "$NATIVE_EVENT_0"
IFS= read -r ack || exit 1
case "$ack" in
  *'"method":"ack"'*) ;;
  *) exit 2 ;;
esac
printf '%s\n' '{"jsonrpc":"2.0","id":"0:0","result":{"acked":true}}'
IFS= read -r close || exit 1
case "$close" in
  *'"method":"stream_close"'*) ;;
  *) exit 3 ;;
esac
IFS= read -r _request || exit 1
printf '%s\n' '{"jsonrpc":"2.0","id":"0:1","result":{"closed":true}}'
while IFS= read -r _request; do :; done
"#;
        let mut runner = spawn_fixture(script, &[notification(7)]).await;
        let control = runner.event_transport.clone();
        let (events_tx, mut events_rx) = mpsc::channel(1);
        control
            .install_sink(Arc::new(move |_, event| {
                events_tx
                    .try_send(event)
                    .map_err(|_| io::Error::other("fixture sink full"))
            }))
            .unwrap();
        let invocation = task::try_spawn(async move {
            let reply = runner
                .request("invoke", json!({"operation": "webhook"}))
                .await;
            (runner, reply)
        })
        .unwrap();
        let event = fcp_async_core::time::timeout(Duration::from_secs(2), events_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let ack = EventAck::new(&event.topic, vec![event.seq]).with_cursors(vec![event.cursor]);
        control.acknowledge("stream-123", &ack).await.unwrap();
        let (mut runner, reply) = fcp_async_core::time::timeout(Duration::from_secs(2), invocation)
            .await
            .expect("ACK must not wait behind the in-flight invoke")
            .unwrap();
        assert_eq!(reply.unwrap()["result"]["acked"], true);
        control.close_stream("stream-123").await.unwrap();
        let reply = runner.request("health", json!({})).await.unwrap();
        assert_eq!(reply["result"]["closed"], true);
    }

    #[cfg(unix)]
    #[fcp_async_core::runtime::test]
    async fn unsolicited_events_and_a_full_sink_retire_without_silent_delivery() {
        let script = r#"
IFS= read -r _request || exit 1
printf '%s\n' "$NATIVE_EVENT_0"
printf '%s\n' "$NATIVE_EVENT_1"
printf '%s\n' '{"jsonrpc":"2.0","id":"0:0","result":{"must_not_succeed":true}}'
while IFS= read -r _request; do :; done
"#;
        let mut unauthorized = spawn_fixture(script, &[notification(1), notification(2)]).await;
        let error = unauthorized.request("health", json!({})).await.unwrap_err();
        assert!(error.to_string().contains("without an authorized sink"));
        assert!(unauthorized.request("health", json!({})).await.is_err());

        let mut full = spawn_fixture(script, &[notification(1), notification(2)]).await;
        let delivered = Arc::new(AtomicU64::new(0));
        let recorded = Arc::clone(&delivered);
        full.event_transport
            .install_sink(Arc::new(move |_, _| {
                if recorded.load(Ordering::Acquire) != 0 {
                    return Err(io::Error::other("fixture durable queue full"));
                }
                recorded.fetch_add(1, Ordering::AcqRel);
                Ok(())
            }))
            .unwrap();
        let error = full.request("health", json!({})).await.unwrap_err();
        assert!(error.to_string().contains("fixture durable queue full"));
        assert_eq!(delivered.load(Ordering::Acquire), 1);
    }

    #[cfg(unix)]
    #[fcp_async_core::runtime::test]
    async fn partial_frame_eof_and_cancelled_writes_cannot_reuse_transport() {
        let script = r#"
IFS= read -r _request || exit 1
printf '%s' '{"jsonrpc":"2.0","id":"0:0","result":{}}'
"#;
        let mut runner = spawn_fixture(script, &[]).await;
        let error = runner.request("health", json!({})).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        assert!(error.to_string().contains("incomplete frame"));
        assert!(runner.request("health", json!({})).await.is_err());

        let runner = spawn_fixture("while IFS= read -r _request; do :; done", &[]).await;
        let control = runner.event_transport.clone();
        drop(NativeWriteGuard {
            transport: &control,
            completed: false,
        });
        assert!(control.close_stream("stream-123").await.is_err());
        assert!(
            control
                .failure_error()
                .to_string()
                .contains("write interrupted")
        );
    }
}
