//! Bound untrusted mesh envelopes before JSON decoding and replay admission.
//!
//! Each admitted request reserves one complete wire-body allowance. The permit
//! remains live through signature verification and durable replay admission;
//! the handler releases it before running the authenticated operation. These
//! limits bound pending envelopes, not process RSS or already admitted work.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use axum::Json;
use axum::body::Body;
use axum::extract::{FromRequest, Request};
use axum::http::{StatusCode, header::CONTENT_LENGTH};
use futures_util::StreamExt;
use serde::de::DeserializeOwned;

/// Four 24 MiB wire bodies may be pending at once (96 MiB of wire data).
/// Decoded JSON, framing, and allocator overhead are additional to that bound.
const MAX_PENDING_ENVELOPES: usize = 4;
/// A total upload deadline: receiving another chunk does not reset this clock.
const BODY_READ_TIMEOUT: Duration = Duration::from_secs(5);
/// Yield even when a peer keeps supplying immediately ready or empty chunks.
const CHUNKS_BEFORE_YIELD: usize = 64;

type Rejection = (StatusCode, &'static str);

#[derive(Clone)]
pub(super) struct Intake(Arc<Runtime>);

struct Runtime {
    active: AtomicUsize,
    maximum_pending: usize,
    maximum_body_bytes: usize,
    body_read_timeout: Duration,
}

impl Default for Intake {
    fn default() -> Self {
        Self::new(
            super::MESH_FORWARD_HTTP_BODY_LIMIT_BYTES,
            MAX_PENDING_ENVELOPES,
            BODY_READ_TIMEOUT,
        )
    }
}

impl Intake {
    fn new(maximum_body_bytes: usize, maximum_pending: usize, body_read_timeout: Duration) -> Self {
        Self(Arc::new(Runtime {
            active: AtomicUsize::new(0),
            maximum_pending,
            maximum_body_bytes,
            body_read_timeout,
        }))
    }

    fn acquire(&self) -> Result<Permit, Rejection> {
        self.0
            .active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < self.0.maximum_pending).then(|| active + 1)
            })
            .map_err(|_| {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "mesh forward intake is at capacity",
                )
            })?;
        Ok(Permit(Arc::clone(&self.0)))
    }
}

/// Dropping the request/extractor on any failure or disconnect frees its slot.
pub(super) struct Permit(Arc<Runtime>);

impl Drop for Permit {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::AcqRel);
    }
}

/// JSON and the still-held unauthenticated-intake reservation.
pub(super) struct AdmittedJson<T> {
    pub(super) value: T,
    pub(super) permit: Permit,
}

#[cfg(test)]
impl<T> AdmittedJson<T> {
    /// Direct handler tests bypass HTTP framing, but still exercise ownership
    /// and release of an actual intake reservation.
    pub(super) fn for_test(value: T) -> Self {
        Self {
            value,
            permit: Intake::default().acquire().expect("fresh test intake"),
        }
    }
}

impl<S, T> FromRequest<S> for AdmittedJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned + Send,
{
    type Rejection = Rejection;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        let intake = request.extensions().get::<Intake>().cloned().ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "mesh forward intake is unavailable",
        ))?;
        // Never queue: body collection and JSON allocation start only when
        // capacity for the entire envelope is available.
        let permit = intake.acquire()?;
        if let Some(length) = request.headers().get(CONTENT_LENGTH) {
            let length = length
                .to_str()
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "mesh forward body length is invalid",
                ))?;
            if length > intake.0.maximum_body_bytes as u64 {
                return Err(payload_too_large());
            }
        }

        let (parts, body) = request.into_parts();
        let read_deadline = Instant::now() + intake.0.body_read_timeout;
        let bytes = fcp_async_core::time::timeout(
            intake.0.body_read_timeout,
            read_body(body, intake.0.maximum_body_bytes, read_deadline),
        )
        .await
        .map_err(|_| body_read_timeout())??;
        let request = Request::from_parts(parts, Body::from(bytes));
        let Json(value) = Json::<T>::from_request(request, state)
            .await
            // Detailed serde rejections can contain untrusted field contents.
            // Keep the HTTP status, but never echo the envelope or its tokens.
            .map_err(|error| (error.status(), "mesh forward envelope is invalid"))?;
        Ok(Self { value, permit })
    }
}

fn payload_too_large() -> Rejection {
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        "mesh forward body exceeds the wire limit",
    )
}

fn body_read_timeout() -> Rejection {
    (
        StatusCode::REQUEST_TIMEOUT,
        "mesh forward body read timed out",
    )
}

async fn read_body(body: Body, maximum: usize, deadline: Instant) -> Result<Vec<u8>, Rejection> {
    let mut stream = body.into_data_stream();
    let mut bytes = Vec::new();
    let mut chunks_since_yield = 0;
    loop {
        // A stream that stays ready need not yield to the timeout's timer.
        // Check the same monotonic deadline inside the collector as well.
        if Instant::now() >= deadline {
            return Err(body_read_timeout());
        }
        let next = stream.next().await;
        if Instant::now() >= deadline {
            return Err(body_read_timeout());
        }
        let Some(chunk) = next else {
            break;
        };
        let chunk = chunk.map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "mesh forward body could not be read",
            )
        })?;
        if chunk.len() > maximum.saturating_sub(bytes.len()) {
            return Err(payload_too_large());
        }
        let next_length = bytes.len() + chunk.len();
        if next_length > bytes.capacity() {
            // Do not round a near-limit upload up to another full allocation.
            let capacity = next_length.max(bytes.capacity().saturating_mul(2).min(maximum));
            bytes
                .try_reserve_exact(capacity - bytes.len())
                .map_err(|_| {
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "mesh forward intake is unavailable",
                    )
                })?;
        }
        bytes.extend_from_slice(&chunk);
        chunks_since_yield += 1;
        if chunks_since_yield == CHUNKS_BEFORE_YIELD {
            chunks_since_yield = 0;
            fcp_async_core::task::yield_now().await;
        }
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::task::Poll;

    use axum::body::{Bytes, to_bytes};
    use axum::extract::DefaultBodyLimit;
    use axum::routing::post;
    use axum::{Extension, Router};
    use futures_util::{poll, stream};
    use serde_json::{Value, json};
    use tower::ServiceExt;

    use super::*;

    const ROUTE: &str = fcp_host::mesh_routing::MESH_FORWARD_ROUTE;

    fn intake(maximum: usize, pending: usize, timeout: Duration) -> Intake {
        Intake::new(maximum, pending, timeout)
    }

    fn app(intake: Intake) -> Router {
        let maximum = intake.0.maximum_body_bytes;
        Router::new()
            .route(
                ROUTE,
                post(
                    |AdmittedJson { value, permit }: AdmittedJson<Value>| async move {
                        drop(permit);
                        Json(value)
                    },
                ),
            )
            .layer(DefaultBodyLimit::max(maximum))
            .layer(Extension(intake))
    }

    fn request(body: Body) -> Request {
        Request::builder()
            .method("POST")
            .uri(ROUTE)
            .header("content-type", "application/json")
            .body(body)
            .expect("mesh HTTP request")
    }

    fn active(intake: &Intake) -> usize {
        intake.0.active.load(Ordering::Acquire)
    }

    #[fcp_async_core::runtime::test]
    async fn declared_oversize_is_rejected_before_body_poll_and_frees_capacity() {
        let intake = intake(32, 1, Duration::from_secs(1));
        let app = app(intake.clone());
        let body = Body::from_stream(stream::poll_fn(
            |_| -> Poll<Option<Result<Bytes, Infallible>>> {
                panic!("oversized declared body must not be polled")
            },
        ));
        let mut oversized = request(body);
        oversized
            .headers_mut()
            .insert(CONTENT_LENGTH, "33".parse().unwrap());
        let response = app.clone().oneshot(oversized).await.unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(active(&intake), 0);
        assert_eq!(
            app.oneshot(request(Body::from("{}")))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
    }

    #[fcp_async_core::runtime::test]
    async fn chunked_body_enforces_actual_bytes_and_accepts_exact_limit() {
        let intake = intake(32, 1, Duration::from_secs(1));
        let app = app(intake.clone());
        let chunks = stream::iter([
            Ok::<_, Infallible>(Bytes::from_static(b"                 ")),
            Ok(Bytes::from_static(b"                 ")),
        ]);
        let mut oversized = request(Body::from_stream(chunks));
        // A smaller declared length never overrides actual bytes consumed.
        oversized
            .headers_mut()
            .insert(CONTENT_LENGTH, "1".parse().unwrap());
        assert_eq!(
            app.clone().oneshot(oversized).await.unwrap().status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(active(&intake), 0);
        let exact = format!("{}{{}}", " ".repeat(30));
        let response = app.oneshot(request(Body::from(exact))).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(to_bytes(response.into_body(), 32).await.unwrap(), "{}");
    }

    #[fcp_async_core::runtime::test]
    async fn concurrent_uploads_fail_fast_and_dropped_request_releases_slot() {
        let intake = intake(32, MAX_PENDING_ENVELOPES, Duration::from_secs(5));
        let app = app(intake.clone());
        let mut uploads = Vec::new();
        for _ in 0..MAX_PENDING_ENVELOPES {
            let body = Body::from_stream(stream::pending::<Result<Bytes, Infallible>>());
            let mut upload = Box::pin(app.clone().oneshot(request(body)));
            assert!(poll!(upload.as_mut()).is_pending());
            uploads.push(upload);
        }
        assert_eq!(active(&intake), MAX_PENDING_ENVELOPES);
        let response = fcp_async_core::time::timeout(
            Duration::from_millis(100),
            app.clone().oneshot(request(Body::from("{}"))),
        )
        .await
        .expect("saturation must fail immediately instead of waiting")
        .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        drop(uploads.pop());
        assert_eq!(active(&intake), MAX_PENDING_ENVELOPES - 1);
        assert_eq!(
            app.oneshot(request(Body::from("{}")))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        drop(uploads);
        assert_eq!(active(&intake), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn slow_trickle_uses_one_total_deadline_and_releases_capacity() {
        let intake = intake(4096, 1, Duration::from_millis(35));
        let app = app(intake.clone());
        let chunks = stream::unfold(0_u32, |index| async move {
            if index > 0 {
                fcp_async_core::time::sleep(Duration::from_millis(10)).await;
            }
            Some((Ok::<_, Infallible>(Bytes::from_static(b" ")), index + 1))
        });
        let response = fcp_async_core::time::timeout(
            Duration::from_secs(1),
            app.clone().oneshot(request(Body::from_stream(chunks))),
        )
        .await
        .expect("successive chunks must not extend the upload deadline")
        .unwrap();
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        assert_eq!(active(&intake), 0);
        assert_eq!(
            app.oneshot(request(Body::from("{}")))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
    }

    #[fcp_async_core::runtime::test]
    async fn always_ready_empty_chunks_cannot_starve_upload_deadline() {
        let intake = intake(256, 1, Duration::from_millis(20));
        let app = app(intake.clone());
        let chunks = stream::repeat(Ok::<_, Infallible>(Bytes::new()));
        let response = fcp_async_core::time::timeout(
            Duration::from_secs(1),
            app.oneshot(request(Body::from_stream(chunks))),
        )
        .await
        .expect("ready chunks cannot prevent timeout progress")
        .unwrap();
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        assert_eq!(active(&intake), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn stream_and_json_errors_release_permits_without_echoing_input() {
        let intake = intake(256, 1, Duration::from_secs(1));
        let app = app(intake.clone());
        let secret = "mesh-intake-secret-canary";
        let body = Body::from_stream(stream::iter([Err::<Bytes, _>(std::io::Error::other(
            secret,
        ))]));
        let response = app.clone().oneshot(request(body)).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let bytes = to_bytes(response.into_body(), 256).await.unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains(secret));
        assert_eq!(active(&intake), 0);

        let response = app
            .clone()
            .oneshot(request(Body::from(format!("{{\"{secret}\":"))))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            to_bytes(response.into_body(), 256).await.unwrap(),
            "mesh forward envelope is invalid"
        );
        assert_eq!(active(&intake), 0);
        assert_eq!(
            app.oneshot(request(Body::from("{}")))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
    }

    #[fcp_async_core::runtime::test]
    async fn permit_covers_authentication_but_releases_before_long_execution() {
        let intake = intake(256, 1, Duration::from_secs(1));
        let (admit_tx, admit_rx) = fcp_async_core::channel::oneshot::channel::<()>();
        let (finish_tx, finish_rx) = fcp_async_core::channel::oneshot::channel::<()>();
        let gates = Arc::new(std::sync::Mutex::new(Some((admit_rx, finish_rx))));
        let app = Router::new()
            .route(
                ROUTE,
                post(move |AdmittedJson { value, permit }: AdmittedJson<Value>| {
                    let gates = Arc::clone(&gates);
                    async move {
                        if value == json!({"method": "invoke"}) {
                            let (admit, finish) = gates.lock().unwrap().take().unwrap();
                            admit.await.unwrap();
                            drop(permit);
                            finish.await.unwrap();
                        } else {
                            drop(permit);
                        }
                        StatusCode::OK
                    }
                }),
            )
            .layer(Extension(intake.clone()));
        let mut invocation = Box::pin(
            app.clone()
                .oneshot(request(Body::from(r#"{"method":"invoke"}"#))),
        );
        assert!(poll!(invocation.as_mut()).is_pending());
        assert_eq!(active(&intake), 1);
        assert_eq!(
            app.clone()
                .oneshot(request(Body::from("{}")))
                .await
                .unwrap()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "decoded requests waiting for authentication still consume capacity"
        );
        admit_tx.send(()).unwrap();
        assert!(poll!(invocation.as_mut()).is_pending());
        assert_eq!(active(&intake), 0);
        for method in ["cancel", "stream_ack"] {
            let body = Body::from(json!({"method": method}).to_string());
            assert_eq!(
                app.clone().oneshot(request(body)).await.unwrap().status(),
                StatusCode::OK,
                "authenticated long-running work must not block control messages"
            );
        }
        finish_tx.send(()).unwrap();
        assert_eq!(invocation.await.unwrap().status(), StatusCode::OK);
        assert_eq!(active(&intake), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn missing_route_intake_fails_closed() {
        let app = Router::new().route(
            ROUTE,
            post(|_: AdmittedJson<Value>| async { StatusCode::OK }),
        );
        let response = app.oneshot(request(Body::from("{}"))).await.unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn loopback_saturation_disconnect_and_healthy_request() {
        use fcp_async_core::io::{AsyncReadExt, AsyncWriteExt};
        use fcp_async_core::net::{TcpListener, TcpStream};

        async fn wait_for_active(intake: &Intake, expected: usize) {
            fcp_async_core::time::timeout(Duration::from_secs(2), async {
                while active(intake) != expected {
                    fcp_async_core::time::sleep(Duration::from_millis(1)).await;
                }
            })
            .await
            .expect("connection must enter or release intake");
        }

        async fn exchange(address: std::net::SocketAddr) -> String {
            let mut stream = TcpStream::connect(address).await.unwrap();
            let request = format!(
                "POST {ROUTE} HTTP/1.1\r\nHost: localhost\r\n\
                 Content-Type: application/json\r\nContent-Length: 2\r\n\
                 Connection: close\r\n\r\n{{}}"
            );
            stream.write_all(request.as_bytes()).await.unwrap();
            let mut response = Vec::new();
            fcp_async_core::time::timeout(
                Duration::from_secs(2),
                stream.read_to_end(&mut response),
            )
            .await
            .expect("HTTP refusal must not wait for another upload")
            .unwrap();
            String::from_utf8(response).unwrap()
        }

        let intake = intake(256, 1, Duration::from_secs(3));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = app(intake.clone());
        let (shutdown_tx, shutdown_rx) = fcp_async_core::channel::watch::channel(false);
        let server = fcp_async_core::task::spawn(async move {
            super::super::serve_tcp(listener, app, shutdown_rx).await
        });
        let mut stalled = TcpStream::connect(address).await.unwrap();
        let request = format!(
            "POST {ROUTE} HTTP/1.1\r\nHost: localhost\r\n\
             Content-Type: application/json\r\nContent-Length: 128\r\n\
             Connection: close\r\n\r\n{{"
        );
        stalled.write_all(request.as_bytes()).await.unwrap();
        wait_for_active(&intake, 1).await;
        let saturated = exchange(address).await;
        assert!(saturated.starts_with("HTTP/1.1 503"), "{saturated}");

        // The peer disconnects without delivering its declared body. Hyper's
        // body error must release the permit without waiting for the deadline.
        drop(stalled);
        wait_for_active(&intake, 0).await;
        let healthy = exchange(address).await;
        assert!(healthy.starts_with("HTTP/1.1 200"), "{healthy}");
        assert_eq!(active(&intake), 0);

        shutdown_tx.send(true).unwrap();
        fcp_async_core::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("loopback server must stop")
            .expect("loopback server task")
            .expect("loopback server");
    }
}
