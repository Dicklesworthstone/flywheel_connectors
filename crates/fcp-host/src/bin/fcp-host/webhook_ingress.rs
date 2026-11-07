//! Opt-in public HTTP delivery to the authenticated webhook-receiver operation.
//!
//! The host owns the listener, body budgets and invocation authority. Provider
//! authentication and replay admission remain in the receiver. A public caller
//! can supply a delivery, never a connector, zone, capability or approval.

use std::future::Future;
use std::io::Read;
use std::sync::atomic::AtomicUsize;

use fcp_host::webhook_ingress::{
    WEBHOOK_INGRESS_ROUTE, WebhookIngressConfig, WebhookIngressError, response_for,
};
use futures_util::StreamExt;

use super::*;

const CONFIG_ENV: &str = "FCP_HOST_WEBHOOK_INGRESS_CONFIG_FILE";
const MAX_CONFIG_BYTES: usize = 64 * 1024;
const MAX_TOKEN_BYTES: usize = 32 * 1024;
const MAX_HOLDER_KEY_BYTES: usize = 128;

/// Only the TCP accept loop creates this extension. Forwarded headers never do.
#[derive(Clone, Copy)]
pub(super) struct PeerAddress(pub SocketAddr);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    connector_id: ConnectorId,
    zone_id: ZoneId,
    public_base_url: String,
    capability_token_file: PathBuf,
    #[serde(default)]
    holder_key_file: Option<PathBuf>,
    #[serde(default = "default_max_body_bytes")]
    max_body_bytes: usize,
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,
    #[serde(default = "default_max_in_flight")]
    max_in_flight: usize,
}

const fn default_max_body_bytes() -> usize {
    1024 * 1024
}

const fn default_timeout_ms() -> u64 {
    15_000
}

const fn default_max_in_flight() -> usize {
    8
}

fn invalid_config(message: &str) -> HostError {
    HostError::InvalidFilter(format!("webhook ingress: {message}"))
}

fn read_bounded(path: &StdPath, maximum: usize) -> HostResult<zeroize::Zeroizing<Vec<u8>>> {
    let metadata =
        std::fs::metadata(path).map_err(|_| invalid_config("cannot read configured file"))?;
    if !metadata.is_file() || metadata.len() > maximum as u64 {
        return Err(invalid_config(
            "configured file is not a bounded regular file",
        ));
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    // An operator can rotate this path while a request is being admitted. Do
    // not block if a regular file is replaced by a FIFO between stat and open.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let mut file = options
        .open(path)
        .map_err(|_| invalid_config("cannot open configured file"))?;
    let metadata = file
        .metadata()
        .map_err(|_| invalid_config("cannot inspect configured file"))?;
    if !metadata.is_file() || metadata.len() > maximum as u64 {
        return Err(invalid_config(
            "configured file is not a bounded regular file",
        ));
    }
    // Allocate the entire bound, including an overflow sentinel, before any
    // secret bytes arrive. A growing Vec can leave earlier copies in freed
    // allocations that its final zeroizing wrapper cannot clear.
    let capacity = maximum
        .checked_add(1)
        .ok_or_else(|| invalid_config("configured file byte limit is invalid"))?;
    let mut bytes = zeroize::Zeroizing::new(vec![0_u8; capacity]);
    let mut length = 0;
    loop {
        match file.read(&mut bytes[length..]) {
            Ok(0) => break,
            Ok(read) => {
                length += read;
                if length > maximum {
                    return Err(invalid_config("configured file exceeds its byte limit"));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(invalid_config("cannot read configured file")),
        }
    }
    bytes.truncate(length);
    Ok(bytes)
}

fn read_holder_key(path: &StdPath) -> Result<fcp_crypto::Ed25519SigningKey, WebhookIngressError> {
    let bytes =
        read_bounded(path, MAX_HOLDER_KEY_BYTES).map_err(|_| WebhookIngressError::Unavailable)?;
    let mut secret = zeroize::Zeroizing::new([0_u8; 32]);
    if bytes.len() == secret.len() {
        secret.copy_from_slice(&bytes);
    } else {
        let encoded = std::str::from_utf8(&bytes)
            .map_err(|_| WebhookIngressError::Unavailable)?
            .trim();
        if encoded.len() != 64 {
            return Err(WebhookIngressError::Unavailable);
        }
        hex::decode_to_slice(encoded, &mut *secret)
            .map_err(|_| WebhookIngressError::Unavailable)?;
    }
    fcp_crypto::Ed25519SigningKey::from_bytes(&secret).map_err(|_| WebhookIngressError::Unavailable)
}

/// The binding is fixed at startup. Authority is provisioned after the receiver
/// has a live instance and can then be rotated without changing that instance.
pub(super) struct ConfiguredIngress {
    binding: WebhookIngressConfig,
    token_file: PathBuf,
    holder_key_file: Option<PathBuf>,
}

impl FileConfig {
    fn into_config(self) -> HostResult<ConfiguredIngress> {
        if !self.capability_token_file.is_absolute() {
            return Err(invalid_config("capability_token_file must be absolute"));
        }
        if self
            .holder_key_file
            .as_ref()
            .is_some_and(|path| !path.is_absolute())
        {
            return Err(invalid_config("holder_key_file must be absolute"));
        }
        let binding = WebhookIngressConfig::without_capability_token(
            self.connector_id,
            self.zone_id,
            self.public_base_url,
            self.max_body_bytes,
            self.timeout_ms,
            self.max_in_flight,
        )
        .map_err(|error| invalid_config(&error.to_string()))?;
        Ok(ConfiguredIngress {
            binding,
            token_file: self.capability_token_file,
            holder_key_file: self.holder_key_file,
        })
    }
}

/// Validate once, before connector processes start. Missing config mounts no
/// public receiver route. A missing capability file leaves the route inactive
/// until an operator publishes a capability for the prepared receiver instance.
pub(super) fn from_env() -> HostResult<Option<ConfiguredIngress>> {
    let Some(path) = read_optional_trimmed_env_string(CONFIG_ENV)? else {
        return Ok(None);
    };
    let bytes = read_bounded(StdPath::new(&path), MAX_CONFIG_BYTES)?;
    let config: FileConfig = serde_json::from_slice(&bytes)
        .map_err(|_| invalid_config("configuration is malformed or contains unknown fields"))?;
    config.into_config().map(Some)
}

struct IngressRuntime {
    config: WebhookIngressConfig,
    token_file: Option<PathBuf>,
    holder_key_file: Option<PathBuf>,
    active: AtomicUsize,
}

impl IngressRuntime {
    #[cfg(test)]
    fn new(config: WebhookIngressConfig) -> Self {
        Self {
            config,
            token_file: None,
            holder_key_file: None,
            active: AtomicUsize::new(0),
        }
    }

    fn configured(config: ConfiguredIngress) -> Self {
        Self {
            config: config.binding,
            token_file: Some(config.token_file),
            holder_key_file: config.holder_key_file,
            active: AtomicUsize::new(0),
        }
    }

    fn current_authority(&self) -> Result<WebhookIngressConfig, WebhookIngressError> {
        let Some(path) = &self.token_file else {
            return Ok(self.config.clone());
        };
        let bytes =
            read_bounded(path, MAX_TOKEN_BYTES).map_err(|_| WebhookIngressError::Unavailable)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| WebhookIngressError::Unavailable)?;
        let token = capability_token_from_cbor_b64(text, CONFIG_ENV)
            .map_err(|_| WebhookIngressError::Unavailable)?;
        let holder_key = self
            .holder_key_file
            .as_deref()
            .map(read_holder_key)
            .transpose()?;
        // Never cache authority: removal, corruption and expiry must not fall
        // back to a previously accepted token or signer. Normal host admission
        // verifies the capability and current membership's holder key. Validate
        // signing context before reading potentially large provider bodies.
        self.config
            .clone()
            .with_execution_authority(token, holder_key)
    }

    fn admit(&self) -> Result<IngressPermit<'_>, WebhookIngressError> {
        self.active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < self.config.max_in_flight()).then_some(active + 1)
            })
            .map_err(|_| WebhookIngressError::TooManyRequests)?;
        Ok(IngressPermit(self))
    }

    /// The same bounded path is used by the live route and controlled transport
    /// tests. There is no waiter queue and no task spawned by this adapter.
    async fn receive<F, Fut>(&self, request: Request<Body>, dispatch: F) -> (StatusCode, Value)
    where
        F: FnOnce(InvokeRequest, Instant) -> Fut,
        Fut: Future<Output = Result<InvokeResponse, (StatusCode, String)>>,
    {
        let started = Instant::now();
        let deadline = started + Duration::from_millis(self.config.timeout_ms());
        let _permit = match self.admit() {
            Ok(permit) => permit,
            Err(error) => return error.response(),
        };
        let (parts, body) = request.into_parts();
        if parts.method != axum::http::Method::POST {
            return WebhookIngressError::MethodNotAllowed.response();
        }
        if let Err(error) = self
            .config
            .validate_request_head(&parts.headers, &parts.uri)
        {
            return error.response();
        }
        if let Some(length) = parts.headers.get(axum::http::header::CONTENT_LENGTH) {
            let length = length.to_str().ok().and_then(|text| {
                (!text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()))
                    .then(|| text.parse::<u64>().ok())
                    .flatten()
            });
            match length {
                Some(length) if length <= self.config.max_body_bytes() as u64 => {}
                Some(_) => return WebhookIngressError::PayloadTooLarge.response(),
                None => {
                    return WebhookIngressError::InvalidInput("invalid content length").response();
                }
            }
        }
        let authority = match self.current_authority() {
            Ok(authority) => authority,
            Err(error) => return error.response(),
        };
        let peer_ip = parts
            .extensions
            .get::<PeerAddress>()
            .map(|peer| peer.0.ip());
        // Bound bytes during collection, including bodies without Content-Length.
        // The timeout includes header validation and bounded local authority
        // loading; it is never restarted for dispatch.
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return WebhookIngressError::Timeout.response();
        }
        let body = match fcp_async_core::time::timeout(
            remaining,
            read_body(body, self.config.max_body_bytes()),
        )
        .await
        {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(error)) => return error.response(),
            Err(_) => return WebhookIngressError::Timeout.response(),
        };
        let Ok(body) = std::str::from_utf8(&body) else {
            return WebhookIngressError::InvalidInput("request body must be UTF-8").response();
        };
        let mut invocation =
            match authority.build_request(&parts.headers, &parts.uri, body, peer_ip) {
                Ok(invocation) => invocation,
                Err(error) => return error.response(),
            };
        if Instant::now() >= deadline {
            return WebhookIngressError::Timeout.response();
        }
        constrain_invoke_deadline(&mut invocation, deadline);
        let request_id = invocation.id.clone();
        // The ordinary host route owns cancellation, durable execution and the
        // remaining deadline. Dropping a caller never claims to undo an effect.
        let response = match fcp_async_core::time::timeout(
            deadline.saturating_duration_since(Instant::now()),
            dispatch(invocation, deadline),
        )
        .await
        {
            Ok(response) => response,
            Err(_) => return WebhookIngressError::Timeout.response(),
        };
        if Instant::now() >= deadline {
            return WebhookIngressError::Timeout.response();
        }
        match response {
            Ok(response) if response.id == request_id => response_for(&response),
            Ok(_) => WebhookIngressError::InvalidResponse.response(),
            Err((status, _)) if status == StatusCode::TOO_MANY_REQUESTS => {
                WebhookIngressError::TooManyRequests.response()
            }
            Err((status, _)) if status == StatusCode::GATEWAY_TIMEOUT => {
                WebhookIngressError::Timeout.response()
            }
            Err(_) => WebhookIngressError::Unavailable.response(),
        }
    }
}

async fn read_body(body: Body, maximum: usize) -> Result<Vec<u8>, WebhookIngressError> {
    let mut stream = body.into_data_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk
            .map_err(|_| WebhookIngressError::InvalidInput("request body could not be read"))?;
        if chunk.len() > maximum.saturating_sub(bytes.len()) {
            return Err(WebhookIngressError::PayloadTooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

struct IngressPermit<'a>(&'a IngressRuntime);

impl Drop for IngressPermit<'_> {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::AcqRel);
    }
}

struct Service {
    host: Arc<AppState>,
    runtime: IngressRuntime,
}

pub(super) fn routes(
    host: Arc<AppState>,
    config: Option<ConfiguredIngress>,
) -> Router<Arc<AppState>> {
    let Some(config) = config else {
        return Router::new();
    };
    Router::new()
        .route(WEBHOOK_INGRESS_ROUTE, post(receive))
        .with_state(Arc::new(Service {
            host,
            runtime: IngressRuntime::configured(config),
        }))
}

async fn receive(
    State(service): State<Arc<Service>>,
    request: Request<Body>,
) -> (StatusCode, Json<Value>) {
    let started = Instant::now();
    let host = &service.host;
    let (status, body) = service
        .runtime
        .receive(request, |mut invocation, deadline| async move {
            // The active fencing sequence is host-owned configuration. Public
            // headers and provider data never select a lease or its epoch.
            if host
                .registry
                .allow_list_snapshot(&invocation.connector_id)
                .await
                .is_some_and(|snapshot| snapshot.singleton_writer)
            {
                invocation.lease_seq = current_hrw_lease_routing_config()
                    .map_err(map_host_error)?
                    .and_then(|routing| routing.current_lease_seq);
            }
            // No outer provider headers reach principal or capability admission.
            route_invoke_with_deadline(host, invocation, None, Some(deadline)).await
        })
        .await;
    tracing::info!(
        event = "webhook_ingress_response",
        status_code = status.as_u16(),
        duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        "webhook ingress completed"
    );
    (status, Json(body))
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::task::Poll;

    use futures_util::{poll, stream};

    use super::*;

    fn runtime(maximum: usize, timeout_ms: u64, concurrency: usize) -> IngressRuntime {
        IngressRuntime::new(
            WebhookIngressConfig::new(
                ConnectorId::from_static("fcp.webhook-receiver"),
                ZoneId::work(),
                fcp_core::CapabilityToken::test_token(),
                "https://hooks.example.test/webhooks".to_owned(),
                maximum,
                timeout_ms,
                concurrency,
            )
            .expect("valid ingress config"),
        )
    }

    fn request(body: Body) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/webhooks/incoming")
            .header("content-type", "application/json")
            .header("x-signature", "provider-signature")
            .body(body)
            .expect("request")
    }

    fn accepted(invocation: InvokeRequest) -> InvokeResponse {
        InvokeResponse::ok(
            invocation.id,
            json!({
                "accepted": true,
                "status_code": 202,
                "event": { "payload": "private-provider-data" },
                "ingest_log": { "signature": "private-authentication-evidence" },
            }),
        )
    }

    fn publish_holder_token(path: &StdPath, holder: Option<&str>, jti: Option<&[u8]>) {
        let issuer = fcp_crypto::Ed25519SigningKey::from_bytes(&[71; 32]).unwrap();
        let mut claims = fcp_crypto::cose::CwtClaims::new()
            .capability_id("webhook.events.write")
            .zone_id("z:work")
            .operations(&["webhook.events.ingest"]);
        if let Some(holder) = holder {
            claims = claims.holder_node(holder);
        }
        if let Some(jti) = jti {
            claims = claims.token_id(jti);
        }
        let token = fcp_crypto::cose::CoseToken::sign(&issuer, &claims).unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(token.to_cbor().unwrap());
        let next = path.with_extension("next");
        std::fs::write(&next, encoded).unwrap();
        std::fs::rename(next, path).unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn webhook_runtime_returns_verification_only_after_bound_receiver_success() {
        let runtime = runtime(1024, 15_000, 8);
        let raw =
            r#"{"type":"url_verification","challenge":"untrusted-input","token":"private-token"}"#;
        for matching_request in [true, false] {
            let (status, body) = runtime
                .receive(request(Body::from(raw)), |invocation, _| async move {
                    assert_eq!(invocation.input["body"], raw);
                    Ok(InvokeResponse::ok(
                        if matching_request {
                            invocation.id
                        } else {
                            RequestId::new("unrelated-invocation")
                        },
                        json!({
                            "accepted": true,
                            "status_code": 200,
                            "verification": {
                                "provider": "slack",
                                "kind": "url_verification",
                                "challenge": "authenticated-output",
                            },
                            "token": "private-token",
                        }),
                    ))
                })
                .await;
            if matching_request {
                assert_eq!(status, StatusCode::OK);
                assert_eq!(body, json!({"challenge": "authenticated-output"}));
            } else {
                assert_eq!(status, StatusCode::BAD_GATEWAY);
                assert!(body.get("challenge").is_none());
            }
            assert!(!body.to_string().contains("untrusted-input"));
            assert!(!body.to_string().contains("private-token"));
        }
        let (status, body) = runtime
            .receive(request(Body::from(raw)), |invocation, _| async move {
                Ok(InvokeResponse::error(
                    invocation.id,
                    fcp_core::FcpError::InvalidSignature,
                ))
            })
            .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(body.get("challenge").is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn webhook_runtime_preserves_bytes_and_uses_only_observed_peer_identity() {
        let runtime = runtime(1024, 15_000, 8);
        let raw = "{ \"message\" : \"unchanged\" }\n";
        let mut request = request(Body::from(raw));
        *request.uri_mut() = "/webhooks/incoming?bodySHA256=abc&name=a%2Bb"
            .parse()
            .expect("raw URI");
        request.extensions_mut().insert(PeerAddress(
            "192.0.2.23:8081".parse().expect("actual transport peer"),
        ));
        request
            .headers_mut()
            .insert("x-forwarded-for", HeaderValue::from_static("127.0.0.1"));
        request.headers_mut().insert(
            "x-forwarded-host",
            HeaderValue::from_static("attacker.test"),
        );
        request
            .headers_mut()
            .insert("x-principal", HeaderValue::from_static("owner"));
        let (status, response) = runtime
            .receive(request, |invocation, deadline| async move {
                assert_eq!(invocation.input["body"], raw);
                assert_eq!(invocation.input["path"], "/incoming");
                assert_eq!(invocation.input["source_ip"], "192.0.2.23");
                assert_eq!(
                    invocation.input["url"],
                    "https://hooks.example.test/webhooks/incoming?bodySHA256=abc&name=a%2Bb"
                );
                assert_eq!(invocation.zone_id, ZoneId::work());
                assert_eq!(invocation.operation.as_str(), "webhook.events.ingest");
                assert!(deadline > Instant::now());
                assert!(invocation.deadline_ms.is_some_and(|ms| ms <= 15_000));
                Ok(accepted(invocation))
            })
            .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(response["accepted"], true);
        let public = response.to_string();
        assert!(!public.contains("private-"));
        assert_eq!(runtime.active.load(Ordering::Acquire), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn webhook_runtime_never_asserts_a_forwarded_ip_without_a_transport_peer() {
        let runtime = runtime(1024, 15_000, 1);
        let mut request = request(Body::from("{}"));
        request
            .headers_mut()
            .insert("x-forwarded-for", HeaderValue::from_static("127.0.0.1"));
        let (status, _) = runtime
            .receive(request, |invocation, _| async move {
                assert!(invocation.input.get("source_ip").is_none());
                Ok(accepted(invocation))
            })
            .await;
        assert_eq!(status, StatusCode::ACCEPTED);
    }

    #[fcp_async_core::runtime::test]
    async fn webhook_runtime_rejects_declared_overflow_without_polling_body_or_dispatch() {
        let runtime = runtime(8, 15_000, 1);
        let body = Body::from_stream(stream::poll_fn(
            |_| -> Poll<Option<Result<Bytes, Infallible>>> {
                panic!("oversized Content-Length must reject before reading")
            },
        ));
        let mut request = request(body);
        request
            .headers_mut()
            .insert("content-length", HeaderValue::from_static("9"));
        let (status, _) = runtime
            .receive(request, |_, _| async { panic!("must not dispatch") })
            .await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(runtime.active.load(Ordering::Acquire), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn webhook_runtime_bounds_chunked_bodies_before_dispatch() {
        let runtime = runtime(8, 15_000, 1);
        let chunks = stream::iter([
            Ok::<_, Infallible>(Bytes::from_static(b"12345")),
            Ok(Bytes::from_static(b"6789")),
        ]);
        let (status, _) = runtime
            .receive(request(Body::from_stream(chunks)), |_, _| async {
                panic!("oversized streamed body must not dispatch")
            })
            .await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        let (status, _) = runtime
            .receive(
                request(Body::from("12345678")),
                |invocation, _| async move {
                    assert_eq!(invocation.input["body"], "12345678");
                    Ok(accepted(invocation))
                },
            )
            .await;
        assert_eq!(status, StatusCode::ACCEPTED);
    }

    #[fcp_async_core::runtime::test]
    async fn webhook_runtime_rejects_duplicate_headers_before_polling_a_body() {
        let runtime = runtime(1024, 15_000, 1);
        let body = Body::from_stream(stream::poll_fn(
            |_| -> Poll<Option<Result<Bytes, Infallible>>> {
                panic!("duplicate headers must reject before reading")
            },
        ));
        let mut request = request(body);
        request.headers_mut().append(
            "x-signature",
            HeaderValue::from_static("different-signature"),
        );
        let (status, _) = runtime
            .receive(request, |_, _| async { panic!("must not dispatch") })
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[fcp_async_core::runtime::test]
    async fn webhook_runtime_rejects_invalid_utf8_and_transport_failures() {
        let runtime = runtime(1024, 15_000, 1);
        let bodies = [
            Body::from(vec![0xff, 0xfe]),
            Body::from_stream(stream::iter([Err::<Bytes, _>(std::io::Error::other(
                "private transport details",
            ))])),
        ];
        for body in bodies {
            let (status, response) = runtime
                .receive(request(body), |_, _| async { panic!("must not dispatch") })
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert!(!response.to_string().contains("private"));
        }
    }

    #[fcp_async_core::runtime::test]
    async fn webhook_runtime_bounds_a_never_finishing_body() {
        let runtime = runtime(1024, 20, 1);
        let body = Body::from_stream(stream::pending::<Result<Bytes, Infallible>>());
        let (status, _) = runtime
            .receive(request(body), |_, _| async { panic!("must not dispatch") })
            .await;
        assert!(status == StatusCode::REQUEST_TIMEOUT || status == StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(runtime.active.load(Ordering::Acquire), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn webhook_runtime_sheds_concurrency_without_waiting_or_reading() {
        let runtime = runtime(1024, 15_000, 1);
        let body = Body::from_stream(stream::pending::<Result<Bytes, Infallible>>());
        let mut pending =
            Box::pin(runtime.receive(request(body), |_, _| async { panic!("pending body") }));
        assert!(poll!(pending.as_mut()).is_pending());
        assert_eq!(runtime.active.load(Ordering::Acquire), 1);
        let (status, _) = runtime
            .receive(request(Body::from("{}")), |_, _| async {
                panic!("no admission")
            })
            .await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        drop(pending);
        assert_eq!(runtime.active.load(Ordering::Acquire), 0);
        let (status, _) = runtime
            .receive(request(Body::from("{}")), |invocation, _| async move {
                Ok(accepted(invocation))
            })
            .await;
        assert_eq!(status, StatusCode::ACCEPTED);
    }

    #[fcp_async_core::runtime::test]
    async fn webhook_runtime_applies_one_budget_to_body_and_dispatch() {
        let runtime = runtime(1024, 1000, 1);
        let body = Body::from_stream(stream::once(async {
            fcp_async_core::time::sleep(Duration::from_millis(10)).await;
            Ok::<_, Infallible>(Bytes::from_static(b"{}"))
        }));
        let (status, _) = runtime
            .receive(request(body), |invocation, _| async move {
                assert!(invocation.deadline_ms.is_some_and(|ms| ms < 1000));
                Ok(accepted(invocation))
            })
            .await;
        assert_eq!(status, StatusCode::ACCEPTED);
    }

    #[fcp_async_core::runtime::test]
    async fn webhook_runtime_bounds_dispatch_and_rejects_late_ready_success() {
        let runtime = runtime(1024, 20, 1);
        let (status, _) = runtime
            .receive(request(Body::from("{}")), |_, _| async {
                std::future::pending::<Result<InvokeResponse, (StatusCode, String)>>().await
            })
            .await;
        assert!(status == StatusCode::REQUEST_TIMEOUT || status == StatusCode::GATEWAY_TIMEOUT);
        let (status, _) = runtime
            .receive(request(Body::from("{}")), |invocation, _| async move {
                std::thread::sleep(Duration::from_millis(25));
                Ok(accepted(invocation))
            })
            .await;
        assert!(status == StatusCode::REQUEST_TIMEOUT || status == StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(runtime.active.load(Ordering::Acquire), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn webhook_runtime_redacts_host_authority_errors() {
        let runtime = runtime(1024, 15_000, 1);
        let (status, response) = runtime
            .receive(request(Body::from("{}")), |_, _| async {
                Err((
                    StatusCode::FORBIDDEN,
                    "private operator configuration and capability details".to_owned(),
                ))
            })
            .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(!response.to_string().contains("private"));
        assert_eq!(response["accepted"], false);
    }

    #[fcp_async_core::runtime::test]
    async fn webhook_runtime_rejects_success_for_a_different_invocation() {
        let runtime = runtime(1024, 15_000, 1);
        let (status, response) = runtime
            .receive(request(Body::from("{}")), |invocation, _| async move {
                let mut response = accepted(invocation);
                response.id = RequestId::random();
                Ok(response)
            })
            .await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(response["accepted"], false);
        assert!(!response.to_string().contains("private-"));
    }

    #[fcp_async_core::runtime::test]
    async fn webhook_runtime_rejects_non_post_and_invalid_content_lengths() {
        let runtime = runtime(1024, 15_000, 1);
        let mut get = request(Body::empty());
        *get.method_mut() = axum::http::Method::GET;
        let (status, _) = runtime
            .receive(get, |_, _| async { panic!("must not dispatch") })
            .await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        for length in ["+1", "-1", "x", "18446744073709551616"] {
            let mut request = request(Body::empty());
            request
                .headers_mut()
                .insert("content-length", length.parse().expect("header value"));
            let (status, _) = runtime
                .receive(request, |_, _| async { panic!("must not dispatch") })
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }
    }

    #[test]
    fn webhook_config_requires_an_absolute_live_capability_file() {
        for authority in [
            json!({}),
            json!({"capability_token_b64": "token", "capability_token_file": "/tmp/token"}),
            json!({"capability_token_file": "relative-token"}),
            json!({"capability_token_file": "/tmp/token", "holder_key_file": "relative-key"}),
            json!({"capability_token_file": "/tmp/token", "holder_key": "inline-private-key"}),
        ] {
            let mut value = json!({
                "connector_id": "fcp.webhook-receiver",
                "zone_id": "z:work",
                "public_base_url": "https://hooks.example.test/webhooks",
            });
            value
                .as_object_mut()
                .expect("object")
                .extend(authority.as_object().expect("object").clone());
            if let Ok(config) = serde_json::from_value::<FileConfig>(value) {
                assert!(config.into_config().is_err());
            }
        }
        assert!(
            serde_json::from_value::<FileConfig>(json!({
                "connector_id": "fcp.webhook-receiver",
                "zone_id": "z:work",
                "public_base_url": "https://hooks.example.test/webhooks",
                "capability_token_file": "/tmp/token",
                "trust_forwarded_for": true,
            }))
            .is_err()
        );
    }

    #[fcp_async_core::runtime::test]
    async fn webhook_authority_can_be_provisioned_and_rotated_without_a_restart() {
        let directory = tempfile::tempdir().expect("temp directory");
        let token_file = directory.path().join("capability.b64");
        let config = FileConfig {
            connector_id: ConnectorId::from_static("fcp.webhook-receiver"),
            zone_id: ZoneId::work(),
            public_base_url: "https://hooks.example.test/webhooks".to_owned(),
            capability_token_file: token_file.clone(),
            holder_key_file: None,
            max_body_bytes: 1024,
            timeout_ms: 15_000,
            max_in_flight: 1,
        }
        .into_config()
        .expect("binding can start before its live instance has authority");
        let runtime = IngressRuntime::configured(config);
        let body = Body::from_stream(stream::poll_fn(
            |_| -> Poll<Option<Result<Bytes, Infallible>>> {
                panic!("inactive binding must not read provider data")
            },
        ));
        let (status, _) = runtime
            .receive(request(body), |_, _| async { panic!("inactive binding") })
            .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

        for _ in 0..2 {
            let token = fcp_core::CapabilityToken::test_token();
            let expected = token.raw().to_cbor().expect("COSE bytes");
            let encoded = base64::engine::general_purpose::STANDARD.encode(&expected);
            let next = directory.path().join("capability.next");
            std::fs::write(&next, format!("{encoded}\n")).expect("write replacement");
            std::fs::rename(&next, &token_file).expect("publish capability atomically");
            let (status, _) = runtime
                .receive(request(Body::from("{}")), |invocation, _| async move {
                    assert_eq!(
                        invocation
                            .capability_token
                            .raw()
                            .to_cbor()
                            .expect("COSE bytes"),
                        expected
                    );
                    assert_eq!(invocation.zone_id, ZoneId::work());
                    assert_eq!(invocation.operation.as_str(), "webhook.events.ingest");
                    Ok(accepted(invocation))
                })
                .await;
            assert_eq!(status, StatusCode::ACCEPTED);
        }

        for invalid in [
            b"private-invalid-token".to_vec(),
            vec![0xff],
            vec![b'A'; MAX_TOKEN_BYTES + 1],
        ] {
            std::fs::write(&token_file, invalid).expect("replace authority with invalid data");
            let (status, response) = runtime
                .receive(request(Body::from("{}")), |_, _| async {
                    panic!("invalid replacement must never reuse old authority")
                })
                .await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert!(!response.to_string().contains("private-"));
        }
        assert_eq!(runtime.active.load(Ordering::Acquire), 0);
    }

    #[test]
    fn webhook_holder_keys_accept_bounded_raw_or_hex_material_and_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("holder.key");
        let secret = [72_u8; 32];
        for encoded in [
            secret.to_vec(),
            format!("{}\n", hex::encode(secret)).into_bytes(),
        ] {
            std::fs::write(&path, encoded).unwrap();
            let key = read_holder_key(&path).unwrap();
            assert_eq!(key.to_bytes(), secret);
        }
        for invalid in [
            Vec::new(),
            b"private-invalid-holder-key".to_vec(),
            vec![b'g'; 64],
            vec![0xff; 64],
            vec![b'a'; MAX_HOLDER_KEY_BYTES + 1],
        ] {
            std::fs::write(&path, invalid).unwrap();
            let error = read_holder_key(&path).unwrap_err();
            assert!(matches!(error, WebhookIngressError::Unavailable));
            assert!(!error.to_string().contains("private-"));
        }
        assert!(read_holder_key(directory.path()).is_err());
        assert!(read_holder_key(&directory.path().join("absent")).is_err());
    }

    #[fcp_async_core::runtime::test]
    #[allow(clippy::too_many_lines)]
    async fn webhook_holder_authority_rotates_token_key_and_proof_for_each_admission() {
        let directory = tempfile::tempdir().unwrap();
        let token_file = directory.path().join("capability.b64");
        let key_file = directory.path().join("holder.key");
        let config = FileConfig {
            connector_id: ConnectorId::from_static("fcp.webhook-receiver"),
            zone_id: ZoneId::work(),
            public_base_url: "https://hooks.example.test/webhooks".to_owned(),
            capability_token_file: token_file.clone(),
            holder_key_file: Some(key_file.clone()),
            max_body_bytes: 1024,
            timeout_ms: 15_000,
            max_in_flight: 1,
        }
        .into_config()
        .expect("authority may be provisioned after startup");
        let runtime = IngressRuntime::configured(config);
        publish_holder_token(
            &token_file,
            Some("node:initial-holder"),
            Some(b"initial-jti"),
        );
        let unread_body = || {
            Body::from_stream(stream::poll_fn(
                |_| -> Poll<Option<Result<Bytes, Infallible>>> {
                    panic!("unavailable holder authority must reject before reading the body")
                },
            ))
        };
        let (status, _) = runtime
            .receive(request(unread_body()), |_, _| async {
                panic!("missing holder key")
            })
            .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

        for (holder, jti, secret) in [
            (
                "node:initial-holder",
                b"initial-jti".as_slice(),
                [72_u8; 32],
            ),
            ("node:successor", b"successor-jti".as_slice(), [73_u8; 32]),
        ] {
            let key = fcp_crypto::Ed25519SigningKey::from_bytes(&secret).unwrap();
            publish_holder_token(&token_file, Some(holder), Some(jti));
            let next = key_file.with_extension("next");
            std::fs::write(&next, hex::encode(secret)).unwrap();
            std::fs::rename(next, &key_file).unwrap();
            let verifier = key.verifying_key();
            let (status, _) = runtime
                .receive(request(Body::from("{}")), |invocation, _| async move {
                    let proof = invocation
                        .holder_proof
                        .as_ref()
                        .expect("current holder proof");
                    assert_eq!(proof.holder_node.as_str(), holder);
                    let bytes = fcp_core::HolderProof::signable_bytes(
                        &invocation.id,
                        &invocation.operation,
                        jti,
                    );
                    verifier
                        .verify(
                            &bytes,
                            &fcp_crypto::Ed25519Signature::from_bytes(&proof.signature),
                        )
                        .expect("proof uses current key, request ID and token JTI");
                    Ok(accepted(invocation))
                })
                .await;
            assert_eq!(status, StatusCode::ACCEPTED);
        }

        for invalid in [Vec::new(), b"private-broken-key".to_vec(), vec![b'a'; 129]] {
            std::fs::write(&key_file, invalid).unwrap();
            let (status, public) = runtime
                .receive(request(unread_body()), |_, _| async {
                    panic!("invalid replacement must never reuse a previous signer")
                })
                .await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert!(!public.to_string().contains("private-"));
        }
        std::fs::rename(&key_file, key_file.with_extension("withdrawn")).unwrap();
        let (status, _) = runtime
            .receive(request(unread_body()), |_, _| async {
                panic!("withdrawn key")
            })
            .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

        std::fs::write(&key_file, hex::encode([73_u8; 32])).unwrap();
        for (holder, jti) in [
            (None, Some(b"bearer-jti".as_slice())),
            (Some("node:successor"), None),
            (Some("node:successor"), Some(b"".as_slice())),
        ] {
            publish_holder_token(&token_file, holder, jti);
            let (status, _) = runtime
                .receive(request(unread_body()), |_, _| async {
                    panic!("invalid signing context")
                })
                .await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        }
        assert_eq!(runtime.active.load(Ordering::Acquire), 0);
    }

    #[test]
    fn webhook_config_file_reads_are_bounded_and_errors_do_not_echo_content() {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("ingress.json");
        std::fs::write(&path, "private-configuration").expect("write config");
        let error = read_bounded(&path, 4).expect_err("bounded read");
        assert!(!error.to_string().contains("private-configuration"));
        assert!(read_bounded(directory.path(), 1024).is_err());
        assert_eq!(
            read_bounded(&path, 1024).expect("bounded file").as_slice(),
            b"private-configuration"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn webhook_route_is_absent_without_explicit_configuration() {
        let host = super::super::tests::cancel_route_test_state();
        let app = routes(Arc::clone(&host), None).with_state(host);
        let response = app
            .oneshot(request(Body::from("{}")))
            .await
            .expect("router");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
