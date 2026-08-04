//! Signal HTTP client.
//!
//! Communicates with signal-cli's REST daemon API.
//! Uses HTTP calls to `signal-cli-rest-api`.

use fcp_sdk::ConnectorRuntime;
use fcp_sdk::migration::{
    AttemptOutcome, HttpRetryConfig, RetryLoop, classify_http_status,
    transport_error_reached_service,
};
use fcp_sdk::retry::RetryDecision;
use reqwest::{Client, Url};
use std::time::Duration;
use tracing::{debug, warn};

use crate::error::{SignalError, SignalResult};
use crate::types::{
    GroupInfo, SendMessageRequest, SendMessageResponse, SignalConfig, SignalEnvelope,
    SignalIdentity, TrustIdentityRequest,
};

/// Percent-encode a value for safe inclusion in a URL path segment.
fn encode_path_segment(s: &str) -> String {
    use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
    utf8_percent_encode(s, NON_ALPHANUMERIC).to_string()
}

/// Signal API client (HTTP daemon mode).
#[derive(Debug)]
pub struct SignalClient {
    client: Client,
    daemon_url: String,
    phone_number: String,
    retry_config: HttpRetryConfig,
}

impl SignalClient {
    /// Create a new Signal client for the REST daemon.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be built.
    pub fn new(config: &SignalConfig) -> SignalResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_millis(config.request_timeout_ms))
            .build()
            .map_err(SignalError::Http)?;

        Ok(Self {
            client,
            daemon_url: config.normalized_daemon_url(),
            phone_number: config.normalized_phone_number(),
            retry_config: config.retry.clone(),
        })
    }

    /// Build the signal-cli SSE event stream URL for this configured account.
    ///
    /// # Errors
    ///
    /// Returns a configuration error when the daemon URL cannot be joined with
    /// the event endpoint.
    pub fn event_stream_url(&self) -> SignalResult<Url> {
        let mut url = Url::parse(&format!("{}/api/v1/events", self.daemon_url))
            .map_err(|error| SignalError::Config(format!("invalid event stream URL: {error}")))?;
        url.query_pairs_mut()
            .append_pair("account", &self.phone_number);
        Ok(url)
    }

    /// Send a message to one or more recipients.
    ///
    /// # Errors
    ///
    /// Returns an error if the API call fails.
    pub async fn send_message(
        &self,
        runtime: &ConnectorRuntime,
        request: &SendMessageRequest,
    ) -> SignalResult<SendMessageResponse> {
        let url = format!("{}/v2/send", self.daemon_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        let mut body = serde_json::json!({
            "number": self.phone_number,
            "recipients": &request.recipients,
            "message": &request.message,
            "base64_attachments": &request.attachments,
        });
        if let Some(quote_timestamp) = request.quote_timestamp {
            body["quote_timestamp"] = serde_json::json!(quote_timestamp);
        }
        let body_clone = body.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let body = body_clone.clone();
            async move {
                debug!(attempt, "Sending Signal message");
                let resp = match client.post(&url).json(&body).send().await {
                    Ok(r) => r,
                    Err(e) => {
                        // br-kxd3e: only a connect-phase failure proves the
                        // request never reached the daemon.
                        let replayable = !transport_error_reached_service(&e);
                        return AttemptOutcome::retryable_if_replayable(
                            SignalError::Http(e),
                            None,
                            replayable,
                        );
                    }
                };

                let status = resp.status().as_u16();
                if status == 429 {
                    let retry_after = resp
                        .headers()
                        .get("retry-after")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.parse::<u64>().ok())
                        .map(Duration::from_secs);
                    return AttemptOutcome::Retryable {
                        error: SignalError::RateLimited {
                            retry_after_ms: retry_after
                                .unwrap_or(Duration::from_secs(30))
                                .as_millis()
                                .try_into()
                                .unwrap_or(u64::MAX),
                        },
                        retry_after,
                    };
                }

                if status == 401 {
                    return AttemptOutcome::Terminal(SignalError::Unauthorized(
                        "Signal daemon returned 401".into(),
                    ));
                }

                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    // br-kxd3e: every remaining retryable class here is a 5xx,
                    // which means the daemon received the send and may already
                    // have delivered it. signal-cli offers no dedup key, so the
                    // honest outcome is one error rather than N more messages.
                    // 429 is handled above, before this gate, because it was
                    // refused WITHOUT the message being sent.
                    return AttemptOutcome::Terminal(SignalError::from_api_response(status, &text));
                }

                match resp.json::<SendMessageResponse>().await {
                    Ok(r) => AttemptOutcome::Success(r),
                    Err(e) => AttemptOutcome::Terminal(SignalError::Http(e)),
                }
            }
        })
        .await
    }

    /// Receive messages from the signal-cli daemon.
    ///
    /// # Errors
    ///
    /// Returns an error if the API call fails.
    pub async fn receive_messages(
        &self,
        runtime: &ConnectorRuntime,
        timeout_seconds: u64,
    ) -> SignalResult<Vec<SignalEnvelope>> {
        let url = format!(
            "{}/v1/receive/{}",
            self.daemon_url,
            encode_path_segment(&self.phone_number)
        );
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            async move {
                debug!(attempt, "Receiving Signal messages");
                let resp = match client
                    .get(&url)
                    .query(&[("timeout", timeout_seconds.to_string())])
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: SignalError::Http(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    warn!(status, "Signal receive request failed");
                    let decision = classify_http_status(status, None);
                    let err = SignalError::from_api_response(status, &text);
                    if !matches!(decision, RetryDecision::Terminal) {
                        return AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        };
                    }
                    return AttemptOutcome::Terminal(err);
                }

                match resp.json::<Vec<SignalEnvelope>>().await {
                    Ok(r) => AttemptOutcome::Success(r),
                    Err(e) => AttemptOutcome::Terminal(SignalError::Http(e)),
                }
            }
        })
        .await
    }

    /// Get group info by group ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the API call fails.
    pub async fn get_group(
        &self,
        runtime: &ConnectorRuntime,
        group_id: &str,
    ) -> SignalResult<GroupInfo> {
        let url = format!(
            "{}/v1/groups/{}",
            self.daemon_url,
            encode_path_segment(&self.phone_number)
        );
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let group_id = group_id.to_string();
            async move {
                debug!(attempt, group_id = %group_id, "Fetching Signal group");
                let resp = match client.get(&url).query(&[("id", &group_id)]).send().await {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: SignalError::Http(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                if status == 404 {
                    return AttemptOutcome::Terminal(SignalError::GroupNotFound(group_id));
                }

                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    let decision = classify_http_status(status, None);
                    let err = SignalError::from_api_response(status, &text);
                    if !matches!(decision, RetryDecision::Terminal) {
                        return AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        };
                    }
                    return AttemptOutcome::Terminal(err);
                }

                match resp.json::<GroupInfo>().await {
                    Ok(r) => AttemptOutcome::Success(r),
                    Err(e) => AttemptOutcome::Terminal(SignalError::Http(e)),
                }
            }
        })
        .await
    }

    /// List all groups for the registered number.
    ///
    /// # Errors
    ///
    /// Returns an error if the API call fails.
    pub async fn list_groups(&self, runtime: &ConnectorRuntime) -> SignalResult<Vec<GroupInfo>> {
        let url = format!(
            "{}/v1/groups/{}",
            self.daemon_url,
            encode_path_segment(&self.phone_number)
        );
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            async move {
                debug!(attempt, "Listing Signal groups");
                let resp = match client.get(&url).send().await {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: SignalError::Http(e),
                            retry_after: None,
                        };
                    }
                };

                if !resp.status().is_success() {
                    let status = resp.status().as_u16();
                    let text = resp.text().await.unwrap_or_default();
                    let decision = classify_http_status(status, None);
                    let err = SignalError::from_api_response(status, &text);
                    if !matches!(decision, RetryDecision::Terminal) {
                        return AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        };
                    }
                    return AttemptOutcome::Terminal(err);
                }

                match resp.json::<Vec<GroupInfo>>().await {
                    Ok(r) => AttemptOutcome::Success(r),
                    Err(e) => AttemptOutcome::Terminal(SignalError::Http(e)),
                }
            }
        })
        .await
    }

    /// Get identity info for a phone number.
    ///
    /// # Errors
    ///
    /// Returns an error if the API call fails.
    pub async fn get_identity(
        &self,
        runtime: &ConnectorRuntime,
        number: &str,
    ) -> SignalResult<SignalIdentity> {
        let url = format!(
            "{}/v1/identities/{}/{}",
            self.daemon_url,
            encode_path_segment(&self.phone_number),
            encode_path_segment(number)
        );
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            async move {
                debug!(attempt, "Fetching Signal identity");
                let resp = match client.get(&url).send().await {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: SignalError::Http(e),
                            retry_after: None,
                        };
                    }
                };

                if !resp.status().is_success() {
                    let status = resp.status().as_u16();
                    let text = resp.text().await.unwrap_or_default();
                    return AttemptOutcome::Terminal(SignalError::from_api_response(status, &text));
                }

                match resp.json::<SignalIdentity>().await {
                    Ok(r) => AttemptOutcome::Success(r),
                    Err(e) => AttemptOutcome::Terminal(SignalError::Http(e)),
                }
            }
        })
        .await
    }

    /// Trust an identity (mark as verified).
    ///
    /// # Errors
    ///
    /// Returns an error if the API call fails.
    pub async fn trust_identity(
        &self,
        runtime: &ConnectorRuntime,
        request: &TrustIdentityRequest,
    ) -> SignalResult<()> {
        let url = format!(
            "{}/v1/identities/{}/trust/{}",
            self.daemon_url,
            encode_path_segment(&self.phone_number),
            encode_path_segment(&request.number)
        );
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        let mut payload = serde_json::Map::new();
        if let Some(verified_safety_number) = request
            .verified_safety_number
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            payload.insert(
                "verified_safety_number".into(),
                serde_json::Value::String(verified_safety_number.to_owned()),
            );
        }
        if request.trust_all_known_keys {
            payload.insert("trust_all_known_keys".into(), serde_json::Value::Bool(true));
        }
        let payload = serde_json::Value::Object(payload);

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let payload = payload.clone();
            async move {
                debug!(attempt, "Trusting Signal identity");
                let resp = match client.put(&url).json(&payload).send().await {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: SignalError::Http(e),
                            retry_after: None,
                        };
                    }
                };

                if !resp.status().is_success() {
                    let status = resp.status().as_u16();
                    let text = resp.text().await.unwrap_or_default();
                    return AttemptOutcome::Terminal(SignalError::from_api_response(status, &text));
                }

                AttemptOutcome::Success(())
            }
        })
        .await
    }

    /// Lightweight health check: verify daemon is reachable.
    ///
    /// # Errors
    ///
    /// Returns an error if the daemon is unreachable.
    pub async fn health_check(&self) -> SignalResult<()> {
        let url = format!("{}/v1/about", self.daemon_url);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|_| SignalError::BridgeNotRunning)?;

        if resp.status().is_success() {
            Ok(())
        } else {
            Err(SignalError::BridgeNotRunning)
        }
    }

    /// Get the daemon base URL (for diagnostics).
    #[must_use]
    pub fn daemon_url(&self) -> &str {
        &self.daemon_url
    }

    /// Get the registered phone number.
    #[must_use]
    pub fn phone_number(&self) -> &str {
        &self.phone_number
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    fn test_config(daemon_url: &str) -> SignalConfig {
        SignalConfig::from_value(serde_json::json!({
            "daemon_url": daemon_url,
            "phone_number": "+15551234567"
        }))
        .expect("valid config")
    }

    struct LoopbackHttpServer {
        uri: String,
        handle: thread::JoinHandle<()>,
    }

    struct LoopbackHttpResponse {
        method: &'static str,
        path: &'static str,
        status: u16,
        body: String,
        content_type: &'static str,
        body_contains: Option<&'static str>,
    }

    impl LoopbackHttpServer {
        fn start(responses: Vec<LoopbackHttpResponse>) -> Self {
            let listener =
                TcpListener::bind("127.0.0.1:0").expect("bind Signal loopback HTTP listener");
            let address = listener.local_addr().expect("Signal listener address");
            let handle = thread::spawn(move || {
                for response in responses {
                    let (mut stream, _) = listener
                        .accept()
                        .expect("accept Signal loopback HTTP client");
                    let request = read_http_request(&mut stream);
                    let first_line = request.lines().next().unwrap_or_default();
                    let expected_prefix = format!("{} {}", response.method, response.path);
                    assert!(
                        first_line.starts_with(&expected_prefix),
                        "unexpected Signal HTTP request line: {first_line:?}",
                    );
                    if let Some(expected_body) = response.body_contains {
                        assert!(
                            request.contains(expected_body),
                            "Signal HTTP request body missing {expected_body:?}: {request:?}",
                        );
                    }
                    write_http_response(&mut stream, &response);
                }
            });

            Self {
                uri: format!("http://{address}"),
                handle,
            }
        }

        fn uri(&self) -> &str {
            &self.uri
        }

        fn join(self) {
            self.handle
                .join()
                .expect("Signal loopback HTTP thread should finish");
        }
    }

    impl LoopbackHttpResponse {
        fn json(
            method: &'static str,
            path: &'static str,
            status: u16,
            body: &serde_json::Value,
        ) -> Self {
            Self {
                method,
                path,
                status,
                body: serde_json::to_string(body).expect("Signal JSON response should serialize"),
                content_type: "application/json",
                body_contains: None,
            }
        }

        fn text(method: &'static str, path: &'static str, status: u16, body: &'static str) -> Self {
            Self {
                method,
                path,
                status,
                body: body.to_owned(),
                content_type: "text/plain",
                body_contains: None,
            }
        }

        fn empty(method: &'static str, path: &'static str, status: u16) -> Self {
            Self {
                method,
                path,
                status,
                body: String::new(),
                content_type: "text/plain",
                body_contains: None,
            }
        }

        fn with_body_contains(mut self, expected: &'static str) -> Self {
            self.body_contains = Some(expected);
            self
        }
    }

    fn read_http_request(stream: &mut TcpStream) -> String {
        let mut request = Vec::new();
        let mut buf = [0_u8; 1024];
        let header_end = loop {
            let read = stream
                .read(&mut buf)
                .expect("read Signal loopback HTTP request");
            if read == 0 {
                break None;
            }
            request.extend_from_slice(&buf[..read]);
            if let Some(position) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                break Some(position + 4);
            }
        };

        if let Some(header_end) = header_end {
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or(0);
            while request.len() < header_end + content_length {
                let read = stream
                    .read(&mut buf)
                    .expect("read Signal loopback HTTP request body");
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..read]);
            }
        }

        String::from_utf8_lossy(&request).into_owned()
    }

    fn write_http_response(stream: &mut TcpStream, response: &LoopbackHttpResponse) {
        let reason = match response.status {
            204 => "No Content",
            401 => "Unauthorized",
            _ => "OK",
        };
        let message = format!(
            "HTTP/1.1 {} {reason}\r\n\
             Content-Type: {}\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {}",
            response.status,
            response.content_type,
            response.body.len(),
            response.body,
        );
        stream
            .write_all(message.as_bytes())
            .expect("write Signal loopback HTTP response");
        stream.flush().expect("flush Signal loopback HTTP response");
    }

    #[test]
    fn client_creation() {
        let client = SignalClient::new(&test_config("http://localhost:8080"));
        assert!(client.is_ok());
    }

    #[test]
    fn daemon_url_trimmed() {
        let client = SignalClient::new(&test_config("http://localhost:8080/")).unwrap();
        assert!(!client.daemon_url().ends_with('/'));
    }

    #[test]
    fn client_creation_trims_runtime_values() {
        let config = SignalConfig::from_value(serde_json::json!({
            "daemon_url": "  http://localhost:8080/  ",
            "phone_number": "  +15551234567  "
        }))
        .expect("valid config");

        let client = SignalClient::new(&config).expect("client");
        assert_eq!(client.daemon_url(), "http://localhost:8080");
        assert_eq!(client.phone_number(), "+15551234567");
    }

    #[test]
    fn phone_number_stored() {
        let client = SignalClient::new(&test_config("http://localhost:8080")).unwrap();
        assert_eq!(client.phone_number(), "+15551234567");
    }

    #[test]
    fn event_stream_url_encodes_account_query() {
        let client = SignalClient::new(&test_config("http://localhost:8080/")).unwrap();
        let url = client.event_stream_url().unwrap();
        assert_eq!(
            url.as_str(),
            "http://localhost:8080/api/v1/events?account=%2B15551234567"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn send_message_success() {
        let server = LoopbackHttpServer::start(vec![LoopbackHttpResponse::json(
            "POST",
            "/v2/send",
            200,
            &serde_json::json!({
                "timestamp": "1700000001000"
            }),
        )]);

        let client = SignalClient::new(&test_config(server.uri())).unwrap();
        let runtime = ConnectorRuntime::new(fcp_sdk::ConnectorRuntimeConfig::default());
        let resp = client
            .send_message(
                &runtime,
                &SendMessageRequest {
                    recipients: vec!["+15559876543".into()],
                    message: "Hello Signal".into(),
                    attachments: Vec::new(),
                    quote_timestamp: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(resp.timestamp, 1_700_000_001_000);
        server.join();
    }

    #[fcp_async_core::runtime::test]
    async fn send_message_includes_quote_timestamp() {
        let server = LoopbackHttpServer::start(vec![
            LoopbackHttpResponse::json(
                "POST",
                "/v2/send",
                200,
                &serde_json::json!({
                    "timestamp": "42"
                }),
            )
            .with_body_contains("\"quote_timestamp\":42"),
        ]);

        let client = SignalClient::new(&test_config(server.uri())).unwrap();
        let runtime = ConnectorRuntime::new(fcp_sdk::ConnectorRuntimeConfig::default());
        let response = client
            .send_message(
                &runtime,
                &SendMessageRequest {
                    recipients: vec!["+15559876543".into()],
                    message: "quoted".into(),
                    attachments: Vec::new(),
                    quote_timestamp: Some(42),
                },
            )
            .await
            .unwrap();

        assert_eq!(response.timestamp, 42);
        server.join();
    }

    #[fcp_async_core::runtime::test]
    async fn receive_messages_success() {
        let server = LoopbackHttpServer::start(vec![LoopbackHttpResponse::json(
            "GET",
            "/v1/receive/%2B15551234567",
            200,
            &serde_json::json!([
                    {
                        "source": "+15559876543",
                        "sourceDevice": 1,
                    "timestamp": 1_700_000_000_000_u64,
                    "dataMessage": {
                        "timestamp": 1_700_000_000_000_u64,
                        "message": "Hello back"
                    }
                }
            ]),
        )]);

        let client = SignalClient::new(&test_config(server.uri())).unwrap();
        let runtime = ConnectorRuntime::new(fcp_sdk::ConnectorRuntimeConfig::default());
        let envelopes = client.receive_messages(&runtime, 10).await.unwrap();
        assert_eq!(envelopes.len(), 1);
        assert_eq!(envelopes[0].source, Some("+15559876543".into()));
        server.join();
    }

    #[fcp_async_core::runtime::test]
    async fn health_check_success() {
        let server = LoopbackHttpServer::start(vec![LoopbackHttpResponse::json(
            "GET",
            "/v1/about",
            200,
            &serde_json::json!({
                "versions": ["v1", "v2"],
                "build": 1
            }),
        )]);

        let client = SignalClient::new(&test_config(server.uri())).unwrap();
        assert!(client.health_check().await.is_ok());
        server.join();
    }

    #[fcp_async_core::runtime::test]
    async fn health_check_daemon_down() {
        // Use a URL that will refuse connections
        let client = SignalClient::new(&test_config("http://127.0.0.1:1")).unwrap();
        let result = client.health_check().await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignalError::BridgeNotRunning));
    }

    #[fcp_async_core::runtime::test]
    async fn send_message_401_unauthorized() {
        let server = LoopbackHttpServer::start(vec![LoopbackHttpResponse::text(
            "POST",
            "/v2/send",
            401,
            "unauthorized",
        )]);

        let client = SignalClient::new(&test_config(server.uri())).unwrap();
        let runtime = ConnectorRuntime::new(fcp_sdk::ConnectorRuntimeConfig::default());
        let result = client
            .send_message(
                &runtime,
                &SendMessageRequest {
                    recipients: vec!["+15559876543".into()],
                    message: "Hello".into(),
                    attachments: Vec::new(),
                    quote_timestamp: None,
                },
            )
            .await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignalError::Unauthorized(_)));
        server.join();
    }

    #[fcp_async_core::runtime::test]
    async fn trust_identity_uses_verified_safety_number_when_provided() {
        let server = LoopbackHttpServer::start(vec![
            LoopbackHttpResponse::empty(
                "PUT",
                "/v1/identities/%2B15551234567/trust/%2B15559876543",
                204,
            )
            .with_body_contains("\"verified_safety_number\":\"12345 67890\""),
        ]);

        let client = SignalClient::new(&test_config(server.uri())).unwrap();
        let runtime = ConnectorRuntime::new(fcp_sdk::ConnectorRuntimeConfig::default());
        client
            .trust_identity(
                &runtime,
                &TrustIdentityRequest {
                    number: "+15559876543".into(),
                    verified_safety_number: Some("12345 67890".into()),
                    trust_all_known_keys: false,
                },
            )
            .await
            .expect("trust identity");
        server.join();
    }

    #[fcp_async_core::runtime::test]
    async fn list_groups_success() {
        let server = LoopbackHttpServer::start(vec![LoopbackHttpResponse::json(
            "GET",
            "/v1/groups/%2B15551234567",
            200,
            &serde_json::json!([
                    {
                        "id": "Z3JvdXBfMQ==",
                        "name": "Test Group 1",
                    "members": ["+15551111111"],
                    "admins": ["+15551111111"]
                },
                {
                    "id": "Z3JvdXBfMg==",
                    "name": "Test Group 2",
                    "members": ["+15552222222"],
                    "admins": []
                }
            ]),
        )]);

        let client = SignalClient::new(&test_config(server.uri())).unwrap();
        let runtime = ConnectorRuntime::new(fcp_sdk::ConnectorRuntimeConfig::default());
        let groups = client.list_groups(&runtime).await.unwrap();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].name, Some("Test Group 1".into()));
        server.join();
    }
}
