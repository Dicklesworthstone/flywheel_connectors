//! Bounded owner-cancellation submission to the selected host.
//!
//! This helper does not grant cancellation authority or choose another target.
//! The caller supplies the already-resolved capability in the request body;
//! the host verifies it and the original operation's ownership.

use std::fmt;
use std::io::{self, Read};
use std::time::{Duration, Instant};

use reqwest::blocking::Client;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

const CANCEL_SELF_PATH: &str = "/rpc/cancel-self";
const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;

/// Sanitized transport outcomes. No variant retains a body, URL or credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CancellationFailure {
    Timeout,
    Transport,
    Http(u16),
    ResponseTooLarge,
    InvalidResponse,
}

impl fmt::Display for CancellationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => formatter.write_str(
                "Owner cancellation timed out; its outcome is unknown.",
            ),
            Self::Transport => formatter.write_str(
                "Owner cancellation could not be acknowledged; its outcome is unknown.",
            ),
            Self::Http(status) => write!(
                formatter,
                "Owner cancellation endpoint returned HTTP {status}."
            ),
            Self::ResponseTooLarge => formatter.write_str(
                "Owner cancellation response exceeded the 1 MiB limit; its outcome is unknown.",
            ),
            Self::InvalidResponse => formatter.write_str(
                "Owner cancellation response was invalid or identified another operation; its outcome is unknown.",
            ),
        }
    }
}

impl std::error::Error for CancellationFailure {}

/// Submit exactly one owner-scoped cancellation request.
///
/// The supplied client must disable redirects and automatic retries, as the
/// CLI host client does. The base URL must identify the already selected host.
/// This helper never falls back to an administrative route or resubmits an
/// invocation. The timeout includes receiving the response body, which is
/// limited to 1 MiB so requested partial results can be returned safely.
///
/// Only a successful JSON response naming the exact original operation is
/// decoded into the requested type. Non-success response bodies and underlying
/// transport diagnostics are discarded because they can echo credentials.
///
/// # Errors
///
/// Returns a sanitized failure when submission, body consumption, identity
/// validation or decoding fails. Such a failure does not prove the operation
/// stopped, nor that the host did not receive the cancellation.
pub(crate) fn submit<Q, R>(
    client: &Client,
    base_url: &str,
    operation_id: &str,
    request: &Q,
    timeout: Duration,
) -> Result<R, CancellationFailure>
where
    Q: Serialize + ?Sized,
    R: DeserializeOwned,
{
    if timeout.is_zero() {
        return Err(CancellationFailure::Timeout);
    }
    let started = Instant::now();
    let response = client
        .post(format!(
            "{}{CANCEL_SELF_PATH}",
            base_url.trim_end_matches('/')
        ))
        .json(request)
        .timeout(timeout)
        .send()
        .map_err(|error| {
            if error.is_timeout() {
                CancellationFailure::Timeout
            } else {
                CancellationFailure::Transport
            }
        })?;
    let status = response.status();
    if !status.is_success() {
        return Err(CancellationFailure::Http(status.as_u16()));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES)
    {
        return Err(CancellationFailure::ResponseTooLarge);
    }
    let mut body = Vec::new();
    response
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(|error| {
            // Blocking response readers wrap HTTP errors in io::Error. The
            // elapsed budget also catches timeout errors whose IO kind is Other.
            if error.kind() == io::ErrorKind::TimedOut || started.elapsed() >= timeout {
                CancellationFailure::Timeout
            } else {
                CancellationFailure::Transport
            }
        })?;
    if body.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(CancellationFailure::ResponseTooLarge);
    }
    let value: Value =
        serde_json::from_slice(&body).map_err(|_| CancellationFailure::InvalidResponse)?;
    if value.get("operation_id").and_then(Value::as_str) != Some(operation_id) {
        return Err(CancellationFailure::InvalidResponse);
    }
    serde_json::from_value(value).map_err(|_| CancellationFailure::InvalidResponse)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::{BufRead, BufReader, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    use serde::Deserialize;
    use serde_json::json;

    use super::*;

    const OPERATION_ID: &str = "invoke-original-123";
    const SECRET: &str = "cancel-capability-must-never-be-rendered";
    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    #[derive(Debug, Deserialize, Eq, PartialEq)]
    #[serde(rename_all = "snake_case")]
    enum Outcome {
        Cancelled,
        Pending,
        TooLate,
        Failed,
    }

    #[derive(Debug, Deserialize)]
    struct Reply {
        operation_id: String,
        outcome: Outcome,
        #[serde(default)]
        partial_result: Option<Value>,
    }

    #[derive(Debug)]
    struct CapturedRequest {
        request_line: String,
        headers: BTreeMap<String, String>,
        body: Value,
    }

    struct TestHost {
        url: String,
        worker: Option<thread::JoinHandle<CapturedRequest>>,
    }

    impl TestHost {
        fn start(respond: impl FnOnce(&mut TcpStream) -> io::Result<()> + Send + 'static) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let worker = thread::spawn(move || {
                let deadline = Instant::now() + TEST_TIMEOUT;
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline, "no cancellation request arrived");
                            thread::sleep(Duration::from_millis(1));
                        }
                        Err(error) => panic!("accept failed: {error}"),
                    }
                };
                stream.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
                stream.set_write_timeout(Some(TEST_TIMEOUT)).unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request_line = String::new();
                reader.read_line(&mut request_line).unwrap();
                let mut headers = BTreeMap::new();
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                    assert!(!line.is_empty(), "request headers were incomplete");
                    let (name, value) = line.split_once(':').unwrap();
                    headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
                }
                let length: usize = headers["content-length"].parse().unwrap();
                assert!(length <= 64 * 1024);
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                let captured = CapturedRequest {
                    request_line: request_line.trim().to_owned(),
                    headers,
                    body: serde_json::from_slice(&body).unwrap(),
                };
                // Timeout and bounded-read tests intentionally close the client
                // before a delayed or excessive response has finished writing.
                let _ = respond(&mut stream);
                captured
            });
            Self {
                url,
                worker: Some(worker),
            }
        }

        fn finish(mut self) -> CapturedRequest {
            self.worker.take().unwrap().join().unwrap()
        }
    }

    impl Drop for TestHost {
        fn drop(&mut self) {
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }

    fn client() -> Client {
        Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .build()
            .unwrap()
    }

    fn request() -> Value {
        json!({
            "operation_id": OPERATION_ID,
            "reason": {"type":"user_requested"},
            "cleanup": {"type":"best_effort"},
            "return_partial": true,
            "capability_token": SECRET,
        })
    }

    fn reply(outcome: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "operation_id": OPERATION_ID,
            "outcome": outcome,
        }))
        .unwrap()
    }

    fn respond(stream: &mut TcpStream, status: u16, body: &[u8]) -> io::Result<()> {
        write!(
            stream,
            "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len(),
        )?;
        stream.write_all(body)
    }

    #[test]
    fn submits_exact_owner_route_body_and_authority_once() {
        let body = serde_json::to_vec(&json!({
            "operation_id": OPERATION_ID,
            "outcome": "cancelled",
            "partial_result": {"data":"x".repeat(128 * 1024)},
        }))
        .unwrap();
        let host = TestHost::start(move |stream| respond(stream, 200, &body));
        let sent = request();
        let response: Reply = submit(
            &client(),
            &format!("{}/", host.url),
            OPERATION_ID,
            &sent,
            TEST_TIMEOUT,
        )
        .unwrap();
        assert_eq!(response.operation_id, OPERATION_ID);
        assert_eq!(response.outcome, Outcome::Cancelled);
        assert_eq!(
            response.partial_result.unwrap()["data"]
                .as_str()
                .unwrap()
                .len(),
            128 * 1024
        );
        let captured = host.finish();
        assert_eq!(captured.request_line, "POST /rpc/cancel-self HTTP/1.1");
        assert_eq!(captured.body, sent);
        assert!(!captured.headers.contains_key("authorization"));
        assert!(!captured.headers.contains_key("x-principal"));
    }

    #[test]
    fn denied_and_unknown_requests_do_not_fall_back_or_expose_reflected_credentials() {
        for status in [403, 404, 503] {
            let host = TestHost::start(move |stream| {
                respond(
                    stream,
                    status,
                    format!("reflected credential: {SECRET}").as_bytes(),
                )
            });
            let error =
                submit::<_, Reply>(&client(), &host.url, OPERATION_ID, &request(), TEST_TIMEOUT)
                    .unwrap_err();
            assert_eq!(error, CancellationFailure::Http(status));
            assert!(!error.to_string().contains(SECRET));
            assert!(!format!("{error:?}").contains(SECRET));
            assert!(std::error::Error::source(&error).is_none());
            assert_eq!(host.finish().request_line, "POST /rpc/cancel-self HTTP/1.1");
        }
    }

    #[test]
    fn redirects_cannot_forward_the_capability_to_another_destination() {
        let destination = TcpListener::bind("127.0.0.1:0").unwrap();
        destination.set_nonblocking(true).unwrap();
        let location = format!("http://{}/rpc/cancel", destination.local_addr().unwrap());
        let host = TestHost::start(move |stream| {
            write!(
                stream,
                "HTTP/1.1 307 Temporary Redirect\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
        });
        let error =
            submit::<_, Reply>(&client(), &host.url, OPERATION_ID, &request(), TEST_TIMEOUT)
                .unwrap_err();
        assert_eq!(error, CancellationFailure::Http(307));
        assert_eq!(
            destination.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(host.finish().body["capability_token"], SECRET);
    }

    #[test]
    fn wrong_operation_identity_is_rejected_before_typed_decoding() {
        // Value would accept any valid JSON. Identity validation must therefore
        // happen independently of the caller's response type.
        let host = TestHost::start(|stream| {
            respond(
                stream,
                200,
                br#"{"operation_id":"another-call","outcome":"cancelled"}"#,
            )
        });
        let error =
            submit::<_, Value>(&client(), &host.url, OPERATION_ID, &request(), TEST_TIMEOUT)
                .unwrap_err();
        assert_eq!(error, CancellationFailure::InvalidResponse);
        host.finish();
    }

    #[test]
    fn malformed_unidentified_and_typed_invalid_responses_are_rejected() {
        for body in [
            b"not JSON".to_vec(),
            b"[]".to_vec(),
            b"{}".to_vec(),
            serde_json::to_vec(&json!({"operation_id": OPERATION_ID})).unwrap(),
            serde_json::to_vec(&json!({"operation_id": OPERATION_ID, "outcome":"invented"}))
                .unwrap(),
        ] {
            let host = TestHost::start(move |stream| respond(stream, 200, &body));
            assert_eq!(
                submit::<_, Reply>(&client(), &host.url, OPERATION_ID, &request(), TEST_TIMEOUT,)
                    .unwrap_err(),
                CancellationFailure::InvalidResponse,
            );
            host.finish();
        }
    }

    #[test]
    fn announced_oversized_response_is_rejected_without_waiting_for_its_body() {
        let host = TestHost::start(|stream| {
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                MAX_RESPONSE_BYTES + 1,
            )
        });
        assert_eq!(
            submit::<_, Reply>(&client(), &host.url, OPERATION_ID, &request(), TEST_TIMEOUT,)
                .unwrap_err(),
            CancellationFailure::ResponseTooLarge,
        );
        host.finish();
    }

    #[test]
    fn chunked_response_cannot_bypass_the_body_limit() {
        let host = TestHost::start(|stream| {
            let body = vec![b'x'; MAX_RESPONSE_BYTES as usize + 1];
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n",
                body.len(),
            )?;
            stream.write_all(&body)?;
            stream.write_all(b"\r\n0\r\n\r\n")
        });
        assert_eq!(
            submit::<_, Reply>(&client(), &host.url, OPERATION_ID, &request(), TEST_TIMEOUT,)
                .unwrap_err(),
            CancellationFailure::ResponseTooLarge,
        );
        host.finish();
    }

    #[test]
    fn exact_response_limit_and_every_known_outcome_are_preserved() {
        for outcome in ["cancelled", "pending", "too_late", "failed"] {
            let mut body = reply(outcome);
            body.resize(MAX_RESPONSE_BYTES as usize, b' ');
            let host = TestHost::start(move |stream| respond(stream, 200, &body));
            let response: Reply =
                submit(&client(), &host.url, OPERATION_ID, &request(), TEST_TIMEOUT).unwrap();
            assert_eq!(response.operation_id, OPERATION_ID);
            let expected = serde_json::from_value::<Outcome>(json!(outcome)).unwrap();
            assert_eq!(response.outcome, expected);
            host.finish();
        }
    }

    #[test]
    fn timeout_bounds_waiting_for_headers_and_for_a_partial_body() {
        for send_headers in [false, true] {
            let host = TestHost::start(move |stream| {
                let body = reply("pending");
                if send_headers {
                    write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len(),
                    )?;
                    stream.flush()?;
                }
                thread::sleep(Duration::from_millis(200));
                if send_headers {
                    stream.write_all(&body)
                } else {
                    respond(stream, 200, &body)
                }
            });
            let error = submit::<_, Reply>(
                &client(),
                &host.url,
                OPERATION_ID,
                &request(),
                Duration::from_millis(50),
            )
            .unwrap_err();
            assert_eq!(error, CancellationFailure::Timeout);
            host.finish();
        }
    }

    #[test]
    fn interrupted_response_is_unknown_and_does_not_expose_transport_diagnostics() {
        let host = TestHost::start(|stream| {
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: 256\r\nConnection: close\r\n\r\n{SECRET}",
            )
        });
        let error =
            submit::<_, Reply>(&client(), &host.url, OPERATION_ID, &request(), TEST_TIMEOUT)
                .unwrap_err();
        assert_eq!(error, CancellationFailure::Transport);
        assert!(!error.to_string().contains(SECRET));
        assert!(!format!("{error:?}").contains(SECRET));
        host.finish();
    }

    #[test]
    fn exhausted_timeout_fails_without_attempting_http() {
        let error = submit::<_, Value>(
            &client(),
            "not a URL",
            OPERATION_ID,
            &request(),
            Duration::ZERO,
        )
        .unwrap_err();
        assert_eq!(error, CancellationFailure::Timeout);
    }
}
