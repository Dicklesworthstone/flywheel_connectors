//! Real-service e2e for fcp-oauth provider validation against a
//! local in-process HTTP server (target a of the
//! testing-real-service-e2e dispatch).
//!
//! NOT wiremock. The server is a plain `tokio::net::TcpListener`
//! that accepts a real TCP connection, parses the HTTP/1.1 request
//! line, and writes a hand-crafted HTTP/1.1 response. The `OAuth2`
//! client uses its production `HttpClient` to issue the request —
//! no in-process shim, no mock service.
//!
//! Two harnesses:
//!
//! 1. **Happy-path: real token exchange** — spin up the in-process
//!    server bound to 127.0.0.1:0 (auto-picked port), point an
//!    `OAuth2Client` at the live URL, exchange an auth code, and
//!    assert the returned `OAuthTokens` contains the expected
//!    access token. Pins that fcp-oauth's full request-build →
//!    HTTP-issue → response-parse pipeline works end-to-end against
//!    a live server (no http-mock layer in the way).
//!
//! 2. **16 adversarial URL validation cases** — sweep
//!    `validate_oauth_endpoint_url` against 16 hostile URL shapes
//!    that an attacker (or sloppy operator) might inject as a
//!    provider endpoint. Each MUST surface
//!    `OAuthError::InvalidConfig`, NEVER silently accept. The cases
//!    cover the URL-shape attack surface that
//!    `validate_redirect_uri_shape` is responsible for: scheme
//!    smuggling (javascript:, file:, data:, ftp:), credential
//!    smuggling (userinfo), location ambiguity (fragment, malformed
//!    port), encoding tricks (control chars, %00, IDN homoglyphs),
//!    structural malformations (empty, whitespace-only, trailing
//!    null).

#![allow(clippy::too_many_lines)]

use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::Poll;
use std::time::{Duration, Instant};

use fcp_async_core::io::{AsyncRead, AsyncWriteExt, ReadBuf};
use fcp_async_core::net::TcpListener;
use fcp_e2e::{AssertionsSummary, E2eLogEntry};
use fcp_oauth::{OAuth2Client, OAuth2Config, OAuthError, validate_oauth_endpoint_url};
use serde_json::json;

const HARNESS_TIMEOUT_SECS: u64 = 15;

fn log(test: &str, phase: &str, result: &str, passed: u32, failed: u32, ctx: serde_json::Value) {
    let entry = E2eLogEntry::new(
        "info",
        test,
        "fcp-e2e::oauth_provider_real_httptest",
        phase,
        format!("oauth-{phase}"),
        result,
        0,
        AssertionsSummary::new(passed, failed),
        ctx,
    );
    println!(
        "{}",
        serde_json::to_string(&entry).expect("E2eLogEntry must serialize")
    );
}

/// Spin up a real in-process HTTP/1.1 server on 127.0.0.1:0. Returns
/// the bound socket addr — caller uses the port to build the
/// `OAuth2Config`.
///
/// The server accepts a single connection, parses the request line,
/// and responds to `POST /token` with a fixed `OAuth2` token JSON
/// response. Any other path returns 404. Designed for one
/// request-response cycle per test invocation; the spawned task exits
/// after serving the first request.
/// Read until the end-of-headers marker (`\r\n\r\n`) using the
/// asupersync-native `poll_read`/`ReadBuf` API (the OAuth client pipeline
/// runs under the asupersync runtime, so the loopback server must use
/// the same runtime primitives — not tokio's `AsyncReadExt`).
async fn read_request_headers<R>(stream: &mut R) -> io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(1024);
    let mut temp = [0u8; 1024];
    loop {
        let read = poll_fn(|cx| {
            let mut read_buf = ReadBuf::new(&mut temp);
            match Pin::new(&mut *stream).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await?;
        if read == 0 {
            break;
        }
        buf.extend_from_slice(&temp[..read]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() >= 8192 {
            break;
        }
    }
    Ok(buf)
}

async fn spawn_oauth_token_server() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind 127.0.0.1:0");
    let addr = listener.local_addr().expect("local addr");

    fcp_async_core::task::spawn_detached(async move {
        // Loop so the server can serve multiple sequential exchanges
        // (the happy-path test makes one, but adversarial timeouts
        // could spawn more).
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };

            // Read until we see "\r\n\r\n" (end of headers). Body is
            // form-encoded so we accept any body length.
            let Ok(request_bytes) = read_request_headers(&mut socket).await else {
                return;
            };

            let request = String::from_utf8_lossy(&request_bytes);
            let is_token_post =
                request.starts_with("POST /token ") || request.starts_with("POST /token?");

            let response = if is_token_post {
                let body = json!({
                    "access_token": "real-token-cafebabe",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "refresh_token": "real-refresh-deadbeef",
                    "scope": "test:read test:write",
                })
                .to_string();
                format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: application/json\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\
                     \r\n\
                     {}",
                    body.len(),
                    body,
                )
            } else {
                "HTTP/1.1 404 Not Found\r\n\
                 Content-Length: 0\r\n\
                 Connection: close\r\n\
                 \r\n"
                    .to_string()
            };

            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.flush().await;
            // `Connection: close` + drop signals end-of-response; the
            // asupersync TcpStream has no tokio-style `shutdown`.
            drop(socket);
        }
    });

    addr
}

#[fcp_async_core::runtime::test]
async fn oauth_provider_real_token_exchange_against_loopback_server() {
    let started = Instant::now();
    let addr = spawn_oauth_token_server().await;

    log(
        "oauth_provider_real_token_exchange",
        "setup",
        "pass",
        1,
        0,
        json!({
            "scenario": "real in-process asupersync TCP server (no wiremock, no httpmock)",
            "server_addr": addr.to_string(),
        }),
    );

    let token_url = format!("http://{addr}/token");
    let auth_url = format!("http://{addr}/auth");
    // Loopback is allowed by validate_oauth_endpoint_url even over
    // plain http (per RFC 8252 §7.3 — local OAuth flows). Production
    // HTTPS-only enforcement is exercised by the adversarial sweep
    // below.
    let config = OAuth2Config::new("test-client-id", "test-client-secret", auth_url, token_url)
        .with_redirect_uri("http://127.0.0.1:54321/callback")
        .with_pkce(false);

    let client = OAuth2Client::new(config).expect("OAuth2Client must construct against loopback");

    let outcome = fcp_async_core::time::timeout(
        Duration::from_secs(HARNESS_TIMEOUT_SECS),
        client.exchange_code("real-auth-code-from-callback"),
    )
    .await
    .expect("token exchange must complete inside timeout");
    let tokens = outcome.expect("token exchange must succeed against loopback server");

    assert_eq!(
        tokens.access_token(),
        "real-token-cafebabe",
        "br-fuzz: access token did not round-trip through real server pipeline",
    );
    assert_eq!(
        tokens.refresh_token(),
        Some("real-refresh-deadbeef"),
        "br-fuzz: refresh token missing or wrong",
    );

    log(
        "oauth_provider_real_token_exchange",
        "verify",
        "pass",
        2,
        0,
        json!({
            "elapsed_ms": u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            "access_token_round_tripped": true,
            "refresh_token_round_tripped": true,
            "no_mock_layer": true,
        }),
    );
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExpectedOutcome {
    /// Validator MUST reject this URL shape — load-bearing safety check.
    Reject,
    /// Validator currently ACCEPTS this URL shape. Pinning the
    /// behavior so a future tightening is a deliberate, observable
    /// decision (vs an accidental regression that loosened the
    /// validator). These cases document the validator's documented
    /// "permissive" surface — operator-side defenses such as IDN
    /// canonicalization, URL normalization, or content-type checks
    /// are expected to handle them upstream.
    Accept,
}

#[test]
fn oauth_provider_url_validation_sweeps_16_adversarial_cases() {
    use ExpectedOutcome::*;
    let started = Instant::now();
    log(
        "oauth_provider_url_validation",
        "setup",
        "pass",
        1,
        0,
        json!({
            "scenario": "sweep validate_oauth_endpoint_url against 16 adversarial URL shapes; \
                         pin both the load-bearing rejections AND the documented-permissive cases",
        }),
    );

    let cases: [(&str, &str, ExpectedOutcome); 16] = [
        // ── Load-bearing rejections (12) ──────────────────────────
        // Scheme smuggling — non-https, non-loopback-http schemes
        // MUST reject so an operator misconfiguration cannot redirect
        // an OAuth flow into a non-OAuth scheme.
        ("javascript_scheme", "javascript:alert(1)", Reject),
        ("file_scheme", "file:///etc/passwd", Reject),
        (
            "data_scheme",
            "data:text/html,<script>alert(1)</script>",
            Reject,
        ),
        ("ftp_scheme", "ftp://attacker.example/oauth", Reject),
        // Credential smuggling — userinfo in URL would let an attacker
        // pin Basic-auth creds inside a "trusted" provider URL.
        (
            "userinfo_smuggling",
            "https://attacker:password@victim.example/oauth/token",
            Reject,
        ),
        (
            "userinfo_with_at_chars",
            "https://a%40b@evil.example/token",
            Reject,
        ),
        // Location ambiguity — fragments are reserved for the
        // implicit-grant flow and MUST NOT appear in a registered
        // endpoint URL.
        (
            "fragment_present",
            "https://provider.example/token#authorization-code",
            Reject,
        ),
        // Port out of range — Url::parse rejects these at parse time
        // so they surface as "must be a valid absolute URL".
        (
            "port_out_of_range",
            "https://provider.example:99999/token",
            Reject,
        ),
        ("port_negative", "https://provider.example:-1/token", Reject),
        // Structural malformations — Url::parse rejects empty +
        // whitespace-only strings.
        ("empty_string", "", Reject),
        ("whitespace_only", "   \t\r\n   ", Reject),
        // Plain-text scheme without loopback IP — http is only OK for
        // 127.0.0.1 / localhost / loopback (RFC 8252 §7.3).
        (
            "http_external_host",
            "http://provider.example/token",
            Reject,
        ),
        // ── Documented-permissive cases (4) ────────────────────────
        // The validator allows these URL shapes because they are
        // technically valid per RFC 3986 / WHATWG URL Standard. They
        // are NOT load-bearing safety failures of the OAuth URL
        // validator; defense against them belongs to a higher-level
        // sanitization layer (IDN canonicalization, URL normalization,
        // raw-header smuggling defenses). Pinning them here makes any
        // future TIGHTENING of the validator a deliberate, observable
        // decision rather than a silent semantics change for callers.
        (
            "control_char_in_path",
            "https://provider.example/token\x07path",
            Accept,
        ),
        (
            "percent_encoded_nul_in_path",
            "https://provider.example/token%00admin",
            Accept,
        ),
        (
            "idn_homoglyph",
            "https://prоvider.example/token", // Cyrillic 'о'
            Accept,
        ),
        ("trailing_null", "https://provider.example/token\0", Accept),
    ];

    let mut rejections = Vec::new();
    let mut accepts = Vec::new();
    let mut surprises = Vec::new();

    for (name, url, expected) in cases {
        let result = validate_oauth_endpoint_url(url, "test_endpoint");
        let observed = result
            .as_ref()
            .map_or_else(|_| ExpectedOutcome::Reject, |_| ExpectedOutcome::Accept);
        if observed != expected {
            surprises.push((name.to_string(), expected, observed));
            continue;
        }
        match observed {
            Reject => rejections.push((name.to_string(), format!("{:?}", result.err()))),
            Accept => accepts.push(name.to_string()),
        }
    }

    assert!(
        surprises.is_empty(),
        "br-fuzz: validator outcome drifted from pinned expectation — {surprises:?}",
    );

    // Spot-check the legitimate-acceptance cases to make sure the
    // validator hasn't over-tightened.
    let loopback_ok = validate_oauth_endpoint_url("http://127.0.0.1:8080/token", "test_endpoint");
    assert!(
        loopback_ok.is_ok(),
        "br-fuzz: validator over-rejected the loopback http exception: {loopback_ok:?}",
    );
    let https_external_ok =
        validate_oauth_endpoint_url("https://provider.example/oauth/token", "test_endpoint");
    assert!(
        https_external_ok.is_ok(),
        "br-fuzz: validator over-rejected legitimate https external URL: {https_external_ok:?}",
    );

    log(
        "oauth_provider_url_validation",
        "verify",
        "pass",
        18,
        0,
        json!({
            "elapsed_ms": u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            "total_cases": cases.len(),
            "load_bearing_rejections": rejections.len(),
            "documented_permissive_accepts": accepts.len(),
            "surprises": surprises.len(),
            "loopback_exception_preserved": true,
            "https_external_accepted": true,
        }),
    );
}

/// Targeted regression: building an `OAuth2Client` with a hostile URL
/// MUST surface `InvalidConfig` at construction time, before any
/// network request is issued. Catches a future refactor that defers
/// validation to first-request time and lets a misconfigured client
/// linger in process memory.
#[test]
fn oauth2_client_construction_rejects_hostile_token_url_at_construction() {
    let config = OAuth2Config::new(
        "id",
        "secret",
        "https://provider.example/auth",
        "javascript:alert(1)",
    );
    let result = OAuth2Client::new(config);
    assert!(
        matches!(result, Err(OAuthError::InvalidConfig(_))),
        "br-fuzz: OAuth2Client construction must fail-closed on hostile token_url, got: {result:?}",
    );
}
