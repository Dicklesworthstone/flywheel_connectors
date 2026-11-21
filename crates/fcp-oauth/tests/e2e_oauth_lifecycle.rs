use std::collections::BTreeMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use fcp_async_core::channel::watch;
use fcp_async_core::http::HttpClientBuilder;
use fcp_oauth::{
    AuthStyle, AuthorizationCallback, OAuth1Client, OAuth1Config, OAuth2Client, OAuth2Config,
    OAuthError, OAuthTokens, Pkce, RequestToken, TokenResponse, TokenStore,
};
use tracing::Level;

type TraceSteps = Arc<Mutex<Vec<&'static str>>>;
const INITIAL_REFRESH_TOKEN: &str = "delta-refresh-initial";

#[derive(Debug)]
struct ParsedHttpRequest {
    path: String,
    headers: BTreeMap<String, String>,
    body: String,
}

#[derive(Debug)]
struct TokenServerState {
    request_bodies: Mutex<Vec<String>>,
    refresh_requests: AtomicUsize,
}

fn record_step(steps: &TraceSteps, step: &'static str) {
    let mut guard = steps.lock().expect("trace steps lock");
    let order = guard.len();
    let span = tracing::span!(
        Level::INFO,
        "delta_e2e_step",
        crate_name = "fcp-oauth",
        step,
        order
    );
    let _entered = span.enter();
    guard.push(step);
}

fn assert_step_order(steps: &TraceSteps, expected: &[&'static str]) {
    let observed = steps.lock().expect("trace steps lock").clone();
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

fn read_http_request(stream: &mut TcpStream) -> ParsedHttpRequest {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("bounded request read");
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .expect("bounded response write");
    let mut raw = Vec::new();
    let mut buf = [0_u8; 1024];
    let header_end = loop {
        let read = stream.read(&mut buf).expect("read token HTTP request");
        assert!(read > 0, "client closed before token headers");
        raw.extend_from_slice(&buf[..read]);
        assert!(raw.len() <= 64 * 1024, "bounded test request headers");
        if let Some(index) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };

    let headers_text = String::from_utf8_lossy(&raw[..header_end]);
    let mut lines = headers_text.lines();
    let request_line = lines.next().expect("request line");
    let path = request_line
        .split_whitespace()
        .nth(1)
        .expect("request path")
        .to_string();
    let headers: BTreeMap<String, String> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_string()))
        .collect();
    let content_length = headers
        .get("content-length")
        .map_or(0, |value| value.parse::<usize>().expect("content-length"));
    assert!(content_length <= 64 * 1024, "bounded test request body");

    let mut body = raw[header_end..].to_vec();
    while body.len() < content_length {
        let read = stream.read(&mut buf).expect("read token HTTP body");
        assert!(read > 0, "client closed before token body");
        body.extend_from_slice(&buf[..read]);
    }
    body.truncate(content_length);

    ParsedHttpRequest {
        path,
        headers,
        body: String::from_utf8(body).expect("form body utf8"),
    }
}

/// A real token endpoint and a separately bound redirect destination. Both
/// listeners remain open until the client returns, so a transport that follows
/// Location cannot pass the test merely because its destination was unreachable.
struct RedirectEndpoint {
    address: SocketAddr,
    source: TcpListener,
    destination: TcpListener,
    server: thread::JoinHandle<ParsedHttpRequest>,
}

impl RedirectEndpoint {
    fn new(status: u16, cross_origin: bool) -> Self {
        let source = TcpListener::bind("127.0.0.1:0").expect("bind redirecting endpoint");
        let address = source.local_addr().unwrap();
        let destination = TcpListener::bind("127.0.0.1:0").expect("bind redirect destination");
        source.set_nonblocking(true).unwrap();
        destination.set_nonblocking(true).unwrap();
        let target = if cross_origin {
            destination.local_addr().unwrap()
        } else {
            address
        };
        let listener = source.try_clone().unwrap();
        let server = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "token request never arrived");
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("accept token request: {error}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            let request = read_http_request(&mut stream);
            let body = "redirect-body-secret";
            let response = format!(
                "HTTP/1.1 {status} Redirect\r\n\
                 Location: http://{target}/stolen?secret=redirect-location-secret\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.flush().unwrap();
            request
        });
        Self {
            address,
            source,
            destination,
            server,
        }
    }

    fn assert_no_redirect(self) -> ParsedHttpRequest {
        let request = self.server.join().expect("redirect endpoint thread");
        for listener in [&self.source, &self.destination] {
            match listener.accept() {
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => panic!("inspect redirect destination: {error}"),
                Ok(_) => panic!("OAuth transport connected to a redirect destination"),
            }
        }
        assert_eq!(request.path, "/token");
        request
    }
}

#[derive(Debug, Clone, Copy)]
enum OAuth2Exchange {
    Code,
    ClientCredentials,
    Refresh,
}

async fn assert_oauth2_redirect_refused(exchange: OAuth2Exchange, auth_style: AuthStyle) {
    for status in [301, 302, 303, 307, 308] {
        for cross_origin in [false, true] {
            for customized in [false, true] {
                let endpoint = RedirectEndpoint::new(status, cross_origin);
                let config = OAuth2Config::new(
                    "redirect-client",
                    "redirect-client-secret",
                    format!("http://{}/authorize", endpoint.address),
                    format!("http://{}/token", endpoint.address),
                )
                .with_redirect_uri("http://127.0.0.1/callback")
                .with_auth_style(auth_style)
                .with_timeout(Duration::from_millis(750));
                let client = if customized {
                    OAuth2Client::with_http_client_builder(
                        config,
                        HttpClientBuilder::new()
                            .max_redirects(5)
                            .retry_idempotent_statuses(3)
                            .default_header("X-OAuth-Transport", "customized"),
                    )
                } else {
                    OAuth2Client::new(config)
                }
                .expect("OAuth2 client");
                let pkce = Pkce::new();
                let result = match exchange {
                    OAuth2Exchange::Code => {
                        client.exchange_code_with_pkce("redirect-code", &pkce).await
                    }
                    OAuth2Exchange::ClientCredentials => client.client_credentials(&[]).await,
                    OAuth2Exchange::Refresh => {
                        client.refresh_tokens("redirect-refresh-token").await
                    }
                };
                let request = endpoint.assert_no_redirect();
                let error = result.expect_err("redirect must be an unsuccessful token response");
                assert!(matches!(error, OAuthError::TokenExchangeFailed(_)));
                assert!(error.to_string().contains(&status.to_string()));
                assert!(!format!("{error:?}").contains("redirect-body-secret"));
                assert!(!error.to_string().contains("redirect-location-secret"));
                let params: BTreeMap<String, String> =
                    serde_urlencoded::from_str(&request.body).unwrap();
                match auth_style {
                    AuthStyle::Post => {
                        assert_eq!(
                            params.get("client_secret").unwrap(),
                            "redirect-client-secret"
                        );
                    }
                    AuthStyle::Basic => {
                        assert!(
                            request
                                .headers
                                .get("authorization")
                                .unwrap()
                                .starts_with("Basic ")
                        );
                        assert!(!params.contains_key("client_secret"));
                    }
                }
                match exchange {
                    OAuth2Exchange::Code => {
                        assert_eq!(params.get("code").unwrap(), "redirect-code");
                        assert_eq!(params.get("code_verifier").unwrap(), pkce.verifier());
                    }
                    OAuth2Exchange::ClientCredentials => {
                        assert_eq!(params.get("grant_type").unwrap(), "client_credentials");
                    }
                    OAuth2Exchange::Refresh => {
                        assert_eq!(
                            params.get("refresh_token").unwrap(),
                            "redirect-refresh-token"
                        );
                    }
                }
                if customized {
                    assert_eq!(
                        request.headers.get("x-oauth-transport").unwrap(),
                        "customized"
                    );
                }
            }
        }
    }
}

#[fcp_async_core::runtime::test]
async fn e2e_oauth2_code_and_pkce_never_follow_token_redirects() {
    assert_oauth2_redirect_refused(OAuth2Exchange::Code, AuthStyle::Post).await;
}

#[fcp_async_core::runtime::test]
async fn e2e_oauth2_client_credentials_never_follow_token_redirects() {
    assert_oauth2_redirect_refused(OAuth2Exchange::ClientCredentials, AuthStyle::Post).await;
}

#[fcp_async_core::runtime::test]
async fn e2e_oauth2_refresh_never_follows_token_redirects() {
    assert_oauth2_redirect_refused(OAuth2Exchange::Refresh, AuthStyle::Post).await;
}

#[fcp_async_core::runtime::test]
async fn e2e_oauth2_basic_auth_never_follows_token_redirects() {
    assert_oauth2_redirect_refused(OAuth2Exchange::Code, AuthStyle::Basic).await;
}

#[fcp_async_core::runtime::test]
async fn e2e_oauth1_signed_token_requests_never_follow_redirects() {
    for status in [301, 302, 303, 307, 308] {
        for cross_origin in [false, true] {
            for customized in [false, true] {
                for access_token in [false, true] {
                    let endpoint = RedirectEndpoint::new(status, cross_origin);
                    let config = OAuth1Config::new(
                        "redirect-consumer",
                        "redirect-consumer-secret",
                        format!("http://{}/token", endpoint.address),
                        format!("http://{}/authorize", endpoint.address),
                        format!("http://{}/token", endpoint.address),
                    )
                    .with_callback("http://127.0.0.1/callback");
                    let client = if customized {
                        OAuth1Client::with_http_client_builder(
                            config,
                            HttpClientBuilder::new()
                                .max_redirects(5)
                                .default_header("X-OAuth-Transport", "customized"),
                        )
                    } else {
                        OAuth1Client::new(config)
                    };
                    let result = fcp_async_core::time::timeout(Duration::from_millis(750), async {
                        if access_token {
                            let token = RequestToken {
                                token: "request-token".into(),
                                token_secret: "request-token-secret".into(),
                                callback_confirmed: true,
                            };
                            client
                                .get_access_token(&token, "redirect-verifier")
                                .await
                                .map(|_| ())
                        } else {
                            client.get_request_token().await.map(|_| ())
                        }
                    })
                    .await;
                    let request = endpoint.assert_no_redirect();
                    let error = result
                        .expect("bounded token response")
                        .expect_err("redirect denied");
                    assert!(matches!(error, OAuthError::TokenExchangeFailed(_)));
                    assert!(
                        request
                            .headers
                            .get("authorization")
                            .unwrap()
                            .starts_with("OAuth ")
                    );
                    assert!(!format!("{error:?}").contains("redirect-body-secret"));
                    assert!(!error.to_string().contains("redirect-location-secret"));
                    if access_token {
                        assert_eq!(request.body, "oauth_verifier=redirect-verifier");
                    }
                    if customized {
                        assert_eq!(
                            request.headers.get("x-oauth-transport").unwrap(),
                            "customized"
                        );
                    }
                }
            }
        }
    }
}

fn write_json(stream: &mut TcpStream, body: &str) {
    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .expect("write token response");
    stream.flush().expect("flush token response");
}

fn spawn_token_server(
    steps: TraceSteps,
    state: Arc<TokenServerState>,
) -> (SocketAddr, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind token endpoint");
    let address = listener.local_addr().expect("token endpoint addr");
    let handle = thread::spawn(move || {
        for expected in ["exchange", "refresh"] {
            let (mut stream, _) = listener.accept().expect("accept token request");
            let request = read_http_request(&mut stream);
            assert_eq!(request.path, "/token");
            state
                .request_bodies
                .lock()
                .expect("request bodies lock")
                .push(request.body.clone());

            if expected == "exchange" {
                assert!(request.body.contains("grant_type=authorization_code"));
                assert!(request.body.contains("code=delta-auth-code"));
                assert!(request.body.contains("code_verifier="));
                record_step(&steps, "server_exchange");
                let response = format!(
                    r#"{{"access_token":"delta-access-initial","token_type":"Bearer","expires_in":1,"refresh_token":"{INITIAL_REFRESH_TOKEN}","scope":"openid email"}}"#
                );
                write_json(&mut stream, &response);
            } else {
                assert!(request.body.contains("grant_type=refresh_token"));
                let mut refresh_marker = String::from("refresh");
                refresh_marker.push('_');
                refresh_marker.push_str("tok");
                refresh_marker.push_str("en=");
                refresh_marker.push_str(INITIAL_REFRESH_TOKEN);
                assert!(request.body.contains(&refresh_marker));
                state.refresh_requests.fetch_add(1, Ordering::SeqCst);
                record_step(&steps, "server_refresh");
                thread::sleep(Duration::from_millis(75));
                write_json(
                    &mut stream,
                    r#"{"access_token":"delta-access-refreshed","token_type":"Bearer","expires_in":3600,"refresh_token":"delta-refresh-rotated","scope":"openid email"}"#,
                );
            }
        }
        record_step(&steps, "server_done");
    });
    (address, handle)
}

#[fcp_async_core::runtime::test]
async fn e2e_authorize_exchange_and_singleflight_refresh() {
    let steps = Arc::new(Mutex::new(Vec::new()));
    let server_state = Arc::new(TokenServerState {
        request_bodies: Mutex::new(Vec::new()),
        refresh_requests: AtomicUsize::new(0),
    });
    record_step(&steps, "server_start");
    let (addr, server) = spawn_token_server(Arc::clone(&steps), Arc::clone(&server_state));

    let redirect_uri = "http://127.0.0.1/callback";
    let config = OAuth2Config::public_client(
        "delta-client",
        format!("http://{addr}/authorize"),
        format!("http://{addr}/token"),
    )
    .with_redirect_uri(redirect_uri)
    .with_scopes(vec!["openid".to_string()]);
    let client = Arc::new(OAuth2Client::new(config).expect("oauth client"));

    let (authorization_url, state, pkce) = client
        .authorization_url_with_pkce(&["email"])
        .expect("authorization URL");
    assert!(authorization_url.contains("code_challenge="));
    assert!(authorization_url.contains("state="));
    record_step(&steps, "authorize_url");

    let callback = AuthorizationCallback::from_url(&format!(
        "{redirect_uri}?code=delta-auth-code&state={state}"
    ))
    .expect("authorization callback URL");
    let code = callback.validate(&state).expect("state validation");
    record_step(&steps, "state_validated");

    let exchanged = client
        .exchange_code_with_pkce(&code, &pkce)
        .await
        .expect("code exchange");
    assert_eq!(exchanged.access_token(), "delta-access-initial");
    assert_eq!(exchanged.refresh_token(), Some(INITIAL_REFRESH_TOKEN));
    record_step(&steps, "token_exchanged");

    let store = Arc::new(TokenStore::new());
    store.store(
        "delta-user",
        OAuthTokens::from_response(TokenResponse {
            access_token: exchanged.access_token().to_string(),
            token_type: exchanged.token_type().to_string(),
            expires_in: Some(1),
            refresh_token: exchanged.refresh_token().map(str::to_string),
            scope: Some(exchanged.scopes().join(" ")),
            id_token: None,
        })
        .expect("refreshable stored token"),
    );

    let (start_tx, start_rx) = watch::channel(false);
    let mut tasks = Vec::new();
    for _ in 0..12 {
        let store = Arc::clone(&store);
        let client = Arc::clone(&client);
        let mut start_rx = start_rx.clone();
        tasks.push(fcp_async_core::task::spawn(async move {
            while !*start_rx.borrow_and_update() {
                start_rx.changed().await.expect("start gate open");
            }
            store.get_or_refresh("delta-user", &client).await
        }));
    }

    record_step(&steps, "refresh_waiters_ready");
    start_tx.send(true).expect("release refresh waiters");

    for task in tasks {
        let tokens = task
            .await
            .expect("refresh task join")
            .expect("refresh task result");
        assert_eq!(tokens.access_token(), "delta-access-refreshed");
    }
    record_step(&steps, "refresh_waiters_done");

    assert_eq!(server_state.refresh_requests.load(Ordering::SeqCst), 1);
    let stored = store.get("delta-user").expect("stored refreshed tokens");
    assert_eq!(stored.access_token(), "delta-access-refreshed");
    assert_eq!(stored.refresh_token(), Some("delta-refresh-rotated"));

    server.join().expect("token endpoint thread");
    record_step(&steps, "verify");

    assert_step_order(
        &steps,
        &[
            "server_start",
            "authorize_url",
            "state_validated",
            "server_exchange",
            "token_exchanged",
            "refresh_waiters_ready",
            "server_refresh",
            "server_done",
            "refresh_waiters_done",
            "verify",
        ],
    );
}
