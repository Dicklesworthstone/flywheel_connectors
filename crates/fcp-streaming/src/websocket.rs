//! WebSocket client implementation.
//!
//! Provides full WebSocket protocol support with automatic reconnection.

use std::collections::HashMap;
use std::future::{Future, poll_fn};
use std::io;
use std::net::Shutdown;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use chrono::{DateTime, Utc};
use fcp_async_core::{
    AsyncError,
    bytes::Bytes,
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    time::{Sleep, sleep, timeout},
    tls::{TlsConnector, TlsConnectorBuilder, TlsStream},
    websocket::{
        ClientHandshake, CloseCode, CloseConfig, CloseReason, HttpResponse, Message, WebSocket,
        WebSocketConfig, WsError, WsUrl,
    },
};
use futures_util::stream::Stream;

use crate::reconnect::ReconnectHandler;
use crate::{
    FCP_BACKPRESSURE_REASON_HEADER, FCP_BACKPRESSURE_RETRY_AFTER_HEADER, HOST_BACKPRESSURE_STATUS,
    HostBackpressureSignal, StreamError, StreamResult,
};

/// Hard ceiling for inbound WebSocket payloads, regardless of caller config.
pub const MAX_WEBSOCKET_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

fn websocket_cx() -> fcp_async_core::Cx {
    fcp_async_core::compatibility_cx()
}

fn websocket_config(config: &WsConfig) -> WebSocketConfig {
    let mut websocket_config = WebSocketConfig::new()
        .max_message_size(config.max_message_size.min(MAX_WEBSOCKET_MESSAGE_SIZE))
        .ping_interval(config.ping_interval)
        .connect_timeout(Some(config.connect_timeout));
    websocket_config.close_config = CloseConfig::new().with_timeout(config.pong_timeout);
    websocket_config
}

fn socket_addr(url: &WsUrl) -> String {
    if url.host.contains(':') {
        format!("[{}]:{}", url.host, url.port)
    } else {
        format!("{}:{}", url.host, url.port)
    }
}

fn connection_failed(message: impl Into<String>) -> StreamError {
    StreamError::ConnectionFailed(message.into())
}

fn parse_retry_after(value: &str) -> Option<Duration> {
    let value = value.trim();
    if let Ok(seconds) = value.parse::<u128>() {
        return Some(Duration::from_secs(
            u64::try_from(seconds).unwrap_or(u64::MAX),
        ));
    }

    let retry_at = DateTime::parse_from_rfc2822(value).ok()?;
    let wait = retry_at
        .with_timezone(&Utc)
        .signed_duration_since(Utc::now());
    if wait <= chrono::Duration::zero() {
        Some(Duration::ZERO)
    } else {
        wait.to_std().ok().or(Some(Duration::from_secs(u64::MAX)))
    }
}

fn max_retry_after(left: Option<Duration>, right: Option<Duration>) -> Option<Duration> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn host_backpressure_signal_from_response(
    response: &HttpResponse,
) -> Option<HostBackpressureSignal> {
    if response.status != HOST_BACKPRESSURE_STATUS {
        return None;
    }

    let reason = response.header(FCP_BACKPRESSURE_REASON_HEADER)?;
    let retry_after = max_retry_after(
        response.header("retry-after").and_then(parse_retry_after),
        response
            .header(FCP_BACKPRESSURE_RETRY_AFTER_HEADER)
            .and_then(parse_retry_after),
    );

    Some(HostBackpressureSignal::new(reason, retry_after))
}

fn http_error_from_response(response: &HttpResponse) -> StreamError {
    if let Some(signal) = host_backpressure_signal_from_response(response) {
        return StreamError::HostBackpressure {
            status: response.status,
            message: response.reason.clone(),
            signal,
        };
    }

    let retry_after = if response.status == 429 {
        response.header("retry-after").and_then(parse_retry_after)
    } else {
        None
    };

    StreamError::HttpError {
        status: response.status,
        message: response.reason.clone(),
        retry_after,
    }
}

/// Pick the reconnect delay, honouring a server `Retry-After` but never
/// letting it exceed the configured ceiling.
///
/// `Retry-After` is attacker-controlled: `parse_retry_after` maps an oversized
/// integer to `Duration::from_secs(u64::MAX)`, so an unclamped
/// `base.max(retry_after)` let one response header park the stream for ~584
/// billion years — the sleep never resolves, the connector never reconnects,
/// and its timer thread stays alive. `delay_for_attempt` already enforces
/// `max_delay`; the server-supplied value has to be intersected with the same
/// ceiling rather than allowed to override it.
fn reconnect_delay_for_error(handler: &ReconnectHandler, err: &StreamError) -> Duration {
    let config = handler.config();
    let base = config.delay_for_attempt(handler.attempts());
    err.retry_after().map_or(base, |retry_after| {
        base.max(retry_after).min(config.max_delay)
    })
}

fn websocket_error(err: WsError) -> StreamError {
    match err {
        WsError::PayloadTooLarge { size, max } => StreamError::BufferOverflow {
            size: usize::try_from(size).unwrap_or(usize::MAX),
            limit: max,
        },
        other => StreamError::WebSocketError(other.to_string()),
    }
}

fn build_handshake(url: &str, headers: &HashMap<String, String>) -> StreamResult<ClientHandshake> {
    let cx = websocket_cx();
    let mut handshake = ClientHandshake::new(url, cx.entropy())
        .map_err(|err| connection_failed(err.to_string()))?;
    for (name, value) in headers {
        handshake = handshake.header(name.clone(), value.clone());
    }
    Ok(handshake)
}

async fn write_all<IO>(io: &mut IO, buf: &[u8]) -> io::Result<()>
where
    IO: AsyncWrite + Unpin,
{
    let mut written = 0;
    while written < buf.len() {
        let n = poll_fn(|cx| Pin::new(&mut *io).poll_write(cx, &buf[written..])).await?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "write returned 0"));
        }
        written += n;
    }
    Ok(())
}

async fn read_http_response<IO>(io: &mut IO) -> io::Result<Vec<u8>>
where
    IO: AsyncRead + Unpin,
{
    let mut response = Vec::with_capacity(1024);
    let mut byte = [0_u8; 1];

    loop {
        if response.ends_with(b"\r\n\r\n") {
            return Ok(response);
        }

        if response.len() >= 16 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP response too large",
            ));
        }

        let n = poll_fn(|cx| {
            let mut read_buf = ReadBuf::new(&mut byte);
            match Pin::new(&mut *io).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await?;

        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF before HTTP response complete",
            ));
        }

        response.push(byte[0]);
    }
}

async fn perform_handshake<IO>(
    mut io: IO,
    url: &str,
    config: &WsConfig,
) -> StreamResult<WebSocket<IO>>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let handshake = build_handshake(url, &config.headers)?;
    let request = handshake.request_bytes();
    write_all(&mut io, &request)
        .await
        .map_err(|err| connection_failed(err.to_string()))?;

    let response_bytes = read_http_response(&mut io)
        .await
        .map_err(|err| connection_failed(err.to_string()))?;
    let response =
        HttpResponse::parse(&response_bytes).map_err(|err| connection_failed(err.to_string()))?;
    if response.status != 101 {
        return Err(http_error_from_response(&response));
    }
    handshake
        .validate_response(&response)
        .map_err(|err| connection_failed(err.to_string()))?;

    Ok(WebSocket::from_upgraded(io, websocket_config(config)))
}

fn build_tls_connector() -> StreamResult<TlsConnector> {
    TlsConnectorBuilder::new()
        .with_native_roots()
        .map_err(|err| connection_failed(err.to_string()))?
        .alpn_http()
        .build()
        .map_err(|err| connection_failed(err.to_string()))
}

struct WsTcpStream(TcpStream);

impl WsTcpStream {
    async fn connect(address: String) -> StreamResult<Self> {
        let tcp = TcpStream::connect(address)
            .await
            .map_err(|err| connection_failed(err.to_string()))?;
        let _ = tcp.set_nodelay(true);
        Ok(Self(tcp))
    }
}

impl AsyncRead for WsTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for WsTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl Drop for WsTcpStream {
    fn drop(&mut self) {
        let _ = self.0.shutdown(Shutdown::Both);
    }
}

enum WsTransport {
    Plain(Box<WebSocket<WsTcpStream>>),
    Tls(Box<WebSocket<TlsStream<WsTcpStream>>>),
}

impl WsTransport {
    async fn send(&mut self, message: Message) -> Result<(), WsError> {
        let cx = websocket_cx();
        match self {
            Self::Plain(socket) => socket.send(&cx, message).await,
            Self::Tls(socket) => socket.send(&cx, message).await,
        }
    }

    async fn recv(&mut self) -> Result<Option<Message>, WsError> {
        let cx = websocket_cx();
        match self {
            Self::Plain(socket) => socket.recv(&cx).await,
            Self::Tls(socket) => socket.recv(&cx).await,
        }
    }

    async fn close(&mut self, reason: CloseReason) -> Result<(), WsError> {
        let cx = websocket_cx();
        match self {
            Self::Plain(socket) => socket.close(&cx, reason).await,
            Self::Tls(socket) => socket.close(&cx, reason).await,
        }
    }
}

async fn connect_websocket(url: String, config: WsConfig) -> StreamResult<WsTransport> {
    let parsed = WsUrl::parse(&url).map_err(|err| connection_failed(err.to_string()))?;
    let address = socket_addr(&parsed);
    let tcp = WsTcpStream::connect(address).await?;

    if parsed.tls {
        let connector = build_tls_connector()?;
        let tls_stream = connector
            .connect(&parsed.host, tcp)
            .await
            .map_err(|err| connection_failed(err.to_string()))?;
        perform_handshake(tls_stream, &url, &config)
            .await
            .map(Box::new)
            .map(WsTransport::Tls)
    } else {
        perform_handshake(tcp, &url, &config)
            .await
            .map(Box::new)
            .map(WsTransport::Plain)
    }
}

/// WebSocket message types.
///
/// Binary/control payloads are stored as `Bytes` so that conversions
/// from the upstream `fastwebsockets::Message::Binary(Bytes)` (and the
/// matching Ping/Pong control frames) preserve the zero-copy
/// reference-counted buffer instead of memcpying into a fresh
/// `Vec<u8>` on every received frame (br-298cj).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsMessage {
    /// Text message.
    Text(String),
    /// Binary message.
    Binary(Bytes),
    /// Ping message.
    Ping(Bytes),
    /// Pong message.
    Pong(Bytes),
    /// Close message.
    Close(Option<WsCloseFrame>),
}

impl WsMessage {
    /// Create a text message.
    #[must_use]
    pub fn text(data: impl Into<String>) -> Self {
        Self::Text(data.into())
    }

    /// Create a binary message.
    #[must_use]
    pub fn binary(data: impl Into<Bytes>) -> Self {
        Self::Binary(data.into())
    }

    /// Create a ping control frame.
    #[must_use]
    pub fn ping(data: impl Into<Bytes>) -> Self {
        Self::Ping(data.into())
    }

    /// Create a pong control frame.
    #[must_use]
    pub fn pong(data: impl Into<Bytes>) -> Self {
        Self::Pong(data.into())
    }

    /// Check if this is a text message.
    #[must_use]
    pub const fn is_text(&self) -> bool {
        matches!(self, Self::Text(_))
    }

    /// Check if this is a binary message.
    #[must_use]
    pub const fn is_binary(&self) -> bool {
        matches!(self, Self::Binary(_))
    }

    /// Check if this is a close message.
    #[must_use]
    pub const fn is_close(&self) -> bool {
        matches!(self, Self::Close(_))
    }

    /// Get text data if this is a text message.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(data) => Some(data),
            _ => None,
        }
    }

    /// Get binary data if this is a binary message.
    #[must_use]
    pub fn as_binary(&self) -> Option<&[u8]> {
        match self {
            Self::Binary(data) => Some(data.as_ref()),
            _ => None,
        }
    }

    /// Parse text as JSON.
    ///
    /// # Errors
    /// Returns a JSON parsing error if the payload is not valid JSON.
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        match self {
            Self::Text(data) => serde_json::from_str(data),
            Self::Binary(data) => serde_json::from_slice(data.as_ref()),
            _ => Err(serde::de::Error::custom("Not a data message")),
        }
    }
}

impl From<CloseReason> for WsCloseFrame {
    fn from(reason: CloseReason) -> Self {
        Self {
            code: reason.wire_code().unwrap_or(1000),
            reason: reason.text.unwrap_or_default(),
        }
    }
}

impl From<WsCloseFrame> for CloseReason {
    fn from(frame: WsCloseFrame) -> Self {
        let raw_code = CloseCode::is_valid_code(frame.code).then_some(frame.code);
        Self {
            code: raw_code.and_then(CloseCode::from_u16),
            raw_code,
            text: (!frame.reason.is_empty()).then_some(frame.reason),
        }
    }
}

impl From<Message> for WsMessage {
    fn from(message: Message) -> Self {
        match message {
            Message::Text(text) => Self::Text(text),
            // br-298cj: zero-copy on the recv hot path.
            // `Bytes` is reference-counted, so moving it from
            // `Message::Binary(Bytes)` into `WsMessage::Binary(Bytes)`
            // is a pointer transfer — no memcpy, no reallocation.
            Message::Binary(data) => Self::Binary(data),
            Message::Ping(data) => Self::Ping(data),
            Message::Pong(data) => Self::Pong(data),
            Message::Close(reason) => Self::Close(reason.map(Self::close_frame_from_reason)),
        }
    }
}

impl WsMessage {
    fn close_frame_from_reason(reason: CloseReason) -> WsCloseFrame {
        reason.into()
    }
}

impl From<WsMessage> for Message {
    fn from(message: WsMessage) -> Self {
        match message {
            WsMessage::Text(text) => Self::Text(text),
            // Zero-copy send path: both sides already hold `Bytes`.
            WsMessage::Binary(data) => Self::Binary(data),
            WsMessage::Ping(data) => Self::Ping(data),
            WsMessage::Pong(data) => Self::Pong(data),
            WsMessage::Close(frame) => Self::Close(frame.map(CloseReason::from)),
        }
    }
}

/// WebSocket close frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsCloseFrame {
    /// Close code.
    pub code: u16,
    /// Close reason.
    pub reason: String,
}

impl WsCloseFrame {
    /// Create a new close frame.
    #[must_use]
    pub fn new(code: u16, reason: impl Into<String>) -> Self {
        Self {
            code,
            reason: reason.into(),
        }
    }

    /// Normal closure.
    #[must_use]
    pub fn normal() -> Self {
        Self::new(1000, "Normal closure")
    }

    /// Going away.
    #[must_use]
    pub fn going_away() -> Self {
        Self::new(1001, "Going away")
    }
}

/// WebSocket configuration.
#[derive(Clone)]
pub struct WsConfig {
    /// Connection timeout.
    pub connect_timeout: Duration,
    /// Ping interval.
    pub ping_interval: Option<Duration>,
    /// Pong timeout.
    pub pong_timeout: Duration,
    /// Maximum message size.
    pub max_message_size: usize,
    /// Additional headers.
    pub headers: HashMap<String, String>,
    /// Auto-reconnect on disconnect.
    pub auto_reconnect: bool,
    /// Maximum reconnection attempts.
    pub max_reconnect_attempts: Option<u32>,
    /// Reconnection delay.
    pub reconnect_delay: Duration,
}

impl std::fmt::Debug for WsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redacted_headers: HashMap<&str, &str> = self
            .headers
            .keys()
            .map(|key| (key.as_str(), "[REDACTED]"))
            .collect();

        f.debug_struct("WsConfig")
            .field("connect_timeout", &self.connect_timeout)
            .field("ping_interval", &self.ping_interval)
            .field("pong_timeout", &self.pong_timeout)
            .field("max_message_size", &self.max_message_size)
            .field("headers", &redacted_headers)
            .field("auto_reconnect", &self.auto_reconnect)
            .field("max_reconnect_attempts", &self.max_reconnect_attempts)
            .field("reconnect_delay", &self.reconnect_delay)
            .finish()
    }
}

impl Default for WsConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(30),
            ping_interval: Some(Duration::from_secs(30)),
            pong_timeout: Duration::from_secs(10),
            max_message_size: MAX_WEBSOCKET_MESSAGE_SIZE,
            headers: HashMap::new(),
            auto_reconnect: true,
            max_reconnect_attempts: Some(10),
            reconnect_delay: Duration::from_secs(1),
        }
    }
}

impl WsConfig {
    /// Create new configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set connection timeout.
    #[must_use]
    pub const fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Set ping interval.
    #[must_use]
    pub const fn with_ping_interval(mut self, interval: Option<Duration>) -> Self {
        self.ping_interval = interval;
        self
    }

    /// Set maximum message size.
    #[must_use]
    pub const fn with_max_message_size(mut self, size: usize) -> Self {
        self.max_message_size = if size > MAX_WEBSOCKET_MESSAGE_SIZE {
            MAX_WEBSOCKET_MESSAGE_SIZE
        } else {
            size
        };
        self
    }

    /// Add a header.
    #[must_use]
    pub fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }

    /// Set auto-reconnect.
    #[must_use]
    pub const fn with_auto_reconnect(mut self, enabled: bool) -> Self {
        self.auto_reconnect = enabled;
        self
    }

    fn io_timeout(&self) -> Duration {
        let keepalive_budget = self.ping_interval.map_or(self.pong_timeout, |interval| {
            interval.saturating_add(self.pong_timeout)
        });
        self.connect_timeout.max(keepalive_budget)
    }
}

/// WebSocket client.
#[derive(Clone)]
pub struct WsClient {
    url: String,
    config: WsConfig,
}

impl WsClient {
    /// Create a new WebSocket client.
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            config: WsConfig::default(),
        }
    }

    /// Create with configuration.
    #[must_use]
    pub fn with_config(url: impl Into<String>, config: WsConfig) -> Self {
        Self {
            url: url.into(),
            config,
        }
    }

    /// Connect to the WebSocket server.
    ///
    /// # Errors
    /// Returns an error if the connection attempt fails or times out.
    pub async fn connect(&self) -> StreamResult<WsConnection> {
        let connect_future = Box::pin(connect_websocket(self.url.clone(), self.config.clone()));
        let result = timeout(self.config.connect_timeout, connect_future)
            .await
            .map_err(|error| match error {
                AsyncError::Timeout { .. } => StreamError::Timeout(self.config.connect_timeout),
                other => StreamError::ConnectionFailed(other.to_string()),
            })?;

        Ok(WsConnection::new(result?, self.config.clone()))
    }

    /// Get the URL.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Get the configuration.
    #[must_use]
    pub const fn config(&self) -> &WsConfig {
        &self.config
    }

    /// Create a reconnecting stream.
    #[must_use]
    pub fn stream(&self) -> ReconnectingWsStream {
        ReconnectingWsStream::new(self.clone())
    }
}

/// Active WebSocket connection.
pub struct WsConnection {
    inner: Option<WsTransport>,
    config: WsConfig,
    closed: bool,
}

impl WsConnection {
    const fn new(inner: WsTransport, config: WsConfig) -> Self {
        Self {
            inner: Some(inner),
            config,
            closed: false,
        }
    }

    fn io_timeout(&self) -> Duration {
        self.config.io_timeout()
    }

    fn drop_transport(&mut self) {
        self.closed = true;
        let _ = self.inner.take();
    }

    fn timeout_error(&mut self) -> StreamError {
        self.drop_transport();
        StreamError::Timeout(self.io_timeout())
    }

    fn transport_mut(&mut self) -> StreamResult<&mut WsTransport> {
        self.inner
            .as_mut()
            .ok_or_else(|| StreamError::InvalidState("Connection is closed".into()))
    }

    /// Send a message.
    ///
    /// # Errors
    /// Returns a stream error if the message cannot be sent.
    pub async fn send(&mut self, message: WsMessage) -> StreamResult<()> {
        if self.closed {
            return Err(StreamError::InvalidState("Connection is closed".into()));
        }

        let is_close = message.is_close();
        let io_timeout = self.io_timeout();
        let result = {
            let transport = self.transport_mut()?;
            timeout(io_timeout, transport.send(message.into())).await
        };
        match result {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                let err = websocket_error(err);
                self.drop_transport();
                return Err(err);
            }
            Err(_) => return Err(self.timeout_error()),
        }
        if is_close {
            self.drop_transport();
        }
        Ok(())
    }

    /// Send a text message.
    ///
    /// # Errors
    /// Returns a stream error if the message cannot be sent.
    pub async fn send_text(&mut self, text: impl Into<String>) -> StreamResult<()> {
        self.send(WsMessage::text(text)).await
    }

    /// Send a binary message.
    ///
    /// # Errors
    /// Returns a stream error if the message cannot be sent.
    pub async fn send_binary(&mut self, data: impl Into<Bytes>) -> StreamResult<()> {
        self.send(WsMessage::binary(data)).await
    }

    /// Send JSON data.
    ///
    /// # Errors
    /// Returns a stream error if serialization or send fails.
    pub async fn send_json<T: serde::Serialize + Sync>(&mut self, data: &T) -> StreamResult<()> {
        let json =
            serde_json::to_string(data).map_err(|err| StreamError::ParseError(err.to_string()))?;
        self.send_text(json).await
    }

    /// Receive the next message.
    ///
    /// # Errors
    /// Returns a stream error if the underlying socket fails.
    pub async fn recv(&mut self) -> StreamResult<Option<WsMessage>> {
        if self.closed {
            return Ok(None);
        }

        let io_timeout = self.io_timeout();
        let result = {
            let transport = self.transport_mut()?;
            timeout(io_timeout, transport.recv()).await
        };
        let message = match result {
            Ok(Ok(message)) => message,
            Ok(Err(err)) => {
                let err = websocket_error(err);
                self.drop_transport();
                return Err(err);
            }
            Err(_) => return Err(self.timeout_error()),
        };
        if let Some(message) = message {
            let message: WsMessage = message.into();
            if message.is_close() {
                self.drop_transport();
            }
            Ok(Some(message))
        } else {
            self.drop_transport();
            Ok(None)
        }
    }

    /// Close the connection.
    ///
    /// # Errors
    /// Returns a stream error if the close handshake fails.
    pub async fn close(&mut self) -> StreamResult<()> {
        if !self.closed {
            let io_timeout = self.io_timeout();
            let result = {
                let transport = self.transport_mut()?;
                timeout(io_timeout, transport.close(CloseReason::normal())).await
            };
            match result {
                Ok(Ok(())) => self.drop_transport(),
                Ok(Err(err)) => {
                    let err = websocket_error(err);
                    self.drop_transport();
                    return Err(err);
                }
                Err(_) => return Err(self.timeout_error()),
            }
        }
        Ok(())
    }

    /// Close with a specific frame.
    ///
    /// # Errors
    /// Returns a stream error if the close handshake fails.
    pub async fn close_with_frame(&mut self, frame: WsCloseFrame) -> StreamResult<()> {
        if !self.closed {
            let io_timeout = self.io_timeout();
            let result = {
                let transport = self.transport_mut()?;
                timeout(io_timeout, transport.close(frame.into())).await
            };
            match result {
                Ok(Ok(())) => self.drop_transport(),
                Ok(Err(err)) => {
                    let err = websocket_error(err);
                    self.drop_transport();
                    return Err(err);
                }
                Err(_) => return Err(self.timeout_error()),
            }
        }
        Ok(())
    }

    /// Check if the connection is closed.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    /// Get the configuration.
    #[must_use]
    pub const fn config(&self) -> &WsConfig {
        &self.config
    }
}

type ConnectFuture = Pin<Box<dyn Future<Output = StreamResult<WsConnection>>>>;
type ReceiveFuture =
    Pin<Box<dyn Future<Output = (Box<WsConnection>, StreamResult<Option<WsMessage>>)>>>;

/// Reconnecting WebSocket stream.
pub struct ReconnectingWsStream {
    client: WsClient,
    handler: ReconnectHandler,
    state: ReconnectState,
    reset_backoff_after_first_message: bool,
}

enum ReconnectState {
    /// Initial state or between attempts.
    Idle,
    /// Waiting for backoff delay.
    Waiting(Pin<Box<Sleep>>),
    /// Connection attempt in progress.
    Connecting(ConnectFuture),
    /// Active connection ready to receive.
    Connected(Box<WsConnection>),
    /// Message receive in progress.
    Receiving(ReceiveFuture),
    /// The stream is finished and will yield `None` from here on.
    ///
    /// Reaching a terminal outcome MUST move the state machine here before
    /// returning. `Some(Err(_))` is a resumable `Stream` item, so a normal
    /// consumer polls again after one — and leaving a *completed*
    /// `Connecting`/`Receiving` future in `state` meant that next poll
    /// re-polled an `async` block that had already returned `Ready`, which
    /// panics with "`async fn` resumed after completion". This variant also
    /// makes the stream properly fused after `None`.
    Terminated,
}

impl ReconnectingWsStream {
    fn new(client: WsClient) -> Self {
        let config = crate::reconnect::ReconnectConfig::new()
            .with_max_attempts(if client.config.auto_reconnect {
                client.config.max_reconnect_attempts.unwrap_or(u32::MAX)
            } else {
                0
            })
            .with_initial_delay(client.config.reconnect_delay);

        Self {
            client,
            handler: ReconnectHandler::new(config),
            state: ReconnectState::Idle,
            reset_backoff_after_first_message: false,
        }
    }

    const fn note_connection_established(&mut self) {
        // A TCP/WebSocket handshake alone is not proof of a healthy session. If the
        // peer immediately closes before delivering any frame, keep the accumulated
        // retry budget so reconnect storms back off instead of restarting from zero.
        self.reset_backoff_after_first_message = true;
    }

    const fn note_message_received(&mut self, message: &WsMessage) {
        // br-hjaej + br-f46kk: only a data-carrying application frame
        // (Text or Binary) is proof of a healthy session. The earlier
        // fix (br-hjaej) correctly excluded Close, but Ping and Pong
        // control frames ALSO reach note_message_received via
        // Ok(Some(WsMessage::Ping/Pong(..))) from recv(), and an
        // adversarial peer that completes the WS handshake then
        // immediately streams Pings (or replays a Pong without our
        // initiating a Ping) would have still reset the retry budget
        // to zero — leaving the reconnect storm defence in place only
        // against Close-on-accept, not against Ping-flood-on-accept.
        // A genuine ping/pong round-trip is NOT observable at this
        // call site (we see inbound control frames only, not the
        // outbound ping that would prove reachability); to preserve
        // the invariant we only reset on Text / Binary.
        if !self.reset_backoff_after_first_message {
            return;
        }
        if !(message.is_text() || message.is_binary()) {
            return;
        }
        self.handler.reset();
        self.reset_backoff_after_first_message = false;
    }

    const fn note_connection_lost(&mut self) {
        self.reset_backoff_after_first_message = false;
    }
}

impl Stream for ReconnectingWsStream {
    type Item = StreamResult<WsMessage>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match &mut self.state {
                ReconnectState::Idle => {
                    let client = self.client.clone();
                    self.state =
                        ReconnectState::Connecting(Box::pin(async move { client.connect().await }));
                }
                ReconnectState::Waiting(delay) => match delay.as_mut().poll(cx) {
                    Poll::Ready(()) => self.state = ReconnectState::Idle,
                    Poll::Pending => return Poll::Pending,
                },
                ReconnectState::Terminated => return Poll::Ready(None),
                ReconnectState::Connecting(future) => match future.as_mut().poll(cx) {
                    Poll::Ready(Ok(connection)) => {
                        self.note_connection_established();
                        self.state = ReconnectState::Connected(Box::new(connection));
                    }
                    Poll::Ready(Err(err)) => {
                        if !self.handler.can_reconnect() {
                            self.state = ReconnectState::Terminated;
                            return Poll::Ready(Some(Err(err)));
                        }
                        let delay = reconnect_delay_for_error(&self.handler, &err);
                        self.handler.record_failure();
                        self.state = ReconnectState::Waiting(Box::pin(sleep(delay)));
                    }
                    Poll::Pending => return Poll::Pending,
                },
                ReconnectState::Connected(_) => {
                    let ReconnectState::Connected(connection) =
                        std::mem::replace(&mut self.state, ReconnectState::Idle)
                    else {
                        unreachable!();
                    };
                    self.state = ReconnectState::Receiving(Box::pin(async move {
                        let mut connection = connection;
                        let result = connection.recv().await;
                        (connection, result)
                    }));
                }
                ReconnectState::Receiving(future) => match future.as_mut().poll(cx) {
                    Poll::Ready((connection, Ok(Some(message)))) => {
                        self.note_message_received(&message);
                        self.state = ReconnectState::Connected(connection);
                        return Poll::Ready(Some(Ok(message)));
                    }
                    Poll::Ready((connection, Ok(None))) => {
                        drop(connection);
                        self.note_connection_lost();
                        if !self.handler.can_reconnect() {
                            self.state = ReconnectState::Terminated;
                            return Poll::Ready(None);
                        }
                        let attempt = self.handler.attempts();
                        let delay = self.handler.config().delay_for_attempt(attempt);
                        self.handler.record_failure();
                        self.state = ReconnectState::Waiting(Box::pin(sleep(delay)));
                    }
                    Poll::Ready((connection, Err(err))) => {
                        drop(connection);
                        self.note_connection_lost();
                        if !self.handler.can_reconnect() {
                            self.state = ReconnectState::Terminated;
                            return Poll::Ready(Some(Err(err)));
                        }
                        let delay = reconnect_delay_for_error(&self.handler, &err);
                        self.handler.record_failure();
                        self.state = ReconnectState::Waiting(Box::pin(sleep(delay)));
                    }
                    Poll::Pending => return Poll::Pending,
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener as StdTcpListener, TcpStream as StdTcpStream};
    use std::thread;

    use base64::Engine as _;
    use futures_util::StreamExt as _;
    use sha1::{Digest, Sha1};

    fn block_on<F>(future: F) -> F::Output
    where
        F: Future,
    {
        fcp_async_core::runtime::block_on_sync(future).expect("test runtime")
    }

    fn read_http_request(stream: &mut StdTcpStream) -> String {
        let mut request = Vec::new();
        let mut buf = [0_u8; 1024];
        while !request.ends_with(b"\r\n\r\n") {
            let n = stream.read(&mut buf).expect("read websocket handshake");
            assert!(n > 0, "client closed before handshake completed");
            request.extend_from_slice(&buf[..n]);
        }
        String::from_utf8(request).expect("websocket handshake utf8")
    }

    fn websocket_accept_value(key: &str) -> String {
        let mut digest = Sha1::new();
        digest.update(key.as_bytes());
        digest.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        base64::engine::general_purpose::STANDARD.encode(digest.finalize())
    }

    fn complete_server_handshake(stream: &mut StdTcpStream) {
        let request = read_http_request(stream);
        let key = request
            .lines()
            .find_map(|line| line.strip_prefix("Sec-WebSocket-Key: "))
            .expect("Sec-WebSocket-Key header");
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Connection: Upgrade\r\n\
             Upgrade: websocket\r\n\
             Sec-WebSocket-Accept: {}\r\n\
             \r\n",
            websocket_accept_value(key.trim())
        );
        stream
            .write_all(response.as_bytes())
            .expect("write websocket handshake response");
        stream.flush().expect("flush websocket handshake response");
    }

    fn spawn_blackhole_websocket_server(stall: Duration) -> (String, thread::JoinHandle<()>) {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind websocket test listener");
        let address = listener.local_addr().expect("listener addr");
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept websocket client");
            complete_server_handshake(&mut stream);
            thread::sleep(stall);
        });
        (format!("ws://{address}"), handle)
    }

    fn spawn_blackhole_then_message_server(
        stall: Duration,
        message: &'static str,
    ) -> (String, thread::JoinHandle<()>) {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind websocket test listener");
        let address = listener.local_addr().expect("listener addr");
        let handle = thread::spawn(move || {
            let (mut first, _) = listener.accept().expect("accept first websocket client");
            complete_server_handshake(&mut first);
            thread::sleep(stall);
            drop(first);

            let (mut second, _) = listener.accept().expect("accept second websocket client");
            complete_server_handshake(&mut second);
            let payload = message.as_bytes();
            assert!(
                payload.len() < 126,
                "test payload must fit in a short frame"
            );
            let short_payload_len = u8::try_from(payload.len())
                .expect("test payload length already asserted below 126 bytes");
            let mut frame = vec![0x81, short_payload_len];
            frame.extend_from_slice(payload);
            second.write_all(&frame).expect("write websocket frame");
            second.flush().expect("flush websocket frame");
        });
        (format!("ws://{address}"), handle)
    }

    #[test]
    fn ws_message_text_accessors() {
        let message = WsMessage::text("hello");
        assert!(message.is_text());
        assert!(!message.is_binary());
        assert_eq!(message.as_text(), Some("hello"));
        assert_eq!(message.as_binary(), None);
    }

    #[test]
    fn reconnect_stream_only_resets_backoff_after_first_message() {
        let client = WsClient::new("ws://localhost:8080");
        let mut stream = ReconnectingWsStream::new(client);

        stream.handler.record_failure();
        stream.handler.record_failure();
        assert_eq!(stream.handler.attempts(), 2);

        stream.note_connection_established();
        assert_eq!(stream.handler.attempts(), 2);
        assert!(stream.reset_backoff_after_first_message);

        stream.note_connection_lost();
        assert_eq!(stream.handler.attempts(), 2);
        assert!(!stream.reset_backoff_after_first_message);

        stream.note_connection_established();
        stream.note_message_received(&WsMessage::text("healthy"));
        assert_eq!(stream.handler.attempts(), 0);
        assert!(!stream.reset_backoff_after_first_message);
    }

    /// br-hjaej regression: a peer that completes the WS handshake and
    /// immediately sends Close still returns `Ok(Some(WsMessage::Close))`
    /// from `recv()`. The pre-fix `note_message_received` reset the backoff
    /// unconditionally on any Ok(Some(_)), which defeated the 6e6cr
    /// hardening and turned "handshake-then-close" into a near-hot
    /// reconnect loop. After the fix, Close frames leave the retry
    /// budget untouched.
    #[test]
    fn reconnect_stream_close_frame_does_not_reset_backoff() {
        let client = WsClient::new("ws://localhost:8080");
        let mut stream = ReconnectingWsStream::new(client);

        stream.handler.record_failure();
        stream.handler.record_failure();
        stream.handler.record_failure();
        assert_eq!(stream.handler.attempts(), 3);

        stream.note_connection_established();
        assert!(stream.reset_backoff_after_first_message);

        // Peer completes handshake and immediately sends Close.
        // This must NOT reset the backoff counter; the reset gate
        // stays armed so a subsequent data frame (if any) would still
        // clear it, but the retry budget is preserved.
        stream.note_message_received(&WsMessage::Close(None));
        assert_eq!(
            stream.handler.attempts(),
            3,
            "Close frame must NOT reset backoff (br-hjaej)"
        );
        assert!(
            stream.reset_backoff_after_first_message,
            "reset gate stays armed after Close so a subsequent data frame can still clear it"
        );
    }

    #[test]
    fn reconnect_stream_close_frame_with_reason_also_preserves_backoff() {
        let client = WsClient::new("ws://localhost:8080");
        let mut stream = ReconnectingWsStream::new(client);

        stream.handler.record_failure();
        assert_eq!(stream.handler.attempts(), 1);
        stream.note_connection_established();

        stream.note_message_received(&WsMessage::Close(Some(WsCloseFrame::new(
            1011,
            "server error",
        ))));
        assert_eq!(
            stream.handler.attempts(),
            1,
            "Close with reason payload must also preserve the retry budget"
        );
    }

    #[test]
    fn reconnect_stream_data_message_after_close_still_resets_backoff() {
        // The reset gate must remain armed after a Close so the first
        // real data frame on a *subsequent* successful connect can
        // clear it. This pins the "arm once, reset on first genuine
        // data" contract.
        let client = WsClient::new("ws://localhost:8080");
        let mut stream = ReconnectingWsStream::new(client);

        stream.handler.record_failure();
        stream.handler.record_failure();
        stream.note_connection_established();
        stream.note_message_received(&WsMessage::Close(None));
        assert_eq!(stream.handler.attempts(), 2);
        // A subsequent Text frame — the reset gate is still armed —
        // must now clear the retry budget.
        stream.note_message_received(&WsMessage::text("finally healthy"));
        assert_eq!(stream.handler.attempts(), 0);
        assert!(!stream.reset_backoff_after_first_message);
    }

    /// br-f46kk regression: Ping is a CONTROL frame, not proof of a
    /// healthy data path. An adversarial peer that completes the
    /// handshake and immediately streams Pings would otherwise have
    /// reset the retry budget through the hjaej-era gate, because
    /// hjaej excluded only Close. Now the reset predicate requires
    /// Text or Binary.
    #[test]
    fn reconnect_stream_ping_frame_does_not_reset_backoff() {
        let client = WsClient::new("ws://localhost:8080");
        let mut stream = ReconnectingWsStream::new(client);

        stream.handler.record_failure();
        stream.handler.record_failure();
        stream.handler.record_failure();
        assert_eq!(stream.handler.attempts(), 3);
        stream.note_connection_established();

        stream.note_message_received(&WsMessage::ping(vec![0x42; 4]));
        assert_eq!(
            stream.handler.attempts(),
            3,
            "Ping must NOT reset backoff (br-f46kk)"
        );
        assert!(
            stream.reset_backoff_after_first_message,
            "reset gate stays armed after Ping so a subsequent data frame can still clear it"
        );
    }

    /// br-f46kk regression: Pong is symmetric to Ping — an inbound
    /// Pong observed here is not a verified round-trip because this
    /// call site cannot distinguish "response to our Ping" from
    /// "unsolicited Pong the peer replayed to sneak past the gate".
    /// Only data frames reset.
    #[test]
    fn reconnect_stream_pong_frame_does_not_reset_backoff() {
        let client = WsClient::new("ws://localhost:8080");
        let mut stream = ReconnectingWsStream::new(client);

        stream.handler.record_failure();
        stream.handler.record_failure();
        stream.note_connection_established();

        stream.note_message_received(&WsMessage::pong(vec![0x00]));
        assert_eq!(
            stream.handler.attempts(),
            2,
            "Pong must NOT reset backoff (br-f46kk)"
        );
        assert!(stream.reset_backoff_after_first_message);
    }

    /// br-f46kk: after a burst of control frames (any mix of Close +
    /// Ping + Pong), the first genuine Text or Binary frame MUST
    /// still clear the retry budget. Control frames neither reset
    /// nor disarm the gate.
    #[test]
    fn reconnect_stream_data_frame_after_control_burst_resets_backoff() {
        let client = WsClient::new("ws://localhost:8080");
        let mut stream = ReconnectingWsStream::new(client);

        stream.handler.record_failure();
        stream.handler.record_failure();
        stream.handler.record_failure();
        stream.note_connection_established();

        stream.note_message_received(&WsMessage::ping(vec![1, 2]));
        stream.note_message_received(&WsMessage::pong(vec![3, 4]));
        stream.note_message_received(&WsMessage::Close(None));
        assert_eq!(
            stream.handler.attempts(),
            3,
            "control-frame burst must leave the budget intact"
        );
        assert!(stream.reset_backoff_after_first_message);

        // And the first data frame resets.
        stream.note_message_received(&WsMessage::binary(vec![0xAA; 8]));
        assert_eq!(stream.handler.attempts(), 0);
        assert!(!stream.reset_backoff_after_first_message);
    }

    #[test]
    fn ws_message_binary_accessors() {
        let message = WsMessage::binary(vec![1, 2, 3]);
        assert!(message.is_binary());
        assert!(!message.is_text());
        assert_eq!(message.as_binary(), Some(&[1, 2, 3][..]));
        assert_eq!(message.as_text(), None);
    }

    #[test]
    fn ws_message_json_supports_text_and_binary() {
        #[derive(Debug, serde::Deserialize, PartialEq, Eq)]
        struct Payload {
            key: String,
        }

        let text = WsMessage::text(r#"{"key":"value"}"#);
        let binary = WsMessage::binary(br#"{"key":"value"}"#.to_vec());

        assert_eq!(
            text.json::<Payload>().expect("text json"),
            Payload {
                key: "value".into(),
            }
        );
        assert_eq!(
            binary.json::<Payload>().expect("binary json"),
            Payload {
                key: "value".into(),
            }
        );
    }

    #[test]
    fn ws_message_json_rejects_control_messages() {
        assert!(WsMessage::ping(vec![]).json::<serde_json::Value>().is_err());
        assert!(WsMessage::pong(vec![]).json::<serde_json::Value>().is_err());
        assert!(WsMessage::Close(None).json::<serde_json::Value>().is_err());
    }

    #[test]
    fn ws_close_frame_builders() {
        assert_eq!(
            WsCloseFrame::normal(),
            WsCloseFrame::new(1000, "Normal closure")
        );
        assert_eq!(
            WsCloseFrame::going_away(),
            WsCloseFrame::new(1001, "Going away")
        );
    }

    #[test]
    fn ws_message_roundtrip_asupersync_text() {
        let original = WsMessage::text("roundtrip");
        let message: Message = original.clone().into();
        let roundtrip: WsMessage = message.into();
        assert_eq!(roundtrip, original);
    }

    #[test]
    fn ws_message_roundtrip_asupersync_binary() {
        let original = WsMessage::binary(vec![10, 20, 30]);
        let message: Message = original.clone().into();
        let roundtrip: WsMessage = message.into();
        assert_eq!(roundtrip, original);
    }

    #[test]
    fn ws_message_from_asupersync_close_frame() {
        let reason = CloseReason::with_text(CloseCode::Normal, "bye");
        let message: WsMessage = Message::Close(Some(reason)).into();
        assert_eq!(
            message,
            WsMessage::Close(Some(WsCloseFrame::new(1000, "bye")))
        );
    }

    #[test]
    fn ws_message_to_asupersync_close_frame() {
        let message: Message = WsMessage::Close(Some(WsCloseFrame::going_away())).into();
        let Message::Close(Some(reason)) = message else {
            panic!("expected close message");
        };
        assert_eq!(reason.wire_code(), Some(1001));
        assert_eq!(reason.text.as_deref(), Some("Going away"));
    }

    #[test]
    fn ws_config_builder() {
        let config = WsConfig::new()
            .with_connect_timeout(Duration::from_secs(60))
            .with_ping_interval(Some(Duration::from_secs(15)))
            .with_max_message_size(1024)
            .with_header("Authorization", "Bearer token")
            .with_auto_reconnect(false);

        assert_eq!(config.connect_timeout, Duration::from_secs(60));
        assert_eq!(config.ping_interval, Some(Duration::from_secs(15)));
        assert_eq!(config.max_message_size, 1024);
        assert_eq!(
            config.headers.get("Authorization"),
            Some(&"Bearer token".to_string())
        );
        assert!(!config.auto_reconnect);
    }

    #[test]
    fn ws_client_accessors() {
        let config = WsConfig::new().with_connect_timeout(Duration::from_secs(45));
        let client = WsClient::with_config("ws://localhost:8080", config);

        assert_eq!(client.url(), "ws://localhost:8080");
        assert_eq!(client.config().connect_timeout, Duration::from_secs(45));
    }

    #[test]
    fn ws_client_stream_construction() {
        let client = WsClient::new("ws://localhost:9999");
        let _stream = client.stream();
    }

    #[test]
    fn ws_client_invalid_url_returns_connection_failed() {
        block_on(async {
            let client = WsClient::new("not-a-valid-url");
            let result = client.connect().await;
            assert!(matches!(result, Err(StreamError::ConnectionFailed(_))));
        });
    }

    #[test]
    fn ws_client_connection_refused() {
        block_on(async {
            let client = WsClient::with_config(
                "ws://127.0.0.1:1",
                WsConfig::new().with_connect_timeout(Duration::from_millis(200)),
            );
            assert!(client.connect().await.is_err());
        });
    }

    #[test]
    fn ws_connection_recv_times_out_when_peer_blackholes_after_handshake() {
        // Server blackholes then drops TCP. We want recv() to observe
        // the blackhole as a timeout BEFORE TCP close, so the test must:
        //
        //   - Drive the steady-state I/O budget (`io_timeout()`) below
        //     the server stall. That budget is `connect_timeout.max(
        //     ping_interval + pong_timeout)` — both inputs need to be
        //     smaller than the stall.
        //   - Disable client-side keepalive pings so the budget collapses
        //     to `pong_timeout`. Otherwise the default
        //     `ping_interval = Some(30s)` swamps `pong_timeout`.
        //   - Choose `connect_timeout` loose enough to absorb dial jitter
        //     on loaded CI runners (TCP + HTTP-upgrade roundtrip can
        //     stretch past tens of milliseconds on shared infra), and the
        //     server stall comfortably above it so the timeout window has
        //     real headroom to fire before TCP close lands.
        //
        // Concretely: 300ms connect_timeout (≥3x typical local dial),
        // 1500ms stall (5x connect_timeout). Total test runtime is bound
        // by the stall (~1.5s) since `server.join()` blocks on the
        // server thread.
        let (url, server) = spawn_blackhole_websocket_server(Duration::from_millis(1500));
        let connect_timeout = Duration::from_millis(300);
        let pong_timeout = Duration::from_millis(50);

        block_on(async {
            let mut config = WsConfig::new().with_connect_timeout(connect_timeout);
            config.pong_timeout = pong_timeout;
            config.ping_interval = None;
            config.auto_reconnect = false;

            let client = WsClient::with_config(url, config);
            let mut connection = client.connect().await.expect("connect websocket");
            let err = connection.recv().await.expect_err("recv should time out");
            // Effective timeout is `connect_timeout.max(pong_timeout)`
            // when `ping_interval = None` — i.e. `connect_timeout` here
            // since the floor is the longer of the two.
            let expected_timeout = connect_timeout.max(pong_timeout);
            assert!(
                matches!(err, StreamError::Timeout(t) if t == expected_timeout),
                "expected Timeout({expected_timeout:?}), got {err:?}"
            );
            assert!(connection.is_closed());
            assert!(
                connection.inner.is_none(),
                "timed-out recv must drop the transport so TcpStream shutdown runs promptly"
            );
        });

        server.join().expect("websocket server thread");
    }

    #[test]
    fn reconnecting_stream_recovers_after_recv_timeout() {
        let (url, server) =
            spawn_blackhole_then_message_server(Duration::from_millis(250), "recovered");
        let timeout_duration = Duration::from_millis(50);

        block_on(async {
            let mut config = WsConfig::new().with_connect_timeout(Duration::from_secs(1));
            config.pong_timeout = timeout_duration;
            config.reconnect_delay = Duration::from_millis(10);
            config.max_reconnect_attempts = Some(3);

            let client = WsClient::with_config(url, config);
            let mut stream = client.stream();
            let item = timeout(
                Duration::from_secs(1),
                Box::pin(async { stream.next().await }),
            )
            .await
            .expect("stream should not hang")
            .expect("stream item")
            .expect("reconnected message");

            assert_eq!(item, WsMessage::text("recovered"));
        });

        server.join().expect("websocket server thread");
    }

    // ── WsMessage: close variant ───────────────────────────────────────

    #[test]
    fn ws_message_close_none() {
        let msg = WsMessage::Close(None);
        assert!(msg.is_close());
        assert!(!msg.is_text());
        assert!(!msg.is_binary());
        assert!(msg.as_text().is_none());
        assert!(msg.as_binary().is_none());
    }

    #[test]
    fn ws_message_close_with_frame() {
        let msg = WsMessage::Close(Some(WsCloseFrame::normal()));
        assert!(msg.is_close());
    }

    // ── WsMessage: ping/pong ───────────────────────────────────────────

    #[test]
    fn ws_message_ping_is_not_data() {
        let msg = WsMessage::ping(vec![1, 2, 3]);
        assert!(!msg.is_text());
        assert!(!msg.is_binary());
        assert!(!msg.is_close());
        assert!(msg.as_text().is_none());
        assert!(msg.as_binary().is_none());
    }

    #[test]
    fn ws_message_pong_is_not_data() {
        let msg = WsMessage::pong(vec![4, 5]);
        assert!(!msg.is_text());
        assert!(!msg.is_binary());
        assert!(!msg.is_close());
    }

    // ── WsMessage: equality ────────────────────────────────────────────

    #[test]
    fn ws_message_equality() {
        assert_eq!(WsMessage::text("a"), WsMessage::text("a"));
        assert_ne!(WsMessage::text("a"), WsMessage::text("b"));
        assert_ne!(WsMessage::text("a"), WsMessage::binary(b"a".to_vec()));
        assert_eq!(WsMessage::binary(vec![1, 2]), WsMessage::binary(vec![1, 2]));
        assert_ne!(WsMessage::binary(vec![1, 2]), WsMessage::binary(vec![3, 4]));
    }

    #[test]
    fn ws_message_clone() {
        let msg = WsMessage::text("clone me");
        let cloned = msg.clone();
        assert_eq!(msg, cloned);
    }

    #[test]
    fn ws_message_debug() {
        let msg = WsMessage::text("debug");
        let dbg = format!("{msg:?}");
        assert!(dbg.contains("Text"));
        assert!(dbg.contains("debug"));
    }

    // ── WsMessage: json edge cases ─────────────────────────────────────

    #[test]
    fn ws_message_json_invalid_text() {
        let msg = WsMessage::text("not json{");
        assert!(msg.json::<serde_json::Value>().is_err());
    }

    #[test]
    fn ws_message_json_binary_valid() {
        let msg = WsMessage::binary(b"42".to_vec());
        let val: i32 = msg.json().unwrap();
        assert_eq!(val, 42);
    }

    #[test]
    fn ws_message_json_empty_text() {
        let msg = WsMessage::text("");
        assert!(msg.json::<serde_json::Value>().is_err());
    }

    // ── WsMessage: empty payloads ──────────────────────────────────────

    #[test]
    fn ws_message_text_empty() {
        let msg = WsMessage::text("");
        assert!(msg.is_text());
        assert_eq!(msg.as_text(), Some(""));
    }

    #[test]
    fn ws_message_binary_empty() {
        let msg = WsMessage::binary(vec![]);
        assert!(msg.is_binary());
        assert_eq!(msg.as_binary(), Some(&[][..]));
    }

    // ── WsCloseFrame ───────────────────────────────────────────────────

    #[test]
    fn ws_close_frame_custom() {
        let frame = WsCloseFrame::new(4000, "custom close");
        assert_eq!(frame.code, 4000);
        assert_eq!(frame.reason, "custom close");
    }

    #[test]
    fn ws_close_frame_debug_clone_eq() {
        let frame = WsCloseFrame::normal();
        let cloned = frame.clone();
        assert_eq!(frame, cloned);
        let dbg = format!("{frame:?}");
        assert!(dbg.contains("WsCloseFrame"));
        assert!(dbg.contains("1000"));
    }

    #[test]
    fn ws_close_frame_empty_reason() {
        let frame = WsCloseFrame::new(1000, "");
        assert_eq!(frame.reason, "");
    }

    // ── WsCloseFrame conversions ───────────────────────────────────────

    #[test]
    fn ws_close_frame_roundtrip_through_close_reason() {
        let original = WsCloseFrame::new(1000, "normal");
        let reason: CloseReason = original.clone().into();
        let back: WsCloseFrame = reason.into();
        assert_eq!(back.code, original.code);
        assert_eq!(back.reason, original.reason);
    }

    #[test]
    fn ws_close_frame_from_close_reason_no_text() {
        let reason = CloseReason {
            code: Some(CloseCode::Normal),
            raw_code: Some(1000),
            text: None,
        };
        let frame: WsCloseFrame = reason.into();
        assert_eq!(frame.code, 1000);
        assert_eq!(frame.reason, "");
    }

    // ── WsConfig defaults ──────────────────────────────────────────────

    #[test]
    fn ws_config_defaults() {
        let config = WsConfig::default();
        assert_eq!(config.connect_timeout, Duration::from_secs(30));
        assert_eq!(config.ping_interval, Some(Duration::from_secs(30)));
        assert_eq!(config.pong_timeout, Duration::from_secs(10));
        assert_eq!(config.max_message_size, MAX_WEBSOCKET_MESSAGE_SIZE);
        assert!(config.headers.is_empty());
        assert!(config.auto_reconnect);
        assert_eq!(config.max_reconnect_attempts, Some(10));
        assert_eq!(config.reconnect_delay, Duration::from_secs(1));
    }

    #[test]
    fn ws_config_new_equals_default() {
        let a = WsConfig::new();
        let b = WsConfig::default();
        assert_eq!(a.connect_timeout, b.connect_timeout);
        assert_eq!(a.ping_interval, b.ping_interval);
        assert_eq!(a.max_message_size, b.max_message_size);
        assert_eq!(a.auto_reconnect, b.auto_reconnect);
    }

    #[test]
    fn ws_config_debug() {
        let config = WsConfig::default();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("WsConfig"));
    }

    #[test]
    fn ws_config_debug_redacts_header_values() {
        let config = WsConfig::new()
            .with_header("Authorization", "Bearer super-secret-token")
            .with_header("Cookie", "session=topsecret");
        let dbg = format!("{config:?}");
        assert!(dbg.contains("Authorization"));
        assert!(dbg.contains("Cookie"));
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("super-secret-token"));
        assert!(!dbg.contains("session=topsecret"));
    }

    #[test]
    fn ws_config_clone() {
        let config = WsConfig::new()
            .with_header("X-Custom", "value")
            .with_max_message_size(1024);
        let cloned = config.clone();
        assert_eq!(config.max_message_size, cloned.max_message_size);
        assert_eq!(cloned.headers.get("X-Custom"), Some(&"value".to_string()));
    }

    #[test]
    fn ws_config_multiple_headers() {
        let config = WsConfig::new()
            .with_header("A", "1")
            .with_header("B", "2")
            .with_header("A", "3"); // overwrite
        assert_eq!(config.headers.len(), 2);
        assert_eq!(config.headers.get("A"), Some(&"3".to_string()));
        assert_eq!(config.headers.get("B"), Some(&"2".to_string()));
    }

    #[test]
    fn ws_config_no_ping_interval() {
        let config = WsConfig::new().with_ping_interval(None);
        assert!(config.ping_interval.is_none());
    }

    // ── socket_addr helper ─────────────────────────────────────────────

    #[test]
    fn socket_addr_ipv4() {
        let url = WsUrl::parse("ws://127.0.0.1:8080/ws").unwrap();
        assert_eq!(socket_addr(&url), "127.0.0.1:8080");
    }

    #[test]
    fn socket_addr_hostname() {
        let url = WsUrl::parse("ws://example.com:443/ws").unwrap();
        assert_eq!(socket_addr(&url), "example.com:443");
    }

    #[test]
    fn socket_addr_ipv6() {
        let url = WsUrl {
            host: "::1".to_string(),
            port: 9090,
            path: "/ws".to_string(),
            tls: false,
        };
        assert_eq!(socket_addr(&url), "[::1]:9090");
    }

    // ── websocket_error conversion ─────────────────────────────────────

    #[test]
    fn websocket_error_payload_too_large() {
        let err = WsError::PayloadTooLarge {
            size: 2048,
            max: 1024,
        };
        let stream_err = websocket_error(err);
        assert!(matches!(
            stream_err,
            StreamError::BufferOverflow {
                size: 2048,
                limit: 1024
            }
        ));
    }

    #[test]
    fn websocket_error_generic() {
        let err = WsError::ProtocolViolation("test violation");
        let stream_err = websocket_error(err);
        assert!(matches!(stream_err, StreamError::WebSocketError(_)));
        assert!(stream_err.to_string().contains("test violation"));
    }

    // ── connection_failed helper ───────────────────────────────────────

    #[test]
    fn connection_failed_helper() {
        let err = connection_failed("test failure");
        assert!(matches!(err, StreamError::ConnectionFailed(ref s) if s == "test failure"));
    }

    #[test]
    fn retry_after_delta_seconds_parses() {
        assert_eq!(parse_retry_after("7"), Some(Duration::from_secs(7)));
    }

    #[test]
    fn retry_after_large_delta_seconds_saturates() {
        assert_eq!(
            parse_retry_after("340282366920938463463374607431768211455"),
            Some(Duration::from_secs(u64::MAX))
        );
    }

    #[test]
    fn http_error_from_429_response_preserves_retry_after() {
        let response =
            HttpResponse::parse(b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 7\r\n\r\n")
                .unwrap();
        let err = http_error_from_response(&response);
        assert!(matches!(
            err,
            StreamError::HttpError {
                status: 429,
                retry_after: Some(delay),
                ..
            } if delay == Duration::from_secs(7)
        ));
    }

    #[test]
    fn http_error_from_503_budget_backpressure_is_terminal() {
        let response = HttpResponse::parse(
            b"HTTP/1.1 503 Service Unavailable\r\n\
              X-FCP-Backpressure-Reason: budget-exhausted\r\n\
              Retry-After: 4\r\n\
              X-FCP-Backpressure-Retry-After: 12\r\n\r\n",
        )
        .unwrap();

        let err = http_error_from_response(&response);

        assert!(err.is_terminal_backpressure());
        assert_eq!(err.retry_after(), Some(Duration::from_secs(12)));
    }

    #[test]
    fn reconnect_delay_uses_retry_after_when_server_requests_longer_wait() {
        let config = crate::reconnect::ReconnectConfig::new()
            .with_initial_delay(Duration::from_millis(100))
            .with_max_delay(Duration::from_secs(30))
            .with_jitter(false);
        let handler = ReconnectHandler::new(config);
        let err = StreamError::HttpError {
            status: 429,
            message: "Too Many Requests".into(),
            retry_after: Some(Duration::from_secs(5)),
        };
        assert_eq!(
            reconnect_delay_for_error(&handler, &err),
            Duration::from_secs(5)
        );
    }

    #[test]
    fn reconnect_delay_keeps_backoff_when_retry_after_is_shorter_than_base() {
        let config = crate::reconnect::ReconnectConfig::new()
            .with_initial_delay(Duration::from_secs(2))
            .with_max_delay(Duration::from_secs(30))
            .with_jitter(false);
        let mut handler = ReconnectHandler::new(config);
        handler.record_failure();
        let err = StreamError::HttpError {
            status: 429,
            message: "Too Many Requests".into(),
            retry_after: Some(Duration::from_millis(500)),
        };
        assert_eq!(
            reconnect_delay_for_error(&handler, &err),
            Duration::from_secs(4)
        );
    }

    // ── WsMessage roundtrips: ping/pong ────────────────────────────────

    #[test]
    fn ws_message_roundtrip_ping() {
        let original = WsMessage::ping(vec![1, 2, 3]);
        let message: Message = original.clone().into();
        let roundtrip: WsMessage = message.into();
        assert_eq!(roundtrip, original);
    }

    #[test]
    fn ws_message_roundtrip_pong() {
        let original = WsMessage::pong(vec![4, 5, 6]);
        let message: Message = original.clone().into();
        let roundtrip: WsMessage = message.into();
        assert_eq!(roundtrip, original);
    }

    #[test]
    fn ws_message_roundtrip_close_none() {
        let original = WsMessage::Close(None);
        let message: Message = original.clone().into();
        let roundtrip: WsMessage = message.into();
        assert_eq!(roundtrip, original);
    }

    // ── WsClient clone ────────────────────────────────────────────────

    #[test]
    fn ws_client_clone() {
        let client = WsClient::new("ws://localhost:8080");
        let cloned = client.clone();
        assert_eq!(client.url(), cloned.url());
    }

    // ── WsMessage: unicode text ─────────────────────────────────────────

    #[test]
    fn ws_message_text_unicode() {
        let msg = WsMessage::text("\u{1F600}\u{1F4A9}\u{2764}\u{FE0F}");
        assert!(msg.is_text());
        assert_eq!(msg.as_text(), Some("\u{1F600}\u{1F4A9}\u{2764}\u{FE0F}"));
    }

    #[test]
    fn ws_message_text_cjk_characters() {
        let msg = WsMessage::text("\u{4F60}\u{597D}\u{4E16}\u{754C}");
        assert_eq!(msg.as_text().unwrap().chars().count(), 4);
    }

    #[test]
    fn ws_message_text_long() {
        let long_text = "a".repeat(100_000);
        let msg = WsMessage::text(long_text.clone());
        assert_eq!(msg.as_text(), Some(long_text.as_str()));
    }

    #[test]
    fn ws_message_binary_large() {
        let data = vec![0xAB_u8; 65_536];
        let msg = WsMessage::binary(data.clone());
        assert_eq!(msg.as_binary(), Some(data.as_slice()));
    }

    // ── WsMessage: json with various types ──────────────────────────────

    #[test]
    fn ws_message_json_text_number() {
        let msg = WsMessage::text("42");
        let val: i64 = msg.json().unwrap();
        assert_eq!(val, 42);
    }

    #[test]
    fn ws_message_json_text_string() {
        let msg = WsMessage::text(r#""hello""#);
        let val: String = msg.json().unwrap();
        assert_eq!(val, "hello");
    }

    #[test]
    fn ws_message_json_text_bool() {
        let msg = WsMessage::text("true");
        let val: bool = msg.json().unwrap();
        assert!(val);
    }

    #[test]
    fn ws_message_json_text_null() {
        let msg = WsMessage::text("null");
        let val: serde_json::Value = msg.json().unwrap();
        assert!(val.is_null());
    }

    #[test]
    fn ws_message_json_text_array() {
        let msg = WsMessage::text("[1,2,3]");
        let val: Vec<i32> = msg.json().unwrap();
        assert_eq!(val, vec![1, 2, 3]);
    }

    #[test]
    fn ws_message_json_binary_invalid() {
        let msg = WsMessage::binary(b"not json{".to_vec());
        assert!(msg.json::<serde_json::Value>().is_err());
    }

    #[test]
    fn ws_message_json_close_with_frame_rejects() {
        let msg = WsMessage::Close(Some(WsCloseFrame::normal()));
        assert!(msg.json::<serde_json::Value>().is_err());
    }

    // ── WsMessage: clone variants ───────────────────────────────────────

    #[test]
    fn ws_message_clone_binary() {
        let msg = WsMessage::binary(vec![1, 2, 3]);
        let cloned = msg.clone();
        assert_eq!(msg, cloned);
    }

    #[test]
    fn ws_message_clone_ping() {
        let msg = WsMessage::ping(vec![9, 8, 7]);
        let cloned = msg.clone();
        assert_eq!(msg, cloned);
    }

    #[test]
    fn ws_message_clone_pong() {
        let msg = WsMessage::pong(vec![5, 6]);
        let cloned = msg.clone();
        assert_eq!(msg, cloned);
    }

    #[test]
    fn ws_message_clone_close_none() {
        let msg = WsMessage::Close(None);
        let cloned = msg.clone();
        assert_eq!(msg, cloned);
    }

    #[test]
    fn ws_message_clone_close_with_frame() {
        let msg = WsMessage::Close(Some(WsCloseFrame::new(1002, "protocol error")));
        let cloned = msg.clone();
        assert_eq!(msg, cloned);
    }

    // ── WsMessage: debug variants ───────────────────────────────────────

    #[test]
    fn ws_message_debug_binary() {
        let msg = WsMessage::binary(vec![1, 2]);
        let dbg = format!("{msg:?}");
        assert!(dbg.contains("Binary"));
    }

    #[test]
    fn ws_message_debug_ping() {
        let msg = WsMessage::ping(vec![]);
        let dbg = format!("{msg:?}");
        assert!(dbg.contains("Ping"));
    }

    #[test]
    fn ws_message_debug_pong() {
        let msg = WsMessage::pong(vec![]);
        let dbg = format!("{msg:?}");
        assert!(dbg.contains("Pong"));
    }

    #[test]
    fn ws_message_debug_close() {
        let msg = WsMessage::Close(Some(WsCloseFrame::normal()));
        let dbg = format!("{msg:?}");
        assert!(dbg.contains("Close"));
    }

    // ── WsCloseFrame: additional tests ──────────────────────────────────

    #[test]
    fn ws_close_frame_unicode_reason() {
        let frame = WsCloseFrame::new(1000, "\u{1F44B} bye");
        assert_eq!(frame.reason, "\u{1F44B} bye");
    }

    #[test]
    fn ws_close_frame_max_code() {
        let frame = WsCloseFrame::new(u16::MAX, "max code");
        assert_eq!(frame.code, u16::MAX);
    }

    #[test]
    fn ws_close_frame_zero_code() {
        let frame = WsCloseFrame::new(0, "zero");
        assert_eq!(frame.code, 0);
    }

    #[test]
    fn ws_close_frame_long_reason() {
        let long_reason = "r".repeat(10_000);
        let frame = WsCloseFrame::new(1000, long_reason.clone());
        assert_eq!(frame.reason, long_reason);
    }

    #[test]
    fn ws_close_frame_equality_different_code() {
        let a = WsCloseFrame::new(1000, "same");
        let b = WsCloseFrame::new(1001, "same");
        assert_ne!(a, b);
    }

    #[test]
    fn ws_close_frame_equality_different_reason() {
        let a = WsCloseFrame::new(1000, "reason a");
        let b = WsCloseFrame::new(1000, "reason b");
        assert_ne!(a, b);
    }

    // ── WsConfig: additional builder tests ──────────────────────────────

    #[test]
    fn ws_config_connect_timeout_zero() {
        let config = WsConfig::new().with_connect_timeout(Duration::ZERO);
        assert_eq!(config.connect_timeout, Duration::ZERO);
    }

    #[test]
    fn ws_config_max_message_size_zero() {
        let config = WsConfig::new().with_max_message_size(0);
        assert_eq!(config.max_message_size, 0);
    }

    #[test]
    fn ws_config_max_message_size_large() {
        let config = WsConfig::new().with_max_message_size(usize::MAX);
        assert_eq!(config.max_message_size, MAX_WEBSOCKET_MESSAGE_SIZE);
    }

    #[test]
    fn websocket_config_enforces_hard_max_when_builder_tries_to_disable_cap() {
        let config = WsConfig::new().with_max_message_size(usize::MAX);
        let websocket_config = websocket_config(&config);

        assert_eq!(
            websocket_config.max_message_size,
            MAX_WEBSOCKET_MESSAGE_SIZE
        );
    }

    #[test]
    fn huge_payload_frame_rejected_even_when_config_requests_unbounded_size() {
        let config = WsConfig::new().with_max_message_size(usize::MAX);
        let websocket_config = websocket_config(&config);
        let oversized = websocket_config.max_message_size as u64 + 1;
        let stream_err = websocket_error(WsError::PayloadTooLarge {
            size: oversized,
            max: websocket_config.max_message_size,
        });

        assert!(matches!(
            stream_err,
            StreamError::BufferOverflow { size, limit }
                if size == MAX_WEBSOCKET_MESSAGE_SIZE + 1
                    && limit == MAX_WEBSOCKET_MESSAGE_SIZE
        ));
    }

    #[test]
    fn ws_config_header_overwrite() {
        let config = WsConfig::new()
            .with_header("Key", "val1")
            .with_header("Key", "val2");
        assert_eq!(config.headers.get("Key"), Some(&"val2".to_string()));
        assert_eq!(config.headers.len(), 1);
    }

    #[test]
    fn ws_config_auto_reconnect_toggle() {
        let config = WsConfig::new()
            .with_auto_reconnect(false)
            .with_auto_reconnect(true);
        assert!(config.auto_reconnect);
    }

    // ── WsClient: additional tests ──────────────────────────────────────

    #[test]
    fn ws_client_new_default_config() {
        let client = WsClient::new("ws://localhost:8080");
        assert_eq!(client.config().connect_timeout, Duration::from_secs(30));
        assert!(client.config().auto_reconnect);
    }

    #[test]
    fn ws_client_with_config_custom() {
        let config = WsConfig::new()
            .with_auto_reconnect(false)
            .with_max_message_size(512);
        let client = WsClient::with_config("ws://example.com/ws", config);
        assert!(!client.config().auto_reconnect);
        assert_eq!(client.config().max_message_size, 512);
    }

    #[test]
    fn ws_client_url_with_path() {
        let client = WsClient::new("ws://localhost:8080/api/v1/stream");
        assert_eq!(client.url(), "ws://localhost:8080/api/v1/stream");
    }

    #[test]
    fn ws_client_wss_url() {
        let client = WsClient::new("wss://secure.example.com/ws");
        assert_eq!(client.url(), "wss://secure.example.com/ws");
    }

    // ── Roundtrip edge cases ────────────────────────────────────────────

    #[test]
    fn ws_message_roundtrip_empty_text() {
        let original = WsMessage::text("");
        let message: Message = original.clone().into();
        let roundtrip: WsMessage = message.into();
        assert_eq!(roundtrip, original);
    }

    #[test]
    fn ws_message_roundtrip_empty_binary() {
        let original = WsMessage::binary(vec![]);
        let message: Message = original.clone().into();
        let roundtrip: WsMessage = message.into();
        assert_eq!(roundtrip, original);
    }

    #[test]
    fn ws_message_roundtrip_empty_ping() {
        let original = WsMessage::ping(vec![]);
        let message: Message = original.clone().into();
        let roundtrip: WsMessage = message.into();
        assert_eq!(roundtrip, original);
    }

    #[test]
    fn ws_message_roundtrip_empty_pong() {
        let original = WsMessage::pong(vec![]);
        let message: Message = original.clone().into();
        let roundtrip: WsMessage = message.into();
        assert_eq!(roundtrip, original);
    }

    // ── socket_addr edge cases ──────────────────────────────────────────

    #[test]
    fn socket_addr_ipv6_full() {
        let url = WsUrl {
            host: "2001:db8::1".to_string(),
            port: 443,
            path: "/ws".to_string(),
            tls: true,
        };
        assert_eq!(socket_addr(&url), "[2001:db8::1]:443");
    }

    #[test]
    fn socket_addr_default_port() {
        let url = WsUrl::parse("ws://example.com/ws").unwrap();
        assert_eq!(socket_addr(&url), "example.com:80");
    }

    // ── WsMessage: is_close on non-close variants ──────────────────────

    #[test]
    fn ws_message_text_is_not_close() {
        let msg = WsMessage::text("hello");
        assert!(!msg.is_close());
    }

    #[test]
    fn ws_message_binary_is_not_close() {
        let msg = WsMessage::binary(vec![1, 2, 3]);
        assert!(!msg.is_close());
    }

    #[test]
    fn ws_message_ping_is_not_close() {
        let msg = WsMessage::ping(vec![]);
        assert!(!msg.is_close());
    }

    #[test]
    fn ws_message_pong_is_not_close() {
        let msg = WsMessage::pong(vec![]);
        assert!(!msg.is_close());
    }

    // ── WsMessage: text with special content ────────────────────────────

    #[test]
    fn ws_message_text_with_newlines() {
        let msg = WsMessage::text("line1\nline2\nline3");
        assert_eq!(msg.as_text(), Some("line1\nline2\nline3"));
    }

    #[test]
    fn ws_message_text_with_null_bytes() {
        let msg = WsMessage::text("before\0after");
        assert_eq!(msg.as_text(), Some("before\0after"));
    }

    // ── WsMessage: binary with specific patterns ────────────────────────

    #[test]
    fn ws_message_binary_all_zeros() {
        let data = vec![0_u8; 256];
        let msg = WsMessage::binary(data.clone());
        assert_eq!(msg.as_binary(), Some(data.as_slice()));
    }

    #[test]
    fn ws_message_binary_all_0xff() {
        let data = vec![0xFF_u8; 128];
        let msg = WsMessage::binary(data.clone());
        assert_eq!(msg.as_binary(), Some(data.as_slice()));
    }

    // ── WsCloseFrame: well-known codes ──────────────────────────────────

    #[test]
    fn ws_close_frame_protocol_error_code() {
        let frame = WsCloseFrame::new(1002, "protocol error");
        assert_eq!(frame.code, 1002);
        assert_eq!(frame.reason, "protocol error");
    }

    #[test]
    fn ws_close_frame_unsupported_data_code() {
        let frame = WsCloseFrame::new(1003, "unsupported data");
        assert_eq!(frame.code, 1003);
    }

    #[test]
    fn ws_close_frame_abnormal_closure_code() {
        let frame = WsCloseFrame::new(1006, "abnormal closure");
        assert_eq!(frame.code, 1006);
    }

    // ── WsConfig: pong_timeout setter ───────────────────────────────────

    #[test]
    fn ws_config_pong_timeout_default() {
        let config = WsConfig::default();
        assert_eq!(config.pong_timeout, Duration::from_secs(10));
    }

    #[test]
    fn ws_config_reconnect_delay_default() {
        let config = WsConfig::default();
        assert_eq!(config.reconnect_delay, Duration::from_secs(1));
    }

    #[test]
    fn ws_config_max_reconnect_attempts_default() {
        let config = WsConfig::default();
        assert_eq!(config.max_reconnect_attempts, Some(10));
    }

    // ── websocket_error: additional WsError variants ────────────────────

    #[test]
    fn websocket_error_payload_zero_max() {
        let err = WsError::PayloadTooLarge { size: 100, max: 0 };
        let stream_err = websocket_error(err);
        assert!(matches!(
            stream_err,
            StreamError::BufferOverflow {
                size: 100,
                limit: 0
            }
        ));
    }

    // ── WsCloseFrame: From<CloseReason> with different codes ────────────

    #[test]
    fn ws_close_frame_from_close_reason_going_away() {
        let reason = CloseReason::with_text(CloseCode::GoingAway, "leaving");
        let frame: WsCloseFrame = reason.into();
        assert_eq!(frame.code, 1001);
        assert_eq!(frame.reason, "leaving");
    }

    #[test]
    fn ws_close_frame_into_close_reason_empty_reason() {
        let frame = WsCloseFrame::new(1000, "");
        let reason: CloseReason = frame.into();
        // Empty reason results in text being None
        assert!(reason.text.is_none());
    }

    #[test]
    fn ws_close_frame_into_close_reason_with_text() {
        let frame = WsCloseFrame::new(1000, "goodbye");
        let reason: CloseReason = frame.into();
        assert_eq!(reason.text.as_deref(), Some("goodbye"));
        assert_eq!(reason.raw_code, Some(1000));
    }

    // ── WsMessage: equality across variants ──

    #[test]
    fn ws_message_ne_text_vs_binary_same_content() {
        let text = WsMessage::text("hello");
        let binary = WsMessage::binary(b"hello".to_vec());
        assert_ne!(text, binary);
    }

    #[test]
    fn ws_message_ne_ping_vs_pong_same_data() {
        let outgoing = WsMessage::ping(vec![1, 2, 3]);
        let reply = WsMessage::pong(vec![1, 2, 3]);
        assert_ne!(outgoing, reply);
    }

    #[test]
    fn ws_message_ne_close_none_vs_close_some() {
        let none = WsMessage::Close(None);
        let some = WsMessage::Close(Some(WsCloseFrame::normal()));
        assert_ne!(none, some);
    }

    #[test]
    fn ws_message_eq_close_none_both() {
        let a = WsMessage::Close(None);
        let b = WsMessage::Close(None);
        assert_eq!(a, b);
    }

    // ── WsMessage: JSON with nested objects ──

    #[test]
    fn ws_message_json_text_nested_object() {
        let msg = WsMessage::text(r#"{"a":{"b":{"c":42}}}"#);
        let val: serde_json::Value = msg.json().unwrap();
        assert_eq!(val["a"]["b"]["c"], 42);
    }

    #[test]
    fn ws_message_json_binary_nested_array() {
        let msg = WsMessage::binary(b"[[1,2],[3,4]]".to_vec());
        let val: Vec<Vec<i32>> = msg.json().unwrap();
        assert_eq!(val, vec![vec![1, 2], vec![3, 4]]);
    }

    // ── WsMessage: as_text/as_binary on wrong variants ──

    #[test]
    fn ws_message_as_text_on_ping() {
        let msg = WsMessage::ping(vec![1]);
        assert!(msg.as_text().is_none());
    }

    #[test]
    fn ws_message_as_binary_on_pong() {
        let msg = WsMessage::pong(vec![1]);
        assert!(msg.as_binary().is_none());
    }

    #[test]
    fn ws_message_as_text_on_close() {
        let msg = WsMessage::Close(None);
        assert!(msg.as_text().is_none());
    }

    #[test]
    fn ws_message_as_binary_on_close() {
        let msg = WsMessage::Close(Some(WsCloseFrame::normal()));
        assert!(msg.as_binary().is_none());
    }

    // ── WsCloseFrame: roundtrip with various codes ──

    #[test]
    fn ws_close_frame_roundtrip_protocol_error() {
        let original = WsCloseFrame::new(1002, "protocol error");
        let reason: CloseReason = original.clone().into();
        let back: WsCloseFrame = reason.into();
        assert_eq!(back.code, original.code);
        assert_eq!(back.reason, original.reason);
    }

    #[test]
    fn ws_close_frame_roundtrip_going_away() {
        let original = WsCloseFrame::going_away();
        let reason: CloseReason = original.clone().into();
        let back: WsCloseFrame = reason.into();
        assert_eq!(back.code, original.code);
        assert_eq!(back.reason, original.reason);
    }

    // ── WsConfig: chained builder ──

    #[test]
    fn ws_config_full_builder_chain() {
        let config = WsConfig::new()
            .with_connect_timeout(Duration::from_secs(15))
            .with_ping_interval(Some(Duration::from_secs(20)))
            .with_max_message_size(2048)
            .with_header("Auth", "token")
            .with_auto_reconnect(false);
        assert_eq!(config.connect_timeout, Duration::from_secs(15));
        assert_eq!(config.ping_interval, Some(Duration::from_secs(20)));
        assert_eq!(config.max_message_size, 2048);
        assert_eq!(config.headers.get("Auth"), Some(&"token".to_string()));
        assert!(!config.auto_reconnect);
    }

    // ── WsClient: url edge cases ──

    #[test]
    fn ws_client_empty_url() {
        let client = WsClient::new("");
        assert_eq!(client.url(), "");
    }

    #[test]
    fn ws_client_unicode_url() {
        let client = WsClient::new("ws://\u{00FC}ber.example.com/ws");
        assert!(client.url().contains('\u{00FC}'));
    }

    // ── WsMessage: text constructor with Into<String> ──

    #[test]
    fn ws_message_text_from_string() {
        let s = String::from("owned string");
        let msg = WsMessage::text(s);
        assert_eq!(msg.as_text(), Some("owned string"));
    }

    #[test]
    fn ws_message_binary_from_array() {
        let msg = WsMessage::binary(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(msg.as_binary(), Some(&[0xDE, 0xAD, 0xBE, 0xEF][..]));
    }

    // ── socket_addr: additional cases ──

    #[test]
    fn socket_addr_wss_default_port() {
        let url = WsUrl::parse("wss://secure.example.com/ws").unwrap();
        assert_eq!(socket_addr(&url), "secure.example.com:443");
    }

    // ── websocket_error: PayloadTooLarge large size ──

    #[test]
    fn websocket_error_payload_large_u64_size() {
        let err = WsError::PayloadTooLarge {
            size: u64::MAX,
            max: 1024,
        };
        let stream_err = websocket_error(err);
        assert!(matches!(
            stream_err,
            StreamError::BufferOverflow {
                size: usize::MAX,
                limit: 1024
            }
        ));
    }

    // ── WsMessage: debug with long content ──

    #[test]
    fn ws_message_debug_long_text() {
        let long_text = "a".repeat(1000);
        let msg = WsMessage::text(long_text);
        let dbg = format!("{msg:?}");
        assert!(dbg.contains("Text"));
    }

    #[test]
    fn ws_message_debug_close_with_reason() {
        let msg = WsMessage::Close(Some(WsCloseFrame::new(1001, "going away")));
        let dbg = format!("{msg:?}");
        assert!(dbg.contains("Close"));
        assert!(dbg.contains("going away"));
    }
}
