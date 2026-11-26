//! GraphQL over WebSocket subscriptions.

use std::collections::HashMap;
use std::future::{Future, poll_fn};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::Duration;

use fcp_async_core::{
    channel::mpsc::{self, error::TrySendError},
    http::StatusCode,
    task, time,
};
use futures_util::stream::BoxStream;
use serde::{Deserialize, Serialize};
use tracing::debug;

use fcp_streaming::{
    ReconnectConfig, ReconnectHandler, StreamError, WsClient, WsConfig, WsConnection, WsMessage,
};

use crate::error::{GraphqlClientError, GraphqlError};
use crate::operation::{GraphqlOperation, GraphqlQueryLimits, GraphqlResponse};

/// GraphQL WebSocket message types (graphql-transport-ws).
#[derive(Debug, Serialize, Deserialize)]
struct GraphqlWsMessage {
    #[serde(rename = "type")]
    message_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    payload: Option<serde_json::Value>,
}

const GRAPHQL_WEBSOCKET_SUBPROTOCOL: &str = "graphql-transport-ws";
const SUBSCRIPTION_ID: &str = "1";
const SUBSCRIPTION_RESULT_BUFFER_CAPACITY: usize = 16;
const SUBSCRIPTION_CLOSE_TIMEOUT: Duration = Duration::from_millis(250);

/// Keep retry decisions attached to transport errors until they reach the caller.
#[derive(Debug)]
struct SubscriptionFailure {
    error: GraphqlClientError,
    retryable: bool,
    retry_after: Option<Duration>,
}

impl From<GraphqlClientError> for SubscriptionFailure {
    fn from(error: GraphqlClientError) -> Self {
        Self {
            error,
            retryable: false,
            retry_after: None,
        }
    }
}

impl From<StreamError> for SubscriptionFailure {
    fn from(error: StreamError) -> Self {
        let retry_after = error.retry_after();
        let retryable = !error.is_terminal_backpressure()
            && match &error {
                StreamError::HttpError { status, .. }
                | StreamError::HostBackpressure { status, .. } => {
                    matches!(status, 408 | 429 | 500..=599)
                }
                StreamError::ConnectionClosed { code, .. } => !matches!(
                    code,
                    Some(1002 | 1003 | 1007 | 1008 | 1009 | 1010 | 4400 | 4401 | 4403 | 4406 | 4409 | 4429)
                ),
                StreamError::ConnectionFailed(_)
                | StreamError::WebSocketError(_)
                | StreamError::IoError(_)
                | StreamError::Timeout(_) => true,
                _ => false,
            };
        Self {
            error: error.into(),
            retryable,
            retry_after,
        }
    }
}

/// Subscription configuration.
#[derive(Debug, Clone)]
pub struct GraphqlSubscriptionConfig {
    /// WebSocket configuration.
    pub ws: WsConfig,
    /// Initial payload for connection_init.
    pub init_payload: Option<serde_json::Value>,
    /// Time to wait for connection_ack.
    pub ack_timeout: Duration,
    /// Query resource limits enforced before WebSocket connection setup.
    pub query_limits: GraphqlQueryLimits,
}

impl Default for GraphqlSubscriptionConfig {
    fn default() -> Self {
        Self {
            ws: WsConfig::default(),
            init_payload: None,
            ack_timeout: Duration::from_secs(10),
            query_limits: GraphqlQueryLimits::default(),
        }
    }
}

/// Subscription stream type.
pub type GraphqlSubscriptionStream<T> =
    BoxStream<'static, Result<GraphqlResponse<T>, GraphqlClientError>>;

/// GraphQL subscription client.
#[derive(Debug, Clone)]
pub struct GraphqlSubscriptionClient {
    url: String,
    service_name: String,
    config: GraphqlSubscriptionConfig,
    headers: HashMap<String, String>,
}

impl GraphqlSubscriptionClient {
    /// Create a new subscription client.
    #[must_use]
    pub fn new(url: impl Into<String>, service_name: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            service_name: service_name.into(),
            config: GraphqlSubscriptionConfig::default(),
            headers: HashMap::new(),
        }
    }

    /// Set configuration.
    #[must_use]
    pub fn with_config(mut self, config: GraphqlSubscriptionConfig) -> Self {
        self.config = config;
        self
    }

    /// Add a header to the WebSocket handshake.
    #[must_use]
    pub fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }

    /// Subscribe to a typed GraphQL operation.
    pub async fn subscribe<O: GraphqlOperation>(
        &self,
        variables: O::Variables,
    ) -> Result<GraphqlSubscriptionStream<O::ResponseData>, GraphqlClientError>
    where
        O::ResponseData: 'static,
    {
        self.config.query_limits.validate(O::QUERY)?;

        let mut ws_config = self.config.ws.clone();
        if ws_config
            .required_subprotocol
            .as_deref()
            .is_some_and(|protocol| protocol != GRAPHQL_WEBSOCKET_SUBPROTOCOL)
        {
            return Err(GraphqlClientError::Protocol {
                message: "GraphQL subscriptions require the graphql-transport-ws subprotocol"
                    .to_owned(),
            });
        }
        ws_config.required_subprotocol = Some(GRAPHQL_WEBSOCKET_SUBPROTOCOL.to_owned());
        if self
            .config
            .init_payload
            .as_ref()
            .is_some_and(|payload| !payload.is_object() && !payload.is_null())
        {
            return Err(GraphqlClientError::Protocol {
                message: "connection_init payload must be an object or null".to_owned(),
            });
        }
        for (key, value) in &self.headers {
            ws_config.headers.insert(key.clone(), value.clone());
        }
        let client = WsClient::with_config(self.url.clone(), ws_config);
        let payload = serde_json::json!({
            "query": O::QUERY,
            "operationName": O::OPERATION_NAME,
            "variables": variables,
        });
        let connection = Box::pin(establish_subscription(
            &client,
            &self.service_name,
            self.config.init_payload.clone(),
            self.config.ack_timeout,
            &payload,
        ))
        .await
        .map_err(|failure| failure.error)?;

        let (tx, rx) = mpsc::channel(SUBSCRIPTION_RESULT_BUFFER_CAPACITY);
        let service_name = self.service_name.clone();
        let init_payload = self.config.init_payload.clone();
        let ack_timeout = self.config.ack_timeout;
        let reconnect_config = reconnect_config_from_ws(client.config());

        // br-xnroh: terminal-error slot, set by the producer task on
        // backpressure overflow (or any other fail-closed exit) and
        // observed by the consumer's stream after the channel
        // drains. This makes overflow distinguishable from a clean
        // server-initiated `complete`: instead of the consumer
        // observing only the queued Ok items followed by stream end,
        // it observes the queued Ok items, then a terminal Err,
        // then stream end.
        let terminal_error: Arc<Mutex<Option<GraphqlClientError>>> = Arc::new(Mutex::new(None));
        let producer_terminal = Arc::clone(&terminal_error);

        task::spawn_detached(async move {
            let mut conn = connection;
            let mut reconnect_handler = ReconnectHandler::new(reconnect_config);
            loop {
                fcp_async_core::select! {
                    () = tx.closed() => {
                        send_complete_and_close(&mut conn).await;
                        break;
                    },
                    recv = receive_subscription_message(&mut conn) => {
                        let message = match recv {
                            Ok(message) => message,
                            Err(failure) => {
                                match Box::pin(reconnect_connection(
                                    &client,
                                    &service_name,
                                    init_payload.clone(),
                                    ack_timeout,
                                    &payload,
                                    &mut reconnect_handler,
                                    &tx,
                                    failure,
                                ))
                                .await
                                {
                                    Ok(Some(new_conn)) => {
                                        conn = new_conn;
                                        continue;
                                    }
                                    Ok(None) => break,
                                    Err(err) => {
                                        let _ =
                                            deliver_subscription_item(
                                                &tx,
                                                &mut conn,
                                                &producer_terminal,
                                                Err(err),
                                            )
                                                .await;
                                        break;
                                    }
                                }
                            }
                        };

                match message {
                    WsMessage::Ping(payload) => {
                        match while_subscribed(&tx, conn.send(WsMessage::Pong(payload))).await {
                            Some(Ok(())) => continue,
                            None => {
                                send_complete_and_close(&mut conn).await;
                                break;
                            }
                            Some(Err(err)) => {
                                let _ = deliver_subscription_item(
                                    &tx,
                                    &mut conn,
                                    &producer_terminal,
                                    Err(err.into()),
                                )
                                .await;
                                break;
                            }
                        }
                    }
                    WsMessage::Pong(_) => continue,
                    WsMessage::Text(_) | WsMessage::Binary(_) | WsMessage::Close(_) => {}
                }

                match decode_ws_message(message) {
                    Ok(ws_msg) => match ws_msg.message_type.as_str() {
                        "next" => {
                            if let Err(err) = validate_subscription_message_id(&ws_msg) {
                                let _ = deliver_subscription_item(
                                    &tx,
                                    &mut conn,
                                    &producer_terminal,
                                    Err(err),
                                )
                                .await;
                                break;
                            }
                            match parse_next_payload::<O::ResponseData>(ws_msg.payload) {
                                Ok(response) => {
                                    if !deliver_subscription_item(
                                        &tx,
                                        &mut conn,
                                        &producer_terminal,
                                        Ok(response),
                                    )
                                    .await
                                    {
                                        break;
                                    }
                                    // An ACK alone does not prove a usable subscription.
                                    // Only delivered data replenishes the reconnect budget.
                                    reconnect_handler.reset();
                                }
                                Err(err) => {
                                    let _ = deliver_subscription_item(
                                        &tx,
                                        &mut conn,
                                        &producer_terminal,
                                        Err(err),
                                    )
                                    .await;
                                    break;
                                }
                            }
                        }
                        "error" => {
                            if let Err(err) = validate_subscription_message_id(&ws_msg) {
                                let _ = deliver_subscription_item(
                                    &tx,
                                    &mut conn,
                                    &producer_terminal,
                                    Err(err),
                                )
                                .await;
                                break;
                            }
                            let error = match parse_error_payload(ws_msg.payload) {
                                Ok(errors) => GraphqlClientError::GraphqlErrors { errors },
                                Err(err) => err,
                            };
                            let _ = deliver_subscription_item(
                                &tx,
                                &mut conn,
                                &producer_terminal,
                                Err(error),
                            )
                            .await;
                            break;
                        }
                        "complete" => {
                            if let Err(err) = validate_subscription_message_id(&ws_msg) {
                                let _ = deliver_subscription_item(
                                    &tx,
                                    &mut conn,
                                    &producer_terminal,
                                    Err(err),
                                )
                                .await;
                            }
                            break;
                        }
                        "ping" => {
                            match while_subscribed(&tx, reply_to_ping(&mut conn, ws_msg)).await {
                                Some(Ok(())) => {}
                                None => {
                                    send_complete_and_close(&mut conn).await;
                                    break;
                                }
                                Some(Err(failure)) => {
                                    let _ = deliver_subscription_item(
                                        &tx,
                                        &mut conn,
                                        &producer_terminal,
                                        Err(failure.error),
                                    )
                                    .await;
                                    break;
                                }
                            }
                        }
                        "pong" => {
                            if let Err(err) = validate_control_message(&ws_msg) {
                                let _ = deliver_subscription_item(
                                    &tx,
                                    &mut conn,
                                    &producer_terminal,
                                    Err(err),
                                )
                                .await;
                                break;
                            }
                        }
                        _ => {
                            let _ = deliver_subscription_item(
                                &tx,
                                &mut conn,
                                &producer_terminal,
                                Err(GraphqlClientError::Protocol {
                                    message: format!(
                                        "unexpected websocket message: {}",
                                        ws_msg.message_type
                                    ),
                                }),
                            )
                            .await;
                            break;
                        }
                    },
                    Err(err) => {
                        let _ = deliver_subscription_item(
                            &tx,
                            &mut conn,
                            &producer_terminal,
                            Err(GraphqlClientError::Protocol {
                                message: format!("decode failed: {err}"),
                            }),
                        )
                        .await;
                        break;
                    }
                }
                    }
                }
            }
        });

        // br-xnroh: the consumer's stream FIRST drains the channel
        // (yielding the queued Ok / Err items in arrival order),
        // THEN observes the terminal-error slot exactly once if the
        // producer set one (typically `SubscriptionBufferOverflow`),
        // THEN yields None to signal end-of-stream. This makes
        // backpressure overflow distinguishable from a clean
        // server-initiated `complete` for any consumer that drains
        // to the last item.
        Ok(Box::pin(futures_util::stream::unfold(
            (rx, terminal_error),
            |(mut receiver, terminal)| async move {
                if let Some(item) = receiver.recv().await {
                    return Some((item, (receiver, terminal)));
                }
                let pending_terminal = terminal
                    .lock()
                    .expect("subscription terminal-error mutex poisoned")
                    .take();
                if let Some(err) = pending_terminal {
                    return Some((Err(err), (receiver, terminal)));
                }
                None
            },
        )))
    }
}

async fn deliver_subscription_item<T>(
    tx: &mpsc::Sender<Result<GraphqlResponse<T>, GraphqlClientError>>,
    connection: &mut WsConnection,
    terminal_error: &Mutex<Option<GraphqlClientError>>,
    item: Result<GraphqlResponse<T>, GraphqlClientError>,
) -> bool {
    match tx.try_send(item) {
        Ok(()) => true,
        Err(TrySendError::Closed(_)) => {
            // Consumer dropped its receiver — no point publishing a
            // terminal error nobody will observe. Just close cleanly.
            send_complete_and_close(connection).await;
            false
        }
        Err(TrySendError::Full(_)) => {
            // br-xnroh: backpressure overflow MUST be observable to
            // the consumer as a terminal Err, not as a silent clean
            // EOF. Stage the error in the terminal slot BEFORE
            // closing the channel so the consumer's stream wrapper
            // (in `subscribe`) can yield it after draining the
            // already-queued Ok items.
            //
            // First-writer-wins: if multiple fail-closed paths race
            // we keep the FIRST cause for diagnostics; subsequent
            // attempts no-op via `get_or_insert`.
            debug!(
                capacity = SUBSCRIPTION_RESULT_BUFFER_CAPACITY,
                "graphql subscription result buffer full; closing subscription with \
                 terminal SubscriptionBufferOverflow error"
            );
            // Scope the MutexGuard tightly so it is dropped strictly
            // before the upcoming await — `std::sync::MutexGuard`
            // is `!Send` and the producer task's future must be
            // `Send` for `task::spawn_detached`.
            {
                let mut slot = terminal_error
                    .lock()
                    .expect("subscription terminal-error mutex poisoned");
                slot.get_or_insert(GraphqlClientError::SubscriptionBufferOverflow {
                    capacity: SUBSCRIPTION_RESULT_BUFFER_CAPACITY,
                });
            }
            send_complete_and_close(connection).await;
            false
        }
    }
}

fn reconnect_config_from_ws(config: &WsConfig) -> ReconnectConfig {
    let reconnect_config = ReconnectConfig::new().with_initial_delay(config.reconnect_delay);
    if !config.auto_reconnect {
        return reconnect_config.with_max_attempts(0);
    }
    match config.max_reconnect_attempts {
        Some(max_attempts) => reconnect_config.with_max_attempts(max_attempts),
        None => reconnect_config.with_unlimited_attempts(),
    }
}

async fn establish_subscription(
    client: &WsClient,
    service_name: &str,
    init_payload: Option<serde_json::Value>,
    ack_timeout: Duration,
    payload: &serde_json::Value,
) -> Result<WsConnection, SubscriptionFailure> {
    let mut connection = client.connect().await?;

    let init = GraphqlWsMessage {
        message_type: "connection_init".to_string(),
        id: None,
        payload: init_payload,
    };
    connection.send_json(&init).await?;

    // GraphQL and WebSocket heartbeats are legal before acknowledgement.
    // Bound the whole exchange once: heartbeats must not renew the deadline.
    time::timeout(ack_timeout, receive_connection_ack(&mut connection))
        .await
        .map_err(|_| SubscriptionFailure {
            error: GraphqlClientError::Protocol {
                message: format!("{service_name} connection_ack timeout"),
            },
            retryable: true,
            retry_after: None,
        })??;

    let subscribe = GraphqlWsMessage {
        message_type: "subscribe".to_string(),
        id: Some(SUBSCRIPTION_ID.to_string()),
        payload: Some(payload.clone()),
    };
    connection.send_json(&subscribe).await?;

    Ok(connection)
}

async fn receive_subscription_message(
    connection: &mut WsConnection,
) -> Result<WsMessage, SubscriptionFailure> {
    match connection.recv().await? {
        Some(WsMessage::Close(frame)) => Err(StreamError::ConnectionClosed {
            code: frame.as_ref().map(|frame| frame.code),
            reason: frame.map_or_else(
                || "websocket closed".to_owned(),
                |frame| format!("websocket closed with code {}", frame.code),
            ),
        }
        .into()),
        Some(message) => Ok(message),
        None => Err(StreamError::ConnectionClosed {
            code: None,
            reason: "connection closed".to_owned(),
        }
        .into()),
    }
}

async fn receive_connection_ack(connection: &mut WsConnection) -> Result<(), SubscriptionFailure> {
    loop {
        let message = receive_subscription_message(connection).await?;
        match message {
            WsMessage::Ping(payload) => {
                connection.send(WsMessage::Pong(payload)).await?;
            }
            WsMessage::Pong(_) => {}
            message => {
                let message = decode_ws_message(message)?;
                match message.message_type.as_str() {
                    "connection_ack" => {
                        return validate_control_message(&message).map_err(Into::into);
                    }
                    "ping" => reply_to_ping(connection, message).await?,
                    "pong" => validate_control_message(&message)?,
                    _ => {
                        return Err(GraphqlClientError::Protocol {
                            message: format!(
                                "expected connection_ack, got {}",
                                message.message_type
                            ),
                        }
                        .into());
                    }
                }
            }
        }
    }
}

fn validate_control_message(message: &GraphqlWsMessage) -> Result<(), GraphqlClientError> {
    if message.id.is_some()
        || message
            .payload
            .as_ref()
            .is_some_and(|payload| !payload.is_object() && !payload.is_null())
    {
        return Err(GraphqlClientError::Protocol {
            message: format!(
                "invalid {} control message: expected no operation id and an optional object payload",
                message.message_type
            ),
        });
    }
    Ok(())
}

async fn reply_to_ping(
    connection: &mut WsConnection,
    ping: GraphqlWsMessage,
) -> Result<(), SubscriptionFailure> {
    validate_control_message(&ping)?;
    let pong = GraphqlWsMessage {
        message_type: "pong".to_owned(),
        id: None,
        payload: ping.payload,
    };
    connection
        .send_json(&pong)
        .await
        .map_err(SubscriptionFailure::from)
}

/// Poll receiver closure first, including when both futures are already ready.
async fn while_subscribed<T, F: Future>(tx: &mpsc::Sender<T>, future: F) -> Option<F::Output> {
    let mut closed = std::pin::pin!(tx.closed());
    let mut future = std::pin::pin!(future);
    poll_fn(|cx| {
        if closed.as_mut().poll(cx).is_ready() {
            return Poll::Ready(None);
        }
        future.as_mut().poll(cx).map(Some)
    })
    .await
}

#[allow(clippy::too_many_arguments)]
async fn reconnect_connection<T>(
    client: &WsClient,
    service_name: &str,
    init_payload: Option<serde_json::Value>,
    ack_timeout: Duration,
    payload: &serde_json::Value,
    reconnect_handler: &mut ReconnectHandler,
    tx: &mpsc::Sender<T>,
    mut failure: SubscriptionFailure,
) -> Result<Option<WsConnection>, GraphqlClientError> {
    loop {
        if !failure.retryable {
            return Err(failure.error);
        }
        if !reconnect_handler.can_reconnect() {
            if matches!(failure.error, GraphqlClientError::HttpStatus { .. }) {
                return Err(failure.error);
            }
            return Err(GraphqlClientError::Protocol {
                message: format!(
                    "{service_name} subscription disconnected; reconnect exhausted after {} attempts: {}",
                    reconnect_handler.attempts(), failure.error
                ),
            });
        }

        match while_subscribed(
            tx,
            reconnect_handler.wait_for_reconnect_after(failure.retry_after),
        )
        .await
        {
            None => return Ok(None),
            Some(Ok(())) => {}
            // A provider minimum outside local policy must never be shortened.
            // Keep the upstream status and retry guidance for the caller.
            Some(Err(_)) => return Err(failure.error),
        }

        match while_subscribed(
            tx,
            establish_subscription(
                client,
                service_name,
                init_payload.clone(),
                ack_timeout,
                payload,
            ),
        )
        .await
        {
            None => return Ok(None),
            Some(Ok(connection)) => {
                debug!(service = service_name, "graphql subscription reconnected");
                return Ok(Some(connection));
            }
            Some(Err(next_failure)) => {
                debug!(
                    service = service_name,
                    attempt = reconnect_handler.attempts(),
                    error = %next_failure.error,
                    "graphql subscription reconnect attempt failed"
                );
                failure = next_failure;
            }
        }
    }
}

async fn send_complete_and_close(connection: &mut WsConnection) {
    let complete = GraphqlWsMessage {
        message_type: "complete".to_string(),
        id: Some(SUBSCRIPTION_ID.to_string()),
        payload: None,
    };
    // All callers terminate and drop the connection after this best-effort
    // cleanup; a peer that stops reading must not retain a detached producer.
    let _ = time::timeout(SUBSCRIPTION_CLOSE_TIMEOUT, async {
        let _ = connection.send_json(&complete).await;
        let _ = connection.close().await;
    })
    .await;
}

fn parse_next_payload<T: serde::de::DeserializeOwned>(
    payload: Option<serde_json::Value>,
) -> Result<GraphqlResponse<T>, GraphqlClientError> {
    let payload = payload.filter(serde_json::Value::is_object).ok_or_else(|| {
        GraphqlClientError::Protocol {
            message: "subscription next frame requires an object payload".to_owned(),
        }
    })?;
    serde_json::from_value(payload).map_err(|err| GraphqlClientError::Json(err.to_string()))
}

fn parse_error_payload(
    payload: Option<serde_json::Value>,
) -> Result<Vec<GraphqlError>, GraphqlClientError> {
    let invalid = || GraphqlClientError::Protocol {
        message: "subscription error frame requires a non-empty GraphQL error array".to_owned(),
    };
    let payload = payload.filter(serde_json::Value::is_array).ok_or_else(invalid)?;
    let errors: Vec<GraphqlError> = serde_json::from_value(payload).map_err(|_| invalid())?;
    if errors.is_empty() {
        return Err(invalid());
    }
    Ok(errors)
}

fn validate_subscription_message_id(ws_msg: &GraphqlWsMessage) -> Result<(), GraphqlClientError> {
    match ws_msg.id.as_deref() {
        Some(SUBSCRIPTION_ID) => Ok(()),
        Some(actual_id) => Err(GraphqlClientError::Protocol {
            message: format!(
                "subscription {} frame id mismatch: expected `{SUBSCRIPTION_ID}`, got `{actual_id}`",
                ws_msg.message_type
            ),
        }),
        None => Err(GraphqlClientError::Protocol {
            message: format!(
                "subscription {} frame missing id `{SUBSCRIPTION_ID}`",
                ws_msg.message_type
            ),
        }),
    }
}

fn decode_ws_message(message: WsMessage) -> Result<GraphqlWsMessage, GraphqlClientError> {
    match message {
        WsMessage::Text(text) => {
            serde_json::from_str(&text).map_err(|err| GraphqlClientError::Json(err.to_string()))
        }
        WsMessage::Binary(binary) => {
            serde_json::from_slice(&binary).map_err(|err| GraphqlClientError::Json(err.to_string()))
        }
        WsMessage::Ping(_) | WsMessage::Pong(_) => Err(GraphqlClientError::Protocol {
            message: "unexpected websocket ping/pong".to_string(),
        }),
        WsMessage::Close(_) => Err(GraphqlClientError::Protocol {
            message: "websocket closed".to_string(),
        }),
    }
}

/// Fuzz-only entry points for the GraphQL-over-WebSocket frame decoder.
///
/// Exposed for the `graphql_ws_message` libfuzzer target so it can drive the
/// private `decode_ws_message` entry point with adversarial `WsMessage` values
/// while keeping the production parser and its internal message type private.
///
/// Bead flywheel_connectors-ren6p.
#[doc(hidden)]
pub mod __fuzz {
    use super::{GraphqlClientError, WsMessage, decode_ws_message};

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct DecodedGraphqlWsMessage {
        pub message_type: String,
        pub id: Option<String>,
        pub payload: Option<serde_json::Value>,
    }

    pub fn decode_message(
        message: WsMessage,
    ) -> Result<DecodedGraphqlWsMessage, GraphqlClientError> {
        let decoded = decode_ws_message(message)?;
        Ok(DecodedGraphqlWsMessage {
            message_type: decoded.message_type,
            id: decoded.id,
            payload: decoded.payload,
        })
    }
}

impl From<StreamError> for GraphqlClientError {
    fn from(err: StreamError) -> Self {
        if err.is_terminal_backpressure() {
            return Self::Protocol {
                message: err.to_string(),
            };
        }
        match err {
            StreamError::HttpError {
                status,
                message,
                retry_after,
            } => Self::HttpStatus {
                status: StatusCode(status),
                body: message,
                retry_after,
            },
            StreamError::HostBackpressure {
                status,
                message,
                signal,
            } => Self::HttpStatus {
                status: StatusCode(status),
                body: message,
                retry_after: signal.retry_after(),
            },
            other => Self::Protocol {
                message: other.to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscription_retry_classification_preserves_http_guidance() {
        for (status, retryable) in [(401, false), (403, false), (429, true), (503, true)] {
            let failure = SubscriptionFailure::from(StreamError::HttpError {
                status,
                message: "upstream refusal".to_owned(),
                retry_after: Some(Duration::from_secs(7)),
            });
            assert_eq!(failure.retryable, retryable, "status {status}");
            assert_eq!(failure.retry_after, Some(Duration::from_secs(7)));
            match failure.error {
                GraphqlClientError::HttpStatus {
                    status: actual,
                    retry_after,
                    ..
                } => {
                    assert_eq!(actual.as_u16(), status);
                    assert_eq!(retry_after, Some(Duration::from_secs(7)));
                }
                other => panic!("HTTP refusal lost its status: {other:?}"),
            }
        }

        let failure = SubscriptionFailure::from(StreamError::HostBackpressure {
            status: 503,
            message: "host refusal".to_owned(),
            signal: fcp_streaming::HostBackpressureSignal::new(
                "budget-exhausted",
                Some(Duration::from_secs(7)),
            ),
        });
        assert!(!failure.retryable);
        assert!(!failure.error.is_retryable());
        assert_eq!(failure.retry_after, Some(Duration::from_secs(7)));
    }

    #[test]
    fn subscription_close_codes_distinguish_refusal_from_restart() {
        for code in [1002, 1003, 1007, 1008, 1009, 1010, 4400, 4401, 4403, 4406, 4409, 4429] {
            let failure = SubscriptionFailure::from(StreamError::ConnectionClosed {
                code: Some(code),
                reason: "refused".to_owned(),
            });
            assert!(!failure.retryable, "close code {code} must be terminal");
        }
        for code in [None, Some(1000), Some(1001), Some(1012), Some(1013), Some(4408)] {
            let failure = SubscriptionFailure::from(StreamError::ConnectionClosed {
                code,
                reason: "restart".to_owned(),
            });
            assert!(failure.retryable, "close code {code:?} may reconnect");
        }
    }

    #[test]
    fn subscription_payloads_require_valid_protocol_shapes() {
        for payload in [None, Some(serde_json::Value::Null), Some(serde_json::json!([])), Some(serde_json::json!(false))] {
            assert!(parse_next_payload::<serde_json::Value>(payload).is_err());
        }
        let response = parse_next_payload::<serde_json::Value>(Some(serde_json::json!({
            "errors": [{"message": "field unavailable"}]
        })))
        .expect("GraphQL error-only execution result is valid next payload");
        assert_eq!(response.errors.len(), 1);

        for payload in [
            None,
            Some(serde_json::Value::Null),
            Some(serde_json::json!([])),
            Some(serde_json::json!({"message": "not an array"})),
            Some(serde_json::json!([{"message": "valid"}, {"secret": "do-not-log"}])),
        ] {
            let error = parse_error_payload(payload).expect_err("malformed error payload");
            assert!(matches!(error, GraphqlClientError::Protocol { .. }));
            assert!(!error.to_string().contains("do-not-log"));
        }
        let errors = parse_error_payload(Some(serde_json::json!([{"message": "denied"}])))
            .expect("valid GraphQL error array");
        assert_eq!(errors[0].message, "denied");
    }

    #[fcp_async_core::runtime::test]
    async fn consumer_drop_wins_before_ready_reconnect_work() {
        let (tx, rx) = mpsc::channel::<()>(1);
        drop(rx);
        let operation = async {
            panic!("closed receiver must prevent new reconnect work from being polled");
        };
        assert_eq!(while_subscribed(&tx, operation).await, None);
    }

    #[fcp_async_core::runtime::test]
    async fn consumer_drop_cancels_and_drops_in_flight_reconnect_work() {
        use std::sync::atomic::{AtomicBool, Ordering};

        struct DropSignal(Arc<AtomicBool>);
        impl Drop for DropSignal {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let (tx, rx) = mpsc::channel::<()>(1);
        let (started_tx, started_rx) = fcp_async_core::channel::oneshot::channel();
        let dropped = Arc::new(AtomicBool::new(false));
        let signal = DropSignal(Arc::clone(&dropped));
        let worker = task::spawn(async move {
            while_subscribed(&tx, async move {
                let _signal = signal;
                started_tx.send(()).expect("consumer alive");
                std::future::pending::<()>().await;
            })
            .await
        });
        time::timeout(Duration::from_secs(1), started_rx)
            .await
            .expect("work started promptly")
            .expect("work start signal");
        drop(rx);
        assert_eq!(
            time::timeout(Duration::from_millis(250), worker)
                .await
                .expect("consumer cancellation must interrupt the pending future")
                .expect("worker joined"),
            None
        );
        assert!(dropped.load(Ordering::SeqCst));
    }

    // ---- GraphqlWsMessage serde ----

    #[test]
    fn ws_message_serialize_connection_init() {
        let msg = GraphqlWsMessage {
            message_type: "connection_init".to_string(),
            id: None,
            payload: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains(r#""type":"connection_init"#));
        assert_eq!(json, r#"{"type":"connection_init"}"#);
    }

    #[test]
    fn control_messages_reject_operation_ids_and_non_object_payloads() {
        for kind in ["connection_ack", "ping", "pong"] {
            for payload in [
                None,
                Some(serde_json::json!({})),
                Some(serde_json::Value::Null),
            ] {
                let mut message = GraphqlWsMessage {
                    message_type: kind.to_owned(),
                    id: None,
                    payload,
                };
                assert!(validate_control_message(&message).is_ok());
                message.id = Some(SUBSCRIPTION_ID.to_owned());
                assert!(validate_control_message(&message).is_err());
            }
            for payload in [
                serde_json::json!([]),
                serde_json::json!("secret-value"),
                serde_json::json!(42),
                serde_json::json!(true),
            ] {
                let message = GraphqlWsMessage {
                    message_type: kind.to_owned(),
                    id: None,
                    payload: Some(payload),
                };
                let error = validate_control_message(&message).expect_err("invalid control shape");
                assert!(!error.to_string().contains("secret-value"));
            }
        }
    }

    #[test]
    fn ws_message_serialize_subscribe() {
        let msg = GraphqlWsMessage {
            message_type: "subscribe".to_string(),
            id: Some("1".to_string()),
            payload: Some(serde_json::json!({"query": "subscription { events }"})),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains(r#""type":"subscribe"#));
        assert!(json.contains(r#""id":"1"#));
        assert!(json.contains("events"));
    }

    #[test]
    fn ws_message_deserialize_next() {
        let json = r#"{"type":"next","id":"1","payload":{"data":{"event":"hello"}}}"#;
        let msg: GraphqlWsMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.message_type, "next");
        assert_eq!(msg.id.as_deref(), Some("1"));
        assert!(msg.payload.is_some());
    }

    #[test]
    fn ws_message_deserialize_complete() {
        let json = r#"{"type":"complete","id":"1"}"#;
        let msg: GraphqlWsMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.message_type, "complete");
        assert_eq!(msg.id.as_deref(), Some("1"));
        assert!(msg.payload.is_none());
    }

    #[test]
    fn ws_message_deserialize_connection_ack() {
        let json = r#"{"type":"connection_ack"}"#;
        let msg: GraphqlWsMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.message_type, "connection_ack");
        assert!(msg.id.is_none());
        assert!(msg.payload.is_none());
    }

    #[test]
    fn ws_message_deserialize_error() {
        let json = r#"{"type":"error","id":"1","payload":[{"message":"syntax error"}]}"#;
        let msg: GraphqlWsMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.message_type, "error");
        assert!(msg.payload.unwrap().is_array());
    }

    #[test]
    fn ws_message_roundtrip() {
        let msg = GraphqlWsMessage {
            message_type: "ping".to_string(),
            id: None,
            payload: Some(serde_json::json!({})),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let back: GraphqlWsMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(back.message_type, "ping");
    }

    // ---- validate_subscription_message_id ----

    #[test]
    fn subscription_message_id_accepts_expected_id() {
        let msg = GraphqlWsMessage {
            message_type: "next".to_string(),
            id: Some(SUBSCRIPTION_ID.to_string()),
            payload: None,
        };
        assert!(validate_subscription_message_id(&msg).is_ok());
    }

    #[test]
    fn subscription_message_id_rejects_wrong_id() {
        let msg = GraphqlWsMessage {
            message_type: "error".to_string(),
            id: Some("stale-99".to_string()),
            payload: None,
        };
        match validate_subscription_message_id(&msg).unwrap_err() {
            GraphqlClientError::Protocol { message } => {
                assert!(message.contains("error"));
                assert!(message.contains(SUBSCRIPTION_ID));
                assert!(message.contains("stale-99"));
            }
            other => panic!("expected Protocol error, got {other:?}"),
        }
    }

    #[test]
    fn subscription_message_id_rejects_missing_id() {
        let msg = GraphqlWsMessage {
            message_type: "complete".to_string(),
            id: None,
            payload: None,
        };
        match validate_subscription_message_id(&msg).unwrap_err() {
            GraphqlClientError::Protocol { message } => {
                assert!(message.contains("complete"));
                assert!(message.contains("missing id"));
            }
            other => panic!("expected Protocol error, got {other:?}"),
        }
    }

    // ---- decode_ws_message ----

    #[test]
    fn decode_text_message() {
        let text = r#"{"type":"next","id":"1","payload":{"data":{"x":1}}}"#;
        let msg = WsMessage::Text(text.to_string());
        let result = decode_ws_message(msg).unwrap();
        assert_eq!(result.message_type, "next");
        assert_eq!(result.id.as_deref(), Some("1"));
    }

    #[test]
    fn decode_binary_message() {
        let json = r#"{"type":"connection_ack"}"#;
        let msg = WsMessage::Binary(json.as_bytes().to_vec().into());
        let result = decode_ws_message(msg).unwrap();
        assert_eq!(result.message_type, "connection_ack");
    }

    #[test]
    fn decode_text_invalid_json() {
        let msg = WsMessage::Text("{not json".to_string());
        let result = decode_ws_message(msg);
        assert!(result.is_err());
        match result.unwrap_err() {
            GraphqlClientError::Json(s) => assert!(!s.is_empty()),
            other => panic!("expected Json error, got {other:?}"),
        }
    }

    #[test]
    fn decode_binary_invalid_json() {
        let msg = WsMessage::Binary(b"not json".to_vec().into());
        let result = decode_ws_message(msg);
        assert!(result.is_err());
        match result.unwrap_err() {
            GraphqlClientError::Json(_) => {}
            other => panic!("expected Json error, got {other:?}"),
        }
    }

    #[test]
    fn decode_ping_returns_protocol_error() {
        let msg = WsMessage::Ping(vec![].into());
        let result = decode_ws_message(msg);
        match result.unwrap_err() {
            GraphqlClientError::Protocol { message } => {
                assert!(message.contains("ping/pong"));
            }
            other => panic!("expected Protocol error, got {other:?}"),
        }
    }

    #[test]
    fn decode_pong_returns_protocol_error() {
        let msg = WsMessage::Pong(vec![1, 2, 3].into());
        let result = decode_ws_message(msg);
        match result.unwrap_err() {
            GraphqlClientError::Protocol { message } => {
                assert!(message.contains("ping/pong"));
            }
            other => panic!("expected Protocol error, got {other:?}"),
        }
    }

    #[test]
    fn decode_close_returns_protocol_error() {
        let msg = WsMessage::Close(None);
        let result = decode_ws_message(msg);
        match result.unwrap_err() {
            GraphqlClientError::Protocol { message } => {
                assert!(message.contains("closed"));
            }
            other => panic!("expected Protocol error, got {other:?}"),
        }
    }

    // ---- reconnect_config_from_ws ----

    #[test]
    fn reconnect_config_auto_reconnect_disabled() {
        let ws_config = WsConfig {
            auto_reconnect: false,
            ..WsConfig::default()
        };
        let config = reconnect_config_from_ws(&ws_config);
        // max_attempts should be Some(0) when auto_reconnect is false
        assert_eq!(config.max_attempts, Some(0));
    }

    #[test]
    fn reconnect_config_auto_reconnect_with_max() {
        let ws_config = WsConfig {
            auto_reconnect: true,
            max_reconnect_attempts: Some(5),
            ..WsConfig::default()
        };
        let config = reconnect_config_from_ws(&ws_config);
        assert_eq!(config.max_attempts, Some(5));
    }

    #[test]
    fn reconnect_config_auto_reconnect_unlimited() {
        let ws_config = WsConfig {
            auto_reconnect: true,
            max_reconnect_attempts: None,
            ..WsConfig::default()
        };
        let config = reconnect_config_from_ws(&ws_config);
        assert!(config.max_attempts.is_none());
    }

    #[test]
    fn reconnect_config_preserves_initial_delay() {
        let ws_config = WsConfig {
            auto_reconnect: true,
            reconnect_delay: Duration::from_secs(5),
            ..WsConfig::default()
        };
        let config = reconnect_config_from_ws(&ws_config);
        assert_eq!(config.initial_delay, Duration::from_secs(5));
    }

    // ---- GraphqlSubscriptionConfig ----

    #[test]
    fn subscription_config_default() {
        let config = GraphqlSubscriptionConfig::default();
        assert!(config.init_payload.is_none());
        assert_eq!(config.ack_timeout, Duration::from_secs(10));
    }

    #[test]
    fn subscription_config_debug() {
        let config = GraphqlSubscriptionConfig::default();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("GraphqlSubscriptionConfig"));
    }

    #[test]
    fn subscription_config_clone() {
        let config = GraphqlSubscriptionConfig {
            ack_timeout: Duration::from_secs(30),
            init_payload: Some(serde_json::json!({"token": "abc"})),
            ..GraphqlSubscriptionConfig::default()
        };
        let moved = config;
        assert_eq!(moved.ack_timeout, Duration::from_secs(30));
        assert!(moved.init_payload.is_some());
    }

    // ---- GraphqlSubscriptionClient ----

    #[test]
    fn subscription_client_new() {
        let client = GraphqlSubscriptionClient::new("wss://api.test.com/graphql", "github");
        assert_eq!(client.url, "wss://api.test.com/graphql");
        assert_eq!(client.service_name, "github");
        assert!(client.headers.is_empty());
    }

    #[test]
    fn subscription_client_with_header() {
        let client = GraphqlSubscriptionClient::new("wss://api.test.com/graphql", "github")
            .with_header("Authorization", "Bearer tok123");
        assert_eq!(
            client.headers.get("Authorization").unwrap(),
            "Bearer tok123"
        );
    }

    #[test]
    fn subscription_client_with_multiple_headers() {
        let client = GraphqlSubscriptionClient::new("wss://api.test.com/graphql", "github")
            .with_header("Authorization", "Bearer tok")
            .with_header("X-Custom", "value");
        assert_eq!(client.headers.len(), 2);
    }

    #[test]
    fn subscription_client_with_config() {
        let config = GraphqlSubscriptionConfig {
            ack_timeout: Duration::from_secs(60),
            ..GraphqlSubscriptionConfig::default()
        };
        let client = GraphqlSubscriptionClient::new("wss://api.test.com/graphql", "github")
            .with_config(config);
        assert_eq!(client.config.ack_timeout, Duration::from_secs(60));
    }

    #[test]
    fn subscription_client_clone() {
        let client = GraphqlSubscriptionClient::new("wss://api.test.com/graphql", "github")
            .with_header("Authorization", "Bearer tok");
        let cloned = client.clone();
        assert_eq!(cloned.url, client.url);
        assert_eq!(cloned.service_name, client.service_name);
        assert_eq!(cloned.headers, client.headers);
    }

    #[test]
    fn subscription_client_debug() {
        let client = GraphqlSubscriptionClient::new("wss://api.test.com/graphql", "github");
        let dbg = format!("{client:?}");
        assert!(dbg.contains("GraphqlSubscriptionClient"));
        assert!(dbg.contains("api.test.com"));
    }

    // ---- SUBSCRIPTION_ID constant ----

    #[test]
    fn subscription_id_is_one() {
        assert_eq!(SUBSCRIPTION_ID, "1");
    }

    // ---- StreamError conversion ----

    #[test]
    fn stream_error_converts_to_protocol() {
        let stream_err = StreamError::ConnectionFailed("test disconnect".to_string());
        let gql_err: GraphqlClientError = stream_err.into();
        match gql_err {
            GraphqlClientError::Protocol { message } => {
                assert!(!message.is_empty());
            }
            other => panic!("expected Protocol error, got {other:?}"),
        }
    }

    // ---- additional edge case tests ----

    #[test]
    fn ws_message_deserialize_with_extra_fields() {
        // Unknown fields should be silently ignored by serde
        let json = r#"{"type":"next","id":"1","payload":null,"extra_field":"ignored"}"#;
        let msg: GraphqlWsMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.message_type, "next");
        assert_eq!(msg.id.as_deref(), Some("1"));
    }

    #[test]
    fn ws_message_serialize_pong() {
        let msg = GraphqlWsMessage {
            message_type: "pong".to_string(),
            id: Some("1".to_string()),
            payload: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains(r#""type":"pong"#));
        assert!(json.contains(r#""id":"1"#));
    }

    #[test]
    fn ws_message_deserialize_missing_optional_fields() {
        // Only type is mandatory; id and payload have #[serde(default)]
        let json = r#"{"type":"ka"}"#;
        let msg: GraphqlWsMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.message_type, "ka");
        assert!(msg.id.is_none());
        assert!(msg.payload.is_none());
    }

    #[test]
    fn decode_close_with_frame() {
        use fcp_streaming::WsCloseFrame;
        let frame = WsCloseFrame {
            code: 1000,
            reason: "normal closure".to_string(),
        };
        let msg = WsMessage::Close(Some(frame));
        let result = decode_ws_message(msg);
        match result.unwrap_err() {
            GraphqlClientError::Protocol { message } => {
                assert!(message.contains("closed"));
            }
            other => panic!("expected Protocol error, got {other:?}"),
        }
    }

    #[test]
    fn reconnect_config_zero_delay() {
        let ws_config = WsConfig {
            auto_reconnect: true,
            reconnect_delay: Duration::from_secs(0),
            max_reconnect_attempts: Some(3),
            ..WsConfig::default()
        };
        let config = reconnect_config_from_ws(&ws_config);
        assert_eq!(config.initial_delay, Duration::from_secs(0));
        assert_eq!(config.max_attempts, Some(3));
    }

    #[test]
    fn subscription_client_header_overwrite() {
        let client = GraphqlSubscriptionClient::new("wss://api.test.com/graphql", "svc")
            .with_header("Authorization", "Bearer old")
            .with_header("Authorization", "Bearer new");
        assert_eq!(client.headers.get("Authorization").unwrap(), "Bearer new");
        assert_eq!(client.headers.len(), 1);
    }

    #[test]
    fn subscription_config_custom_init_payload() {
        let config = GraphqlSubscriptionConfig {
            init_payload: Some(
                serde_json::json!({"type": "connection_init", "payload": {"token": "abc"}}),
            ),
            ack_timeout: Duration::from_secs(5),
            ..GraphqlSubscriptionConfig::default()
        };
        assert!(config.init_payload.is_some());
        let payload = config.init_payload.unwrap();
        assert_eq!(payload["payload"]["token"], "abc");
    }

    // ---- GraphqlWsMessage additional serde tests ----

    #[test]
    fn ws_message_serialize_connection_ack() {
        let msg = GraphqlWsMessage {
            message_type: "connection_ack".to_string(),
            id: None,
            payload: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains(r#""type":"connection_ack"#));
    }

    #[test]
    fn ws_message_serialize_complete() {
        let msg = GraphqlWsMessage {
            message_type: "complete".to_string(),
            id: Some("1".to_string()),
            payload: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains(r#""type":"complete"#));
        assert!(json.contains(r#""id":"1"#));
    }

    #[test]
    fn ws_message_serialize_next_with_data() {
        let msg = GraphqlWsMessage {
            message_type: "next".to_string(),
            id: Some("1".to_string()),
            payload: Some(serde_json::json!({"data": {"user": {"id": "42"}}})),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains(r#""type":"next"#));
        assert!(json.contains("42"));
    }

    #[test]
    fn ws_message_serialize_error_with_payload() {
        let msg = GraphqlWsMessage {
            message_type: "error".to_string(),
            id: Some("1".to_string()),
            payload: Some(serde_json::json!([{"message": "syntax error"}])),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("syntax error"));
    }

    #[test]
    fn ws_message_debug() {
        let msg = GraphqlWsMessage {
            message_type: "ping".to_string(),
            id: None,
            payload: None,
        };
        let dbg = format!("{msg:?}");
        assert!(dbg.contains("GraphqlWsMessage"));
        assert!(dbg.contains("ping"));
    }

    #[test]
    fn ws_message_deserialize_with_null_payload() {
        let json = r#"{"type":"next","id":"1","payload":null}"#;
        let msg: GraphqlWsMessage = serde_json::from_str(json).unwrap();
        assert!(msg.payload.is_none());
    }

    #[test]
    fn ws_message_deserialize_with_empty_object_payload() {
        let json = r#"{"type":"next","id":"1","payload":{}}"#;
        let msg: GraphqlWsMessage = serde_json::from_str(json).unwrap();
        assert!(msg.payload.is_some());
        assert!(msg.payload.unwrap().is_object());
    }

    // ---- decode_ws_message additional tests ----

    #[test]
    fn decode_text_valid_complete_msg() {
        let text = r#"{"type":"complete","id":"1"}"#;
        let msg = WsMessage::Text(text.to_string());
        let result = decode_ws_message(msg).unwrap();
        assert_eq!(result.message_type, "complete");
    }

    #[test]
    fn decode_binary_valid_next_msg() {
        let json = r#"{"type":"next","id":"1","payload":{"data":{"x":99}}}"#;
        let msg = WsMessage::Binary(json.as_bytes().to_vec().into());
        let result = decode_ws_message(msg).unwrap();
        assert_eq!(result.message_type, "next");
        assert!(result.payload.is_some());
    }

    #[test]
    fn decode_text_empty_string() {
        let msg = WsMessage::Text(String::new());
        let result = decode_ws_message(msg);
        assert!(result.is_err());
    }

    #[test]
    fn decode_binary_empty() {
        let msg = WsMessage::Binary(vec![].into());
        let result = decode_ws_message(msg);
        assert!(result.is_err());
    }

    // ---- GraphqlSubscriptionClient additional tests ----

    #[test]
    fn subscription_client_with_empty_headers() {
        let client = GraphqlSubscriptionClient::new("wss://api.test.com/graphql", "svc");
        assert!(client.headers.is_empty());
    }

    #[test]
    fn subscription_client_with_config_updates() {
        let config = GraphqlSubscriptionConfig {
            ack_timeout: Duration::from_secs(120),
            init_payload: Some(serde_json::json!({"auth": "token"})),
            ..GraphqlSubscriptionConfig::default()
        };
        let client =
            GraphqlSubscriptionClient::new("wss://ws.test.com/sub", "my_svc").with_config(config);
        assert_eq!(client.config.ack_timeout, Duration::from_secs(120));
        assert!(client.config.init_payload.is_some());
    }

    #[test]
    fn subscription_client_chaining() {
        let client = GraphqlSubscriptionClient::new("wss://ws.test.com/sub", "svc")
            .with_header("Authorization", "Bearer abc")
            .with_header("X-Custom", "val")
            .with_config(GraphqlSubscriptionConfig {
                ack_timeout: Duration::from_secs(20),
                ..GraphqlSubscriptionConfig::default()
            });
        assert_eq!(client.headers.len(), 2);
        assert_eq!(client.config.ack_timeout, Duration::from_secs(20));
    }

    // ---- reconnect_config_from_ws additional tests ----

    #[test]
    fn reconnect_config_with_large_delay() {
        let ws_config = WsConfig {
            auto_reconnect: true,
            reconnect_delay: Duration::from_secs(60),
            max_reconnect_attempts: Some(10),
            ..WsConfig::default()
        };
        let config = reconnect_config_from_ws(&ws_config);
        assert_eq!(config.initial_delay, Duration::from_secs(60));
        assert_eq!(config.max_attempts, Some(10));
    }

    #[test]
    fn reconnect_config_disabled_with_max_attempts() {
        // Even if max_reconnect_attempts is set, auto_reconnect=false should override
        let ws_config = WsConfig {
            auto_reconnect: false,
            max_reconnect_attempts: Some(100),
            ..WsConfig::default()
        };
        let config = reconnect_config_from_ws(&ws_config);
        assert_eq!(config.max_attempts, Some(0));
    }

    // ---- decode_ws_message: text with various valid payloads ----

    #[test]
    fn decode_text_ping_message() {
        let json = r#"{"type":"ping"}"#;
        let msg = WsMessage::Text(json.to_string());
        let result = decode_ws_message(msg).unwrap();
        assert_eq!(result.message_type, "ping");
        assert!(result.id.is_none());
        assert!(result.payload.is_none());
    }

    #[test]
    fn decode_text_pong_message() {
        let json = r#"{"type":"pong","id":"1","payload":{"ts":12345}}"#;
        let msg = WsMessage::Text(json.to_string());
        let result = decode_ws_message(msg).unwrap();
        assert_eq!(result.message_type, "pong");
        assert_eq!(result.id.as_deref(), Some("1"));
    }

    #[test]
    fn decode_text_error_with_single_error() {
        let json = r#"{"type":"error","id":"1","payload":{"message":"bad query"}}"#;
        let msg = WsMessage::Text(json.to_string());
        let result = decode_ws_message(msg).unwrap();
        assert_eq!(result.message_type, "error");
        assert!(result.payload.unwrap().is_object());
    }

    #[test]
    fn decode_text_with_nested_payload() {
        let json = r#"{"type":"next","id":"1","payload":{"data":{"user":{"name":"Alice","posts":[{"id":"1"},{"id":"2"}]}}}}"#;
        let msg = WsMessage::Text(json.to_string());
        let result = decode_ws_message(msg).unwrap();
        let payload = result.payload.unwrap();
        assert_eq!(payload["data"]["user"]["name"], "Alice");
    }

    // ---- decode_ws_message: binary edge cases ----

    #[test]
    fn decode_binary_with_connection_ack_payload() {
        let json = r#"{"type":"connection_ack","payload":{"version":"1.0"}}"#;
        let msg = WsMessage::Binary(json.as_bytes().to_vec().into());
        let result = decode_ws_message(msg).unwrap();
        assert_eq!(result.message_type, "connection_ack");
        assert_eq!(result.payload.unwrap()["version"], "1.0");
    }

    #[test]
    fn decode_binary_partial_json() {
        let msg = WsMessage::Binary(b"{\"type\":".to_vec().into());
        let result = decode_ws_message(msg);
        match result.unwrap_err() {
            GraphqlClientError::Json(s) => assert!(!s.is_empty()),
            other => panic!("expected Json error, got {other:?}"),
        }
    }

    // ---- decode_ws_message: ping/pong with payload ----

    #[test]
    fn decode_ping_with_payload_returns_protocol_error() {
        let msg = WsMessage::Ping(vec![1, 2, 3, 4].into());
        let result = decode_ws_message(msg);
        match result.unwrap_err() {
            GraphqlClientError::Protocol { message } => {
                assert!(message.contains("ping/pong"));
            }
            other => panic!("expected Protocol error, got {other:?}"),
        }
    }

    #[test]
    fn decode_pong_empty_payload_returns_protocol_error() {
        let msg = WsMessage::Pong(vec![].into());
        let result = decode_ws_message(msg);
        match result.unwrap_err() {
            GraphqlClientError::Protocol { message } => {
                assert!(message.contains("ping/pong"));
            }
            other => panic!("expected Protocol error, got {other:?}"),
        }
    }

    // ---- GraphqlWsMessage serde edge cases ----

    #[test]
    fn ws_message_with_numeric_id() {
        // GraphQL transport WS spec uses string IDs, but test robustness
        let json = r#"{"type":"next","id":"42","payload":null}"#;
        let msg: GraphqlWsMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.id.as_deref(), Some("42"));
    }

    #[test]
    fn ws_message_with_empty_type() {
        let json = r#"{"type":"","id":null,"payload":null}"#;
        let msg: GraphqlWsMessage = serde_json::from_str(json).unwrap();
        assert!(msg.message_type.is_empty());
    }

    #[test]
    fn ws_message_serde_roundtrip_all_fields() {
        let msg = GraphqlWsMessage {
            message_type: "subscribe".to_string(),
            id: Some("sub-123".to_string()),
            payload: Some(serde_json::json!({
                "query": "subscription { events { id type } }",
                "variables": {}
            })),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let back: GraphqlWsMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(back.message_type, "subscribe");
        assert_eq!(back.id.as_deref(), Some("sub-123"));
        assert!(
            back.payload.unwrap()["query"]
                .as_str()
                .unwrap()
                .contains("events")
        );
    }

    // ---- GraphqlSubscriptionConfig edge cases ----

    #[test]
    fn subscription_config_zero_ack_timeout() {
        let config = GraphqlSubscriptionConfig {
            ack_timeout: Duration::ZERO,
            ..GraphqlSubscriptionConfig::default()
        };
        assert_eq!(config.ack_timeout, Duration::ZERO);
    }

    #[test]
    fn subscription_config_large_ack_timeout() {
        let config = GraphqlSubscriptionConfig {
            ack_timeout: Duration::from_secs(3600),
            ..GraphqlSubscriptionConfig::default()
        };
        assert_eq!(config.ack_timeout, Duration::from_secs(3600));
    }

    #[test]
    fn subscription_config_clone_preserves_init_payload() {
        let config = GraphqlSubscriptionConfig {
            init_payload: Some(serde_json::json!({"auth": "bearer xyz"})),
            ..GraphqlSubscriptionConfig::default()
        };
        let cloned = config.clone();
        assert_eq!(cloned.init_payload.unwrap()["auth"], "bearer xyz");
        // Use original after clone to avoid redundant_clone
        assert!(config.init_payload.is_some());
    }

    // ---- GraphqlSubscriptionClient edge cases ----

    #[test]
    fn subscription_client_empty_service_name() {
        let client = GraphqlSubscriptionClient::new("wss://ws.test.com/graphql", "");
        assert!(client.service_name.is_empty());
    }

    #[test]
    fn subscription_client_with_many_headers() {
        let client = GraphqlSubscriptionClient::new("wss://ws.test.com/graphql", "svc")
            .with_header("H1", "v1")
            .with_header("H2", "v2")
            .with_header("H3", "v3")
            .with_header("H4", "v4")
            .with_header("H5", "v5");
        assert_eq!(client.headers.len(), 5);
    }

    #[test]
    fn subscription_client_clone_preserves_config() {
        let config = GraphqlSubscriptionConfig {
            ack_timeout: Duration::from_secs(45),
            init_payload: Some(serde_json::json!({"key": "value"})),
            ..GraphqlSubscriptionConfig::default()
        };
        let client = GraphqlSubscriptionClient::new("wss://ws.test.com/graphql", "svc")
            .with_config(config)
            .with_header("Auth", "token");
        let cloned = client.clone();
        assert_eq!(cloned.config.ack_timeout, Duration::from_secs(45));
        assert!(cloned.config.init_payload.is_some());
        assert_eq!(cloned.headers.get("Auth").unwrap(), "token");
        // Use original after clone to avoid redundant_clone
        assert_eq!(client.url, "wss://ws.test.com/graphql");
    }

    #[test]
    fn subscription_client_debug_contains_url_and_service() {
        let client = GraphqlSubscriptionClient::new("wss://api.example.com/ws", "my-service");
        let dbg = format!("{client:?}");
        assert!(dbg.contains("api.example.com"));
        assert!(dbg.contains("my-service"));
    }

    // ---- reconnect_config_from_ws additional edge cases ----

    #[test]
    fn reconnect_config_auto_reconnect_with_one_attempt() {
        let ws_config = WsConfig {
            auto_reconnect: true,
            max_reconnect_attempts: Some(1),
            ..WsConfig::default()
        };
        let config = reconnect_config_from_ws(&ws_config);
        assert_eq!(config.max_attempts, Some(1));
    }

    #[test]
    fn reconnect_config_auto_reconnect_with_zero_attempts() {
        let ws_config = WsConfig {
            auto_reconnect: true,
            max_reconnect_attempts: Some(0),
            ..WsConfig::default()
        };
        let config = reconnect_config_from_ws(&ws_config);
        assert_eq!(config.max_attempts, Some(0));
    }

    #[test]
    fn reconnect_config_small_delay() {
        let ws_config = WsConfig {
            auto_reconnect: true,
            reconnect_delay: Duration::from_millis(100),
            max_reconnect_attempts: Some(5),
            ..WsConfig::default()
        };
        let config = reconnect_config_from_ws(&ws_config);
        assert_eq!(config.initial_delay, Duration::from_millis(100));
    }

    // ---- StreamError conversion additional tests ----

    #[test]
    fn stream_error_connection_closed_converts() {
        let stream_err = StreamError::ConnectionClosed {
            reason: "server shutdown".to_string(),
            code: Some(1001),
        };
        let gql_err: GraphqlClientError = stream_err.into();
        match gql_err {
            GraphqlClientError::Protocol { message } => {
                assert!(!message.is_empty());
            }
            other => panic!("expected Protocol error, got {other:?}"),
        }
    }

    #[test]
    fn stream_error_parse_error_converts() {
        let stream_err = StreamError::ParseError("invalid frame".to_string());
        let gql_err: GraphqlClientError = stream_err.into();
        match gql_err {
            GraphqlClientError::Protocol { message } => {
                assert!(!message.is_empty());
            }
            other => panic!("expected Protocol error, got {other:?}"),
        }
    }

    // ---- GraphqlWsMessage: edge case serde ----

    #[test]
    fn ws_message_with_unicode_type() {
        let msg = GraphqlWsMessage {
            message_type: "Verbindung".to_string(),
            id: None,
            payload: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let back: GraphqlWsMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(back.message_type, "Verbindung");
    }

    #[test]
    fn ws_message_with_large_payload() {
        let large_data: Vec<i32> = (0..1000).collect();
        let msg = GraphqlWsMessage {
            message_type: "next".to_string(),
            id: Some("1".to_string()),
            payload: Some(serde_json::json!({"items": large_data})),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let back: GraphqlWsMessage = serde_json::from_str(&json).unwrap();
        assert!(back.payload.unwrap()["items"].is_array());
    }

    #[test]
    fn ws_message_with_numeric_string_id() {
        let msg = GraphqlWsMessage {
            message_type: "subscribe".to_string(),
            id: Some("999".to_string()),
            payload: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains(r#""id":"999"#));
    }

    // ---- decode_ws_message: text with minimal valid JSON ----

    #[test]
    fn decode_text_minimal_type_only() {
        let text = r#"{"type":"ka"}"#;
        let msg = WsMessage::Text(text.to_string());
        let result = decode_ws_message(msg).unwrap();
        assert_eq!(result.message_type, "ka");
        assert!(result.id.is_none());
        assert!(result.payload.is_none());
    }

    // ---- decode_ws_message: binary with all fields ----

    #[test]
    fn decode_binary_all_fields() {
        let json = r#"{"type":"next","id":"sub-1","payload":{"data":{"event":"tick"}}}"#;
        let msg = WsMessage::Binary(json.as_bytes().to_vec().into());
        let result = decode_ws_message(msg).unwrap();
        assert_eq!(result.message_type, "next");
        assert_eq!(result.id.as_deref(), Some("sub-1"));
        assert_eq!(result.payload.unwrap()["data"]["event"], "tick");
    }

    // ---- GraphqlSubscriptionConfig: clone with all fields ----

    #[test]
    fn subscription_config_clone_all_fields() {
        let config = GraphqlSubscriptionConfig {
            ws: WsConfig {
                auto_reconnect: true,
                reconnect_delay: Duration::from_millis(500),
                max_reconnect_attempts: Some(3),
                ..WsConfig::default()
            },
            init_payload: Some(serde_json::json!({"token": "xyz"})),
            ack_timeout: Duration::from_secs(15),
            query_limits: GraphqlQueryLimits::default(),
        };
        let cloned = config.clone();
        assert_eq!(cloned.ack_timeout, Duration::from_secs(15));
        assert!(cloned.init_payload.is_some());
        assert!(config.ws.auto_reconnect);
    }

    // ---- GraphqlSubscriptionClient: with_config overrides default ----

    #[test]
    fn subscription_client_with_config_overrides_ack_timeout() {
        let client = GraphqlSubscriptionClient::new("wss://ws.test.com/graphql", "svc");
        assert_eq!(client.config.ack_timeout, Duration::from_secs(10));

        let client = client.with_config(GraphqlSubscriptionConfig {
            ack_timeout: Duration::from_secs(60),
            ..GraphqlSubscriptionConfig::default()
        });
        assert_eq!(client.config.ack_timeout, Duration::from_secs(60));
    }

    // ---- reconnect_config_from_ws: large max_attempts ----

    #[test]
    fn reconnect_config_large_max_attempts() {
        let ws_config = WsConfig {
            auto_reconnect: true,
            max_reconnect_attempts: Some(1_000_000),
            ..WsConfig::default()
        };
        let config = reconnect_config_from_ws(&ws_config);
        assert_eq!(config.max_attempts, Some(1_000_000));
    }

    // ---- decode_ws_message: close with various frames ----

    #[test]
    fn decode_close_with_abnormal_code() {
        use fcp_streaming::WsCloseFrame;
        let frame = WsCloseFrame {
            code: 1006,
            reason: "abnormal closure".to_string(),
        };
        let msg = WsMessage::Close(Some(frame));
        let result = decode_ws_message(msg);
        match result.unwrap_err() {
            GraphqlClientError::Protocol { message } => {
                assert!(message.contains("closed"));
            }
            other => panic!("expected Protocol error, got {other:?}"),
        }
    }

    // ---- subscription client: empty URL ----

    #[test]
    fn subscription_client_empty_url() {
        let client = GraphqlSubscriptionClient::new("", "svc");
        assert!(client.url.is_empty());
        assert_eq!(client.service_name, "svc");
    }

    // ---- ws_message: deserialize with boolean payload ----

    #[test]
    fn ws_message_with_boolean_payload() {
        let json = r#"{"type":"next","id":"1","payload":true}"#;
        let msg: GraphqlWsMessage = serde_json::from_str(json).unwrap();
        assert!(msg.payload.unwrap().is_boolean());
    }

    // ---- ws_message: deserialize with array payload ----

    #[test]
    fn ws_message_with_array_payload() {
        let json = r#"{"type":"next","id":"1","payload":[1,2,3]}"#;
        let msg: GraphqlWsMessage = serde_json::from_str(json).unwrap();
        assert!(msg.payload.unwrap().is_array());
    }
}
