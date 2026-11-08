//! Explicit executor affinity for the native event journal.
//!
//! A stream remains on the selected host through open, resume, polling and
//! acknowledgement. We never rediscover a replacement after an uncertain
//! result: another host has a different custody journal even for the same
//! connector, stream identifier and capability.

use super::*;
use fcp_mesh::invoke_route::MeshForwardBody;

const RESPONSE_BYTES: usize = 2 * 1024 * 1024;

pub(super) enum Request {
    Open(OpenRequest),
    Poll(PollRequest),
    Ack(AckRequest),
    Close(CloseRequest),
}

impl Request {
    pub(super) fn decode(method: &str, request_json: &str) -> Result<Self, (StatusCode, String)> {
        if request_json.len() > REQUEST_BYTES {
            return Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                "native stream request exceeds its byte limit".to_owned(),
            ));
        }
        let parsed = match method {
            "stream_open" => serde_json::from_str(request_json).map(Self::Open),
            "stream_poll" => serde_json::from_str(request_json).map(Self::Poll),
            "stream_ack" => serde_json::from_str(request_json).map(Self::Ack),
            "stream_close" => serde_json::from_str(request_json).map(Self::Close),
            _ => return Err(map_host_error(invalid("unknown native stream method"))),
        };
        // Parser diagnostics can include caller-provided strings. Capabilities
        // must never be copied into an error response or diagnostic.
        parsed.map_err(|_| map_host_error(invalid("invalid forwarded native stream request")))
    }

    fn executor(&self) -> Option<&TailscaleNodeId> {
        match self {
            Self::Open(request) => request.executor_node.as_ref(),
            Self::Poll(request) => request.executor_node.as_ref(),
            Self::Ack(request) => request.executor_node.as_ref(),
            Self::Close(request) => request.executor_node.as_ref(),
        }
    }

    fn authority(&self) -> &StreamAuthority {
        match self {
            Self::Open(request) => &request.auth,
            Self::Poll(request) => &request.auth,
            Self::Ack(request) => &request.auth,
            Self::Close(request) => &request.auth,
        }
    }

    fn stream_id(&self) -> Option<&str> {
        match self {
            Self::Open(request) => request.stream_id.as_deref(),
            Self::Poll(request) => Some(&request.stream_id),
            Self::Ack(request) => Some(&request.stream_id),
            Self::Close(request) => Some(&request.stream_id),
        }
    }

    fn forward_body(&self) -> Result<MeshForwardBody, (StatusCode, String)> {
        let request_json = match self {
            Self::Open(request) => serde_json::to_string(request),
            Self::Poll(request) => serde_json::to_string(request),
            Self::Ack(request) => serde_json::to_string(request),
            Self::Close(request) => serde_json::to_string(request),
        }
        .map_err(|_| map_host_error(invalid("native stream request could not be encoded")))?;
        if request_json.len() > REQUEST_BYTES {
            return Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                "native stream request exceeds its byte limit".to_owned(),
            ));
        }
        Ok(match self {
            Self::Open(_) => MeshForwardBody::StreamOpen { request_json },
            Self::Poll(_) => MeshForwardBody::StreamPoll { request_json },
            Self::Ack(_) => MeshForwardBody::StreamAck { request_json },
            Self::Close(_) => MeshForwardBody::StreamClose { request_json },
        })
    }

    fn validate_reply(
        &self,
        target: &TailscaleNodeId,
        value: &Value,
    ) -> Result<(), (StatusCode, String)> {
        let mismatch = || {
            (
            StatusCode::BAD_GATEWAY,
            "native stream reply does not match the selected executor, stream or scope; retain the original identities before retrying".to_owned(),
        )
        };
        let auth = self.authority();
        let stream = value.get("stream").ok_or_else(mismatch)?;
        let returned_id = stream
            .get("stream_id")
            .and_then(Value::as_str)
            .ok_or_else(mismatch)?;
        if value.get("executor_node").and_then(Value::as_str) != Some(target.as_str())
            || returned_id.is_empty()
            || returned_id.len() > 128
            || self
                .stream_id()
                .is_some_and(|expected| returned_id != expected)
            || stream.pointer("/binding/connector_id") != Some(&json!(auth.connector_id))
            || stream.pointer("/binding/zone_id") != Some(&json!(auth.zone_id))
            || stream.pointer("/binding/topic").and_then(Value::as_str) != Some(auth.topic.as_str())
        {
            return Err(mismatch());
        }
        match self {
            Self::Open(request) => {
                if stream.get("window_size").and_then(Value::as_u64)
                    != Some(u64::from(request.window_size))
                    || stream.get("closed").and_then(Value::as_bool) != Some(false)
                    || value.get("attached").and_then(Value::as_bool) != Some(true)
                {
                    return Err(mismatch());
                }
            }
            Self::Poll(request) => {
                let events = value
                    .get("events")
                    .and_then(Value::as_array)
                    .ok_or_else(mismatch)?;
                if events.len() > request.limit {
                    return Err(mismatch());
                }
                for event in events {
                    if event.get("topic").and_then(Value::as_str) != Some(auth.topic.as_str())
                        || event.pointer("/data/connector_id") != Some(&json!(auth.connector_id))
                        || event.pointer("/data/zone_id") != Some(&json!(auth.zone_id))
                    {
                        return Err(mismatch());
                    }
                }
            }
            Self::Ack(_) => {
                if value.get("acknowledged").and_then(Value::as_bool) != Some(true) {
                    return Err(mismatch());
                }
            }
            Self::Close(_) => {
                if stream.get("closed").and_then(Value::as_bool) != Some(true) {
                    return Err(mismatch());
                }
            }
        }
        Ok(())
    }
}

/// The HTTP entry host needs neither a connector installation nor a journal.
/// Only the selected executor performs local admission and custody changes.
pub(super) async fn dispatch(
    service: &EventService,
    host: &Arc<AppState>,
    request: Request,
    forwarded: bool,
) -> Result<Value, (StatusCode, String)> {
    let work = async {
        if forwarded && request.executor().is_none() {
            return Err(map_host_error(invalid(
                "forwarded streams require an explicit executor node",
            )));
        }
        if let Some(target) = request.executor() {
            let router = host.mesh.as_ref().ok_or_else(|| {
                map_host_error(unavailable(
                    "an explicit stream executor requires configured mesh routing",
                ))
            })?;
            if target != router.local_node() {
                if forwarded {
                    return Err((
                        StatusCode::MISDIRECTED_REQUEST,
                        "stream executor does not match this receiving host".to_owned(),
                    ));
                }
                let body = request.forward_body()?;
                // One attempt, one exact peer. Even transport failures known
                // to precede delivery do not select another custody journal.
                let reply = router.forward(target, body).await.map_err(|_| (
                    StatusCode::BAD_GATEWAY,
                    "selected native stream executor did not return an authenticated result; retry only with the same executor, request, stream and event identities".to_owned(),
                ))?;
                if reply.body_json.len() > RESPONSE_BYTES {
                    return Err((
                        StatusCode::BAD_GATEWAY,
                        "native stream reply exceeds its byte limit".to_owned(),
                    ));
                }
                let status = StatusCode::from_u16(reply.status).map_err(|_| {
                    (
                        StatusCode::BAD_GATEWAY,
                        "native stream reply has an invalid status".to_owned(),
                    )
                })?;
                if !status.is_success() {
                    if !status.is_client_error() && !status.is_server_error() {
                        return Err((
                            StatusCode::BAD_GATEWAY,
                            "native stream reply has an invalid status".to_owned(),
                        ));
                    }
                    let message = serde_json::from_str::<String>(&reply.body_json)
                        .ok()
                        .filter(|message| message.len() <= 8192)
                        .unwrap_or_else(|| {
                            "selected executor rejected native stream request".to_owned()
                        });
                    return Err((status, message));
                }
                let value: Value = serde_json::from_str(&reply.body_json).map_err(|_| {
                    (
                        StatusCode::BAD_GATEWAY,
                        "native stream reply is not valid JSON".to_owned(),
                    )
                })?;
                request.validate_reply(target, &value)?;
                return Ok(value);
            }
        }
        let mut value = match request {
            Request::Open(request) => service.open(host, request).await,
            Request::Poll(request) => service.poll(host, request).await,
            Request::Ack(request) => service.acknowledge(host, request).await,
            Request::Close(request) => service.close(host, request).await,
        }
        .map_err(map_host_error)?;
        value["executor_node"] = host
            .mesh
            .as_ref()
            .map_or(Value::Null, |router| json!(router.local_node()));
        Ok(value)
    };
    fcp_async_core::time::timeout(REQUEST_TIMEOUT, work).await.map_err(|_| map_host_error(unavailable(
        "event request deadline expired; retry with the original executor, stream and event identities",
    )))?
}
