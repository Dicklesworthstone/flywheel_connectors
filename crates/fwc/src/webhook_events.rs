//! Validate complete webhook polling pages before exposing events to rule execution.
//!
//! Cursors remain opaque receiver capabilities. A provider delivery keeps the
//! same normalized identity across pages, while host, connector, zone, and
//! endpoint boundaries remain part of that identity.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};

use anyhow::Result;
use chrono::{DateTime, Utc};
use fcp_core::FcpError;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::reactive_rules::IncomingEvent;
use crate::rules_cmd::flatten_stream_field;

pub(crate) const WEBHOOK_EVENT_TOPIC: &str = "webhook.received";
const MAX_EVENTS: u32 = 64;
const MAX_PAGE_BYTES: usize = 16 * 1024 * 1024;
const MAX_EVENT_BYTES: usize = 256 * 1024;
const MAX_CURSOR_BYTES: usize = 128;
const MAX_PROVIDER_EVENT_ID_BYTES: usize = 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WebhookSourceScope {
    pub(crate) host: String,
    pub(crate) connector: String,
    pub(crate) zone: String,
    pub(crate) endpoint_id: String,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, clap::ValueEnum)]
pub(crate) enum PollStart {
    #[default]
    Earliest,
    Latest,
}

#[derive(Clone, Debug)]
pub(crate) struct WebhookPollPage {
    pub(crate) events: Vec<IncomingEvent>,
    pub(crate) start_cursor: String,
    pub(crate) next_cursor: String,
    pub(crate) has_more: bool,
    pub(crate) serialized_event_bytes: usize,
    pub(crate) oldest_available_sequence: Option<u64>,
    pub(crate) next_sequence: u64,
    pub(crate) history_truncated: bool,
}

/// Only fixed, redacted diagnostics cross the untrusted source boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WebhookFailure {
    InvalidRequest,
    Credential,
    Transport,
    Timeout,
    Http(u16),
    InvalidResponse,
    ResponseTooLarge,
    ReplayGap,
    CursorExpired,
    PageTooLarge,
    Denied,
    SourceUnavailable,
}

impl WebhookFailure {
    pub(crate) fn from_fcp_error(error: &FcpError) -> Self {
        match error {
            FcpError::External {
                service,
                message,
                status_code: Some(410),
                ..
            } => match (service.as_str(), message.as_str()) {
                ("webhook-receiver", "webhook_replay_gap") => Self::ReplayGap,
                ("webhook-receiver", "webhook_cursor_expired") => Self::CursorExpired,
                _ => Self::InvalidResponse,
            },
            FcpError::External {
                status_code: Some(413),
                ..
            } => Self::PageTooLarge,
            FcpError::External {
                status_code: Some(401 | 403),
                ..
            }
            | FcpError::Unauthorized { .. }
            | FcpError::TokenExpired
            | FcpError::TokenNotYetValid
            | FcpError::InvalidSignature
            | FcpError::CapabilityDenied { .. }
            | FcpError::OperationNotGranted { .. }
            | FcpError::ResourceNotAllowed { .. }
            | FcpError::CapabilityConstraintDenied { .. }
            | FcpError::ZoneViolation { .. }
            | FcpError::TaintViolation { .. }
            | FcpError::ElevationRequired { .. } => Self::Denied,
            _ => Self::SourceUnavailable,
        }
    }

    pub(crate) const fn details(self) -> (&'static str, &'static str) {
        match self {
            Self::InvalidRequest => (
                "invalid-webhook-poll-request",
                "Webhook source scope, cursor, page size, or event limit is invalid or exceeds its bound.",
            ),
            Self::Credential => (
                "invalid-webhook-poll-capability",
                "Webhook polling requires a readable signed capability and valid holder proof for the selected source.",
            ),
            Self::Transport => (
                "webhook-poll-transport-failed",
                "The selected host did not return a complete readable webhook page. The saved source cursor has not advanced.",
            ),
            Self::Timeout => (
                "webhook-poll-timeout",
                "Webhook polling exceeded its bounded deadline. The saved source cursor has not advanced.",
            ),
            Self::Denied | Self::Http(401 | 403) => (
                "webhook-poll-authority-denied",
                "The selected host rejected webhook source authority. Check the signed subject, grant, endpoint, zone, and current policy.",
            ),
            Self::Http(300..=399) => (
                "webhook-poll-redirect-refused",
                "The selected host returned a redirect. Source authority was not forwarded to another host.",
            ),
            Self::Http(_) => (
                "webhook-poll-host-rejected",
                "The selected host returned an unsuccessful status. Its response body is omitted because it may contain credentials or delivery data.",
            ),
            Self::InvalidResponse => (
                "invalid-webhook-poll-response",
                "The complete webhook page did not match its requested scope, cursor, retention, signature, or bounded event contract. No page events were applied.",
            ),
            Self::ResponseTooLarge => (
                "webhook-poll-response-too-large",
                "The webhook response exceeded its bounded transport or normalized page size. The saved source cursor has not advanced.",
            ),
            Self::ReplayGap => (
                "webhook-replay-gap",
                "Retained webhook deliveries no longer cover the saved source cursor. Reconcile the missing deliveries before explicitly resetting the source cursor.",
            ),
            Self::CursorExpired => (
                "webhook-cursor-expired",
                "The receiver replaced its cursor epoch. Reconcile source continuity before explicitly resetting the saved source cursor.",
            ),
            Self::PageTooLarge => (
                "webhook-page-too-large",
                "The next webhook delivery exceeds the selected page budget or the 256 KiB normalized rule-event limit. The saved source cursor has not advanced.",
            ),
            Self::SourceUnavailable => (
                "webhook-source-unavailable",
                "The selected webhook source could not produce a page. Source error details are omitted, and the saved source cursor has not advanced.",
            ),
        }
    }
}

impl std::fmt::Display for WebhookFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.details().1)
    }
}

impl std::error::Error for WebhookFailure {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WirePage {
    endpoint_id: String,
    events: Vec<WireEvent>,
    start_cursor: String,
    next_cursor: String,
    has_more: bool,
    serialized_event_bytes: usize,
    retention: WireRetention,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireEvent {
    sequence: u64,
    event_id: String,
    endpoint_id: String,
    received_at: String,
    headers: BTreeMap<String, String>,
    payload: Value,
    signature_valid: bool,
    source_ip_hash: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRetention {
    oldest_available_sequence: Option<u64>,
    next_sequence: u64,
    history_truncated: bool,
}

/// Validate the entire page before a caller can execute or checkpoint any event.
/// The receiver's byte count describes retained events before privacy redaction;
/// it is checked independently of the public response and normalized event sizes.
pub(crate) fn decode_page(
    scope: &WebhookSourceScope,
    requested_cursor: Option<&str>,
    start: PollStart,
    limit: u32,
    max_bytes: usize,
    value: Value,
) -> Result<WebhookPollPage> {
    if !(1..=MAX_EVENTS).contains(&limit)
        || !(1..=MAX_PAGE_BYTES).contains(&max_bytes)
        || requested_cursor.is_some_and(|cursor| !valid_cursor(cursor))
        || !valid_scope(scope)
    {
        return Err(WebhookFailure::InvalidRequest.into());
    }
    bounded_size(&value, MAX_PAGE_BYTES, WebhookFailure::ResponseTooLarge)?;
    // Option<T> accepts an absent field during deserialization. Require exact
    // public shapes as well, so omitted redaction and retention fields cannot
    // silently become null and raw private fields cannot enter rule data.
    validate_shape(&value)?;
    let page: WirePage =
        serde_json::from_value(value).map_err(|_| WebhookFailure::InvalidResponse)?;
    validate_page(scope, requested_cursor, start, limit, max_bytes, &page)?;

    let mut events = Vec::with_capacity(page.events.len());
    let mut provider_ids = BTreeSet::new();
    let mut previous_sequence = None;
    let mut normalized_bytes = 0_usize;
    let mut minimum_retained_bytes = 0_usize;
    for event in &page.events {
        if event.endpoint_id != scope.endpoint_id
            || event.event_id.is_empty()
            || event.event_id.len() > MAX_PROVIDER_EVENT_ID_BYTES
            || !provider_ids.insert(event.event_id.as_str())
            || !event.signature_valid
            || previous_sequence.is_some_and(|sequence| event.sequence <= sequence)
            || event.sequence >= page.retention.next_sequence
            || page
                .retention
                .oldest_available_sequence
                .is_none_or(|oldest| event.sequence < oldest)
            || event.source_ip_hash.as_deref().is_some_and(|hash| {
                hash.len() != 32
                    || !hash
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
        {
            return Err(WebhookFailure::InvalidResponse.into());
        }
        let received_at = DateTime::parse_from_rfc3339(&event.received_at)
            .map_err(|_| WebhookFailure::InvalidResponse)?
            .with_timezone(&Utc);
        let mut data = BTreeMap::from([
            ("endpoint_id".into(), event.endpoint_id.clone()),
            ("event_id".into(), event.event_id.clone()),
            ("sequence".into(), event.sequence.to_string()),
            ("signature_valid".into(), "true".into()),
            (
                "source_ip_hash".into(),
                event.source_ip_hash.clone().unwrap_or_else(|| "null".into()),
            ),
        ]);
        for (name, value) in &event.headers {
            let name = name.to_ascii_lowercase();
            if !safe_header_name(&name)
                || value
                    .chars()
                    .any(|character| character.is_control() && character != '\t')
            {
                return Err(WebhookFailure::InvalidResponse.into());
            }
            flatten_stream_field(
                &format!("headers.{name}"),
                &Value::String(value.clone()),
                0,
                &mut data,
            )
            .map_err(|_| WebhookFailure::InvalidResponse)?;
        }
        flatten_stream_field("payload", &event.payload, 0, &mut data)
            .map_err(|_| WebhookFailure::InvalidResponse)?;

        let identity = serde_json::to_vec(&(
            &scope.host,
            &scope.connector,
            &scope.zone,
            &scope.endpoint_id,
            &event.event_id,
        ))
        .map_err(|_| WebhookFailure::InvalidResponse)?;
        let mut hasher =
            blake3::Hasher::new_derive_key("flywheel_connectors.reactive_rules.webhook_event.v1");
        hasher.update(&identity);
        let normalized = IncomingEvent {
            connector: scope.connector.clone(),
            event_type: WEBHOOK_EVENT_TOPIC.into(),
            event_id: Some(format!("webhook:{}", hasher.finalize().to_hex())),
            data,
            received_at,
        };
        let event_bytes =
            bounded_size(&normalized, MAX_EVENT_BYTES, WebhookFailure::PageTooLarge)?;
        normalized_bytes = normalized_bytes
            .checked_add(event_bytes)
            .filter(|bytes| *bytes <= MAX_PAGE_BYTES)
            .ok_or(WebhookFailure::ResponseTooLarge)?;
        // Private source_ip may add bytes to the retained event. Removing it
        // gives a trustworthy lower bound, not equality with the public page.
        let minimum = MinimumRetainedEvent {
            event_id: &event.event_id,
            endpoint_id: &event.endpoint_id,
            received_at,
            headers: &event.headers,
            payload: &event.payload,
            signature_valid: event.signature_valid,
        };
        minimum_retained_bytes = minimum_retained_bytes
            .checked_add(bounded_size(
                &minimum,
                max_bytes,
                WebhookFailure::InvalidResponse,
            )?)
            .filter(|bytes| *bytes <= page.serialized_event_bytes)
            .ok_or(WebhookFailure::InvalidResponse)?;
        previous_sequence = Some(event.sequence);
        events.push(normalized);
    }

    Ok(WebhookPollPage {
        events,
        start_cursor: page.start_cursor,
        next_cursor: page.next_cursor,
        has_more: page.has_more,
        serialized_event_bytes: page.serialized_event_bytes,
        oldest_available_sequence: page.retention.oldest_available_sequence,
        next_sequence: page.retention.next_sequence,
        history_truncated: page.retention.history_truncated,
    })
}

#[derive(Serialize)]
struct MinimumRetainedEvent<'a> {
    event_id: &'a str,
    endpoint_id: &'a str,
    received_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    headers: &'a BTreeMap<String, String>,
    payload: &'a Value,
    signature_valid: bool,
}

fn valid_scope(scope: &WebhookSourceScope) -> bool {
    [
        (&scope.host, 4096),
        (&scope.connector, 512),
        (&scope.zone, 512),
        (&scope.endpoint_id, 512),
    ]
    .into_iter()
    .all(|(value, max_bytes)| {
        !value.trim().is_empty()
            && value.len() <= max_bytes
            && !value.chars().any(char::is_control)
    })
}

fn valid_cursor(cursor: &str) -> bool {
    !cursor.is_empty()
        && cursor.len() <= MAX_CURSOR_BYTES
        && cursor
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn validate_shape(value: &Value) -> Result<(), WebhookFailure> {
    if !exact_fields(
        value,
        &[
            "endpoint_id",
            "events",
            "start_cursor",
            "next_cursor",
            "has_more",
            "serialized_event_bytes",
            "retention",
        ],
    ) || !exact_fields(
        &value["retention"],
        &[
            "oldest_available_sequence",
            "next_sequence",
            "history_truncated",
        ],
    ) {
        return Err(WebhookFailure::InvalidResponse);
    }
    let events = value["events"]
        .as_array()
        .ok_or(WebhookFailure::InvalidResponse)?;
    if events.len() > MAX_EVENTS as usize
        || events.iter().any(|event| {
            !exact_fields(
                event,
                &[
                    "sequence",
                    "event_id",
                    "endpoint_id",
                    "received_at",
                    "headers",
                    "payload",
                    "signature_valid",
                    "source_ip_hash",
                ],
            )
        })
    {
        return Err(WebhookFailure::InvalidResponse);
    }
    Ok(())
}

fn exact_fields(value: &Value, fields: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == fields.len() && fields.iter().all(|field| object.contains_key(*field))
    })
}

fn validate_page(
    scope: &WebhookSourceScope,
    requested_cursor: Option<&str>,
    start: PollStart,
    limit: u32,
    max_bytes: usize,
    page: &WirePage,
) -> Result<(), WebhookFailure> {
    let retention = &page.retention;
    if page.endpoint_id != scope.endpoint_id
        || page.events.len() > limit as usize
        || !valid_cursor(&page.start_cursor)
        || !valid_cursor(&page.next_cursor)
        || requested_cursor.is_some_and(|cursor| page.start_cursor != cursor)
        || page.serialized_event_bytes > max_bytes
        || page.events.is_empty() != (page.serialized_event_bytes == 0)
        || retention
            .oldest_available_sequence
            .is_some_and(|oldest| oldest >= retention.next_sequence)
        || (retention.history_truncated && retention.next_sequence == 0)
        || (!page.events.is_empty() && page.start_cursor == page.next_cursor)
        || (page.has_more
            && page.events.last().is_none_or(|last| {
                last.sequence
                    .checked_add(1)
                    .is_none_or(|next| next >= retention.next_sequence)
            }))
    {
        return Err(WebhookFailure::InvalidResponse);
    }
    if requested_cursor.is_none() {
        match start {
            PollStart::Earliest => {
                if page.events.first().map(|event| event.sequence)
                    != retention.oldest_available_sequence
                    || (page.events.is_empty() && page.start_cursor != page.next_cursor)
                {
                    return Err(WebhookFailure::InvalidResponse);
                }
            }
            PollStart::Latest => {
                if !page.events.is_empty()
                    || page.has_more
                    || page.start_cursor != page.next_cursor
                {
                    return Err(WebhookFailure::InvalidResponse);
                }
            }
        }
    }
    Ok(())
}

fn safe_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'\x60'
                        | b'|'
                        | b'~'
                )
        })
        && ![
            "authorization",
            "cookie",
            "signature",
            "secret",
            "token",
            "api-key",
            "api_key",
        ]
        .iter()
        .any(|sensitive| name.contains(sensitive))
}

struct SizeCounter {
    bytes: usize,
    limit: usize,
    exceeded: bool,
}

impl Write for SizeCounter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self.bytes.checked_add(bytes.len()) {
            Some(total) if total <= self.limit => {
                self.bytes = total;
                Ok(bytes.len())
            }
            _ => {
                self.exceeded = true;
                Err(io::Error::other("bounded serialization limit exceeded"))
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn bounded_size<T: Serialize>(
    value: &T,
    limit: usize,
    oversized: WebhookFailure,
) -> Result<usize, WebhookFailure> {
    let mut counter = SizeCounter {
        bytes: 0,
        limit,
        exceeded: false,
    };
    serde_json::to_writer(&mut counter, value).map_err(|_| {
        if counter.exceeded {
            oversized
        } else {
            WebhookFailure::InvalidResponse
        }
    })?;
    Ok(counter.bytes)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn scope() -> WebhookSourceScope {
        WebhookSourceScope {
            host: "https://host.example".into(),
            connector: "fcp.webhook-receiver:ingest:1.0.0".into(),
            zone: "z:work".into(),
            endpoint_id: "payments".into(),
        }
    }

    fn event(sequence: u64, event_id: &str) -> Value {
        json!({
            "sequence": sequence,
            "event_id": event_id,
            "endpoint_id": "payments",
            "received_at": "2026-11-07T12:34:56.123+00:00",
            "headers": {"Content-Type": "application/json", "X-Github-Event": "push"},
            "payload": {"order": {"id": "42"}, "signature_valid": false},
            "signature_valid": true,
            "source_ip_hash": "0123456789abcdef0123456789abcdef"
        })
    }

    fn page() -> Value {
        json!({
            "endpoint_id": "payments",
            "events": [event(4, "delivery-1"), event(7, "delivery-2")],
            "start_cursor": "c3RhcnQ",
            "next_cursor": "bmV4dA",
            "has_more": false,
            "serialized_event_bytes": 1000,
            "retention": {
                "oldest_available_sequence": 4,
                "next_sequence": 8,
                "history_truncated": true
            }
        })
    }

    fn decode(value: Value) -> Result<WebhookPollPage> {
        decode_page(&scope(), None, PollStart::Earliest, 64, MAX_PAGE_BYTES, value)
    }

    fn assert_failure(result: Result<WebhookPollPage>, expected: WebhookFailure) {
        let error = result.expect_err("malformed pages must fail before returning events");
        assert_eq!(error.downcast_ref::<WebhookFailure>(), Some(&expected));
    }

    #[test]
    fn normalizes_verified_events_with_separate_payload_and_metadata() {
        let page = decode(page()).unwrap();
        assert_eq!(page.events.len(), 2);
        assert_eq!(page.start_cursor, "c3RhcnQ");
        assert_eq!(page.next_cursor, "bmV4dA");
        assert_eq!(page.oldest_available_sequence, Some(4));
        assert_eq!(page.next_sequence, 8);
        assert!(page.history_truncated);
        assert!(!page.has_more);
        let first = &page.events[0];
        assert_eq!(first.connector, scope().connector);
        assert_eq!(first.event_type, WEBHOOK_EVENT_TOPIC);
        assert!(first.event_id.as_deref().unwrap().starts_with("webhook:"));
        assert_eq!(first.data["endpoint_id"], "payments");
        assert_eq!(first.data["event_id"], "delivery-1");
        assert_eq!(first.data["sequence"], "4");
        assert_eq!(first.data["signature_valid"], "true");
        assert_eq!(first.data["payload.signature_valid"], "false");
        assert_eq!(first.data["payload.order.id"], "42");
        assert_eq!(first.data["headers.x-github-event"], "push");
        assert_eq!(first.received_at.timestamp_millis(), 1_794_054_896_123);
    }

    #[test]
    fn stable_delivery_identity_is_independent_of_page_cursor_and_sequence() {
        let first = decode(page()).unwrap().events.remove(0);
        let mut replay = page();
        replay["events"] = json!([event(40, "delivery-1")]);
        replay["start_cursor"] = json!("YW5vdGhlcg");
        replay["next_cursor"] = json!("bGF0ZXI");
        replay["retention"]["oldest_available_sequence"] = json!(40);
        replay["retention"]["next_sequence"] = json!(41);
        let second = decode(replay).unwrap().events.remove(0);
        assert_eq!(first.event_id, second.event_id);
    }

    #[test]
    fn delivery_identity_is_scoped_to_host_connector_zone_and_endpoint() {
        let original = decode(page()).unwrap().events.remove(0).event_id;
        for field in ["host", "connector", "zone", "endpoint"] {
            let mut changed = scope();
            let mut value = page();
            match field {
                "host" => changed.host = "https://other.example".into(),
                "connector" => changed.connector = "fcp.other:ingest:1.0.0".into(),
                "zone" => changed.zone = "z:private".into(),
                _ => {
                    changed.endpoint_id = "orders".into();
                    value["endpoint_id"] = json!("orders");
                    for event in value["events"].as_array_mut().unwrap() {
                        event["endpoint_id"] = json!("orders");
                    }
                }
            }
            let decoded = decode_page(
                &changed,
                None,
                PollStart::Earliest,
                64,
                MAX_PAGE_BYTES,
                value,
            )
            .unwrap();
            assert_ne!(original, decoded.events[0].event_id, "{field}");
        }
    }

    #[test]
    fn rejects_malformed_tail_without_exposing_a_valid_prefix() {
        for (field, value) in [
            ("endpoint_id", json!("other-endpoint")),
            ("signature_valid", json!(false)),
            ("event_id", json!("delivery-1")),
            ("event_id", json!("")),
            ("sequence", json!(4)),
            ("sequence", json!(3)),
            ("sequence", json!(8)),
            ("received_at", json!("not-a-timestamp")),
            ("source_ip_hash", json!("192.0.2.1")),
            ("source_ip_hash", json!("0123456789ABCDEF0123456789ABCDEF")),
        ] {
            let mut bad = page();
            bad["events"][1][field] = value;
            assert_failure(decode(bad), WebhookFailure::InvalidResponse);
        }
    }

    #[test]
    fn requires_exact_redacted_shapes_including_nullable_fields() {
        let mut unknown_page = page();
        unknown_page["signing_secret"] = json!("private-value");
        let mut raw_ip = page();
        raw_ip["events"][1]["source_ip"] = json!("192.0.2.1");
        let mut missing_hash = page();
        missing_hash["events"][1]
            .as_object_mut()
            .unwrap()
            .remove("source_ip_hash");
        let mut missing_oldest = page();
        missing_oldest["retention"]
            .as_object_mut()
            .unwrap()
            .remove("oldest_available_sequence");
        let mut unknown_retention = page();
        unknown_retention["retention"]["private"] = json!(true);
        for bad in [
            unknown_page,
            raw_ip,
            missing_hash,
            missing_oldest,
            unknown_retention,
        ] {
            assert_failure(decode(bad), WebhookFailure::InvalidResponse);
        }
        let mut null_hash = page();
        null_hash["events"][0]["source_ip_hash"] = Value::Null;
        assert_eq!(
            decode(null_hash).unwrap().events[0].data["source_ip_hash"],
            "null"
        );
    }

    #[test]
    fn rejects_sensitive_ambiguous_and_invalid_headers() {
        for name in [
            "Authorization",
            "Cookie",
            "X-Hub-Signature-256",
            "X-Secret",
            "X-Token",
            "X-Api-Key",
            "bad name",
            "Content-Type",
        ] {
            let mut bad = page();
            bad["events"][1]["headers"][name] = json!("private-value");
            if name == "Content-Type" {
                bad["events"][1]["headers"]["content-type"] = json!("application/json");
            }
            assert_failure(decode(bad), WebhookFailure::InvalidResponse);
        }
        let mut bad = page();
        bad["events"][1]["headers"]["x-note"] = json!("value\r\nAuthorization: secret");
        assert_failure(decode(bad), WebhookFailure::InvalidResponse);
    }

    #[test]
    fn preserves_valid_horizontal_tab_in_safe_headers() {
        let mut value = page();
        value["events"][0]["headers"]["x-note"] = json!("one\ttwo");
        let decoded = decode(value).unwrap();
        assert_eq!(decoded.events[0].data["headers.x-note"], "one\ttwo");
    }

    #[test]
    fn enforces_retention_and_start_contract_without_assuming_contiguous_sequences() {
        assert!(decode(page()).is_ok());
        for (field, value) in [
            ("oldest_available_sequence", Value::Null),
            ("oldest_available_sequence", json!(5)),
            ("oldest_available_sequence", json!(8)),
            ("next_sequence", json!(7)),
            ("next_sequence", json!(0)),
        ] {
            let mut bad = page();
            bad["retention"][field] = value;
            assert_failure(decode(bad), WebhookFailure::InvalidResponse);
        }
        let mut bad = page();
        bad["has_more"] = json!(true);
        assert_failure(decode(bad), WebhookFailure::InvalidResponse);
        let mut more = page();
        more["has_more"] = json!(true);
        more["retention"]["next_sequence"] = json!(10);
        assert!(decode(more).unwrap().has_more);
    }

    #[test]
    fn exact_resume_cursor_is_required_and_initial_policy_does_not_override_it() {
        assert!(
            decode_page(
                &scope(),
                Some("c3RhcnQ"),
                PollStart::Latest,
                64,
                MAX_PAGE_BYTES,
                page(),
            )
            .is_ok()
        );
        assert_failure(
            decode_page(
                &scope(),
                Some("b3RoZXI"),
                PollStart::Earliest,
                64,
                MAX_PAGE_BYTES,
                page(),
            ),
            WebhookFailure::InvalidResponse,
        );
        for cursor in ["", "with spaces", "padded=", "slash/", "nonasciié"] {
            let mut bad = page();
            bad["next_cursor"] = json!(cursor);
            assert_failure(decode(bad), WebhookFailure::InvalidResponse);
        }
        let mut bad = page();
        bad["start_cursor"] = json!("a".repeat(MAX_CURSOR_BYTES + 1));
        assert_failure(decode(bad), WebhookFailure::InvalidResponse);
        let mut bad = page();
        bad["next_cursor"] = bad["start_cursor"].clone();
        assert_failure(decode(bad), WebhookFailure::InvalidResponse);
    }

    #[test]
    fn latest_initialization_requires_empty_caught_up_page() {
        assert_failure(
            decode_page(
                &scope(),
                None,
                PollStart::Latest,
                64,
                MAX_PAGE_BYTES,
                page(),
            ),
            WebhookFailure::InvalidResponse,
        );
        let mut latest = page();
        latest["events"] = json!([]);
        latest["serialized_event_bytes"] = json!(0);
        latest["start_cursor"] = latest["next_cursor"].clone();
        assert!(
            decode_page(
                &scope(),
                None,
                PollStart::Latest,
                64,
                MAX_PAGE_BYTES,
                latest.clone(),
            )
            .is_ok()
        );
        assert_failure(decode(latest), WebhookFailure::InvalidResponse);
        let mut empty = page();
        empty["events"] = json!([]);
        empty["serialized_event_bytes"] = json!(0);
        empty["retention"]["oldest_available_sequence"] = Value::Null;
        empty["retention"]["history_truncated"] = json!(false);
        empty["start_cursor"] = empty["next_cursor"].clone();
        assert!(decode(empty).unwrap().events.is_empty());
    }

    #[test]
    fn rejects_false_byte_accounting_and_oversized_normalized_events() {
        for bytes in [0, 1, MAX_PAGE_BYTES + 1] {
            let mut bad = page();
            bad["serialized_event_bytes"] = json!(bytes);
            assert_failure(decode(bad), WebhookFailure::InvalidResponse);
        }
        let mut huge = page();
        huge["events"][1]["payload"] = json!("x".repeat(MAX_EVENT_BYTES));
        huge["serialized_event_bytes"] = json!(MAX_EVENT_BYTES + 1000);
        assert_failure(decode(huge), WebhookFailure::PageTooLarge);
        let mut huge_response = page();
        huge_response["events"][1]["payload"] = json!("x".repeat(MAX_PAGE_BYTES));
        assert_failure(decode(huge_response), WebhookFailure::ResponseTooLarge);
    }

    #[test]
    fn rejects_ambiguous_or_excessively_nested_payload_fields() {
        let mut ambiguous = page();
        ambiguous["events"][1]["payload"] = json!({"a.b": 1, "a": {"b": 2}});
        assert_failure(decode(ambiguous), WebhookFailure::InvalidResponse);
        let mut nested = json!(true);
        for _ in 0..18 {
            nested = json!({"nested": nested});
        }
        let mut bad = page();
        bad["events"][1]["payload"] = nested;
        assert_failure(decode(bad), WebhookFailure::InvalidResponse);
    }

    #[test]
    fn request_and_event_count_bounds_are_enforced() {
        for limit in [0, 65, u32::MAX] {
            assert_failure(
                decode_page(
                    &scope(),
                    None,
                    PollStart::Earliest,
                    limit,
                    MAX_PAGE_BYTES,
                    page(),
                ),
                WebhookFailure::InvalidRequest,
            );
        }
        for max_bytes in [0, MAX_PAGE_BYTES + 1] {
            assert_failure(
                decode_page(
                    &scope(),
                    None,
                    PollStart::Earliest,
                    64,
                    max_bytes,
                    page(),
                ),
                WebhookFailure::InvalidRequest,
            );
        }
        assert_failure(
            decode_page(
                &scope(),
                None,
                PollStart::Earliest,
                1,
                MAX_PAGE_BYTES,
                page(),
            ),
            WebhookFailure::InvalidResponse,
        );
        assert_failure(
            decode_page(
                &scope(),
                Some("invalid="),
                PollStart::Earliest,
                64,
                MAX_PAGE_BYTES,
                page(),
            ),
            WebhookFailure::InvalidRequest,
        );
    }

    #[test]
    fn accepts_sixty_four_events_and_rejects_an_oversized_batch() {
        let mut batch = page();
        batch["events"] = Value::Array(
            (0..64)
                .map(|sequence| event(sequence, &format!("delivery-{sequence}")))
                .collect(),
        );
        batch["serialized_event_bytes"] = json!(64 * 1000);
        batch["retention"]["oldest_available_sequence"] = json!(0);
        batch["retention"]["next_sequence"] = json!(64);
        batch["retention"]["history_truncated"] = json!(false);
        assert_eq!(decode(batch.clone()).unwrap().events.len(), 64);
        batch["events"]
            .as_array_mut()
            .unwrap()
            .push(event(64, "delivery-64"));
        batch["retention"]["next_sequence"] = json!(65);
        assert_failure(decode(batch), WebhookFailure::InvalidResponse);
    }

    #[test]
    fn retained_byte_count_allows_only_private_field_overhead() {
        let mut value = page();
        value["events"] = json!([event(4, "delivery-1")]);
        let received_at = DateTime::parse_from_rfc3339(
            value["events"][0]["received_at"].as_str().unwrap(),
        )
        .unwrap()
        .with_timezone(&Utc);
        let wire: WireEvent = serde_json::from_value(value["events"][0].clone()).unwrap();
        let minimum = MinimumRetainedEvent {
            event_id: &wire.event_id,
            endpoint_id: &wire.endpoint_id,
            received_at,
            headers: &wire.headers,
            payload: &wire.payload,
            signature_valid: true,
        };
        let exact_size = serde_json::to_vec(&minimum).unwrap().len();
        value["serialized_event_bytes"] = json!(exact_size);
        assert!(decode(value.clone()).is_ok());
        value["serialized_event_bytes"] = json!(exact_size + 32);
        assert!(decode(value.clone()).is_ok());
        value["serialized_event_bytes"] = json!(exact_size - 1);
        assert_failure(decode(value), WebhookFailure::InvalidResponse);
    }

    fn external(service: &str, message: &str, status: u16) -> FcpError {
        FcpError::External {
            service: service.into(),
            message: message.into(),
            status_code: Some(status),
            retryable: false,
            retry_after: None,
        }
    }

    #[test]
    fn maps_only_exact_receiver_continuity_errors_without_reflecting_details() {
        for (message, status, expected) in [
            ("webhook_replay_gap", 410, WebhookFailure::ReplayGap),
            ("webhook_cursor_expired", 410, WebhookFailure::CursorExpired),
            (
                "webhook_replay_gap: private-value",
                410,
                WebhookFailure::InvalidResponse,
            ),
            ("private-value", 413, WebhookFailure::PageTooLarge),
            ("private-value", 403, WebhookFailure::Denied),
            ("private-value", 507, WebhookFailure::SourceUnavailable),
        ] {
            let failure =
                WebhookFailure::from_fcp_error(&external("webhook-receiver", message, status));
            assert_eq!(failure, expected);
            assert!(!failure.to_string().contains("private-value"));
            assert!(!format!("{failure:?}").contains("private-value"));
        }
        assert_eq!(
            WebhookFailure::from_fcp_error(&external(
                "other-service",
                "webhook_replay_gap",
                410,
            )),
            WebhookFailure::InvalidResponse,
        );
        assert_eq!(
            WebhookFailure::from_fcp_error(&FcpError::Unauthorized {
                code: 2001,
                message: "private-value".into(),
            }),
            WebhookFailure::Denied,
        );
    }

    #[test]
    fn scope_serialization_rejects_unknown_fields() {
        let mut value = serde_json::to_value(scope()).unwrap();
        value["signing_secret"] = json!("private-value");
        assert!(serde_json::from_value::<WebhookSourceScope>(value).is_err());
    }
}
