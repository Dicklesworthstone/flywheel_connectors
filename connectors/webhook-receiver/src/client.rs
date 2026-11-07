//! In-memory webhook endpoint and event store.
//!
//! Unlike other connectors that wrap an HTTP client, the webhook receiver
//! stores all state locally. It manages webhook endpoint registrations and
//! buffers received events.

use std::cmp::Reverse;
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{self, Write};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use rand::RngCore as _;
use subtle::ConstantTimeEq as _;
use tracing::debug;

use crate::{
    error::{WebhookReceiverError, WebhookReceiverResult},
    types::{EndpointSummary, WebhookEndpoint, WebhookEvent, WebhookProvider},
};

/// Maximum number of endpoints that can be registered.
pub const MAX_ENDPOINTS: usize = 100;

/// Maximum number of events stored per endpoint.
pub const MAX_EVENTS_PER_ENDPOINT: usize = 1000;

/// Maximum distinct delivery IDs retained for one endpoint's lifetime.
///
/// Replay identities are never evicted to admit a new delivery.
pub const MAX_REPLAY_IDS_PER_ENDPOINT: usize = 100_000;

/// Maximum distinct delivery IDs retained across all registered endpoints.
///
/// Each accepted delivery retains at most two 32-byte digests: its public ID
/// and its authenticated content identity. This bounds identity payloads to
/// 6.4 MB; hash-table allocation overhead is additional. The shared ceiling
/// prevents every endpoint from independently allocating the full budget.
pub const MAX_REPLAY_IDS_TOTAL: usize = 100_000;

/// Maximum UTF-8 byte length of a delivery ID.
pub const MAX_EVENT_ID_BYTES: usize = 1024;

/// Maximum serialized event bytes retained for one endpoint.
pub const MAX_RETAINED_EVENT_BYTES_PER_ENDPOINT: usize = 16 * 1024 * 1024;

/// Maximum serialized event bytes retained across all endpoints.
pub const MAX_RETAINED_EVENT_BYTES_TOTAL: usize = 64 * 1024 * 1024;

/// Default limit for recent events query.
pub const DEFAULT_EVENTS_LIMIT: usize = 50;

/// Maximum limit for recent events query.
pub const MAX_EVENTS_LIMIT: usize = 100;

/// Maximum encoded cursor length accepted by event polling.
pub const MAX_EVENT_CURSOR_BYTES: usize = 128;

/// Default public base URL used before the connector is explicitly configured.
pub const DEFAULT_PUBLIC_BASE_URL: &str = "http://localhost:8080";

const EVENT_CURSOR_VERSION: u8 = 1;
const EVENT_CURSOR_PAYLOAD_BYTES: usize = 1 + 16 + 32 + 8;
const EVENT_CURSOR_BYTES: usize = EVENT_CURSOR_PAYLOAD_BYTES + 32;

/// A bounded page in monotonic arrival order for one endpoint.
#[derive(Debug)]
pub struct WebhookEventPage {
    /// Arrival sequence and retained event for each selected delivery.
    pub events: Vec<(u64, WebhookEvent)>,
    /// Opaque continuation scoped to this endpoint and receiver lifetime.
    pub next_cursor: String,
    /// Whether a retained event remains beyond this page.
    pub has_more: bool,
    /// First sequence still retained for this endpoint, if any.
    pub oldest_available_sequence: Option<u64>,
    /// Global arrival frontier; the next accepted delivery receives this sequence.
    pub next_sequence: u64,
    /// Whether any event body has been evicted from this endpoint.
    pub history_truncated: bool,
    /// Stored event JSON bytes selected, excluding page metadata and wire framing.
    pub serialized_event_bytes: usize,
}

struct CursorIdentity {
    epoch: [u8; 16],
    key: [u8; 32],
}

impl CursorIdentity {
    fn new() -> Self {
        let mut epoch = [0; 16];
        let mut key = [0; 32];
        rand::rngs::OsRng.fill_bytes(&mut epoch);
        rand::rngs::OsRng.fill_bytes(&mut key);
        Self { epoch, key }
    }
}

impl std::fmt::Debug for CursorIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CursorIdentity")
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct RetainedEvent {
    event: WebhookEvent,
    serialized_bytes: usize,
    sequence: u64,
}

#[derive(Debug, Default)]
struct EventBuffer {
    events: VecDeque<RetainedEvent>,
    serialized_bytes: usize,
    highest_evicted_sequence: Option<u64>,
}

impl EventBuffer {
    fn evict_oldest(&mut self) {
        if let Some(event) = self.events.pop_front() {
            self.serialized_bytes -= event.serialized_bytes;
            self.highest_evicted_sequence = Some(
                self.highest_evicted_sequence
                    .map_or(event.sequence, |sequence| sequence.max(event.sequence)),
            );
        }
    }
}

/// Measure retained payloads without allocating a second copy of their JSON.
#[derive(Default)]
struct SerializedSize {
    bytes: usize,
}

impl Write for SerializedSize {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes = self.bytes.saturating_add(bytes.len());
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// In-memory store for webhook endpoints and received events.
#[derive(Debug)]
pub struct WebhookStore {
    /// Public base URL used to build endpoint URLs.
    public_base_url: String,
    /// Registered endpoints, keyed by `endpoint_id`.
    endpoints: HashMap<String, WebhookEndpoint>,
    /// Events per endpoint, keyed by `endpoint_id`.
    events: HashMap<String, EventBuffer>,
    /// Digests of all seen event IDs per endpoint, keyed by `endpoint_id`.
    ///
    /// This stays independent from the bounded event body buffer so replay
    /// protection remains fail-closed even after old event bodies are evicted.
    /// A digest collision is treated as a duplicate, conservatively denying
    /// a new delivery rather than permitting any previously accepted replay.
    event_ids: HashMap<String, HashSet<[u8; 32]>>,
    /// Authenticated delivery digests, independent of unsigned public event IDs.
    ///
    /// Each successful admission adds at most one digest alongside one public
    /// ID, so the existing delivery capacity bounds both indexes. Neither index
    /// is changed on a failed admission or pruned when event bodies are evicted.
    authenticated_deliveries: HashMap<String, HashSet<[u8; 32]>>,
    /// Monotonic arrival order, independent of caller-supplied event timestamps.
    next_event_sequence: u64,
    /// Authentication material for bounded, endpoint-scoped replay cursors.
    cursor_identity: CursorIdentity,
}

impl WebhookStore {
    /// Create a new empty webhook store.
    pub fn new() -> Self {
        Self {
            public_base_url: DEFAULT_PUBLIC_BASE_URL.to_string(),
            endpoints: HashMap::new(),
            events: HashMap::new(),
            event_ids: HashMap::new(),
            authenticated_deliveries: HashMap::new(),
            next_event_sequence: 0,
            cursor_identity: CursorIdentity::new(),
        }
    }

    /// Get the current public base URL.
    #[must_use]
    pub fn public_base_url(&self) -> &str {
        &self.public_base_url
    }

    /// Update the public base URL and rebase any existing endpoint URLs.
    pub fn set_public_base_url(&mut self, public_base_url: &str) {
        self.public_base_url = public_base_url.to_string();
        for endpoint in self.endpoints.values_mut() {
            endpoint.update_public_base_url(public_base_url);
        }
    }

    /// Register a new webhook endpoint.
    pub fn create_endpoint(
        &mut self,
        path: String,
        signing_secret: String,
        allowed_sources: Vec<String>,
    ) -> WebhookReceiverResult<WebhookEndpoint> {
        self.create_endpoint_profile(
            path,
            signing_secret,
            allowed_sources,
            WebhookProvider::Generic,
            WebhookProvider::Generic
                .default_signature_header()
                .to_string(),
            WebhookProvider::Generic
                .default_signature_algorithm()
                .to_string(),
        )
    }

    /// Register a new webhook endpoint with a provider-aware verification profile.
    pub fn create_endpoint_profile(
        &mut self,
        path: String,
        signing_secret: String,
        allowed_sources: Vec<String>,
        provider: WebhookProvider,
        signature_header: String,
        signature_algorithm: String,
    ) -> WebhookReceiverResult<WebhookEndpoint> {
        // Check for duplicate path
        if self.endpoints.values().any(|ep| ep.path == path) {
            return Err(WebhookReceiverError::DuplicatePath { path });
        }

        // Check capacity
        if self.endpoints.len() >= MAX_ENDPOINTS {
            return Err(WebhookReceiverError::CapacityExceeded {
                message: format!("Maximum of {MAX_ENDPOINTS} endpoints reached"),
            });
        }

        let endpoint = WebhookEndpoint::new(
            path,
            signing_secret,
            allowed_sources,
            &self.public_base_url,
            provider,
            signature_header,
            signature_algorithm,
        );
        let validation_issues = endpoint.validation_issues();
        if !validation_issues.is_empty() {
            return Err(WebhookReceiverError::InvalidInput {
                message: validation_issues.join("; "),
            });
        }
        debug!(endpoint_id = %endpoint.endpoint_id, path = %endpoint.path, "Created webhook endpoint");

        self.endpoints
            .insert(endpoint.endpoint_id.clone(), endpoint.clone());
        self.events
            .insert(endpoint.endpoint_id.clone(), EventBuffer::default());
        self.event_ids
            .insert(endpoint.endpoint_id.clone(), HashSet::new());
        self.authenticated_deliveries
            .insert(endpoint.endpoint_id.clone(), HashSet::new());

        Ok(endpoint)
    }

    /// Rotate the signing secret for a specific endpoint.
    pub fn rotate_endpoint_secret(
        &mut self,
        endpoint_id: &str,
        signing_secret: String,
    ) -> WebhookReceiverResult<WebhookEndpoint> {
        let endpoint = self.endpoints.get_mut(endpoint_id).ok_or_else(|| {
            WebhookReceiverError::EndpointNotFound {
                endpoint_id: endpoint_id.into(),
            }
        })?;
        endpoint.rotate_signing_secret(signing_secret);
        Ok(endpoint.clone())
    }

    /// Delete a webhook endpoint and its events.
    pub fn delete_endpoint(&mut self, endpoint_id: &str) -> WebhookReceiverResult<()> {
        if self.endpoints.remove(endpoint_id).is_none() {
            return Err(WebhookReceiverError::EndpointNotFound {
                endpoint_id: endpoint_id.into(),
            });
        }
        self.events.remove(endpoint_id);
        self.event_ids.remove(endpoint_id);
        self.authenticated_deliveries.remove(endpoint_id);
        debug!(endpoint_id = %endpoint_id, "Deleted webhook endpoint");
        Ok(())
    }

    /// List all registered endpoints with event counts.
    pub fn list_endpoints(&self) -> Vec<EndpointSummary> {
        self.endpoints
            .values()
            .map(|ep| {
                let event_count = self
                    .events
                    .get(&ep.endpoint_id)
                    .map_or(0, |buffer| buffer.events.len());
                EndpointSummary::from_endpoint(ep, event_count)
            })
            .collect()
    }

    /// Get a specific endpoint by ID.
    pub fn get_endpoint(&self, endpoint_id: &str) -> WebhookReceiverResult<&WebhookEndpoint> {
        self.endpoints
            .get(endpoint_id)
            .ok_or_else(|| WebhookReceiverError::EndpointNotFound {
                endpoint_id: endpoint_id.into(),
            })
    }

    /// Get a specific endpoint by path.
    pub fn get_endpoint_by_path(&self, path: &str) -> WebhookReceiverResult<&WebhookEndpoint> {
        self.endpoints
            .values()
            .find(|endpoint| endpoint.path == path && endpoint.active)
            .ok_or_else(|| WebhookReceiverError::EndpointNotFound {
                endpoint_id: path.into(),
            })
    }

    /// Snapshot the current endpoints for readiness checks.
    #[must_use]
    pub fn endpoint_snapshots(&self) -> Vec<WebhookEndpoint> {
        self.endpoints.values().cloned().collect()
    }

    /// Record a received webhook event.
    pub fn record_event(&mut self, event: WebhookEvent) -> WebhookReceiverResult<()> {
        self.record_event_inner(event, None)
    }

    /// Admit a verified delivery, checking both its public ID and authenticated
    /// identity before changing replay indexes or retained event bodies.
    ///
    /// The digest must come from successful provider signature verification;
    /// transport IDs and other unsigned metadata must never contribute to it.
    pub(crate) fn record_authenticated_event(
        &mut self,
        event: WebhookEvent,
        replay_digest: [u8; 32],
    ) -> WebhookReceiverResult<()> {
        self.record_event_inner(event, Some(replay_digest))
    }

    fn record_event_inner(
        &mut self,
        event: WebhookEvent,
        replay_digest: Option<[u8; 32]>,
    ) -> WebhookReceiverResult<()> {
        if !self.endpoints.contains_key(&event.endpoint_id) {
            return Err(WebhookReceiverError::EndpointNotFound {
                endpoint_id: event.endpoint_id,
            });
        }
        if event.event_id.len() > MAX_EVENT_ID_BYTES {
            return Err(WebhookReceiverError::InvalidInput {
                message: format!("Webhook delivery ID exceeds {MAX_EVENT_ID_BYTES} bytes"),
            });
        }

        let event_digest = *blake3::hash(event.event_id.as_bytes()).as_bytes();
        let event_ids = self.event_ids.get(&event.endpoint_id);
        // Report known duplicates even when replay capacity is exhausted.
        // No identity or retained body is evicted to make room for a new ID.
        if event_ids.is_some_and(|ids| ids.contains(&event_digest))
            || replay_digest.is_some_and(|digest| {
                self.authenticated_deliveries
                    .get(&event.endpoint_id)
                    .is_some_and(|digests| digests.contains(&digest))
            })
        {
            return Err(WebhookReceiverError::DuplicateEvent {
                endpoint_id: event.endpoint_id,
                event_id: event.event_id,
            });
        }
        if event_ids.map_or(0, HashSet::len) >= MAX_REPLAY_IDS_PER_ENDPOINT
            || self.replay_event_count() >= MAX_REPLAY_IDS_TOTAL
        {
            return Err(WebhookReceiverError::ReplayCapacityExceeded {
                endpoint_id: event.endpoint_id,
                limit: MAX_REPLAY_IDS_PER_ENDPOINT.min(MAX_REPLAY_IDS_TOTAL),
            });
        }

        let mut serialized_size = SerializedSize::default();
        serde_json::to_writer(&mut serialized_size, &event)?;
        let serialized_bytes = serialized_size.bytes;
        if serialized_bytes > MAX_RETAINED_EVENT_BYTES_PER_ENDPOINT {
            return Err(WebhookReceiverError::PayloadTooLarge {
                message: format!(
                    "Serialized webhook event exceeds the {MAX_RETAINED_EVENT_BYTES_PER_ENDPOINT}-byte retention limit"
                ),
            });
        }
        let sequence = self.next_event_sequence;
        let next_sequence =
            sequence
                .checked_add(1)
                .ok_or_else(|| WebhookReceiverError::Internal {
                    message: "Webhook event arrival sequence exhausted".into(),
                })?;

        // Every fallible admission check precedes retention changes. Evict only
        // event bodies, retaining independent replay digests for the namespace.
        let buffer = self.events.entry(event.endpoint_id.clone()).or_default();
        while buffer.events.len() >= MAX_EVENTS_PER_ENDPOINT
            || buffer.serialized_bytes > MAX_RETAINED_EVENT_BYTES_PER_ENDPOINT - serialized_bytes
        {
            buffer.evict_oldest();
        }
        while self.retained_event_bytes() > MAX_RETAINED_EVENT_BYTES_TOTAL - serialized_bytes {
            // The byte total is derived from these buffers; a positive total
            // always has a nonempty buffer. Arrival sequence prevents supplied
            // timestamps from controlling eviction across endpoints.
            if let Some(oldest) = self
                .events
                .values_mut()
                .filter(|buffer| !buffer.events.is_empty())
                .min_by_key(|buffer| buffer.events.front().map(|event| event.sequence))
            {
                oldest.evict_oldest();
            }
        }

        self.event_ids
            .entry(event.endpoint_id.clone())
            .or_default()
            .insert(event_digest);
        if let Some(digest) = replay_digest {
            self.authenticated_deliveries
                .entry(event.endpoint_id.clone())
                .or_default()
                .insert(digest);
        }
        let buffer = self.events.entry(event.endpoint_id.clone()).or_default();
        buffer.serialized_bytes += serialized_bytes;
        buffer.events.push_back(RetainedEvent {
            event,
            serialized_bytes,
            sequence,
        });
        self.next_event_sequence = next_sequence;

        Ok(())
    }

    /// Get recent events, optionally filtered by endpoint and time.
    pub fn get_recent_events(
        &self,
        endpoint_id: Option<&str>,
        limit: Option<usize>,
        since_ts: Option<DateTime<Utc>>,
    ) -> WebhookReceiverResult<Vec<WebhookEvent>> {
        let limit = limit.unwrap_or(DEFAULT_EVENTS_LIMIT).min(MAX_EVENTS_LIMIT);

        // If endpoint_id is specified, validate it exists
        if let Some(eid) = endpoint_id
            && !self.endpoints.contains_key(eid)
        {
            return Err(WebhookReceiverError::EndpointNotFound {
                endpoint_id: eid.into(),
            });
        }

        let mut all_events: Vec<&WebhookEvent> = if let Some(eid) = endpoint_id {
            self.events.get(eid).map_or_else(Vec::new, |buffer| {
                buffer.events.iter().map(|entry| &entry.event).collect()
            })
        } else {
            self.events
                .values()
                .flat_map(|buffer| buffer.events.iter().map(|entry| &entry.event))
                .collect()
        };

        // Filter by since_ts if provided
        if let Some(since) = since_ts {
            all_events.retain(|e| e.received_at >= since);
        }

        // Sort by received_at descending (most recent first)
        all_events.sort_by_key(|e| Reverse(e.received_at));

        // Apply limit
        all_events.truncate(limit);

        // Large payloads are copied only after filtering, ordering and limiting.
        Ok(all_events.into_iter().cloned().collect())
    }

    /// Poll retained deliveries in arrival order without timestamp ambiguity.
    ///
    /// An initial poll starts at the oldest retained event, or at the current
    /// frontier when `start_at_latest` is true. Continuing a cursor never skips
    /// unread evictions: a cursor at or below the endpoint's eviction watermark
    /// returns [`WebhookReceiverError::ReplayGap`]. Polling does not consume
    /// events or change the independent delivery replay-protection indexes.
    pub fn poll_events(
        &self,
        endpoint_id: &str,
        cursor: Option<&str>,
        limit: usize,
        max_bytes: usize,
        start_at_latest: bool,
    ) -> WebhookReceiverResult<WebhookEventPage> {
        if endpoint_id.trim().is_empty()
            || !(1..=MAX_EVENTS_LIMIT).contains(&limit)
            || !(1..=MAX_RETAINED_EVENT_BYTES_PER_ENDPOINT).contains(&max_bytes)
            || (cursor.is_some() && start_at_latest)
        {
            return Err(WebhookReceiverError::InvalidInput {
                message: format!(
                    "Event polling requires an endpoint, limit 1..={MAX_EVENTS_LIMIT}, max_bytes 1..={MAX_RETAINED_EVENT_BYTES_PER_ENDPOINT}, and no start override with a cursor"
                ),
            });
        }

        // Recognize an expired receiver epoch even if reconfiguration removed
        // the old endpoint. Current-epoch cursors still require the exact scope.
        let resumed_sequence = cursor
            .map(|cursor| self.decode_event_cursor(endpoint_id, cursor))
            .transpose()?;
        self.get_endpoint(endpoint_id)?;
        let buffer =
            self.events
                .get(endpoint_id)
                .ok_or_else(|| WebhookReceiverError::Internal {
                    message: "Webhook endpoint event buffer is unavailable".into(),
                })?;
        if resumed_sequence.is_some_and(|sequence| {
            buffer
                .highest_evicted_sequence
                .is_some_and(|evicted| sequence <= evicted)
        }) {
            return Err(WebhookReceiverError::ReplayGap {
                endpoint_id: endpoint_id.to_owned(),
            });
        }
        let oldest_available_sequence = buffer.events.front().map(|event| event.sequence);
        let start_sequence = resumed_sequence.unwrap_or_else(|| {
            if start_at_latest {
                self.next_event_sequence
            } else {
                oldest_available_sequence.unwrap_or(self.next_event_sequence)
            }
        });
        let mut events = Vec::with_capacity(limit.min(buffer.events.len()));
        let mut serialized_event_bytes = 0;
        let mut has_more = false;
        let mut continuation_sequence = self.next_event_sequence;
        for retained in buffer
            .events
            .iter()
            .filter(|retained| retained.sequence >= start_sequence)
        {
            if events.len() == limit {
                has_more = true;
                break;
            }
            if retained.serialized_bytes > max_bytes - serialized_event_bytes {
                if events.is_empty() {
                    return Err(WebhookReceiverError::PayloadTooLarge {
                        message: format!(
                            "Next webhook event requires {} serialized bytes; increase max_bytes beyond the current {max_bytes}-byte page budget",
                            retained.serialized_bytes
                        ),
                    });
                }
                has_more = true;
                break;
            }
            serialized_event_bytes += retained.serialized_bytes;
            // Admission never assigns u64::MAX: it reserves the next sequence
            // before recording the event, so this increment cannot overflow.
            continuation_sequence = retained.sequence + 1;
            events.push((retained.sequence, retained.event.clone()));
        }
        if !has_more {
            // Other endpoints may have advanced the global sequence since the
            // last matching delivery. An exhausted poll catches up to that
            // frontier without claiming or consuming any future event.
            continuation_sequence = self.next_event_sequence;
        }

        Ok(WebhookEventPage {
            events,
            next_cursor: self.encode_event_cursor(endpoint_id, continuation_sequence),
            has_more,
            oldest_available_sequence,
            next_sequence: self.next_event_sequence,
            history_truncated: buffer.highest_evicted_sequence.is_some(),
            serialized_event_bytes,
        })
    }

    fn encode_event_cursor(&self, endpoint_id: &str, next_sequence: u64) -> String {
        let mut bytes = [0; EVENT_CURSOR_BYTES];
        bytes[0] = EVENT_CURSOR_VERSION;
        bytes[1..17].copy_from_slice(&self.cursor_identity.epoch);
        bytes[17..49].copy_from_slice(blake3::hash(endpoint_id.as_bytes()).as_bytes());
        bytes[49..EVENT_CURSOR_PAYLOAD_BYTES].copy_from_slice(&next_sequence.to_be_bytes());
        let tag = blake3::keyed_hash(
            &self.cursor_identity.key,
            &bytes[..EVENT_CURSOR_PAYLOAD_BYTES],
        );
        bytes[EVENT_CURSOR_PAYLOAD_BYTES..].copy_from_slice(tag.as_bytes());
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn decode_event_cursor(&self, endpoint_id: &str, cursor: &str) -> WebhookReceiverResult<u64> {
        let invalid = || WebhookReceiverError::InvalidInput {
            message: "webhook_cursor_invalid".into(),
        };
        if cursor.is_empty() || cursor.len() > MAX_EVENT_CURSOR_BYTES {
            return Err(invalid());
        }
        let bytes = URL_SAFE_NO_PAD.decode(cursor).map_err(|_| invalid())?;
        if bytes.len() != EVENT_CURSOR_BYTES || bytes[0] != EVENT_CURSOR_VERSION {
            return Err(invalid());
        }
        // Old stores have different MAC keys, so their tags cannot be
        // authenticated here. A foreign epoch only produces a fail-closed
        // expiry response; it never authorizes a position or reveals events.
        if bytes[1..17] != self.cursor_identity.epoch {
            return Err(WebhookReceiverError::ExpiredCursor);
        }
        let expected = blake3::keyed_hash(
            &self.cursor_identity.key,
            &bytes[..EVENT_CURSOR_PAYLOAD_BYTES],
        );
        if !bool::from(
            expected
                .as_bytes()
                .as_slice()
                .ct_eq(&bytes[EVENT_CURSOR_PAYLOAD_BYTES..]),
        ) || bytes[17..49] != *blake3::hash(endpoint_id.as_bytes()).as_bytes()
        {
            return Err(invalid());
        }
        let sequence_bytes: [u8; 8] = bytes[49..EVENT_CURSOR_PAYLOAD_BYTES]
            .try_into()
            .map_err(|_| invalid())?;
        let next_sequence = u64::from_be_bytes(sequence_bytes);
        if next_sequence > self.next_event_sequence {
            return Err(invalid());
        }
        Ok(next_sequence)
    }

    /// Get the number of registered endpoints.
    pub fn endpoint_count(&self) -> usize {
        self.endpoints.len()
    }

    /// Get the number of active endpoints.
    #[must_use]
    pub fn active_endpoint_count(&self) -> usize {
        self.endpoints
            .values()
            .filter(|endpoint| endpoint.active)
            .count()
    }

    /// Get the total number of stored events.
    pub fn total_event_count(&self) -> usize {
        self.events.values().map(|buffer| buffer.events.len()).sum()
    }

    /// Distinct replay identities retained across all endpoints.
    #[must_use]
    pub fn replay_event_count(&self) -> usize {
        self.event_ids.values().map(HashSet::len).sum()
    }

    /// Remaining shared capacity for previously unseen delivery identities.
    #[must_use]
    pub fn replay_capacity_remaining(&self) -> usize {
        MAX_REPLAY_IDS_TOTAL.saturating_sub(self.replay_event_count())
    }

    /// Active endpoints unable to accept a previously unseen delivery identity.
    ///
    /// Shared exhaustion blocks every active endpoint, including empty ones.
    #[must_use]
    pub fn replay_exhausted_endpoint_count(&self) -> usize {
        if self.replay_capacity_remaining() == 0 {
            return self.active_endpoint_count();
        }
        self.endpoints
            .values()
            .filter(|endpoint| {
                endpoint.active
                    && self
                        .event_ids
                        .get(&endpoint.endpoint_id)
                        .is_some_and(|ids| ids.len() >= MAX_REPLAY_IDS_PER_ENDPOINT)
            })
            .count()
    }

    /// Distinct replay identities retained for an existing endpoint.
    pub fn endpoint_replay_event_count(&self, endpoint_id: &str) -> WebhookReceiverResult<usize> {
        self.get_endpoint(endpoint_id)?;
        Ok(self.event_ids.get(endpoint_id).map_or(0, HashSet::len))
    }

    /// Serialized event bytes retained across all endpoints, excluding allocator
    /// overhead, replay identities and endpoint configuration.
    #[must_use]
    pub fn retained_event_bytes(&self) -> usize {
        self.events
            .values()
            .map(|buffer| buffer.serialized_bytes)
            .sum()
    }

    /// Serialized event bytes retained for an existing endpoint.
    pub fn endpoint_retained_event_bytes(&self, endpoint_id: &str) -> WebhookReceiverResult<usize> {
        self.get_endpoint(endpoint_id)?;
        Ok(self
            .events
            .get(endpoint_id)
            .map_or(0, |buffer| buffer.serialized_bytes))
    }

    /// Clear all endpoints and events.
    pub fn clear(&mut self) {
        self.endpoints.clear();
        self.events.clear();
        self.event_ids.clear();
        self.authenticated_deliveries.clear();
        self.next_event_sequence = 0;
        self.cursor_identity = CursorIdentity::new();
    }
}

impl Default for WebhookStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn store_new_is_empty() {
        let store = WebhookStore::new();
        assert_eq!(store.endpoint_count(), 0);
        assert_eq!(store.total_event_count(), 0);
        assert_eq!(store.public_base_url(), DEFAULT_PUBLIC_BASE_URL);
    }

    #[test]
    fn store_default_is_empty() {
        let store = WebhookStore::default();
        assert_eq!(store.endpoint_count(), 0);
        assert_eq!(store.total_event_count(), 0);
    }

    #[test]
    fn create_endpoint_basic() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/github".into(), "secret".into(), vec![])
            .unwrap();
        assert!(ep.endpoint_id.starts_with("ep_"));
        assert_eq!(ep.path, "/hooks/github");
        assert_eq!(ep.url, "http://localhost:8080/hooks/github");
        assert_eq!(store.endpoint_count(), 1);
    }

    #[test]
    fn create_endpoint_with_allowed_sources() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint(
                "/hooks/stripe".into(),
                "whsec_123".into(),
                vec!["10.0.0.0/8".into(), "172.16.0.0/12".into()],
            )
            .unwrap();
        assert_eq!(ep.allowed_sources.len(), 2);
    }

    #[test]
    fn set_public_base_url_rebases_existing_endpoints() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/github".into(), "secret".into(), vec![])
            .unwrap();
        assert_eq!(ep.url, "http://localhost:8080/hooks/github");

        store.set_public_base_url("https://hooks.flywheel.test/");

        let updated = store.get_endpoint(&ep.endpoint_id).unwrap();
        assert_eq!(updated.url, "https://hooks.flywheel.test/hooks/github");
    }

    #[test]
    fn create_endpoint_profile_uses_provider_defaults() {
        let mut store = WebhookStore::new();
        store.set_public_base_url("https://hooks.flywheel.test");
        let ep = store
            .create_endpoint_profile(
                "/hooks/github".into(),
                "ghsec_123".into(),
                vec![],
                WebhookProvider::GitHub,
                "X-Hub-Signature-256".into(),
                "hmac-sha256".into(),
            )
            .unwrap();
        assert_eq!(ep.provider, WebhookProvider::GitHub);
        assert_eq!(ep.signature_header, "X-Hub-Signature-256");
        assert_eq!(ep.signature_algorithm, "hmac-sha256");
        assert_eq!(ep.url, "https://hooks.flywheel.test/hooks/github");
    }

    #[test]
    fn create_endpoint_profile_rejects_provider_mismatch() {
        let mut store = WebhookStore::new();
        let result = store.create_endpoint_profile(
            "/hooks/github".into(),
            "ghsec_123".into(),
            vec![],
            WebhookProvider::GitHub,
            "Stripe-Signature".into(),
            "stripe-signature-v1".into(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn create_endpoint_duplicate_path_rejected() {
        let mut store = WebhookStore::new();
        store
            .create_endpoint("/hooks/github".into(), "s1".into(), vec![])
            .unwrap();
        let result = store.create_endpoint("/hooks/github".into(), "s2".into(), vec![]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(
            &err,
            WebhookReceiverError::DuplicatePath { path } if path == "/hooks/github"
        ));
    }

    #[test]
    fn create_endpoint_different_paths_allowed() {
        let mut store = WebhookStore::new();
        store
            .create_endpoint("/hooks/github".into(), "s1".into(), vec![])
            .unwrap();
        store
            .create_endpoint("/hooks/stripe".into(), "s2".into(), vec![])
            .unwrap();
        assert_eq!(store.endpoint_count(), 2);
    }

    #[test]
    fn delete_endpoint_success() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/test".into(), "s".into(), vec![])
            .unwrap();
        store.delete_endpoint(&ep.endpoint_id).unwrap();
        assert_eq!(store.endpoint_count(), 0);
    }

    #[test]
    fn delete_endpoint_removes_events() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/test".into(), "s".into(), vec![])
            .unwrap();
        let event = WebhookEvent::new(ep.endpoint_id.clone(), json!({}), true, None);
        store.record_event(event).unwrap();
        assert_eq!(store.total_event_count(), 1);
        store.delete_endpoint(&ep.endpoint_id).unwrap();
        assert_eq!(store.total_event_count(), 0);
    }

    #[test]
    fn delete_endpoint_not_found() {
        let mut store = WebhookStore::new();
        let result = store.delete_endpoint("ep_nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn rotate_endpoint_secret_updates_stored_secret() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/test".into(), "old_secret".into(), vec![])
            .unwrap();
        let rotated = store
            .rotate_endpoint_secret(&ep.endpoint_id, "new_secret".into())
            .unwrap();
        assert_eq!(rotated.signing_secret, "new_secret");
        assert!(
            store
                .get_endpoint(&ep.endpoint_id)
                .unwrap()
                .signing_secret
                .eq("new_secret")
        );
    }

    #[test]
    fn list_endpoints_empty() {
        let store = WebhookStore::new();
        assert!(store.list_endpoints().is_empty());
    }

    #[test]
    fn list_endpoints_returns_all() {
        let mut store = WebhookStore::new();
        store
            .create_endpoint("/a".into(), "s".into(), vec![])
            .unwrap();
        store
            .create_endpoint("/b".into(), "s".into(), vec![])
            .unwrap();
        let list = store.list_endpoints();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn list_endpoints_includes_event_counts() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/test".into(), "s".into(), vec![])
            .unwrap();
        for _ in 0..3 {
            let event = WebhookEvent::new(ep.endpoint_id.clone(), json!({}), true, None);
            store.record_event(event).unwrap();
        }
        let list = store.list_endpoints();
        let summary = list
            .iter()
            .find(|s| s.endpoint_id == ep.endpoint_id)
            .unwrap();
        assert_eq!(summary.event_count, 3);
    }

    #[test]
    fn get_endpoint_success() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/test".into(), "s".into(), vec![])
            .unwrap();
        let found = store.get_endpoint(&ep.endpoint_id).unwrap();
        assert_eq!(found.path, "/hooks/test");
    }

    #[test]
    fn get_endpoint_not_found() {
        let store = WebhookStore::new();
        let result = store.get_endpoint("ep_nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn record_event_success() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/test".into(), "s".into(), vec![])
            .unwrap();
        let event = WebhookEvent::new(
            ep.endpoint_id,
            json!({"type": "push"}),
            true,
            Some("1.2.3.4".into()),
        );
        store.record_event(event).unwrap();
        assert_eq!(store.total_event_count(), 1);
    }

    #[test]
    fn record_event_endpoint_not_found() {
        let mut store = WebhookStore::new();
        let event = WebhookEvent::new("ep_nonexistent".into(), json!({}), true, None);
        let result = store.record_event(event);
        assert!(result.is_err());
    }

    #[test]
    fn record_event_duplicate_event_id_rejected_for_same_endpoint() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/test".into(), "s".into(), vec![])
            .unwrap();
        let mut first = WebhookEvent::new(ep.endpoint_id.clone(), json!({"seq": 1}), true, None);
        first.event_id = "evt_dup".into();
        store.record_event(first).unwrap();

        let mut duplicate =
            WebhookEvent::new(ep.endpoint_id.clone(), json!({"seq": 2}), true, None);
        duplicate.event_id = "evt_dup".into();
        let err = store
            .record_event(duplicate)
            .expect_err("duplicate event_id must be rejected");
        assert!(matches!(
            &err,
            WebhookReceiverError::DuplicateEvent {
                endpoint_id,
                event_id,
            } if endpoint_id == &ep.endpoint_id && event_id == "evt_dup"
        ));
        assert_eq!(store.total_event_count(), 1);
    }

    #[test]
    fn record_event_same_id_allowed_on_different_endpoints() {
        let mut store = WebhookStore::new();
        let ep1 = store
            .create_endpoint("/hooks/a".into(), "s1".into(), vec![])
            .unwrap();
        let ep2 = store
            .create_endpoint("/hooks/b".into(), "s2".into(), vec![])
            .unwrap();

        let mut event_a = WebhookEvent::new(ep1.endpoint_id, json!({"a": 1}), true, None);
        event_a.event_id = "evt_shared".into();
        store.record_event(event_a).unwrap();

        let mut event_b = WebhookEvent::new(ep2.endpoint_id, json!({"b": 2}), true, None);
        event_b.event_id = "evt_shared".into();
        store.record_event(event_b).unwrap();

        assert_eq!(store.total_event_count(), 2);
    }

    #[test]
    fn authenticated_replay_checks_both_identities_without_claiming_failed_attempts() {
        let mut store = WebhookStore::new();
        let endpoint = store
            .create_endpoint("/authenticated".into(), "secret".into(), vec![])
            .unwrap();
        let mut original = WebhookEvent::new(
            endpoint.endpoint_id.clone(),
            json!({"value": 1}),
            true,
            None,
        );
        original.event_id = "original".into();
        store
            .record_authenticated_event(original.clone(), [1; 32])
            .unwrap();
        let retained_bytes = store.retained_event_bytes();

        let mut renamed = original.clone();
        renamed.event_id = "renamed".into();
        assert!(matches!(
            store.record_authenticated_event(renamed.clone(), [1; 32]),
            Err(WebhookReceiverError::DuplicateEvent { .. })
        ));
        // A new authenticated identity cannot reuse an existing public ID.
        assert!(matches!(
            store.record_authenticated_event(original.clone(), [2; 32]),
            Err(WebhookReceiverError::DuplicateEvent { .. })
        ));
        assert_eq!(store.replay_event_count(), 1);
        assert_eq!(
            store.authenticated_deliveries[&endpoint.endpoint_id].len(),
            1
        );
        assert_eq!(store.retained_event_bytes(), retained_bytes);

        // Neither failed duplicate may consume its previously unseen identity.
        store.record_authenticated_event(renamed, [2; 32]).unwrap();
        assert_eq!(store.replay_event_count(), 2);
        assert_eq!(
            store.authenticated_deliveries[&endpoint.endpoint_id].len(),
            2
        );

        let other = store
            .create_endpoint("/other".into(), "secret".into(), vec![])
            .unwrap();
        original.endpoint_id = other.endpoint_id;
        store.record_authenticated_event(original, [1; 32]).unwrap();
        assert_eq!(store.total_event_count(), 3);
    }

    #[test]
    fn record_event_evicts_oldest_at_capacity() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/test".into(), "s".into(), vec![])
            .unwrap();
        let initial_cursor = store
            .poll_events(&ep.endpoint_id, None, 1, 1024, false)
            .unwrap()
            .next_cursor;

        // Fill to capacity
        for i in 0..MAX_EVENTS_PER_ENDPOINT {
            let mut event =
                WebhookEvent::new(ep.endpoint_id.clone(), json!({"index": i}), true, None);
            event.event_id = format!("evt_{i}");
            store.record_event(event).unwrap();
        }
        assert_eq!(store.total_event_count(), MAX_EVENTS_PER_ENDPOINT);
        let first_page = store
            .poll_events(&ep.endpoint_id, Some(&initial_cursor), 1, 1024, false)
            .unwrap();
        assert_eq!(first_page.events[0].0, 0);
        assert!(!first_page.history_truncated);

        // Add one more; oldest should be evicted
        let mut new_event =
            WebhookEvent::new(ep.endpoint_id.clone(), json!({"index": "new"}), true, None);
        new_event.event_id = "evt_new".into();
        store.record_event(new_event).unwrap();
        assert_eq!(store.total_event_count(), MAX_EVENTS_PER_ENDPOINT);

        // Verify the oldest was evicted
        let events = store
            .get_recent_events(Some(&ep.endpoint_id), Some(MAX_EVENTS_LIMIT), None)
            .unwrap();
        let ids: Vec<&str> = events.iter().map(|e| e.event_id.as_str()).collect();
        assert!(!ids.contains(&"evt_0"));
        assert!(ids.contains(&"evt_new"));
        assert!(matches!(
            store.poll_events(&ep.endpoint_id, Some(&initial_cursor), 1, 1024, false),
            Err(WebhookReceiverError::ReplayGap { .. })
        ));
        // A cursor that consumed the evicted prefix still reads without a gap.
        let continued = store
            .poll_events(
                &ep.endpoint_id,
                Some(&first_page.next_cursor),
                1,
                1024,
                false,
            )
            .unwrap();
        assert_eq!(continued.events[0].0, 1);
        assert_eq!(continued.oldest_available_sequence, Some(1));
        assert!(continued.history_truncated);
        store
            .record_event(WebhookEvent::new(
                ep.endpoint_id.clone(),
                json!({}),
                true,
                None,
            ))
            .unwrap();
        assert!(matches!(
            store.poll_events(
                &ep.endpoint_id,
                Some(&first_page.next_cursor),
                1,
                1024,
                false
            ),
            Err(WebhookReceiverError::ReplayGap { .. })
        ));
        let restarted = store
            .poll_events(&ep.endpoint_id, None, 1, 1024, false)
            .unwrap();
        assert_eq!(restarted.events[0].0, 2);
        assert!(restarted.history_truncated);
    }

    #[test]
    fn record_event_replay_identities_survive_original_body_eviction() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/test".into(), "s".into(), vec![])
            .unwrap();

        let mut original =
            WebhookEvent::new(ep.endpoint_id.clone(), json!({"index": 0}), true, None);
        original.event_id = "evt_replay".into();
        store.record_authenticated_event(original, [7; 32]).unwrap();

        for i in 1..=MAX_EVENTS_PER_ENDPOINT {
            let mut event =
                WebhookEvent::new(ep.endpoint_id.clone(), json!({"index": i}), true, None);
            event.event_id = format!("evt_{i}");
            store.record_event(event).unwrap();
        }

        let recent = store
            .get_recent_events(Some(&ep.endpoint_id), Some(MAX_EVENTS_LIMIT), None)
            .unwrap();
        assert!(
            !recent.iter().any(|event| event.event_id == "evt_replay"),
            "bounded event retention should evict the oldest event body"
        );

        let mut replay = WebhookEvent::new(
            ep.endpoint_id.clone(),
            json!({"index": "replay"}),
            true,
            None,
        );
        replay.event_id = "evt_replay".into();
        let err = store
            .record_event(replay)
            .expect_err("dedup state must outlive event-body eviction");
        assert!(matches!(
            &err,
            WebhookReceiverError::DuplicateEvent {
                endpoint_id,
                event_id,
            } if endpoint_id == &ep.endpoint_id && event_id == "evt_replay"
        ));
        let mut renamed = WebhookEvent::new(ep.endpoint_id, json!({"index": 0}), true, None);
        renamed.event_id = "changed-unsigned-delivery-id".into();
        assert!(matches!(
            store.record_authenticated_event(renamed, [7; 32]),
            Err(WebhookReceiverError::DuplicateEvent { .. })
        ));
        assert_eq!(store.replay_event_count(), MAX_EVENTS_PER_ENDPOINT + 1);
    }

    #[test]
    fn replay_capacity_blocks_new_ids_without_evicting_known_ids() {
        let mut store = WebhookStore::new();
        let first = store
            .create_endpoint("/first".into(), "secret".into(), vec![])
            .unwrap();
        let second = store
            .create_endpoint("/second".into(), "secret".into(), vec![])
            .unwrap();
        let unused = store
            .create_endpoint("/unused".into(), "secret".into(), vec![])
            .unwrap();

        for index in 0..MAX_REPLAY_IDS_TOTAL {
            let endpoint = if index % 2 == 0 { &first } else { &second };
            let mut event = WebhookEvent::new(endpoint.endpoint_id.clone(), json!({}), true, None);
            event.event_id = format!("delivery-{index}");
            let digest = *blake3::hash(event.event_id.as_bytes()).as_bytes();
            store.record_authenticated_event(event, digest).unwrap();
        }
        assert_eq!(store.replay_event_count(), MAX_REPLAY_IDS_TOTAL);
        assert_eq!(store.replay_capacity_remaining(), 0);
        assert_eq!(store.replay_exhausted_endpoint_count(), 3);
        assert_eq!(
            store
                .endpoint_replay_event_count(&unused.endpoint_id)
                .unwrap(),
            0
        );
        let retained_count = store.total_event_count();
        let retained_bytes = store.retained_event_bytes();

        for endpoint in [&first, &second, &unused] {
            let event = WebhookEvent::new(endpoint.endpoint_id.clone(), json!({}), true, None);
            assert!(matches!(
                store.record_authenticated_event(event, [9; 32]),
                Err(WebhookReceiverError::ReplayCapacityExceeded { .. })
            ));
        }
        let mut renamed = WebhookEvent::new(first.endpoint_id.clone(), json!({}), true, None);
        renamed.event_id = "changed-delivery-id".into();
        assert!(matches!(
            store.record_authenticated_event(renamed, *blake3::hash(b"delivery-0").as_bytes()),
            Err(WebhookReceiverError::DuplicateEvent { .. })
        ));
        assert_eq!(
            store
                .authenticated_deliveries
                .values()
                .map(HashSet::len)
                .sum::<usize>(),
            MAX_REPLAY_IDS_TOTAL
        );
        // A secret change does not discard replay identities or create room.
        store
            .rotate_endpoint_secret(&first.endpoint_id, "new-secret".into())
            .unwrap();
        let mut replay = WebhookEvent::new(first.endpoint_id.clone(), json!({}), true, None);
        replay.event_id = "delivery-0".into();
        assert!(matches!(
            store.record_event(replay),
            Err(WebhookReceiverError::DuplicateEvent { .. })
        ));
        assert_eq!(store.replay_event_count(), MAX_REPLAY_IDS_TOTAL);
        assert_eq!(store.total_event_count(), retained_count);
        assert_eq!(store.retained_event_bytes(), retained_bytes);

        store.delete_endpoint(&first.endpoint_id).unwrap();
        assert_eq!(store.replay_event_count(), MAX_REPLAY_IDS_TOTAL / 2);
        assert!(
            !store
                .authenticated_deliveries
                .contains_key(&first.endpoint_id)
        );
        assert_eq!(store.replay_exhausted_endpoint_count(), 0);
        assert!(store.retained_event_bytes() < retained_bytes);
        store
            .record_authenticated_event(
                WebhookEvent::new(unused.endpoint_id, json!({}), true, None),
                [9; 32],
            )
            .unwrap();
        let mut replay = WebhookEvent::new(second.endpoint_id, json!({}), true, None);
        replay.event_id = "delivery-1".into();
        assert!(matches!(
            store.record_event(replay),
            Err(WebhookReceiverError::DuplicateEvent { .. })
        ));

        store.clear();
        assert_eq!(store.replay_event_count(), 0);
        assert!(store.authenticated_deliveries.is_empty());
        assert_eq!(store.replay_capacity_remaining(), MAX_REPLAY_IDS_TOTAL);
        assert_eq!(store.replay_exhausted_endpoint_count(), 0);
        assert_eq!(store.retained_event_bytes(), 0);
        assert_eq!(store.total_event_count(), 0);
    }

    #[test]
    fn event_id_limit_counts_bytes_and_rejects_without_changing_state() {
        let mut store = WebhookStore::new();
        let endpoint = store
            .create_endpoint("/events".into(), "secret".into(), vec![])
            .unwrap();
        let mut event = WebhookEvent::new(endpoint.endpoint_id.clone(), json!({}), true, None);
        event.event_id = "é".repeat(MAX_EVENT_ID_BYTES / 2);
        store.record_event(event).unwrap();
        let retained_bytes = store.retained_event_bytes();

        let mut event = WebhookEvent::new(endpoint.endpoint_id, json!({}), true, None);
        event.event_id = "é".repeat(MAX_EVENT_ID_BYTES / 2 + 1);
        assert!(matches!(
            store.record_event(event),
            Err(WebhookReceiverError::InvalidInput { .. })
        ));
        assert_eq!(store.replay_event_count(), 1);
        assert_eq!(store.total_event_count(), 1);
        assert_eq!(store.retained_event_bytes(), retained_bytes);
    }

    fn sized_event(endpoint_id: &str, event_id: &str, size: usize) -> WebhookEvent {
        let mut event = WebhookEvent::new(endpoint_id.into(), json!({"value": ""}), true, None);
        event.event_id = event_id.into();
        let empty_size = serde_json::to_vec(&event).unwrap().len();
        event.payload["value"] = json!("x".repeat(size.checked_sub(empty_size).unwrap()));
        event
    }

    #[test]
    fn authenticated_admission_errors_preserve_both_replay_indexes_and_retention() {
        let mut store = WebhookStore::new();
        let endpoint = store
            .create_endpoint("/atomic".into(), "secret".into(), vec![])
            .unwrap();
        store
            .record_authenticated_event(sized_event(&endpoint.endpoint_id, "first", 512), [1; 32])
            .unwrap();

        let mut invalid_id = WebhookEvent::new(endpoint.endpoint_id.clone(), json!({}), true, None);
        invalid_id.event_id = "x".repeat(MAX_EVENT_ID_BYTES + 1);
        assert!(matches!(
            store.record_authenticated_event(invalid_id, [2; 32]),
            Err(WebhookReceiverError::InvalidInput { .. })
        ));
        assert!(matches!(
            store.record_authenticated_event(
                WebhookEvent::new("missing-endpoint".into(), json!({}), true, None),
                [2; 32],
            ),
            Err(WebhookReceiverError::EndpointNotFound { .. })
        ));
        let oversized = sized_event(
            &endpoint.endpoint_id,
            "retry",
            MAX_RETAINED_EVENT_BYTES_PER_ENDPOINT + 1,
        );
        assert!(matches!(
            store.record_authenticated_event(oversized, [2; 32]),
            Err(WebhookReceiverError::PayloadTooLarge { .. })
        ));
        store.next_event_sequence = u64::MAX;
        assert!(matches!(
            store.record_authenticated_event(
                sized_event(&endpoint.endpoint_id, "retry", 512),
                [2; 32]
            ),
            Err(WebhookReceiverError::Internal { .. })
        ));
        assert_eq!(store.replay_event_count(), 1);
        assert_eq!(
            store.authenticated_deliveries[&endpoint.endpoint_id].len(),
            1
        );
        assert_eq!(store.total_event_count(), 1);
        assert_eq!(store.retained_event_bytes(), 512);

        store.next_event_sequence = 1;
        store
            .record_authenticated_event(sized_event(&endpoint.endpoint_id, "retry", 512), [2; 32])
            .unwrap();
        assert_eq!(store.replay_event_count(), 2);
        assert_eq!(
            store.authenticated_deliveries[&endpoint.endpoint_id].len(),
            2
        );
        assert_eq!(store.total_event_count(), 2);
        assert_eq!(store.retained_event_bytes(), 1024);
    }

    #[test]
    fn retained_byte_accounting_includes_encoded_headers_ids_and_payload() {
        let mut store = WebhookStore::new();
        let endpoint = store
            .create_endpoint("/events".into(), "secret".into(), vec![])
            .unwrap();
        let mut event = WebhookEvent::new(
            endpoint.endpoint_id.clone(),
            json!({"text": "é\n\"", "values": [1, true, null]}),
            true,
            Some("127.0.0.1".into()),
        );
        event
            .headers
            .insert("x-event".into(), "quoted\"header".into());
        let expected_size = serde_json::to_vec(&event).unwrap().len();
        store.record_event(event).unwrap();
        assert_eq!(store.retained_event_bytes(), expected_size);
        assert_eq!(
            store
                .endpoint_retained_event_bytes(&endpoint.endpoint_id)
                .unwrap(),
            expected_size
        );
        assert!(store.endpoint_replay_event_count("unknown").is_err());
        assert!(store.endpoint_retained_event_bytes("unknown").is_err());
    }

    #[test]
    fn endpoint_byte_retention_evicts_bodies_but_preserves_replay_protection() {
        let mut store = WebhookStore::new();
        let endpoint = store
            .create_endpoint("/events".into(), "secret".into(), vec![])
            .unwrap();
        let initial_cursor = store
            .poll_events(&endpoint.endpoint_id, None, 1, 1024, false)
            .unwrap()
            .next_cursor;
        let half_limit = MAX_RETAINED_EVENT_BYTES_PER_ENDPOINT / 2;
        store
            .record_event(sized_event(&endpoint.endpoint_id, "first", half_limit))
            .unwrap();
        store
            .record_event(sized_event(&endpoint.endpoint_id, "second", half_limit))
            .unwrap();
        assert_eq!(
            store.retained_event_bytes(),
            MAX_RETAINED_EVENT_BYTES_PER_ENDPOINT
        );

        let third = sized_event(&endpoint.endpoint_id, "third", 1024);
        store.record_event(third).unwrap();
        assert_eq!(store.total_event_count(), 2);
        assert_eq!(store.retained_event_bytes(), half_limit + 1024);
        assert_eq!(store.replay_event_count(), 3);
        assert!(matches!(
            store.poll_events(
                &endpoint.endpoint_id,
                Some(&initial_cursor),
                1,
                half_limit,
                false
            ),
            Err(WebhookReceiverError::ReplayGap { .. })
        ));
        let retention = store
            .poll_events(&endpoint.endpoint_id, None, 1, 1024, true)
            .unwrap();
        assert!(retention.history_truncated);
        assert_eq!(retention.oldest_available_sequence, Some(1));
        let mut replay = WebhookEvent::new(endpoint.endpoint_id.clone(), json!({}), true, None);
        replay.event_id = "first".into();
        assert!(matches!(
            store.record_event(replay),
            Err(WebhookReceiverError::DuplicateEvent { .. })
        ));

        let oversized = sized_event(
            &endpoint.endpoint_id,
            "oversized",
            MAX_RETAINED_EVENT_BYTES_PER_ENDPOINT + 1,
        );
        assert!(matches!(
            store.record_event(oversized),
            Err(WebhookReceiverError::PayloadTooLarge { .. })
        ));
        assert_eq!(store.total_event_count(), 2);
        assert_eq!(store.retained_event_bytes(), half_limit + 1024);
        assert_eq!(store.replay_event_count(), 3);
        let replacement = sized_event(&endpoint.endpoint_id, "oversized", 512);
        store.record_event(replacement).unwrap();
        assert_eq!(store.replay_event_count(), 4);
    }

    #[test]
    fn global_byte_retention_evicts_by_arrival_order_and_keeps_other_endpoints() {
        let mut store = WebhookStore::new();
        let mut endpoint_ids = Vec::new();
        let mut cursors = Vec::new();
        let count = MAX_RETAINED_EVENT_BYTES_TOTAL / MAX_RETAINED_EVENT_BYTES_PER_ENDPOINT + 1;
        for index in 0..count {
            let endpoint = store
                .create_endpoint(format!("/events-{index}"), "secret".into(), vec![])
                .unwrap();
            cursors.push(
                store
                    .poll_events(&endpoint.endpoint_id, None, 1, 1024, false)
                    .unwrap()
                    .next_cursor,
            );
            let mut event = sized_event(
                &endpoint.endpoint_id,
                "delivery",
                MAX_RETAINED_EVENT_BYTES_PER_ENDPOINT,
            );
            // A far-future supplied timestamp cannot pin the first arrival.
            if index == 0 {
                event.received_at += chrono::Duration::days(30);
            }
            store.record_event(event).unwrap();
            endpoint_ids.push(endpoint.endpoint_id);
            assert!(store.retained_event_bytes() <= MAX_RETAINED_EVENT_BYTES_TOTAL);
        }
        assert_eq!(store.retained_event_bytes(), MAX_RETAINED_EVENT_BYTES_TOTAL);
        assert_eq!(store.total_event_count(), count - 1);
        assert_eq!(
            store
                .endpoint_retained_event_bytes(&endpoint_ids[0])
                .unwrap(),
            0
        );
        for endpoint_id in &endpoint_ids[1..] {
            assert_eq!(
                store.endpoint_retained_event_bytes(endpoint_id).unwrap(),
                MAX_RETAINED_EVENT_BYTES_PER_ENDPOINT
            );
        }
        assert_eq!(store.replay_event_count(), count);
        assert!(matches!(
            store.poll_events(&endpoint_ids[0], Some(&cursors[0]), 1, 1024, false),
            Err(WebhookReceiverError::ReplayGap { .. })
        ));
        let empty = store
            .poll_events(&endpoint_ids[0], None, 1, 1024, false)
            .unwrap();
        assert!(empty.events.is_empty());
        assert!(empty.history_truncated);
        assert_eq!(empty.oldest_available_sequence, None);
        assert_eq!(empty.next_sequence, count as u64);
        // Eviction from the first endpoint does not invalidate another scope.
        assert!(matches!(
            store.poll_events(&endpoint_ids[1], Some(&cursors[1]), 1, 1024, false),
            Err(WebhookReceiverError::PayloadTooLarge { .. })
        ));
        let mut replay = WebhookEvent::new(endpoint_ids[0].clone(), json!({}), true, None);
        replay.event_id = "delivery".into();
        assert!(matches!(
            store.record_event(replay),
            Err(WebhookReceiverError::DuplicateEvent { .. })
        ));
    }

    #[test]
    fn poll_events_pages_by_arrival_despite_tied_and_out_of_order_timestamps() {
        let mut store = WebhookStore::new();
        let endpoint = store
            .create_endpoint("/poll".into(), "secret".into(), vec![])
            .unwrap();
        let initial_cursor = store
            .poll_events(&endpoint.endpoint_id, None, 2, 4096, false)
            .unwrap()
            .next_cursor;
        let timestamp = Utc::now();
        for (index, seconds) in [30, 30, -10, 90, -60].into_iter().enumerate() {
            let mut event = WebhookEvent::new(
                endpoint.endpoint_id.clone(),
                json!({"index": index}),
                true,
                None,
            );
            event.event_id = format!("delivery-{index}");
            event.received_at = timestamp + chrono::Duration::seconds(seconds);
            store.record_event(event).unwrap();
        }

        let first = store
            .poll_events(&endpoint.endpoint_id, Some(&initial_cursor), 2, 4096, false)
            .unwrap();
        assert_eq!(
            first.events.iter().map(|(seq, _)| *seq).collect::<Vec<_>>(),
            vec![0, 1]
        );
        assert_eq!(first.events[0].1.event_id, "delivery-0");
        assert_eq!(first.events[1].1.event_id, "delivery-1");
        assert!(first.has_more);
        assert!(!first.history_truncated);
        assert_eq!(first.oldest_available_sequence, Some(0));
        assert_eq!(first.next_sequence, 5);
        let repeated = store
            .poll_events(&endpoint.endpoint_id, Some(&initial_cursor), 2, 4096, false)
            .unwrap();
        assert_eq!(repeated.next_cursor, first.next_cursor);
        assert_eq!(
            repeated.serialized_event_bytes,
            first.serialized_event_bytes
        );
        assert_eq!(
            serde_json::to_value(repeated.events).unwrap(),
            serde_json::to_value(&first.events).unwrap()
        );

        let second = store
            .poll_events(
                &endpoint.endpoint_id,
                Some(&first.next_cursor),
                2,
                4096,
                false,
            )
            .unwrap();
        assert_eq!(
            second
                .events
                .iter()
                .map(|(seq, _)| *seq)
                .collect::<Vec<_>>(),
            vec![2, 3]
        );
        assert!(second.has_more);
        let last = store
            .poll_events(
                &endpoint.endpoint_id,
                Some(&second.next_cursor),
                2,
                4096,
                false,
            )
            .unwrap();
        assert_eq!(last.events.len(), 1);
        assert_eq!(last.events[0].0, 4);
        assert_eq!(last.events[0].1.event_id, "delivery-4");
        assert!(!last.has_more);
        let exhausted = store
            .poll_events(
                &endpoint.endpoint_id,
                Some(&last.next_cursor),
                2,
                4096,
                false,
            )
            .unwrap();
        assert!(exhausted.events.is_empty());
        assert_eq!(exhausted.serialized_event_bytes, 0);
        assert!(!exhausted.has_more);
        assert_eq!(exhausted.next_cursor, last.next_cursor);
    }

    #[test]
    fn poll_events_scope_and_frontier_follow_interleaved_endpoint_arrivals() {
        let mut store = WebhookStore::new();
        let first = store
            .create_endpoint("/first".into(), "secret".into(), vec![])
            .unwrap();
        let other = store
            .create_endpoint("/other".into(), "secret".into(), vec![])
            .unwrap();
        for (index, endpoint_id) in [
            &first.endpoint_id,
            &other.endpoint_id,
            &first.endpoint_id,
            &other.endpoint_id,
        ]
        .into_iter()
        .enumerate()
        {
            let mut event = WebhookEvent::new(endpoint_id.clone(), json!({}), true, None);
            event.event_id = format!("delivery-{index}");
            store.record_event(event).unwrap();
        }
        let first_page = store
            .poll_events(&first.endpoint_id, None, 1, 4096, false)
            .unwrap();
        assert_eq!(first_page.events[0].0, 0);
        assert!(first_page.has_more);
        assert!(matches!(
            store.poll_events(
                &other.endpoint_id,
                Some(&first_page.next_cursor),
                1,
                4096,
                false
            ),
            Err(WebhookReceiverError::InvalidInput { .. })
        ));
        let second_page = store
            .poll_events(
                &first.endpoint_id,
                Some(&first_page.next_cursor),
                1,
                4096,
                false,
            )
            .unwrap();
        assert_eq!(second_page.events[0].0, 2);
        assert!(!second_page.has_more);
        assert_eq!(second_page.next_sequence, 4);
        assert_eq!(
            store
                .decode_event_cursor(&first.endpoint_id, &second_page.next_cursor)
                .unwrap(),
            4
        );

        store
            .record_event(WebhookEvent::new(other.endpoint_id, json!({}), true, None))
            .unwrap();
        let exhausted = store
            .poll_events(
                &first.endpoint_id,
                Some(&second_page.next_cursor),
                1,
                4096,
                false,
            )
            .unwrap();
        assert!(exhausted.events.is_empty());
        assert!(!exhausted.has_more);
        assert_eq!(exhausted.next_sequence, 5);
        assert_eq!(
            store
                .decode_event_cursor(&first.endpoint_id, &exhausted.next_cursor)
                .unwrap(),
            5
        );
        assert_ne!(exhausted.next_cursor, second_page.next_cursor);
    }

    #[test]
    fn poll_cursors_reject_current_epoch_tampering_future_positions_and_oversized_input() {
        let mut store = WebhookStore::new();
        let endpoint = store
            .create_endpoint("/poll".into(), "secret".into(), vec![])
            .unwrap();
        let cursor = store
            .poll_events(&endpoint.endpoint_id, None, 1, 1024, false)
            .unwrap()
            .next_cursor;
        assert!(cursor.len() <= MAX_EVENT_CURSOR_BYTES);
        for index in [
            0,
            17,
            48,
            49,
            56,
            EVENT_CURSOR_PAYLOAD_BYTES,
            EVENT_CURSOR_BYTES - 1,
        ] {
            let mut bytes = URL_SAFE_NO_PAD.decode(&cursor).unwrap();
            bytes[index] ^= 1;
            let modified = URL_SAFE_NO_PAD.encode(bytes);
            assert!(
                matches!(
                    store.poll_events(&endpoint.endpoint_id, Some(&modified), 1, 1024, false),
                    Err(WebhookReceiverError::InvalidInput { .. })
                ),
                "tampered byte {index}"
            );
        }
        let future = store.encode_event_cursor(&endpoint.endpoint_id, 1);
        for malformed in [
            String::new(),
            "%%%".into(),
            "a".repeat(MAX_EVENT_CURSOR_BYTES + 1),
            URL_SAFE_NO_PAD.encode([0; EVENT_CURSOR_BYTES - 1]),
            format!("{cursor}="),
            future,
        ] {
            assert!(matches!(
                store.poll_events(&endpoint.endpoint_id, Some(&malformed), 1, 1024, false),
                Err(WebhookReceiverError::InvalidInput { .. })
            ));
        }
        let mut foreign_epoch = URL_SAFE_NO_PAD.decode(&cursor).unwrap();
        foreign_epoch[1] ^= 1;
        assert!(matches!(
            store.poll_events(
                &endpoint.endpoint_id,
                Some(&URL_SAFE_NO_PAD.encode(foreign_epoch)),
                1,
                1024,
                false
            ),
            Err(WebhookReceiverError::ExpiredCursor)
        ));
        // A matching epoch alone cannot authorize a cursor with a different key.
        store.cursor_identity.key[0] ^= 1;
        assert!(matches!(
            store.poll_events(&endpoint.endpoint_id, Some(&cursor), 1, 1024, false),
            Err(WebhookReceiverError::InvalidInput { .. })
        ));
    }

    #[test]
    fn poll_events_byte_budget_returns_complete_events_and_no_empty_retry_loop() {
        let mut store = WebhookStore::new();
        let endpoint = store
            .create_endpoint("/poll".into(), "secret".into(), vec![])
            .unwrap();
        for (event_id, size) in [("first", 512), ("second", 1024), ("third", 768)] {
            store
                .record_event(sized_event(&endpoint.endpoint_id, event_id, size))
                .unwrap();
        }
        assert!(matches!(
            store.poll_events(&endpoint.endpoint_id, None, 100, 511, false),
            Err(WebhookReceiverError::PayloadTooLarge { .. })
        ));
        let first = store
            .poll_events(&endpoint.endpoint_id, None, 100, 512, false)
            .unwrap();
        assert_eq!(first.events.len(), 1);
        assert_eq!(first.events[0].1.event_id, "first");
        assert_eq!(first.serialized_event_bytes, 512);
        assert!(first.has_more);
        assert!(matches!(
            store.poll_events(
                &endpoint.endpoint_id,
                Some(&first.next_cursor),
                100,
                1023,
                false
            ),
            Err(WebhookReceiverError::PayloadTooLarge { .. })
        ));
        let second = store
            .poll_events(
                &endpoint.endpoint_id,
                Some(&first.next_cursor),
                100,
                1024,
                false,
            )
            .unwrap();
        assert_eq!(second.events.len(), 1);
        assert_eq!(second.events[0].1.event_id, "second");
        assert_eq!(second.serialized_event_bytes, 1024);
        assert!(second.has_more);
        let exact = store
            .poll_events(&endpoint.endpoint_id, None, 100, 1536, false)
            .unwrap();
        assert_eq!(exact.events.len(), 2);
        assert_eq!(exact.serialized_event_bytes, 1536);
        assert_eq!(exact.next_cursor, second.next_cursor);
        assert!(exact.has_more);
        let last = store
            .poll_events(
                &endpoint.endpoint_id,
                Some(&exact.next_cursor),
                100,
                768,
                false,
            )
            .unwrap();
        assert_eq!(last.events[0].1.event_id, "third");
        assert_eq!(last.serialized_event_bytes, 768);
        assert!(!last.has_more);
        assert_eq!(store.total_event_count(), 3);
        assert_eq!(store.replay_event_count(), 3);
        assert_eq!(store.retained_event_bytes(), 2304);
    }

    #[test]
    fn poll_events_latest_empty_and_argument_boundaries_are_explicit() {
        let mut store = WebhookStore::new();
        let endpoint = store
            .create_endpoint("/poll".into(), "secret".into(), vec![])
            .unwrap();
        let empty = store
            .poll_events(&endpoint.endpoint_id, None, 100, 1, false)
            .unwrap();
        assert!(empty.events.is_empty());
        assert!(!empty.has_more);
        assert!(!empty.history_truncated);
        assert_eq!(empty.oldest_available_sequence, None);
        assert_eq!(empty.next_sequence, 0);
        assert_eq!(empty.serialized_event_bytes, 0);
        store
            .record_event(sized_event(&endpoint.endpoint_id, "existing", 512))
            .unwrap();
        let latest = store
            .poll_events(&endpoint.endpoint_id, None, 1, 1, true)
            .unwrap();
        assert!(latest.events.is_empty());
        assert!(!latest.has_more);
        assert_eq!(latest.oldest_available_sequence, Some(0));
        assert_eq!(latest.next_sequence, 1);
        store
            .record_event(sized_event(&endpoint.endpoint_id, "new", 512))
            .unwrap();
        let arrival = store
            .poll_events(
                &endpoint.endpoint_id,
                Some(&latest.next_cursor),
                1,
                512,
                false,
            )
            .unwrap();
        assert_eq!(arrival.events.len(), 1);
        assert_eq!(arrival.events[0].0, 1);
        assert_eq!(arrival.events[0].1.event_id, "new");
        let retained = store
            .poll_events(
                &endpoint.endpoint_id,
                Some(&empty.next_cursor),
                100,
                1024,
                false,
            )
            .unwrap();
        assert_eq!(retained.events.len(), 2);
        for (limit, max_bytes) in [
            (0, 1),
            (MAX_EVENTS_LIMIT + 1, 1),
            (1, 0),
            (1, MAX_RETAINED_EVENT_BYTES_PER_ENDPOINT + 1),
        ] {
            assert!(matches!(
                store.poll_events(&endpoint.endpoint_id, None, limit, max_bytes, false),
                Err(WebhookReceiverError::InvalidInput { .. })
            ));
        }
        assert!(matches!(
            store.poll_events(
                &endpoint.endpoint_id,
                Some(&latest.next_cursor),
                1,
                1024,
                true
            ),
            Err(WebhookReceiverError::InvalidInput { .. })
        ));
        assert!(matches!(
            store.poll_events(" ", None, 1, 1024, false),
            Err(WebhookReceiverError::InvalidInput { .. })
        ));
        assert!(matches!(
            store.poll_events("unknown", None, 1, 1024, false),
            Err(WebhookReceiverError::EndpointNotFound { .. })
        ));
    }

    #[test]
    fn poll_cursors_survive_secret_rotation_but_expire_on_clear_and_restart() {
        let mut store = WebhookStore::new();
        let endpoint = store
            .create_endpoint("/poll".into(), "secret".into(), vec![])
            .unwrap();
        let initial = store
            .poll_events(&endpoint.endpoint_id, None, 1, 1024, false)
            .unwrap();
        store
            .rotate_endpoint_secret(&endpoint.endpoint_id, "rotated".into())
            .unwrap();
        let rotated = store
            .poll_events(
                &endpoint.endpoint_id,
                Some(&initial.next_cursor),
                1,
                1024,
                false,
            )
            .unwrap();
        assert_eq!(rotated.next_cursor, initial.next_cursor);
        let restarted = WebhookStore::new();
        assert!(matches!(
            restarted.poll_events(
                &endpoint.endpoint_id,
                Some(&initial.next_cursor),
                1,
                1024,
                false
            ),
            Err(WebhookReceiverError::ExpiredCursor)
        ));
        store.clear();
        assert!(matches!(
            store.poll_events(
                &endpoint.endpoint_id,
                Some(&initial.next_cursor),
                1,
                1024,
                false
            ),
            Err(WebhookReceiverError::ExpiredCursor)
        ));
        let replacement = store
            .create_endpoint("/poll".into(), "replacement".into(), vec![])
            .unwrap();
        assert!(matches!(
            store.poll_events(
                &replacement.endpoint_id,
                Some(&initial.next_cursor),
                1,
                1024,
                false
            ),
            Err(WebhookReceiverError::ExpiredCursor)
        ));
        let current = store
            .poll_events(&replacement.endpoint_id, None, 1, 1024, false)
            .unwrap();
        assert_ne!(current.next_cursor, initial.next_cursor);
        store.delete_endpoint(&replacement.endpoint_id).unwrap();
        assert!(matches!(
            store.poll_events(
                &replacement.endpoint_id,
                Some(&current.next_cursor),
                1,
                1024,
                false
            ),
            Err(WebhookReceiverError::EndpointNotFound { .. })
        ));
        let recreated = store
            .create_endpoint("/poll".into(), "replacement".into(), vec![])
            .unwrap();
        assert!(matches!(
            store.poll_events(
                &recreated.endpoint_id,
                Some(&current.next_cursor),
                1,
                1024,
                false
            ),
            Err(WebhookReceiverError::InvalidInput { .. })
        ));
    }

    #[test]
    fn poll_events_does_not_consume_deliveries_or_authenticated_replay_claims() {
        let mut store = WebhookStore::new();
        let endpoint = store
            .create_endpoint("/poll".into(), "secret".into(), vec![])
            .unwrap();
        let event = sized_event(&endpoint.endpoint_id, "original", 512);
        store
            .record_authenticated_event(event.clone(), [7; 32])
            .unwrap();
        for _ in 0..3 {
            let page = store
                .poll_events(&endpoint.endpoint_id, None, 1, 512, false)
                .unwrap();
            assert_eq!(page.events[0].1.event_id, "original");
            assert_eq!(page.next_sequence, 1);
        }
        assert!(matches!(
            store.record_authenticated_event(event.clone(), [8; 32]),
            Err(WebhookReceiverError::DuplicateEvent { .. })
        ));
        let mut alias = event;
        alias.event_id = "unsigned-alias".into();
        assert!(matches!(
            store.record_authenticated_event(alias, [7; 32]),
            Err(WebhookReceiverError::DuplicateEvent { .. })
        ));
        assert_eq!(store.total_event_count(), 1);
        assert_eq!(store.replay_event_count(), 1);
        assert_eq!(
            store.authenticated_deliveries[&endpoint.endpoint_id].len(),
            1
        );
        assert_eq!(store.next_event_sequence, 1);
    }

    #[test]
    fn cursor_authentication_key_is_redacted_from_store_debug() {
        let mut store = WebhookStore::new();
        store.cursor_identity.key = [83; 32];
        let debug = format!("{store:?}");
        assert!(debug.contains("CursorIdentity"));
        assert!(!debug.contains(&format!("{:?}", store.cursor_identity.key)));
        assert!(!debug.contains(&URL_SAFE_NO_PAD.encode(store.cursor_identity.key)));
    }

    #[test]
    fn get_recent_events_all() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/test".into(), "s".into(), vec![])
            .unwrap();
        for _ in 0..5 {
            let event = WebhookEvent::new(ep.endpoint_id.clone(), json!({}), true, None);
            store.record_event(event).unwrap();
        }
        let events = store
            .get_recent_events(Some(&ep.endpoint_id), None, None)
            .unwrap();
        assert_eq!(events.len(), 5);
    }

    #[test]
    fn get_recent_events_with_limit() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/test".into(), "s".into(), vec![])
            .unwrap();
        for _ in 0..10 {
            let event = WebhookEvent::new(ep.endpoint_id.clone(), json!({}), true, None);
            store.record_event(event).unwrap();
        }
        let events = store
            .get_recent_events(Some(&ep.endpoint_id), Some(3), None)
            .unwrap();
        assert_eq!(events.len(), 3);
    }

    #[test]
    fn get_recent_events_limit_capped_at_max() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/test".into(), "s".into(), vec![])
            .unwrap();
        for _ in 0..150 {
            let event = WebhookEvent::new(ep.endpoint_id.clone(), json!({}), true, None);
            store.record_event(event).unwrap();
        }
        let events = store
            .get_recent_events(Some(&ep.endpoint_id), Some(200), None)
            .unwrap();
        assert_eq!(events.len(), MAX_EVENTS_LIMIT);
    }

    #[test]
    fn get_recent_events_default_limit() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/test".into(), "s".into(), vec![])
            .unwrap();
        for _ in 0..100 {
            let event = WebhookEvent::new(ep.endpoint_id.clone(), json!({}), true, None);
            store.record_event(event).unwrap();
        }
        let events = store
            .get_recent_events(Some(&ep.endpoint_id), None, None)
            .unwrap();
        assert_eq!(events.len(), DEFAULT_EVENTS_LIMIT);
    }

    #[test]
    fn get_recent_events_across_endpoints() {
        let mut store = WebhookStore::new();
        let ep1 = store
            .create_endpoint("/a".into(), "s".into(), vec![])
            .unwrap();
        let ep2 = store
            .create_endpoint("/b".into(), "s".into(), vec![])
            .unwrap();
        store
            .record_event(WebhookEvent::new(ep1.endpoint_id, json!({}), true, None))
            .unwrap();
        store
            .record_event(WebhookEvent::new(ep2.endpoint_id, json!({}), true, None))
            .unwrap();

        // Without filter, gets events from all endpoints
        let events = store.get_recent_events(None, None, None).unwrap();
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn get_recent_events_filtered_by_endpoint() {
        let mut store = WebhookStore::new();
        let ep1 = store
            .create_endpoint("/a".into(), "s".into(), vec![])
            .unwrap();
        let ep2 = store
            .create_endpoint("/b".into(), "s".into(), vec![])
            .unwrap();
        for _ in 0..3 {
            store
                .record_event(WebhookEvent::new(
                    ep1.endpoint_id.clone(),
                    json!({}),
                    true,
                    None,
                ))
                .unwrap();
        }
        store
            .record_event(WebhookEvent::new(ep2.endpoint_id, json!({}), true, None))
            .unwrap();

        let events = store
            .get_recent_events(Some(&ep1.endpoint_id), None, None)
            .unwrap();
        assert_eq!(events.len(), 3);
    }

    #[test]
    fn get_recent_events_endpoint_not_found() {
        let store = WebhookStore::new();
        let result = store.get_recent_events(Some("ep_nope"), None, None);
        assert!(result.is_err());
    }

    #[test]
    fn get_recent_events_sorted_most_recent_first() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/test".into(), "s".into(), vec![])
            .unwrap();

        for _ in 0..5 {
            let event = WebhookEvent::new(ep.endpoint_id.clone(), json!({}), true, None);
            store.record_event(event).unwrap();
        }

        let events = store
            .get_recent_events(Some(&ep.endpoint_id), None, None)
            .unwrap();
        for i in 1..events.len() {
            assert!(events[i - 1].received_at >= events[i].received_at);
        }
    }

    #[test]
    fn get_recent_events_with_since_ts() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/test".into(), "s".into(), vec![])
            .unwrap();

        // Record an event "in the past"
        let mut old_event = WebhookEvent::new(ep.endpoint_id.clone(), json!({}), true, None);
        old_event.received_at = chrono::DateTime::parse_from_rfc3339("2020-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        store.record_event(old_event).unwrap();

        // Record a recent event
        let recent_event = WebhookEvent::new(ep.endpoint_id.clone(), json!({}), true, None);
        store.record_event(recent_event).unwrap();

        let since = chrono::DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let events = store
            .get_recent_events(Some(&ep.endpoint_id), None, Some(since))
            .unwrap();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn clear_removes_everything() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/test".into(), "s".into(), vec![])
            .unwrap();
        store
            .record_event(WebhookEvent::new(ep.endpoint_id, json!({}), true, None))
            .unwrap();
        store.clear();
        assert_eq!(store.endpoint_count(), 0);
        assert_eq!(store.total_event_count(), 0);
    }

    #[test]
    fn store_debug_format() {
        let store = WebhookStore::new();
        let dbg = format!("{store:?}");
        assert!(dbg.contains("WebhookStore"));
    }

    #[test]
    fn multiple_events_multiple_endpoints() {
        let mut store = WebhookStore::new();
        let ep1 = store
            .create_endpoint("/a".into(), "s1".into(), vec![])
            .unwrap();
        let ep2 = store
            .create_endpoint("/b".into(), "s2".into(), vec![])
            .unwrap();
        let ep3 = store
            .create_endpoint("/c".into(), "s3".into(), vec![])
            .unwrap();

        for ep_id in [&ep1.endpoint_id, &ep2.endpoint_id, &ep3.endpoint_id] {
            for _ in 0..5 {
                store
                    .record_event(WebhookEvent::new(ep_id.clone(), json!({}), true, None))
                    .unwrap();
            }
        }

        assert_eq!(store.endpoint_count(), 3);
        assert_eq!(store.total_event_count(), 15);
    }

    #[test]
    fn get_recent_events_empty_store() {
        let store = WebhookStore::new();
        let events = store.get_recent_events(None, None, None).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn get_recent_events_no_events_for_endpoint() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/test".into(), "s".into(), vec![])
            .unwrap();
        let events = store
            .get_recent_events(Some(&ep.endpoint_id), None, None)
            .unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn delete_then_recreate_same_path() {
        let mut store = WebhookStore::new();
        let ep1 = store
            .create_endpoint("/hooks/reuse".into(), "s".into(), vec![])
            .unwrap();
        store.delete_endpoint(&ep1.endpoint_id).unwrap();
        let ep2 = store
            .create_endpoint("/hooks/reuse".into(), "s".into(), vec![])
            .unwrap();
        assert_ne!(ep1.endpoint_id, ep2.endpoint_id);
    }

    #[test]
    fn constants_values() {
        assert_eq!(MAX_ENDPOINTS, 100);
        assert_eq!(MAX_EVENTS_PER_ENDPOINT, 1000);
        assert_eq!(DEFAULT_EVENTS_LIMIT, 50);
        assert_eq!(MAX_EVENTS_LIMIT, 100);
    }

    #[test]
    fn store_clear_then_create_again() {
        let mut store = WebhookStore::new();
        store
            .create_endpoint("/a".into(), "s".into(), vec![])
            .unwrap();
        store.clear();
        assert_eq!(store.endpoint_count(), 0);
        // Can create with same path after clear
        store
            .create_endpoint("/a".into(), "s".into(), vec![])
            .unwrap();
        assert_eq!(store.endpoint_count(), 1);
    }

    #[test]
    fn get_endpoint_returns_correct_data() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint(
                "/hooks/verify".into(),
                "secret123".into(),
                vec!["10.0.0.0/8".into()],
            )
            .unwrap();
        let found = store.get_endpoint(&ep.endpoint_id).unwrap();
        assert_eq!(found.signing_secret, "secret123");
        assert_eq!(found.allowed_sources.len(), 1);
        assert_eq!(found.allowed_sources[0], "10.0.0.0/8");
    }

    #[test]
    fn total_event_count_across_endpoints() {
        let mut store = WebhookStore::new();
        let ep1 = store
            .create_endpoint("/a".into(), "s".into(), vec![])
            .unwrap();
        let ep2 = store
            .create_endpoint("/b".into(), "s".into(), vec![])
            .unwrap();

        for _ in 0..3 {
            store
                .record_event(WebhookEvent::new(
                    ep1.endpoint_id.clone(),
                    json!({}),
                    true,
                    None,
                ))
                .unwrap();
        }
        for _ in 0..7 {
            store
                .record_event(WebhookEvent::new(
                    ep2.endpoint_id.clone(),
                    json!({}),
                    true,
                    None,
                ))
                .unwrap();
        }

        assert_eq!(store.total_event_count(), 10);
    }

    #[test]
    fn delete_endpoint_only_removes_that_endpoint() {
        let mut store = WebhookStore::new();
        let ep1 = store
            .create_endpoint("/a".into(), "s".into(), vec![])
            .unwrap();
        let ep2 = store
            .create_endpoint("/b".into(), "s".into(), vec![])
            .unwrap();

        store
            .record_event(WebhookEvent::new(
                ep1.endpoint_id.clone(),
                json!({}),
                true,
                None,
            ))
            .unwrap();
        let ep2_id = ep2.endpoint_id;
        store
            .record_event(WebhookEvent::new(ep2_id, json!({}), true, None))
            .unwrap();

        store.delete_endpoint(&ep1.endpoint_id).unwrap();
        assert_eq!(store.endpoint_count(), 1);
        assert_eq!(store.total_event_count(), 1);
    }

    #[test]
    fn list_endpoints_order_independent() {
        let mut store = WebhookStore::new();
        store
            .create_endpoint("/z".into(), "s".into(), vec![])
            .unwrap();
        store
            .create_endpoint("/a".into(), "s".into(), vec![])
            .unwrap();
        store
            .create_endpoint("/m".into(), "s".into(), vec![])
            .unwrap();
        let list = store.list_endpoints();
        assert_eq!(list.len(), 3);
        let paths: Vec<&str> = list.iter().map(|s| s.path.as_str()).collect();
        assert!(paths.contains(&"/z"));
        assert!(paths.contains(&"/a"));
        assert!(paths.contains(&"/m"));
    }

    #[test]
    fn get_recent_events_limit_of_zero() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/test".into(), "s".into(), vec![])
            .unwrap();
        store
            .record_event(WebhookEvent::new(
                ep.endpoint_id.clone(),
                json!({}),
                true,
                None,
            ))
            .unwrap();
        let events = store
            .get_recent_events(Some(&ep.endpoint_id), Some(0), None)
            .unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn get_recent_events_limit_of_one() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/test".into(), "s".into(), vec![])
            .unwrap();
        for _ in 0..5 {
            store
                .record_event(WebhookEvent::new(
                    ep.endpoint_id.clone(),
                    json!({}),
                    true,
                    None,
                ))
                .unwrap();
        }
        let events = store
            .get_recent_events(Some(&ep.endpoint_id), Some(1), None)
            .unwrap();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn record_event_with_source_ip() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/test".into(), "s".into(), vec![])
            .unwrap();
        let event = WebhookEvent::new(
            ep.endpoint_id.clone(),
            json!({}),
            true,
            Some("192.168.1.100".into()),
        );
        store.record_event(event).unwrap();
        let events = store
            .get_recent_events(Some(&ep.endpoint_id), None, None)
            .unwrap();
        assert_eq!(events[0].source_ip, Some("192.168.1.100".into()));
    }

    #[test]
    fn record_event_with_invalid_signature() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/test".into(), "s".into(), vec![])
            .unwrap();
        let event = WebhookEvent::new(ep.endpoint_id.clone(), json!({}), false, None);
        store.record_event(event).unwrap();
        let events = store
            .get_recent_events(Some(&ep.endpoint_id), None, None)
            .unwrap();
        assert!(!events[0].signature_valid);
    }

    #[test]
    fn endpoint_count_after_multiple_creates_and_deletes() {
        let mut store = WebhookStore::new();
        let ep1 = store
            .create_endpoint("/a".into(), "s".into(), vec![])
            .unwrap();
        let ep2 = store
            .create_endpoint("/b".into(), "s".into(), vec![])
            .unwrap();
        let _ep3 = store
            .create_endpoint("/c".into(), "s".into(), vec![])
            .unwrap();
        assert_eq!(store.endpoint_count(), 3);
        store.delete_endpoint(&ep1.endpoint_id).unwrap();
        assert_eq!(store.endpoint_count(), 2);
        store.delete_endpoint(&ep2.endpoint_id).unwrap();
        assert_eq!(store.endpoint_count(), 1);
    }

    #[test]
    fn get_recent_events_since_ts_filters_old() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/test".into(), "s".into(), vec![])
            .unwrap();

        // Old event
        let mut old = WebhookEvent::new(ep.endpoint_id.clone(), json!({"old": true}), true, None);
        old.received_at = chrono::DateTime::parse_from_rfc3339("2020-06-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        store.record_event(old).unwrap();

        // Recent events
        for _ in 0..3 {
            store
                .record_event(WebhookEvent::new(
                    ep.endpoint_id.clone(),
                    json!({}),
                    true,
                    None,
                ))
                .unwrap();
        }

        let since = chrono::DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let events = store
            .get_recent_events(Some(&ep.endpoint_id), None, Some(since))
            .unwrap();
        assert_eq!(events.len(), 3);
    }

    #[test]
    fn get_recent_events_since_ts_all_old() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/test".into(), "s".into(), vec![])
            .unwrap();

        let mut old = WebhookEvent::new(ep.endpoint_id.clone(), json!({}), true, None);
        old.received_at = chrono::DateTime::parse_from_rfc3339("2020-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        store.record_event(old).unwrap();

        let since = chrono::DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let events = store
            .get_recent_events(Some(&ep.endpoint_id), None, Some(since))
            .unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn double_delete_returns_error() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/test".into(), "s".into(), vec![])
            .unwrap();
        store.delete_endpoint(&ep.endpoint_id).unwrap();
        let result = store.delete_endpoint(&ep.endpoint_id);
        assert!(result.is_err());
    }
}
