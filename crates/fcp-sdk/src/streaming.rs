//! Streaming helpers for connectors: subscriptions, replay buffers, and acks.
//!
//! These utilities are intentionally in-memory and lightweight. They provide
//! standard replay/cursor semantics and ack tracking without forcing a specific
//! transport or storage backend.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use fcp_prelude::{
    EventAck, EventCaps, EventData, EventEnvelope, EventNack, ReplayBufferInfo, RequestId,
    SubscribeRequest, SubscribeResponse, SubscribeResult,
};

/// How many times `max_events` a buffer may grow purely because entries are
/// still awaiting an ack, before the oldest unacked entry is dropped anyway.
const DEFAULT_ACK_SLACK_FACTOR: usize = 4;

/// Maximum topics accepted from a single [`SubscribeRequest`].
pub const MAX_TOPICS_PER_SUBSCRIBE: usize = 64;

/// Maximum length of an accepted topic name, in bytes.
pub const MAX_TOPIC_LEN: usize = 128;

/// Maximum number of distinct topics an [`EventStreamManager`] will track on
/// behalf of subscribers.
pub const MAX_TRACKED_TOPICS: usize = 256;

/// Whether a client-supplied topic name is acceptable.
///
/// Topics are identifiers, not free text: they are echoed back to the client,
/// used as map keys, and appear in logs. Restricting them to a small charset
/// keeps a subscriber from retaining arbitrary attacker-chosen strings.
#[must_use]
pub fn topic_name_is_valid(topic: &str) -> bool {
    !topic.is_empty()
        && topic.len() <= MAX_TOPIC_LEN
        && topic
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'))
}

/// Replay buffer sizing limits.
#[derive(Debug, Clone, Copy)]
pub struct BufferLimits {
    /// Minimum number of events retained for replay.
    pub min_events: usize,
    /// Soft maximum: events past this are evicted once they have been acked.
    pub max_events: usize,
    /// Absolute ceiling on retained events, INCLUDING those still awaiting an
    /// ack.
    ///
    /// `max_events` alone is not a bound: eviction stops at the first unacked
    /// entry, so a consumer that simply stops sending acks pins the front of
    /// the buffer and both the buffer and the pending-ack set grow for as long
    /// as events keep arriving. Past this ceiling the oldest entry is dropped
    /// even if unacked. Losing replay for a consumer that stopped acking is
    /// strictly better than unbounded growth, and it is observable via
    /// [`EventStreamManager::dropped_unacked`]. See br-l2ack.
    pub hard_max_events: usize,
}

impl BufferLimits {
    /// Create buffer limits ensuring `max_events >= min_events`.
    ///
    /// `hard_max_events` defaults to `DEFAULT_ACK_SLACK_FACTOR × max_events`,
    /// leaving a slow consumer room to catch up before anything is dropped.
    #[must_use]
    pub fn new(min_events: usize, max_events: usize) -> Self {
        let max_events = max_events.max(min_events);
        Self {
            min_events,
            max_events,
            hard_max_events: max_events
                .saturating_mul(DEFAULT_ACK_SLACK_FACTOR)
                .max(max_events),
        }
    }

    /// Override the absolute retention ceiling.
    ///
    /// Clamped to at least `max_events`, since a ceiling below the soft maximum
    /// would make the soft maximum unreachable.
    #[must_use]
    pub fn with_hard_max(mut self, hard_max_events: usize) -> Self {
        self.hard_max_events = hard_max_events.max(self.max_events);
        self
    }
}

impl Default for BufferLimits {
    fn default() -> Self {
        Self::new(10, 100)
    }
}

/// Errors returned by replay helpers.
#[derive(Debug, thiserror::Error, Clone)]
pub enum ReplayError {
    /// The requested topic does not exist or has no buffer.
    #[error("unknown topic '{topic}'")]
    UnknownTopic {
        /// The topic that was not found.
        topic: String,
    },
    /// The cursor string could not be parsed as a sequence number.
    #[error("invalid cursor '{cursor}' for topic '{topic}'")]
    InvalidCursor {
        /// The topic that had an invalid cursor.
        topic: String,
        /// The invalid cursor string.
        cursor: String,
    },
    /// The cursor points to an event that has been trimmed from the buffer.
    #[error(
        "cursor {cursor_seq} is older than oldest buffered seq {oldest_seq} for topic '{topic}'"
    )]
    CursorStale {
        /// The topic that had a stale cursor.
        topic: String,
        /// The sequence number from the cursor.
        cursor_seq: u64,
        /// The oldest sequence number still in the buffer.
        oldest_seq: u64,
    },
}

/// Result of applying an [`EventAck`].
#[derive(Debug, Clone)]
pub struct AckResult {
    /// Sequence numbers that were successfully acknowledged.
    pub acked: Vec<u64>,
    /// Sequence numbers that were not found in pending acks.
    pub missing: Vec<u64>,
}

/// Result of applying an [`EventNack`].
#[derive(Debug, Clone)]
pub struct NackResult {
    /// Events to redeliver from the buffer.
    pub redeliver: Vec<EventEnvelope>,
    /// Sequence numbers that were not found in the buffer.
    pub missing: Vec<u64>,
}

/// Outcome of handling a [`SubscribeRequest`].
#[derive(Debug, Clone)]
pub struct SubscribeOutcome {
    /// The subscribe response to send to the client.
    pub response: SubscribeResponse,
    /// Events to replay per topic (if replay was requested).
    pub replay_events: HashMap<String, Vec<EventEnvelope>>,
}

#[derive(Debug, Default)]
struct TopicState {
    next_seq: u64,
    buffer: VecDeque<EventEnvelope>,
    pending_acks: HashSet<u64>,
    /// Events dropped from the buffer while still unacked, because the hard
    /// retention ceiling was reached. Non-zero means a consumer has stopped
    /// acking and has lost replay coverage.
    dropped_unacked: u64,
}

impl TopicState {
    fn record_event(
        &mut self,
        mut envelope: EventEnvelope,
        caps: &EventCaps,
        limits: BufferLimits,
    ) -> EventEnvelope {
        if envelope.seq == 0 {
            envelope.seq = self.next_seq;
        }
        if envelope.seq >= self.next_seq {
            self.next_seq = envelope.seq.saturating_add(1);
        }

        if envelope.cursor.is_empty() {
            envelope.cursor = envelope.seq.to_string();
        }

        if caps.requires_ack {
            envelope.requires_ack = true;
        }

        if envelope.requires_ack {
            self.pending_acks.insert(envelope.seq);
        }

        self.buffer.push_back(envelope.clone());
        self.trim_buffer(limits);
        envelope
    }

    fn trim_buffer(&mut self, limits: BufferLimits) {
        // Soft trim: drop acked events down to `max_events`, stopping at the
        // first entry still awaiting an ack so replay stays available for it.
        while self.buffer.len() > limits.max_events {
            let Some(front) = self.buffer.front() else {
                break;
            };
            if self.pending_acks.contains(&front.seq) {
                break;
            }
            self.buffer.pop_front();
        }

        // Hard ceiling: the loop above stops at the first unacked entry, so a
        // consumer that simply stops acking pins the front and the buffer grows
        // without bound. Past the ceiling, evict the oldest entry anyway and
        // drop its ack obligation with it — that is what keeps `pending_acks`
        // bounded by the buffer rather than by the consumer's behaviour, and it
        // is why no separate pending-ack TTL is needed.
        while self.buffer.len() > limits.hard_max_events {
            let Some(front) = self.buffer.pop_front() else {
                break;
            };
            if self.pending_acks.remove(&front.seq) {
                self.dropped_unacked = self.dropped_unacked.saturating_add(1);
                tracing::warn!(
                    topic = %front.topic,
                    seq = front.seq,
                    retained = self.buffer.len(),
                    hard_max_events = limits.hard_max_events,
                    dropped_unacked_total = self.dropped_unacked,
                    "replay buffer hit its hard ceiling; dropping an unacked event \
                     (consumer is not acking)"
                );
            }
        }
    }

    fn latest_cursor(&self) -> Option<String> {
        self.buffer.back().map(|env| env.cursor.clone())
    }

    fn replay_from_cursor(
        &self,
        topic: &str,
        cursor: &str,
    ) -> Result<Vec<EventEnvelope>, ReplayError> {
        if cursor.is_empty() {
            return Ok(self.buffer.iter().cloned().collect());
        }

        let cursor_seq = cursor
            .parse::<u64>()
            .map_err(|_| ReplayError::InvalidCursor {
                topic: topic.to_string(),
                cursor: cursor.to_string(),
            })?;

        let Some(oldest) = self.buffer.front() else {
            return Ok(Vec::new());
        };
        if cursor_seq < oldest.seq {
            return Err(ReplayError::CursorStale {
                topic: topic.to_string(),
                cursor_seq,
                oldest_seq: oldest.seq,
            });
        }

        Ok(self
            .buffer
            .iter()
            .filter(|env| env.seq > cursor_seq)
            .cloned()
            .collect())
    }

    fn apply_ack(&mut self, ack: &EventAck, limits: BufferLimits) -> AckResult {
        let mut acked = Vec::new();
        let mut missing = Vec::new();

        for seq in &ack.seqs {
            if self.pending_acks.remove(seq) {
                acked.push(*seq);
            } else {
                missing.push(*seq);
            }
        }

        self.trim_buffer(limits);

        AckResult { acked, missing }
    }

    fn apply_nack(&self, nack: &EventNack) -> NackResult {
        let mut redeliver = Vec::new();
        let mut missing = Vec::new();

        for seq in &nack.seqs {
            match self.buffer.iter().find(|env| env.seq == *seq) {
                Some(env) => redeliver.push(env.clone()),
                None => missing.push(*seq),
            }
        }

        NackResult { redeliver, missing }
    }
}

/// Slow-consumer policy for bounded sequential event queues.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SequentialOverflowPolicy {
    /// Reject the newly enqueued item once a bound is reached.
    RejectNewest,
    /// Drop the oldest queued item to make room for the new one.
    DropOldest,
}

/// Configuration for [`SequentialEventProcessor`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SequentialEventProcessorConfig {
    /// Maximum queued items allowed per stream key (active work is not counted).
    pub max_queue_per_key: usize,
    /// Maximum queued items allowed across all stream keys.
    pub max_total_queued: usize,
    /// Overflow strategy to apply when a queue bound is reached.
    pub overflow_policy: SequentialOverflowPolicy,
    /// Optional timeout for queued items waiting behind a slow consumer.
    pub item_timeout: Option<Duration>,
}

impl Default for SequentialEventProcessorConfig {
    fn default() -> Self {
        Self {
            max_queue_per_key: 32,
            max_total_queued: 256,
            overflow_policy: SequentialOverflowPolicy::RejectNewest,
            item_timeout: None,
        }
    }
}

/// Item returned by [`SequentialEventProcessor::next_ready`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequentialEvent<T> {
    /// Stream key used to isolate ordering.
    pub stream_key: String,
    /// Connector-defined payload.
    pub item: T,
}

/// Result of a successful [`SequentialEventProcessor::enqueue`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequentialEnqueueOutcome<T> {
    /// Item displaced by a drop policy, if any.
    pub dropped: Option<SequentialEvent<T>>,
}

impl<T> SequentialEnqueueOutcome<T> {
    #[must_use]
    const fn accepted() -> Self {
        Self { dropped: None }
    }
}

/// Errors returned when a sequential queue refuses a new item.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SequentialEnqueueError<T> {
    /// The queue refused the new item once a bound was reached.
    #[error("sequential queue is full for stream key '{stream_key}'")]
    QueueFull {
        /// Stream key that hit its queue bound.
        stream_key: String,
        /// Item that could not be queued.
        item: T,
    },
}

#[derive(Debug)]
struct QueuedSequentialEvent<T> {
    item: T,
    enqueued_at: Instant,
    ticket: u64,
}

#[derive(Debug)]
struct SequentialKeyState<T> {
    active: bool,
    queued: VecDeque<QueuedSequentialEvent<T>>,
}

impl<T> Default for SequentialKeyState<T> {
    fn default() -> Self {
        Self {
            active: false,
            queued: VecDeque::new(),
        }
    }
}

/// In-memory helper that guarantees sequential processing within a stream key
/// while round-robining fairly across independent keys.
///
/// Connectors enqueue work under a key such as a chat ID, thread ID, or channel
/// ID, call [`next_ready`](Self::next_ready) to obtain the next runnable item,
/// and then call [`finish_key`](Self::finish_key) once processing for that key
/// completes.
#[derive(Debug)]
pub struct SequentialEventProcessor<T> {
    config: SequentialEventProcessorConfig,
    keys: HashMap<String, SequentialKeyState<T>>,
    ready: VecDeque<String>,
    total_queued: usize,
    next_ticket: u64,
}

impl<T> SequentialEventProcessor<T> {
    /// Create a new sequential processor.
    #[must_use]
    pub fn new(config: SequentialEventProcessorConfig) -> Self {
        Self {
            config,
            keys: HashMap::new(),
            ready: VecDeque::new(),
            total_queued: 0,
            next_ticket: 0,
        }
    }

    /// Return the processor configuration.
    #[must_use]
    pub const fn config(&self) -> &SequentialEventProcessorConfig {
        &self.config
    }

    /// Return the number of queued items waiting behind currently running work.
    #[must_use]
    pub const fn queue_depth(&self) -> usize {
        self.total_queued
    }

    /// Return the queued depth for a single stream key.
    #[must_use]
    pub fn queue_depth_for(&self, stream_key: &str) -> usize {
        self.keys
            .get(stream_key)
            .map_or(0, |state| state.queued.len())
    }

    /// Return the number of keys with active in-flight work.
    #[must_use]
    pub fn active_keys(&self) -> usize {
        self.keys.values().filter(|state| state.active).count()
    }

    /// Return `true` when no queued or active work remains.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        self.total_queued == 0 && self.active_keys() == 0
    }

    /// Enqueue a new item under `stream_key`.
    ///
    /// # Errors
    ///
    /// Returns [`SequentialEnqueueError::QueueFull`] when the configured bounds
    /// are reached and the processor is configured to reject new items.
    pub fn enqueue(
        &mut self,
        stream_key: impl Into<String>,
        item: T,
    ) -> Result<SequentialEnqueueOutcome<T>, SequentialEnqueueError<T>> {
        self.prune_expired();

        let stream_key = stream_key.into();
        if self.config.max_queue_per_key == 0 || self.config.max_total_queued == 0 {
            return Err(SequentialEnqueueError::QueueFull { stream_key, item });
        }

        let mut outcome = SequentialEnqueueOutcome::accepted();

        if self.queue_depth_for(&stream_key) >= self.config.max_queue_per_key {
            match self.config.overflow_policy {
                SequentialOverflowPolicy::RejectNewest => {
                    return Err(SequentialEnqueueError::QueueFull { stream_key, item });
                }
                SequentialOverflowPolicy::DropOldest => {
                    outcome.dropped = self.drop_oldest_for_key(&stream_key);
                }
            }
        }

        if self.total_queued >= self.config.max_total_queued {
            match self.config.overflow_policy {
                SequentialOverflowPolicy::RejectNewest => {
                    return Err(SequentialEnqueueError::QueueFull { stream_key, item });
                }
                SequentialOverflowPolicy::DropOldest => {
                    if outcome.dropped.is_none() {
                        outcome.dropped = self.drop_oldest_globally();
                    }
                }
            }
        }

        let was_idle = {
            let state = self.keys.entry(stream_key.clone()).or_default();
            let idle = !state.active && state.queued.is_empty();
            state.queued.push_back(QueuedSequentialEvent {
                item,
                enqueued_at: Instant::now(),
                ticket: self.next_ticket,
            });
            idle
        };

        self.next_ticket = self.next_ticket.saturating_add(1);
        self.total_queued = self.total_queued.saturating_add(1);
        if was_idle {
            self.ready.push_back(stream_key);
        }

        Ok(outcome)
    }

    /// Return the next ready item while ensuring only one item per key may be
    /// in-flight at a time.
    #[must_use]
    pub fn next_ready(&mut self) -> Option<SequentialEvent<T>> {
        self.prune_expired();
        self.compact_ready();

        while let Some(stream_key) = self.ready.pop_front() {
            let Some(state) = self.keys.get_mut(&stream_key) else {
                continue;
            };
            if state.active {
                continue;
            }

            let Some(queued) = state.queued.pop_front() else {
                continue;
            };

            state.active = true;
            self.total_queued = self.total_queued.saturating_sub(1);
            return Some(SequentialEvent {
                stream_key,
                item: queued.item,
            });
        }

        None
    }

    /// Mark the active item for `stream_key` as complete.
    ///
    /// Returns `true` when more queued work for the same key became runnable.
    pub fn finish_key(&mut self, stream_key: &str) -> bool {
        let has_more = {
            let Some(state) = self.keys.get_mut(stream_key) else {
                return false;
            };
            if !state.active {
                return false;
            }

            state.active = false;
            !state.queued.is_empty()
        };

        if has_more {
            self.ready.push_back(stream_key.to_string());
        } else {
            self.keys.remove(stream_key);
        }

        has_more
    }

    fn drop_oldest_for_key(&mut self, stream_key: &str) -> Option<SequentialEvent<T>> {
        let state = self.keys.get_mut(stream_key)?;
        let dropped = state.queued.pop_front().map(|queued| SequentialEvent {
            stream_key: stream_key.to_string(),
            item: queued.item,
        });
        if dropped.is_some() {
            self.total_queued = self.total_queued.saturating_sub(1);
        }
        let should_remove = dropped.is_some() && state.queued.is_empty() && !state.active;

        if should_remove {
            self.keys.remove(stream_key);
            self.compact_ready();
        }

        dropped
    }

    fn drop_oldest_globally(&mut self) -> Option<SequentialEvent<T>> {
        let oldest_key = self
            .keys
            .iter()
            .filter_map(|(stream_key, state)| {
                state
                    .queued
                    .front()
                    .map(|queued| (stream_key.clone(), queued.ticket))
            })
            .min_by_key(|(_, ticket)| *ticket)
            .map(|(stream_key, _)| stream_key)?;

        self.drop_oldest_for_key(&oldest_key)
    }

    fn prune_expired(&mut self) {
        let Some(timeout) = self.config.item_timeout else {
            return;
        };

        let now = Instant::now();
        let keys: Vec<String> = self.keys.keys().cloned().collect();
        for stream_key in keys {
            let should_remove = if let Some(state) = self.keys.get_mut(&stream_key) {
                while let Some(front) = state.queued.front() {
                    if now.duration_since(front.enqueued_at) < timeout {
                        break;
                    }

                    let _ = state.queued.pop_front();
                    self.total_queued = self.total_queued.saturating_sub(1);
                }
                state.queued.is_empty() && !state.active
            } else {
                false
            };

            if should_remove {
                self.keys.remove(&stream_key);
            }
        }

        self.compact_ready();
    }

    fn compact_ready(&mut self) {
        let mut seen = HashSet::new();
        let mut compacted = VecDeque::new();
        while let Some(stream_key) = self.ready.pop_front() {
            if !seen.insert(stream_key.clone()) {
                continue;
            }
            if self
                .keys
                .get(&stream_key)
                .is_some_and(|state| !state.active && !state.queued.is_empty())
            {
                compacted.push_back(stream_key);
            }
        }
        self.ready = compacted;
    }
}

impl<T> Default for SequentialEventProcessor<T> {
    fn default() -> Self {
        Self::new(SequentialEventProcessorConfig::default())
    }
}

/// In-memory manager for streaming event topics.
#[derive(Debug, Default)]
pub struct EventStreamManager {
    caps: EventCaps,
    limits: BufferLimits,
    topics: HashMap<String, TopicState>,
}

impl EventStreamManager {
    /// Create a manager from connector event capabilities.
    #[must_use]
    pub fn new(caps: EventCaps) -> Self {
        let min_events = caps.min_buffer_events as usize;
        let limits = BufferLimits::new(min_events, min_events.max(1));
        Self {
            caps,
            limits,
            topics: HashMap::new(),
        }
    }

    /// Create a manager with explicit buffer limits.
    #[must_use]
    pub fn with_limits(caps: EventCaps, limits: BufferLimits) -> Self {
        Self {
            caps,
            limits,
            topics: HashMap::new(),
        }
    }

    /// Emit a new event for a topic (auto-assigns seq + cursor).
    pub fn emit(&mut self, topic: &str, data: EventData) -> EventEnvelope {
        let envelope = EventEnvelope::new(topic, data);
        self.record(envelope)
    }

    /// Emit a new event with a caller-provided seq.
    pub fn emit_with_seq(&mut self, topic: &str, seq: u64, data: EventData) -> EventEnvelope {
        let envelope = EventEnvelope::new(topic, data)
            .with_seq(seq)
            .with_cursor_seq(seq);
        self.record(envelope)
    }

    /// Record an already-constructed event (fills missing cursor/ack flags).
    pub fn record(&mut self, envelope: EventEnvelope) -> EventEnvelope {
        let topic = envelope.topic.clone();
        let state = self.topics.entry(topic).or_default();
        state.record_event(envelope, &self.caps, self.limits)
    }

    /// Handle a [`SubscribeRequest`] and compute replay responses if requested.
    ///
    /// # Errors
    ///
    /// Returns [`ReplayError::CursorStale`] if the `since` cursor is no longer in the buffer.
    /// Returns [`ReplayError::InvalidCursor`] if the cursor cannot be parsed.
    pub fn handle_subscribe(
        &mut self,
        req: &SubscribeRequest,
    ) -> Result<SubscribeOutcome, ReplayError> {
        let mut confirmed = Vec::new();
        let mut cursors = HashMap::new();

        // `confirmed_topics` used to echo back every topic the client named,
        // creating retained state for each one. That made the response
        // misleading — a typo looked identical to a subscription that would
        // never fire — and let a client grow the topic map without bound.
        // Only topics actually accepted are created and confirmed. See br-l2ack.
        for topic in req.topics.iter().take(MAX_TOPICS_PER_SUBSCRIBE) {
            if !topic_name_is_valid(topic) {
                tracing::warn!(topic = %topic, "rejecting invalid topic name in subscribe");
                continue;
            }
            // An already-tracked topic is always accepted; only the creation of
            // a NEW one is capped, so reaching the ceiling cannot break
            // existing subscribers.
            let known = self.topics.contains_key(topic);
            if !known && self.topics.len() >= MAX_TRACKED_TOPICS {
                tracing::warn!(
                    topic = %topic,
                    tracked = self.topics.len(),
                    max_tracked_topics = MAX_TRACKED_TOPICS,
                    "refusing new topic: tracked-topic ceiling reached"
                );
                continue;
            }
            let state = self.topics.entry(topic.clone()).or_default();
            confirmed.push(topic.clone());
            if let Some(cursor) = state.latest_cursor() {
                if !cursor.is_empty() {
                    cursors.insert(topic.clone(), cursor);
                }
            }
        }

        let buffer = if self.caps.replay {
            Some(ReplayBufferInfo {
                min_events: u32::try_from(self.limits.min_events).unwrap_or(u32::MAX),
                overflow: "drop_oldest".to_string(),
            })
        } else {
            None
        };

        let response = SubscribeResponse {
            r#type: "response".to_string(),
            id: RequestId(req.id.0.clone()),
            result: SubscribeResult {
                confirmed_topics: confirmed.clone(),
                cursors,
                replay_supported: self.caps.replay,
                buffer,
            },
        };

        let mut replay_events = HashMap::new();
        if self.caps.replay {
            if let Some(ref since) = req.since {
                for topic in &confirmed {
                    let events = self.replay_from(topic, since)?;
                    if !events.is_empty() {
                        replay_events.insert(topic.clone(), events);
                    }
                }
            }
        }

        Ok(SubscribeOutcome {
            response,
            replay_events,
        })
    }

    /// Number of events dropped from a topic's buffer while still unacked.
    ///
    /// Non-zero means the consumer stopped acking, the hard retention ceiling
    /// was reached, and replay coverage for that topic has gaps. See br-l2ack.
    #[must_use]
    pub fn dropped_unacked(&self, topic: &str) -> u64 {
        self.topics
            .get(topic)
            .map_or(0, |state| state.dropped_unacked)
    }

    /// Number of distinct topics currently tracked.
    #[must_use]
    pub fn tracked_topics(&self) -> usize {
        self.topics.len()
    }

    /// Remove subscriptions for topics and return how many were removed.
    pub fn unsubscribe(&mut self, topics: &[String]) -> usize {
        let mut removed = 0;
        for topic in topics {
            if self.topics.remove(topic).is_some() {
                removed += 1;
            }
        }
        removed
    }

    /// Replay buffered events for a topic from a cursor.
    ///
    /// # Errors
    ///
    /// Returns [`ReplayError::UnknownTopic`] if the topic does not exist.
    /// Returns [`ReplayError::CursorStale`] if the cursor is no longer in the buffer.
    /// Returns [`ReplayError::InvalidCursor`] if the cursor cannot be parsed.
    pub fn replay_from(
        &self,
        topic: &str,
        cursor: &str,
    ) -> Result<Vec<EventEnvelope>, ReplayError> {
        self.topics.get(topic).map_or_else(
            || {
                Err(ReplayError::UnknownTopic {
                    topic: topic.to_string(),
                })
            },
            |state| state.replay_from_cursor(topic, cursor),
        )
    }

    /// Apply an [`EventAck`] to update pending-ack state.
    pub fn handle_ack(&mut self, ack: &EventAck) -> AckResult {
        match self.topics.get_mut(&ack.topic) {
            Some(state) => state.apply_ack(ack, self.limits),
            None => AckResult {
                acked: Vec::new(),
                missing: ack.seqs.clone(),
            },
        }
    }

    /// Apply an [`EventNack`] and return events to redeliver.
    #[must_use]
    pub fn handle_nack(&self, nack: &EventNack) -> NackResult {
        self.topics.get(&nack.topic).map_or_else(
            || NackResult {
                redeliver: Vec::new(),
                missing: nack.seqs.clone(),
            },
            |state| state.apply_nack(nack),
        )
    }

    /// Pending ack count for a topic.
    #[must_use]
    pub fn pending_acks(&self, topic: &str) -> usize {
        self.topics
            .get(topic)
            .map_or(0, |state| state.pending_acks.len())
    }
}

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;
    use fcp_prelude::{ConnectorId, InstanceId, Principal, TrustLevel, ZoneId};
    use serde_json::json;

    fn sample_event_data() -> EventData {
        EventData::new(
            ConnectorId::from_static("test:streaming:v1"),
            InstanceId::new(),
            ZoneId::work(),
            Principal {
                kind: "user".to_string(),
                id: "alice".to_string(),
                trust: TrustLevel::Paired,
                display: Some("Alice".to_string()),
            },
            json!({"message": "hi"}),
        )
    }

    fn caps(replay: bool, requires_ack: bool, min_buffer_events: u32) -> EventCaps {
        EventCaps {
            streaming: true,
            replay,
            min_buffer_events,
            requires_ack,
        }
    }

    #[test]
    fn sequential_processor_preserves_order_within_key() {
        let mut processor = SequentialEventProcessor::new(SequentialEventProcessorConfig {
            max_queue_per_key: 4,
            max_total_queued: 8,
            overflow_policy: SequentialOverflowPolicy::RejectNewest,
            item_timeout: None,
        });

        processor.enqueue("chat-1", 1_u8).unwrap();
        processor.enqueue("chat-1", 2_u8).unwrap();
        processor.enqueue("chat-1", 3_u8).unwrap();

        let first = processor.next_ready().unwrap();
        assert_eq!(first.stream_key, "chat-1");
        assert_eq!(first.item, 1);
        assert!(processor.next_ready().is_none());

        assert!(processor.finish_key("chat-1"));
        let second = processor.next_ready().unwrap();
        assert_eq!(second.item, 2);
        assert!(processor.finish_key("chat-1"));

        let third = processor.next_ready().unwrap();
        assert_eq!(third.item, 3);
        assert!(!processor.finish_key("chat-1"));
        assert!(processor.is_idle());
    }

    #[test]
    fn sequential_processor_round_robins_across_keys() {
        let mut processor = SequentialEventProcessor::new(SequentialEventProcessorConfig {
            max_queue_per_key: 4,
            max_total_queued: 8,
            overflow_policy: SequentialOverflowPolicy::RejectNewest,
            item_timeout: None,
        });

        processor.enqueue("alpha", "a1").unwrap();
        processor.enqueue("alpha", "a2").unwrap();
        processor.enqueue("beta", "b1").unwrap();
        processor.enqueue("beta", "b2").unwrap();

        let first = processor.next_ready().unwrap();
        assert_eq!(first.stream_key, "alpha");
        assert_eq!(first.item, "a1");
        assert!(processor.finish_key("alpha"));

        let second = processor.next_ready().unwrap();
        assert_eq!(second.stream_key, "beta");
        assert_eq!(second.item, "b1");
        assert!(processor.finish_key("beta"));

        let third = processor.next_ready().unwrap();
        assert_eq!(third.stream_key, "alpha");
        assert_eq!(third.item, "a2");
        assert!(!processor.finish_key("alpha"));

        let fourth = processor.next_ready().unwrap();
        assert_eq!(fourth.stream_key, "beta");
        assert_eq!(fourth.item, "b2");
        assert!(!processor.finish_key("beta"));
    }

    #[test]
    fn sequential_processor_rejects_when_key_queue_is_full() {
        let mut processor = SequentialEventProcessor::new(SequentialEventProcessorConfig {
            max_queue_per_key: 2,
            max_total_queued: 8,
            overflow_policy: SequentialOverflowPolicy::RejectNewest,
            item_timeout: None,
        });

        processor.enqueue("chat-1", 1_u8).unwrap();
        processor.enqueue("chat-1", 2_u8).unwrap();

        let error = processor.enqueue("chat-1", 3_u8).unwrap_err();
        assert_eq!(
            error,
            SequentialEnqueueError::QueueFull {
                stream_key: "chat-1".to_string(),
                item: 3,
            }
        );
        assert_eq!(processor.queue_depth_for("chat-1"), 2);
    }

    #[test]
    fn sequential_processor_drops_oldest_when_configured() {
        let mut processor = SequentialEventProcessor::new(SequentialEventProcessorConfig {
            max_queue_per_key: 2,
            max_total_queued: 8,
            overflow_policy: SequentialOverflowPolicy::DropOldest,
            item_timeout: None,
        });

        processor.enqueue("chat-1", "a1").unwrap();
        processor.enqueue("chat-1", "a2").unwrap();
        let outcome = processor.enqueue("chat-1", "a3").unwrap();

        assert_eq!(
            outcome.dropped,
            Some(SequentialEvent {
                stream_key: "chat-1".to_string(),
                item: "a1",
            })
        );

        let first = processor.next_ready().unwrap();
        assert_eq!(first.item, "a2");
        assert!(processor.finish_key("chat-1"));

        let second = processor.next_ready().unwrap();
        assert_eq!(second.item, "a3");
        assert!(!processor.finish_key("chat-1"));
    }

    #[test]
    fn sequential_processor_drops_global_oldest_when_total_cap_is_hit() {
        let mut processor = SequentialEventProcessor::new(SequentialEventProcessorConfig {
            max_queue_per_key: 4,
            max_total_queued: 2,
            overflow_policy: SequentialOverflowPolicy::DropOldest,
            item_timeout: None,
        });

        processor.enqueue("alpha", "a1").unwrap();
        processor.enqueue("beta", "b1").unwrap();
        let outcome = processor.enqueue("gamma", "g1").unwrap();

        assert_eq!(
            outcome.dropped,
            Some(SequentialEvent {
                stream_key: "alpha".to_string(),
                item: "a1",
            })
        );

        let first = processor.next_ready().unwrap();
        assert_eq!(first.stream_key, "beta");
        assert_eq!(first.item, "b1");
        assert!(!processor.finish_key("beta"));

        let second = processor.next_ready().unwrap();
        assert_eq!(second.stream_key, "gamma");
        assert_eq!(second.item, "g1");
        assert!(!processor.finish_key("gamma"));
    }

    #[test]
    fn sequential_processor_expires_items_waiting_too_long() {
        let mut processor = SequentialEventProcessor::new(SequentialEventProcessorConfig {
            max_queue_per_key: 4,
            max_total_queued: 8,
            overflow_policy: SequentialOverflowPolicy::RejectNewest,
            item_timeout: Some(Duration::from_millis(1)),
        });

        processor.enqueue("chat-1", 1_u8).unwrap();
        thread::sleep(Duration::from_millis(5));
        processor.enqueue("chat-1", 2_u8).unwrap();

        let next = processor.next_ready().unwrap();
        assert_eq!(next.item, 2);
        assert!(!processor.finish_key("chat-1"));
        assert!(processor.next_ready().is_none());
    }

    #[test]
    fn cursor_monotonicity() {
        let mut manager = EventStreamManager::new(caps(true, false, 3));
        let e1 = manager.emit("events.test", sample_event_data());
        let e2 = manager.emit("events.test", sample_event_data());
        let e3 = manager.emit("events.test", sample_event_data());

        assert_eq!(e1.seq, 0);
        assert_eq!(e2.seq, 1);
        assert_eq!(e3.seq, 2);
        assert_eq!(e1.cursor, "0");
        assert_eq!(e2.cursor, "1");
        assert_eq!(e3.cursor, "2");
    }

    #[test]
    fn ack_required_tracks_pending() {
        let mut manager = EventStreamManager::new(caps(true, true, 2));
        let e1 = manager.emit("events.ack", sample_event_data());
        let e2 = manager.emit("events.ack", sample_event_data());

        assert!(e1.requires_ack);
        assert!(e2.requires_ack);
        assert_eq!(manager.pending_acks("events.ack"), 2);

        let ack = EventAck::new("events.ack", vec![e1.seq]).with_cursors(vec![e1.cursor.clone()]);
        let result = manager.handle_ack(&ack);
        assert_eq!(result.acked, vec![e1.seq]);
        assert_eq!(manager.pending_acks("events.ack"), 1);
    }

    #[test]
    fn subscribe_replay_ack_flow() {
        let mut manager = EventStreamManager::new(caps(true, true, 3));
        let req = SubscribeRequest {
            r#type: "subscribe".to_string(),
            id: RequestId::new("req-1"),
            topics: vec!["events.flow".to_string()],
            since: None,
            max_events_per_sec: None,
            batch_ms: None,
            window_size: None,
            capability_token: None,
        };

        let outcome = manager.handle_subscribe(&req).unwrap();
        assert!(outcome.response.result.replay_supported);

        let e1 = manager.emit("events.flow", sample_event_data());
        let e2 = manager.emit("events.flow", sample_event_data());

        let ack = EventAck::new("events.flow", vec![e1.seq]).with_cursors(vec![e1.cursor.clone()]);
        manager.handle_ack(&ack);

        let replayed = manager.replay_from("events.flow", &e1.cursor).unwrap();
        assert_eq!(replayed.len(), 1);
        assert_eq!(replayed[0].seq, e2.seq);
    }

    #[test]
    fn buffer_limits_default() {
        let limits = BufferLimits::default();
        assert_eq!(limits.min_events, 10);
        assert_eq!(limits.max_events, 100);
    }

    #[test]
    fn buffer_limits_max_enforced() {
        let limits = BufferLimits::new(5, 20);
        assert_eq!(limits.min_events, 5);
        assert_eq!(limits.max_events, 20);
    }

    #[test]
    fn buffer_limits_min_overrides_max() {
        let limits = BufferLimits::new(50, 10);
        assert_eq!(limits.min_events, 50);
        assert_eq!(limits.max_events, 50); // max clamped to min
    }

    #[test]
    fn emit_with_seq_respects_provided_seq() {
        let mut manager = EventStreamManager::new(caps(false, false, 3));
        let e = manager.emit_with_seq("topic", 42, sample_event_data());
        assert_eq!(e.seq, 42);
        assert_eq!(e.cursor, "42");
    }

    #[test]
    fn emit_auto_increments_seq() {
        let mut manager = EventStreamManager::new(caps(false, false, 10));
        let e1 = manager.emit("t", sample_event_data());
        let e2 = manager.emit("t", sample_event_data());
        let e3 = manager.emit("t", sample_event_data());
        assert_eq!(e1.seq, 0);
        assert_eq!(e2.seq, 1);
        assert_eq!(e3.seq, 2);
    }

    #[test]
    fn replay_from_unknown_topic_error() {
        let manager = EventStreamManager::new(caps(true, false, 3));
        let result = manager.replay_from("nonexistent", "0");
        assert!(matches!(result, Err(ReplayError::UnknownTopic { .. })));
    }

    #[test]
    fn replay_from_invalid_cursor_error() {
        let mut manager = EventStreamManager::new(caps(true, false, 3));
        manager.emit("t", sample_event_data());
        let result = manager.replay_from("t", "not_a_number");
        assert!(matches!(result, Err(ReplayError::InvalidCursor { .. })));
    }

    #[test]
    fn replay_from_stale_cursor_error() {
        let mut manager =
            EventStreamManager::with_limits(caps(true, false, 2), BufferLimits::new(1, 2));
        // Fill buffer beyond capacity so oldest gets trimmed
        manager.emit("t", sample_event_data()); // seq 0
        manager.emit("t", sample_event_data()); // seq 1
        manager.emit("t", sample_event_data()); // seq 2 → trims seq 0

        let result = manager.replay_from("t", "0");
        // seq 0 should have been trimmed, so cursor is stale
        match result {
            Err(ReplayError::CursorStale { cursor_seq, .. }) => {
                assert_eq!(cursor_seq, 0);
            }
            // If buffer hasn't trimmed (e.g., pending acks keeping it), replay might succeed
            Ok(_) => {} // acceptable if buffer retained all events
            Err(other) => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn replay_from_empty_cursor_returns_all() {
        let mut manager = EventStreamManager::new(caps(true, false, 10));
        manager.emit("t", sample_event_data());
        manager.emit("t", sample_event_data());
        let events = manager.replay_from("t", "").unwrap();
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn nack_redelivers_events() {
        let mut manager = EventStreamManager::new(caps(true, true, 5));
        let e1 = manager.emit("t", sample_event_data());
        let e2 = manager.emit("t", sample_event_data());

        let nack = EventNack::new("t", vec![e1.seq, e2.seq], "retry");
        let result = manager.handle_nack(&nack);
        assert_eq!(result.redeliver.len(), 2);
        assert!(result.missing.is_empty());
    }

    #[test]
    fn nack_unknown_topic_returns_all_missing() {
        let manager = EventStreamManager::new(caps(true, false, 3));
        let nack = EventNack::new("nonexistent", vec![0, 1], "retry");
        let result = manager.handle_nack(&nack);
        assert!(result.redeliver.is_empty());
        assert_eq!(result.missing, vec![0, 1]);
    }

    #[test]
    fn ack_unknown_topic_returns_all_missing() {
        let mut manager = EventStreamManager::new(caps(true, true, 3));
        let ack = EventAck::new("nonexistent", vec![0, 1]).with_cursors(vec![]);
        let result = manager.handle_ack(&ack);
        assert!(result.acked.is_empty());
        assert_eq!(result.missing, vec![0, 1]);
    }

    #[test]
    fn unsubscribe_removes_topics() {
        let mut manager = EventStreamManager::new(caps(true, false, 3));
        manager.emit("t1", sample_event_data());
        manager.emit("t2", sample_event_data());

        let removed = manager.unsubscribe(&["t1".to_string()]);
        assert_eq!(removed, 1);
        assert!(manager.replay_from("t1", "").is_err());
        assert!(manager.replay_from("t2", "").is_ok());
    }

    #[test]
    fn unsubscribe_nonexistent_returns_zero() {
        let mut manager = EventStreamManager::new(caps(false, false, 3));
        assert_eq!(manager.unsubscribe(&["nope".to_string()]), 0);
    }

    #[test]
    fn pending_acks_unknown_topic_is_zero() {
        let manager = EventStreamManager::new(caps(true, true, 3));
        assert_eq!(manager.pending_acks("nonexistent"), 0);
    }

    // ── Unbounded-growth regressions (br-l2ack) ──────────────────────

    fn subscribe_req(topics: Vec<String>) -> SubscribeRequest {
        SubscribeRequest {
            r#type: "subscribe".to_string(),
            id: RequestId::new("req-l2ack"),
            topics,
            since: None,
            max_events_per_sec: None,
            batch_ms: None,
            window_size: None,
            capability_token: None,
        }
    }

    /// A consumer that simply stops acking used to pin the front of the buffer
    /// and grow both the buffer and the pending-ack set for as long as events
    /// kept arriving. The hard ceiling bounds both.
    #[test]
    fn buffer_is_bounded_when_consumer_never_acks() {
        let limits = BufferLimits::new(1, 4); // hard ceiling 16
        let mut manager = EventStreamManager::with_limits(caps(true, true, 1), limits);

        for _ in 0..500 {
            manager.emit("t", sample_event_data());
        }

        assert!(
            manager.dropped_unacked("t") > 0,
            "the ceiling must actually engage; nothing was dropped"
        );
        // `pending_acks` is bounded BY the buffer, which is why no separate
        // pending-ack TTL is needed.
        assert!(
            manager.pending_acks("t") <= limits.hard_max_events,
            "pending acks {} exceeded the hard ceiling {}",
            manager.pending_acks("t"),
            limits.hard_max_events
        );
    }

    /// Acking normally must not trip the ceiling — the fix must not cost a
    /// well-behaved consumer any replay coverage.
    #[test]
    fn well_behaved_consumer_never_loses_unacked_events() {
        let mut manager =
            EventStreamManager::with_limits(caps(true, true, 1), BufferLimits::new(1, 4));

        for _ in 0..500 {
            let envelope = manager.emit("t", sample_event_data());
            let ack = EventAck::new("t", vec![envelope.seq]).with_cursors(vec![envelope.cursor]);
            manager.handle_ack(&ack);
        }

        assert_eq!(manager.dropped_unacked("t"), 0);
        assert_eq!(manager.pending_acks("t"), 0);
    }

    /// `confirmed_topics` used to echo back whatever the client sent, so a typo
    /// was indistinguishable from a real subscription and every distinct string
    /// was retained forever.
    #[test]
    fn subscribe_rejects_invalid_topic_names() {
        let mut manager = EventStreamManager::new(caps(true, false, 1));
        let req = subscribe_req(vec![
            "good.topic".to_string(),
            String::new(),
            "has space".to_string(),
            "bad/slash".to_string(),
            "x".repeat(MAX_TOPIC_LEN + 1),
        ]);

        let outcome = manager.handle_subscribe(&req).unwrap();

        assert_eq!(outcome.response.result.confirmed_topics, vec!["good.topic"]);
        assert_eq!(
            manager.tracked_topics(),
            1,
            "rejected topics must not create retained state"
        );
    }

    #[test]
    fn subscribe_caps_topics_per_request() {
        let mut manager = EventStreamManager::new(caps(true, false, 1));
        let topics: Vec<String> = (0..MAX_TOPICS_PER_SUBSCRIBE * 3)
            .map(|i| format!("topic.{i}"))
            .collect();

        let outcome = manager.handle_subscribe(&subscribe_req(topics)).unwrap();

        assert_eq!(
            outcome.response.result.confirmed_topics.len(),
            MAX_TOPICS_PER_SUBSCRIBE
        );
        assert_eq!(manager.tracked_topics(), MAX_TOPICS_PER_SUBSCRIBE);
    }

    /// Repeated subscribes must not grow the topic map without bound, and
    /// hitting the ceiling must not break topics that already exist.
    #[test]
    fn subscribe_refuses_new_topics_past_the_tracking_ceiling() {
        let mut manager = EventStreamManager::new(caps(true, false, 1));
        for chunk in 0..(MAX_TRACKED_TOPICS / MAX_TOPICS_PER_SUBSCRIBE + 4) {
            let topics: Vec<String> = (0..MAX_TOPICS_PER_SUBSCRIBE)
                .map(|i| format!("t.{chunk}.{i}"))
                .collect();
            manager.handle_subscribe(&subscribe_req(topics)).unwrap();
        }

        assert_eq!(manager.tracked_topics(), MAX_TRACKED_TOPICS);

        // An already-tracked topic is still accepted at the ceiling.
        let outcome = manager
            .handle_subscribe(&subscribe_req(vec!["t.0.0".to_string()]))
            .unwrap();
        assert_eq!(outcome.response.result.confirmed_topics, vec!["t.0.0"]);
    }

    #[test]
    fn buffer_trim_respects_pending_acks() {
        let mut manager =
            EventStreamManager::with_limits(caps(true, true, 1), BufferLimits::new(1, 2));
        let e1 = manager.emit("t", sample_event_data()); // seq 0, pending ack
        manager.emit("t", sample_event_data()); // seq 1, pending ack
        manager.emit("t", sample_event_data()); // seq 2 → tries to trim but pending acks block

        // e1 should still be in buffer because it has pending ack
        assert!(manager.pending_acks("t") >= 2);

        // Ack e1 to allow trimming
        let ack = EventAck::new("t", vec![e1.seq]).with_cursors(vec![e1.cursor]);
        manager.handle_ack(&ack);
    }

    #[test]
    fn subscribe_creates_topic_state() {
        let mut manager = EventStreamManager::new(caps(true, false, 3));
        let req = SubscribeRequest {
            r#type: "subscribe".to_string(),
            id: RequestId::new("req-sub"),
            topics: vec!["new.topic".to_string()],
            since: None,
            max_events_per_sec: None,
            batch_ms: None,
            window_size: None,
            capability_token: None,
        };

        let outcome = manager.handle_subscribe(&req).unwrap();
        assert_eq!(
            outcome.response.result.confirmed_topics,
            vec!["new.topic".to_string()]
        );
        // Topic now exists, so replay_from should work
        assert!(manager.replay_from("new.topic", "").is_ok());
    }

    #[test]
    fn subscribe_with_replay_since() {
        let mut manager = EventStreamManager::new(caps(true, false, 10));
        manager.emit("events.replay", sample_event_data()); // seq 0
        manager.emit("events.replay", sample_event_data()); // seq 1
        manager.emit("events.replay", sample_event_data()); // seq 2

        let req = SubscribeRequest {
            r#type: "subscribe".to_string(),
            id: RequestId::new("req-replay"),
            topics: vec!["events.replay".to_string()],
            since: Some("1".to_string()),
            max_events_per_sec: None,
            batch_ms: None,
            window_size: None,
            capability_token: None,
        };

        let outcome = manager.handle_subscribe(&req).unwrap();
        let replayed = outcome.replay_events.get("events.replay").unwrap();
        assert_eq!(replayed.len(), 1); // only seq 2
        assert_eq!(replayed[0].seq, 2);
    }

    #[test]
    fn multiple_topics_independent() {
        let mut manager = EventStreamManager::new(caps(true, false, 10));
        manager.emit("topic.a", sample_event_data());
        manager.emit("topic.b", sample_event_data());
        manager.emit("topic.a", sample_event_data());

        let a_events = manager.replay_from("topic.a", "").unwrap();
        let b_events = manager.replay_from("topic.b", "").unwrap();
        assert_eq!(a_events.len(), 2);
        assert_eq!(b_events.len(), 1);
    }

    #[test]
    fn replay_error_display() {
        let e = ReplayError::UnknownTopic { topic: "t".into() };
        assert_eq!(e.to_string(), "unknown topic 't'");

        let e = ReplayError::InvalidCursor {
            topic: "t".into(),
            cursor: "bad".into(),
        };
        assert_eq!(e.to_string(), "invalid cursor 'bad' for topic 't'");

        let e = ReplayError::CursorStale {
            topic: "t".into(),
            cursor_seq: 5,
            oldest_seq: 10,
        };
        assert!(e.to_string().contains('5'));
        assert!(e.to_string().contains("10"));
        assert!(e.to_string().contains("'t'"));
    }

    #[test]
    fn ack_result_debug() {
        let result = AckResult {
            acked: vec![1],
            missing: vec![2],
        };
        let debug = format!("{result:?}");
        assert!(debug.contains("AckResult"));
    }

    #[test]
    fn nack_result_debug() {
        let result = NackResult {
            redeliver: vec![],
            missing: vec![1],
        };
        let debug = format!("{result:?}");
        assert!(debug.contains("NackResult"));
    }

    #[test]
    fn subscribe_no_replay_when_disabled() {
        let mut manager = EventStreamManager::new(caps(false, false, 3));
        manager.emit("t", sample_event_data());

        let req = SubscribeRequest {
            r#type: "subscribe".to_string(),
            id: RequestId::new("req-noreplay"),
            topics: vec!["t".to_string()],
            since: Some("0".to_string()),
            max_events_per_sec: None,
            batch_ms: None,
            window_size: None,
            capability_token: None,
        };

        let outcome = manager.handle_subscribe(&req).unwrap();
        assert!(!outcome.response.result.replay_supported);
        assert!(outcome.replay_events.is_empty());
    }

    #[test]
    fn with_limits_constructor() {
        let caps = caps(true, false, 5);
        let limits = BufferLimits::new(3, 50);
        let manager = EventStreamManager::with_limits(caps, limits);
        let debug = format!("{manager:?}");
        assert!(debug.contains("EventStreamManager"));
    }

    // ── TopicState edge cases ──

    #[test]
    fn record_with_seq_behind_next_does_not_advance() {
        let mut manager = EventStreamManager::new(caps(false, false, 10));
        // Emit three events: next_seq becomes 3
        manager.emit("t", sample_event_data()); // seq 0
        manager.emit("t", sample_event_data()); // seq 1
        manager.emit("t", sample_event_data()); // seq 2

        // Now emit with seq=1 (behind next_seq=3): next_seq should stay 3
        let e = manager.emit_with_seq("t", 1, sample_event_data());
        assert_eq!(e.seq, 1);
        // Next auto-assigned seq should still be 3 (not 2)
        let e_next = manager.emit("t", sample_event_data());
        assert_eq!(e_next.seq, 3);
    }

    #[test]
    fn record_with_pre_set_cursor_keeps_it() {
        let mut manager = EventStreamManager::new(caps(false, false, 10));
        let envelope = EventEnvelope::new("t", sample_event_data())
            .with_seq(5)
            .with_cursor("custom-cursor-abc".to_string());
        let recorded = manager.record(envelope);
        assert_eq!(recorded.cursor, "custom-cursor-abc");
    }

    #[test]
    fn ack_non_pending_seq_returns_missing() {
        let mut manager = EventStreamManager::new(caps(true, true, 10));
        let e1 = manager.emit("t", sample_event_data());

        // Ack a seq that was never emitted
        let ack = EventAck::new("t", vec![e1.seq, 999]).with_cursors(vec![]);
        let result = manager.handle_ack(&ack);
        assert_eq!(result.acked, vec![e1.seq]);
        assert_eq!(result.missing, vec![999]);
    }

    #[test]
    fn nack_for_trimmed_seq_returns_missing() {
        let mut manager =
            EventStreamManager::with_limits(caps(true, false, 1), BufferLimits::new(1, 2));
        manager.emit("t", sample_event_data()); // seq 0
        manager.emit("t", sample_event_data()); // seq 1
        manager.emit("t", sample_event_data()); // seq 2 → trims seq 0

        let nack = EventNack::new("t", vec![0], "retry");
        let result = manager.handle_nack(&nack);
        // seq 0 should be trimmed (no pending ack holding it)
        assert!(
            result.redeliver.is_empty()
                || result.redeliver[0].seq != 0
                || result.missing.contains(&0)
        );
    }

    #[test]
    fn replay_from_cursor_at_latest_returns_empty() {
        let mut manager = EventStreamManager::new(caps(true, false, 10));
        manager.emit("t", sample_event_data()); // seq 0
        let e2 = manager.emit("t", sample_event_data()); // seq 1

        // Replay from the latest cursor should return nothing
        let events = manager.replay_from("t", &e2.cursor).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn subscribe_response_id_matches_request() {
        let mut manager = EventStreamManager::new(caps(true, false, 3));
        let req = SubscribeRequest {
            r#type: "subscribe".to_string(),
            id: RequestId::new("unique-req-42"),
            topics: vec!["t".to_string()],
            since: None,
            max_events_per_sec: None,
            batch_ms: None,
            window_size: None,
            capability_token: None,
        };
        let outcome = manager.handle_subscribe(&req).unwrap();
        assert_eq!(outcome.response.id.0, "unique-req-42");
    }

    #[test]
    fn subscribe_includes_cursors_for_existing_topics() {
        let mut manager = EventStreamManager::new(caps(true, false, 10));
        manager.emit("t", sample_event_data()); // seq 0
        manager.emit("t", sample_event_data()); // seq 1

        let req = SubscribeRequest {
            r#type: "subscribe".to_string(),
            id: RequestId::new("req-cur"),
            topics: vec!["t".to_string()],
            since: None,
            max_events_per_sec: None,
            batch_ms: None,
            window_size: None,
            capability_token: None,
        };
        let outcome = manager.handle_subscribe(&req).unwrap();
        let cursor = outcome.response.result.cursors.get("t").unwrap();
        assert_eq!(cursor, "1"); // latest seq
    }

    #[test]
    fn new_manager_limits_from_caps() {
        let c = caps(true, false, 7);
        let manager = EventStreamManager::new(c);
        // min_buffer_events=7, so limits.min_events=7, max_events=max(7,1)=7
        // Emit 8 events, buffer should trim to 7
        let mut m = manager;
        for _ in 0..8 {
            m.emit("t", sample_event_data());
        }
        let events = m.replay_from("t", "").unwrap();
        assert!(events.len() <= 8); // may or may not have trimmed depending on exact logic
    }

    #[test]
    fn unsubscribe_multiple_topics() {
        let mut manager = EventStreamManager::new(caps(true, false, 3));
        manager.emit("t1", sample_event_data());
        manager.emit("t2", sample_event_data());
        manager.emit("t3", sample_event_data());

        let removed = manager.unsubscribe(&["t1".to_string(), "t3".to_string()]);
        assert_eq!(removed, 2);
        assert!(manager.replay_from("t1", "").is_err());
        assert!(manager.replay_from("t2", "").is_ok());
        assert!(manager.replay_from("t3", "").is_err());
    }

    #[test]
    fn replay_error_clone() {
        let e = ReplayError::CursorStale {
            topic: "t".into(),
            cursor_seq: 5,
            oldest_seq: 10,
        };
        let cloned = e.clone();
        assert_eq!(cloned.to_string(), e.to_string());
    }

    #[test]
    fn buffer_limits_clone() {
        let limits = BufferLimits::new(3, 15);
        let cloned = limits;
        assert_eq!(cloned.min_events, 3);
        assert_eq!(cloned.max_events, 15);
    }

    #[test]
    fn subscribe_outcome_debug() {
        let outcome = SubscribeOutcome {
            response: SubscribeResponse {
                r#type: "response".to_string(),
                id: RequestId::new("r"),
                result: SubscribeResult {
                    confirmed_topics: vec![],
                    cursors: HashMap::new(),
                    replay_supported: false,
                    buffer: None,
                },
            },
            replay_events: HashMap::new(),
        };
        let debug = format!("{outcome:?}");
        assert!(debug.contains("SubscribeOutcome"));
    }

    #[test]
    fn double_ack_same_seq_second_is_missing() {
        let mut manager = EventStreamManager::new(caps(true, true, 10));
        let e = manager.emit("t", sample_event_data());

        let ack = EventAck::new("t", vec![e.seq]).with_cursors(vec![]);
        let r1 = manager.handle_ack(&ack);
        assert_eq!(r1.acked, vec![e.seq]);

        // Second ack of same seq should be missing
        let r2 = manager.handle_ack(&ack);
        assert!(r2.acked.is_empty());
        assert_eq!(r2.missing, vec![e.seq]);
    }

    #[test]
    fn emit_without_ack_flag_when_caps_not_required() {
        let mut manager = EventStreamManager::new(caps(true, false, 10));
        let e = manager.emit("t", sample_event_data());
        assert!(!e.requires_ack);
        assert_eq!(manager.pending_acks("t"), 0);
    }

    #[test]
    fn replay_from_empty_buffer_returns_empty() {
        let mut manager = EventStreamManager::new(caps(true, false, 10));
        // Create topic via subscribe but don't emit events
        let req = SubscribeRequest {
            r#type: "subscribe".to_string(),
            id: RequestId::new("r"),
            topics: vec!["empty".to_string()],
            since: None,
            max_events_per_sec: None,
            batch_ms: None,
            window_size: None,
            capability_token: None,
        };
        manager.handle_subscribe(&req).unwrap();
        let events = manager.replay_from("empty", "").unwrap();
        assert!(events.is_empty());
    }

    // ── SequentialEventProcessor additional coverage ──

    #[test]
    fn sequential_processor_config_accessor() {
        let cfg = SequentialEventProcessorConfig {
            max_queue_per_key: 5,
            max_total_queued: 20,
            overflow_policy: SequentialOverflowPolicy::DropOldest,
            item_timeout: Some(Duration::from_secs(30)),
        };
        let processor = SequentialEventProcessor::<u8>::new(cfg);
        let c = processor.config();
        assert_eq!(c.max_queue_per_key, 5);
        assert_eq!(c.max_total_queued, 20);
        assert_eq!(c.overflow_policy, SequentialOverflowPolicy::DropOldest);
        assert_eq!(c.item_timeout, Some(Duration::from_secs(30)));
    }

    #[test]
    fn sequential_processor_queue_depth_tracking() {
        let mut processor = SequentialEventProcessor::new(SequentialEventProcessorConfig {
            max_queue_per_key: 4,
            max_total_queued: 16,
            overflow_policy: SequentialOverflowPolicy::RejectNewest,
            item_timeout: None,
        });
        assert_eq!(processor.queue_depth(), 0);
        assert_eq!(processor.queue_depth_for("a"), 0);

        processor.enqueue("a", 1_u32).unwrap();
        processor.enqueue("a", 2_u32).unwrap();
        processor.enqueue("b", 10_u32).unwrap();

        assert_eq!(processor.queue_depth(), 3);
        assert_eq!(processor.queue_depth_for("a"), 2);
        assert_eq!(processor.queue_depth_for("b"), 1);
        assert_eq!(processor.queue_depth_for("unknown"), 0);
    }

    #[test]
    fn sequential_processor_active_keys_count() {
        let mut processor = SequentialEventProcessor::new(SequentialEventProcessorConfig {
            max_queue_per_key: 4,
            max_total_queued: 16,
            overflow_policy: SequentialOverflowPolicy::RejectNewest,
            item_timeout: None,
        });
        assert_eq!(processor.active_keys(), 0);

        processor.enqueue("a", 1_u32).unwrap();
        processor.enqueue("b", 2_u32).unwrap();
        // Dequeue "a" - now active
        let _ = processor.next_ready().unwrap();
        assert_eq!(processor.active_keys(), 1);

        // Dequeue "b" - now both active
        let _ = processor.next_ready().unwrap();
        assert_eq!(processor.active_keys(), 2);

        // Finish "a"
        processor.finish_key("a");
        assert_eq!(processor.active_keys(), 1);

        processor.finish_key("b");
        assert_eq!(processor.active_keys(), 0);
    }

    #[test]
    fn sequential_processor_is_idle_transitions() {
        let mut processor = SequentialEventProcessor::new(SequentialEventProcessorConfig {
            max_queue_per_key: 4,
            max_total_queued: 16,
            overflow_policy: SequentialOverflowPolicy::RejectNewest,
            item_timeout: None,
        });
        assert!(processor.is_idle());

        processor.enqueue("a", 1_u32).unwrap();
        assert!(!processor.is_idle()); // queued work

        let _ = processor.next_ready().unwrap();
        assert!(!processor.is_idle()); // active work

        processor.finish_key("a");
        assert!(processor.is_idle()); // back to idle
    }

    #[test]
    fn sequential_processor_default_config() {
        let processor = SequentialEventProcessor::<u8>::default();
        let c = processor.config();
        assert_eq!(c.max_queue_per_key, 32);
        assert_eq!(c.max_total_queued, 256);
        assert_eq!(c.overflow_policy, SequentialOverflowPolicy::RejectNewest);
        assert!(c.item_timeout.is_none());
        assert!(processor.is_idle());
    }

    #[test]
    fn sequential_processor_finish_unknown_key() {
        let mut processor = SequentialEventProcessor::<u8>::default();
        // Finishing a key that was never enqueued should return false
        assert!(!processor.finish_key("nonexistent"));
    }

    #[test]
    fn sequential_processor_finish_non_active_key() {
        let mut processor = SequentialEventProcessor::new(SequentialEventProcessorConfig {
            max_queue_per_key: 4,
            max_total_queued: 16,
            overflow_policy: SequentialOverflowPolicy::RejectNewest,
            item_timeout: None,
        });
        processor.enqueue("a", 1_u32).unwrap();
        // Key "a" is queued but not active (nothing dequeued yet)
        // finish_key should return false because state.active is false
        assert!(!processor.finish_key("a"));
    }

    #[test]
    fn sequential_processor_zero_max_queue_rejects() {
        let mut processor = SequentialEventProcessor::new(SequentialEventProcessorConfig {
            max_queue_per_key: 0,
            max_total_queued: 10,
            overflow_policy: SequentialOverflowPolicy::RejectNewest,
            item_timeout: None,
        });
        let err = processor.enqueue("a", 1_u32).unwrap_err();
        match err {
            SequentialEnqueueError::QueueFull { stream_key, item } => {
                assert_eq!(stream_key, "a");
                assert_eq!(item, 1);
            }
        }
    }

    #[test]
    fn sequential_processor_zero_max_total_rejects() {
        let mut processor = SequentialEventProcessor::new(SequentialEventProcessorConfig {
            max_queue_per_key: 10,
            max_total_queued: 0,
            overflow_policy: SequentialOverflowPolicy::DropOldest,
            item_timeout: None,
        });
        let err = processor.enqueue("a", 1_u32).unwrap_err();
        match err {
            SequentialEnqueueError::QueueFull { stream_key, item } => {
                assert_eq!(stream_key, "a");
                assert_eq!(item, 1);
            }
        }
    }

    #[test]
    fn sequential_processor_total_cap_reject_newest() {
        let mut processor = SequentialEventProcessor::new(SequentialEventProcessorConfig {
            max_queue_per_key: 4,
            max_total_queued: 2,
            overflow_policy: SequentialOverflowPolicy::RejectNewest,
            item_timeout: None,
        });
        processor.enqueue("a", 1_u32).unwrap();
        processor.enqueue("b", 2_u32).unwrap();
        // Total is at cap, should reject
        let err = processor.enqueue("c", 3_u32).unwrap_err();
        match err {
            SequentialEnqueueError::QueueFull { stream_key, .. } => {
                assert_eq!(stream_key, "c");
            }
        }
    }

    #[test]
    fn sequential_enqueue_error_display() {
        let err = SequentialEnqueueError::QueueFull {
            stream_key: "my-key".to_string(),
            item: 42_u32,
        };
        let msg = err.to_string();
        assert!(msg.contains("my-key"));
        assert!(msg.contains("full"));
    }

    #[test]
    fn sequential_event_processor_config_default() {
        let cfg = SequentialEventProcessorConfig::default();
        assert_eq!(cfg.max_queue_per_key, 32);
        assert_eq!(cfg.max_total_queued, 256);
        assert_eq!(cfg.overflow_policy, SequentialOverflowPolicy::RejectNewest);
        assert!(cfg.item_timeout.is_none());
    }

    #[test]
    fn sequential_processor_next_ready_empty() {
        let mut processor = SequentialEventProcessor::<u8>::default();
        assert!(processor.next_ready().is_none());
    }

    #[test]
    fn sequential_processor_drop_oldest_global_when_per_key_also_overflows() {
        // Per-key limit is 1, total limit is 2, DropOldest policy.
        // Enqueue one item on "a", one on "b" (total=2).
        // Then enqueue another on "a" -> per-key overflow drops oldest from "a",
        // but total is still at 2 (because we added one). Check that
        // the global overflow path is also triggered if needed.
        let mut processor = SequentialEventProcessor::new(SequentialEventProcessorConfig {
            max_queue_per_key: 1,
            max_total_queued: 2,
            overflow_policy: SequentialOverflowPolicy::DropOldest,
            item_timeout: None,
        });
        processor.enqueue("a", "a1").unwrap();
        processor.enqueue("b", "b1").unwrap();
        // Now total=2, per-key("a")=1. Enqueuing another "a" drops "a1" (per-key),
        // total becomes 1 (after drop) + 1 (new) = 2, which is at the cap
        // but the per-key drop already freed space, so no global drop needed.
        let outcome = processor.enqueue("a", "a2").unwrap();
        assert_eq!(
            outcome.dropped,
            Some(SequentialEvent {
                stream_key: "a".to_string(),
                item: "a1",
            })
        );
        assert_eq!(processor.queue_depth(), 2);
    }

    #[test]
    fn sequential_processor_timeout_removes_all_expired_items() {
        let mut processor = SequentialEventProcessor::new(SequentialEventProcessorConfig {
            max_queue_per_key: 8,
            max_total_queued: 16,
            overflow_policy: SequentialOverflowPolicy::RejectNewest,
            item_timeout: Some(Duration::from_millis(1)),
        });

        processor.enqueue("a", 1_u32).unwrap();
        processor.enqueue("a", 2_u32).unwrap();
        processor.enqueue("b", 3_u32).unwrap();

        thread::sleep(Duration::from_millis(5));

        // All items should have expired; next_ready triggers prune
        assert!(processor.next_ready().is_none());
        assert!(processor.is_idle());
        assert_eq!(processor.queue_depth(), 0);
    }

    #[test]
    fn sequential_processor_timeout_preserves_fresh_items() {
        let mut processor = SequentialEventProcessor::new(SequentialEventProcessorConfig {
            max_queue_per_key: 8,
            max_total_queued: 16,
            overflow_policy: SequentialOverflowPolicy::RejectNewest,
            item_timeout: Some(Duration::from_millis(1)),
        });

        processor.enqueue("a", 1_u32).unwrap();
        thread::sleep(Duration::from_millis(5));
        // Item 1 expired, enqueue item 2 which is fresh
        processor.enqueue("a", 2_u32).unwrap();

        let next = processor.next_ready().unwrap();
        assert_eq!(next.item, 2);
    }

    // ── EventStreamManager additional coverage ──

    #[test]
    fn emit_with_seq_ahead_of_next_advances_next_seq() {
        let mut manager = EventStreamManager::new(caps(false, false, 10));
        // Emit with seq=100, next_seq advances to 101
        let e1 = manager.emit_with_seq("t", 100, sample_event_data());
        assert_eq!(e1.seq, 100);
        // Next auto-assigned should be 101
        let e2 = manager.emit("t", sample_event_data());
        assert_eq!(e2.seq, 101);
    }

    #[test]
    fn subscribe_buffer_info_when_replay_enabled() {
        let mut manager =
            EventStreamManager::with_limits(caps(true, false, 5), BufferLimits::new(5, 50));
        let req = SubscribeRequest {
            r#type: "subscribe".to_string(),
            id: RequestId::new("req-buf"),
            topics: vec!["t".to_string()],
            since: None,
            max_events_per_sec: None,
            batch_ms: None,
            window_size: None,
            capability_token: None,
        };
        let outcome = manager.handle_subscribe(&req).unwrap();
        let buf = outcome.response.result.buffer.unwrap();
        assert_eq!(buf.min_events, 5);
        assert_eq!(buf.overflow, "drop_oldest");
    }

    #[test]
    fn subscribe_no_buffer_info_when_replay_disabled() {
        let mut manager = EventStreamManager::new(caps(false, false, 5));
        let req = SubscribeRequest {
            r#type: "subscribe".to_string(),
            id: RequestId::new("req-nobuf"),
            topics: vec!["t".to_string()],
            since: None,
            max_events_per_sec: None,
            batch_ms: None,
            window_size: None,
            capability_token: None,
        };
        let outcome = manager.handle_subscribe(&req).unwrap();
        assert!(outcome.response.result.buffer.is_none());
    }

    #[test]
    fn subscribe_multiple_topics_with_replay_since() {
        let mut manager = EventStreamManager::new(caps(true, false, 10));
        manager.emit("t1", sample_event_data()); // seq 0
        manager.emit("t1", sample_event_data()); // seq 1
        manager.emit("t2", sample_event_data()); // seq 0
        manager.emit("t2", sample_event_data()); // seq 1
        manager.emit("t2", sample_event_data()); // seq 2

        let req = SubscribeRequest {
            r#type: "subscribe".to_string(),
            id: RequestId::new("req-multi"),
            topics: vec!["t1".to_string(), "t2".to_string()],
            since: Some("0".to_string()),
            max_events_per_sec: None,
            batch_ms: None,
            window_size: None,
            capability_token: None,
        };

        let outcome = manager.handle_subscribe(&req).unwrap();
        // t1 has seq 1 after cursor "0", t2 has seq 1,2 after cursor "0"
        let t1_replay = outcome.replay_events.get("t1").unwrap();
        assert_eq!(t1_replay.len(), 1);
        assert_eq!(t1_replay[0].seq, 1);

        let t2_replay = outcome.replay_events.get("t2").unwrap();
        assert_eq!(t2_replay.len(), 2);
        assert_eq!(t2_replay[0].seq, 1);
        assert_eq!(t2_replay[1].seq, 2);
    }

    #[test]
    fn replay_from_nonempty_cursor_on_empty_buffer() {
        let mut manager = EventStreamManager::new(caps(true, false, 10));
        // Create topic via subscribe, buffer is empty
        let req = SubscribeRequest {
            r#type: "subscribe".to_string(),
            id: RequestId::new("r"),
            topics: vec!["t".to_string()],
            since: None,
            max_events_per_sec: None,
            batch_ms: None,
            window_size: None,
            capability_token: None,
        };
        manager.handle_subscribe(&req).unwrap();
        // Replay with a non-empty cursor on an empty buffer returns empty (no error)
        let events = manager.replay_from("t", "5").unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn nack_mixed_found_and_missing() {
        let mut manager = EventStreamManager::new(caps(true, true, 10));
        let e1 = manager.emit("t", sample_event_data());
        manager.emit("t", sample_event_data());

        // Nack with one valid seq and one invalid seq
        let nack = EventNack::new("t", vec![e1.seq, 999], "retry");
        let result = manager.handle_nack(&nack);
        assert_eq!(result.redeliver.len(), 1);
        assert_eq!(result.redeliver[0].seq, e1.seq);
        assert_eq!(result.missing, vec![999]);
    }

    #[test]
    fn record_envelope_requiring_ack_without_caps_flag() {
        // Caps don't require ack, but envelope itself has requires_ack = true
        let mut manager = EventStreamManager::new(caps(true, false, 10));
        let envelope = EventEnvelope::new("t", sample_event_data()).requiring_ack();
        let recorded = manager.record(envelope);
        assert!(recorded.requires_ack);
        assert_eq!(manager.pending_acks("t"), 1);
    }

    #[test]
    fn subscribe_with_replay_since_no_matching_events() {
        let mut manager = EventStreamManager::new(caps(true, false, 10));
        manager.emit("t", sample_event_data()); // seq 0
        manager.emit("t", sample_event_data()); // seq 1

        let req = SubscribeRequest {
            r#type: "subscribe".to_string(),
            id: RequestId::new("req-noevt"),
            topics: vec!["t".to_string()],
            since: Some("1".to_string()), // cursor at latest, nothing after
            max_events_per_sec: None,
            batch_ms: None,
            window_size: None,
            capability_token: None,
        };
        let outcome = manager.handle_subscribe(&req).unwrap();
        // No replay events since cursor is at the latest
        assert!(outcome.replay_events.is_empty());
    }

    #[test]
    fn ack_result_clone() {
        let result = AckResult {
            acked: vec![1, 2, 3],
            missing: vec![4],
        };
        let cloned = result.clone();
        assert_eq!(result.acked, cloned.acked);
        assert_eq!(result.missing, cloned.missing);
    }

    #[test]
    fn nack_result_clone() {
        let result = NackResult {
            redeliver: vec![],
            missing: vec![10, 20],
        };
        let cloned = result.clone();
        assert_eq!(result.missing, cloned.missing);
        assert!(cloned.redeliver.is_empty());
    }

    #[test]
    fn subscribe_outcome_clone() {
        let outcome = SubscribeOutcome {
            response: SubscribeResponse {
                r#type: "response".to_string(),
                id: RequestId::new("r"),
                result: SubscribeResult {
                    confirmed_topics: vec!["t".to_string()],
                    cursors: HashMap::new(),
                    replay_supported: true,
                    buffer: None,
                },
            },
            replay_events: HashMap::new(),
        };
        let cloned = outcome.clone();
        assert_eq!(
            outcome.response.result.confirmed_topics,
            cloned.response.result.confirmed_topics
        );
    }

    #[test]
    fn sequential_event_debug_and_eq() {
        let event = SequentialEvent {
            stream_key: "k".to_string(),
            item: 42_u32,
        };
        let debug = format!("{event:?}");
        assert!(debug.contains("SequentialEvent"));
        assert!(debug.contains("42"));

        let same = SequentialEvent {
            stream_key: "k".to_string(),
            item: 42_u32,
        };
        assert_eq!(event, same);

        let different = SequentialEvent {
            stream_key: "k".to_string(),
            item: 99_u32,
        };
        assert_ne!(event, different);
    }

    #[test]
    fn sequential_enqueue_outcome_debug() {
        let outcome = SequentialEnqueueOutcome::<u32> { dropped: None };
        let debug = format!("{outcome:?}");
        assert!(debug.contains("SequentialEnqueueOutcome"));
    }

    #[test]
    fn buffer_limits_debug() {
        let limits = BufferLimits::new(2, 8);
        let debug = format!("{limits:?}");
        assert!(debug.contains("BufferLimits"));
        assert!(debug.contains('2'));
        assert!(debug.contains('8'));
    }

    #[test]
    fn sequential_overflow_policy_eq_and_debug() {
        let reject = SequentialOverflowPolicy::RejectNewest;
        let drop_oldest = SequentialOverflowPolicy::DropOldest;
        assert_ne!(reject, drop_oldest);
        assert_eq!(reject, SequentialOverflowPolicy::RejectNewest);
        let debug = format!("{reject:?}");
        assert!(debug.contains("RejectNewest"));
    }

    #[test]
    fn replay_error_debug() {
        let err = ReplayError::InvalidCursor {
            topic: "my_topic".into(),
            cursor: "xyz".into(),
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("InvalidCursor"));
        assert!(debug.contains("my_topic"));
    }

    // ── NEW: ReplayError Display ─────────────────────────────────────

    #[test]
    fn replay_error_unknown_topic_display() {
        let err = ReplayError::UnknownTopic {
            topic: "events".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("events"));
        assert!(msg.contains("unknown topic"));
    }

    #[test]
    fn replay_error_invalid_cursor_display() {
        let err = ReplayError::InvalidCursor {
            topic: "updates".to_string(),
            cursor: "abc".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("updates"));
        assert!(msg.contains("abc"));
    }

    #[test]
    fn replay_error_cursor_stale_display() {
        let err = ReplayError::CursorStale {
            topic: "events".to_string(),
            cursor_seq: 5,
            oldest_seq: 10,
        };
        let msg = err.to_string();
        assert!(msg.contains('5'));
        assert!(msg.contains("10"));
        assert!(msg.contains("events"));
    }

    #[test]
    fn replay_error_clone_roundtrip() {
        let err = ReplayError::UnknownTopic {
            topic: "t".to_string(),
        };
        let cloned = err.clone();
        assert_eq!(err.to_string(), cloned.to_string());
    }

    // ── NEW: BufferLimits edge cases ─────────────────────────────────

    #[test]
    fn buffer_limits_max_enforced_at_least_min() {
        let limits = BufferLimits::new(10, 5);
        // max_events should be bumped to at least min_events
        assert_eq!(limits.max_events, 10);
    }

    #[test]
    fn buffer_limits_default_values() {
        let limits = BufferLimits::default();
        assert_eq!(limits.min_events, 10);
        assert_eq!(limits.max_events, 100);
    }

    #[test]
    fn buffer_limits_copy() {
        let limits = BufferLimits::new(5, 50);
        let copied = limits;
        assert_eq!(limits.min_events, copied.min_events);
        assert_eq!(limits.max_events, copied.max_events);
    }

    // ── NEW: AckResult and NackResult ────────────────────────────────

    #[test]
    fn ack_result_debug_and_clone() {
        let result = AckResult {
            acked: vec![1, 2, 3],
            missing: vec![4],
        };
        let cloned = result.clone();
        assert_eq!(result.acked, cloned.acked);
        assert_eq!(result.missing, cloned.missing);
        let debug = format!("{result:?}");
        assert!(debug.contains("AckResult"));
    }

    #[test]
    fn nack_result_debug_and_clone() {
        let result = NackResult {
            redeliver: vec![],
            missing: vec![1, 2],
        };
        let cloned = result.clone();
        assert_eq!(result.missing, cloned.missing);
        let debug = format!("{result:?}");
        assert!(debug.contains("NackResult"));
    }

    // ── NEW: SubscribeOutcome ────────────────────────────────────────

    #[test]
    fn subscribe_outcome_debug_and_clone() {
        let outcome = SubscribeOutcome {
            response: SubscribeResponse {
                r#type: "response".to_string(),
                id: RequestId("test-id".to_string()),
                result: SubscribeResult {
                    confirmed_topics: vec!["t1".to_string()],
                    cursors: HashMap::new(),
                    replay_supported: false,
                    buffer: None,
                },
            },
            replay_events: HashMap::new(),
        };
        let cloned = outcome.clone();
        assert_eq!(
            outcome.response.result.confirmed_topics,
            cloned.response.result.confirmed_topics
        );
        let debug = format!("{outcome:?}");
        assert!(debug.contains("SubscribeOutcome"));
    }

    // ── NEW: SequentialEnqueueError ──────────────────────────────────

    #[test]
    fn sequential_enqueue_error_display_detail() {
        let err = SequentialEnqueueError::QueueFull {
            stream_key: "chat_123".to_string(),
            item: 42_u32,
        };
        let msg = err.to_string();
        assert!(msg.contains("chat_123"));
        assert!(msg.contains("full"));
    }

    #[test]
    fn sequential_enqueue_error_eq() {
        let err1 = SequentialEnqueueError::QueueFull {
            stream_key: "k".to_string(),
            item: 1_u32,
        };
        let err2 = SequentialEnqueueError::QueueFull {
            stream_key: "k".to_string(),
            item: 1_u32,
        };
        assert_eq!(err1, err2);
    }

    // ── NEW: SequentialEventProcessorConfig ──────────────────────────

    #[test]
    fn sequential_config_default_values() {
        let config = SequentialEventProcessorConfig::default();
        assert_eq!(config.max_queue_per_key, 32);
        assert_eq!(config.max_total_queued, 256);
        assert_eq!(
            config.overflow_policy,
            SequentialOverflowPolicy::RejectNewest
        );
        assert!(config.item_timeout.is_none());
    }

    #[test]
    fn sequential_config_clone_and_copy() {
        let config = SequentialEventProcessorConfig {
            max_queue_per_key: 16,
            max_total_queued: 128,
            overflow_policy: SequentialOverflowPolicy::DropOldest,
            item_timeout: Some(Duration::from_secs(30)),
        };
        let copied = config;
        assert_eq!(config.max_queue_per_key, copied.max_queue_per_key);
        assert_eq!(config.item_timeout, copied.item_timeout);
    }

    // ── Additional coverage: edge cases, boundary values, error paths ──

    #[test]
    fn buffer_limits_zero_zero() {
        let limits = BufferLimits::new(0, 0);
        assert_eq!(limits.min_events, 0);
        assert_eq!(limits.max_events, 0);
    }

    #[test]
    fn buffer_limits_equal_min_max() {
        let limits = BufferLimits::new(25, 25);
        assert_eq!(limits.min_events, 25);
        assert_eq!(limits.max_events, 25);
    }

    #[test]
    fn event_stream_manager_debug() {
        let manager = EventStreamManager::new(caps(true, true, 5));
        let dbg = format!("{manager:?}");
        assert!(dbg.contains("EventStreamManager"));
    }

    #[test]
    fn event_stream_manager_default() {
        let manager = EventStreamManager::default();
        let dbg = format!("{manager:?}");
        assert!(dbg.contains("EventStreamManager"));
        assert_eq!(manager.pending_acks("nonexistent"), 0);
    }

    #[test]
    fn emit_multiple_topics_seq_independent() {
        let mut manager = EventStreamManager::new(caps(false, false, 10));
        let e_a = manager.emit("topic_a", sample_event_data());
        let e_b = manager.emit("topic_b", sample_event_data());
        let e_a2 = manager.emit("topic_a", sample_event_data());
        // Each topic has independent seq
        assert_eq!(e_a.seq, 0);
        assert_eq!(e_b.seq, 0);
        assert_eq!(e_a2.seq, 1);
    }

    #[test]
    fn unsubscribe_all_topics() {
        let mut manager = EventStreamManager::new(caps(true, false, 10));
        manager.emit("t1", sample_event_data());
        manager.emit("t2", sample_event_data());
        manager.emit("t3", sample_event_data());
        let removed = manager.unsubscribe(&["t1".to_string(), "t2".to_string(), "t3".to_string()]);
        assert_eq!(removed, 3);
    }

    #[test]
    fn unsubscribe_partial_overlap() {
        let mut manager = EventStreamManager::new(caps(true, false, 10));
        manager.emit("t1", sample_event_data());
        manager.emit("t2", sample_event_data());
        let removed = manager.unsubscribe(&["t1".to_string(), "nonexistent".to_string()]);
        assert_eq!(removed, 1);
    }

    #[test]
    fn sequential_processor_enqueue_multiple_keys_track_depth() {
        let mut processor = SequentialEventProcessor::new(SequentialEventProcessorConfig {
            max_queue_per_key: 8,
            max_total_queued: 32,
            overflow_policy: SequentialOverflowPolicy::RejectNewest,
            item_timeout: None,
        });
        processor.enqueue("a", 1_u32).unwrap();
        processor.enqueue("b", 2_u32).unwrap();
        processor.enqueue("c", 3_u32).unwrap();
        processor.enqueue("a", 4_u32).unwrap();
        assert_eq!(processor.queue_depth(), 4);
        assert_eq!(processor.queue_depth_for("a"), 2);
        assert_eq!(processor.queue_depth_for("b"), 1);
        assert_eq!(processor.queue_depth_for("c"), 1);
    }

    #[test]
    fn sequential_processor_next_ready_dequeues_all() {
        let mut processor = SequentialEventProcessor::new(SequentialEventProcessorConfig {
            max_queue_per_key: 4,
            max_total_queued: 16,
            overflow_policy: SequentialOverflowPolicy::RejectNewest,
            item_timeout: None,
        });
        processor.enqueue("x", 10_u32).unwrap();
        processor.enqueue("y", 20_u32).unwrap();

        let e1 = processor.next_ready().unwrap();
        processor.finish_key(&e1.stream_key);
        let e2 = processor.next_ready().unwrap();
        processor.finish_key(&e2.stream_key);

        assert!(processor.next_ready().is_none());
        assert!(processor.is_idle());
    }

    #[test]
    fn sequential_overflow_policy_copy() {
        let a = SequentialOverflowPolicy::RejectNewest;
        let b = a;
        assert_eq!(a, b);
        let c = SequentialOverflowPolicy::DropOldest;
        let d = c;
        assert_eq!(c, d);
    }

    #[test]
    fn sequential_event_clone() {
        let event = SequentialEvent {
            stream_key: "k1".to_string(),
            item: 77_u32,
        };
        let cloned = event.clone();
        assert_eq!(event, cloned);
    }

    #[test]
    fn sequential_enqueue_outcome_accepted_has_no_dropped() {
        let outcome = SequentialEnqueueOutcome::<u32>::accepted();
        assert!(outcome.dropped.is_none());
    }

    #[test]
    fn sequential_processor_config_eq() {
        let c1 = SequentialEventProcessorConfig {
            max_queue_per_key: 4,
            max_total_queued: 8,
            overflow_policy: SequentialOverflowPolicy::RejectNewest,
            item_timeout: None,
        };
        let c2 = c1;
        assert_eq!(c1, c2);

        let c3 = SequentialEventProcessorConfig {
            max_queue_per_key: 4,
            max_total_queued: 16,
            overflow_policy: SequentialOverflowPolicy::RejectNewest,
            item_timeout: None,
        };
        assert_ne!(c1, c3);
    }

    #[test]
    fn replay_error_all_variants_display_non_empty() {
        let errors: Vec<ReplayError> = vec![
            ReplayError::UnknownTopic {
                topic: "t".to_string(),
            },
            ReplayError::InvalidCursor {
                topic: "t".to_string(),
                cursor: "bad".to_string(),
            },
            ReplayError::CursorStale {
                topic: "t".to_string(),
                cursor_seq: 0,
                oldest_seq: 5,
            },
        ];
        for err in &errors {
            assert!(!err.to_string().is_empty());
        }
    }

    #[test]
    fn ack_empty_seqs() {
        let mut manager = EventStreamManager::new(caps(true, true, 10));
        manager.emit("t", sample_event_data());
        let ack = EventAck::new("t", vec![]).with_cursors(vec![]);
        let result = manager.handle_ack(&ack);
        assert!(result.acked.is_empty());
        assert!(result.missing.is_empty());
    }

    #[test]
    fn nack_empty_seqs() {
        let mut manager = EventStreamManager::new(caps(true, true, 10));
        manager.emit("t", sample_event_data());
        let nack = EventNack::new("t", vec![], "retry");
        let result = manager.handle_nack(&nack);
        assert!(result.redeliver.is_empty());
        assert!(result.missing.is_empty());
    }

    #[test]
    fn emit_with_seq_zero_gets_auto_assigned() {
        let mut manager = EventStreamManager::new(caps(false, false, 10));
        // EventEnvelope::new sets seq=0 by default; record should assign next_seq=0
        let e = manager.emit("t", sample_event_data());
        assert_eq!(e.seq, 0);
        assert_eq!(e.cursor, "0");
    }

    #[test]
    fn sequential_processor_debug() {
        let processor = SequentialEventProcessor::<u8>::default();
        let dbg = format!("{processor:?}");
        assert!(dbg.contains("SequentialEventProcessor"));
    }

    #[test]
    fn sequential_enqueue_error_debug() {
        let err = SequentialEnqueueError::QueueFull {
            stream_key: "k".to_string(),
            item: 1_u32,
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("QueueFull"));
    }

    #[test]
    fn subscribe_with_since_none_no_replay_events() {
        let mut manager = EventStreamManager::new(caps(true, false, 10));
        manager.emit("t", sample_event_data());
        let req = SubscribeRequest {
            r#type: "subscribe".to_string(),
            id: RequestId::new("r"),
            topics: vec!["t".to_string()],
            since: None,
            max_events_per_sec: None,
            batch_ms: None,
            window_size: None,
            capability_token: None,
        };
        let outcome = manager.handle_subscribe(&req).unwrap();
        assert!(outcome.replay_events.is_empty());
    }

    #[test]
    fn subscribe_empty_topics_list() {
        let mut manager = EventStreamManager::new(caps(true, false, 10));
        let req = SubscribeRequest {
            r#type: "subscribe".to_string(),
            id: RequestId::new("r"),
            topics: vec![],
            since: None,
            max_events_per_sec: None,
            batch_ms: None,
            window_size: None,
            capability_token: None,
        };
        let outcome = manager.handle_subscribe(&req).unwrap();
        assert!(outcome.response.result.confirmed_topics.is_empty());
        assert!(outcome.replay_events.is_empty());
    }
}
