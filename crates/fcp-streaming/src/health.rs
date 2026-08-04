//! Streaming health state model.
//!
//! Defines health state transitions for long-lived streaming connections
//! (WebSocket, SSE, polling). The model tracks heartbeat liveness, reconnection
//! history, and maps to [`fcp_core::ConnectorHealth`] for external reporting.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Health state of a streaming connection.
///
/// State transitions:
/// ```text
/// Connected ──(missed heartbeat)──▶ Degraded
/// Connected ──(connection lost)───▶ Reconnecting
/// Degraded  ──(heartbeat received)─▶ Connected
/// Degraded  ──(zombie timeout)────▶ Unhealthy
/// Degraded  ──(connection lost)───▶ Reconnecting
/// Reconnecting ──(connected)──────▶ Connected
/// Reconnecting ──(max retries)────▶ Unhealthy
/// Unhealthy ──(manual reset)──────▶ Connected
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamHealthState {
    /// Connection is active and receiving data within expected intervals.
    Connected,
    /// Connection is active but heartbeats are overdue.
    Degraded,
    /// Connection was lost; reconnection is in progress.
    Reconnecting,
    /// Connection is dead — either zombie timeout or max retries exhausted.
    Unhealthy,
}

impl StreamHealthState {
    /// Whether the connection is usable for sending/receiving.
    #[must_use]
    pub const fn is_available(self) -> bool {
        matches!(self, Self::Connected | Self::Degraded)
    }

    /// Whether the connection needs operator attention.
    #[must_use]
    pub const fn needs_attention(self) -> bool {
        matches!(self, Self::Degraded | Self::Unhealthy)
    }
}

/// Configuration for streaming health evaluation.
#[derive(Debug, Clone)]
pub struct StreamHealthConfig {
    /// Duration after which a missing heartbeat triggers degraded state.
    pub heartbeat_timeout: Duration,
    /// Duration after which a degraded connection is declared unhealthy (zombie).
    pub zombie_timeout: Duration,
    /// Maximum consecutive reconnection attempts before declaring unhealthy.
    pub max_reconnect_attempts: u32,
}

impl Default for StreamHealthConfig {
    fn default() -> Self {
        Self {
            heartbeat_timeout: Duration::from_secs(env_or(
                "FCP_STREAMING_HEARTBEAT_TIMEOUT_SECS",
                30,
            )),
            zombie_timeout: Duration::from_secs(env_or("FCP_STREAMING_ZOMBIE_TIMEOUT_SECS", 120)),
            max_reconnect_attempts: env_or("FCP_STREAMING_MAX_RECONNECT_ATTEMPTS", 10),
        }
    }
}

/// Snapshot of streaming connection health at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamHealthSnapshot {
    /// Current health state.
    pub state: StreamHealthState,
    /// Milliseconds since the last heartbeat (or message) was received.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_heartbeat_ms_ago: Option<u64>,
    /// Milliseconds since the last acknowledgment was sent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_ack_ms_ago: Option<u64>,
    /// Consecutive reconnection attempts since the last healthy connection.
    pub reconnect_count: u32,
    /// Total messages received in the current session.
    pub messages_received: u64,
    /// Milliseconds the connection has been alive in the current connected span.
    pub uptime_ms: u64,
}

/// Mutable health tracker for a streaming connection.
///
/// Call [`record_heartbeat`](Self::record_heartbeat) on every received
/// message or heartbeat, and [`evaluate`](Self::evaluate) periodically
/// to drive state transitions.
#[derive(Debug)]
pub struct StreamHealthTracker {
    config: StreamHealthConfig,
    state: StreamHealthState,
    last_heartbeat: Option<Instant>,
    last_ack: Option<Instant>,
    reconnect_count: u32,
    messages_received: u64,
    connected_since: Option<Instant>,
}

impl StreamHealthTracker {
    /// Create a new tracker with the given configuration.
    #[must_use]
    pub fn new(config: StreamHealthConfig) -> Self {
        Self {
            config,
            state: StreamHealthState::Connected,
            last_heartbeat: None,
            last_ack: None,
            reconnect_count: 0,
            messages_received: 0,
            connected_since: Some(Instant::now()),
        }
    }

    /// Current health state.
    #[must_use]
    pub const fn state(&self) -> StreamHealthState {
        self.state
    }

    /// Record that a heartbeat (or any meaningful message) was received.
    pub fn record_heartbeat(&mut self) {
        self.last_heartbeat = Some(Instant::now());
        // br-upgdb: saturating_add matches the existing reconnect_count
        // discipline on line 148. Wrapping at u64::MAX would break
        // monotonic-counter health telemetry after counter exhaustion.
        self.messages_received = self.messages_received.saturating_add(1);
        // Heartbeat receipt can promote Degraded back to Connected.
        if self.state == StreamHealthState::Degraded {
            self.state = StreamHealthState::Connected;
        }
    }

    /// Record that an acknowledgment was sent upstream.
    pub fn record_ack(&mut self) {
        self.last_ack = Some(Instant::now());
    }

    /// Record that the connection was lost and reconnection started.
    pub const fn record_disconnect(&mut self) {
        self.reconnect_count = self.reconnect_count.saturating_add(1);
        self.connected_since = None;
        if self.reconnect_count >= self.config.max_reconnect_attempts {
            self.state = StreamHealthState::Unhealthy;
        } else {
            self.state = StreamHealthState::Reconnecting;
        }
    }

    /// Record that reconnection succeeded.
    pub fn record_reconnected(&mut self) {
        self.state = StreamHealthState::Connected;
        self.reconnect_count = 0;
        self.connected_since = Some(Instant::now());
        self.last_heartbeat = Some(Instant::now());
    }

    /// Reset the tracker to a healthy connected state (e.g., after manual intervention).
    pub fn reset(&mut self) {
        self.state = StreamHealthState::Connected;
        self.reconnect_count = 0;
        self.connected_since = Some(Instant::now());
        self.last_heartbeat = Some(Instant::now());
    }

    /// Timestamp the timeouts are measured from: the last heartbeat if one
    /// has ever arrived, otherwise the moment the connection came up.
    ///
    /// `TrackerBuilder::new` starts in `Connected` with `last_heartbeat =
    /// None`, so keying the timeouts off `last_heartbeat` alone meant a peer
    /// that completed the handshake and then went permanently silent never
    /// left `Connected`: `state().is_available()` stayed `true` and
    /// `to_connector_health()` reported `Healthy` forever. That is exactly the
    /// zombie connection `zombie_timeout` exists to catch, and it applied to
    /// the first connection of every tracker — the one an adversarial peer
    /// controls. Falling back to `connected_since` closes the hole while
    /// leaving post-reconnect behaviour unchanged (`record_reconnected` and
    /// `reset` both stamp `last_heartbeat`).
    const fn liveness_baseline(&self) -> Option<Instant> {
        match self.last_heartbeat {
            Some(last) => Some(last),
            None => self.connected_since,
        }
    }

    /// Evaluate health based on elapsed time since the last liveness signal.
    ///
    /// Call this periodically (e.g., on a timer or before returning health status).
    /// Drives the state transitions:
    /// - Connected → Degraded (heartbeat overdue)
    /// - Degraded → Unhealthy (zombie timeout)
    pub fn evaluate(&mut self) -> StreamHealthState {
        let now = Instant::now();

        match self.state {
            StreamHealthState::Connected => {
                if let Some(last) = self.liveness_baseline() {
                    if now.duration_since(last) > self.config.heartbeat_timeout {
                        self.state = StreamHealthState::Degraded;
                    }
                }
            }
            StreamHealthState::Degraded => {
                if let Some(last) = self.liveness_baseline() {
                    if now.duration_since(last) > self.config.zombie_timeout {
                        self.state = StreamHealthState::Unhealthy;
                    }
                }
            }
            StreamHealthState::Reconnecting | StreamHealthState::Unhealthy => {
                // No automatic transitions out of these states — requires
                // record_reconnected() or reset().
            }
        }

        self.state
    }

    /// Produce a snapshot of the current health state.
    #[must_use]
    pub fn snapshot(&self) -> StreamHealthSnapshot {
        let now = Instant::now();
        StreamHealthSnapshot {
            state: self.state,
            last_heartbeat_ms_ago: self.last_heartbeat.map(|t| millis_since(now, t)),
            last_ack_ms_ago: self.last_ack.map(|t| millis_since(now, t)),
            reconnect_count: self.reconnect_count,
            messages_received: self.messages_received,
            uptime_ms: self.connected_since.map_or(0, |t| millis_since(now, t)),
        }
    }

    /// Map the current streaming health to the core `ConnectorHealth` enum.
    #[must_use]
    pub fn to_connector_health(&self) -> fcp_core::ConnectorHealth {
        let now = Instant::now();
        match self.state {
            StreamHealthState::Connected => fcp_core::ConnectorHealth::Healthy,
            StreamHealthState::Degraded => fcp_core::ConnectorHealth::Degraded {
                reason: format!(
                    "heartbeat overdue ({}ms)",
                    self.last_heartbeat.map_or(0, |t| millis_since(now, t))
                ),
            },
            StreamHealthState::Reconnecting => fcp_core::ConnectorHealth::Degraded {
                reason: format!("reconnecting (attempt {})", self.reconnect_count),
            },
            StreamHealthState::Unhealthy => fcp_core::ConnectorHealth::Unavailable {
                reason: "streaming connection dead".into(),
                since: chrono::Utc::now(),
            },
        }
    }
}

/// Parse an environment variable, falling back to a default if unset or unparseable.
fn env_or<T: std::str::FromStr>(var: &str, default: T) -> T {
    std::env::var(var)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Convert a duration between two instants to milliseconds, saturating at `u64::MAX`.
fn millis_since(now: Instant, earlier: Instant) -> u64 {
    u64::try_from(now.duration_since(earlier).as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_tracker() -> StreamHealthTracker {
        StreamHealthTracker::new(StreamHealthConfig::default())
    }

    fn fast_tracker() -> StreamHealthTracker {
        StreamHealthTracker::new(StreamHealthConfig {
            heartbeat_timeout: Duration::from_millis(50),
            zombie_timeout: Duration::from_millis(200),
            max_reconnect_attempts: 3,
        })
    }

    // ── Initial state ────────────────────────────────────────────────

    #[test]
    fn initial_state_is_connected() {
        let tracker = default_tracker();
        assert_eq!(tracker.state(), StreamHealthState::Connected);
    }

    #[test]
    fn initial_snapshot_has_zero_messages() {
        let tracker = default_tracker();
        let snap = tracker.snapshot();
        assert_eq!(snap.messages_received, 0);
        assert_eq!(snap.reconnect_count, 0);
        assert_eq!(snap.state, StreamHealthState::Connected);
    }

    #[test]
    fn initial_snapshot_has_uptime() {
        let tracker = default_tracker();
        let snap = tracker.snapshot();
        assert!(snap.uptime_ms < 100); // should be near-zero
    }

    #[test]
    fn initial_last_heartbeat_is_none() {
        let tracker = default_tracker();
        let snap = tracker.snapshot();
        assert!(snap.last_heartbeat_ms_ago.is_none());
    }

    #[test]
    fn initial_last_ack_is_none() {
        let tracker = default_tracker();
        let snap = tracker.snapshot();
        assert!(snap.last_ack_ms_ago.is_none());
    }

    // ── Heartbeat recording ──────────────────────────────────────────

    #[test]
    fn heartbeat_increments_message_count() {
        let mut tracker = default_tracker();
        tracker.record_heartbeat();
        tracker.record_heartbeat();
        tracker.record_heartbeat();
        assert_eq!(tracker.snapshot().messages_received, 3);
    }

    #[test]
    fn heartbeat_messages_received_saturates_at_u64_max() {
        // br-upgdb: prior to the fix, record_heartbeat used `+= 1`
        // which wraps at u64::MAX in release builds, breaking
        // monotonic-counter health telemetry. saturating_add now
        // pins the counter at u64::MAX. Same discipline as
        // reconnect_count (line 148).
        let mut tracker = default_tracker();
        // Private-field access is permitted within the same module.
        tracker.messages_received = u64::MAX;
        tracker.record_heartbeat();
        assert_eq!(
            tracker.snapshot().messages_received,
            u64::MAX,
            "messages_received must saturate at u64::MAX, not wrap to 0"
        );
        // Subsequent heartbeats also stay pinned.
        tracker.record_heartbeat();
        assert_eq!(tracker.snapshot().messages_received, u64::MAX);
    }

    #[test]
    fn heartbeat_sets_last_heartbeat() {
        let mut tracker = default_tracker();
        tracker.record_heartbeat();
        let snap = tracker.snapshot();
        assert!(snap.last_heartbeat_ms_ago.is_some());
        assert!(snap.last_heartbeat_ms_ago.unwrap() < 100);
    }

    #[test]
    fn ack_sets_last_ack() {
        let mut tracker = default_tracker();
        tracker.record_ack();
        let snap = tracker.snapshot();
        assert!(snap.last_ack_ms_ago.is_some());
        assert!(snap.last_ack_ms_ago.unwrap() < 100);
    }

    // ── State transitions: Connected → Degraded ──────────────────────

    #[test]
    fn missed_heartbeat_degrades() {
        let mut tracker = fast_tracker();
        tracker.record_heartbeat();
        std::thread::sleep(Duration::from_millis(80));
        let state = tracker.evaluate();
        assert_eq!(state, StreamHealthState::Degraded);
    }

    #[test]
    fn silent_first_connection_degrades_then_goes_unhealthy() {
        // A peer that completes the handshake and then never sends anything is
        // exactly the zombie `zombie_timeout` exists to catch. Because the
        // tracker starts `Connected` with `last_heartbeat = None`, keying the
        // timeouts off `last_heartbeat` alone left it reporting Healthy
        // forever — on the one connection an adversarial peer controls. The
        // timeouts now fall back to `connected_since`.
        let mut tracker = fast_tracker();
        assert_eq!(tracker.evaluate(), StreamHealthState::Connected);

        std::thread::sleep(Duration::from_millis(80));
        assert_eq!(tracker.evaluate(), StreamHealthState::Degraded);
        assert!(!matches!(
            tracker.to_connector_health(),
            fcp_core::ConnectorHealth::Healthy
        ));

        std::thread::sleep(Duration::from_millis(160));
        assert_eq!(tracker.evaluate(), StreamHealthState::Unhealthy);
        assert!(!tracker.state().is_available());
    }

    // ── State transitions: Degraded → Connected (recovery) ──────────

    #[test]
    fn heartbeat_recovers_from_degraded() {
        let mut tracker = fast_tracker();
        tracker.record_heartbeat();
        std::thread::sleep(Duration::from_millis(80));
        tracker.evaluate();
        assert_eq!(tracker.state(), StreamHealthState::Degraded);

        tracker.record_heartbeat();
        assert_eq!(tracker.state(), StreamHealthState::Connected);
    }

    // ── State transitions: Degraded → Unhealthy (zombie) ─────────────

    #[test]
    fn zombie_timeout_makes_unhealthy() {
        let mut tracker = fast_tracker();
        tracker.record_heartbeat();
        std::thread::sleep(Duration::from_millis(80));
        tracker.evaluate();
        assert_eq!(tracker.state(), StreamHealthState::Degraded);

        std::thread::sleep(Duration::from_millis(170));
        let state = tracker.evaluate();
        assert_eq!(state, StreamHealthState::Unhealthy);
    }

    // ── State transitions: disconnect / reconnect ────────────────────

    #[test]
    fn disconnect_transitions_to_reconnecting() {
        let mut tracker = default_tracker();
        tracker.record_disconnect();
        assert_eq!(tracker.state(), StreamHealthState::Reconnecting);
        assert_eq!(tracker.snapshot().reconnect_count, 1);
    }

    #[test]
    fn reconnect_transitions_to_connected() {
        let mut tracker = default_tracker();
        tracker.record_disconnect();
        tracker.record_reconnected();
        assert_eq!(tracker.state(), StreamHealthState::Connected);
        assert_eq!(tracker.snapshot().reconnect_count, 0);
    }

    #[test]
    fn max_reconnect_attempts_makes_unhealthy() {
        let mut tracker = fast_tracker(); // max_reconnect_attempts = 3
        tracker.record_disconnect(); // 1
        tracker.record_disconnect(); // 2
        assert_eq!(tracker.state(), StreamHealthState::Reconnecting);
        tracker.record_disconnect(); // 3 >= 3
        assert_eq!(tracker.state(), StreamHealthState::Unhealthy);
    }

    #[test]
    fn zero_max_reconnect_attempts_fails_first_disconnect() {
        let mut tracker = StreamHealthTracker::new(StreamHealthConfig {
            heartbeat_timeout: Duration::from_millis(50),
            zombie_timeout: Duration::from_millis(200),
            max_reconnect_attempts: 0,
        });

        tracker.record_disconnect();

        assert_eq!(tracker.state(), StreamHealthState::Unhealthy);
        assert_eq!(tracker.snapshot().reconnect_count, 1);
    }

    #[test]
    fn successful_reconnect_resets_reconnect_count() {
        let mut tracker = default_tracker();
        tracker.record_disconnect();
        assert_eq!(tracker.snapshot().reconnect_count, 1);

        tracker.record_reconnected();
        assert_eq!(tracker.snapshot().reconnect_count, 0);
    }

    #[test]
    fn disconnect_clears_connected_since() {
        let mut tracker = default_tracker();
        tracker.record_disconnect();
        assert_eq!(tracker.snapshot().uptime_ms, 0);
    }

    #[test]
    fn reconnect_restores_uptime() {
        let mut tracker = default_tracker();
        tracker.record_disconnect();
        tracker.record_reconnected();
        let snap = tracker.snapshot();
        assert!(snap.uptime_ms < 100);
    }

    // ── Reset ────────────────────────────────────────────────────────

    #[test]
    fn reset_clears_reconnect_count() {
        let mut tracker = default_tracker();
        tracker.record_disconnect();
        tracker.record_disconnect();
        tracker.reset();
        assert_eq!(tracker.state(), StreamHealthState::Connected);
        assert_eq!(tracker.snapshot().reconnect_count, 0);
    }

    #[test]
    fn reset_from_unhealthy_to_connected() {
        let mut tracker = fast_tracker();
        // Force unhealthy via max reconnects
        for _ in 0..5 {
            tracker.record_disconnect();
        }
        assert_eq!(tracker.state(), StreamHealthState::Unhealthy);
        tracker.reset();
        assert_eq!(tracker.state(), StreamHealthState::Connected);
    }

    // ── StreamHealthState methods ────────────────────────────────────

    #[test]
    fn connected_is_available() {
        assert!(StreamHealthState::Connected.is_available());
    }

    #[test]
    fn degraded_is_available() {
        assert!(StreamHealthState::Degraded.is_available());
    }

    #[test]
    fn reconnecting_is_not_available() {
        assert!(!StreamHealthState::Reconnecting.is_available());
    }

    #[test]
    fn unhealthy_is_not_available() {
        assert!(!StreamHealthState::Unhealthy.is_available());
    }

    #[test]
    fn connected_does_not_need_attention() {
        assert!(!StreamHealthState::Connected.needs_attention());
    }

    #[test]
    fn degraded_needs_attention() {
        assert!(StreamHealthState::Degraded.needs_attention());
    }

    #[test]
    fn unhealthy_needs_attention() {
        assert!(StreamHealthState::Unhealthy.needs_attention());
    }

    #[test]
    fn reconnecting_does_not_need_attention() {
        // Reconnecting is transient — it's handled by the reconnect loop, not operators.
        assert!(!StreamHealthState::Reconnecting.needs_attention());
    }

    // ── ConnectorHealth mapping ──────────────────────────────────────

    #[test]
    fn connected_maps_to_healthy() {
        let tracker = default_tracker();
        assert!(matches!(
            tracker.to_connector_health(),
            fcp_core::ConnectorHealth::Healthy
        ));
    }

    #[test]
    fn degraded_maps_to_degraded() {
        let mut tracker = fast_tracker();
        tracker.record_heartbeat();
        std::thread::sleep(Duration::from_millis(80));
        tracker.evaluate();
        assert!(matches!(
            tracker.to_connector_health(),
            fcp_core::ConnectorHealth::Degraded { .. }
        ));
    }

    #[test]
    fn reconnecting_maps_to_degraded() {
        let mut tracker = default_tracker();
        tracker.record_disconnect();
        assert!(matches!(
            tracker.to_connector_health(),
            fcp_core::ConnectorHealth::Degraded { .. }
        ));
    }

    #[test]
    fn unhealthy_maps_to_unavailable() {
        let mut tracker = fast_tracker();
        for _ in 0..5 {
            tracker.record_disconnect();
        }
        assert!(matches!(
            tracker.to_connector_health(),
            fcp_core::ConnectorHealth::Unavailable { .. }
        ));
    }

    // ── Serialization ────────────────────────────────────────────────

    #[test]
    fn snapshot_serializes_to_json() {
        let mut tracker = default_tracker();
        tracker.record_heartbeat();
        tracker.record_ack();
        let snap = tracker.snapshot();
        let json = serde_json::to_string(&snap).unwrap();
        assert!(json.contains("\"state\":\"connected\""));
        assert!(json.contains("\"messages_received\":1"));
    }

    #[test]
    fn state_serializes_correctly() {
        assert_eq!(
            serde_json::to_string(&StreamHealthState::Connected).unwrap(),
            "\"connected\""
        );
        assert_eq!(
            serde_json::to_string(&StreamHealthState::Degraded).unwrap(),
            "\"degraded\""
        );
        assert_eq!(
            serde_json::to_string(&StreamHealthState::Reconnecting).unwrap(),
            "\"reconnecting\""
        );
        assert_eq!(
            serde_json::to_string(&StreamHealthState::Unhealthy).unwrap(),
            "\"unhealthy\""
        );
    }

    #[test]
    fn state_deserializes_correctly() {
        let s: StreamHealthState = serde_json::from_str("\"degraded\"").unwrap();
        assert_eq!(s, StreamHealthState::Degraded);
    }

    #[test]
    fn snapshot_omits_none_fields() {
        let tracker = default_tracker();
        let json = serde_json::to_string(&tracker.snapshot()).unwrap();
        assert!(!json.contains("last_heartbeat_ms_ago"));
        assert!(!json.contains("last_ack_ms_ago"));
    }

    // ── Config ───────────────────────────────────────────────────────

    #[test]
    fn default_config_values() {
        let config = StreamHealthConfig::default();
        assert_eq!(config.heartbeat_timeout, Duration::from_secs(30));
        assert_eq!(config.zombie_timeout, Duration::from_secs(120));
        assert_eq!(config.max_reconnect_attempts, 10);
    }

    #[test]
    fn zombie_timeout_greater_than_heartbeat_timeout() {
        let config = StreamHealthConfig::default();
        assert!(config.zombie_timeout > config.heartbeat_timeout);
    }

    // ── Edge cases ───────────────────────────────────────────────────

    #[test]
    fn evaluate_from_unhealthy_stays_unhealthy() {
        let mut tracker = fast_tracker();
        for _ in 0..5 {
            tracker.record_disconnect();
        }
        assert_eq!(tracker.evaluate(), StreamHealthState::Unhealthy);
        assert_eq!(tracker.evaluate(), StreamHealthState::Unhealthy);
    }

    #[test]
    fn evaluate_from_reconnecting_stays_reconnecting() {
        let mut tracker = default_tracker();
        tracker.record_disconnect();
        assert_eq!(tracker.evaluate(), StreamHealthState::Reconnecting);
    }

    #[test]
    fn multiple_heartbeats_keep_connected() {
        let mut tracker = fast_tracker();
        for _ in 0..10 {
            tracker.record_heartbeat();
            assert_eq!(tracker.evaluate(), StreamHealthState::Connected);
        }
    }

    #[test]
    fn messages_received_persists_across_reconnects() {
        let mut tracker = default_tracker();
        tracker.record_heartbeat();
        tracker.record_heartbeat();
        tracker.record_disconnect();
        tracker.record_reconnected();
        tracker.record_heartbeat();
        assert_eq!(tracker.snapshot().messages_received, 3);
    }

    // ── Simulated streaming loop ─────────────────────────────────────
    //
    // These tests drive the tracker through realistic multi-phase
    // lifecycles to verify deterministic end-to-end behavior.

    #[test]
    fn simulated_healthy_session() {
        // Simulate a perfectly healthy session: connect, receive N messages, shutdown.
        let mut tracker = fast_tracker();

        // Phase 1: receive steady heartbeats
        for i in 0..20 {
            tracker.record_heartbeat();
            assert_eq!(
                tracker.evaluate(),
                StreamHealthState::Connected,
                "should stay connected on heartbeat {i}"
            );
        }

        let snap = tracker.snapshot();
        assert_eq!(snap.state, StreamHealthState::Connected);
        assert_eq!(snap.messages_received, 20);
        assert_eq!(snap.reconnect_count, 0);
        assert!(snap.last_heartbeat_ms_ago.is_some());
        // uptime_ms may be 0 if the loop ran faster than 1ms; just check it's present
        let _ = snap.uptime_ms;
    }

    #[test]
    fn simulated_degrade_and_recovery() {
        // Simulate: connect → heartbeats → miss → degrade → heartbeat → recover.
        let mut tracker = fast_tracker();

        // Phase 1: healthy
        tracker.record_heartbeat();
        assert_eq!(tracker.evaluate(), StreamHealthState::Connected);

        // Phase 2: miss heartbeat
        std::thread::sleep(Duration::from_millis(80));
        assert_eq!(tracker.evaluate(), StreamHealthState::Degraded);

        // Snapshot during degradation
        let snap = tracker.snapshot();
        assert_eq!(snap.state, StreamHealthState::Degraded);
        assert!(snap.last_heartbeat_ms_ago.unwrap() >= 50);

        // Phase 3: heartbeat arrives → recovery
        tracker.record_heartbeat();
        assert_eq!(tracker.state(), StreamHealthState::Connected);
        assert_eq!(tracker.evaluate(), StreamHealthState::Connected);

        let snap = tracker.snapshot();
        assert_eq!(snap.messages_received, 2);
    }

    #[test]
    fn simulated_disconnect_reconnect_cycle() {
        // Simulate: connect → disconnect → reconnect → healthy → disconnect → reconnect.
        let mut tracker = fast_tracker(); // max_reconnect_attempts = 3

        tracker.record_heartbeat();
        assert_eq!(tracker.state(), StreamHealthState::Connected);

        // First disconnect/reconnect cycle
        tracker.record_disconnect();
        assert_eq!(tracker.state(), StreamHealthState::Reconnecting);
        assert_eq!(tracker.snapshot().reconnect_count, 1);
        assert_eq!(tracker.snapshot().uptime_ms, 0);

        tracker.record_reconnected();
        assert_eq!(tracker.state(), StreamHealthState::Connected);

        // Continue receiving messages
        tracker.record_heartbeat();
        tracker.record_heartbeat();

        // Second disconnect/reconnect cycle
        tracker.record_disconnect();
        assert_eq!(tracker.snapshot().reconnect_count, 1);
        tracker.record_reconnected();

        // Still healthy
        tracker.record_heartbeat();
        assert_eq!(tracker.evaluate(), StreamHealthState::Connected);
        assert_eq!(tracker.snapshot().messages_received, 4);
    }

    #[test]
    fn simulated_zombie_death() {
        // Simulate: connect → heartbeats → miss → degrade → zombie timeout → unhealthy.
        let mut tracker = fast_tracker();

        // Phase 1: healthy with heartbeats
        tracker.record_heartbeat();
        assert_eq!(tracker.evaluate(), StreamHealthState::Connected);

        // Phase 2: miss heartbeat → degrade
        std::thread::sleep(Duration::from_millis(80));
        assert_eq!(tracker.evaluate(), StreamHealthState::Degraded);

        // Phase 3: still no heartbeat → zombie
        std::thread::sleep(Duration::from_millis(170));
        assert_eq!(tracker.evaluate(), StreamHealthState::Unhealthy);

        // Verify it stays unhealthy
        assert_eq!(tracker.evaluate(), StreamHealthState::Unhealthy);

        // Verify connector health mapping
        assert!(matches!(
            tracker.to_connector_health(),
            fcp_core::ConnectorHealth::Unavailable { .. }
        ));
    }

    #[test]
    fn simulated_max_reconnects_exhaustion() {
        // Simulate: repeated reconnect attempts exceeding max_reconnect_attempts.
        let mut tracker = fast_tracker(); // max = 3

        // Disconnect until the reconnect budget is exhausted.
        tracker.record_disconnect(); // 1 → Reconnecting
        assert_eq!(tracker.state(), StreamHealthState::Reconnecting);

        tracker.record_disconnect(); // 2 → Reconnecting
        assert_eq!(tracker.state(), StreamHealthState::Reconnecting);

        tracker.record_disconnect(); // 3 >= max(3) → Unhealthy
        assert_eq!(tracker.state(), StreamHealthState::Unhealthy);

        // Manual reset recovers
        tracker.reset();
        assert_eq!(tracker.state(), StreamHealthState::Connected);
        assert_eq!(tracker.snapshot().reconnect_count, 0);
    }

    #[test]
    fn simulated_full_lifecycle() {
        // Full lifecycle: connect → messages → degrade → recover → disconnect →
        // reconnect → messages → zombie → reset → healthy.
        let mut tracker = fast_tracker();

        // 1. Connected: receive messages
        for _ in 0..5 {
            tracker.record_heartbeat();
        }
        tracker.record_ack();
        assert_eq!(tracker.evaluate(), StreamHealthState::Connected);
        let snap = tracker.snapshot();
        assert_eq!(snap.messages_received, 5);
        assert!(snap.last_ack_ms_ago.is_some());

        // 2. Degrade: miss heartbeat
        std::thread::sleep(Duration::from_millis(80));
        assert_eq!(tracker.evaluate(), StreamHealthState::Degraded);

        // 3. Recover: heartbeat arrives
        tracker.record_heartbeat();
        assert_eq!(tracker.state(), StreamHealthState::Connected);

        // 4. Disconnect
        tracker.record_disconnect();
        assert_eq!(tracker.state(), StreamHealthState::Reconnecting);

        // 5. Reconnect
        tracker.record_reconnected();
        assert_eq!(tracker.state(), StreamHealthState::Connected);

        // 6. More messages
        tracker.record_heartbeat();
        tracker.record_heartbeat();

        // 7. Zombie: miss heartbeat past zombie timeout
        std::thread::sleep(Duration::from_millis(80));
        tracker.evaluate();
        std::thread::sleep(Duration::from_millis(170));
        assert_eq!(tracker.evaluate(), StreamHealthState::Unhealthy);

        // 8. Reset
        tracker.reset();
        assert_eq!(tracker.state(), StreamHealthState::Connected);

        // Final snapshot
        let snap = tracker.snapshot();
        assert_eq!(snap.state, StreamHealthState::Connected);
        assert_eq!(snap.messages_received, 8); // 5 + 1 + 2
        assert_eq!(snap.reconnect_count, 0); // reset clears this
    }

    #[test]
    fn simulated_snapshot_fields_at_each_stage() {
        // Verify snapshot fields are correct at each lifecycle stage.
        let mut tracker = fast_tracker();

        // Stage 1: Fresh connected
        let snap = tracker.snapshot();
        assert_eq!(snap.state, StreamHealthState::Connected);
        assert!(snap.last_heartbeat_ms_ago.is_none());
        assert!(snap.last_ack_ms_ago.is_none());
        assert_eq!(snap.reconnect_count, 0);
        assert_eq!(snap.messages_received, 0);

        // Stage 2: After heartbeat + ack
        tracker.record_heartbeat();
        tracker.record_ack();
        let snap = tracker.snapshot();
        assert!(snap.last_heartbeat_ms_ago.unwrap() < 50);
        assert!(snap.last_ack_ms_ago.unwrap() < 50);
        assert_eq!(snap.messages_received, 1);

        // Stage 3: After disconnect
        tracker.record_disconnect();
        let snap = tracker.snapshot();
        assert_eq!(snap.state, StreamHealthState::Reconnecting);
        assert_eq!(snap.reconnect_count, 1);
        assert_eq!(snap.uptime_ms, 0); // no active connection

        // Stage 4: After reconnect
        tracker.record_reconnected();
        let snap = tracker.snapshot();
        assert_eq!(snap.state, StreamHealthState::Connected);
        assert!(snap.uptime_ms < 50); // just reconnected
        assert_eq!(snap.reconnect_count, 0);
    }
}
