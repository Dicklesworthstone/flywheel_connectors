//! Transport-only peer circuit state. The admission mutex owns this book.
//!
//! A verified reply proves transport health even when the operation failed.
//! A circuit never rewrites the outcome of an already-sent request. It only
//! refuses later, not-yet-delivered forwards. Advertisements and HTTP status
//! alone are not authenticated evidence that the invoke path is healthy.
//! Retained peer history is bounded even when signed membership keeps rotating
//! through new node IDs. Capacity pressure never evicts a live ticket or probe.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

const FAILURE_THRESHOLD: u8 = 3;
const BASE_COOLDOWN: Duration = Duration::from_secs(5);
const MAX_COOLDOWN: Duration = Duration::from_secs(30);
const MAX_TRACKED_PEERS: usize = 16_384;
const IDLE_HISTORY_RETENTION: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Clone, Copy)]
pub(super) enum ForwardOutcome {
    AuthenticatedReply,
    Unavailable,
    InvalidReply,
}

#[derive(Debug, Clone, Copy)]
enum Mode {
    Closed,
    Open { retry_at: Instant },
    Probe,
}

#[derive(Debug)]
struct PeerCircuit {
    mode: Mode,
    failures: u8,
    cooldown: Duration,
    // Identity, not a wrapping integer counter. In-flight tickets retain
    // their generation, so an old allocation cannot be reused underneath one.
    generation: Arc<()>,
    // Independent of generation: opening a circuit must not make tickets from
    // the previous generation invisible to capacity reclamation. Every ticket
    // pins this identity until its owning forward has finished dropping.
    activity: Arc<()>,
    last_activity: Instant,
}

impl PeerCircuit {
    fn new(now: Instant) -> Self {
        Self {
            mode: Mode::Closed,
            failures: 0,
            cooldown: BASE_COOLDOWN,
            generation: Arc::new(()),
            activity: Arc::new(()),
            last_activity: now,
        }
    }

    fn reclaimable(&self, now: Instant) -> bool {
        if Arc::strong_count(&self.activity) != 1 {
            return false;
        }
        match self.mode {
            Mode::Probe => false,
            Mode::Closed if self.failures == 0 => true,
            Mode::Open { retry_at } if now < retry_at => false,
            Mode::Closed | Mode::Open { .. } => {
                now.saturating_duration_since(self.last_activity) >= IDLE_HISTORY_RETENTION
            }
        }
    }

    fn open(&mut self, now: Instant, reason: &'static str) -> CircuitTransition {
        self.generation = Arc::new(());
        self.mode = Mode::Open {
            retry_at: now + self.cooldown,
        };
        CircuitTransition {
            state: "open",
            reason,
            cooldown_ms: u64::try_from(self.cooldown.as_millis()).unwrap_or(u64::MAX),
        }
    }
}

#[derive(Debug)]
pub(super) struct CircuitTicket {
    generation: Arc<()>,
    activity: Arc<()>,
    probe: bool,
}

#[derive(Debug)]
pub(super) struct CircuitTransition {
    pub(super) state: &'static str,
    pub(super) reason: &'static str,
    pub(super) cooldown_ms: u64,
}

#[derive(Debug)]
pub(super) struct CircuitBook {
    // Only directory-resolved peers reach the transport admission path.
    // Membership churn can still introduce unlimited distinct node IDs over
    // time, so directory size alone is not a bound on retained circuit state.
    peers: BTreeMap<String, PeerCircuit>,
    capacity: usize,
}

impl Default for CircuitBook {
    fn default() -> Self {
        Self {
            peers: BTreeMap::new(),
            capacity: MAX_TRACKED_PEERS,
        }
    }
}

impl CircuitBook {
    /// Call only after all resource ceilings have passed. A refused resource
    /// reservation must not consume the sole recovery-probe ticket.
    pub(super) fn reserve(
        &mut self,
        peer: &str,
        now: Instant,
    ) -> Result<CircuitTicket, &'static str> {
        if !self.peers.contains_key(peer) && self.peers.len() >= self.capacity {
            // Scan only at capacity for a new identity; established peers keep
            // logarithmic admission. Never discard a cooldown to create room.
            // Oldest reclaimable history wins, with node-id order breaking ties.
            let victim = self
                .peers
                .iter()
                .filter(|(_, circuit)| circuit.reclaimable(now))
                .min_by_key(|(_, circuit)| circuit.last_activity)
                .map(|(node_id, _)| node_id.clone())
                .ok_or("peer_circuit_capacity")?;
            self.peers.remove(&victim);
        }
        let circuit = self
            .peers
            .entry(peer.to_owned())
            .or_insert_with(|| PeerCircuit::new(now));
        let probe = match circuit.mode {
            Mode::Closed => false,
            Mode::Open { retry_at } if now >= retry_at => true,
            Mode::Open { .. } => return Err("peer_circuit_open"),
            Mode::Probe => return Err("peer_recovery_probe_in_flight"),
        };
        if probe {
            circuit.mode = Mode::Probe;
        }
        // Concurrent callers can sample their clocks before acquiring the
        // admission mutex, so observations need not arrive in time order.
        circuit.last_activity = circuit.last_activity.max(now);
        Ok(CircuitTicket {
            generation: Arc::clone(&circuit.generation),
            activity: Arc::clone(&circuit.activity),
            probe,
        })
    }

    /// Complete a ticket, or abandon it on cancellation/panic (`None`).
    /// Old-generation completions never alter a newer circuit decision.
    pub(super) fn complete(
        &mut self,
        peer: &str,
        ticket: &CircuitTicket,
        outcome: Option<ForwardOutcome>,
        now: Instant,
    ) -> Option<CircuitTransition> {
        let circuit = self.peers.get_mut(peer)?;
        if !Arc::ptr_eq(&circuit.activity, &ticket.activity) {
            return None;
        }
        circuit.last_activity = circuit.last_activity.max(now);
        if !Arc::ptr_eq(&circuit.generation, &ticket.generation) {
            return None;
        }
        match outcome {
            Some(ForwardOutcome::AuthenticatedReply) => {
                circuit.mode = Mode::Closed;
                circuit.failures = 0;
                circuit.cooldown = BASE_COOLDOWN;
                ticket.probe.then_some(CircuitTransition {
                    state: "closed",
                    reason: "authenticated_recovery_reply",
                    cooldown_ms: 0,
                })
            }
            Some(outcome) => {
                circuit.failures = circuit.failures.saturating_add(1);
                if ticket.probe {
                    circuit.cooldown = circuit.cooldown.saturating_mul(2).min(MAX_COOLDOWN);
                }
                let invalid = matches!(outcome, ForwardOutcome::InvalidReply);
                if invalid {
                    // Do not keep sending operations to a peer that cannot
                    // authenticate its reply, even before three failures.
                    circuit.cooldown = MAX_COOLDOWN;
                }
                if invalid || ticket.probe || circuit.failures >= FAILURE_THRESHOLD {
                    let reason = if invalid {
                        "unauthenticated_reply"
                    } else if ticket.probe {
                        "recovery_probe_failed"
                    } else {
                        "consecutive_transport_failures"
                    };
                    Some(circuit.open(now, reason))
                } else {
                    None
                }
            }
            None if ticket.probe => {
                // Cancellation is not peer-failure evidence. Release the
                // probe slot without escalating backoff or claiming recovery.
                Some(circuit.open(now, "recovery_probe_cancelled"))
            }
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fail_three(book: &mut CircuitBook, peer: &str, now: Instant) {
        for index in 0..3 {
            let ticket = book.reserve(peer, now).unwrap();
            let transition = book.complete(peer, &ticket, Some(ForwardOutcome::Unavailable), now);
            assert_eq!(transition.is_some(), index == 2);
        }
    }

    #[test]
    fn consecutive_failures_open_and_only_one_probe_can_recover() {
        let mut book = CircuitBook::default();
        let now = Instant::now();
        fail_three(&mut book, "a", now);
        assert_eq!(book.reserve("a", now).unwrap_err(), "peer_circuit_open");
        assert!(
            book.reserve("a", now + BASE_COOLDOWN - Duration::from_nanos(1))
                .is_err()
        );
        let probe = book.reserve("a", now + BASE_COOLDOWN).unwrap();
        assert_eq!(
            book.reserve("a", now + BASE_COOLDOWN).unwrap_err(),
            "peer_recovery_probe_in_flight"
        );
        let recovered = book
            .complete(
                "a",
                &probe,
                Some(ForwardOutcome::AuthenticatedReply),
                now + BASE_COOLDOWN,
            )
            .unwrap();
        assert_eq!(recovered.state, "closed");
        assert!(book.reserve("a", now + BASE_COOLDOWN).is_ok());
    }

    #[test]
    fn one_peer_outage_does_not_trip_another_peer() {
        let mut book = CircuitBook::default();
        let now = Instant::now();
        fail_three(&mut book, "a", now);
        let b = book.reserve("b", now).unwrap();
        assert!(
            book.complete("b", &b, Some(ForwardOutcome::AuthenticatedReply), now)
                .is_none()
        );
        assert!(book.reserve("a", now).is_err());
        assert!(book.reserve("b", now).is_ok());
    }

    #[test]
    fn healthy_reply_resets_consecutive_failures() {
        let mut book = CircuitBook::default();
        let now = Instant::now();
        for _ in 0..2 {
            let ticket = book.reserve("a", now).unwrap();
            assert!(
                book.complete("a", &ticket, Some(ForwardOutcome::Unavailable), now)
                    .is_none()
            );
        }
        let ticket = book.reserve("a", now).unwrap();
        assert!(
            book.complete("a", &ticket, Some(ForwardOutcome::AuthenticatedReply), now)
                .is_none()
        );
        fail_three(&mut book, "a", now);
    }

    #[test]
    fn failed_probes_back_off_but_never_exceed_the_ceiling() {
        let mut book = CircuitBook::default();
        let mut now = Instant::now();
        fail_three(&mut book, "a", now);
        let mut previous = BASE_COOLDOWN;
        for seconds in [10, 20, 30, 30, 30] {
            now += previous;
            let ticket = book.reserve("a", now).unwrap();
            let transition = book
                .complete("a", &ticket, Some(ForwardOutcome::Unavailable), now)
                .unwrap();
            previous = Duration::from_secs(seconds);
            assert_eq!(transition.cooldown_ms, seconds * 1000);
            assert!(
                book.reserve("a", now + previous - Duration::from_nanos(1))
                    .is_err()
            );
        }
        now += previous;
        let ticket = book.reserve("a", now).unwrap();
        assert!(
            book.complete("a", &ticket, Some(ForwardOutcome::AuthenticatedReply), now)
                .is_some()
        );
        fail_three(&mut book, "a", now);
        assert!(
            book.reserve("a", now + BASE_COOLDOWN).is_ok(),
            "successful recovery resets backoff"
        );
    }

    #[test]
    fn invalid_reply_isolates_the_peer_immediately() {
        let mut book = CircuitBook::default();
        let now = Instant::now();
        let ticket = book.reserve("a", now).unwrap();
        let transition = book
            .complete("a", &ticket, Some(ForwardOutcome::InvalidReply), now)
            .unwrap();
        assert_eq!(transition.reason, "unauthenticated_reply");
        assert_eq!(transition.cooldown_ms, 30_000);
        assert!(book.reserve("a", now + BASE_COOLDOWN).is_err());
        assert!(book.reserve("a", now + MAX_COOLDOWN).is_ok());
    }

    #[test]
    fn late_success_cannot_close_a_newer_open_circuit() {
        let mut book = CircuitBook::default();
        let now = Instant::now();
        let old = book.reserve("a", now).unwrap();
        fail_three(&mut book, "a", now);
        assert!(
            book.complete("a", &old, Some(ForwardOutcome::AuthenticatedReply), now)
                .is_none()
        );
        assert!(book.reserve("a", now).is_err());
    }

    #[test]
    fn late_failures_cannot_poison_a_successful_recovery() {
        let mut book = CircuitBook::default();
        let now = Instant::now();
        let old: Vec<_> = (0..4).map(|_| book.reserve("a", now).unwrap()).collect();
        fail_three(&mut book, "a", now);
        let recovered_at = now + BASE_COOLDOWN;
        let probe = book.reserve("a", recovered_at).unwrap();
        assert!(
            book.complete(
                "a",
                &probe,
                Some(ForwardOutcome::AuthenticatedReply),
                recovered_at,
            )
            .is_some()
        );
        for ticket in old {
            assert!(
                book.complete("a", &ticket, Some(ForwardOutcome::InvalidReply), recovered_at)
                    .is_none()
            );
        }
        assert!(book.reserve("a", recovered_at).is_ok());
        assert_eq!(book.peers["a"].failures, 0);
    }

    #[test]
    fn cancelled_probe_releases_its_slot_without_escalating_backoff() {
        let mut book = CircuitBook::default();
        let now = Instant::now();
        fail_three(&mut book, "a", now);
        let retry_at = now + BASE_COOLDOWN;
        let ticket = book.reserve("a", retry_at).unwrap();
        let transition = book.complete("a", &ticket, None, retry_at).unwrap();
        assert_eq!(transition.reason, "recovery_probe_cancelled");
        assert_eq!(transition.cooldown_ms, 5_000);
        assert!(book.reserve("a", retry_at).is_err());
        assert!(book.reserve("a", retry_at + BASE_COOLDOWN).is_ok());
    }

    #[test]
    fn ordinary_cancellation_is_not_a_peer_failure() {
        let mut book = CircuitBook::default();
        let now = Instant::now();
        for _ in 0..20 {
            let ticket = book.reserve("a", now).unwrap();
            assert!(book.complete("a", &ticket, None, now).is_none());
        }
        assert_eq!(book.peers["a"].failures, 0);
        assert!(book.reserve("a", now).is_ok());
    }

    fn bounded_book(capacity: usize) -> CircuitBook {
        assert!(capacity > 0);
        CircuitBook {
            capacity,
            ..CircuitBook::default()
        }
    }

    #[test]
    fn capacity_refusal_preserves_live_tickets_and_existing_peer_admission() {
        let mut book = bounded_book(1);
        let now = Instant::now();
        let ticket = book.reserve("a", now).unwrap();
        assert_eq!(book.reserve("b", now).unwrap_err(), "peer_circuit_capacity");
        assert_eq!(book.peers.len(), 1);
        assert!(Arc::ptr_eq(&book.peers["a"].generation, &ticket.generation));
        let second = book.reserve("a", now).unwrap();
        drop(second);
        book.complete("a", &ticket, None, now);
        drop(ticket);
        assert!(book.reserve("b", now).is_ok());
        assert_eq!(book.peers.len(), 1);
        assert!(!book.peers.contains_key("a"));
    }

    #[test]
    fn healthy_idle_history_is_reclaimed_in_deterministic_oldest_order() {
        let mut book = bounded_book(2);
        let now = Instant::now();
        // Insert in reverse lexical order to pin the tie-breaker independently
        // of insertion order. No failure history needs to be retained here.
        for peer in ["b", "a"] {
            let ticket = book.reserve(peer, now).unwrap();
            book.complete(peer, &ticket, Some(ForwardOutcome::AuthenticatedReply), now);
        }
        let c = book.reserve("c", now).unwrap();
        assert!(!book.peers.contains_key("a"));
        assert!(book.peers.contains_key("b"));
        book.complete("c", &c, None, now + Duration::from_secs(1));
        drop(c);
        assert!(book.reserve("d", now + Duration::from_secs(2)).is_ok());
        assert!(!book.peers.contains_key("b"));
        assert!(book.peers.contains_key("c"));
        assert_eq!(book.peers.len(), 2);
    }

    #[test]
    fn failure_history_survives_pressure_until_idle_retention_boundary() {
        let mut book = bounded_book(1);
        let now = Instant::now();
        fail_three(&mut book, "a", now);
        for elapsed in [
            Duration::ZERO,
            BASE_COOLDOWN,
            IDLE_HISTORY_RETENTION - Duration::from_nanos(1),
        ] {
            assert_eq!(
                book.reserve("b", now + elapsed).unwrap_err(),
                "peer_circuit_capacity"
            );
        }
        assert_eq!(book.peers["a"].failures, FAILURE_THRESHOLD);
        assert!(matches!(book.peers["a"].mode, Mode::Open { .. }));
        assert!(book.reserve("b", now + IDLE_HISTORY_RETENTION).is_ok());
        assert!(!book.peers.contains_key("a"));
    }

    #[test]
    fn partial_failure_streak_and_recent_probe_cancellation_are_retained() {
        let mut book = bounded_book(1);
        let now = Instant::now();
        let ticket = book.reserve("a", now).unwrap();
        book.complete("a", &ticket, Some(ForwardOutcome::Unavailable), now);
        drop(ticket);
        assert_eq!(book.reserve("b", now).unwrap_err(), "peer_circuit_capacity");
        assert_eq!(book.peers["a"].failures, 1);
        for _ in 0..2 {
            let ticket = book.reserve("a", now).unwrap();
            book.complete("a", &ticket, Some(ForwardOutcome::Unavailable), now);
        }
        let later = now + IDLE_HISTORY_RETENTION;
        let probe = book.reserve("a", later).unwrap();
        assert_eq!(
            book.reserve("b", later + IDLE_HISTORY_RETENTION).unwrap_err(),
            "peer_circuit_capacity",
            "a live recovery probe must never be reclaimed"
        );
        let cancelled_at = later + IDLE_HISTORY_RETENTION;
        book.complete("a", &probe, None, cancelled_at);
        drop(probe);
        assert_eq!(
            book.reserve("b", cancelled_at + BASE_COOLDOWN).unwrap_err(),
            "peer_circuit_capacity"
        );
        assert!(book.reserve("b", cancelled_at + IDLE_HISTORY_RETENTION).is_ok());
    }

    #[test]
    fn generation_rotation_cannot_hide_an_old_live_ticket_from_reclamation() {
        let mut book = bounded_book(1);
        let now = Instant::now();
        let old = book.reserve("a", now).unwrap();
        fail_three(&mut book, "a", now);
        let recovered_at = now + BASE_COOLDOWN;
        let probe = book.reserve("a", recovered_at).unwrap();
        book.complete("a", &probe, Some(ForwardOutcome::AuthenticatedReply), recovered_at);
        drop(probe);
        assert!(!Arc::ptr_eq(&book.peers["a"].generation, &old.generation));
        assert_eq!(
            book.reserve("b", now + IDLE_HISTORY_RETENTION).unwrap_err(),
            "peer_circuit_capacity"
        );
        assert!(
            book.complete("a", &old, Some(ForwardOutcome::InvalidReply), recovered_at)
                .is_none()
        );
        assert_eq!(book.peers["a"].failures, 0);
        drop(old);
        assert!(book.reserve("b", recovered_at).is_ok());
    }

    #[test]
    fn clock_observation_reordering_cannot_age_history_prematurely() {
        let mut book = bounded_book(1);
        let now = Instant::now();
        let later = now + IDLE_HISTORY_RETENTION;
        let first = book.reserve("a", now).unwrap();
        let second = book.reserve("a", later).unwrap();
        book.complete("a", &second, Some(ForwardOutcome::Unavailable), later);
        drop(second);
        book.complete("a", &first, Some(ForwardOutcome::Unavailable), now);
        drop(first);
        assert_eq!(book.peers["a"].last_activity, later);
        assert_eq!(book.reserve("b", later).unwrap_err(), "peer_circuit_capacity");
        assert!(book.reserve("b", later + IDLE_HISTORY_RETENTION).is_ok());
    }

    #[test]
    fn membership_churn_cannot_grow_retained_state_past_capacity() {
        let mut book = bounded_book(3);
        let now = Instant::now();
        let pinned = book.reserve("pinned", now).unwrap();
        for index in 0..1000 {
            let peer = format!("rotating-peer-{index}");
            let ticket = book.reserve(&peer, now).unwrap();
            book.complete(&peer, &ticket, Some(ForwardOutcome::AuthenticatedReply), now);
            drop(ticket);
            assert!(book.peers.len() <= 3);
            assert!(Arc::ptr_eq(&book.peers["pinned"].activity, &pinned.activity));
        }
        assert_eq!(book.peers.len(), 3);
    }

    #[test]
    fn capacity_pressure_does_not_steal_a_ready_recovery_probe() {
        let mut book = bounded_book(1);
        let now = Instant::now();
        fail_three(&mut book, "a", now);
        let retry_at = now + BASE_COOLDOWN;
        assert_eq!(book.reserve("b", retry_at).unwrap_err(), "peer_circuit_capacity");
        let probe = book.reserve("a", retry_at).unwrap();
        assert!(probe.probe);
        assert_eq!(
            book.reserve("a", retry_at).unwrap_err(),
            "peer_recovery_probe_in_flight"
        );
        book.complete("a", &probe, Some(ForwardOutcome::AuthenticatedReply), retry_at);
        drop(probe);
        assert!(book.reserve("b", retry_at).is_ok());
    }
}
