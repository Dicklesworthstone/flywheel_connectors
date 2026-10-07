//! Transport-only peer circuit state. The admission mutex owns this book.
//!
//! A verified reply proves transport health even when the operation failed.
//! A circuit never rewrites the outcome of an already-sent request. It only
//! refuses later, not-yet-delivered forwards. Advertisements and HTTP status
//! alone are not authenticated evidence that the invoke path is healthy.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

const FAILURE_THRESHOLD: u8 = 3;
const BASE_COOLDOWN: Duration = Duration::from_secs(5);
const MAX_COOLDOWN: Duration = Duration::from_secs(30);

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
}

impl Default for PeerCircuit {
    fn default() -> Self {
        Self {
            mode: Mode::Closed,
            failures: 0,
            cooldown: BASE_COOLDOWN,
            generation: Arc::new(()),
        }
    }
}

impl PeerCircuit {
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
    probe: bool,
}

#[derive(Debug)]
pub(super) struct CircuitTransition {
    pub(super) state: &'static str,
    pub(super) reason: &'static str,
    pub(super) cooldown_ms: u64,
}

#[derive(Debug, Default)]
pub(super) struct CircuitBook {
    // Only directory-resolved peers reach the transport admission path.
    // Entries do not grow with request ids, connector ids, or payload data.
    peers: BTreeMap<String, PeerCircuit>,
}

impl CircuitBook {
    /// Call only after all resource ceilings have passed. A refused resource
    /// reservation must not consume the sole recovery-probe ticket.
    pub(super) fn reserve(
        &mut self,
        peer: &str,
        now: Instant,
    ) -> Result<CircuitTicket, &'static str> {
        let circuit = self.peers.entry(peer.to_owned()).or_default();
        let probe = match circuit.mode {
            Mode::Closed => false,
            Mode::Open { retry_at } if now >= retry_at => true,
            Mode::Open { .. } => return Err("peer_circuit_open"),
            Mode::Probe => return Err("peer_recovery_probe_in_flight"),
        };
        if probe {
            circuit.mode = Mode::Probe;
        }
        Ok(CircuitTicket {
            generation: Arc::clone(&circuit.generation),
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
}
