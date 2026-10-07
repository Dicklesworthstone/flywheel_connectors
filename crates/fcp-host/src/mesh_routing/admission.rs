//! Shared admission control for outbound mesh RPCs.
//!
//! Admission is fail-fast and precedes all network I/O. A refused request is
//! provably not delivered; an admitted request keeps its reservation through
//! reply authentication. Dropping the future releases every reservation, so
//! cancellation cannot strand capacity or create an unbounded waiter queue.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Mutex;

use serde::Serialize;

use super::{MeshForwardFailure, MeshForwardReply};
use crate::{HostError, HostResult};

/// Maximum simultaneous forwards across one router.
pub const MESH_FORWARD_MAX_IN_FLIGHT_ENV: &str = "FCP_HOST_MESH_FORWARD_MAX_IN_FLIGHT";
/// Maximum simultaneous forwards to one peer.
pub const MESH_FORWARD_MAX_PER_PEER_ENV: &str = "FCP_HOST_MESH_FORWARD_MAX_PER_PEER";
/// Maximum aggregate serialized request bytes held by admitted forwards.
pub const MESH_FORWARD_MAX_REQUEST_BYTES_ENV: &str = "FCP_HOST_MESH_FORWARD_MAX_REQUEST_BYTES";

pub(super) const LIMIT_ENV_KEYS: [&str; 3] = [
    MESH_FORWARD_MAX_IN_FLIGHT_ENV,
    MESH_FORWARD_MAX_PER_PEER_ENV,
    MESH_FORWARD_MAX_REQUEST_BYTES_ENV,
];

/// Router-wide and per-peer outbound resource ceilings.
///
/// The byte limit accounts for serialized signed requests, not response
/// bodies. Each response also has the transport's independent size limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct MeshForwardLimits {
    /// Maximum number of admitted forwards across all peers.
    pub max_in_flight: usize,
    /// Maximum number of admitted forwards to any one peer.
    pub max_per_peer: usize,
    /// Maximum sum of serialized request lengths for admitted forwards.
    pub max_request_bytes: usize,
}

impl Default for MeshForwardLimits {
    fn default() -> Self {
        Self {
            max_in_flight: 32,
            max_per_peer: 4,
            max_request_bytes: 64 * 1024 * 1024,
        }
    }
}

impl MeshForwardLimits {
    /// Load optional limits without reading ambient process state.
    ///
    /// # Errors
    ///
    /// Rejects empty, nonnumeric, zero, overflowing, or inconsistent limits.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> HostResult<Self> {
        let defaults = Self::default();
        let read = |name: &str, default: usize| -> HostResult<usize> {
            match lookup(name) {
                None => Ok(default),
                Some(raw) => raw.trim().parse::<usize>().map_err(|_| {
                    HostError::InvalidFilter(format!("{name} must be a positive integer"))
                }),
            }
        };
        let limits = Self {
            max_in_flight: read(MESH_FORWARD_MAX_IN_FLIGHT_ENV, defaults.max_in_flight)?,
            max_per_peer: read(MESH_FORWARD_MAX_PER_PEER_ENV, defaults.max_per_peer)?,
            max_request_bytes: read(
                MESH_FORWARD_MAX_REQUEST_BYTES_ENV,
                defaults.max_request_bytes,
            )?,
        };
        limits.validate()?;
        Ok(limits)
    }

    /// Check that every ceiling is nonzero and the peer ceiling fits the total.
    ///
    /// # Errors
    ///
    /// Returns a configuration error for an unusable limit set.
    pub fn validate(self) -> HostResult<()> {
        if self.max_in_flight == 0 || self.max_per_peer == 0 || self.max_request_bytes == 0 {
            return Err(HostError::InvalidFilter(
                "mesh forward limits must all be greater than zero".to_owned(),
            ));
        }
        if self.max_per_peer > self.max_in_flight {
            return Err(HostError::InvalidFilter(
                "mesh forward per-peer limit must not exceed the router limit".to_owned(),
            ));
        }
        Ok(())
    }
}

/// An atomic, redaction-safe snapshot of current outbound reservations.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct MeshForwardUsage {
    /// Admitted forwards, including those awaiting or verifying a reply.
    pub in_flight: usize,
    /// Aggregate serialized request bytes reserved by those forwards.
    pub request_bytes: usize,
    /// Active reservations per peer, in deterministic node-id order.
    pub peers: BTreeMap<String, usize>,
}

#[derive(Debug)]
pub(super) struct ForwardControl {
    limits: MeshForwardLimits,
    usage: Mutex<MeshForwardUsage>,
}

impl ForwardControl {
    pub(super) fn new(limits: MeshForwardLimits) -> HostResult<Self> {
        limits.validate()?;
        Ok(Self {
            limits,
            usage: Mutex::new(MeshForwardUsage::default()),
        })
    }

    pub(super) const fn limits(&self) -> MeshForwardLimits {
        self.limits
    }

    pub(super) fn snapshot(&self) -> HostResult<MeshForwardUsage> {
        self.usage.lock().map(|usage| usage.clone()).map_err(|_| {
            HostError::Internal("mesh forward admission state is poisoned".to_owned())
        })
    }

    /// `send` is not even constructed until all ceilings have been reserved.
    /// No lock is held while it is running, and every exit releases the lease.
    pub(super) async fn execute<F, Fut>(
        &self,
        peer: &str,
        request_bytes: usize,
        send: F,
    ) -> Result<MeshForwardReply, MeshForwardFailure>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<MeshForwardReply, MeshForwardFailure>>,
    {
        let _permit = self.reserve(peer, request_bytes)?;
        send().await
    }

    fn reserve<'a>(
        &'a self,
        peer: &'a str,
        request_bytes: usize,
    ) -> Result<ForwardPermit<'a>, MeshForwardFailure> {
        let mut usage = self
            .usage
            .lock()
            .map_err(|_| admission_refusal(peer, "state_poisoned"))?;
        let reason = if usage.in_flight >= self.limits.max_in_flight {
            Some("router_in_flight_limit")
        } else if usage.peers.get(peer).copied().unwrap_or(0) >= self.limits.max_per_peer {
            Some("peer_in_flight_limit")
        } else if request_bytes > self.limits.max_request_bytes.saturating_sub(usage.request_bytes) {
            Some("request_byte_limit")
        } else {
            None
        };
        if let Some(reason) = reason {
            drop(usage);
            return Err(admission_refusal(peer, reason));
        }
        // These additions cannot overflow: each is bounded above by a
        // validated usize ceiling, and byte admission checked the remainder.
        usage.in_flight += 1;
        usage.request_bytes += request_bytes;
        *usage.peers.entry(peer.to_owned()).or_default() += 1;
        drop(usage);
        Ok(ForwardPermit {
            control: self,
            peer,
            request_bytes,
        })
    }
}

fn admission_refusal(peer: &str, reason: &'static str) -> MeshForwardFailure {
    tracing::debug!(
        event = "mesh_forward_admission_refused",
        peer,
        reason,
        "mesh forward refused before transmission"
    );
    MeshForwardFailure::NotDelivered {
        peer: peer.to_owned(),
        detail: format!("mesh forward admission refused before transmission: {reason}"),
    }
}

#[derive(Debug)]
struct ForwardPermit<'a> {
    control: &'a ForwardControl,
    peer: &'a str,
    request_bytes: usize,
}

impl Drop for ForwardPermit<'_> {
    fn drop(&mut self) {
        // A poisoned state refuses all subsequent admission, but existing
        // futures must still be able to release resources during unwinding.
        let mut usage = self
            .control
            .usage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        usage.in_flight = usage.in_flight.saturating_sub(1);
        usage.request_bytes = usage.request_bytes.saturating_sub(self.request_bytes);
        if let Some(count) = usage.peers.get_mut(self.peer) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                usage.peers.remove(self.peer);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Context;

    use futures_util::FutureExt;
    use futures_util::future::pending;

    use super::*;

    fn control(total: usize, peer: usize, bytes: usize) -> ForwardControl {
        ForwardControl::new(MeshForwardLimits {
            max_in_flight: total,
            max_per_peer: peer,
            max_request_bytes: bytes,
        })
        .unwrap()
    }

    #[test]
    fn limits_parse_defaults_and_overrides() {
        assert_eq!(MeshForwardLimits::from_lookup(|_| None).unwrap(), MeshForwardLimits::default());
        let limits = MeshForwardLimits::from_lookup(|name| match name {
            MESH_FORWARD_MAX_IN_FLIGHT_ENV => Some(" 8 ".to_owned()),
            MESH_FORWARD_MAX_PER_PEER_ENV => Some("2".to_owned()),
            MESH_FORWARD_MAX_REQUEST_BYTES_ENV => Some("4096".to_owned()),
            _ => None,
        })
        .unwrap();
        assert_eq!(limits.max_in_flight, 8);
        assert_eq!(limits.max_per_peer, 2);
        assert_eq!(limits.max_request_bytes, 4096);
    }

    #[test]
    fn invalid_limits_fail_closed() {
        for name in LIMIT_ENV_KEYS {
            for value in ["", " ", "0", "-1", "no", "999999999999999999999999999999999999"] {
                assert!(MeshForwardLimits::from_lookup(|key| {
                    (key == name).then(|| value.to_owned())
                }).is_err(), "{name}={value:?}");
            }
        }
        assert!(MeshForwardLimits { max_in_flight: 1, max_per_peer: 2, max_request_bytes: 1 }.validate().is_err());
    }

    #[test]
    fn a_busy_peer_cannot_consume_other_peers_capacity() {
        let control = control(2, 1, 100);
        let a = control.reserve("a", 20).unwrap();
        let denied = control.reserve("a", 1).unwrap_err();
        assert!(denied.safe_to_retry());
        assert!(denied.summary().contains("peer_in_flight_limit"));
        let b = control.reserve("b", 30).unwrap();
        assert!(control.reserve("c", 1).unwrap_err().summary().contains("router_in_flight_limit"));
        assert_eq!(control.snapshot().unwrap().request_bytes, 50);
        drop(a);
        let c = control.reserve("c", 1).unwrap();
        assert_eq!(control.snapshot().unwrap().in_flight, 2);
        drop((b, c));
        assert_eq!(control.snapshot().unwrap(), MeshForwardUsage::default());
    }

    #[test]
    fn byte_budget_is_atomic_and_overflow_safe() {
        let control = control(8, 8, usize::MAX);
        let a = control.reserve("a", usize::MAX - 2).unwrap();
        let b = control.reserve("b", 2).unwrap();
        let before = control.snapshot().unwrap();
        assert!(control.reserve("c", 1).unwrap_err().summary().contains("request_byte_limit"));
        assert_eq!(control.snapshot().unwrap(), before, "refusal must not partially reserve");
        drop(a);
        let c = control.reserve("c", usize::MAX - 2).unwrap();
        drop((b, c));
        assert_eq!(control.snapshot().unwrap(), MeshForwardUsage::default());
    }

    #[test]
    fn oversized_single_request_does_not_occupy_a_slot() {
        let control = control(2, 1, 10);
        assert!(control.reserve("a", 11).is_err());
        assert_eq!(control.snapshot().unwrap(), MeshForwardUsage::default());
        assert!(control.reserve("a", 10).is_ok());
    }

    #[test]
    fn refusal_never_constructs_the_transport_future() {
        let control = control(1, 1, 10);
        let _occupied = control.reserve("a", 1).unwrap();
        let called = Cell::new(false);
        let failure = control.execute("b", 1, || {
            called.set(true);
            pending()
        }).now_or_never().unwrap().unwrap_err();
        assert!(failure.safe_to_retry());
        assert!(!called.get());
    }

    #[test]
    fn cancellation_releases_all_reservations() {
        let control = control(1, 1, 10);
        let mut future = Box::pin(control.execute("a", 10, pending));
        let waker = futures_util::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(future.as_mut().poll(&mut cx).is_pending());
        assert_eq!(control.snapshot().unwrap().request_bytes, 10);
        drop(future);
        assert_eq!(control.snapshot().unwrap(), MeshForwardUsage::default());
        assert!(control.reserve("a", 10).is_ok());
    }

    #[test]
    fn ambiguous_failure_is_preserved_and_capacity_released() {
        let control = control(1, 1, 10);
        let error = MeshForwardFailure::OutcomeUnknown {
            peer: "a".to_owned(), detail: "reply lost".to_owned(),
        };
        let result = control.execute("a", 10, || async { Err(error.clone()) }).now_or_never().unwrap();
        assert_eq!(result.unwrap_err(), error);
        assert!(!error.safe_to_retry());
        assert_eq!(control.snapshot().unwrap(), MeshForwardUsage::default());
    }

    #[test]
    fn panic_in_transport_construction_releases_capacity() {
        let control = control(1, 1, 10);
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = control.execute("a", 10, || {
                panic!("injected construction panic");
                #[allow(unreachable_code)]
                pending()
            }).now_or_never();
        }));
        assert!(caught.is_err());
        assert_eq!(control.snapshot().unwrap(), MeshForwardUsage::default());
    }

    #[test]
    fn concurrent_admission_never_oversubscribes() {
        let control = control(3, 3, 30);
        let barrier = Barrier::new(16);
        let admitted = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..16 {
                scope.spawn(|| {
                    barrier.wait();
                    let permit = control.reserve("a", 10);
                    if permit.is_ok() {
                        admitted.fetch_add(1, Ordering::SeqCst);
                    }
                    // Keep all successful reservations until every contender
                    // has attempted admission; exactly three can succeed.
                    barrier.wait();
                    drop(permit);
                });
            }
        });
        assert_eq!(admitted.load(Ordering::SeqCst), 3);
        assert_eq!(control.snapshot().unwrap(), MeshForwardUsage::default());
    }

    #[test]
    fn poisoned_state_never_masquerades_as_free_capacity() {
        let control = control(1, 1, 10);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = control.usage.lock().unwrap();
            panic!("injected state poison");
        }));
        assert!(control.snapshot().is_err());
        assert!(control.reserve("a", 1).unwrap_err().summary().contains("state_poisoned"));
    }
}
