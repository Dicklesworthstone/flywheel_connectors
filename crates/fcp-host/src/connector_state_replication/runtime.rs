//! Shared, fail-fast resource admission for connector-state transfers.
//!
//! The service owns this state; there is no process-global registry or waiter
//! queue. Reservations cover declared canonical bytes, wire bytes and object
//! counts, not allocator overhead. They end when the service future ends;
//! already-admitted durable store work retains its own cancellation semantics.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use super::{ConnectorStateTransferLimits, validate_metadata};
use crate::{HostError, HostResult};

const MAX_ACTIVE: usize = 8;
const MAX_PER_PEER: usize = 2;
const MAX_CANONICAL_BYTES: usize = 16 * 1024 * 1024;
const MAX_WIRE_BYTES: usize = 16 * 1024 * 1024;
const MAX_OBJECTS: usize = 8192;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Usage {
    active: usize,
    canonical_bytes: usize,
    wire_bytes: usize,
    objects: usize,
}

impl Usage {
    fn reserve(self, limits: ConnectorStateTransferLimits) -> HostResult<Self> {
        Ok(Self {
            active: bounded_add(self.active, 1, MAX_ACTIVE)?,
            canonical_bytes: bounded_add(
                self.canonical_bytes, limits.max_canonical_bytes, MAX_CANONICAL_BYTES,
            )?,
            wire_bytes: bounded_add(self.wire_bytes, limits.max_wire_bytes, MAX_WIRE_BYTES)?,
            objects: bounded_add(self.objects, limits.max_objects, MAX_OBJECTS)?,
        })
    }

    fn release(self, limits: ConnectorStateTransferLimits) -> Option<Self> {
        Some(Self {
            active: self.active.checked_sub(1)?,
            canonical_bytes: self.canonical_bytes.checked_sub(limits.max_canonical_bytes)?,
            wire_bytes: self.wire_bytes.checked_sub(limits.max_wire_bytes)?,
            objects: self.objects.checked_sub(limits.max_objects)?,
        })
    }
}

fn exhausted() -> HostError {
    HostError::Unavailable("connector-state transfer capacity exhausted".to_owned())
}

fn unavailable() -> HostError {
    HostError::Unavailable("connector-state transfer admission is unavailable".to_owned())
}

fn bounded_add(current: usize, requested: usize, maximum: usize) -> HostResult<usize> {
    current.checked_add(requested).filter(|next| *next <= maximum).ok_or_else(exhausted)
}

#[derive(Default)]
struct State {
    usage: Usage,
    peers: HashMap<String, usize>,
    failed: bool,
}

#[derive(Default)]
pub(crate) struct TransferRuntime {
    state: Mutex<State>,
}

impl TransferRuntime {
    fn lock(&self) -> HostResult<MutexGuard<'_, State>> {
        let state = self.state.lock().map_err(|_| unavailable())?;
        if state.failed {
            return Err(unavailable());
        }
        Ok(state)
    }

    /// Called only after grant and transport authorization. No future is
    /// created, source read, or response decoded before successful admission.
    pub(crate) fn admit(
        &self,
        peer: &str,
        limits: ConnectorStateTransferLimits,
    ) -> HostResult<TransferPermit<'_>> {
        validate_metadata(peer)?;
        limits.validate()?;
        let mut state = self.lock()?;
        let peer_active = state.peers.get(peer).copied().unwrap_or(0);
        let next_peer = bounded_add(peer_active, 1, MAX_PER_PEER)?;
        let next_usage = state.usage.reserve(limits)?;
        // Commit every dimension together. A rejected request cannot leave a
        // partial reservation or grow the active-peer map.
        state.peers.insert(peer.to_owned(), next_peer);
        state.usage = next_usage;
        Ok(TransferPermit { runtime: self, peer: peer.to_owned(), limits })
    }

    #[cfg(test)]
    pub(crate) fn active(&self) -> usize {
        self.state.lock().expect("test admission state").usage.active
    }
}

/// Owning a permit is necessary but never sufficient authority to transfer
/// state. Grant expiry and peer continuity are still checked by the caller.
pub(crate) struct TransferPermit<'a> {
    runtime: &'a TransferRuntime,
    peer: String,
    limits: ConnectorStateTransferLimits,
}

impl Drop for TransferPermit<'_> {
    fn drop(&mut self) {
        // Cleanup must not panic during unwinding. Recover the counters, but
        // leave a poisoned mutex poisoned so future admission stays refused.
        let mut state = match self.runtime.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        let next_peer = state.peers.get(&self.peer).and_then(|count| count.checked_sub(1));
        let next_usage = state.usage.release(self.limits);
        let (Some(next_peer), Some(next_usage)) = (next_peer, next_usage) else {
            state.failed = true;
            return;
        };
        if next_peer == 0 {
            state.peers.remove(&self.peer);
        } else {
            state.peers.insert(self.peer.clone(), next_peer);
        }
        state.usage = next_usage;
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::sync::{Arc, Barrier};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Wake, Waker};

    use super::*;

    fn small() -> ConnectorStateTransferLimits {
        ConnectorStateTransferLimits { max_objects: 1, max_canonical_bytes: 1, max_wire_bytes: 1 }
    }

    fn empty(runtime: &TransferRuntime) {
        let state = runtime.lock().unwrap();
        assert_eq!(state.usage, Usage::default());
        assert!(state.peers.is_empty());
    }

    #[test]
    fn per_peer_admission_is_atomic_and_drop_restores_capacity() {
        let runtime = TransferRuntime::default();
        let first = runtime.admit("a", small()).unwrap();
        let second = runtime.admit("a", small()).unwrap();
        let before = runtime.lock().unwrap().usage;
        assert!(runtime.admit("a", small()).is_err());
        assert_eq!(runtime.lock().unwrap().usage, before);
        let other = runtime.admit("b", small()).unwrap();
        drop(first);
        let replacement = runtime.admit("a", small()).unwrap();
        drop((second, other, replacement));
        empty(&runtime);
    }

    #[test]
    fn service_slot_limit_bounds_active_peer_metadata() {
        let runtime = TransferRuntime::default();
        let permits: Vec<_> = (0..MAX_ACTIVE).map(|n| runtime.admit(&n.to_string(), small()).unwrap()).collect();
        assert!(runtime.admit("new-peer", small()).is_err());
        assert_eq!(runtime.lock().unwrap().peers.len(), MAX_ACTIVE);
        drop(permits);
        empty(&runtime);
    }

    #[test]
    fn canonical_wire_and_object_budgets_are_independent() {
        for dimension in 0..3 {
            let runtime = TransferRuntime::default();
            let mut limits = small();
            let count = match dimension {
                0 => { limits.max_canonical_bytes = 4 * 1024 * 1024; 4 },
                1 => { limits.max_wire_bytes = 4 * 1024 * 1024; 4 },
                _ => { limits.max_objects = 4096; 2 },
            };
            let mut permits: Vec<_> = (0..count).map(|n| runtime.admit(&n.to_string(), limits).unwrap()).collect();
            let before = runtime.lock().unwrap().usage;
            assert!(runtime.admit("extra", small()).is_err());
            assert_eq!(runtime.lock().unwrap().usage, before);
            drop(permits.pop());
            let next = runtime.admit("extra", small()).unwrap();
            drop((permits, next));
            empty(&runtime);
        }
        assert!(bounded_add(usize::MAX, 1, usize::MAX).is_err());
    }

    #[test]
    fn invalid_reservations_do_not_grow_state() {
        let runtime = TransferRuntime::default();
        assert!(runtime.admit("", small()).is_err());
        assert!(runtime.admit("peer", ConnectorStateTransferLimits { max_objects: 0, ..small() }).is_err());
        assert!(runtime.admit("peer", ConnectorStateTransferLimits { max_wire_bytes: usize::MAX, ..small() }).is_err());
        empty(&runtime);
    }

    #[test]
    fn dropping_a_pending_future_releases_its_reservation() {
        struct Noop;
        impl Wake for Noop { fn wake(self: Arc<Self>) {} }
        let runtime = TransferRuntime::default();
        let mut future = Box::pin(async {
            let _permit = runtime.admit("peer", small()).unwrap();
            std::future::pending::<()>().await;
        });
        let waker = Waker::from(Arc::new(Noop));
        assert_eq!(future.as_mut().poll(&mut Context::from_waker(&waker)), Poll::Pending);
        assert_eq!(runtime.active(), 1);
        drop(future);
        empty(&runtime);
    }

    #[test]
    fn unwinding_outside_the_lock_releases_the_permit() {
        let runtime = TransferRuntime::default();
        assert!(std::panic::catch_unwind(|| {
            let _permit = runtime.admit("peer", small()).unwrap();
            panic!("fixture future panicked");
        }).is_err());
        empty(&runtime);
    }

    #[test]
    fn poison_never_turns_cleanup_into_new_admission() {
        let runtime = TransferRuntime::default();
        let permit = runtime.admit("peer", small()).unwrap();
        assert!(std::panic::catch_unwind(|| {
            let _lock = runtime.state.lock().unwrap();
            panic!("fixture poisoned state");
        }).is_err());
        drop(permit);
        assert!(runtime.admit("peer", small()).is_err());
        let state = runtime.state.lock().err().unwrap().into_inner();
        assert_eq!(state.usage, Usage::default());
        assert!(state.peers.is_empty());
    }

    #[test]
    fn concurrent_requests_cannot_exceed_service_slots() {
        let runtime = TransferRuntime::default();
        let workers = MAX_ACTIVE * 2;
        let start = Barrier::new(workers + 1);
        let admitted = Barrier::new(workers + 1);
        let release = Barrier::new(workers + 1);
        let successes = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for n in 0..workers {
                let (runtime, start, admitted, release, successes) =
                    (&runtime, &start, &admitted, &release, &successes);
                scope.spawn(move || {
                    start.wait();
                    let permit = runtime.admit(&n.to_string(), small()).ok();
                    if permit.is_some() { successes.fetch_add(1, Ordering::SeqCst); }
                    admitted.wait();
                    release.wait();
                    drop(permit);
                });
            }
            start.wait();
            admitted.wait();
            let count = successes.load(Ordering::SeqCst);
            let active = runtime.active();
            // Release workers before asserting so a failure cannot deadlock
            // the scoped-thread join and conceal the original assertion.
            release.wait();
            assert_eq!(count, MAX_ACTIVE);
            assert_eq!(active, MAX_ACTIVE);
        });
        empty(&runtime);
    }
}
