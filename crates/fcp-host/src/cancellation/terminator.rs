//! Synchronized ownership of one invocation's termination authority.

use std::sync::{Arc, Mutex};

struct Callbacks {
    abort: Box<dyn Fn() + Send + Sync>,
    finished: Box<dyn Fn() -> bool + Send + Sync>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CallbackKind {
    Abort,
    Finished,
}

struct State {
    callbacks: Option<Arc<Callbacks>>,
    abort_requested: bool,
    disarmed: bool,
    active: Option<CallbackKind>,
    pending_abort: bool,
}

/// Keeps a callback exclusive without holding the decision mutex while calling
/// runtime code. Unwinding releases execution ownership, not termination
/// authority, and a queued abort survives a panicking completion probe.
struct CallbackLease {
    state: Arc<Mutex<State>>,
    callbacks: Option<Arc<Callbacks>>,
    released: bool,
}

impl CallbackLease {
    fn release(&mut self) -> (bool, bool) {
        // Active disarm leaves the state's reference in place. Only this
        // execution owner may destroy it, including when disarm arrives after
        // we release our own reference but before clearing `active`.
        drop(self.callbacks.take());
        loop {
            let mut state = self.state.lock().expect("termination state lock");
            if state.disarmed && state.callbacks.is_some() {
                let captures = state.callbacks.take();
                drop(state);
                // Destructors may reenter. Keep execution ownership until
                // they finish, but never run them under the decision mutex.
                drop(captures);
                continue;
            }
            state.active = None;
            self.released = true;
            return (state.disarmed, state.pending_abort);
        }
    }
}

impl Drop for CallbackLease {
    fn drop(&mut self) {
        if !self.released {
            self.release();
        }
    }
}

/// Out-of-band termination of one concrete runtime incarnation.
///
/// Every clone shares the same abort/disarm decision. Completing an invocation
/// can revoke an already extracted reaper handle before its worker is reused.
/// Callbacks must be short and synchronous. They and their captured destructors
/// run outside the decision mutex; reentrant queries return conservatively
/// instead of waiting for a callback already executing on the same thread.
#[derive(Clone)]
pub struct CancellationTerminator {
    state: Arc<Mutex<State>>,
}

impl std::fmt::Debug for CancellationTerminator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CancellationTerminator")
            .finish_non_exhaustive()
    }
}

impl CancellationTerminator {
    /// Capture the runtime selected for this invocation, without looking it up
    /// again by connector ID when the deadline expires.
    #[must_use]
    pub fn new(
        abort: impl Fn() + Send + Sync + 'static,
        finished: impl Fn() -> bool + Send + Sync + 'static,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                callbacks: Some(Arc::new(Callbacks {
                    abort: Box::new(abort),
                    finished: Box::new(finished),
                })),
                abort_requested: false,
                disarmed: false,
                active: None,
                pending_abort: false,
            })),
        }
    }

    /// Request termination unless completion already disarmed this handle.
    ///
    /// The request wins against disarm before runtime code is called. An abort
    /// arriving during a completion probe is latched and delivered after that
    /// probe; overlapping abort calls coalesce. No caller waits for another
    /// callback to finish. A later non-overlapping call can retry termination.
    ///
    /// # Panics
    ///
    /// Propagates callback panics without poisoning the decision mutex. Panics
    /// if the decision mutex itself is poisoned.
    #[must_use]
    pub fn abort(&self) -> bool {
        self.request_abort(false)
    }

    fn request_abort(&self, pending_only: bool) -> bool {
        let mut lease = {
            let mut state = self.state.lock().expect("termination state lock");
            if state.disarmed || (pending_only && !state.pending_abort) {
                return false;
            }
            state.abort_requested = true;
            if let Some(active) = state.active {
                if active == CallbackKind::Finished {
                    state.pending_abort = true;
                }
                return true;
            }
            state.pending_abort = false;
            state.active = Some(CallbackKind::Abort);
            CallbackLease {
                state: Arc::clone(&self.state),
                callbacks: state.callbacks.clone(),
                released: false,
            }
        };
        (lease.callbacks.as_ref().expect("active abort callback").abort)();
        lease.release();
        true
    }

    /// Revoke termination authority before completing or reusing a runtime.
    ///
    /// Returns true only when no abort has won AND no callback or captured
    /// destructor is still executing. A concurrent completion probe makes this
    /// return false, but authority is revoked immediately; retrying after the
    /// probe returns can confirm safe reuse. If abort already won, callbacks
    /// remain available until the reaper observes actual termination, and the
    /// runtime must not return to a pool.
    ///
    /// # Panics
    ///
    /// Panics if the decision mutex is poisoned or a captured destructor panics.
    #[must_use]
    pub fn disarm(&self) -> bool {
        let mut release = {
            let mut state = self.state.lock().expect("termination state lock");
            if state.abort_requested {
                return false;
            }
            state.disarmed = true;
            if state.active.is_some() {
                // Revocation is immediate, but destruction belongs to the
                // active lease. Taking this reference here could race its
                // release and let another thread observe premature reuse.
                return false;
            }
            // Fence reentrant reuse while releasing the final captures, too.
            state.active = Some(CallbackKind::Finished);
            CallbackLease {
                state: Arc::clone(&self.state),
                callbacks: state.callbacks.take(),
                released: false,
            }
        };
        release.release();
        true
    }

    /// Whether the captured runtime exited, or disarm has fully drained.
    ///
    /// Returns false while another callback runs. An abort arriving during a
    /// probe invalidates that probe's result, even if it reported completion.
    /// Reapers must first check that `abort()` returned true; disarmed work is
    /// complete but was not forcibly terminated.
    ///
    /// # Panics
    ///
    /// Propagates callback panics without poisoning the decision mutex. Panics
    /// if the decision mutex itself is poisoned.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        let mut lease = {
            let mut state = self.state.lock().expect("termination state lock");
            if state.active.is_some() {
                return false;
            }
            if state.disarmed {
                return true;
            }
            if state.pending_abort {
                // A previous completion probe may have unwound before it
                // could deliver the abort that arrived while it was running.
                drop(state);
                self.request_abort(true);
                return false;
            }
            state.active = Some(CallbackKind::Finished);
            CallbackLease {
                state: Arc::clone(&self.state),
                callbacks: state.callbacks.clone(),
                released: false,
            }
        };
        let finished = (lease.callbacks.as_ref().expect("active completion callback").finished)();
        let (disarmed, pending_abort) = lease.release();
        if pending_abort {
            self.request_abort(true);
            return false;
        }
        disarmed || finished
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Barrier, OnceLock, Weak, mpsc};
    use std::time::Duration;

    use super::*;

    #[test]
    fn disarm_releases_runtime_even_when_extracted_handles_survive() {
        let runtime = Arc::new(AtomicBool::new(false));
        let weak = Arc::downgrade(&runtime);
        let finished = Arc::clone(&runtime);
        let terminator = CancellationTerminator::new(
            move || runtime.store(true, Ordering::SeqCst),
            move || finished.load(Ordering::SeqCst),
        );
        let stale_reaper = terminator.clone();
        assert!(weak.upgrade().is_some());
        assert!(terminator.disarm());
        assert!(weak.upgrade().is_none());
        assert!(!stale_reaper.abort());
        assert!(stale_reaper.is_finished());
        assert!(stale_reaper.disarm());
    }

    #[test]
    fn abort_winner_prevents_reuse_and_preserves_real_completion_signal() {
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let abort_entered = Arc::clone(&entered);
        let abort_release = Arc::clone(&release);
        let finished = Arc::new(AtomicBool::new(false));
        let observed_finished = Arc::clone(&finished);
        let terminator = CancellationTerminator::new(
            move || {
                abort_entered.wait();
                abort_release.wait();
            },
            move || observed_finished.load(Ordering::SeqCst),
        );
        let abort_target = terminator.clone();
        let abort_thread = std::thread::spawn(move || abort_target.abort());
        entered.wait();
        let disarm_target = terminator.clone();
        let (started_tx, started_rx) = mpsc::channel();
        let disarm_thread = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            disarm_target.disarm()
        });
        started_rx.recv().unwrap();
        release.wait();
        assert!(abort_thread.join().unwrap());
        assert!(!disarm_thread.join().unwrap());
        assert!(!terminator.is_finished());
        finished.store(true, Ordering::SeqCst);
        assert!(terminator.is_finished());
    }

    #[test]
    fn disarm_winner_makes_a_late_reaper_harmless() {
        let aborted = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&aborted);
        let terminator =
            CancellationTerminator::new(move || observed.store(true, Ordering::SeqCst), || false);
        let stale_reaper = terminator.clone();
        let (released_tx, released_rx) = mpsc::channel();
        let late_abort = std::thread::spawn(move || {
            released_rx.recv().unwrap();
            stale_reaper.abort()
        });
        assert!(terminator.disarm());
        released_tx.send(()).unwrap();
        assert!(!late_abort.join().unwrap());
        assert!(!aborted.load(Ordering::SeqCst));
    }

    fn from_slot(slot: &OnceLock<Weak<Mutex<State>>>) -> CancellationTerminator {
        CancellationTerminator {
            state: slot.get().unwrap().upgrade().unwrap(),
        }
    }

    #[test]
    fn abort_callback_can_reenter_without_recursive_abort_or_early_completion() {
        let slot = Arc::new(OnceLock::new());
        let callback_slot = Arc::clone(&slot);
        let calls = Arc::new(AtomicUsize::new(0));
        let callback_calls = Arc::clone(&calls);
        let terminator = CancellationTerminator::new(
            move || {
                callback_calls.fetch_add(1, Ordering::SeqCst);
                let reentrant = from_slot(&callback_slot);
                assert!(reentrant.state.try_lock().is_ok());
                assert!(!reentrant.disarm());
                assert!(!reentrant.is_finished());
                assert!(reentrant.abort());
            },
            || true,
        );
        slot.set(Arc::downgrade(&terminator.state)).unwrap();
        assert!(terminator.abort());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(terminator.is_finished());
        assert!(!terminator.disarm());
    }

    #[test]
    fn probe_disarm_revokes_authority_but_waits_for_captures_before_reuse() {
        let slot = Arc::new(OnceLock::new());
        let callback_slot = Arc::clone(&slot);
        let runtime = Arc::new(());
        let weak_runtime = Arc::downgrade(&runtime);
        let terminator = CancellationTerminator::new(
            || panic!("disarmed callback must never abort"),
            move || {
                let _runtime = &runtime;
                let reentrant = from_slot(&callback_slot);
                assert!(reentrant.state.try_lock().is_ok());
                assert!(!reentrant.is_finished());
                assert!(!reentrant.disarm());
                assert!(!reentrant.abort());
                false
            },
        );
        slot.set(Arc::downgrade(&terminator.state)).unwrap();
        assert!(terminator.is_finished());
        assert!(weak_runtime.upgrade().is_none());
        assert!(terminator.disarm());
        assert!(!terminator.abort());
    }

    #[test]
    fn abort_during_probe_is_delivered_and_invalidates_the_old_completion() {
        let slot = Arc::new(OnceLock::new());
        let callback_slot = Arc::clone(&slot);
        let aborts = Arc::new(AtomicUsize::new(0));
        let callback_aborts = Arc::clone(&aborts);
        let first = AtomicBool::new(true);
        let terminator = CancellationTerminator::new(
            move || {
                callback_aborts.fetch_add(1, Ordering::SeqCst);
            },
            move || {
                if first.swap(false, Ordering::SeqCst) {
                    let reentrant = from_slot(&callback_slot);
                    assert!(reentrant.state.try_lock().is_ok());
                    assert!(reentrant.abort());
                    assert!(!reentrant.disarm());
                }
                true
            },
        );
        slot.set(Arc::downgrade(&terminator.state)).unwrap();
        assert!(!terminator.is_finished(), "pre-abort completion must be discarded");
        assert_eq!(aborts.load(Ordering::SeqCst), 1);
        assert!(terminator.is_finished());
        assert!(!terminator.disarm());
    }

    #[test]
    fn blocked_callback_does_not_block_other_decisions_or_duplicate_abort() {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let release_rx = Mutex::new(release_rx);
        let terminator = CancellationTerminator::new(
            move || {
                entered_tx.send(()).unwrap();
                release_rx.lock().unwrap().recv().unwrap();
            },
            || true,
        );
        let running = terminator.clone();
        let abort_thread = std::thread::spawn(move || running.abort());
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let (decisions_tx, decisions_rx) = mpsc::channel();
        let observing = terminator.clone();
        let observer = std::thread::spawn(move || {
            decisions_tx.send((observing.disarm(), observing.is_finished(), observing.abort())).unwrap();
        });
        // Always release the callback before asserting, even on regression.
        let decisions = decisions_rx.recv_timeout(Duration::from_secs(5));
        release_tx.send(()).unwrap();
        assert!(abort_thread.join().unwrap());
        // Unblock a regressed implementation that invoked a duplicate abort.
        let _ = release_tx.send(());
        observer.join().unwrap();
        assert_eq!(decisions.unwrap(), (false, false, true));
        assert!(terminator.is_finished());
    }

    #[test]
    fn panicking_probe_preserves_queued_abort_and_releases_callback_ownership() {
        let slot = Arc::new(OnceLock::new());
        let callback_slot = Arc::clone(&slot);
        let aborted = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&aborted);
        let first = AtomicBool::new(true);
        let terminator = CancellationTerminator::new(
            move || observed.store(true, Ordering::SeqCst),
            move || {
                if first.swap(false, Ordering::SeqCst) {
                    let reentrant = from_slot(&callback_slot);
                    assert!(reentrant.state.try_lock().is_ok());
                    assert!(reentrant.abort());
                    panic!("probe failure");
                }
                true
            },
        );
        slot.set(Arc::downgrade(&terminator.state)).unwrap();
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| terminator.is_finished())).is_err());
        assert!(!terminator.state.is_poisoned());
        assert!(!terminator.disarm());
        assert!(!terminator.is_finished(), "pending abort precedes another probe");
        assert!(aborted.load(Ordering::SeqCst));
        assert!(terminator.is_finished());
    }

    #[test]
    fn panicking_abort_remains_fenced_and_can_be_retried() {
        let calls = Arc::new(AtomicUsize::new(0));
        let callback_calls = Arc::clone(&calls);
        let finished_calls = Arc::clone(&calls);
        let terminator = CancellationTerminator::new(
            move || {
                assert_ne!(callback_calls.fetch_add(1, Ordering::SeqCst), 0, "first abort fails");
            },
            move || finished_calls.load(Ordering::SeqCst) > 1,
        );
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| terminator.abort())).is_err());
        assert!(!terminator.state.is_poisoned());
        assert!(!terminator.disarm());
        assert!(!terminator.is_finished());
        assert!(terminator.abort());
        assert!(terminator.is_finished());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn capture_destructor_reentry_cannot_reuse_before_release_finishes() {
        struct Capture(Arc<OnceLock<Weak<Mutex<State>>>>);
        impl Drop for Capture {
            fn drop(&mut self) {
                let reentrant = from_slot(&self.0);
                assert!(reentrant.state.try_lock().is_ok());
                assert!(!reentrant.abort());
                assert!(!reentrant.is_finished());
                assert!(!reentrant.disarm());
            }
        }
        let slot = Arc::new(OnceLock::new());
        let capture = Capture(Arc::clone(&slot));
        let terminator = CancellationTerminator::new(move || { let _capture = &capture; }, || false);
        slot.set(Arc::downgrade(&terminator.state)).unwrap();
        assert!(terminator.disarm());
        assert!(terminator.is_finished());
        assert!(terminator.disarm());
    }

    #[test]
    fn disarm_after_probe_reference_release_keeps_capture_custody_with_the_lease() {
        let runtime = Arc::new(());
        let weak_runtime = Arc::downgrade(&runtime);
        let terminator = CancellationTerminator::new(
            move || {
                let _runtime = &runtime;
            },
            || false,
        );
        let mut lease = {
            let mut state = terminator.state.lock().unwrap();
            state.active = Some(CallbackKind::Finished);
            CallbackLease {
                state: Arc::clone(&terminator.state),
                callbacks: state.callbacks.clone(),
                released: false,
            }
        };
        // Reproduce the exact release/disarm interleaving without relying on
        // a scheduler hitting the gap between two consecutive instructions.
        drop(lease.callbacks.take());
        assert!(!terminator.disarm());
        assert!(weak_runtime.upgrade().is_some());
        assert!(!terminator.abort());
        assert!(!terminator.is_finished());
        assert_eq!(lease.release(), (true, false));
        assert!(weak_runtime.upgrade().is_none());
        assert!(terminator.is_finished());
        assert!(terminator.disarm());
    }

    #[test]
    fn disarmed_probe_cannot_finish_while_its_capture_destructor_is_running() {
        struct BlockingCapture {
            entered: mpsc::Sender<()>,
            release: Mutex<mpsc::Receiver<()>>,
        }
        impl Drop for BlockingCapture {
            fn drop(&mut self) {
                self.entered.send(()).unwrap();
                self.release
                    .get_mut()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(10))
                    .unwrap();
            }
        }
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let capture = BlockingCapture {
            entered: entered_tx,
            release: Mutex::new(release_rx),
        };
        let slot = Arc::new(OnceLock::new());
        let callback_slot = Arc::clone(&slot);
        let terminator = CancellationTerminator::new(
            || panic!("revoked authority cannot abort"),
            move || {
                let _capture = &capture;
                let reentrant = from_slot(&callback_slot);
                assert!(!reentrant.disarm());
                false
            },
        );
        slot.set(Arc::downgrade(&terminator.state)).unwrap();
        let probing = terminator.clone();
        let probe = std::thread::spawn(move || probing.is_finished());
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let finished = terminator.is_finished();
        let reusable = terminator.disarm();
        let aborted = terminator.abort();
        // Release before asserting so failures cannot leave the probe parked.
        release_tx.send(()).unwrap();
        assert!(probe.join().unwrap());
        assert!(!finished && !reusable && !aborted);
        assert!(terminator.is_finished());
        assert!(terminator.disarm());
    }
}
