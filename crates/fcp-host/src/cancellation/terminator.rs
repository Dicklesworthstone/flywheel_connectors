//! Synchronized ownership of one invocation's termination authority.

use std::sync::{Arc, Mutex};

struct Callbacks {
    abort: Box<dyn Fn() + Send + Sync>,
    finished: Box<dyn Fn() -> bool + Send + Sync>,
}

struct State {
    callbacks: Option<Callbacks>,
    abort_requested: bool,
}

/// Out-of-band termination of one concrete runtime incarnation.
///
/// Every clone shares the same abort/disarm decision. Completing an invocation
/// can revoke an already extracted reaper handle before its worker is reused.
/// Callbacks must be short, synchronous, and must not call this terminator.
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
                callbacks: Some(Callbacks {
                    abort: Box::new(abort),
                    finished: Box::new(finished),
                }),
                abort_requested: false,
            })),
        }
    }

    /// Request termination unless completion already disarmed this handle.
    ///
    /// Returns false when no termination was requested. The callback runs
    /// under the same lock as disarm, so a successful disarm guarantees that
    /// no stale clone can subsequently abort a reused runtime.
    ///
    /// # Panics
    ///
    /// Panics if a callback panics or the state mutex is poisoned.
    #[must_use]
    pub fn abort(&self) -> bool {
        let mut state = self.state.lock().expect("termination state lock");
        if state.callbacks.is_none() {
            return false;
        }
        state.abort_requested = true;
        if let Some(callbacks) = &state.callbacks {
            (callbacks.abort)();
        }
        drop(state);
        true
    }

    /// Revoke termination authority before completing or reusing a runtime.
    ///
    /// Returns true only if abort has never won. In that case all clones are
    /// inert and their captured runtime references are released immediately.
    /// If abort already won, callbacks remain available to the reaper until it
    /// observes actual termination; the runtime must not return to a pool.
    ///
    /// # Panics
    ///
    /// Panics if the state mutex is poisoned.
    #[must_use]
    pub fn disarm(&self) -> bool {
        let callbacks = {
            let mut state = self.state.lock().expect("termination state lock");
            if state.abort_requested {
                return false;
            }
            state.callbacks.take()
        };
        // Captured runtime destructors may abort tasks. Do not run them while
        // holding the termination state lock.
        drop(callbacks);
        true
    }

    /// Whether the captured runtime exited, or this handle was disarmed.
    ///
    /// Reapers must first check that `abort()` returned true; a disarmed
    /// invocation is complete but was not forcibly terminated.
    ///
    /// # Panics
    ///
    /// Panics if a callback panics or the state mutex is poisoned.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        let state = self.state.lock().expect("termination state lock");
        state
            .callbacks
            .as_ref()
            .is_none_or(|callbacks| (callbacks.finished)())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Barrier, mpsc};

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
}
