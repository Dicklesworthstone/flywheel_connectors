//! Scoped owner-cancellation monitoring for one host invocation.
//!
//! The caller retains the exact invocation identity and cancellation grant in
//! its callback. This monitor never retries an invocation or chooses a new
//! cancellation target. A successful cancellation acknowledgement is not proof
//! that provider work stopped or that its effects were undone.

use std::sync::{Condvar, Mutex};
use std::time::Duration;

use super::McpCallContext;

const CANCELLATION_POLL: Duration = Duration::from_millis(25);
const INITIAL_RETRY_DELAY: Duration = Duration::from_millis(50);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(1);

/// Whether another attempt to cancel this same invocation is appropriate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CancelAttempt {
    /// The host acknowledged cancellation; execution may still be settling.
    Accepted,
    /// Retrying cannot help, for example because authority was denied or the
    /// host reports that execution already completed.
    Terminal,
    /// Registration may still be pending, or the transport outcome is unknown.
    Retry,
}

#[derive(Default)]
struct Completion {
    finished: Mutex<bool>,
    changed: Condvar,
}

impl Completion {
    fn is_finished(&self) -> bool {
        *self
            .finished
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn wait(&self, duration: Duration) -> bool {
        let finished = self
            .finished
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (finished, _) = self
            .changed
            .wait_timeout_while(finished, duration, |finished| !*finished)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *finished
    }

    fn finish(&self) {
        *self
            .finished
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        self.changed.notify_all();
    }
}

struct FinishOnDrop<'a>(&'a Completion);

impl Drop for FinishOnDrop<'_> {
    fn drop(&mut self) {
        self.0.finish();
    }
}

/// Run one invocation while monitoring its original MCP cancellation context.
///
/// `run` executes on the calling thread and need not be `Send`. The scoped
/// monitor joins before this function returns or unwinds. The completion guard
/// interrupts idle polling and retry backoff immediately, including on panic.
/// An already-running cancellation callback must finish before that join, so
/// callers must bound its IO with a timeout.
///
/// Cancellation is latched once observed. Retry always calls the same callback
/// and stops when it acknowledges the request, rejects further attempts, or
/// `run` completes. Callers must retain execution ownership inside `run` for any
/// cleanup needed after an uncertain invocation transport outcome.
pub(crate) fn run<T, Run, Cancel>(context: &McpCallContext, run: Run, cancel: Cancel) -> T
where
    Run: FnOnce() -> T,
    Cancel: FnMut() -> CancelAttempt + Send,
{
    let completion = Completion::default();
    std::thread::scope(|scope| {
        let completion = &completion;
        let _finish = FinishOnDrop(completion);
        scope.spawn(move || monitor(context, completion, cancel));
        run()
    })
}

fn monitor(
    context: &McpCallContext,
    completion: &Completion,
    mut cancel: impl FnMut() -> CancelAttempt,
) {
    while !context.is_cancelled() {
        if completion.wait(CANCELLATION_POLL) {
            return;
        }
    }

    let mut retry_delay = INITIAL_RETRY_DELAY;
    loop {
        if completion.is_finished() {
            return;
        }
        match cancel() {
            CancelAttempt::Accepted | CancelAttempt::Terminal => return,
            CancelAttempt::Retry => {}
        }
        if completion.wait(retry_delay) {
            return;
        }
        retry_delay = retry_delay.saturating_mul(2).min(MAX_RETRY_DELAY);
    }
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::time::Instant;

    use super::*;

    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    struct Dropped<'a>(&'a AtomicBool);

    impl Drop for Dropped<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn ordinary_completion_joins_without_cancelling_and_preserves_non_send_values() {
        let context = McpCallContext::default();
        let calls = AtomicUsize::new(0);
        let call_count = &calls;
        let dropped = AtomicBool::new(false);
        let lifetime = Dropped(&dropped);
        let value = Rc::new("completed");
        let result = run(
            &context,
            || Rc::clone(&value),
            move || {
                let _keep_alive = &lifetime;
                call_count.fetch_add(1, Ordering::SeqCst);
                CancelAttempt::Accepted
            },
        );
        assert!(Rc::ptr_eq(&value, &result));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(dropped.load(Ordering::SeqCst));
        // The monitor has joined, so later context reuse cannot cancel work.
        context.cancel();
    }

    #[test]
    fn cancellation_during_execution_reaches_the_concurrent_monitor() {
        let context = McpCallContext::default();
        let (attempted, observed) = mpsc::channel();
        let result = run(
            &context,
            || {
                context.cancel();
                observed.recv_timeout(TEST_TIMEOUT).unwrap();
                "original result"
            },
            || {
                attempted.send(()).unwrap();
                CancelAttempt::Accepted
            },
        );
        assert_eq!(result, "original result");
    }

    #[test]
    fn registration_race_retries_the_same_callback_without_replaying_execution() {
        let context = McpCallContext::default();
        context.cancel();
        let (attempted, observed) = mpsc::channel();
        let request_id = "session-original-call";
        let token = "original-cancellation-grant";
        let mut attempts = Vec::new();
        let invocations = AtomicUsize::new(0);
        let started = Instant::now();

        let result = run(
            &context,
            || {
                invocations.fetch_add(1, Ordering::SeqCst);
                for expected in 1..=3 {
                    assert_eq!(observed.recv_timeout(TEST_TIMEOUT).unwrap(), expected);
                }
                // The accepted acknowledgement stops retrying even while the
                // original invocation is still returning its own result.
                assert!(observed.recv_timeout(INITIAL_RETRY_DELAY * 2).is_err());
                "settled"
            },
            || {
                attempts.push((request_id, token));
                attempted.send(attempts.len()).unwrap();
                if attempts.len() < 3 {
                    CancelAttempt::Retry
                } else {
                    CancelAttempt::Accepted
                }
            },
        );

        assert_eq!(result, "settled");
        assert_eq!(invocations.load(Ordering::SeqCst), 1);
        assert_eq!(attempts, vec![(request_id, token); 3]);
        assert!(started.elapsed() >= INITIAL_RETRY_DELAY * 3);
    }

    #[test]
    fn terminal_cancellation_does_not_replace_or_repeat_the_invocation() {
        let context = McpCallContext::default();
        context.cancel();
        let (attempted, observed) = mpsc::channel();
        let calls = AtomicUsize::new(0);
        let result = run(
            &context,
            || {
                observed.recv_timeout(TEST_TIMEOUT).unwrap();
                assert!(observed.recv_timeout(INITIAL_RETRY_DELAY * 2).is_err());
                Err::<(), _>("original invocation outcome is unknown")
            },
            || {
                calls.fetch_add(1, Ordering::SeqCst);
                attempted.send(()).unwrap();
                CancelAttempt::Terminal
            },
        );
        assert_eq!(result, Err("original invocation outcome is unknown"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn execution_panic_wakes_and_joins_the_retrying_monitor() {
        let context = McpCallContext::default();
        context.cancel();
        let (attempted, observed) = mpsc::channel();
        let dropped = AtomicBool::new(false);
        let lifetime = Dropped(&dropped);
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run::<(), _, _>(
                &context,
                || {
                    observed.recv_timeout(TEST_TIMEOUT).unwrap();
                    panic!("invocation failed unexpectedly");
                },
                move || {
                    let _keep_alive = &lifetime;
                    attempted.send(()).unwrap();
                    CancelAttempt::Retry
                },
            );
        }));
        assert!(panic.is_err());
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn completion_waits_for_an_inflight_cancellation_attempt_instead_of_detaching_it() {
        let context = McpCallContext::default();
        context.cancel();
        let (attempted, observed_attempt) = mpsc::channel();
        let (finish_run, allow_run) = mpsc::channel();
        let (finish_cancel, allow_cancel) = mpsc::channel();
        let (returned, observed_result) = mpsc::channel();

        std::thread::scope(|scope| {
            scope.spawn(move || {
                let result = run(
                    &context,
                    || {
                        allow_run.recv_timeout(TEST_TIMEOUT).unwrap();
                        42
                    },
                    move || {
                        attempted.send(()).unwrap();
                        allow_cancel.recv_timeout(TEST_TIMEOUT).unwrap();
                        CancelAttempt::Accepted
                    },
                );
                returned.send(result).unwrap();
            });

            observed_attempt.recv_timeout(TEST_TIMEOUT).unwrap();
            finish_run.send(()).unwrap();
            assert!(observed_result.recv_timeout(INITIAL_RETRY_DELAY).is_err());
            finish_cancel.send(()).unwrap();
            assert_eq!(observed_result.recv_timeout(TEST_TIMEOUT).unwrap(), 42);
        });
    }

    #[test]
    fn completion_guard_interrupts_a_long_wait_without_waiting_for_its_timeout() {
        let completion = Completion::default();
        let (waiting, observed_wait) = mpsc::channel();
        let (awoken, observed_wake) = mpsc::channel();

        std::thread::scope(|scope| {
            scope.spawn(|| {
                waiting.send(()).unwrap();
                awoken
                    .send(completion.wait(Duration::from_secs(60)))
                    .unwrap();
            });
            observed_wait.recv_timeout(TEST_TIMEOUT).unwrap();
            drop(FinishOnDrop(&completion));
            assert!(observed_wake.recv_timeout(TEST_TIMEOUT).unwrap());
        });
    }
}
