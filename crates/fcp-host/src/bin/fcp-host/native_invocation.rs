//! Own a logical native invocation from construction through process settlement.
//!
//! The waiter must exist before the first poll: executor rejection or dropping
//! an unpolled HTTP operation must not strand its cancellation registration.
//! Physical process custody remains in the exact RPC tickets owned by the
//! parent module; this boundary never terminates a replacement by connector ID.

use super::{
    Future, HostError, HostResult, InvokeResponse, NativeInvocationTermination,
    NativeInvocationWaiter,
};
use futures_util::future::{Either, select};
use std::pin::{Pin, pin};
use std::task::{Context, Poll};

fn stopped() -> HostError {
    HostError::RegistryError("connector invocation cancelled or deadline expired".to_string())
}

impl NativeInvocationTermination {
    /// Fence both sides of every work poll, including a poll that returns Ready
    /// or requests cancellation and then returns Pending without another wake.
    /// A synchronous poll cannot be preempted here; its late result is withheld.
    fn poll_operation<F>(
        &self,
        operation: Pin<&mut F>,
        context: &mut Context<'_>,
    ) -> Poll<HostResult<InvokeResponse>>
    where
        F: Future<Output = HostResult<InvokeResponse>>,
    {
        if self.is_cancel_requested() {
            return Poll::Ready(Err(stopped()));
        }
        let result = operation.poll(context);
        if self.is_cancel_requested() {
            Poll::Ready(Err(stopped()))
        } else {
            result
        }
    }

    /// Own the operation and its cleanup even when this future is never polled.
    /// Only the operation's captures constrain the returned future's lifetime.
    pub(in super::super) fn invoke<F>(
        &self,
        operation: F,
    ) -> impl Future<Output = HostResult<InvokeResponse>> + use<F>
    where
        F: Future<Output = HostResult<InvokeResponse>>,
    {
        let invocation = self.clone();
        let waiter = NativeInvocationWaiter {
            invocation: invocation.clone(),
            returned: false,
        };
        async move {
            let mut waiter = waiter;
            let result = {
                let mut cancelled = pin!(invocation.cancelled());
                let mut operation = pin!(operation);
                let mut guarded = pin!(std::future::poll_fn(|context| {
                    invocation.poll_operation(operation.as_mut(), context)
                }));
                // Retain one cancellation/deadline waiter and the same pinned
                // operation. No polling timer, detached task, or retry is added.
                match select(cancelled.as_mut(), guarded.as_mut()).await {
                    Either::Left(_) => Err(stopped()),
                    Either::Right((result, _)) => result,
                }
            };
            // Drop the operation before examining its RPCs. Retirement may
            // outlive this waiter, but its registration must retain custody.
            let settlement = invocation.ensure_settled().await;
            waiter.returned = true;
            settlement?;
            // Draining selected work is part of the invocation boundary, not
            // a grace period in which an expired result becomes valid again.
            if invocation.is_cancel_requested() {
                Err(stopped())
            } else {
                result
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::future::pending;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::Waker;
    use std::time::{Duration, Instant};

    use fcp_host::{CancellationController, CancellationScope, ConnectorArchetype};

    use super::super::{NativeRpc, invocation_deadline};
    use super::*;

    struct DropProbe(Arc<AtomicBool>);

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    fn tracked(id: &str) -> (Arc<CancellationController>, NativeInvocationTermination) {
        let controller = Arc::new(CancellationController::new());
        let invocation = NativeInvocationTermination::new(invocation_deadline(Instant::now(), None));
        let registration = controller
            .track_operation(
                id,
                Some("owner"),
                CancellationScope::new("native", ConnectorArchetype::RequestResponse)
                    .with_terminator(invocation.terminator()),
            )
            .unwrap();
        invocation.bind_registration(&controller, registration);
        (controller, invocation)
    }

    fn register_replacement(controller: &CancellationController, id: &str) {
        controller
            .track_operation(
                id,
                Some("replacement"),
                CancellationScope::new("replacement", ConnectorArchetype::RequestResponse),
            )
            .expect("settled invocation must release its registration");
    }

    #[test]
    fn unpolled_drop_releases_registration_and_cancels_only_owned_tickets() {
        let (controller, invocation) = tracked("unpolled-native");
        let queued = invocation.register_rpc();
        let other = NativeRpc::for_io();
        let polled = AtomicBool::new(false);
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = DropProbe(Arc::clone(&dropped));
        let future = invocation.invoke(async {
            let _guard = guard;
            polled.store(true, Ordering::SeqCst);
            pending::<HostResult<InvokeResponse>>().await
        });
        assert!(!invocation.is_finished());
        drop(future);
        assert!(!polled.load(Ordering::SeqCst));
        assert!(dropped.load(Ordering::SeqCst));
        assert!(queued.is_settled());
        assert!(!queued.try_begin());
        assert!(invocation.is_finished());
        assert!(!invocation.register_rpc().try_begin());
        assert!(other.try_begin());
        assert!(other.try_settle_reply());
        register_replacement(&controller, "unpolled-native");
    }

    #[test]
    fn unpolled_drop_without_rpcs_does_not_strand_the_operation_id() {
        let (controller, invocation) = tracked("unpolled-empty");
        drop(invocation.invoke(pending::<HostResult<InvokeResponse>>()));
        assert!(invocation.is_finished());
        register_replacement(&controller, "unpolled-empty");
    }

    #[test]
    fn invoke_owns_its_handle_and_is_send_when_the_operation_is_send() {
        fn assert_send_static<T: Send + 'static>(_: &T) {}

        let (controller, invocation) = tracked("owned-native");
        let future = invocation.invoke(pending::<HostResult<InvokeResponse>>());
        assert_send_static(&future);
        drop(invocation);
        drop(future);
        register_replacement(&controller, "owned-native");
    }

    #[test]
    fn expired_first_poll_drops_work_without_polling_it() {
        let invocation = NativeInvocationTermination::new(Instant::now());
        let polled = AtomicBool::new(false);
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = DropProbe(Arc::clone(&dropped));
        let mut future = Box::pin(invocation.invoke(async {
            let _guard = guard;
            polled.store(true, Ordering::SeqCst);
            pending::<HostResult<InvokeResponse>>().await
        }));
        let result = future.as_mut().poll(&mut Context::from_waker(Waker::noop()));
        assert!(matches!(result, std::task::Poll::Ready(Err(_))));
        assert!(!polled.load(Ordering::SeqCst));
        assert!(dropped.load(Ordering::SeqCst));
        assert!(invocation.is_finished());
    }

    #[fcp_async_core::runtime::test]
    async fn an_early_ready_response_still_settles_normally() {
        let (controller, invocation) = tracked("ready-native");
        let result = invocation
            .invoke(async {
                Ok(InvokeResponse::ok(
                    fcp_core::RequestId::random(),
                    serde_json::json!({"ready": true}),
                ))
            })
            .await
            .unwrap();
        assert_eq!(result.result, Some(serde_json::json!({"ready": true})));
        assert!(invocation.is_finished());
        assert!(!invocation.is_cancel_requested());
        register_replacement(&controller, "ready-native");
    }

    fn response() -> InvokeResponse {
        InvokeResponse::ok(
            fcp_core::RequestId::random(),
            serde_json::json!({"value": "private-response-marker"}),
        )
    }

    fn assert_stopped(result: HostResult<InvokeResponse>) {
        let diagnostic = result.expect_err("stopped work must not publish a result").to_string();
        assert_eq!(diagnostic, stopped().to_string());
        assert!(!diagnostic.contains("private-response-marker"));
        assert!(!diagnostic.contains("private-error-marker"));
    }

    #[fcp_async_core::runtime::test]
    async fn cancellation_inside_a_ready_poll_withholds_the_response() {
        let (controller, invocation) = tracked("ready-cancel");
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = DropProbe(Arc::clone(&dropped));
        let result = invocation
            .invoke(async {
                let _guard = guard;
                invocation.cancel();
                Ok(response())
            })
            .await;
        assert_stopped(result);
        assert!(dropped.load(Ordering::SeqCst));
        assert!(invocation.is_finished());
        register_replacement(&controller, "ready-cancel");
    }

    #[fcp_async_core::runtime::test]
    async fn cancellation_inside_a_ready_error_poll_withholds_the_error_payload() {
        let (_, invocation) = tracked("error-cancel");
        let result = invocation
            .invoke(async {
                invocation.cancel();
                Err(HostError::RegistryError("private-error-marker".to_owned()))
            })
            .await;
        assert_stopped(result);
        assert!(invocation.is_finished());
    }

    #[fcp_async_core::runtime::test]
    async fn pending_poll_cancellation_needs_no_followup_wake_or_poll() {
        let (_, invocation) = tracked("pending-cancel");
        let stop = invocation.clone();
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = DropProbe(Arc::clone(&dropped));
        let operation = std::future::poll_fn(move |_| {
            let _guard = &guard;
            stop.cancel();
            Poll::<HostResult<InvokeResponse>>::Pending
        });
        let mut future = Box::pin(invocation.invoke(operation));
        let Poll::Ready(result) = future.as_mut().poll(&mut Context::from_waker(Waker::noop())) else {
            panic!("a stop observed during Pending must settle in this poll");
        };
        assert_stopped(result);
        assert!(dropped.load(Ordering::SeqCst));
        assert!(invocation.is_finished());
    }

    #[fcp_async_core::runtime::test]
    async fn cancellation_between_polls_never_repolls_the_operation() {
        let (_, invocation) = tracked("between-polls");
        let polls = AtomicUsize::new(0);
        let operation = std::future::poll_fn(|_| {
            polls.fetch_add(1, Ordering::SeqCst);
            Poll::<HostResult<InvokeResponse>>::Pending
        });
        let mut future = Box::pin(invocation.invoke(operation));
        let mut context = Context::from_waker(Waker::noop());
        assert!(future.as_mut().poll(&mut context).is_pending());
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        invocation.cancel();
        let Poll::Ready(result) = future.as_mut().poll(&mut context) else {
            panic!("the next poll must observe cancellation before more work");
        };
        assert_stopped(result);
        assert_eq!(polls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn already_cancelled_invocation_never_polls_its_operation() {
        let (_, invocation) = tracked("pre-cancelled");
        invocation.cancel();
        let polled = AtomicBool::new(false);
        let mut future = Box::pin(invocation.invoke(async {
            polled.store(true, Ordering::SeqCst);
            Ok(response())
        }));
        let Poll::Ready(result) = future.as_mut().poll(&mut Context::from_waker(Waker::noop())) else {
            panic!("pre-cancelled invocation must be immediately refused");
        };
        assert_stopped(result);
        assert!(!polled.load(Ordering::SeqCst));
        assert!(invocation.is_finished());
    }

    #[fcp_async_core::runtime::test]
    async fn deadline_overrun_fences_ready_pending_and_error_polls() {
        for outcome in 0..3 {
            let deadline = Instant::now() + Duration::from_millis(500);
            let invocation = NativeInvocationTermination::new(deadline);
            let polled = AtomicBool::new(false);
            let operation = std::future::poll_fn(|_| {
                polled.store(true, Ordering::SeqCst);
                // Deliberately keep control inside one synchronous poll. Timer
                // notification cannot preempt it; the post-poll fence must win.
                std::thread::sleep(
                    deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(1),
                );
                match outcome {
                    0 => Poll::Ready(Ok(response())),
                    1 => Poll::Pending,
                    _ => Poll::Ready(Err(HostError::RegistryError(
                        "private-error-marker".to_owned(),
                    ))),
                }
            });
            let mut future = Box::pin(invocation.invoke(operation));
            let Poll::Ready(result) = future.as_mut().poll(&mut Context::from_waker(Waker::noop())) else {
                panic!("an elapsed poll must be refused without a timer repoll");
            };
            assert!(polled.load(Ordering::SeqCst), "fixture must exercise a real work poll");
            assert_stopped(result);
            assert!(invocation.is_finished());
        }
    }

    #[fcp_async_core::runtime::test]
    async fn early_operation_errors_keep_their_original_meaning() {
        let (_, invocation) = tracked("early-error");
        let result = invocation
            .invoke(std::future::ready(Err(HostError::RegistryError(
                "original-early-error".to_owned(),
            ))))
            .await;
        assert_eq!(
            result.unwrap_err().to_string(),
            HostError::RegistryError("original-early-error".to_owned()).to_string(),
        );
        assert!(invocation.is_finished());
        assert!(!invocation.is_cancel_requested());
    }

    #[cfg(unix)]
    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn cancellation_during_child_retirement_withholds_a_saved_success() {
        let (controller, invocation) = tracked("retirement-cancel");
        let selected = invocation.register_rpc();
        assert!(selected.try_begin());
        let mut command = fcp_async_core::process::Command::new("/bin/sh");
        command.args(["-c", "exec sleep 30"]).kill_on_drop(true);
        let child = command.spawn().unwrap();
        let mut future = Box::pin(invocation.invoke(std::future::ready(Ok(response()))));
        assert!(futures_util::poll!(future.as_mut()).is_pending());
        assert!(selected.is_cancelled(), "settlement must be draining selected work");
        assert!(!invocation.is_cancel_requested(), "candidate drain is not logical cancellation");
        invocation.cancel();
        selected.retire(child);
        let result = fcp_async_core::time::timeout(Duration::from_secs(5), future)
            .await
            .unwrap();
        assert_stopped(result);
        assert!(selected.transport_retired());
        assert!(selected.is_settled(), "a refusal cannot bypass child exit custody");
        assert!(invocation.is_finished());
        register_replacement(&controller, "retirement-cancel");
    }

    #[cfg(unix)]
    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn unpolled_drop_retains_selected_child_custody_until_observed_exit() {
        let (controller, invocation) = tracked("unpolled-child");
        let selected = invocation.register_rpc();
        assert!(selected.try_begin());
        let mut command = fcp_async_core::process::Command::new("/bin/sh");
        command.args(["-c", "exec sleep 30"]).kill_on_drop(true);
        let child = command.spawn().unwrap();
        drop(invocation.invoke(pending::<HostResult<InvokeResponse>>()));
        assert!(selected.is_cancelled());
        assert!(!selected.is_settled());
        assert!(!invocation.is_finished());
        assert!(
            controller
                .track_operation(
                    "unpolled-child",
                    Some("replacement"),
                    CancellationScope::new("replacement", ConnectorArchetype::RequestResponse),
                )
                .is_err()
        );
        selected.retire(child);
        selected.wait_for_settlement().await;
        assert!(selected.transport_retired());
        assert!(selected.is_settled());
        assert!(invocation.is_finished());
        assert!(controller.reap_expired(Instant::now()).is_empty());
        register_replacement(&controller, "unpolled-child");
    }
}
