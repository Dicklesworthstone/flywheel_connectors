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
use std::pin::pin;

impl NativeInvocationTermination {
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
        let mut waiter = NativeInvocationWaiter {
            invocation: invocation.clone(),
            returned: false,
        };
        async move {
            let result = {
                let mut cancelled = pin!(invocation.cancelled());
                let mut operation = pin!(operation);
                match select(cancelled.as_mut(), operation.as_mut()).await {
                    Either::Left(_) => Err(HostError::RegistryError(
                        "connector invocation cancelled or deadline expired".to_string(),
                    )),
                    Either::Right((result, _)) => result,
                }
            };
            // Drop the operation before examining its RPCs. Retirement may
            // outlive this waiter, but its registration must retain custody.
            let settlement = invocation.ensure_settled().await;
            waiter.returned = true;
            settlement?;
            result
        }
    }
}

#[cfg(test)]
mod tests {
    use std::future::pending;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Context, Waker};
    use std::time::Instant;

    use fcp_host::{CancellationController, CancellationScope, ConnectorArchetype};

    use super::*;
    use super::super::{NativeRpc, invocation_deadline};

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
