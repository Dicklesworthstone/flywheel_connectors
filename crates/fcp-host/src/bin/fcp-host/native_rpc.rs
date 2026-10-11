//! Per-command ownership for native connector RPCs.
//!
//! Queue admission, cancellation and response settlement share one state lock.
//! A selected command that loses its reply boundary retains the actual child
//! until a nonblocking wait confirms exit. An abandoned HTTP future therefore
//! cannot release its operation ID while its selected child is still live.

use std::future::Future;
use std::pin::pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use fcp_async_core::channel::mpsc;
use fcp_async_core::process::Child;
use fcp_core::InvokeResponse;
use fcp_host::{
    CancellationController, CancellationRegistration, CancellationTerminator, HostError, HostResult,
};
use futures_util::future::{Either, select};

use super::{CONNECTOR_RPC_IO_TIMEOUT, ConnectorProcessRunner, ConnectorRpcRequest};

const MAX_NATIVE_INVOCATION_LIFETIME: Duration = Duration::from_secs(60);
const RETIREMENT_GRACE: Duration = Duration::from_secs(2);
const RETIREMENT_POLL: Duration = Duration::from_millis(20);

fn deadline_after(started_at: Instant, timeout: Duration) -> Instant {
    started_at.checked_add(timeout).unwrap_or(started_at)
}

/// Interpret the request's relative deadline once, before session preparation.
#[must_use]
pub(super) fn invocation_deadline(started_at: Instant, deadline_ms: Option<u64>) -> Instant {
    let timeout = deadline_ms
        .map(Duration::from_millis)
        .unwrap_or(MAX_NATIVE_INVOCATION_LIFETIME)
        .min(MAX_NATIVE_INVOCATION_LIFETIME);
    deadline_after(started_at, timeout)
}

enum RpcPhase {
    Queued,
    Active,
    Retiring(Child),
    Settled,
}

struct RpcState {
    phase: RpcPhase,
    cancel_requested: bool,
    transport_retired: bool,
}

/// One physical request, never a lookup of whichever command is running now.
#[derive(Clone)]
pub(super) struct NativeRpc {
    deadline: Instant,
    state: Arc<Mutex<RpcState>>,
}

impl std::fmt::Debug for NativeRpc {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeRpc")
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

impl NativeRpc {
    #[must_use]
    pub(super) fn new(deadline: Instant) -> Self {
        Self {
            deadline,
            state: Arc::new(Mutex::new(RpcState {
                phase: RpcPhase::Queued,
                cancel_requested: false,
                transport_retired: false,
            })),
        }
    }

    #[must_use]
    pub(super) fn for_io() -> Self {
        Self::new(deadline_after(Instant::now(), CONNECTOR_RPC_IO_TIMEOUT))
    }

    #[must_use]
    pub(super) fn waiter(&self) -> NativeRpcWaiter {
        NativeRpcWaiter(self.clone())
    }

    #[must_use]
    pub(super) fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }

    #[must_use]
    pub(super) fn is_cancelled(&self) -> bool {
        let state = self.state.lock().expect("native RPC state lock");
        state.cancel_requested || Instant::now() >= self.deadline
    }

    #[must_use]
    pub(super) fn transport_retired(&self) -> bool {
        self.state
            .lock()
            .expect("native RPC state lock")
            .transport_retired
    }

    #[cfg(test)]
    #[must_use]
    pub(super) fn is_active(&self) -> bool {
        let state = self.state.lock().expect("native RPC state lock");
        matches!(state.phase, RpcPhase::Active)
    }

    /// Linearizes actor selection against queue abandonment and expiration.
    #[must_use]
    pub(super) fn try_begin(&self) -> bool {
        let mut state = self.state.lock().expect("native RPC state lock");
        if !matches!(state.phase, RpcPhase::Queued) {
            return false;
        }
        if state.cancel_requested || Instant::now() >= self.deadline {
            state.phase = RpcPhase::Settled;
            return false;
        }
        state.phase = RpcPhase::Active;
        true
    }

    /// A matched response preserves the transport only if it wins cancellation.
    #[must_use]
    pub(super) fn try_settle_reply(&self) -> bool {
        let mut state = self.state.lock().expect("native RPC state lock");
        if !matches!(state.phase, RpcPhase::Active)
            || state.cancel_requested
            || Instant::now() >= self.deadline
        {
            return false;
        }
        state.phase = RpcPhase::Settled;
        true
    }

    pub(super) fn cancel(&self) {
        let mut state = self.state.lock().expect("native RPC state lock");
        if matches!(state.phase, RpcPhase::Settled) {
            return;
        }
        state.cancel_requested = true;
        if matches!(state.phase, RpcPhase::Queued) {
            // The actor cannot select this ticket after this transition.
            state.phase = RpcPhase::Settled;
        }
    }

    /// Transfer process custody before clearing the runner's active command.
    /// Child::Drop alone only requests asynchronous reaping, not confirmed exit.
    pub(super) fn retire(&self, mut child: Child) {
        if let Err(error) = child.start_kill() {
            tracing::warn!(%error, "native connector termination signal failed");
        }
        let mut state = self.state.lock().expect("native RPC state lock");
        if matches!(state.phase, RpcPhase::Active) {
            state.transport_retired = true;
            state.phase = RpcPhase::Retiring(child);
        }
    }

    /// This callback is nonblocking and must run outside controller map locks.
    #[must_use]
    pub(super) fn is_settled(&self) -> bool {
        let mut state = self.state.lock().expect("native RPC state lock");
        let exited = if let RpcPhase::Retiring(child) = &mut state.phase {
            match child.try_wait() {
                Ok(Some(_)) => true,
                Ok(None) | Err(_) => {
                    // Preserve custody on either outcome. A failed signal or
                    // wait can be retried by the host's next retirement sweep.
                    let _ = child.start_kill();
                    false
                }
            }
        } else {
            false
        };
        if exited {
            state.phase = RpcPhase::Settled;
        }
        matches!(state.phase, RpcPhase::Settled)
    }

    fn stop_error(&self) -> std::io::Error {
        if Instant::now() >= self.deadline {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "connector RPC absolute queue and IO deadline expired",
            )
        } else {
            std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "connector RPC caller cancelled or abandoned the request",
            )
        }
    }

    async fn cancelled(&self) {
        loop {
            if self.is_cancelled() {
                return;
            }
            fcp_async_core::time::sleep(RETIREMENT_POLL.min(self.remaining())).await;
        }
    }

    async fn wait_for_settlement(&self) {
        let deadline = deadline_after(Instant::now(), RETIREMENT_GRACE);
        while !self.is_settled() && Instant::now() < deadline {
            fcp_async_core::time::sleep(
                RETIREMENT_POLL.min(deadline.saturating_duration_since(Instant::now())),
            )
            .await;
        }
    }
}

/// Dropping a receiver must also revoke queued work, not just its reply channel.
pub(super) struct NativeRpcWaiter(NativeRpc);

impl Drop for NativeRpcWaiter {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

/// The production actor owns one command through response or child retirement.
pub(super) async fn run_dispatcher(
    mut runner: ConnectorProcessRunner,
    mut receiver: mpsc::Receiver<ConnectorRpcRequest>,
) {
    while let Some(request) = receiver.recv().await {
        let rpc = request.rpc;
        if !rpc.try_begin() {
            let _ = request.response_tx.send(Err(rpc.stop_error()));
            continue;
        }
        // No await separates selection from publishing the exact active ticket.
        runner.active_rpc = Some(rpc.clone());
        let response = {
            let mut cancelled = pin!(rpc.cancelled());
            let mut operation = pin!(fcp_async_core::time::timeout(
                rpc.remaining(),
                runner.request(&request.method, request.params),
            ));
            match select(cancelled.as_mut(), operation.as_mut()).await {
                Either::Left(_) => Err(rpc.stop_error()),
                Either::Right((Ok(response), _)) => response,
                Either::Right((Err(_), _)) => Err(rpc.stop_error()),
            }
        };
        if response.is_ok() && rpc.try_settle_reply() {
            // A late waiter drop can affect only the now-settled old ticket.
            runner.active_rpc = None;
            let _ = request.response_tx.send(response);
            continue;
        }

        // Ambiguous IO, expiration and selected cancellation retire the
        // transport. Keep the Child in the ticket even if the actor is dropped
        // while waiting for exit or the request receiver has disappeared.
        if let Some(child) = runner.child.take() {
            rpc.retire(child);
        }
        runner.active_rpc = None;
        rpc.wait_for_settlement().await;
        let error = response.err().unwrap_or_else(|| rpc.stop_error());
        let _ = request.response_tx.send(Err(error));
        break;
    }
}

struct InvocationCommands {
    stop_requested: bool,
    rpcs: Vec<NativeRpc>,
}

struct InvocationState {
    deadline: Instant,
    commands: Mutex<InvocationCommands>,
    waiter_finished: AtomicBool,
    registration: OnceLock<(Weak<CancellationController>, CancellationRegistration)>,
    retirement_deadline: OnceLock<Instant>,
}

/// One logical invoke, including its introspect/handshake/zone-lock work.
#[derive(Clone)]
pub(super) struct NativeInvocationTermination {
    state: Arc<InvocationState>,
}

impl NativeInvocationTermination {
    #[must_use]
    pub(super) fn new(deadline: Instant) -> Self {
        Self {
            state: Arc::new(InvocationState {
                deadline,
                commands: Mutex::new(InvocationCommands {
                    stop_requested: false,
                    rpcs: Vec::new(),
                }),
                waiter_finished: AtomicBool::new(false),
                registration: OnceLock::new(),
                retirement_deadline: OnceLock::new(),
            }),
        }
    }

    pub(super) fn bind_registration(
        &self,
        controller: &Arc<CancellationController>,
        registration: CancellationRegistration,
    ) {
        assert!(
            self.state
                .registration
                .set((Arc::downgrade(controller), registration))
                .is_ok(),
            "native invocation registration cannot be rebound"
        );
    }

    #[must_use]
    pub(super) fn terminator(&self) -> CancellationTerminator {
        let stop = self.clone();
        let finished = self.clone();
        CancellationTerminator::new(move || stop.cancel(), move || finished.is_finished())
    }

    /// Registration and the invocation stop latch share this lock so a
    /// cancellation between introspect and handshake cannot be lost.
    #[must_use]
    pub(super) fn register_rpc(&self) -> NativeRpc {
        let rpc = NativeRpc::new(
            self.state
                .deadline
                .min(deadline_after(Instant::now(), CONNECTOR_RPC_IO_TIMEOUT)),
        );
        let mut commands = self.state.commands.lock().expect("native invocation lock");
        if commands.stop_requested
            || self.state.waiter_finished.load(Ordering::SeqCst)
            || Instant::now() >= self.state.deadline
        {
            rpc.cancel();
        }
        commands.rpcs.push(rpc.clone());
        rpc
    }

    #[must_use]
    pub(super) fn is_cancel_requested(&self) -> bool {
        self.state
            .commands
            .lock()
            .expect("native invocation lock")
            .stop_requested
            || Instant::now() >= self.state.deadline
    }

    pub(super) fn cancel(&self) {
        let mut commands = self.state.commands.lock().expect("native invocation lock");
        commands.stop_requested = true;
        for rpc in &commands.rpcs {
            rpc.cancel();
        }
    }

    fn cancel_pending_rpcs(&self) {
        let commands = self.state.commands.lock().expect("native invocation lock");
        for rpc in &commands.rpcs {
            rpc.cancel();
        }
    }

    fn rpcs_settled(&self) -> bool {
        let rpcs = self
            .state
            .commands
            .lock()
            .expect("native invocation lock")
            .rpcs
            .clone();
        rpcs.iter().all(NativeRpc::is_settled)
    }

    fn is_finished(&self) -> bool {
        self.state.waiter_finished.load(Ordering::SeqCst) && self.rpcs_settled()
    }

    async fn cancelled(&self) {
        loop {
            let stop_requested = self
                .state
                .commands
                .lock()
                .expect("native invocation lock")
                .stop_requested;
            if stop_requested || Instant::now() >= self.state.deadline {
                return;
            }
            fcp_async_core::time::sleep(
                RETIREMENT_POLL
                    .min(self.state.deadline.saturating_duration_since(Instant::now())),
            )
            .await;
        }
    }

    /// Drain any selected command before a warm worker can be handed back.
    /// A retirement record that still owns a child remains attached to this
    /// capture so the host reaper can continue probing after the waiter ends.
    pub(super) async fn ensure_settled(&self) -> HostResult<()> {
        if !self.rpcs_settled() {
            // Draining an earlier rejected warm candidate must not cancel a
            // later successful invocation. Only explicit cancellation or
            // waiter abandonment sets the logical stop latch.
            self.cancel_pending_rpcs();
            let deadline = *self
                .state
                .retirement_deadline
                .get_or_init(|| deadline_after(Instant::now(), RETIREMENT_GRACE));
            while !self.rpcs_settled() && Instant::now() < deadline {
                fcp_async_core::time::sleep(
                    RETIREMENT_POLL.min(deadline.saturating_duration_since(Instant::now())),
                )
                .await;
            }
        }
        if !self.rpcs_settled() {
            return Err(HostError::RegistryError(
                "native connector process retirement is still pending".to_string(),
            ));
        }
        Ok(())
    }

    pub(super) async fn invoke<F>(&self, operation: F) -> HostResult<InvokeResponse>
    where
        F: Future<Output = HostResult<InvokeResponse>>,
    {
        let mut waiter = NativeInvocationWaiter {
            invocation: self.clone(),
            returned: false,
        };
        let result = {
            let mut cancelled = pin!(self.cancelled());
            let mut operation = pin!(operation);
            match select(cancelled.as_mut(), operation.as_mut()).await {
                Either::Left(_) => Err(HostError::RegistryError(
                    "connector invocation cancelled or deadline expired".to_string(),
                )),
                Either::Right((result, _)) => result,
            }
        };
        // The losing operation future is dropped before examining its RPCs.
        // Resilience timeouts may also drop an RPC waiter before actor exit.
        let settlement = self.ensure_settled().await;
        waiter.returned = true;
        settlement?;
        result
    }
}

struct NativeInvocationWaiter {
    invocation: NativeInvocationTermination,
    returned: bool,
}

impl Drop for NativeInvocationWaiter {
    fn drop(&mut self) {
        if !self.returned {
            self.invocation.cancel();
        }
        // No RPC can be registered after the waiter closes. Registration
        // checks this flag while holding the same command-admission lock.
        let commands = self
            .invocation
            .state
            .commands
            .lock()
            .expect("native invocation lock");
        self.invocation
            .state
            .waiter_finished
            .store(true, Ordering::SeqCst);
        drop(commands);
        if let Some((controller, registration)) = self.invocation.state.registration.get()
            && let Some(controller) = controller.upgrade()
        {
            controller.complete_registration_when_settled(registration);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abandoned_queued_ticket_cannot_be_selected_or_affect_another_command() {
        let first = NativeRpc::for_io();
        let abandoned = NativeRpc::for_io();
        let stale = abandoned.clone();
        assert!(first.try_begin());
        drop(abandoned.waiter());
        assert!(abandoned.is_settled());
        assert!(!abandoned.try_begin());
        assert!(!first.is_cancelled());
        assert!(first.try_settle_reply());

        let next = NativeRpc::for_io();
        assert!(next.try_begin());
        stale.cancel();
        assert!(!next.is_cancelled());
        assert!(next.try_settle_reply());
    }

    #[test]
    fn expired_queue_deadline_is_not_reset_on_actor_selection() {
        let expired = NativeRpc::new(Instant::now());
        assert!(!expired.try_begin());
        assert!(expired.is_settled());
        assert!(!expired.try_settle_reply());
    }

    #[test]
    fn active_cancellation_requires_retirement_instead_of_reply_settlement() {
        let rpc = NativeRpc::for_io();
        assert!(rpc.try_begin());
        rpc.cancel();
        assert!(!rpc.try_settle_reply());
        assert!(!rpc.is_settled());
    }

    #[test]
    fn cancelled_invocation_cannot_enqueue_a_later_handshake_rpc() {
        let invocation = NativeInvocationTermination::new(invocation_deadline(Instant::now(), None));
        let introspect = invocation.register_rpc();
        assert!(introspect.try_begin());
        assert!(introspect.try_settle_reply());
        invocation.cancel();

        let handshake = invocation.register_rpc();
        assert!(handshake.is_settled());
        assert!(!handshake.try_begin());
        assert!(!invocation.is_finished());
        drop(NativeInvocationWaiter {
            invocation: invocation.clone(),
            returned: false,
        });
        assert!(invocation.is_finished());
    }

    #[cfg(unix)]
    async fn wait_for_fixture_file(path: &std::path::Path) {
        fcp_async_core::time::timeout(Duration::from_secs(5), async {
            while !path.exists() {
                fcp_async_core::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("native fixture must reach the requested command");
    }

    #[cfg(unix)]
    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn production_actor_skips_abandoned_queue_work_and_preserves_rpc_error_transport() {
        use fcp_async_core::channel::oneshot;
        use fcp_async_core::task;
        use serde_json::json;
        use std::collections::BTreeMap;

        let directory = tempfile::tempdir().unwrap();
        let calls = directory.path().join("calls");
        let ready_first = directory.path().join("ready-first");
        let release_first = directory.path().join("release-first");
        let ready_next = directory.path().join("ready-next");
        let release_next = directory.path().join("release-next");
        let environment = BTreeMap::from([
            (
                "NATIVE_RPC_CALLS".to_string(),
                calls.to_string_lossy().into_owned(),
            ),
            (
                "NATIVE_RPC_READY_FIRST".to_string(),
                ready_first.to_string_lossy().into_owned(),
            ),
            (
                "NATIVE_RPC_RELEASE_FIRST".to_string(),
                release_first.to_string_lossy().into_owned(),
            ),
            (
                "NATIVE_RPC_READY_NEXT".to_string(),
                ready_next.to_string_lossy().into_owned(),
            ),
            (
                "NATIVE_RPC_RELEASE_NEXT".to_string(),
                release_next.to_string_lossy().into_owned(),
            ),
        ]);
        let script = r#"
IFS= read -r first || exit 1
printf '%s\n' "$first" > "$NATIVE_RPC_CALLS"
: > "$NATIVE_RPC_READY_FIRST"
while [ ! -f "$NATIVE_RPC_RELEASE_FIRST" ]; do sleep 0.01; done
printf '%s\n' '{"jsonrpc":"2.0","id":"0:0","error":{"code":-32000,"message":"request rejected"}}'
IFS= read -r next || exit 1
printf '%s\n' "$next" >> "$NATIVE_RPC_CALLS"
: > "$NATIVE_RPC_READY_NEXT"
while [ ! -f "$NATIVE_RPC_RELEASE_NEXT" ]; do sleep 0.01; done
printf '%s\n' '{"jsonrpc":"2.0","id":"0:1","result":{"healthy":true}}'
exec sleep 30
"#;
        let runner = ConnectorProcessRunner::spawn(
            "/bin/sh",
            &["-c".to_string(), script.to_string()],
            &environment,
        )
        .await
        .unwrap();
        let (sender, receiver) = mpsc::channel(4);
        let actor = task::try_spawn(run_dispatcher(runner, receiver)).unwrap();

        let first = NativeRpc::for_io();
        let _first_waiter = first.waiter();
        let (first_tx, first_rx) = oneshot::channel();
        sender
            .send(ConnectorRpcRequest {
                method: "first".to_string(),
                params: json!({}),
                response_tx: first_tx,
                rpc: first.clone(),
            })
            .await
            .unwrap();
        wait_for_fixture_file(&ready_first).await;

        let abandoned = NativeRpc::for_io();
        let abandoned_waiter = abandoned.waiter();
        let (abandoned_tx, abandoned_rx) = oneshot::channel();
        sender
            .send(ConnectorRpcRequest {
                method: "abandoned".to_string(),
                params: json!({}),
                response_tx: abandoned_tx,
                rpc: abandoned.clone(),
            })
            .await
            .unwrap();
        drop(abandoned_waiter);
        assert!(abandoned.is_settled());
        assert!(!first.is_cancelled());
        std::fs::write(&release_first, b"").unwrap();
        assert!(first_rx.await.unwrap().unwrap().get("error").is_some());
        assert!(abandoned_rx.await.unwrap().is_err());

        let next = NativeRpc::for_io();
        let _next_waiter = next.waiter();
        let (next_tx, next_rx) = oneshot::channel();
        sender
            .send(ConnectorRpcRequest {
                method: "next".to_string(),
                params: json!({}),
                response_tx: next_tx,
                rpc: next.clone(),
            })
            .await
            .unwrap();
        wait_for_fixture_file(&ready_next).await;
        abandoned.cancel();
        assert!(!next.is_cancelled());
        std::fs::write(&release_next, b"").unwrap();
        assert_eq!(
            next_rx.await.unwrap().unwrap()["result"],
            json!({"healthy": true})
        );
        assert!(!first.transport_retired());
        assert!(!next.transport_retired());
        let methods: Vec<String> = std::fs::read_to_string(calls)
            .unwrap()
            .lines()
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line).unwrap()["method"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        assert_eq!(methods, vec!["first".to_string(), "next".to_string()]);
        actor.abort();
        let _ = actor.await;
    }

    #[cfg(unix)]
    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn draining_rejected_candidate_preserves_fresh_success_and_stop_latch() {
        let invocation = NativeInvocationTermination::new(invocation_deadline(Instant::now(), None));
        let rejected = invocation.register_rpc();
        assert!(rejected.try_begin());
        let mut command = fcp_async_core::process::Command::new("/bin/sh");
        command.args(["-c", "exec sleep 30"]).kill_on_drop(true);
        let child = command.spawn().unwrap();

        let response = invocation.invoke(async {
            let fresh = invocation.register_rpc();
            assert!(fresh.try_begin());
            assert!(fresh.try_settle_reply());
            invocation.ensure_settled().await?;
            assert!(!invocation.is_cancel_requested());
            Ok(InvokeResponse::ok(
                fcp_core::RequestId::random(),
                serde_json::json!({"fresh": true}),
            ))
        });
        let retirement = async {
            // Keep the old candidate Active until the drain actually requests
            // physical cancellation, making the stop-latch regression decisive.
            while !rejected.is_cancelled() {
                fcp_async_core::time::sleep(Duration::from_millis(1)).await;
            }
            rejected.retire(child);
        };
        let (response, ()) = fcp_async_core::time::timeout(
            Duration::from_secs(5),
            futures_util::future::join(response, retirement),
        )
        .await
        .unwrap();
        assert_eq!(
            response.unwrap().result,
            Some(serde_json::json!({"fresh": true}))
        );
        assert!(rejected.is_settled());
        assert!(rejected.transport_retired());
        assert!(!invocation.is_cancel_requested());
    }

    #[cfg(unix)]
    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn abandoned_invocation_retains_registration_until_its_child_exits() {
        use fcp_host::{CancellationScope, ConnectorArchetype};

        let controller = Arc::new(CancellationController::new());
        let invocation = NativeInvocationTermination::new(invocation_deadline(Instant::now(), None));
        let registration = controller
            .track_operation(
                "native-drop",
                Some("owner"),
                CancellationScope::new("native", ConnectorArchetype::RequestResponse)
                    .with_terminator(invocation.terminator()),
            )
            .unwrap();
        invocation.bind_registration(&controller, registration);
        let selected = invocation.register_rpc();
        assert!(selected.try_begin());
        let mut command = fcp_async_core::process::Command::new("/bin/sh");
        command.args(["-c", "exec sleep 30"]).kill_on_drop(true);
        let child = command.spawn().unwrap();
        drop(NativeInvocationWaiter {
            invocation: invocation.clone(),
            returned: false,
        });
        assert!(selected.is_cancelled());
        assert!(
            controller
                .track_operation(
                    "native-drop",
                    Some("replacement"),
                    CancellationScope::new("new", ConnectorArchetype::RequestResponse),
                )
                .is_err()
        );

        selected.retire(child);
        selected.wait_for_settlement().await;
        assert!(selected.is_settled());
        assert!(selected.transport_retired());
        assert!(controller.reap_expired(Instant::now()).is_empty());
        controller
            .track_operation(
                "native-drop",
                Some("replacement"),
                CancellationScope::new("new", ConnectorArchetype::RequestResponse),
            )
            .unwrap();
    }

    #[cfg(unix)]
    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn child_exit_is_required_before_active_retirement_settles() {
        let mut command = fcp_async_core::process::Command::new("/bin/sh");
        command.args(["-c", "exec sleep 30"]).kill_on_drop(true);
        let child = command.spawn().expect("spawn native retirement fixture");
        let rpc = NativeRpc::for_io();
        assert!(rpc.try_begin());
        rpc.cancel();
        assert!(!rpc.is_settled());
        rpc.retire(child);
        rpc.wait_for_settlement().await;
        assert!(rpc.is_settled(), "child must be observed exited");
    }
}
