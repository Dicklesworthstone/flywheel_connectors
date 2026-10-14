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
use fcp_async_core::CancellationToken;
use fcp_core::InvokeResponse;
use fcp_host::{
    CancellationController, CancellationRegistration, CancellationTerminator, HostError, HostResult,
};
use futures_util::future::{Either, select};

use super::{CONNECTOR_RPC_IO_TIMEOUT, ConnectorProcessRunner, ConnectorRpcRequest};

const MAX_NATIVE_INVOCATION_LIFETIME: Duration = Duration::from_secs(60);
const RETIREMENT_GRACE: Duration = Duration::from_secs(2);
// Physical exit still needs a nonblocking child probe. Ordinary cancellation
// must not use this interval: async-core sleep creates a thread for every wait.
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

/// One notification subscription and one absolute-deadline timer per waiter.
/// Subscribing before checking the sticky state closes cancellation-before-poll
/// and cancellation-during-registration races without a polling timer.
async fn cancellation_or_deadline(signal: &CancellationToken, deadline: Instant) {
    let mut listener = signal.subscribe();
    let remaining = deadline.saturating_duration_since(Instant::now());
    if listener.is_cancelled() || remaining.is_zero() {
        return;
    }
    let _ = fcp_async_core::time::timeout(remaining, listener.cancelled()).await;
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
    // Notification only: selection and settlement still consult the state lock.
    cancellation: CancellationToken,
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
            cancellation: CancellationToken::new(),
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
        if matches!(state.phase, RpcPhase::Settled) || state.cancel_requested {
            return;
        }
        state.cancel_requested = true;
        if matches!(state.phase, RpcPhase::Queued) {
            // The actor cannot select this ticket after this transition.
            state.phase = RpcPhase::Settled;
        }
        // A wake callback can re-enter host code. Publish the transition first
        // and never invoke it while holding the command's ownership lock.
        drop(state);
        self.cancellation.cancel();
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
        if !self.is_cancelled() {
            cancellation_or_deadline(&self.cancellation, self.deadline).await;
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
            // cancelled() already enforces the ticket's absolute deadline;
            // wrapping the request in another timeout would duplicate its timer.
            let mut operation = pin!(runner.request(&request.method, request.params));
            match select(cancelled.as_mut(), operation.as_mut()).await {
                Either::Left(_) => Err(rpc.stop_error()),
                Either::Right((response, _)) => response,
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
    cancellation: CancellationToken,
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
                cancellation: CancellationToken::new(),
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
        let cancel = commands.stop_requested
            || self.state.waiter_finished.load(Ordering::SeqCst)
            || Instant::now() >= self.state.deadline;
        commands.rpcs.push(rpc.clone());
        drop(commands);
        if cancel {
            rpc.cancel();
        }
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
        let rpcs = {
            let mut commands = self.state.commands.lock().expect("native invocation lock");
            if commands.stop_requested {
                return;
            }
            commands.stop_requested = true;
            commands.rpcs.clone()
        };
        // Any concurrently registered command observes the stop latch before
        // leaving register_rpc. Wake only outside both ownership locks.
        for rpc in rpcs {
            rpc.cancel();
        }
        self.state.cancellation.cancel();
    }

    fn cancel_pending_rpcs(&self) {
        let rpcs = self
            .state
            .commands
            .lock()
            .expect("native invocation lock")
            .rpcs
            .clone();
        for rpc in rpcs {
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
        if !self.is_cancel_requested() {
            cancellation_or_deadline(&self.state.cancellation, self.state.deadline).await;
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

#[cfg(test)]
mod notification_tests {
    use std::future::pending;
    use std::pin::Pin;
    use std::sync::atomic::AtomicUsize;
    use std::task::{Context, Poll, Wake, Waker};

    use super::*;

    struct WakeProbe {
        wakes: AtomicUsize,
        ownership_locks_free: AtomicBool,
        rpc: Option<Weak<Mutex<RpcState>>>,
        invocation: Option<Weak<InvocationState>>,
    }

    impl WakeProbe {
        fn new(rpc: Option<&NativeRpc>, invocation: Option<&NativeInvocationTermination>) -> Arc<Self> {
            Arc::new(Self {
                wakes: AtomicUsize::new(0),
                ownership_locks_free: AtomicBool::new(true),
                rpc: rpc.map(|rpc| Arc::downgrade(&rpc.state)),
                invocation: invocation.map(|invocation| Arc::downgrade(&invocation.state)),
            })
        }

        fn observe(&self) {
            let rpc_free = self.rpc.as_ref().and_then(Weak::upgrade)
                .is_none_or(|state| state.try_lock().is_ok());
            let invocation_free = self.invocation.as_ref().and_then(Weak::upgrade)
                .is_none_or(|state| state.commands.try_lock().is_ok());
            self.ownership_locks_free.fetch_and(rpc_free && invocation_free, Ordering::SeqCst);
            self.wakes.fetch_add(1, Ordering::SeqCst);
        }

        fn assert_notified(&self) {
            assert!(self.wakes.load(Ordering::SeqCst) > 0, "cancellation must wake a parked task");
            assert!(self.ownership_locks_free.load(Ordering::SeqCst), "wake ran under an ownership lock");
        }
    }

    impl Wake for WakeProbe {
        fn wake(self: Arc<Self>) {
            self.observe();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.observe();
        }
    }

    fn poll_once<F: Future>(future: Pin<&mut F>, probe: &Arc<WakeProbe>) -> Poll<F::Output> {
        let waker = Waker::from(Arc::clone(probe));
        future.poll(&mut Context::from_waker(&waker))
    }

    #[fcp_async_core::runtime::test]
    async fn rpc_cancel_notifies_all_parked_listeners_without_timer_progress() {
        let rpc = NativeRpc::new(invocation_deadline(Instant::now(), None));
        assert!(rpc.try_begin());
        let first_probe = WakeProbe::new(Some(&rpc), None);
        let second_probe = WakeProbe::new(Some(&rpc), None);
        let mut first = Box::pin(rpc.cancelled());
        let mut second = Box::pin(rpc.cancelled());
        assert!(poll_once(first.as_mut(), &first_probe).is_pending());
        assert!(poll_once(second.as_mut(), &second_probe).is_pending());

        rpc.cancel();
        first_probe.assert_notified();
        second_probe.assert_notified();
        assert!(poll_once(first.as_mut(), &first_probe).is_ready());
        assert!(poll_once(second.as_mut(), &second_probe).is_ready());
        assert!(!rpc.try_settle_reply());
        assert!(!rpc.is_settled(), "notification is not physical retirement");
    }

    #[fcp_async_core::runtime::test]
    async fn logical_cancel_notifies_command_and_invocation_outside_both_locks() {
        let invocation = NativeInvocationTermination::new(invocation_deadline(Instant::now(), None));
        let rpc = invocation.register_rpc();
        assert!(rpc.try_begin());
        let command_probe = WakeProbe::new(Some(&rpc), Some(&invocation));
        let invocation_probe = WakeProbe::new(Some(&rpc), Some(&invocation));
        let mut command = Box::pin(rpc.cancelled());
        let mut logical = Box::pin(invocation.cancelled());
        assert!(poll_once(command.as_mut(), &command_probe).is_pending());
        assert!(poll_once(logical.as_mut(), &invocation_probe).is_pending());

        invocation.cancel();
        command_probe.assert_notified();
        invocation_probe.assert_notified();
        assert!(poll_once(command.as_mut(), &command_probe).is_ready());
        assert!(poll_once(logical.as_mut(), &invocation_probe).is_ready());
        assert!(!invocation.register_rpc().try_begin());
        let command_wakes = command_probe.wakes.load(Ordering::SeqCst);
        let invocation_wakes = invocation_probe.wakes.load(Ordering::SeqCst);
        invocation.cancel();
        rpc.cancel();
        assert_eq!(command_probe.wakes.load(Ordering::SeqCst), command_wakes);
        assert_eq!(invocation_probe.wakes.load(Ordering::SeqCst), invocation_wakes);
    }

    #[fcp_async_core::runtime::test]
    async fn cancellation_before_subscription_is_sticky() {
        let invocation = NativeInvocationTermination::new(invocation_deadline(Instant::now(), None));
        let rpc = invocation.register_rpc();
        invocation.cancel();
        let probe = WakeProbe::new(Some(&rpc), Some(&invocation));
        let mut command = Box::pin(rpc.cancelled());
        let mut logical = Box::pin(invocation.cancelled());
        assert!(poll_once(command.as_mut(), &probe).is_ready());
        assert!(poll_once(logical.as_mut(), &probe).is_ready());
        assert!(rpc.is_settled());
        assert!(!rpc.try_begin());
    }

    #[fcp_async_core::runtime::test]
    async fn late_cancellation_does_not_signal_a_settled_ticket() {
        let rpc = NativeRpc::new(invocation_deadline(Instant::now(), None));
        assert!(rpc.try_begin());
        assert!(rpc.try_settle_reply());
        let probe = WakeProbe::new(Some(&rpc), None);
        let mut cancelled = Box::pin(rpc.cancelled());
        assert!(poll_once(cancelled.as_mut(), &probe).is_pending());
        rpc.cancel();
        assert!(!rpc.cancellation.is_cancelled());
        assert!(!rpc.is_cancelled());
        assert_eq!(probe.wakes.load(Ordering::SeqCst), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn candidate_drain_does_not_signal_logical_cancellation() {
        let invocation = NativeInvocationTermination::new(invocation_deadline(Instant::now(), None));
        let rejected = invocation.register_rpc();
        let probe = WakeProbe::new(Some(&rejected), Some(&invocation));
        let mut logical = Box::pin(invocation.cancelled());
        assert!(poll_once(logical.as_mut(), &probe).is_pending());
        invocation.cancel_pending_rpcs();
        assert!(rejected.cancellation.is_cancelled());
        assert!(rejected.is_settled());
        assert!(!invocation.state.cancellation.is_cancelled());
        assert!(!invocation.is_cancel_requested());
        assert_eq!(probe.wakes.load(Ordering::SeqCst), 0);
        let fresh = invocation.register_rpc();
        assert!(fresh.try_begin());
        assert!(fresh.try_settle_reply());
    }

    #[fcp_async_core::runtime::test]
    async fn cancel_releases_a_parked_invocation_and_its_owned_future() {
        struct Dropped(Arc<AtomicBool>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let invocation = NativeInvocationTermination::new(invocation_deadline(Instant::now(), None));
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = Dropped(Arc::clone(&dropped));
        let mut running = Box::pin(invocation.invoke(async move {
            let _guard = guard;
            pending::<HostResult<InvokeResponse>>().await
        }));
        let probe = WakeProbe::new(None, Some(&invocation));
        assert!(poll_once(running.as_mut(), &probe).is_pending());
        invocation.cancel();
        probe.assert_notified();
        assert!(matches!(poll_once(running.as_mut(), &probe), Poll::Ready(Err(_))));
        assert!(dropped.load(Ordering::SeqCst));
        assert!(invocation.is_finished());
    }

    #[fcp_async_core::runtime::test]
    async fn waiter_abandonment_wakes_only_its_exact_queued_command() {
        let abandoned = NativeRpc::new(invocation_deadline(Instant::now(), None));
        let other = NativeRpc::new(invocation_deadline(Instant::now(), None));
        let abandoned_probe = WakeProbe::new(Some(&abandoned), None);
        let other_probe = WakeProbe::new(Some(&other), None);
        let mut abandoned_stop = Box::pin(abandoned.cancelled());
        let mut other_stop = Box::pin(other.cancelled());
        assert!(poll_once(abandoned_stop.as_mut(), &abandoned_probe).is_pending());
        assert!(poll_once(other_stop.as_mut(), &other_probe).is_pending());
        drop(abandoned.waiter());
        abandoned_probe.assert_notified();
        assert!(abandoned.is_settled());
        assert!(!abandoned.try_begin());
        assert_eq!(other_probe.wakes.load(Ordering::SeqCst), 0);
        assert!(other.try_begin());
        assert!(other.try_settle_reply());
    }

    #[test]
    fn racing_registration_cannot_escape_logical_cancellation() {
        for _ in 0..64 {
            let invocation = NativeInvocationTermination::new(invocation_deadline(Instant::now(), None));
            let cancelling = invocation.clone();
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let other_barrier = Arc::clone(&barrier);
            let thread = std::thread::spawn(move || {
                other_barrier.wait();
                cancelling.cancel();
            });
            barrier.wait();
            let rpc = invocation.register_rpc();
            thread.join().unwrap();
            assert!(rpc.is_settled());
            assert!(rpc.cancellation.is_cancelled());
            assert!(!rpc.try_begin());
        }
    }

    #[fcp_async_core::runtime::test]
    async fn absolute_deadlines_still_wake_without_explicit_cancellation() {
        let deadline = deadline_after(Instant::now(), Duration::from_millis(30));
        let rpc = NativeRpc::new(deadline);
        let invocation = NativeInvocationTermination::new(deadline);
        fcp_async_core::time::timeout(
            Duration::from_secs(3),
            futures_util::future::join(rpc.cancelled(), invocation.cancelled()),
        ).await.expect("absolute deadline must release both parked waiters");
        assert!(rpc.is_cancelled());
        assert!(invocation.is_cancel_requested());
        assert!(!rpc.cancellation.is_cancelled(), "deadline is not an explicit cancellation");
        assert!(!invocation.state.cancellation.is_cancelled());
        assert!(!rpc.try_begin());
    }

    #[cfg(unix)]
    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn production_dispatcher_keeps_deadline_and_child_retirement_without_duplicate_timeout() {
        use std::collections::BTreeMap;
        use fcp_async_core::channel::oneshot;

        let runner = ConnectorProcessRunner::spawn(
            "/bin/sh",
            &["-c".to_owned(), "IFS= read -r request || exit 1; exec sleep 30".to_owned()],
            &BTreeMap::new(),
        ).await.unwrap();
        let (sender, receiver) = mpsc::channel(1);
        let actor = fcp_async_core::task::try_spawn(run_dispatcher(runner, receiver)).unwrap();
        let rpc = NativeRpc::new(deadline_after(Instant::now(), Duration::from_secs(1)));
        let _waiter = rpc.waiter();
        let (response_tx, response_rx) = oneshot::channel();
        sender.send(ConnectorRpcRequest {
            method: "blocked".to_owned(),
            params: serde_json::json!({}),
            response_tx,
            rpc: rpc.clone(),
        }).await.unwrap();
        let error = fcp_async_core::time::timeout(Duration::from_secs(5), response_rx)
            .await.unwrap().unwrap().unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        fcp_async_core::time::timeout(Duration::from_secs(3), actor).await.unwrap().unwrap();
        assert!(rpc.transport_retired(), "selected timeout must retire its transport");
        assert!(rpc.is_settled(), "actual child exit is still required");
    }
}
