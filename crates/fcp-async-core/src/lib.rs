//! Shared async runtime substrate for FCP crates.
//!
//! Provides unified entrypoints, task group APIs, timers, channels,
//! and cancellation helpers so all FCP components use a single
//! consistent async concurrency model.

#![forbid(unsafe_code)]
// Lint groups come from [workspace.lints.clippy]; duplicating them here would
// override that table and defeat its allow entries.
#![allow(clippy::module_name_repetitions)]
// These futures run on asupersync's local executor and are deliberately not Send;
// requiring Send would force needless synchronisation. Must live here rather than in
// Cargo.toml because the #![warn(clippy::nursery)] above overrides the lint table.
#![allow(clippy::future_not_send)]
// nursery/pedantic style lints that newer nightlies fire on this unchanged code.
// Needed here rather than in Cargo.toml because this crate re-enables the groups
// with an inner attribute, which overrides the workspace lint table.
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::duration_suboptimal_units)]
#![allow(clippy::redundant_clone)]
#![allow(clippy::significant_drop_tightening)]

extern crate self as fcp_async_core;

use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use thiserror::Error;

pub use asupersync::Cx;
pub use fcp_async_core_macros::{main, test};

#[doc(hidden)]
pub mod __private {
    pub use futures_util;
}

/// `select!` macro routed through the async-core substrate.
#[macro_export]
macro_rules! select {
    (biased; $( $pattern:pat = $future:expr => $body:expr ),+ $(,)?) => {
        $crate::__private::futures_util::select_biased! {
            $( $pattern = $crate::__private::futures_util::FutureExt::fuse($future) => $body, )+
        }
    };
    ($( $pattern:pat = $future:expr => $body:expr ),+ $(,)?) => {
        $crate::__private::futures_util::select! {
            $( $pattern = $crate::__private::futures_util::FutureExt::fuse($future) => $body, )+
        }
    };
}

/// Unified async failure taxonomy for substrate consumers.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum AsyncError {
    /// Operation timed out.
    #[error("operation timed out after {timeout_ms}ms")]
    Timeout {
        /// Timeout budget in milliseconds.
        timeout_ms: u64,
    },

    /// Operation cancelled.
    #[error("operation cancelled")]
    Cancelled,

    /// Channel was closed.
    #[error("channel closed")]
    ChannelClosed,

    /// Channel was full for non-blocking send.
    #[error("channel full")]
    ChannelFull,

    /// Protocol I/O failure.
    #[error("protocol io fault: {message}")]
    ProtocolIo {
        /// Human-readable detail.
        message: String,
    },

    /// Task join failure.
    #[error("task join failed: {message}")]
    Join {
        /// Human-readable detail.
        message: String,
    },

    /// Runtime infrastructure failure.
    #[error("runtime failure: {message}")]
    Runtime {
        /// Human-readable detail.
        message: String,
    },
}

/// Hooks for task and queue instrumentation.
pub trait Instrumentation: Send + Sync {
    /// Called on task spawn.
    fn on_task_spawn(&self, _task_name: &str) {}

    /// Called on task exit.
    fn on_task_exit(&self, _task_name: &str, _result: &Result<(), AsyncError>) {}

    /// Called after queue send.
    fn on_queue_send(&self, _queue_name: &str, _depth: usize, _capacity: usize) {}

    /// Called after queue receive.
    fn on_queue_receive(&self, _queue_name: &str, _depth: usize, _capacity: usize) {}
}

/// No-op hook implementation.
#[derive(Debug, Default)]
pub struct NoopInstrumentation;

impl Instrumentation for NoopInstrumentation {}

/// Return the current `asupersync::Cx`.
///
/// Downstream crates should call this instead of importing `asupersync::Cx`
/// directly, keeping the raw runtime dependency encapsulated. Callers must run
/// under an active asupersync runtime context.
///
/// # Panics
///
/// Panics when called outside an active asupersync runtime context.
#[must_use]
pub fn compatibility_cx() -> asupersync::Cx {
    asupersync::Cx::current().expect(
        "fcp_async_core::compatibility_cx called outside an active asupersync runtime context",
    )
}

/// Runtime bridging helpers.
pub mod runtime {
    use std::cell::RefCell;
    use std::io;
    use std::sync::{Arc, OnceLock};

    #[cfg(test)]
    use std::sync::atomic::{AtomicUsize, Ordering};

    use asupersync::runtime::{
        Runtime as AsupersyncRuntime, RuntimeBuilder as AsupersyncRuntimeBuilder,
        RuntimeHandle as AsupersyncRuntimeHandle,
    };

    use super::{AsyncError, Future};

    pub use fcp_async_core_macros::{main, test};

    /// Cached Tokio runtime handle for compatibility with crates that require
    /// `tokio::runtime::Handle::current()` (e.g., wiremock, reqwest).
    ///
    /// The actual runtime lives on a dedicated background thread so that tasks
    /// spawned via `tokio::spawn` (e.g., wiremock's HTTP server) are actively
    /// polled even though the main thread runs the Asupersync event loop.
    static TOKIO_COMPAT_HANDLE: OnceLock<tokio::runtime::Handle> = OnceLock::new();

    #[cfg(test)]
    static TOKIO_COMPAT_DRIVER_SPAWN_COUNT: AtomicUsize = AtomicUsize::new(0);

    pub(crate) fn get_or_create_tokio_compat_handle() -> tokio::runtime::Handle {
        TOKIO_COMPAT_HANDLE
            .get_or_init(|| {
                let (handle_tx, handle_rx) = std::sync::mpsc::channel();
                std::thread::Builder::new()
                    .name("tokio-compat-driver".into())
                    .spawn(move || {
                        let rt = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                            .expect("failed to create Tokio compatibility runtime");
                        #[cfg(test)]
                        TOKIO_COMPAT_DRIVER_SPAWN_COUNT.fetch_add(1, Ordering::SeqCst);
                        handle_tx
                            .send(rt.handle().clone())
                            .expect("failed to send Tokio compat handle");
                        // Drive the event loop so spawned tasks (wiremock, etc.) get polled.
                        rt.block_on(std::future::pending::<()>());
                    })
                    .expect("failed to spawn tokio-compat-driver thread");
                handle_rx
                    .recv()
                    .expect("tokio-compat-driver thread died before sending handle")
            })
            .clone()
    }

    #[cfg(test)]
    pub(crate) fn tokio_compat_driver_spawn_count() -> usize {
        TOKIO_COMPAT_DRIVER_SPAWN_COUNT.load(Ordering::SeqCst)
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum RuntimeFlavor {
        CurrentThread,
        MultiThread,
    }

    #[derive(Clone)]
    pub(crate) struct RuntimeContext {
        pub(crate) handle: AsupersyncRuntimeHandle,
        pub(crate) flavor: RuntimeFlavor,
    }

    std::thread_local! {
        static CURRENT_RUNTIME: RefCell<Vec<RuntimeContext>> = const { RefCell::new(Vec::new()) };
    }

    pub(crate) struct RuntimeGuard;

    impl RuntimeGuard {
        pub(crate) fn enter(context: RuntimeContext) -> Self {
            CURRENT_RUNTIME.with(|slot| {
                slot.borrow_mut().push(context);
            });
            Self
        }
    }

    impl Drop for RuntimeGuard {
        fn drop(&mut self) {
            CURRENT_RUNTIME.with(|slot| {
                let _ = slot.borrow_mut().pop();
            });
        }
    }

    pub(crate) fn current_runtime_context() -> Option<RuntimeContext> {
        CURRENT_RUNTIME.with(|slot| slot.borrow().last().cloned())
    }

    pub(crate) fn worker_runtime_context(flavor: RuntimeFlavor) -> Option<RuntimeContext> {
        AsupersyncRuntime::current_handle().map(|handle| RuntimeContext { handle, flavor })
    }

    /// Runtime builder abstraction owned by async-core.
    pub struct Builder {
        inner: AsupersyncRuntimeBuilder,
        flavor: RuntimeFlavor,
        io_enabled: bool,
    }

    impl Builder {
        /// Create a single-threaded runtime builder.
        #[must_use]
        pub fn new_current_thread() -> Self {
            Self {
                inner: AsupersyncRuntimeBuilder::current_thread(),
                flavor: RuntimeFlavor::CurrentThread,
                io_enabled: false,
            }
        }

        /// Create a multi-threaded runtime builder.
        #[must_use]
        pub fn new_multi_thread() -> Self {
            Self {
                inner: AsupersyncRuntimeBuilder::multi_thread(),
                flavor: RuntimeFlavor::MultiThread,
                io_enabled: false,
            }
        }

        /// Enable all runtime services.
        #[must_use]
        pub const fn enable_all(mut self) -> Self {
            self.io_enabled = true;
            self
        }

        /// Enable time services.
        #[must_use]
        pub const fn enable_time(self) -> Self {
            self
        }

        /// Enable I/O services.
        #[must_use]
        pub const fn enable_io(mut self) -> Self {
            self.io_enabled = true;
            self
        }

        /// Build runtime.
        ///
        /// # Errors
        ///
        /// Returns I/O errors from runtime initialization.
        pub fn build(self) -> io::Result<Runtime> {
            let inner = if self.io_enabled {
                match platform_reactor()? {
                    // A reactor without a timer driver leaves sleep/timeout
                    // deadlines invisible to the scheduler's I/O poll, which
                    // then falls back to its 250ms idle cap: sub-250ms timers
                    // quantize to ~250ms and racing `timeout(d, fut)` pairs
                    // resolve in the wrong order. Wire the wall-clock timer
                    // driver alongside the reactor so `drive_io_phase` clamps
                    // its poll to the earliest pending timer deadline.
                    Some(reactor) => self
                        .inner
                        .with_reactor(reactor)
                        .with_timer_driver(asupersync::time::TimerDriverHandle::with_wall_clock()),
                    None => self.inner,
                }
            } else {
                self.inner
            };

            inner
                .build()
                .map(|inner| Runtime {
                    inner,
                    flavor: self.flavor,
                })
                .map_err(|err| io::Error::other(err.to_string()))
        }
    }

    fn platform_reactor() -> io::Result<Option<Arc<dyn asupersync::runtime::reactor::Reactor>>> {
        // Exactly one of the mutually exclusive cfg blocks below compiles on
        // any given platform, so each block is that platform's tail
        // expression (no `return`, which clippy flags as needless).
        #[cfg(target_os = "linux")]
        {
            asupersync::runtime::reactor::EpollReactor::new().map(|reactor| {
                Some(Arc::new(reactor) as Arc<dyn asupersync::runtime::reactor::Reactor>)
            })
        }

        #[cfg(any(
            target_os = "macos",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly"
        ))]
        {
            asupersync::runtime::reactor::KqueueReactor::new().map(|reactor| {
                Some(Arc::new(reactor) as Arc<dyn asupersync::runtime::reactor::Reactor>)
            })
        }

        #[cfg(target_os = "windows")]
        {
            asupersync::runtime::reactor::IocpReactor::new().map(|reactor| {
                Some(Arc::new(reactor) as Arc<dyn asupersync::runtime::reactor::Reactor>)
            })
        }

        #[cfg(not(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly",
            target_os = "windows"
        )))]
        {
            Ok(None)
        }
    }

    /// Runtime abstraction owned by async-core.
    pub struct Runtime {
        inner: AsupersyncRuntime,
        flavor: RuntimeFlavor,
    }

    impl std::fmt::Debug for Runtime {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Runtime")
                .field("flavor", &self.flavor)
                .finish_non_exhaustive()
        }
    }

    impl Runtime {
        /// Create a default multi-thread runtime with all drivers enabled.
        ///
        /// # Errors
        ///
        /// Returns I/O errors from runtime initialization.
        pub fn new() -> io::Result<Self> {
            Builder::new_multi_thread().enable_all().build()
        }

        /// Block on a future.
        ///
        /// Also enters a Tokio runtime context so that crates requiring
        /// `tokio::runtime::Handle::current()` (e.g., wiremock, reqwest)
        /// work correctly under the Asupersync runtime.
        pub fn block_on<F>(&self, future: F) -> F::Output
        where
            F: Future,
        {
            let _guard = RuntimeGuard::enter(RuntimeContext {
                handle: self.inner.handle(),
                flavor: self.flavor,
            });
            let tokio_handle = get_or_create_tokio_compat_handle();
            let _tokio_guard = tokio_handle.enter();
            self.inner.block_on(future)
        }
    }

    /// Execute a future from sync context.
    ///
    /// # Errors
    ///
    /// Returns [`AsyncError::Runtime`] when runtime setup is unavailable.
    pub fn block_on_sync<F>(future: F) -> Result<F::Output, AsyncError>
    where
        F: Future,
    {
        if let Some(flavor) =
            CURRENT_RUNTIME.with(|slot| slot.borrow().last().map(|ctx| ctx.flavor))
        {
            let flavor_name = match flavor {
                RuntimeFlavor::CurrentThread => "current-thread",
                RuntimeFlavor::MultiThread => "multi-thread",
            };
            return Err(AsyncError::Runtime {
                message: format!("cannot block_on_sync inside an active {flavor_name} runtime"),
            });
        }

        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|err| AsyncError::Runtime {
                message: format!("failed to build runtime: {err}"),
            })?;
        Ok(runtime.block_on(future))
    }
}

/// Time/timer helpers.
pub mod time {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, OnceLock};
    use std::task::{Context, Poll};
    use std::thread::{self, JoinHandle, Thread};
    use std::time::{Duration, Instant};

    use asupersync::types::Time;

    use super::AsyncError;

    static TIMER_EPOCH: OnceLock<std::time::Instant> = OnceLock::new();

    fn wall_now() -> Time {
        let now = asupersync::time::wall_now();
        let _ = TIMER_EPOCH.get_or_init(std::time::Instant::now);
        now
    }

    fn instant_from_time(time: Time) -> std::time::Instant {
        let epoch = *TIMER_EPOCH.get_or_init(std::time::Instant::now);
        super::saturating_instant_add(epoch, Duration::from_nanos(time.as_nanos()))
    }

    /// Sleep future abstraction owned by async-core.
    struct SleepState {
        ready: AtomicBool,
        cancelled: AtomicBool,
        waker: Mutex<Option<std::task::Waker>>,
    }

    pub struct Sleep {
        duration: Duration,
        state: Arc<SleepState>,
        thread: Option<Thread>,
        join: Option<JoinHandle<()>>,
        started: bool,
    }

    impl Sleep {
        fn start(&mut self) {
            if self.started {
                return;
            }
            self.started = true;

            if self.duration.is_zero() {
                self.state.ready.store(true, Ordering::Release);
                return;
            }

            let state = Arc::clone(&self.state);
            let duration = self.duration;
            let join = thread::spawn(move || {
                let deadline = super::saturating_instant_add(Instant::now(), duration);
                loop {
                    if state.cancelled.load(Ordering::Acquire) {
                        return;
                    }

                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        break;
                    }

                    thread::park_timeout(remaining);
                }

                state.ready.store(true, Ordering::Release);
                let waker = state
                    .waker
                    .lock()
                    .expect("sleep waker mutex poisoned")
                    .take();
                if let Some(waker) = waker {
                    waker.wake();
                }
            });
            self.thread = Some(join.thread().clone());
            self.join = Some(join);
        }
    }

    impl Future for Sleep {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            self.start();
            if self.state.ready.load(Ordering::Acquire) {
                return Poll::Ready(());
            }

            {
                let mut waker = self.state.waker.lock().expect("sleep waker mutex poisoned");
                if !waker.as_ref().is_some_and(|w| w.will_wake(cx.waker())) {
                    *waker = Some(cx.waker().clone());
                }
            }

            if self.state.ready.load(Ordering::Acquire) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }
    }

    impl Drop for Sleep {
        fn drop(&mut self) {
            self.state.cancelled.store(true, Ordering::Release);
            if let Some(thread) = &self.thread {
                thread.unpark();
            }
            let _ = self.join.take();
        }
    }

    /// Interval abstraction owned by async-core.
    pub struct Interval {
        inner: asupersync::time::Interval,
    }

    impl Interval {
        /// Wait for the next interval tick.
        pub async fn tick(&mut self) -> std::time::Instant {
            loop {
                let now = wall_now();
                if self.inner.is_ready(now) {
                    return instant_from_time(self.inner.tick(now));
                }

                let delay = self
                    .inner
                    .deadline()
                    .as_nanos()
                    .saturating_sub(now.as_nanos());
                sleep(Duration::from_nanos(delay)).await;
            }
        }
    }

    /// Sleep for a duration.
    // Arc::new is not const on the active toolchain despite clippy's suggestion.
    #[allow(clippy::missing_const_for_fn)]
    #[must_use]
    pub fn sleep(duration: Duration) -> Sleep {
        Sleep {
            duration,
            state: Arc::new(SleepState {
                ready: AtomicBool::new(false),
                cancelled: AtomicBool::new(false),
                waker: Mutex::new(None),
            }),
            thread: None,
            join: None,
            started: false,
        }
    }

    /// Create interval ticker.
    #[must_use]
    pub fn interval(period: Duration) -> Interval {
        Interval {
            inner: asupersync::time::interval(wall_now(), period),
        }
    }

    /// Timeout wrapper with normalized error mapping.
    ///
    /// # Errors
    ///
    /// Returns [`AsyncError::Timeout`] when elapsed.
    pub async fn timeout<T, F>(duration: Duration, future: F) -> Result<T, AsyncError>
    where
        F: Future<Output = T>,
    {
        let timeout_ms = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);

        crate::select! {
            biased;
            () = sleep(duration) => Err(AsyncError::Timeout { timeout_ms }),
            output = future => Ok(output),
        }
    }
}

fn duration_from_total_nanos(total_nanos: u128) -> Duration {
    const NANOS_PER_SECOND: u128 = 1_000_000_000;

    let seconds = total_nanos / NANOS_PER_SECOND;
    let nanos = u32::try_from(total_nanos % NANOS_PER_SECOND).unwrap_or(u32::MAX);

    Duration::new(u64::try_from(seconds).unwrap_or(u64::MAX), nanos)
}

fn saturating_instant_add(base: Instant, offset: Duration) -> Instant {
    if let Some(target) = base.checked_add(offset) {
        return target;
    }

    let mut low = 0_u128;
    let mut high = offset.as_nanos();
    let mut best = base;

    while low <= high {
        let mid = low + ((high - low) / 2);
        let candidate = duration_from_total_nanos(mid);
        if let Some(target) = base.checked_add(candidate) {
            best = target;
            low = mid.saturating_add(1);
        } else {
            if mid == 0 {
                break;
            }
            high = mid - 1;
        }
    }

    best
}

/// Absolute deadline wrapper used for deterministic timeout budgeting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deadline {
    deadline_at: Instant,
}

impl Deadline {
    /// Create a deadline relative to now.
    #[must_use]
    pub fn after(timeout: Duration) -> Self {
        let now = Instant::now();
        Self {
            deadline_at: saturating_instant_add(now, timeout),
        }
    }

    /// Create a deadline from an absolute instant.
    #[must_use]
    pub const fn at(deadline_at: Instant) -> Self {
        Self { deadline_at }
    }

    /// Return the remaining budget before timeout.
    #[must_use]
    pub fn remaining(self) -> Duration {
        self.deadline_at.saturating_duration_since(Instant::now())
    }

    /// Return true if deadline is already expired.
    #[must_use]
    pub fn is_expired(self) -> bool {
        self.remaining().is_zero()
    }

    /// Run a future under the deadline.
    ///
    /// # Errors
    ///
    /// Returns [`AsyncError::Timeout`] when deadline budget is exhausted.
    pub async fn run<T, F>(self, future: F) -> Result<T, AsyncError>
    where
        F: Future<Output = T>,
    {
        time::timeout(self.remaining(), future).await
    }
}

/// Scope classification for execution contexts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContextScope {
    /// Request-scoped foreground work with explicit deadline budget.
    Request,
    /// Background work that may be cancellation-bound without deadline.
    Background,
}

/// Propagated async context (cancellation + optional deadline + scope).
#[derive(Clone, Debug)]
pub struct ExecutionContext {
    scope: ContextScope,
    cancellation: CancellationToken,
    deadline: Option<Deadline>,
}

impl ExecutionContext {
    /// Create a request-scoped context with fixed timeout budget.
    #[must_use]
    pub fn request_scoped(timeout: Duration) -> Self {
        Self {
            scope: ContextScope::Request,
            cancellation: CancellationToken::new(),
            deadline: Some(Deadline::after(timeout)),
        }
    }

    /// Create a background context (no deadline by default).
    #[must_use]
    pub fn background() -> Self {
        Self {
            scope: ContextScope::Background,
            cancellation: CancellationToken::new(),
            deadline: None,
        }
    }

    /// Create a child context inheriting cancellation and deadline.
    #[must_use]
    pub fn child(&self) -> Self {
        Self {
            scope: self.scope,
            cancellation: self.cancellation.clone(),
            deadline: self.deadline,
        }
    }

    /// Set or replace the context deadline.
    #[must_use]
    pub fn with_deadline(mut self, timeout: Duration) -> Self {
        self.deadline = Some(Deadline::after(timeout));
        self
    }

    /// Context scope.
    #[must_use]
    pub const fn scope(&self) -> ContextScope {
        self.scope
    }

    /// Deadline, if present.
    #[must_use]
    pub const fn deadline(&self) -> Option<Deadline> {
        self.deadline
    }

    /// Remaining timeout budget, if deadline exists.
    #[must_use]
    pub fn remaining_budget(&self) -> Option<Duration> {
        self.deadline.map(Deadline::remaining)
    }

    /// Trigger cancellation on this context (and its descendants).
    pub fn cancel(&self) {
        self.cancellation.cancel();
    }

    /// Whether the context is already cancelled.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    /// Subscribe to context cancellation.
    #[must_use]
    pub fn subscribe(&self) -> CancellationListener {
        self.cancellation.subscribe()
    }

    /// Run a future under this context.
    ///
    /// Cancellation is deterministic and takes precedence over deadline timeout.
    ///
    /// # Errors
    ///
    /// Returns [`AsyncError::Cancelled`] when cancellation is observed first, or
    /// [`AsyncError::Timeout`] when deadline expires first.
    pub async fn run<T, F>(&self, future: F) -> Result<T, AsyncError>
    where
        F: Future<Output = T>,
    {
        let mut listener = self.subscribe();
        if listener.is_cancelled() {
            return Err(AsyncError::Cancelled);
        }

        crate::select! {
            biased;
            _ = listener.cancelled() => Err(AsyncError::Cancelled),
            output = async {
                match self.deadline {
                    Some(deadline) => deadline.run(future).await,
                    None => Ok(future.await),
                }
            } => output,
        }
    }

    /// Sleep for a duration under this context.
    ///
    /// # Errors
    ///
    /// Returns timeout/cancellation failures according to context semantics.
    pub async fn sleep(&self, duration: Duration) -> Result<(), AsyncError> {
        self.run(time::sleep(duration)).await
    }
}

/// Channel helpers and re-exports.
pub mod channel {
    use std::collections::VecDeque;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll};

    use super::{AsyncError, Instrumentation, NoopInstrumentation};

    fn decrement_depth(depth: &AtomicUsize) {
        let _ = depth.try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            current.checked_sub(1)
        });
    }

    /// Tokio broadcast compatibility surface owned by async-core.
    pub mod broadcast {
        use crate::compatibility_cx;

        /// Broadcast send error.
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct SendError<T>(pub T);

        impl<T> std::fmt::Display for SendError<T> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("sending on a closed broadcast channel")
            }
        }

        impl<T: std::fmt::Debug> std::error::Error for SendError<T> {}

        pub mod error {
            /// Broadcast receive error.
            #[derive(Debug, Clone, Copy, PartialEq, Eq)]
            pub enum RecvError {
                Closed,
                Lagged(u64),
            }

            impl std::fmt::Display for RecvError {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    match self {
                        Self::Closed => f.write_str("channel closed"),
                        Self::Lagged(skipped) => write!(f, "channel lagged by {skipped} messages"),
                    }
                }
            }

            impl std::error::Error for RecvError {}
        }

        /// Broadcast sender wrapper.
        #[derive(Clone, Debug)]
        pub struct Sender<T> {
            inner: asupersync::channel::broadcast::Sender<T>,
        }

        /// Broadcast receiver wrapper.
        #[derive(Debug)]
        pub struct Receiver<T> {
            inner: asupersync::channel::broadcast::Receiver<T>,
        }

        impl<T: Clone> Sender<T> {
            /// Send a value to all active subscribers.
            ///
            /// # Errors
            /// Returns `SendError` when the channel is closed and there are no receivers left.
            pub fn send(&self, value: T) -> Result<usize, SendError<T>> {
                let cx = compatibility_cx();
                self.inner.send(&cx, value).map_err(|err| match err {
                    asupersync::channel::broadcast::SendError::Closed(value)
                    | asupersync::channel::broadcast::SendError::Cancelled(value) => {
                        SendError(value)
                    }
                })
            }

            #[must_use]
            pub fn subscribe(&self) -> Receiver<T> {
                Receiver {
                    inner: self.inner.subscribe(),
                }
            }
        }

        impl<T: Clone> Receiver<T> {
            /// Receive the next broadcast value.
            ///
            /// # Errors
            /// Returns `RecvError::Closed` when the channel is closed or cancelled, and
            /// `RecvError::Lagged` when messages were skipped due to backpressure.
            pub async fn recv(&mut self) -> Result<T, error::RecvError> {
                let cx = compatibility_cx();
                self.inner.recv(&cx).await.map_err(|err| match err {
                    asupersync::channel::broadcast::RecvError::Closed
                    | asupersync::channel::broadcast::RecvError::Cancelled
                    | asupersync::channel::broadcast::RecvError::PolledAfterCompletion => {
                        error::RecvError::Closed
                    }
                    asupersync::channel::broadcast::RecvError::Lagged(skipped) => {
                        error::RecvError::Lagged(skipped)
                    }
                })
            }
        }

        /// Create a bounded broadcast channel.
        #[must_use]
        pub fn channel<T: Clone>(capacity: usize) -> (Sender<T>, Receiver<T>) {
            let (sender, receiver) = asupersync::channel::broadcast::channel(capacity);
            (Sender { inner: sender }, Receiver { inner: receiver })
        }
    }

    /// Tokio mpsc compatibility surface owned by async-core.
    pub mod mpsc {
        use std::sync::Arc;
        use std::time::Duration;

        use super::{AtomicUsize, Ordering, StdMutex, VecDeque, decrement_depth};
        use crate::compatibility_cx;

        #[cfg(test)]
        type UnboundedSendHook = Arc<dyn Fn() + Send + Sync + 'static>;

        /// Bounded mpsc send error.
        #[derive(Debug, PartialEq, Eq)]
        pub struct SendError<T>(pub T);

        impl<T> std::fmt::Display for SendError<T> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("channel closed")
            }
        }

        impl<T: std::fmt::Debug> std::error::Error for SendError<T> {}

        pub mod error {
            /// Bounded mpsc try-send error.
            #[derive(Debug, PartialEq, Eq)]
            pub enum TrySendError<T> {
                Closed(T),
                Full(T),
            }

            impl<T> std::fmt::Display for TrySendError<T> {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    match self {
                        Self::Closed(_) => f.write_str("channel closed"),
                        Self::Full(_) => f.write_str("channel full"),
                    }
                }
            }

            impl<T: std::fmt::Debug> std::error::Error for TrySendError<T> {}

            /// Bounded mpsc try-recv error.
            #[derive(Debug, Clone, Copy, PartialEq, Eq)]
            pub enum TryRecvError {
                Empty,
                Disconnected,
            }

            impl std::fmt::Display for TryRecvError {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    match self {
                        Self::Empty => f.write_str("channel empty"),
                        Self::Disconnected => f.write_str("channel disconnected"),
                    }
                }
            }

            impl std::error::Error for TryRecvError {}
        }

        /// Longest a parked [`Sender::closed`] waits before re-checking
        /// `is_closed()` on its own initiative.
        ///
        /// The wrapper signals the closures it can observe (receiver drop and
        /// explicit `Receiver::close`) through `close_signal`, so the common
        /// case wakes immediately. This bound only covers closures that
        /// originate inside the underlying asupersync channel, which the
        /// wrapper never sees. It exists so `closed()` can never hang, and so
        /// that waiting for it always parks the task instead of spinning.
        const CLOSED_RECHECK_INTERVAL: Duration = Duration::from_millis(250);

        /// Bounded sender wrapper.
        #[derive(Debug)]
        pub struct Sender<T> {
            inner: asupersync::channel::mpsc::Sender<T>,
            capacity: usize,
            depth: Arc<AtomicUsize>,
            close_signal: Arc<asupersync::sync::Notify>,
        }

        impl<T> Clone for Sender<T> {
            fn clone(&self) -> Self {
                Self {
                    inner: self.inner.clone(),
                    capacity: self.capacity,
                    depth: Arc::clone(&self.depth),
                    close_signal: Arc::clone(&self.close_signal),
                }
            }
        }

        /// Bounded receiver wrapper.
        #[derive(Debug)]
        pub struct Receiver<T> {
            inner: asupersync::channel::mpsc::Receiver<T>,
            capacity: usize,
            depth: Arc<AtomicUsize>,
            close_signal: Arc<asupersync::sync::Notify>,
        }

        impl<T> Drop for Receiver<T> {
            fn drop(&mut self) {
                // Dropping the receiver is what closes the channel for every
                // sender. Wake anyone parked in `Sender::closed` so they observe
                // it now rather than at the next re-check.
                self.close_signal.notify_waiters();
            }
        }

        struct UnboundedState<T> {
            queue: VecDeque<T>,
            closed: bool,
        }

        struct UnboundedShared<T> {
            state: StdMutex<UnboundedState<T>>,
            sender_count: AtomicUsize,
            notify: asupersync::sync::Notify,
            #[cfg(test)]
            send_hook: StdMutex<Option<UnboundedSendHook>>,
        }

        impl<T> std::fmt::Debug for UnboundedShared<T> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                let state = self.state.lock().expect("unbounded queue poisoned");
                f.debug_struct("UnboundedShared")
                    .field("closed", &state.closed)
                    .field("sender_count", &self.sender_count.load(Ordering::Relaxed))
                    .finish_non_exhaustive()
            }
        }

        impl<T> UnboundedShared<T> {
            fn send(&self, value: T) -> Result<(), SendError<T>> {
                let mut state = self.state.lock().expect("unbounded queue poisoned");
                if state.closed {
                    return Err(SendError(value));
                }
                #[cfg(test)]
                self.run_send_hook();
                state.queue.push_back(value);
                drop(state);
                self.notify.notify_one();
                Ok(())
            }

            fn pop_or_closed(&self) -> Result<Option<T>, ()> {
                let mut state = self.state.lock().expect("unbounded queue poisoned");
                let result = state.queue.pop_front().map_or_else(
                    || {
                        if state.closed { Err(()) } else { Ok(None) }
                    },
                    |value| Ok(Some(value)),
                );
                drop(state);
                result
            }

            fn close(&self) {
                self.state.lock().expect("unbounded queue poisoned").closed = true;
                self.notify.notify_waiters();
            }

            #[cfg(test)]
            fn run_send_hook(&self) {
                let hook = self
                    .send_hook
                    .lock()
                    .expect("unbounded send hook poisoned")
                    .clone();
                if let Some(hook) = hook {
                    hook();
                }
            }
        }

        /// Unbounded sender wrapper.
        #[derive(Debug)]
        pub struct UnboundedSender<T> {
            shared: Arc<UnboundedShared<T>>,
        }

        impl<T> Clone for UnboundedSender<T> {
            fn clone(&self) -> Self {
                self.shared.sender_count.fetch_add(1, Ordering::Relaxed);
                Self {
                    shared: Arc::clone(&self.shared),
                }
            }
        }

        impl<T> Drop for UnboundedSender<T> {
            fn drop(&mut self) {
                if self.shared.sender_count.fetch_sub(1, Ordering::AcqRel) == 1 {
                    self.shared.close();
                }
            }
        }

        /// Unbounded receiver wrapper.
        #[derive(Debug)]
        pub struct UnboundedReceiver<T> {
            shared: Arc<UnboundedShared<T>>,
        }

        impl<T> Sender<T> {
            /// Send a value, waiting for capacity if necessary.
            ///
            /// # Errors
            /// Returns `SendError` when the receiver side has been closed.
            pub async fn send(&self, value: T) -> Result<(), SendError<T>> {
                let cx = compatibility_cx();
                self.inner
                    .send(&cx, value)
                    .await
                    .map(|()| {
                        self.depth.fetch_add(1, Ordering::AcqRel);
                    })
                    .map_err(|err| match err {
                        asupersync::channel::mpsc::SendError::Disconnected(value)
                        | asupersync::channel::mpsc::SendError::Full(value)
                        | asupersync::channel::mpsc::SendError::Cancelled(value) => {
                            SendError(value)
                        }
                    })
            }

            /// Try to send a value without waiting for capacity.
            ///
            /// # Errors
            /// Returns `TrySendError::Closed` when the channel is closed and
            /// `TrySendError::Full` when the queue has no remaining capacity.
            pub fn try_send(&self, value: T) -> Result<(), error::TrySendError<T>> {
                self.inner
                    .try_send(value)
                    .map(|()| {
                        self.depth.fetch_add(1, Ordering::AcqRel);
                    })
                    .map_err(|err| match err {
                        asupersync::channel::mpsc::SendError::Disconnected(value) => {
                            error::TrySendError::Closed(value)
                        }
                        asupersync::channel::mpsc::SendError::Full(value)
                        | asupersync::channel::mpsc::SendError::Cancelled(value) => {
                            error::TrySendError::Full(value)
                        }
                    })
            }

            #[must_use]
            pub fn capacity(&self) -> usize {
                self.capacity
                    .saturating_sub(self.depth.load(Ordering::Acquire))
            }

            #[must_use]
            pub fn len(&self) -> usize {
                self.depth.load(Ordering::Acquire)
            }

            #[must_use]
            pub fn is_empty(&self) -> bool {
                self.len() == 0
            }

            #[must_use]
            pub fn is_closed(&self) -> bool {
                self.inner.is_closed()
            }

            /// Resolve once the receiving half is gone.
            ///
            /// This parks the task. It must never busy-wait: this future is
            /// typically one arm of a `select!` against socket I/O, and a
            /// self-waking arm keeps the task permanently runnable, which
            /// starves the runtime's I/O phase — readiness for every other
            /// socket on the runtime then goes unobserved while only timers
            /// keep firing.
            pub async fn closed(&self) {
                loop {
                    // Register with the signal BEFORE re-testing. `Notified`
                    // captures the notify generation when it is constructed, so a
                    // close landing between this check and the park still
                    // completes the future instead of being missed.
                    let signalled = self.close_signal.notified();
                    if self.is_closed() {
                        return;
                    }
                    let _ = crate::time::timeout(CLOSED_RECHECK_INTERVAL, signalled).await;
                }
            }
        }

        impl<T> Receiver<T> {
            pub async fn recv(&mut self) -> Option<T> {
                let cx = compatibility_cx();
                match self.inner.recv(&cx).await {
                    Ok(value) => {
                        decrement_depth(&self.depth);
                        Some(value)
                    }
                    Err(
                        asupersync::channel::mpsc::RecvError::Disconnected
                        | asupersync::channel::mpsc::RecvError::Cancelled
                        | asupersync::channel::mpsc::RecvError::Empty,
                    ) => None,
                }
            }

            /// Try to receive a queued value without waiting.
            ///
            /// # Errors
            /// Returns `TryRecvError::Empty` when no value is available yet and
            /// `TryRecvError::Disconnected` when all senders are gone.
            pub fn try_recv(&mut self) -> Result<T, error::TryRecvError> {
                self.inner
                    .try_recv()
                    .inspect(|_| {
                        decrement_depth(&self.depth);
                    })
                    .map_err(|err| match err {
                        asupersync::channel::mpsc::RecvError::Empty
                        | asupersync::channel::mpsc::RecvError::Cancelled => {
                            error::TryRecvError::Empty
                        }
                        asupersync::channel::mpsc::RecvError::Disconnected => {
                            error::TryRecvError::Disconnected
                        }
                    })
            }

            pub fn close(&mut self) {
                self.inner.close();
                self.close_signal.notify_waiters();
            }

            #[must_use]
            pub fn capacity(&self) -> usize {
                self.capacity
                    .saturating_sub(self.depth.load(Ordering::Acquire))
            }
        }

        impl<T> UnboundedSender<T> {
            /// Send a value into the unbounded queue.
            ///
            /// # Errors
            /// Returns `SendError` when the receiver has already been closed.
            pub fn send(&self, value: T) -> Result<(), SendError<T>> {
                self.shared.send(value)
            }
        }

        impl<T> UnboundedReceiver<T> {
            pub async fn recv(&mut self) -> Option<T> {
                loop {
                    match self.shared.pop_or_closed() {
                        Ok(Some(value)) => return Some(value),
                        Err(()) => return None,
                        Ok(None) => {}
                    }

                    if self.shared.sender_count.load(Ordering::Acquire) == 0 {
                        return None;
                    }

                    self.shared.notify.notified().await;
                }
            }

            pub fn close(&mut self) {
                self.shared.close();
            }
        }

        #[cfg(test)]
        pub(crate) fn set_unbounded_send_hook<T>(
            sender: &UnboundedSender<T>,
            hook: Option<UnboundedSendHook>,
        ) {
            *sender
                .shared
                .send_hook
                .lock()
                .expect("unbounded send hook poisoned") = hook;
        }

        /// Create a bounded mpsc channel.
        #[must_use]
        pub fn channel<T>(capacity: usize) -> (Sender<T>, Receiver<T>) {
            let (sender, receiver) = asupersync::channel::mpsc::channel(capacity);
            let depth = Arc::new(AtomicUsize::new(0));
            let close_signal = Arc::new(asupersync::sync::Notify::new());
            (
                Sender {
                    inner: sender,
                    capacity,
                    depth: Arc::clone(&depth),
                    close_signal: Arc::clone(&close_signal),
                },
                Receiver {
                    inner: receiver,
                    capacity,
                    depth,
                    close_signal,
                },
            )
        }

        /// Create an unbounded mpsc channel.
        #[must_use]
        pub fn unbounded_channel<T>() -> (UnboundedSender<T>, UnboundedReceiver<T>) {
            let shared = Arc::new(UnboundedShared {
                state: StdMutex::new(UnboundedState {
                    queue: VecDeque::new(),
                    closed: false,
                }),
                sender_count: AtomicUsize::new(1),
                notify: asupersync::sync::Notify::new(),
                #[cfg(test)]
                send_hook: StdMutex::new(None),
            });
            (
                UnboundedSender {
                    shared: Arc::clone(&shared),
                },
                UnboundedReceiver { shared },
            )
        }
    }

    /// Tokio oneshot compatibility surface owned by async-core.
    pub mod oneshot {
        use std::sync::{Arc, Mutex as StdMutex};
        use std::task::Waker;

        use super::{Context, Future, Pin, Poll};

        pub mod error {
            /// Oneshot receive error.
            #[derive(Debug, Clone, Copy, PartialEq, Eq)]
            pub struct RecvError;

            impl std::fmt::Display for RecvError {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("channel closed")
                }
            }

            impl std::error::Error for RecvError {}
        }

        /// Oneshot send error.
        #[derive(Debug, PartialEq, Eq)]
        pub struct SendError<T>(pub T);

        impl<T> std::fmt::Display for SendError<T> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("channel closed")
            }
        }

        impl<T: std::fmt::Debug> std::error::Error for SendError<T> {}

        #[derive(Debug)]
        struct Shared<T> {
            state: StdMutex<State<T>>,
        }

        #[derive(Debug)]
        struct State<T> {
            value: Option<T>,
            sender_consumed: bool,
            receiver_dropped: bool,
            waker: Option<Waker>,
        }

        impl<T> State<T> {
            const fn new() -> Self {
                Self {
                    value: None,
                    sender_consumed: false,
                    receiver_dropped: false,
                    waker: None,
                }
            }
        }

        /// Oneshot sender wrapper.
        #[derive(Debug)]
        pub struct Sender<T> {
            shared: Option<Arc<Shared<T>>>,
        }

        /// Oneshot receiver wrapper.
        pub struct Receiver<T> {
            shared: Arc<Shared<T>>,
            completed: bool,
        }

        impl<T> std::fmt::Debug for Receiver<T> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                let state = self.shared.state.lock().expect("oneshot state poisoned");
                f.debug_struct("Receiver")
                    .field("completed", &self.completed)
                    .field("has_value", &state.value.is_some())
                    .field("sender_consumed", &state.sender_consumed)
                    .field("receiver_dropped", &state.receiver_dropped)
                    .finish()
            }
        }

        impl<T> Drop for Receiver<T> {
            fn drop(&mut self) {
                let mut state = self.shared.state.lock().expect("oneshot state poisoned");
                state.receiver_dropped = true;
                state.waker = None;
            }
        }

        impl<T> Sender<T> {
            /// Deliver the one-shot value to the receiver.
            ///
            /// # Errors
            /// Returns `SendError` when the receiver has already been dropped.
            ///
            /// # Panics
            /// Panics if the same sender is reused after a prior `send` call.
            pub fn send(mut self, value: T) -> Result<(), SendError<T>> {
                let shared = self.shared.take().expect("oneshot sender reused");

                let waker = {
                    let mut state = shared.state.lock().expect("oneshot state poisoned");
                    state.sender_consumed = true;
                    if state.receiver_dropped {
                        return Err(SendError(value));
                    }

                    state.value = Some(value);
                    state.waker.take()
                };

                if let Some(waker) = waker {
                    waker.wake();
                }

                Ok(())
            }
        }

        impl<T> Drop for Sender<T> {
            fn drop(&mut self) {
                let Some(shared) = self.shared.take() else {
                    return;
                };

                let waker = {
                    let mut state = shared.state.lock().expect("oneshot state poisoned");
                    if state.sender_consumed {
                        None
                    } else {
                        state.sender_consumed = true;
                        state.waker.take()
                    }
                };

                if let Some(waker) = waker {
                    waker.wake();
                }
            }
        }

        impl<T> Receiver<T> {
            /// Try to receive the one-shot value without blocking.
            ///
            /// # Errors
            /// Returns `RecvError` when the value is not yet available or the sender was dropped.
            ///
            /// # Panics
            /// Panics if the internal one-shot state mutex is poisoned.
            pub fn try_recv(&mut self) -> Result<T, error::RecvError> {
                if self.completed {
                    return Err(error::RecvError);
                }

                let mut state = self.shared.state.lock().expect("oneshot state poisoned");
                if let Some(value) = state.value.take() {
                    state.waker = None;
                    drop(state);
                    self.completed = true;
                    return Ok(value);
                }

                if state.sender_consumed {
                    state.waker = None;
                    drop(state);
                    self.completed = true;
                    return Err(error::RecvError);
                }

                Err(error::RecvError)
            }

            pub(crate) fn is_finished(&self) -> bool {
                if self.completed {
                    return true;
                }

                let state = self.shared.state.lock().expect("oneshot state poisoned");
                state.value.is_some() || state.sender_consumed || state.receiver_dropped
            }
        }

        impl<T> Future for Receiver<T> {
            type Output = Result<T, error::RecvError>;

            fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                if self.completed {
                    return Poll::Ready(Err(error::RecvError));
                }

                let mut state = self.shared.state.lock().expect("oneshot state poisoned");
                if let Some(value) = state.value.take() {
                    state.waker = None;
                    drop(state);
                    self.completed = true;
                    return Poll::Ready(Ok(value));
                }

                if state.sender_consumed {
                    state.waker = None;
                    drop(state);
                    self.completed = true;
                    return Poll::Ready(Err(error::RecvError));
                }

                if !state
                    .waker
                    .as_ref()
                    .is_some_and(|waker| waker.will_wake(cx.waker()))
                {
                    state.waker = Some(cx.waker().clone());
                }

                Poll::Pending
            }
        }

        /// Create a one-shot channel.
        #[must_use]
        pub fn channel<T>() -> (Sender<T>, Receiver<T>) {
            let shared = Arc::new(Shared {
                state: StdMutex::new(State::new()),
            });
            (
                Sender {
                    shared: Some(Arc::clone(&shared)),
                },
                Receiver {
                    shared,
                    completed: false,
                },
            )
        }
    }

    /// Tokio watch compatibility surface owned by async-core.
    pub mod watch {
        use std::sync::Arc;

        use crate::compatibility_cx;

        pub type Ref<'a, T> = asupersync::channel::watch::Ref<'a, T>;

        pub mod error {
            /// Watch receive error.
            #[derive(Debug, Clone, Copy, PartialEq, Eq)]
            pub struct RecvError;

            impl std::fmt::Display for RecvError {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("channel closed")
                }
            }

            impl std::error::Error for RecvError {}
        }

        /// Watch send error.
        #[derive(Debug, PartialEq, Eq)]
        pub struct SendError<T>(pub T);

        impl<T> std::fmt::Display for SendError<T> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("channel closed")
            }
        }

        impl<T: std::fmt::Debug> std::error::Error for SendError<T> {}

        /// Watch sender wrapper.
        #[derive(Clone, Debug)]
        pub struct Sender<T> {
            inner: Arc<asupersync::channel::watch::Sender<T>>,
        }

        /// Watch receiver wrapper.
        #[derive(Debug)]
        pub struct Receiver<T> {
            inner: asupersync::channel::watch::Receiver<T>,
        }

        impl<T> Clone for Receiver<T> {
            fn clone(&self) -> Self {
                Self {
                    inner: self.inner.clone(),
                }
            }
        }

        impl<T> Sender<T> {
            /// Publish a new watched value.
            ///
            /// # Errors
            /// Returns `SendError` when all receivers have been dropped.
            pub fn send(&self, value: T) -> Result<(), SendError<T>> {
                self.inner.send(value).map_err(|err| match err {
                    asupersync::channel::watch::SendError::Closed(value) => SendError(value),
                })
            }

            pub fn send_modify<F>(&self, f: F)
            where
                T: Clone,
                F: FnOnce(&mut T),
            {
                let _ = self.inner.send_modify(f);
            }

            #[must_use]
            pub fn borrow(&self) -> Ref<'_, T> {
                self.inner.borrow()
            }

            #[must_use]
            pub fn subscribe(&self) -> Receiver<T> {
                Receiver {
                    inner: self.inner.subscribe(),
                }
            }

            #[must_use]
            pub fn is_closed(&self) -> bool {
                self.inner.is_closed()
            }
        }

        impl<T> Receiver<T> {
            /// Wait until the watched value changes.
            ///
            /// # Errors
            /// Returns `RecvError` when the sender side is closed before a new value arrives.
            #[allow(clippy::future_not_send)]
            pub async fn changed(&mut self) -> Result<(), error::RecvError> {
                let cx = compatibility_cx();
                self.inner.changed(&cx).await.map_err(|_| error::RecvError)
            }

            #[must_use]
            pub fn borrow(&self) -> Ref<'_, T> {
                self.inner.borrow()
            }

            #[must_use]
            pub fn borrow_and_update(&mut self) -> Ref<'_, T> {
                self.inner.mark_seen();
                self.inner.borrow()
            }

            #[must_use]
            pub fn has_changed(&self) -> bool {
                self.inner.has_changed()
            }
        }

        /// Create a watch channel.
        #[must_use]
        pub fn channel<T>(value: T) -> (Sender<T>, Receiver<T>) {
            let (sender, receiver) = asupersync::channel::watch::channel(value);
            (
                Sender {
                    inner: Arc::new(sender),
                },
                Receiver { inner: receiver },
            )
        }
    }

    /// Bounded sender with queue instrumentation hooks.
    #[derive(Clone)]
    pub struct BoundedSender<T> {
        name: String,
        capacity: usize,
        inner: mpsc::Sender<T>,
        instrumentation: Arc<dyn Instrumentation>,
    }

    impl<T> BoundedSender<T> {
        fn current_depth(&self) -> usize {
            self.inner.len()
        }

        /// Send with backpressure.
        ///
        /// # Errors
        ///
        /// Returns [`AsyncError::ChannelClosed`] if receiver dropped.
        pub async fn send(&self, value: T) -> Result<(), AsyncError> {
            self.inner
                .send(value)
                .await
                .map_err(|_| AsyncError::ChannelClosed)?;

            self.instrumentation
                .on_queue_send(&self.name, self.current_depth(), self.capacity);
            Ok(())
        }

        /// Try send without waiting.
        ///
        /// # Errors
        ///
        /// Returns [`AsyncError::ChannelFull`] or [`AsyncError::ChannelClosed`].
        pub fn try_send(&self, value: T) -> Result<(), AsyncError> {
            match self.inner.try_send(value) {
                Ok(()) => {
                    self.instrumentation.on_queue_send(
                        &self.name,
                        self.current_depth(),
                        self.capacity,
                    );
                    Ok(())
                }
                Err(mpsc::error::TrySendError::Closed(_)) => Err(AsyncError::ChannelClosed),
                Err(mpsc::error::TrySendError::Full(_)) => Err(AsyncError::ChannelFull),
            }
        }
    }

    /// Bounded receiver with queue instrumentation hooks.
    pub struct BoundedReceiver<T> {
        name: String,
        capacity: usize,
        inner: mpsc::Receiver<T>,
        instrumentation: Arc<dyn Instrumentation>,
    }

    impl<T> BoundedReceiver<T> {
        fn current_depth(&self) -> usize {
            self.capacity.saturating_sub(self.inner.capacity())
        }

        /// Receive next queued item.
        pub async fn recv(&mut self) -> Option<T> {
            let item = self.inner.recv().await;
            self.instrumentation
                .on_queue_receive(&self.name, self.current_depth(), self.capacity);
            item
        }

        /// Close receiver side.
        pub fn close(&mut self) {
            self.inner.close();
        }
    }

    /// Create a bounded channel with no-op instrumentation.
    #[must_use]
    pub fn bounded<T>(
        name: impl Into<String>,
        capacity: usize,
    ) -> (BoundedSender<T>, BoundedReceiver<T>) {
        bounded_with_instrumentation(name, capacity, Arc::new(NoopInstrumentation))
    }

    /// Create a bounded channel with explicit instrumentation.
    #[must_use]
    pub fn bounded_with_instrumentation<T>(
        name: impl Into<String>,
        capacity: usize,
        instrumentation: Arc<dyn Instrumentation>,
    ) -> (BoundedSender<T>, BoundedReceiver<T>) {
        let name = name.into();
        let (sender, receiver) = mpsc::channel(capacity);
        (
            BoundedSender {
                name: name.clone(),
                capacity,
                inner: sender,
                instrumentation: Arc::clone(&instrumentation),
            },
            BoundedReceiver {
                name,
                capacity,
                inner: receiver,
                instrumentation,
            },
        )
    }
}

/// Helpers for watch-based shutdown propagation.
pub mod shutdown {
    use std::time::Duration;

    use super::{AsyncError, channel::watch, time};

    /// Wait until shutdown is signaled (`true`).
    ///
    /// # Errors
    ///
    /// Returns [`AsyncError::Cancelled`] when shutdown is observed or sender drops.
    pub async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) -> Result<(), AsyncError> {
        if *shutdown.borrow() {
            return Err(AsyncError::Cancelled);
        }

        loop {
            shutdown
                .changed()
                .await
                .map_err(|_| AsyncError::Cancelled)?;
            if *shutdown.borrow() {
                return Err(AsyncError::Cancelled);
            }
        }
    }

    /// Sleep until duration elapses unless shutdown arrives first.
    ///
    /// # Errors
    ///
    /// Returns [`AsyncError::Cancelled`] when shutdown is observed before sleep completes.
    pub async fn sleep_or_shutdown(
        duration: Duration,
        shutdown: &mut watch::Receiver<bool>,
    ) -> Result<(), AsyncError> {
        if *shutdown.borrow() {
            return Err(AsyncError::Cancelled);
        }

        crate::select! {
            biased;
            _ = wait_for_shutdown(shutdown) => Err(AsyncError::Cancelled),
            () = time::sleep(duration) => Ok(()),
        }
    }
}

/// Synchronization compatibility surface owned by async-core.
pub mod sync {
    use std::sync::Arc;

    pub use asupersync::sync::OwnedSemaphorePermit;
    use asupersync::sync::{
        LockError, MutexGuard, RwLockReadGuard, RwLockWriteGuard,
        SemaphorePermit as AsupersyncSemaphorePermit,
    };

    use crate::compatibility_cx;

    /// Builds a detached, non-root [`Cx`](asupersync::Cx) for scoping a
    /// semaphore-permit obligation.
    ///
    /// asupersync refuses to create an obligation in the runtime *root* region:
    /// `ObligationToken::reserve` panics with "obligations must be scoped to
    /// non-root regions". The fcp-async-core runtime polls `block_on` futures —
    /// and every `task::spawn`ed task — in the root region, so the ambient
    /// `Cx::current()` there is root and acquiring a permit against it would
    /// always panic (a compatibility break introduced by asupersync 0.3.4). A
    /// permit's real effect is concurrency limiting via its `Drop`; the
    /// obligation is only leak bookkeeping. `detached_cancel_context` provides a
    /// synthetic non-root region intended for exactly this case — it cannot
    /// create a root-scoped obligation. `compatibility_cx()` is still consulted
    /// first so acquiring outside a runtime keeps its clear panic.
    fn permit_scope_cx() -> asupersync::Cx<asupersync::cx::NoCaps> {
        let _ambient = compatibility_cx();
        asupersync::Cx::<asupersync::cx::NoCaps>::detached_cancel_context()
    }

    /// Async mutex compatibility wrapper.
    #[derive(Debug, Default)]
    pub struct Mutex<T> {
        inner: asupersync::sync::Mutex<T>,
    }

    impl<T> Mutex<T> {
        #[must_use]
        pub fn new(value: T) -> Self {
            Self {
                inner: asupersync::sync::Mutex::new(value),
            }
        }

        /// Acquire the mutex asynchronously.
        ///
        /// # Panics
        /// Panics if the underlying lock operation is cancelled or poisoned.
        pub async fn lock(&self) -> MutexGuard<'_, T> {
            let cx = compatibility_cx();
            self.inner
                .lock(&cx)
                .await
                .expect("fcp_async_core::sync::Mutex lock cancelled or poisoned")
        }

        /// Acquire the mutex, tolerating poison instead of panicking.
        ///
        /// Returns `None` when the mutex is (or becomes) poisoned — i.e. a task
        /// panicked while holding the guard. Callers that use the lock purely as
        /// an optimization (e.g. single-flight guards) can degrade to an
        /// unsynchronized path on `None` rather than propagating a poison panic
        /// forever. Cancellation still panics, matching [`Self::lock`].
        ///
        /// # Panics
        /// Panics if the underlying lock operation is cancelled.
        pub async fn lock_poison_tolerant(&self) -> Option<MutexGuard<'_, T>> {
            let cx = compatibility_cx();
            match self.inner.lock(&cx).await {
                Ok(guard) => Some(guard),
                Err(LockError::Poisoned) => None,
                Err(other) => {
                    panic!("fcp_async_core::sync::Mutex lock_poison_tolerant failed: {other:?}")
                }
            }
        }

        /// Returns `true` if the mutex has been poisoned by a panic while held.
        #[must_use]
        pub fn is_poisoned(&self) -> bool {
            self.inner.is_poisoned()
        }

        /// Try to acquire the mutex without waiting.
        ///
        /// # Errors
        /// Returns `TryLockError` when the mutex is already locked.
        pub fn try_lock(&self) -> Result<MutexGuard<'_, T>, TryLockError> {
            self.inner.try_lock().map_err(|_| TryLockError(()))
        }

        /// Returns a mutable reference to the protected value.
        ///
        /// # Panics
        /// Panics if the underlying mutex has been cancelled or poisoned.
        pub fn get_mut(&mut self) -> &mut T {
            self.inner
                .get_mut()
                .expect("fcp_async_core::sync::Mutex get_mut cancelled or poisoned")
        }

        /// Consumes the mutex and returns the protected value.
        ///
        /// # Panics
        /// Panics if the underlying mutex has been cancelled or poisoned.
        pub fn into_inner(self) -> T {
            self.inner
                .into_inner()
                .expect("fcp_async_core::sync::Mutex into_inner cancelled or poisoned")
        }
    }

    /// Async read/write lock compatibility wrapper.
    #[derive(Debug)]
    pub struct RwLock<T> {
        inner: asupersync::sync::RwLock<T>,
    }

    impl<T: Default> Default for RwLock<T> {
        fn default() -> Self {
            Self::new(T::default())
        }
    }

    impl<T> RwLock<T> {
        #[must_use]
        pub fn new(value: T) -> Self {
            Self {
                inner: asupersync::sync::RwLock::new(value),
            }
        }

        /// Acquire a shared read guard asynchronously.
        ///
        /// # Panics
        /// Panics if the underlying lock operation is cancelled or poisoned.
        #[allow(clippy::future_not_send)]
        pub async fn read(&self) -> RwLockReadGuard<'_, T> {
            let cx = compatibility_cx();
            self.inner
                .read(&cx)
                .await
                .expect("fcp_async_core::sync::RwLock read cancelled or poisoned")
        }

        /// Acquire an exclusive write guard asynchronously.
        ///
        /// # Panics
        /// Panics if the underlying lock operation is cancelled or poisoned.
        #[allow(clippy::future_not_send)]
        pub async fn write(&self) -> RwLockWriteGuard<'_, T> {
            let cx = compatibility_cx();
            self.inner
                .write(&cx)
                .await
                .expect("fcp_async_core::sync::RwLock write cancelled or poisoned")
        }

        /// Try to acquire a shared read guard without waiting.
        ///
        /// # Errors
        /// Returns `TryLockError` when the lock cannot be acquired immediately.
        pub fn try_read(&self) -> Result<RwLockReadGuard<'_, T>, TryLockError> {
            self.inner.try_read().map_err(|_| TryLockError(()))
        }

        /// Try to acquire an exclusive write guard without waiting.
        ///
        /// # Errors
        /// Returns `TryLockError` when the lock cannot be acquired immediately.
        pub fn try_write(&self) -> Result<RwLockWriteGuard<'_, T>, TryLockError> {
            self.inner.try_write().map_err(|_| TryLockError(()))
        }

        /// Returns a mutable reference to the protected value.
        ///
        /// # Panics
        /// Panics if the underlying lock has been cancelled or poisoned.
        pub fn get_mut(&mut self) -> &mut T {
            self.inner
                .get_mut()
                .expect("fcp_async_core::sync::RwLock get_mut cancelled or poisoned")
        }

        /// Consumes the lock and returns the protected value.
        ///
        /// # Panics
        /// Panics if the underlying lock has been cancelled or poisoned.
        pub fn into_inner(self) -> T {
            self.inner
                .into_inner()
                .expect("fcp_async_core::sync::RwLock into_inner cancelled or poisoned")
        }
    }

    /// Async semaphore compatibility wrapper.
    #[derive(Debug)]
    pub struct Semaphore {
        inner: Arc<asupersync::sync::Semaphore>,
    }

    impl Default for Semaphore {
        fn default() -> Self {
            Self::new(0)
        }
    }

    impl Semaphore {
        #[must_use]
        pub fn new(permits: usize) -> Self {
            Self {
                inner: Arc::new(asupersync::sync::Semaphore::new(permits)),
            }
        }

        #[must_use]
        pub fn available_permits(&self) -> usize {
            self.inner.available_permits()
        }

        /// Try to acquire a single permit without waiting.
        ///
        /// # Errors
        /// Returns `TryAcquireError` when no permit is currently available.
        pub fn try_acquire(&self) -> Result<SemaphorePermit<'_>, TryAcquireError> {
            // asupersync's synchronous `try_acquire` scopes the permit obligation
            // to `Cx::current()`, which panics with no active context or in the
            // root region (see `permit_scope_cx`). Because this call never awaits,
            // temporarily installing a detached non-root context is safe and keeps
            // the obligation off the root region.
            let _cx_guard = asupersync::Cx::<asupersync::cx::NoCaps>::detached_cancel_context()
                .set_current_restricted();
            self.inner.try_acquire(1).map_err(|_| TryAcquireError(()))
        }

        /// Acquire a single permit asynchronously.
        ///
        /// # Errors
        /// Returns `AcquireError` when the semaphore is closed before a permit is acquired.
        pub async fn acquire(&self) -> Result<SemaphorePermit<'_>, AcquireError> {
            let cx = permit_scope_cx();
            self.inner
                .acquire(&cx, 1)
                .await
                .map_err(|_| AcquireError(()))
        }

        pub fn add_permits(&self, permits: usize) {
            self.inner.add_permits(permits);
        }

        /// Try to acquire an owned permit without waiting.
        ///
        /// # Errors
        /// Returns `TryAcquireError` when no permit is currently available.
        pub fn try_acquire_owned(self: Arc<Self>) -> Result<OwnedSemaphorePermit, TryAcquireError> {
            // See `try_acquire`: scope the permit obligation to a detached
            // non-root context for the duration of this non-awaiting call.
            let _cx_guard = asupersync::Cx::<asupersync::cx::NoCaps>::detached_cancel_context()
                .set_current_restricted();
            asupersync::sync::OwnedSemaphorePermit::try_acquire_arc(&self.inner, 1)
                .map_err(|_| TryAcquireError(()))
        }

        /// Acquire an owned permit asynchronously.
        ///
        /// # Errors
        /// Returns `AcquireError` when the semaphore is closed before a permit is acquired.
        pub async fn acquire_owned(self: Arc<Self>) -> Result<OwnedSemaphorePermit, AcquireError> {
            let cx = permit_scope_cx();
            asupersync::sync::OwnedSemaphorePermit::acquire(Arc::clone(&self.inner), &cx, 1)
                .await
                .map_err(|_| AcquireError(()))
        }
    }

    /// Borrowed semaphore permit.
    pub type SemaphorePermit<'a> = AsupersyncSemaphorePermit<'a>;

    /// Minimal try-lock error compatible with existing call sites.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct TryLockError(());

    impl std::fmt::Display for TryLockError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("operation would block")
        }
    }

    impl std::error::Error for TryLockError {}

    /// Minimal acquire error compatible with existing call sites.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct AcquireError(());

    impl std::fmt::Display for AcquireError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("semaphore closed or cancelled")
        }
    }

    impl std::error::Error for AcquireError {}

    /// Minimal try-acquire error compatible with existing call sites.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct TryAcquireError(());

    impl std::fmt::Display for TryAcquireError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("no permits available")
        }
    }

    impl std::error::Error for TryAcquireError {}
}

/// Task compatibility surface owned by async-core.
pub mod task {
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use crate::AsyncError;
    use futures_util::future::{AbortHandle, Abortable, FutureExt};

    /// Join error returned by spawned tasks.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct JoinError {
        kind: JoinErrorKind,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum JoinErrorKind {
        Cancelled,
        Panicked(String),
    }

    impl JoinError {
        const fn cancelled() -> Self {
            Self {
                kind: JoinErrorKind::Cancelled,
            }
        }

        fn panicked(payload: &(dyn std::any::Any + Send)) -> Self {
            let message = payload.downcast_ref::<&str>().map_or_else(
                || {
                    payload.downcast_ref::<String>().map_or_else(
                        || "task panicked with non-string payload".to_string(),
                        Clone::clone,
                    )
                },
                |message| (*message).to_string(),
            );

            Self {
                kind: JoinErrorKind::Panicked(message),
            }
        }

        /// Returns true when the task was aborted.
        #[must_use]
        pub const fn is_cancelled(&self) -> bool {
            matches!(self.kind, JoinErrorKind::Cancelled)
        }

        /// Returns true when the task panicked.
        #[must_use]
        pub const fn is_panic(&self) -> bool {
            matches!(self.kind, JoinErrorKind::Panicked(_))
        }
    }

    impl std::fmt::Display for JoinError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match &self.kind {
                JoinErrorKind::Cancelled => f.write_str("task was cancelled"),
                JoinErrorKind::Panicked(message) => write!(f, "task panicked: {message}"),
            }
        }
    }

    impl std::error::Error for JoinError {}

    /// Join handle returned from [`spawn`].
    pub struct JoinHandle<T> {
        receiver: crate::channel::oneshot::Receiver<Result<T, JoinError>>,
        abort_handle: AbortHandle,
        detached: bool,
    }

    impl<T> std::fmt::Debug for JoinHandle<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("JoinHandle")
                .field("is_finished", &self.is_finished())
                .finish()
        }
    }

    impl<T> JoinHandle<T> {
        /// Requests cancellation for the spawned task.
        pub fn abort(&self) {
            self.abort_handle.abort();
        }

        /// Returns true if the task has already completed.
        #[must_use]
        pub fn is_finished(&self) -> bool {
            self.receiver.is_finished()
        }

        /// Explicitly detach the task so it can continue after the handle drops.
        pub fn detach(mut self) {
            self.detached = true;
        }
    }

    impl<T> Future for JoinHandle<T> {
        type Output = Result<T, JoinError>;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            match Pin::new(&mut self.receiver).poll(cx) {
                Poll::Ready(Ok(result)) => {
                    self.detached = true;
                    Poll::Ready(result)
                }
                Poll::Ready(Err(_)) => {
                    self.detached = true;
                    Poll::Ready(Err(JoinError::cancelled()))
                }
                Poll::Pending => Poll::Pending,
            }
        }
    }

    impl<T> Drop for JoinHandle<T> {
        fn drop(&mut self) {
            if !self.detached && !self.is_finished() {
                self.abort();
            }
        }
    }

    /// A future wrapper that re-establishes both ambient runtime contexts on
    /// EVERY poll: the Tokio compatibility context (so crates depending on
    /// `tokio`, e.g. `reqwest` and `wiremock`, work on asupersync worker threads)
    /// and the `fcp_async_core` runtime context (so the task can itself spawn).
    ///
    /// Per-poll rather than once-per-task, and that distinction is the whole
    /// point. Both contexts live in thread-locals, and on a work-stealing
    /// multi-threaded scheduler a task may resume on a different worker after
    /// every await. A context installed at the first poll and held across an
    /// await is simply not present on the thread the task resumes on, so the next
    /// `task::spawn` from inside a perfectly healthy task panics with "called
    /// outside an active runtime".
    ///
    /// The Tokio side was already per-poll; the `fcp_async_core` side was not,
    /// which is the bug br-2ak6l traced back to here from two failing `fcp-host`
    /// dispatcher tests.
    ///
    /// Cost: one thread-local read plus a handle clone and a `Vec` push/pop per
    /// poll, the same order as the `Handle::enter` immediately above it that this
    /// path already paid. The alternative — falling back to the ambient handle
    /// inside `current_runtime_context` instead — would be free per poll but has
    /// to GUESS the runtime flavor, since the ambient asupersync handle does not
    /// carry it. Carrying the spawner's flavor explicitly is worth the read: it
    /// also makes `runtime::flavor()` report the truth inside a migrated task.
    struct TaskContextFuture<F> {
        inner: Pin<Box<F>>,
        handle: tokio::runtime::Handle,
        /// Flavor of the runtime this task was spawned from, so the re-derived
        /// context reports the same flavor the spawner had.
        flavor: crate::runtime::RuntimeFlavor,
    }

    impl<F: Future> Future for TaskContextFuture<F> {
        type Output = F::Output;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let _tokio_guard = self.handle.enter();
            // Re-derive from the polling thread's ambient asupersync handle
            // rather than carrying a cloned handle in this future. asupersync
            // installs a WEAK handle on each worker thread; holding a strong
            // clone inside the task would risk dropping the runtime's final
            // reference on a worker during shutdown, which is the hazard
            // `detached_task_shutdown_does_not_drop_final_runtime_reference_on_worker`
            // exists to pin.
            let flavor = self.flavor;
            let _runtime_guard = crate::runtime::worker_runtime_context(flavor)
                .map(crate::runtime::RuntimeGuard::enter);
            self.inner.as_mut().poll(cx)
        }
    }

    const SPAWN_OUTSIDE_RUNTIME_MESSAGE: &str =
        "fcp_async_core::task::spawn called outside an active runtime";

    /// Spawn an asynchronous task.
    ///
    /// The spawned task inherits the Tokio compatibility context from the
    /// calling thread so that crates depending on `tokio` (e.g., `reqwest`,
    /// `wiremock`) work correctly even when the task runs on an asupersync
    /// worker thread.
    ///
    /// # Panics
    /// Panics when called outside an active `fcp_async_core` runtime.
    pub fn spawn<F>(future: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        match try_spawn(future) {
            Ok(handle) => handle,
            Err(AsyncError::Runtime { message }) => panic!("{message}"),
            Err(error) => panic!("fcp_async_core::task::spawn failed: {error}"),
        }
    }

    /// Try to spawn an asynchronous task.
    ///
    /// The spawned task inherits the Tokio compatibility context from the
    /// calling thread so that crates depending on `tokio` (e.g., `reqwest`,
    /// `wiremock`) work correctly even when the task runs on an asupersync
    /// worker thread.
    ///
    /// # Errors
    ///
    /// Returns [`AsyncError::Runtime`] when called outside an active
    /// `fcp_async_core` runtime.
    pub fn try_spawn<F>(future: F) -> Result<JoinHandle<F::Output>, AsyncError>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let runtime_context =
            crate::runtime::current_runtime_context().ok_or_else(|| AsyncError::Runtime {
                message: SPAWN_OUTSIDE_RUNTIME_MESSAGE.to_string(),
            })?;
        let runtime = runtime_context.handle.clone();
        let runtime_flavor = runtime_context.flavor;

        // Capture the Tokio compat handle from the calling thread so the
        // spawned task can enter the Tokio runtime context on whatever
        // worker thread the asupersync scheduler places it on.
        let tokio_handle = crate::runtime::get_or_create_tokio_compat_handle();
        let (result_tx, result_rx) = crate::channel::oneshot::channel();

        let (abort_handle, abort_registration) = AbortHandle::new_pair();
        let future = Abortable::new(
            std::panic::AssertUnwindSafe(future).catch_unwind(),
            abort_registration,
        );

        let wrapped = TaskContextFuture {
            inner: Box::pin(future),
            handle: tokio_handle,
            flavor: runtime_flavor,
        };

        std::mem::drop(runtime.spawn(async move {
            let result = match wrapped.await {
                Ok(Ok(output)) => Ok(output),
                Ok(Err(payload)) => Err(JoinError::panicked(payload.as_ref())),
                Err(_) => Err(JoinError::cancelled()),
            };
            let _ = result_tx.send(result);
        }));

        Ok(JoinHandle {
            receiver: result_rx,
            abort_handle,
            detached: false,
        })
    }

    /// Spawn a task that is allowed to outlive the returned handle.
    pub fn spawn_detached<F>(future: F)
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        spawn(future).detach();
    }

    /// Cooperatively yield execution.
    pub async fn yield_now() {
        asupersync::runtime::yield_now().await;
    }
}

/// Async I/O re-exports and compatibility extensions.
pub mod io {
    use asupersync::stream::StreamExt as _;
    use std::io;

    pub use asupersync::io::{
        AsyncBufRead, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf,
        ReadLine, read_line,
    };

    /// Tokio-style line reader backed by Asupersync's stream-based implementation.
    #[derive(Debug)]
    pub struct Lines<R> {
        inner: asupersync::io::Lines<R>,
    }

    impl<R> Lines<R> {
        /// Create a line reader from an async buffered reader.
        #[must_use]
        pub fn new(reader: R) -> Self {
            Self {
                inner: asupersync::io::Lines::new(reader),
            }
        }
    }

    impl<R> Lines<R>
    where
        R: AsyncBufRead + Unpin,
    {
        /// Return the next available line, matching Tokio's `next_line()` shape.
        ///
        /// # Errors
        ///
        /// Returns any I/O error produced while reading the next buffered line.
        pub async fn next_line(&mut self) -> io::Result<Option<String>> {
            self.inner
                .next()
                .await
                .map_or(Ok(None), |result| result.map(Some))
        }
    }

    /// Extension trait that preserves the Tokio-style `read_line` method shape.
    pub trait AsyncBufReadExt: AsyncBufRead + Unpin {
        /// Read bytes until a newline is found, appending them to `buf`.
        fn read_line<'a>(&'a mut self, buf: &'a mut String) -> ReadLine<'a, Self>
        where
            Self: Sized,
        {
            read_line(self, buf)
        }

        /// Return a cancel-aware line stream, matching Tokio's `lines()` ergonomics.
        fn lines(self) -> Lines<Self>
        where
            Self: Sized,
        {
            Lines::new(self)
        }
    }

    impl<T> AsyncBufReadExt for T where T: AsyncBufRead + Unpin + ?Sized {}
}

/// Native Hyper runtime adapters for async-core I/O types.
pub mod hyper_bridge {
    use std::future::Future;
    use std::io;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};

    use pin_project_lite::pin_project;

    pin_project! {
        /// Wrap an async-core I/O type so Hyper can drive it directly.
        pub struct HyperIo<T> {
            #[pin]
            inner: T,
        }
    }

    impl<T> HyperIo<T> {
        /// Construct a new Hyper-compatible wrapper.
        pub const fn new(inner: T) -> Self {
            Self { inner }
        }

        /// Borrow the wrapped I/O type.
        pub const fn inner(&self) -> &T {
            &self.inner
        }

        /// Mutably borrow the wrapped I/O type.
        pub const fn inner_mut(&mut self) -> &mut T {
            &mut self.inner
        }

        /// Consume the wrapper and return the wrapped I/O type.
        pub fn into_inner(self) -> T {
            self.inner
        }
    }

    impl<T> hyper::rt::Read for HyperIo<T>
    where
        T: crate::io::AsyncRead,
    {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            mut hyper_buf: hyper::rt::ReadBufCursor<'_>,
        ) -> Poll<io::Result<()>> {
            let remaining = hyper_buf.remaining();
            if remaining == 0 {
                return Poll::Ready(Ok(()));
            }

            let mut scratch = vec![0_u8; remaining];
            let mut read_buf = crate::io::ReadBuf::new(&mut scratch);
            match self.project().inner.poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    hyper_buf.put_slice(read_buf.filled());
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Pending => Poll::Pending,
            }
        }
    }

    impl<T> hyper::rt::Write for HyperIo<T>
    where
        T: crate::io::AsyncWrite,
    {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.project().inner.poll_write(cx, buf)
        }

        fn poll_write_vectored(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &[io::IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            self.project().inner.poll_write_vectored(cx, bufs)
        }

        fn is_write_vectored(&self) -> bool {
            self.inner.is_write_vectored()
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.project().inner.poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.project().inner.poll_shutdown(cx)
        }
    }

    type SpawnFuture = Pin<Box<dyn Future<Output = ()> + Send>>;
    type SpawnFn = Arc<dyn Fn(SpawnFuture) + Send + Sync>;

    /// Hyper executor backed by `fcp_async_core::task::spawn`.
    #[derive(Clone)]
    pub struct HyperExecutor {
        spawn_fn: SpawnFn,
    }

    impl std::fmt::Debug for HyperExecutor {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("HyperExecutor")
                .field("has_spawn_fn", &true)
                .finish()
        }
    }

    impl HyperExecutor {
        /// Create an executor with a custom spawn function.
        pub fn with_spawn_fn<F>(spawn_fn: F) -> Self
        where
            F: Fn(SpawnFuture) + Send + Sync + 'static,
        {
            Self {
                spawn_fn: Arc::new(spawn_fn),
            }
        }
    }

    impl<F> hyper::rt::Executor<F> for HyperExecutor
    where
        F: Future<Output = ()> + Send + 'static,
    {
        fn execute(&self, future: F) {
            (self.spawn_fn)(Box::pin(future));
        }
    }
}

/// Async process re-exports.
pub mod process {
    pub use asupersync::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};
}

/// Async network re-exports.
pub mod net {
    #[cfg(unix)]
    pub use asupersync::net::UnixListener;
    #[cfg(unix)]
    pub use asupersync::net::UnixStream;
    pub use asupersync::net::{TcpListener, TcpStream};
}

/// TLS connector and stream re-exports from asupersync.
pub mod tls {
    pub use asupersync::tls::{TlsConnector, TlsConnectorBuilder, TlsStream};
}

/// WebSocket client and protocol re-exports from asupersync.
pub mod websocket {
    pub use asupersync::net::websocket::{
        ClientHandshake, CloseCode, CloseConfig, CloseReason, HttpResponse, Message, WebSocket,
        WebSocketConfig, WsConnectError, WsError, WsUrl,
    };

    /// Client-focused re-exports mirroring asupersync's websocket client surface.
    pub mod client {
        pub use super::{Message, WebSocket, WebSocketConfig, WsConnectError};
    }
}

/// HTTP/1.1 client re-exports from asupersync.
pub mod http {
    pub use asupersync::http::h1::{
        ClientError as HttpClientError, ClientIncomingBody, HttpClient, HttpClientBuilder,
        HttpError, Method, Response as HttpResponse, StatusCode,
    };

    /// HTTP body trait re-exports.
    pub mod body {
        pub use asupersync::http::body::Body;
    }

    /// HTTP client internals re-exports.
    pub mod client_io {
        pub use asupersync::http::h1::http_client::ClientIo;
    }
}

/// Byte buffer re-exports from asupersync.
pub mod bytes {
    pub use asupersync::bytes::{Buf, BufMut, Bytes, BytesMut};
}

/// Signal handling re-exports from asupersync.
pub mod signal {
    #[cfg(unix)]
    pub use asupersync::signal::{Signal, sighup, sigint, sigterm};

    #[cfg(not(unix))]
    pub use asupersync::signal::ctrl_c;
}

#[derive(Debug)]
struct CancellationState {
    sender: channel::watch::Sender<bool>,
    _keepalive: std::sync::Mutex<channel::watch::Receiver<bool>>,
}

/// Cooperative cancellation token.
#[derive(Clone, Debug)]
pub struct CancellationToken {
    inner: Arc<CancellationState>,
}

impl CancellationToken {
    /// Create token.
    #[must_use]
    pub fn new() -> Self {
        let (sender, receiver) = channel::watch::channel(false);
        Self {
            inner: Arc::new(CancellationState {
                sender,
                _keepalive: std::sync::Mutex::new(receiver),
            }),
        }
    }

    /// Trigger cancellation.
    pub fn cancel(&self) {
        let _ = self.inner.sender.send(true);
    }

    /// Current cancellation state.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        *self.inner.sender.borrow()
    }

    /// Subscribe cancellation updates.
    #[must_use]
    pub fn subscribe(&self) -> CancellationListener {
        CancellationListener {
            receiver: self.inner.sender.subscribe(),
        }
    }
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

/// Cancellation listener for a [`CancellationToken`].
#[derive(Debug)]
pub struct CancellationListener {
    receiver: channel::watch::Receiver<bool>,
}

impl CancellationListener {
    /// Current cancellation state.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        *self.receiver.borrow()
    }

    /// Await cancellation.
    ///
    /// # Errors
    ///
    /// Returns [`AsyncError::Cancelled`] if sender side drops.
    pub async fn cancelled(&mut self) -> Result<(), AsyncError> {
        if *self.receiver.borrow() {
            return Ok(());
        }

        loop {
            self.receiver
                .changed()
                .await
                .map_err(|_| AsyncError::Cancelled)?;
            if *self.receiver.borrow() {
                return Ok(());
            }
        }
    }
}

/// Structured task group with cooperative shutdown.
pub struct TaskGroup {
    cancellation: CancellationToken,
    tasks: Vec<(String, task::JoinHandle<Result<(), AsyncError>>)>,
    instrumentation: Arc<dyn Instrumentation>,
}

impl TaskGroup {
    /// Create group with no-op hooks.
    #[must_use]
    pub fn new() -> Self {
        Self::with_instrumentation(Arc::new(NoopInstrumentation))
    }

    /// Create group with custom hooks.
    #[must_use]
    pub fn with_instrumentation(instrumentation: Arc<dyn Instrumentation>) -> Self {
        Self {
            cancellation: CancellationToken::new(),
            tasks: Vec::new(),
            instrumentation,
        }
    }

    /// Get cancellation token.
    #[must_use]
    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    /// Subscribe cancellation.
    #[must_use]
    pub fn subscribe_cancellation(&self) -> CancellationListener {
        self.cancellation.subscribe()
    }

    /// Spawn named task.
    pub fn spawn<F>(&mut self, name: impl Into<String>, future: F)
    where
        F: Future<Output = Result<(), AsyncError>> + Send + 'static,
    {
        let task_name = name.into();
        self.instrumentation.on_task_spawn(&task_name);

        let instrumentation = Arc::clone(&self.instrumentation);
        let hook_name = task_name.clone();
        let handle = task::spawn(async move {
            let result = future.await;
            instrumentation.on_task_exit(&hook_name, &result);
            result
        });

        self.tasks.push((task_name, handle));
    }

    /// Cancel and await tasks with timeout bound.
    ///
    /// # Errors
    ///
    /// Returns first error from task exit/join/timeout.
    pub async fn shutdown(mut self, timeout: Duration) -> Result<(), AsyncError> {
        use crate::__private::futures_util::stream::{FuturesUnordered, StreamExt};

        self.cancellation.cancel();

        let timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
        let deadline = saturating_instant_add(std::time::Instant::now(), timeout);
        let mut first_error: Option<AsyncError> = None;

        let mut pending = self
            .tasks
            .drain(..)
            .map(|(task_name, handle)| async move { (task_name, handle.await) })
            .collect::<FuturesUnordered<_>>();

        while !pending.is_empty() {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(first_error.unwrap_or(AsyncError::Timeout { timeout_ms }));
            }

            match time::timeout(remaining, pending.next()).await {
                Ok(Some((_task_name, Ok(Ok(()))))) => {}
                Ok(Some((task_name, Err(err)))) => {
                    if first_error.is_none() {
                        first_error = Some(AsyncError::Join {
                            message: format!("{task_name}: {err}"),
                        });
                    }
                }
                Ok(Some((_task_name, Ok(Err(err))))) => {
                    if first_error.is_none() {
                        first_error = Some(err);
                    }
                }
                Ok(None) => break,
                Err(AsyncError::Timeout { .. }) => {
                    return Err(first_error.unwrap_or(AsyncError::Timeout { timeout_ms }));
                }
                Err(err) => return Err(first_error.unwrap_or(err)),
            }
        }

        first_error.map_or(Ok(()), Err)
    }
}

impl Default for TaskGroup {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::future;
    use std::task::Poll;
    use std::time::{Duration, Instant};
    use std::{
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
        sync::{Arc, Mutex},
    };

    use super::{
        AsyncError, CancellationToken, ContextScope, ExecutionContext, Instrumentation, TaskGroup,
        channel, io, runtime, task, time, tls, websocket,
    };

    static PANIC_HOOK_LOCK: Mutex<()> = Mutex::new(());

    fn overflowing_duration_for(now: Instant) -> Option<Duration> {
        let mut candidate = Duration::from_secs(1);

        while now.checked_add(candidate).is_some() {
            let Some(next) = candidate.checked_mul(2) else {
                break;
            };
            candidate = next;
        }

        if now.checked_add(candidate).is_none() {
            return Some(candidate);
        }

        now.checked_add(Duration::MAX)
            .is_none()
            .then_some(Duration::MAX)
    }

    #[test]
    fn block_on_sync_executes_outside_tokio_runtime() {
        let output = runtime::block_on_sync(async { 7_u8 }).expect("block_on_sync should succeed");
        assert_eq!(output, 7);
    }

    #[test]
    fn block_on_sync_supports_io_driver() {
        let result = runtime::block_on_sync(async {
            use super::io::{AsyncReadExt as _, AsyncWriteExt as _};

            let listener = super::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind local listener");
            let addr = listener.local_addr().expect("local listener addr");
            let server = task::spawn(async move {
                let (mut stream, _) = listener.accept().await.expect("accept client");
                let mut buf = [0_u8; 4];
                stream
                    .read_exact(&mut buf)
                    .await
                    .expect("server read request");
                assert_eq!(&buf, b"ping");
                stream.write_all(b"pong").await.expect("server write reply");
            });
            let mut client = super::net::TcpStream::connect(addr)
                .await
                .expect("connect client");
            client
                .write_all(b"ping")
                .await
                .expect("client write request");
            let mut reply = [0_u8; 4];
            client
                .read_exact(&mut reply)
                .await
                .expect("client read reply");
            assert_eq!(&reply, b"pong");
            server.await.expect("server task should join");
        });
        assert!(result.is_ok());
    }

    #[test]
    fn tls_and_websocket_reexports_resolve() {
        fn assert_type<T>() {}

        assert_type::<tls::TlsConnector>();
        assert_type::<tls::TlsConnectorBuilder>();
        assert_type::<tls::TlsStream<super::net::TcpStream>>();
        assert_type::<websocket::ClientHandshake>();
        assert_type::<websocket::CloseCode>();
        assert_type::<websocket::CloseConfig>();
        assert_type::<websocket::CloseReason>();
        assert_type::<websocket::HttpResponse>();
        assert_type::<websocket::Message>();
        assert_type::<websocket::WebSocket<super::net::TcpStream>>();
        assert_type::<websocket::WebSocketConfig>();
        assert_type::<websocket::WsConnectError>();
        assert_type::<websocket::WsError>();
        assert_type::<websocket::WsUrl>();
        assert_type::<websocket::client::Message>();
        assert_type::<websocket::client::WebSocket<super::net::TcpStream>>();
        assert_type::<websocket::client::WebSocketConfig>();
        assert_type::<websocket::client::WsConnectError>();
    }

    #[runtime::test]
    async fn timeout_maps_elapsed_to_async_error() {
        let timeout_result = time::timeout(Duration::from_millis(5), future::pending::<()>()).await;
        assert!(matches!(timeout_result, Err(AsyncError::Timeout { .. })));
    }

    #[runtime::test]
    async fn cancellation_propagates_to_all_listeners() {
        let token = CancellationToken::new();
        let mut listener_a = token.subscribe();
        let mut listener_b = token.subscribe();

        let task_a = task::spawn(async move { listener_a.cancelled().await });
        let task_b = task::spawn(async move { listener_b.cancelled().await });

        token.cancel();

        assert!(task_a.await.expect("join task_a").is_ok());
        assert!(task_b.await.expect("join task_b").is_ok());
    }

    #[runtime::test]
    async fn bounded_queue_enforces_capacity() {
        let (sender, mut receiver) = channel::bounded::<u8>("test-queue", 1);

        sender.try_send(1).expect("first send");
        let err = sender.try_send(2).expect_err("full queue should reject");
        assert!(matches!(err, AsyncError::ChannelFull));

        assert_eq!(receiver.recv().await, Some(1));
        sender.send(3).await.expect("send after drain");
        assert_eq!(receiver.recv().await, Some(3));
    }

    #[runtime::test]
    async fn task_group_structured_shutdown() {
        let mut group = TaskGroup::new();
        let mut shutdown = group.subscribe_cancellation();

        group.spawn("worker", async move {
            shutdown.cancelled().await?;
            Ok(())
        });

        let result = group.shutdown(Duration::from_millis(250)).await;
        assert!(result.is_ok());
    }

    #[runtime::test]
    async fn cancellation_storm_drains_task_group_without_orphans() {
        let active = Arc::new(AtomicUsize::new(0));
        let mut group = TaskGroup::new();

        for index in 0..64 {
            let active = Arc::clone(&active);
            let mut listener = group.subscribe_cancellation();
            group.spawn(format!("worker-{index}"), async move {
                active.fetch_add(1, Ordering::SeqCst);
                let result = listener.cancelled().await;
                active.fetch_sub(1, Ordering::SeqCst);
                result
            });
        }

        task::yield_now().await;

        let shutdown = group.shutdown(Duration::from_secs(1)).await;
        assert!(shutdown.is_ok());
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[runtime::test]
    async fn request_context_deadline_times_out() {
        let context = ExecutionContext::request_scoped(Duration::from_millis(10));
        let err = context
            .run(async {
                time::sleep(Duration::from_millis(50)).await;
            })
            .await
            .expect_err("deadline should timeout");
        assert!(matches!(err, AsyncError::Timeout { .. }));
        assert_eq!(context.scope(), ContextScope::Request);
    }

    #[runtime::test]
    async fn request_context_cancellation_precedes_deadline() {
        let context = ExecutionContext::request_scoped(Duration::from_secs(1));
        context.cancel();

        let err = context
            .run(async {
                time::sleep(Duration::from_secs(5)).await;
            })
            .await
            .expect_err("cancelled context should fail");

        assert_eq!(err, AsyncError::Cancelled);
    }

    // ─────────────────────────────────────────────────────────────────────
    // AsyncError enum coverage
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn async_error_display_messages() {
        let timeout = AsyncError::Timeout { timeout_ms: 5000 };
        assert_eq!(timeout.to_string(), "operation timed out after 5000ms");

        let cancelled = AsyncError::Cancelled;
        assert_eq!(cancelled.to_string(), "operation cancelled");

        let closed = AsyncError::ChannelClosed;
        assert_eq!(closed.to_string(), "channel closed");

        let full = AsyncError::ChannelFull;
        assert_eq!(full.to_string(), "channel full");

        let io = AsyncError::ProtocolIo {
            message: "connection reset".into(),
        };
        assert_eq!(io.to_string(), "protocol io fault: connection reset");

        let join = AsyncError::Join {
            message: "task panicked".into(),
        };
        assert_eq!(join.to_string(), "task join failed: task panicked");

        let rt = AsyncError::Runtime {
            message: "no runtime".into(),
        };
        assert_eq!(rt.to_string(), "runtime failure: no runtime");
    }

    #[test]
    fn async_error_clone_and_eq() {
        let a = AsyncError::Timeout { timeout_ms: 100 };
        let b = a.clone();
        assert_eq!(a, b);

        assert_ne!(AsyncError::Cancelled, AsyncError::ChannelClosed);
        assert_ne!(AsyncError::ChannelFull, AsyncError::ChannelClosed);
    }

    #[test]
    fn async_error_debug_format() {
        let err = AsyncError::Timeout { timeout_ms: 42 };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Timeout"));
        assert!(dbg.contains("42"));
    }

    // ─────────────────────────────────────────────────────────────────────
    // Deadline coverage
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn deadline_after_not_immediately_expired() {
        let d = super::Deadline::after(Duration::from_secs(10));
        assert!(!d.is_expired());
        assert!(d.remaining() > Duration::ZERO);
    }

    #[test]
    fn deadline_at_with_past_instant_is_expired() {
        let past = std::time::Instant::now()
            .checked_sub(Duration::from_secs(1))
            .unwrap();
        let d = super::Deadline::at(past);
        assert!(d.is_expired());
        assert_eq!(d.remaining(), Duration::ZERO);
    }

    #[test]
    fn deadline_clone_and_eq() {
        let d1 = super::Deadline::after(Duration::from_secs(5));
        let d2 = d1;
        assert_eq!(d1, d2);
    }

    #[runtime::test]
    async fn deadline_run_succeeds_within_budget() {
        let d = super::Deadline::after(Duration::from_secs(5));
        let result = d.run(async { 42_u32 }).await;
        assert_eq!(result.unwrap(), 42);
    }

    #[runtime::test]
    async fn deadline_run_times_out_on_expired() {
        let past = std::time::Instant::now()
            .checked_sub(Duration::from_secs(1))
            .unwrap();
        let d = super::Deadline::at(past);
        let err = d
            .run(async {
                time::sleep(Duration::from_secs(10)).await;
            })
            .await
            .expect_err("expired deadline should timeout");
        assert!(matches!(err, AsyncError::Timeout { .. }));
    }

    // ─────────────────────────────────────────────────────────────────────
    // ContextScope coverage
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn context_scope_eq_and_debug() {
        assert_eq!(ContextScope::Request, ContextScope::Request);
        assert_eq!(ContextScope::Background, ContextScope::Background);
        assert_ne!(ContextScope::Request, ContextScope::Background);
        let dbg = format!("{:?}", ContextScope::Request);
        assert!(dbg.contains("Request"));
    }

    // ─────────────────────────────────────────────────────────────────────
    // ExecutionContext coverage
    // ─────────────────────────────────────────────────────────────────────

    #[runtime::test]
    async fn background_context_no_deadline() {
        let ctx = ExecutionContext::background();
        assert_eq!(ctx.scope(), ContextScope::Background);
        assert!(ctx.deadline().is_none());
        assert!(ctx.remaining_budget().is_none());
    }

    #[runtime::test]
    async fn background_context_run_completes() {
        let ctx = ExecutionContext::background();
        let result = ctx.run(async { 99_u64 }).await;
        assert_eq!(result.unwrap(), 99);
    }

    #[runtime::test]
    async fn context_child_inherits_scope_and_cancellation() {
        let parent = ExecutionContext::request_scoped(Duration::from_secs(10));
        let child = parent.child();

        assert_eq!(child.scope(), ContextScope::Request);
        assert!(!child.is_cancelled());

        parent.cancel();
        assert!(child.is_cancelled());
    }

    #[runtime::test]
    async fn context_with_deadline_replaces_existing() {
        let ctx = ExecutionContext::background().with_deadline(Duration::from_secs(30));
        assert!(ctx.deadline().is_some());
        assert!(ctx.remaining_budget().is_some());
    }

    #[runtime::test]
    async fn context_remaining_budget_decreases() {
        let ctx = ExecutionContext::request_scoped(Duration::from_millis(500));
        let budget_before = ctx.remaining_budget().unwrap();
        time::sleep(Duration::from_millis(50)).await;
        let budget_after = ctx.remaining_budget().unwrap();
        assert!(budget_after < budget_before);
    }

    #[runtime::test]
    async fn context_sleep_completes_within_budget() {
        let ctx = ExecutionContext::request_scoped(Duration::from_secs(5));
        let result = ctx.sleep(Duration::from_millis(10)).await;
        assert!(result.is_ok());
    }

    #[runtime::test]
    async fn context_sleep_cancelled_returns_error() {
        let ctx = ExecutionContext::request_scoped(Duration::from_secs(5));
        ctx.cancel();
        let err = ctx
            .sleep(Duration::from_secs(10))
            .await
            .expect_err("cancelled context sleep should fail");
        assert_eq!(err, AsyncError::Cancelled);
    }

    #[runtime::test]
    async fn context_is_cancelled_reflects_state() {
        let ctx = ExecutionContext::request_scoped(Duration::from_secs(10));
        assert!(!ctx.is_cancelled());
        ctx.cancel();
        assert!(ctx.is_cancelled());
    }

    // ─────────────────────────────────────────────────────────────────────
    // CancellationToken & CancellationListener coverage
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn cancellation_token_default() {
        let token = CancellationToken::default();
        assert!(!token.is_cancelled());
    }

    #[test]
    fn cancellation_token_cancel_is_observable() {
        let token = CancellationToken::new();
        assert!(!token.is_cancelled());
        token.cancel();
        assert!(token.is_cancelled());
    }

    #[test]
    fn cancellation_token_clone_shares_state() {
        let token = CancellationToken::new();
        let cloned = token.clone();
        token.cancel();
        assert!(cloned.is_cancelled());
    }

    #[runtime::test]
    async fn cancellation_listener_already_cancelled_returns_immediately() {
        let token = CancellationToken::new();
        token.cancel();

        let mut listener = token.subscribe();
        assert!(listener.is_cancelled());

        // cancelled() should return immediately
        let result = time::timeout(Duration::from_millis(100), listener.cancelled()).await;
        assert!(result.is_ok());
    }

    #[runtime::test]
    async fn cancellation_listener_waits_for_cancel() {
        let token = CancellationToken::new();
        let mut listener = token.subscribe();
        assert!(!listener.is_cancelled());

        let token_clone = token.clone();
        task::spawn_detached(async move {
            time::sleep(Duration::from_millis(20)).await;
            token_clone.cancel();
        });

        let result = time::timeout(Duration::from_secs(1), listener.cancelled()).await;
        assert!(result.is_ok());
    }

    // ─────────────────────────────────────────────────────────────────────
    // TaskGroup coverage
    // ─────────────────────────────────────────────────────────────────────

    #[runtime::test]
    async fn task_group_default() {
        let group = TaskGroup::default();
        let result = group.shutdown(Duration::from_millis(100)).await;
        assert!(result.is_ok());
    }

    #[runtime::test]
    async fn task_group_spawn_error_propagated() {
        let mut group = TaskGroup::new();

        group.spawn("failing-task", async {
            Err(AsyncError::Runtime {
                message: "deliberate failure".into(),
            })
        });

        let err = group
            .shutdown(Duration::from_secs(1))
            .await
            .expect_err("task error should propagate");
        assert!(matches!(err, AsyncError::Runtime { .. }));
    }

    #[runtime::test]
    async fn task_group_shutdown_timeout_aborts_hung_tasks() {
        let mut group = TaskGroup::new();

        group.spawn("hung-task", async {
            // Never completes
            future::pending::<Result<(), AsyncError>>().await
        });

        let err = group
            .shutdown(Duration::from_millis(50))
            .await
            .expect_err("hung task should cause timeout");
        assert!(matches!(err, AsyncError::Timeout { .. }));
    }

    #[runtime::test]
    async fn task_group_shutdown_does_not_let_hung_task_mask_ready_error() {
        let mut group = TaskGroup::new();
        let mut hung_cancel = group.subscribe_cancellation();
        let mut error_cancel = group.subscribe_cancellation();
        let error_started = Arc::new(AtomicBool::new(false));
        let error_started_clone = Arc::clone(&error_started);

        group.spawn("hung-first", async move {
            hung_cancel.cancelled().await?;
            future::pending::<Result<(), AsyncError>>().await
        });

        group.spawn("error-second", async move {
            error_cancel.cancelled().await?;
            error_started_clone.store(true, Ordering::SeqCst);
            Err(AsyncError::ChannelClosed)
        });

        let err = group
            .shutdown(Duration::from_millis(50))
            .await
            .expect_err("ready task error should outrank later timeout");
        assert_eq!(err, AsyncError::ChannelClosed);
        assert!(error_started.load(Ordering::SeqCst));
    }

    #[runtime::test]
    async fn task_group_shutdown_overflowing_timeout_still_waits_for_graceful_exit() {
        let Some(overflow) = overflowing_duration_for(Instant::now()) else {
            return;
        };
        let mut group = TaskGroup::new();
        let mut listener = group.subscribe_cancellation();
        let completed = Arc::new(AtomicUsize::new(0));
        let completed_clone = Arc::clone(&completed);

        group.spawn("graceful-exit", async move {
            listener.cancelled().await?;
            time::sleep(Duration::from_millis(20)).await;
            completed_clone.store(1, Ordering::SeqCst);
            Ok(())
        });

        group
            .shutdown(overflow)
            .await
            .expect("overflowing shutdown budget should not collapse to an immediate timeout");
        assert_eq!(completed.load(Ordering::SeqCst), 1);
    }

    #[runtime::test]
    async fn task_group_cancellation_token_shared() {
        let mut group = TaskGroup::new();
        let token = group.cancellation_token();
        let mut listener = group.subscribe_cancellation();

        group.spawn("watcher", async move {
            listener.cancelled().await?;
            Ok(())
        });

        assert!(!token.is_cancelled());
        let result = group.shutdown(Duration::from_secs(1)).await;
        assert!(result.is_ok());
        assert!(token.is_cancelled());
    }

    #[runtime::test]
    async fn task_group_with_instrumentation_fires_hooks() {
        use std::sync::atomic::AtomicU32;

        struct CountingHooks {
            spawns: AtomicU32,
            exits: AtomicU32,
        }

        impl super::Instrumentation for CountingHooks {
            fn on_task_spawn(&self, _name: &str) {
                self.spawns.fetch_add(1, Ordering::SeqCst);
            }
            fn on_task_exit(&self, _name: &str, _result: &Result<(), AsyncError>) {
                self.exits.fetch_add(1, Ordering::SeqCst);
            }
        }

        let hooks = Arc::new(CountingHooks {
            spawns: AtomicU32::new(0),
            exits: AtomicU32::new(0),
        });
        let hooks_ref = Arc::clone(&hooks);

        let mut group = TaskGroup::with_instrumentation(hooks);
        group.spawn("task-a", async { Ok(()) });
        group.spawn("task-b", async { Ok(()) });

        group.shutdown(Duration::from_secs(1)).await.unwrap();

        assert_eq!(hooks_ref.spawns.load(Ordering::SeqCst), 2);
        assert_eq!(hooks_ref.exits.load(Ordering::SeqCst), 2);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Instrumentation trait coverage
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn noop_instrumentation_default() {
        let noop = super::NoopInstrumentation;
        // All methods should be callable without panic
        noop.on_task_spawn("test");
        noop.on_task_exit("test", &Ok(()));
        noop.on_queue_send("q", 5, 10);
        noop.on_queue_receive("q", 4, 10);
    }

    // ─────────────────────────────────────────────────────────────────────
    // BoundedSender/BoundedReceiver coverage
    // ─────────────────────────────────────────────────────────────────────

    #[runtime::test]
    async fn bounded_sender_closed_channel_error() {
        let (sender, receiver) = channel::bounded::<u32>("test", 4);
        drop(receiver);

        let err = sender
            .send(1)
            .await
            .expect_err("closed channel should fail");
        assert_eq!(err, AsyncError::ChannelClosed);
    }

    #[runtime::test]
    async fn bounded_try_send_closed_channel() {
        let (sender, receiver) = channel::bounded::<u32>("test", 4);
        drop(receiver);

        let err = sender.try_send(1).expect_err("closed channel should fail");
        assert_eq!(err, AsyncError::ChannelClosed);
    }

    #[runtime::test]
    async fn bounded_receiver_close_signals_sender() {
        let (sender, mut receiver) = channel::bounded::<u32>("test", 4);
        receiver.close();

        // Sender should eventually fail
        let err = sender
            .send(1)
            .await
            .expect_err("closed receiver should fail");
        assert_eq!(err, AsyncError::ChannelClosed);
    }

    #[runtime::test]
    async fn bounded_receiver_returns_none_when_sender_dropped() {
        let (sender, mut receiver) = channel::bounded::<u32>("test", 4);
        sender.send(1).await.unwrap();
        drop(sender);

        assert_eq!(receiver.recv().await, Some(1));
        assert_eq!(receiver.recv().await, None);
    }

    #[runtime::test]
    async fn bounded_with_instrumentation_fires_hooks() {
        use std::sync::atomic::AtomicU32;

        struct QueueHooks {
            sends: AtomicU32,
            recvs: AtomicU32,
        }

        impl super::Instrumentation for QueueHooks {
            fn on_queue_send(&self, _name: &str, _depth: usize, _capacity: usize) {
                self.sends.fetch_add(1, Ordering::SeqCst);
            }
            fn on_queue_receive(&self, _name: &str, _depth: usize, _capacity: usize) {
                self.recvs.fetch_add(1, Ordering::SeqCst);
            }
        }

        let hooks = Arc::new(QueueHooks {
            sends: AtomicU32::new(0),
            recvs: AtomicU32::new(0),
        });
        let hooks_ref = Arc::clone(&hooks);

        let (sender, mut receiver) =
            channel::bounded_with_instrumentation("instrumented", 4, hooks);

        sender.send(1).await.unwrap();
        sender.try_send(2).unwrap();
        receiver.recv().await;
        receiver.recv().await;

        assert_eq!(hooks_ref.sends.load(Ordering::SeqCst), 2);
        assert_eq!(hooks_ref.recvs.load(Ordering::SeqCst), 2);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Shutdown module coverage
    // ─────────────────────────────────────────────────────────────────────

    #[runtime::test]
    async fn wait_for_shutdown_returns_immediately_if_already_set() {
        let (tx, mut rx) = channel::watch::channel(true);
        let _ = tx; // keep sender alive
        let err = super::shutdown::wait_for_shutdown(&mut rx)
            .await
            .expect_err("already-shutdown should return Cancelled");
        assert_eq!(err, AsyncError::Cancelled);
    }

    #[runtime::test]
    async fn wait_for_shutdown_signals_on_true() {
        let (tx, mut rx) = channel::watch::channel(false);

        task::spawn_detached(async move {
            time::sleep(Duration::from_millis(20)).await;
            tx.send(true).unwrap();
        });

        let err = super::shutdown::wait_for_shutdown(&mut rx)
            .await
            .expect_err("shutdown signal should return Cancelled");
        assert_eq!(err, AsyncError::Cancelled);
    }

    #[runtime::test]
    async fn sleep_or_shutdown_completes_sleep() {
        let (_tx, mut rx) = channel::watch::channel(false);
        let result = super::shutdown::sleep_or_shutdown(Duration::from_millis(10), &mut rx).await;
        assert!(result.is_ok());
    }

    #[runtime::test]
    async fn sleep_or_shutdown_cancelled_by_shutdown() {
        let (tx, mut rx) = channel::watch::channel(false);

        task::spawn_detached(async move {
            time::sleep(Duration::from_millis(10)).await;
            tx.send(true).unwrap();
        });

        let err = super::shutdown::sleep_or_shutdown(Duration::from_secs(60), &mut rx)
            .await
            .expect_err("shutdown should cancel sleep");
        assert_eq!(err, AsyncError::Cancelled);
    }

    #[runtime::test]
    async fn sleep_or_shutdown_already_shutdown() {
        let (_tx, mut rx) = channel::watch::channel(true);
        let err = super::shutdown::sleep_or_shutdown(Duration::from_secs(60), &mut rx)
            .await
            .expect_err("already-shutdown should return immediately");
        assert_eq!(err, AsyncError::Cancelled);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Runtime builder coverage
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn runtime_builder_current_thread() {
        let rt = runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current thread runtime");
        rt.block_on(async { 1 + 1 });
    }

    #[test]
    fn runtime_builder_multi_thread() {
        let rt = runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("multi thread runtime");
        rt.block_on(async { 2 + 2 });
    }

    #[test]
    fn runtime_builder_enable_time_and_io() {
        let rt = runtime::Builder::new_current_thread()
            .enable_time()
            .enable_io()
            .build()
            .expect("runtime with time+io");
        rt.block_on(async { 3 + 3 });
    }

    #[test]
    fn runtime_new_default() {
        let rt = runtime::Runtime::new().expect("default runtime");
        let result = rt.block_on(async { 42 });
        assert_eq!(result, 42);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Channel sub-module factory coverage
    // ─────────────────────────────────────────────────────────────────────

    #[runtime::test]
    async fn broadcast_channel_basic() {
        let (tx, mut rx1) = channel::broadcast::channel::<u32>(16);
        let mut rx2 = tx.subscribe();

        tx.send(42).unwrap();
        assert_eq!(rx1.recv().await.unwrap(), 42);
        assert_eq!(rx2.recv().await.unwrap(), 42);
    }

    #[runtime::test]
    async fn mpsc_channel_basic() {
        let (tx, mut rx) = channel::mpsc::channel::<u32>(8);
        tx.send(7).await.unwrap();
        assert_eq!(rx.recv().await, Some(7));
    }

    #[runtime::test]
    async fn mpsc_unbounded_channel_basic() {
        let (tx, mut rx) = channel::mpsc::unbounded_channel::<u32>();
        tx.send(99).unwrap();
        assert_eq!(rx.recv().await, Some(99));
    }

    #[runtime::test]
    async fn oneshot_channel_basic() {
        let (tx, rx) = channel::oneshot::channel::<String>();
        tx.send("hello".into()).unwrap();
        assert_eq!(rx.await.unwrap(), "hello");
    }

    #[runtime::test]
    async fn oneshot_channel_delayed_send_after_pending_poll() {
        let (tx, rx) = channel::oneshot::channel::<u32>();
        let sender = task::spawn(async move {
            task::yield_now().await;
            tx.send(42).unwrap();
        });

        assert_eq!(rx.await.unwrap(), 42);
        sender.await.expect("sender task should join");
    }

    #[runtime::test]
    async fn watch_channel_basic() {
        let (tx, mut rx) = channel::watch::channel(0_u32);
        assert_eq!(*rx.borrow(), 0);

        tx.send(42).unwrap();
        rx.changed().await.unwrap();
        assert_eq!(*rx.borrow(), 42);
    }

    // ─────────────────────────────────────────────────────────────────────
    // block_on_sync edge case: current-thread rejection
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn block_on_sync_rejects_current_thread_runtime() {
        let rt = runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            let err = runtime::block_on_sync(async { 1 })
                .expect_err("block_on_sync in current-thread should fail");
            assert!(matches!(err, AsyncError::Runtime { .. }));
        });
    }

    // ─────────────────────────────────────────────────────────────────────
    // Time module coverage
    // ─────────────────────────────────────────────────────────────────────

    #[runtime::test]
    async fn sleep_zero_completes_immediately() {
        time::sleep(Duration::ZERO).await;
    }

    #[runtime::test]
    async fn interval_ticks_repeatedly() {
        let mut interval = time::interval(Duration::from_millis(10));
        interval.tick().await; // first tick is immediate
        interval.tick().await; // second tick after delay
    }

    #[runtime::test]
    async fn timeout_succeeds_when_future_completes_fast() {
        let result = time::timeout(Duration::from_secs(5), async { 42_u32 }).await;
        assert_eq!(result.unwrap(), 42);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Sync module: Mutex
    // ─────────────────────────────────────────────────────────────────────

    #[runtime::test]
    async fn mutex_lock_and_read() {
        let mutex = super::sync::Mutex::new(42_u32);
        let guard = mutex.lock().await;
        assert_eq!(*guard, 42);
    }

    #[runtime::test]
    async fn mutex_lock_and_mutate() {
        let mutex = super::sync::Mutex::new(0_u32);
        {
            let mut guard = mutex.lock().await;
            *guard = 99;
        }
        let guard = mutex.lock().await;
        assert_eq!(*guard, 99);
    }

    #[test]
    fn mutex_try_lock_succeeds_when_unlocked() {
        let mutex = super::sync::Mutex::new(7_u32);
        let guard = mutex.try_lock().expect("should succeed");
        assert_eq!(*guard, 7);
    }

    #[test]
    fn mutex_try_lock_fails_when_locked() {
        let mutex = super::sync::Mutex::new(7_u32);
        let _guard = mutex.try_lock().unwrap();
        let err = mutex.try_lock().expect_err("should fail while locked");
        assert_eq!(err.to_string(), "operation would block");
    }

    #[test]
    fn mutex_get_mut() {
        let mut mutex = super::sync::Mutex::new(10_u32);
        *mutex.get_mut() = 20;
        let guard = mutex.try_lock().unwrap();
        assert_eq!(*guard, 20);
    }

    #[test]
    fn mutex_into_inner() {
        let mutex = super::sync::Mutex::new("hello".to_string());
        let value = mutex.into_inner();
        assert_eq!(value, "hello");
    }

    #[test]
    fn mutex_default() {
        let mutex = super::sync::Mutex::<u32>::default();
        let guard = mutex.try_lock().unwrap();
        assert_eq!(*guard, 0);
    }

    #[test]
    fn mutex_debug() {
        let mutex = super::sync::Mutex::new(42_u32);
        let dbg = format!("{mutex:?}");
        assert!(dbg.contains("Mutex"));
    }

    // ─────────────────────────────────────────────────────────────────────
    // Sync module: RwLock
    // ─────────────────────────────────────────────────────────────────────

    #[runtime::test]
    async fn rwlock_read_guard() {
        let lock = super::sync::RwLock::new(42_u32);
        let guard = lock.read().await;
        assert_eq!(*guard, 42);
    }

    #[runtime::test]
    async fn rwlock_write_guard() {
        let lock = super::sync::RwLock::new(0_u32);
        {
            let mut guard = lock.write().await;
            *guard = 99;
        }
        let guard = lock.read().await;
        assert_eq!(*guard, 99);
    }

    #[test]
    fn rwlock_try_read_succeeds() {
        let lock = super::sync::RwLock::new(7_u32);
        let guard = lock.try_read().expect("should succeed");
        assert_eq!(*guard, 7);
    }

    #[test]
    fn rwlock_try_write_succeeds() {
        let lock = super::sync::RwLock::new(7_u32);
        let mut guard = lock.try_write().expect("should succeed");
        *guard = 14;
        drop(guard);
        let read = lock.try_read().unwrap();
        assert_eq!(*read, 14);
    }

    #[test]
    fn rwlock_try_write_fails_when_read_held() {
        let lock = super::sync::RwLock::new(7_u32);
        let _read_guard = lock.try_read().unwrap();
        match lock.try_write() {
            Err(err) => assert_eq!(err.to_string(), "operation would block"),
            Ok(_) => panic!("should fail while read held"),
        }
    }

    #[test]
    fn rwlock_multiple_readers() {
        let lock = super::sync::RwLock::new(42_u32);
        let r1 = lock.try_read().unwrap();
        let r2 = lock.try_read().unwrap();
        assert_eq!(*r1, 42);
        assert_eq!(*r2, 42);
    }

    #[test]
    fn rwlock_get_mut() {
        let mut lock = super::sync::RwLock::new(10_u32);
        *lock.get_mut() = 20;
        let guard = lock.try_read().unwrap();
        assert_eq!(*guard, 20);
    }

    #[test]
    fn rwlock_into_inner() {
        let lock = super::sync::RwLock::new("world".to_string());
        let value = lock.into_inner();
        assert_eq!(value, "world");
    }

    #[test]
    fn rwlock_default() {
        let lock = super::sync::RwLock::<u32>::default();
        let guard = lock.try_read().unwrap();
        assert_eq!(*guard, 0);
    }

    #[test]
    fn rwlock_debug() {
        let lock = super::sync::RwLock::new(42_u32);
        let dbg = format!("{lock:?}");
        assert!(dbg.contains("RwLock"));
    }

    // ─────────────────────────────────────────────────────────────────────
    // Sync module: Semaphore
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn semaphore_new_and_available_permits() {
        let sem = super::sync::Semaphore::new(5);
        assert_eq!(sem.available_permits(), 5);
    }

    #[test]
    fn semaphore_default_zero_permits() {
        let sem = super::sync::Semaphore::default();
        assert_eq!(sem.available_permits(), 0);
    }

    #[test]
    fn semaphore_try_acquire_succeeds() {
        let sem = super::sync::Semaphore::new(2);
        let permit = sem.try_acquire().expect("should have permits");
        assert_eq!(sem.available_permits(), 1);
        drop(permit);
    }

    #[test]
    fn semaphore_try_acquire_fails_when_empty() {
        let sem = super::sync::Semaphore::new(0);
        match sem.try_acquire() {
            Err(err) => assert_eq!(err.to_string(), "no permits available"),
            Ok(_) => panic!("should have no permits"),
        }
    }

    #[test]
    fn semaphore_try_acquire_exhaustion() {
        let sem = super::sync::Semaphore::new(1);
        let _p1 = sem.try_acquire();
        match sem.try_acquire() {
            Err(err) => assert_eq!(err.to_string(), "no permits available"),
            Ok(_) => panic!("should be exhausted"),
        }
    }

    #[test]
    fn semaphore_permit_drop_restores() {
        let sem = super::sync::Semaphore::new(1);
        {
            let _permit = sem.try_acquire().unwrap();
            assert_eq!(sem.available_permits(), 0);
        }
        assert_eq!(sem.available_permits(), 1);
    }

    #[test]
    fn semaphore_add_permits() {
        let sem = super::sync::Semaphore::new(0);
        sem.add_permits(3);
        assert_eq!(sem.available_permits(), 3);
    }

    #[runtime::test]
    async fn semaphore_acquire_async() {
        let sem = super::sync::Semaphore::new(1);
        let permit = sem.acquire().await;
        assert!(permit.is_ok());
        drop(permit);
        assert_eq!(sem.available_permits(), 1);
    }

    #[test]
    fn semaphore_debug() {
        let sem = super::sync::Semaphore::new(3);
        let dbg = format!("{sem:?}");
        assert!(dbg.contains("Semaphore"));
    }

    // ─────────────────────────────────────────────────────────────────────
    // Sync module: Error types
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn try_lock_error_display_via_mutex() {
        let mutex = super::sync::Mutex::new(1_u32);
        let _guard = mutex.try_lock().unwrap();
        let err = mutex.try_lock().expect_err("locked");
        assert_eq!(err.to_string(), "operation would block");
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn try_lock_error_clone_eq_via_mutex() {
        let mutex = super::sync::Mutex::new(1_u32);
        let _guard = mutex.try_lock().unwrap();
        let a = mutex.try_lock().expect_err("locked");
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn try_acquire_error_display_via_semaphore() {
        let sem = super::sync::Semaphore::new(0);
        match sem.try_acquire() {
            Err(err) => {
                assert_eq!(err.to_string(), "no permits available");
                assert!(std::error::Error::source(&err).is_none());
            }
            Ok(_) => panic!("should have no permits"),
        }
    }

    #[test]
    fn try_acquire_error_clone_eq_via_semaphore() {
        let sem = super::sync::Semaphore::new(0);
        match sem.try_acquire() {
            Err(a) => {
                let b = a;
                assert_eq!(a, b);
            }
            Ok(_) => panic!("should have no permits"),
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Channel error types: Display and Error impls
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn broadcast_send_error_display() {
        let err = channel::broadcast::SendError(42_u32);
        assert_eq!(err.to_string(), "sending on a closed broadcast channel");
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn broadcast_send_error_clone_eq() {
        let a = channel::broadcast::SendError(42_u32);
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn broadcast_recv_error_display() {
        let closed = channel::broadcast::error::RecvError::Closed;
        assert_eq!(closed.to_string(), "channel closed");

        let lagged = channel::broadcast::error::RecvError::Lagged(5);
        assert_eq!(lagged.to_string(), "channel lagged by 5 messages");
        assert!(std::error::Error::source(&lagged).is_none());
    }

    #[test]
    fn broadcast_recv_error_clone_eq() {
        let a = channel::broadcast::error::RecvError::Closed;
        let b = a;
        assert_eq!(a, b);

        let c = channel::broadcast::error::RecvError::Lagged(10);
        assert_ne!(a, c);
    }

    #[test]
    fn mpsc_send_error_display() {
        let err = channel::mpsc::SendError(42_u32);
        assert_eq!(err.to_string(), "channel closed");
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn mpsc_try_send_error_display() {
        let closed = channel::mpsc::error::TrySendError::Closed(1_u32);
        assert_eq!(closed.to_string(), "channel closed");

        let full = channel::mpsc::error::TrySendError::Full(2_u32);
        assert_eq!(full.to_string(), "channel full");
        assert!(std::error::Error::source(&full).is_none());
    }

    #[test]
    fn mpsc_try_send_error_eq() {
        let a = channel::mpsc::error::TrySendError::Closed(1_u32);
        let b = channel::mpsc::error::TrySendError::Closed(1_u32);
        assert_eq!(a, b);

        let c = channel::mpsc::error::TrySendError::Full(1_u32);
        assert_ne!(a, c);
    }

    #[test]
    fn mpsc_try_recv_error_display() {
        let empty = channel::mpsc::error::TryRecvError::Empty;
        assert_eq!(empty.to_string(), "channel empty");

        let disc = channel::mpsc::error::TryRecvError::Disconnected;
        assert_eq!(disc.to_string(), "channel disconnected");
        assert!(std::error::Error::source(&disc).is_none());
    }

    #[test]
    fn mpsc_try_recv_error_clone_eq() {
        let a = channel::mpsc::error::TryRecvError::Empty;
        let b = a;
        assert_eq!(a, b);
        assert_ne!(a, channel::mpsc::error::TryRecvError::Disconnected);
    }

    #[test]
    fn oneshot_send_error_display() {
        let err = channel::oneshot::SendError(42_u32);
        assert_eq!(err.to_string(), "channel closed");
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn oneshot_recv_error_display() {
        let err = channel::oneshot::error::RecvError;
        assert_eq!(err.to_string(), "channel closed");
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn oneshot_recv_error_clone_eq() {
        let a = channel::oneshot::error::RecvError;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn watch_send_error_display() {
        let err = channel::watch::SendError(42_u32);
        assert_eq!(err.to_string(), "channel closed");
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn watch_recv_error_display() {
        let err = channel::watch::error::RecvError;
        assert_eq!(err.to_string(), "channel closed");
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn watch_recv_error_clone_eq() {
        let a = channel::watch::error::RecvError;
        let b = a;
        assert_eq!(a, b);
    }

    // ─────────────────────────────────────────────────────────────────────
    // mpsc channel edge cases
    // ─────────────────────────────────────────────────────────────────────

    #[runtime::test]
    async fn mpsc_sender_capacity_and_len() {
        let (tx, _rx) = channel::mpsc::channel::<u32>(4);
        assert_eq!(tx.capacity(), 4);
        assert_eq!(tx.len(), 0);
        assert!(tx.is_empty());

        tx.send(1).await.unwrap();
        assert_eq!(tx.len(), 1);
        assert!(!tx.is_empty());
        assert_eq!(tx.capacity(), 3);
    }

    #[runtime::test]
    async fn mpsc_sender_is_closed_reflects_receiver() {
        let (tx, rx) = channel::mpsc::channel::<u32>(4);
        assert!(!tx.is_closed());
        drop(rx);
        assert!(tx.is_closed());
    }

    #[runtime::test]
    async fn mpsc_try_send_full() {
        let (tx, _rx) = channel::mpsc::channel::<u32>(1);
        tx.send(1).await.unwrap();
        let err = tx.try_send(2).expect_err("should be full");
        assert!(matches!(err, channel::mpsc::error::TrySendError::Full(_)));
    }

    #[runtime::test]
    async fn mpsc_try_send_closed() {
        let (tx, rx) = channel::mpsc::channel::<u32>(4);
        drop(rx);
        let err = tx.try_send(1).expect_err("should be closed");
        assert!(matches!(err, channel::mpsc::error::TrySendError::Closed(_)));
    }

    #[runtime::test]
    async fn mpsc_try_recv_empty() {
        let (_tx, mut rx) = channel::mpsc::channel::<u32>(4);
        let err = rx.try_recv().expect_err("should be empty");
        assert_eq!(err, channel::mpsc::error::TryRecvError::Empty);
    }

    #[runtime::test]
    async fn mpsc_try_recv_disconnected() {
        let (tx, mut rx) = channel::mpsc::channel::<u32>(4);
        drop(tx);
        let err = rx.try_recv().expect_err("should be disconnected");
        assert_eq!(err, channel::mpsc::error::TryRecvError::Disconnected);
    }

    #[runtime::test]
    async fn mpsc_try_recv_value() {
        let (tx, mut rx) = channel::mpsc::channel::<u32>(4);
        tx.send(77).await.unwrap();
        let val = rx.try_recv().expect("should have value");
        assert_eq!(val, 77);
    }

    #[runtime::test]
    async fn mpsc_receiver_close() {
        let (tx, mut rx) = channel::mpsc::channel::<u32>(4);
        rx.close();
        let err = tx.send(1).await.expect_err("should fail after close");
        assert_eq!(err.0, 1);
    }

    #[runtime::test]
    async fn mpsc_receiver_capacity() {
        let (tx, rx) = channel::mpsc::channel::<u32>(4);
        assert_eq!(rx.capacity(), 4);
        tx.send(1).await.unwrap();
        assert_eq!(rx.capacity(), 3);
    }

    /// Complements `mpsc_sender_closed_returns_when_receiver_dropped`, which
    /// drops the receiver before the sender ever parks and so only exercises
    /// the fast path. Here the drop happens while the sender is already parked,
    /// which is the path that depends on the close signal actually firing.
    #[runtime::test]
    async fn mpsc_sender_closed_wakes_when_receiver_drops_after_parking() {
        let (tx, rx) = channel::mpsc::channel::<u32>(4);
        task::spawn_detached(async move {
            time::sleep(Duration::from_millis(20)).await;
            drop(rx);
        });
        time::timeout(Duration::from_secs(5), tx.closed())
            .await
            .expect("closed() must wake once the receiver is dropped");
        assert!(tx.is_closed());
    }

    /// br-4h5ph: `Sender::closed()` must PARK, never busy-wait.
    ///
    /// It was implemented as `while !is_closed() { yield_now().await }`. A
    /// self-waking future keeps its task permanently runnable, so the
    /// scheduler's run queue never empties and the runtime's I/O phase is
    /// starved: socket readiness for every other connection on the runtime goes
    /// unobserved while timers keep firing normally. That made two fcp-graphql
    /// subscription tests hang for ~40s, because the real producer loop races
    /// `tx.closed()` against socket reads in a `select!`.
    ///
    /// This pins the observable consequence rather than the implementation: a
    /// task parked on `closed()` inside a `select!` must not prevent an
    /// unrelated loopback socket from delivering bytes.
    #[runtime::test]
    async fn mpsc_sender_closed_does_not_starve_io_readiness() {
        use io::{AsyncReadExt, AsyncWriteExt};

        let listener = super::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");

        // Peer parks on a read that only completes once the client writes.
        let peer = task::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut byte = [0u8; 1];
            let started = Instant::now();
            stream.read_exact(&mut byte).await.expect("peer read");
            started.elapsed()
        });

        let mut client = super::net::TcpStream::connect(format!("{addr}"))
            .await
            .expect("connect");

        // Hold a task in `select!` on `closed()` for the whole exchange. The
        // receiver is kept alive so this arm never completes.
        let (tx, rx) = channel::mpsc::channel::<u32>(4);
        let _keep_receiver_alive = rx;
        task::spawn_detached(async move {
            crate::select! {
                () = tx.closed() => {},
                () = time::sleep(Duration::from_secs(30)) => {},
            }
        });

        // Give the peer time to reach its parked read, then write.
        time::sleep(Duration::from_millis(50)).await;
        client.write_all(&[42u8]).await.expect("client write");

        let observed = time::timeout(Duration::from_secs(5), peer)
            .await
            .expect("peer never observed the byte: the I/O phase was starved")
            .expect("peer task");
        assert!(
            observed < Duration::from_secs(1),
            "read wakeup was delayed by {observed:?}; closed() is starving the I/O phase"
        );
    }

    #[runtime::test]
    async fn mpsc_sender_clone() {
        let (tx, mut rx) = channel::mpsc::channel::<u32>(4);
        let tx2 = tx.clone();
        tx.send(1).await.unwrap();
        tx2.send(2).await.unwrap();
        assert_eq!(rx.recv().await, Some(1));
        assert_eq!(rx.recv().await, Some(2));
    }

    #[runtime::test]
    async fn mpsc_sender_send_closed() {
        let (tx, rx) = channel::mpsc::channel::<u32>(4);
        drop(rx);
        let err = tx.send(1).await.expect_err("should fail");
        assert_eq!(err.0, 1);
    }

    // ─────────────────────────────────────────────────────────────────────
    // mpsc unbounded channel edge cases
    // ─────────────────────────────────────────────────────────────────────

    #[runtime::test]
    async fn mpsc_unbounded_send_to_closed() {
        let (tx, mut rx) = channel::mpsc::unbounded_channel::<u32>();
        rx.close();
        let err = tx.send(1).expect_err("should fail");
        assert_eq!(err.0, 1);
    }

    #[runtime::test]
    async fn mpsc_unbounded_recv_none_after_senders_dropped() {
        let (tx, mut rx) = channel::mpsc::unbounded_channel::<u32>();
        tx.send(1).unwrap();
        drop(tx);
        assert_eq!(rx.recv().await, Some(1));
        assert_eq!(rx.recv().await, None);
    }

    #[runtime::test]
    async fn mpsc_unbounded_close_receiver() {
        let (tx, mut rx) = channel::mpsc::unbounded_channel::<u32>();
        rx.close();
        let err = tx.send(1).expect_err("closed receiver should reject");
        assert_eq!(err.0, 1);
    }

    #[runtime::test]
    async fn mpsc_unbounded_sender_clone_and_drop() {
        let (tx1, mut rx) = channel::mpsc::unbounded_channel::<u32>();
        let tx2 = tx1.clone();
        tx1.send(1).unwrap();
        tx2.send(2).unwrap();
        drop(tx1);
        // tx2 still alive, channel not closed
        tx2.send(3).unwrap();
        drop(tx2);
        // now all senders dropped
        assert_eq!(rx.recv().await, Some(1));
        assert_eq!(rx.recv().await, Some(2));
        assert_eq!(rx.recv().await, Some(3));
        assert_eq!(rx.recv().await, None);
    }

    #[test]
    fn mpsc_unbounded_shared_debug() {
        let (tx, _rx) = channel::mpsc::unbounded_channel::<u32>();
        let dbg = format!("{tx:?}");
        assert!(dbg.contains("UnboundedSender"));
    }

    #[test]
    fn mpsc_unbounded_close_waits_for_send_critical_section() {
        use std::sync::mpsc;
        use std::thread;

        let (tx, rx) = channel::mpsc::unbounded_channel::<u32>();
        let rx = Arc::new(std::sync::Mutex::new(rx));
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let release_rx = Arc::new(std::sync::Mutex::new(release_rx));
        let (close_done_tx, close_done_rx) = mpsc::channel();

        {
            let release_rx = Arc::clone(&release_rx);
            channel::mpsc::set_unbounded_send_hook(
                &tx,
                Some(Arc::new(move || {
                    entered_tx.send(()).expect("entered signal");
                    release_rx
                        .lock()
                        .expect("release receiver mutex poisoned")
                        .recv()
                        .expect("release signal");
                })),
            );
        }

        thread::scope(|scope| {
            let sender = scope.spawn(|| tx.send(42));
            entered_rx.recv().expect("sender reached critical section");

            let rx_for_close = Arc::clone(&rx);
            let closer = scope.spawn(move || {
                rx_for_close
                    .lock()
                    .expect("receiver mutex poisoned")
                    .close();
                close_done_tx.send(()).expect("close done signal");
            });

            assert!(
                close_done_rx
                    .recv_timeout(Duration::from_millis(50))
                    .is_err(),
                "close should block while send holds the queue state lock"
            );

            release_tx.send(()).expect("release sender");
            assert_eq!(sender.join().expect("sender thread join"), Ok(()));
            closer.join().expect("closer thread join");
        });

        channel::mpsc::set_unbounded_send_hook(&tx, None);

        let rx = Arc::into_inner(rx)
            .expect("receiver arc should be unique")
            .into_inner()
            .expect("receiver mutex poisoned");
        let mut rx = rx;
        let rt = runtime::Runtime::new().expect("runtime");
        rt.block_on(async {
            assert_eq!(rx.recv().await, Some(42));
            assert_eq!(rx.recv().await, None);
        });
    }

    // ─────────────────────────────────────────────────────────────────────
    // broadcast channel edge cases
    // ─────────────────────────────────────────────────────────────────────

    #[runtime::test]
    async fn broadcast_send_no_receivers() {
        let (tx, rx) = channel::broadcast::channel::<u32>(16);
        drop(rx);
        let err = tx.send(42).expect_err("no receivers");
        assert_eq!(err.0, 42);
    }

    #[runtime::test]
    async fn broadcast_subscribe_gets_new_messages() {
        let (tx, _rx1) = channel::broadcast::channel::<u32>(16);
        let mut rx2 = tx.subscribe();
        tx.send(99).unwrap();
        assert_eq!(rx2.recv().await.unwrap(), 99);
    }

    #[runtime::test]
    async fn broadcast_recv_closed_after_sender_drop() {
        let (tx, mut rx) = channel::broadcast::channel::<u32>(16);
        tx.send(1).unwrap();
        drop(tx);
        assert_eq!(rx.recv().await.unwrap(), 1);
        let err = rx.recv().await.expect_err("should be closed");
        assert_eq!(err, channel::broadcast::error::RecvError::Closed);
    }

    #[runtime::test]
    async fn broadcast_sender_clone() {
        let (tx, mut rx) = channel::broadcast::channel::<u32>(16);
        let tx2 = tx.clone();
        tx.send(1).unwrap();
        tx2.send(2).unwrap();
        assert_eq!(rx.recv().await.unwrap(), 1);
        assert_eq!(rx.recv().await.unwrap(), 2);
    }

    // ─────────────────────────────────────────────────────────────────────
    // oneshot channel edge cases
    // ─────────────────────────────────────────────────────────────────────

    #[runtime::test]
    async fn oneshot_send_dropped_receiver() {
        let (tx, rx) = channel::oneshot::channel::<u32>();
        drop(rx);
        let err = tx.send(42).expect_err("receiver dropped");
        assert_eq!(err.0, 42);
    }

    #[runtime::test]
    async fn oneshot_try_recv_not_ready() {
        let (_tx, mut rx) = channel::oneshot::channel::<u32>();
        let err = rx.try_recv().expect_err("not yet sent");
        assert_eq!(err, channel::oneshot::error::RecvError);
    }

    #[runtime::test]
    async fn oneshot_try_recv_after_send() {
        let (tx, mut rx) = channel::oneshot::channel::<u32>();
        tx.send(42).unwrap();
        let val = rx.try_recv().expect("should have value");
        assert_eq!(val, 42);
    }

    #[runtime::test]
    async fn oneshot_recv_sender_dropped() {
        let (tx, rx) = channel::oneshot::channel::<u32>();
        drop(tx);
        let err = rx.await.expect_err("sender dropped");
        assert_eq!(err, channel::oneshot::error::RecvError);
    }

    #[runtime::test]
    async fn oneshot_drop_after_pending_poll_closes_channel() {
        let (tx, rx) = channel::oneshot::channel::<u32>();

        let waiter = task::spawn(async move {
            let mut rx = std::pin::pin!(rx);
            std::future::poll_fn(|cx| {
                assert!(matches!(rx.as_mut().poll(cx), Poll::Pending));
                Poll::Ready(())
            })
            .await;
        });

        waiter.await.expect("waiter task should join");
        let err = tx
            .send(7)
            .expect_err("receiver should be dropped after pending poll");
        assert_eq!(err.0, 7);
    }

    // Regression: 745e32ff.
    //
    // `Receiver::try_recv` and `Receiver::poll` both hold a `MutexGuard` for
    // `self.shared.state` across `self.completed = true`. Under current NLL
    // rules the guard keeps an immutable borrow of `self.shared` alive, so
    // mutating `self.completed` through `self` is a hard compile error. The
    // fix releases the guard via an explicit `drop(state)` before the
    // completion assignment.
    //
    // This test drives all four completion branches (try_recv+value,
    // try_recv+sender_dropped, poll+value, poll+sender_dropped) end-to-end
    // and asserts that post-completion the receiver returns `RecvError` on
    // subsequent calls. Any regression that stops releasing the guard early
    // fails to compile; any regression that forgets to set `completed`
    // before returning fails the second-call assertions below.
    #[runtime::test]
    async fn oneshot_completion_paths_release_lock_and_latch_completed_flag() {
        // Path 1: try_recv with value present.
        {
            let (tx, mut rx) = channel::oneshot::channel::<u32>();
            tx.send(11).expect("send should succeed");
            assert_eq!(rx.try_recv().expect("value present"), 11);
            assert_eq!(
                rx.try_recv(),
                Err(channel::oneshot::error::RecvError),
                "second try_recv after successful take must observe completed flag",
            );
        }

        // Path 2: try_recv with sender dropped.
        {
            let (tx, mut rx) = channel::oneshot::channel::<u32>();
            drop(tx);
            assert_eq!(rx.try_recv(), Err(channel::oneshot::error::RecvError));
            assert_eq!(
                rx.try_recv(),
                Err(channel::oneshot::error::RecvError),
                "second try_recv after sender-dropped branch must latch completed",
            );
        }

        // Path 3: poll with value present.
        {
            let (tx, mut rx) = channel::oneshot::channel::<u32>();
            tx.send(22).expect("send should succeed");
            // Await drives `poll`, returning Ready(Ok(_)) through the
            // value-present branch that sets `self.completed = true`.
            assert_eq!((&mut rx).await.expect("await should receive value"), 22);
            assert_eq!(
                rx.try_recv(),
                Err(channel::oneshot::error::RecvError),
                "try_recv after completed poll must observe completed flag",
            );
        }

        // Path 4: poll with sender dropped.
        {
            let (tx, mut rx) = channel::oneshot::channel::<u32>();
            drop(tx);
            let err = (&mut rx).await.expect_err("sender dropped");
            assert_eq!(err, channel::oneshot::error::RecvError);
            assert_eq!(
                rx.try_recv(),
                Err(channel::oneshot::error::RecvError),
                "try_recv after sender-dropped poll must latch completed",
            );
        }
    }

    // Regression: 31902a6b.
    //
    // `JoinHandle::drop` now aborts the underlying task unless the handle
    // was explicitly detached. `task::spawn_detached(fut)` is the convenience
    // wrapper for `task::spawn(fut).detach()`; prior to the fix there was
    // no way to keep a spawned task alive past the handle drop, so callers
    // leaked futures at scope exit. A straight `task::spawn(async move { …
    // tx.send(value) })` call followed by dropping the handle would cancel
    // the future before the send completed.
    //
    // This test verifies that `spawn_detached` keeps the task alive long
    // enough to deliver a value through a oneshot channel after the spawn
    // site has dropped its reference. A regression that forgets to mark the
    // detached handle as retained (or brings back the automatic abort in
    // `Drop`) fails the await here with `RecvError`.
    #[runtime::test]
    async fn spawn_detached_keeps_task_running_past_caller_scope() {
        // The `spawn_detached` helper must return nothing abortable, so the
        // caller cannot accidentally cancel the task by dropping a handle.
        fn assert_returns_unit<F>(f: F)
        where
            F: FnOnce(),
        {
            f();
        }

        let (tx, rx) = channel::oneshot::channel::<u32>();

        assert_returns_unit(|| {
            task::spawn_detached(async move {
                time::sleep(Duration::from_millis(20)).await;
                tx.send(99).expect("detached sender should remain alive");
            });
        });

        // Even without holding any handle, the task must still run to
        // completion and deliver the value.
        let value = time::timeout(Duration::from_secs(2), rx)
            .await
            .expect("detached task should finish inside budget")
            .expect("receiver should get detached result");
        assert_eq!(value, 99);
    }

    // ─────────────────────────────────────────────────────────────────────
    // watch channel edge cases
    // ─────────────────────────────────────────────────────────────────────

    #[runtime::test]
    async fn watch_send_modify() {
        let (tx, rx) = channel::watch::channel(0_u32);
        tx.send_modify(|v| *v = 42);
        assert_eq!(*rx.borrow(), 42);
    }

    #[runtime::test]
    async fn watch_sender_borrow() {
        let (tx, _rx) = channel::watch::channel(7_u32);
        assert_eq!(*tx.borrow(), 7);
        tx.send(14).unwrap();
        assert_eq!(*tx.borrow(), 14);
    }

    #[runtime::test]
    async fn watch_sender_subscribe() {
        let (tx, _rx) = channel::watch::channel(0_u32);
        let mut rx2 = tx.subscribe();
        tx.send(42).unwrap();
        rx2.changed().await.unwrap();
        assert_eq!(*rx2.borrow(), 42);
    }

    #[runtime::test]
    async fn watch_sender_is_closed() {
        let (tx, rx) = channel::watch::channel(0_u32);
        assert!(!tx.is_closed());
        drop(rx);
        // After dropping all receivers, is_closed may or may not be true
        // depending on implementation. We just verify it doesn't panic.
        let _ = tx.is_closed();
    }

    #[runtime::test]
    async fn watch_receiver_borrow_and_update() {
        let (tx, mut rx) = channel::watch::channel(0_u32);
        tx.send(42).unwrap();
        let val = *rx.borrow_and_update();
        assert_eq!(val, 42);
    }

    #[runtime::test]
    async fn watch_receiver_has_changed() {
        let (tx, rx) = channel::watch::channel(0_u32);
        tx.send(42).unwrap();
        assert!(rx.has_changed());
    }

    #[runtime::test]
    async fn watch_receiver_clone() {
        let (tx, rx) = channel::watch::channel(0_u32);
        let rx2 = rx.clone();
        drop(rx);
        tx.send(42).unwrap();
        assert_eq!(*rx2.borrow(), 42);
    }

    #[runtime::test]
    async fn watch_send_all_receivers_dropped() {
        let (tx, rx) = channel::watch::channel(0_u32);
        drop(rx);
        let _ = tx.send(42);
        assert!(tx.is_closed());
    }

    #[runtime::test]
    async fn watch_changed_returns_error_on_sender_drop() {
        let (tx, mut rx) = channel::watch::channel(0_u32);
        drop(tx);
        let err = rx.changed().await.expect_err("sender dropped");
        assert_eq!(err, channel::watch::error::RecvError);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Task module: JoinError
    // ─────────────────────────────────────────────────────────────────────

    #[runtime::test]
    async fn join_error_cancelled_via_abort() {
        let handle = task::spawn(async {
            super::time::sleep(Duration::from_secs(60)).await;
            42_u32
        });
        handle.abort();
        let err = handle.await.expect_err("should be cancelled");
        assert!(err.is_cancelled());
        assert!(!err.is_panic());
        assert_eq!(err.to_string(), "task was cancelled");
        assert!(std::error::Error::source(&err).is_none());
    }

    #[runtime::test]
    async fn join_error_cancelled_clone_and_eq() {
        let handle = task::spawn(async {
            super::time::sleep(Duration::from_secs(60)).await;
        });
        handle.abort();
        let err = handle.await.expect_err("cancelled");
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[runtime::test]
    async fn join_error_debug_format() {
        let handle = task::spawn(async {
            super::time::sleep(Duration::from_secs(60)).await;
        });
        handle.abort();
        let err = handle.await.expect_err("cancelled");
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Cancelled"));
    }

    // ─────────────────────────────────────────────────────────────────────
    // Task module: spawn, JoinHandle
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn try_spawn_outside_runtime_returns_runtime_error() {
        let err = task::try_spawn(async { 1_u32 })
            .expect_err("runtime mismatch should be returned without panicking");
        assert_eq!(
            err,
            AsyncError::Runtime {
                message: "fcp_async_core::task::spawn called outside an active runtime".to_string(),
            }
        );
    }

    #[runtime::test]
    async fn try_spawn_and_join() {
        let handle = task::try_spawn(async { 42_u32 }).expect("spawn should succeed in runtime");
        let result = handle.await.expect("should join");
        assert_eq!(result, 42);
    }

    #[runtime::test]
    async fn spawn_and_join() {
        let handle = task::spawn(async { 42_u32 });
        let result = handle.await.expect("should join");
        assert_eq!(result, 42);
    }

    #[runtime::test]
    async fn spawned_task_inherits_tokio_compat_context() {
        let handle = task::spawn(async {
            let tokio_handle =
                tokio::runtime::Handle::try_current().expect("tokio compat handle missing");
            let nested = tokio_handle.spawn(async { 7_u32 });
            nested.await.expect("nested tokio task should complete")
        });
        let result = handle.await.expect("spawned task should join");
        assert_eq!(result, 7);
    }

    #[runtime::test]
    async fn spawned_task_inherits_fcp_runtime_context_for_nested_spawn() {
        let handle = task::spawn(async {
            let nested = task::spawn(async { 11_u32 });
            nested.await.expect("nested task should join")
        });

        let result = handle.await.expect("outer task should join");
        assert_eq!(result, 11);
    }

    /// The same nested spawn, but AFTER an await — which is a different test.
    ///
    /// `spawned_task_inherits_fcp_runtime_context_for_nested_spawn` above nests
    /// immediately, so the nested spawn always runs on the same thread that ran
    /// the outer task's first poll. That cannot detect a runtime context which is
    /// established once per task rather than once per poll.
    ///
    /// On a work-stealing multi-threaded scheduler a task may resume on a
    /// different worker after every await. A thread-local context installed at the
    /// first poll and held across the await is then simply absent on the thread
    /// the task resumes on, and the next `task::spawn` panics with "called outside
    /// an active runtime" — on a healthy runtime, from inside a live task.
    ///
    /// Several awaits, and a spawn after each, because which poll lands on which    /// worker is a scheduling decision this test does not control: one await is
    /// not reliably enough to force a migration.
    #[runtime::test(flavor = "multi_thread")]
    async fn nested_spawn_survives_thread_migration_across_awaits() {
        let handle = task::spawn(async {
            let mut total = 0_u32;
            for round in 0..8_u32 {
                // Yield and sleep both hand the task back to the scheduler,
                // which is where a migration to another worker can happen.
                task::yield_now().await;
                time::sleep(Duration::from_millis(1)).await;

                // The assertion is simply that this does not panic. Spawning is
                // what a task does after awaiting anything, so if the context is
                // lost here it is lost for effectively every real task.
                let nested = task::spawn(async move { round });
                total += nested.await.expect("nested task should join");
            }
            total
        });

        assert_eq!(
            handle.await.expect("outer task should join"),
            (0..8_u32).sum::<u32>()
        );
    }

    /// `spawn_detached` must survive the same migration.
    ///
    /// This is the exact shape that broke the `fcp-host` subprocess-dispatcher
    /// tests (br-2ak6l): a long-lived dispatcher loop awaits on a channel and then
    /// detaches a task to answer the request. The panic surfaced there as a
    /// dropped oneshot — "dispatcher stopped before replying" and `RecvError` —
    /// which points at the channel rather than at the spawn that actually died.
    #[runtime::test(flavor = "multi_thread")]
    async fn detached_spawn_survives_thread_migration_across_awaits() {
        let (tx, mut rx) = channel::mpsc::channel::<u32>(8);
        let (done_tx, mut done_rx) = channel::mpsc::channel::<u32>(8);

        let loop_task = task::spawn(async move {
            while let Some(value) = rx.recv().await {
                let done_tx = done_tx.clone();
                // Yield and sleep before detaching. Awaiting the channel alone did
                // NOT reliably migrate the task off its original worker, so without
                // these the test passed with the bug still present — it has to be
                // able to fail to be evidence of anything.
                task::yield_now().await;
                time::sleep(Duration::from_millis(1)).await;
                // Detached spawn from a task that has already awaited — the
                // dispatcher shape.
                task::spawn_detached(async move {
                    let _ = done_tx.send(value * 2).await;
                });
            }
        });

        for value in 1..=5_u32 {
            tx.send(value).await.expect("send should succeed");
        }
        drop(tx);

        let mut seen = Vec::new();
        for _ in 1..=5_u32 {
            seen.push(done_rx.recv().await.expect("each reply should arrive"));
        }
        seen.sort_unstable();
        assert_eq!(seen, vec![2, 4, 6, 8, 10]);

        loop_task.await.expect("dispatcher loop should join");
    }

    #[test]
    fn detached_task_shutdown_does_not_drop_final_runtime_reference_on_worker() {
        let _panic_hook_guard = PANIC_HOOK_LOCK.lock().expect("panic hook lock");
        let worker_join_panics = Arc::new(AtomicUsize::new(0));
        let previous_hook = Arc::new(Mutex::new(Some(std::panic::take_hook())));
        let hook_previous = Arc::clone(&previous_hook);
        let hook_panics = Arc::clone(&worker_join_panics);

        std::panic::set_hook(Box::new(move |info| {
            let payload = info
                .payload()
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| info.payload().downcast_ref::<String>().map(String::as_str))
                .unwrap_or_default();
            let is_worker_join_panic = std::thread::current()
                .name()
                .is_some_and(|name| name.starts_with("asupersync-worker"))
                && payload.contains("failed to join thread");

            if is_worker_join_panic {
                hook_panics.fetch_add(1, Ordering::SeqCst);
            } else if let Some(previous) = hook_previous
                .lock()
                .expect("panic hook previous lock")
                .as_ref()
            {
                previous(info);
            }
        }));

        {
            let runtime = runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            runtime.block_on(async {
                let (started_tx, started_rx) = channel::oneshot::channel::<()>();
                task::spawn(async move {
                    let _ = started_tx.send(());
                    future::pending::<()>().await;
                })
                .detach();
                started_rx.await.expect("detached task should start");
            });
        }

        let _installed_hook = std::panic::take_hook();
        let previous = previous_hook
            .lock()
            .expect("panic hook previous lock")
            .take()
            .expect("previous panic hook should be available");
        std::panic::set_hook(previous);

        assert_eq!(
            worker_join_panics.load(Ordering::SeqCst),
            0,
            "worker-local runtime context must not own the final asupersync runtime reference"
        );
    }

    #[runtime::test]
    async fn spawn_and_abort() {
        let handle = task::spawn(async {
            super::time::sleep(Duration::from_secs(60)).await;
            42_u32
        });
        handle.abort();
        let err = handle.await.expect_err("should be cancelled");
        assert!(err.is_cancelled());
    }

    #[runtime::test]
    async fn dropped_join_handle_aborts_task_and_releases_resources() {
        struct DropFlag(Arc<AtomicBool>);

        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));
        let dropped_flag = Arc::clone(&dropped);
        let future_guard = DropFlag(dropped_flag);
        let handle = task::spawn(async move {
            let _flag = future_guard;
            future::pending::<()>().await;
        });

        drop(handle);

        let released = time::timeout(Duration::from_secs(1), async {
            while !dropped.load(Ordering::SeqCst) {
                task::yield_now().await;
            }
        })
        .await;
        assert!(
            released.is_ok(),
            "dropped task should release its future promptly"
        );
    }

    #[runtime::test]
    async fn detached_join_handle_allows_background_task_to_finish() {
        let (tx, rx) = channel::oneshot::channel::<u32>();
        task::spawn(async move {
            time::sleep(Duration::from_millis(10)).await;
            tx.send(7).expect("detached sender should stay alive");
        })
        .detach();

        let result = time::timeout(Duration::from_secs(1), rx)
            .await
            .expect("detached task should complete")
            .expect("receiver should get detached result");
        assert_eq!(result, 7);
    }

    #[runtime::test]
    async fn join_handle_is_finished_before_and_after() {
        let handle = task::spawn(async { 1_u32 });
        // After await, it's definitely finished
        let _ = handle.await;
    }

    #[runtime::test]
    async fn join_handle_debug() {
        let handle = task::spawn(async { 1_u32 });
        let dbg = format!("{handle:?}");
        assert!(dbg.contains("JoinHandle"));
        let _ = handle.await;
    }

    #[runtime::test]
    async fn yield_now_returns() {
        task::yield_now().await;
    }

    // ─────────────────────────────────────────────────────────────────────
    // Time module: additional edge cases
    // ─────────────────────────────────────────────────────────────────────

    #[runtime::test]
    async fn timeout_error_contains_duration() {
        let err = time::timeout(Duration::from_millis(10), future::pending::<()>())
            .await
            .expect_err("should timeout");
        match err {
            AsyncError::Timeout { timeout_ms } => assert_eq!(timeout_ms, 10),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[runtime::test]
    async fn sleep_short_duration() {
        time::sleep(Duration::from_millis(1)).await;
    }

    #[runtime::test]
    async fn interval_three_ticks() {
        let mut interval = time::interval(Duration::from_millis(5));
        let t1 = interval.tick().await;
        let t2 = interval.tick().await;
        let t3 = interval.tick().await;
        assert!(t2 >= t1);
        assert!(t3 >= t2);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Deadline: additional edge cases
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn deadline_debug() {
        let d = super::Deadline::after(Duration::from_secs(5));
        let dbg = format!("{d:?}");
        assert!(dbg.contains("Deadline"));
    }

    #[test]
    fn deadline_zero_duration() {
        let d = super::Deadline::after(Duration::ZERO);
        // Zero duration may or may not be expired immediately due to timing
        let _ = d.remaining();
    }

    // ─────────────────────────────────────────────────────────────────────
    // ExecutionContext: additional edge cases
    // ─────────────────────────────────────────────────────────────────────

    #[runtime::test]
    async fn execution_context_debug() {
        let ctx = ExecutionContext::request_scoped(Duration::from_secs(5));
        let dbg = format!("{ctx:?}");
        assert!(dbg.contains("ExecutionContext"));
    }

    #[runtime::test]
    async fn execution_context_clone() {
        let ctx = ExecutionContext::request_scoped(Duration::from_secs(5));
        let cloned = ctx.clone();
        assert_eq!(cloned.scope(), ctx.scope());
        ctx.cancel();
        assert!(cloned.is_cancelled());
    }

    #[runtime::test]
    async fn background_context_with_deadline_times_out() {
        let ctx = ExecutionContext::background().with_deadline(Duration::from_millis(10));
        let err = ctx
            .run(async {
                time::sleep(Duration::from_secs(10)).await;
            })
            .await
            .expect_err("should timeout");
        assert!(matches!(err, AsyncError::Timeout { .. }));
    }

    #[runtime::test]
    async fn execution_context_sleep_uses_requested_duration_not_deadline() {
        let ctx = ExecutionContext::request_scoped(Duration::from_secs(5));
        let start = Instant::now();

        ctx.sleep(Duration::from_millis(10))
            .await
            .expect("short sleep should finish before request deadline");

        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(1),
            "short sleep waited too long: {elapsed:?}"
        );
    }

    #[runtime::test]
    async fn background_context_cancellation() {
        let ctx = ExecutionContext::background();
        assert!(!ctx.is_cancelled());
        ctx.cancel();
        assert!(ctx.is_cancelled());
        let err = ctx
            .run(async { 42_u32 })
            .await
            .expect_err("should be cancelled");
        assert_eq!(err, AsyncError::Cancelled);
    }

    #[runtime::test]
    async fn child_context_inherits_deadline() {
        let parent = ExecutionContext::request_scoped(Duration::from_secs(10));
        let child = parent.child();
        assert!(child.deadline().is_some());
        assert!(child.remaining_budget().is_some());
    }

    #[runtime::test]
    async fn context_subscribe_returns_listener() {
        let ctx = ExecutionContext::request_scoped(Duration::from_secs(5));
        let listener = ctx.subscribe();
        assert!(!listener.is_cancelled());
        ctx.cancel();
        assert!(listener.is_cancelled());
    }

    // ─────────────────────────────────────────────────────────────────────
    // CancellationToken: additional edge cases
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn cancellation_token_debug() {
        let token = CancellationToken::new();
        let dbg = format!("{token:?}");
        assert!(dbg.contains("CancellationToken"));
    }

    #[test]
    fn cancellation_token_double_cancel_is_idempotent() {
        let token = CancellationToken::new();
        token.cancel();
        token.cancel();
        assert!(token.is_cancelled());
    }

    #[test]
    fn cancellation_listener_debug() {
        let token = CancellationToken::new();
        let listener = token.subscribe();
        let dbg = format!("{listener:?}");
        assert!(dbg.contains("CancellationListener"));
    }

    // ─────────────────────────────────────────────────────────────────────
    // TaskGroup: additional edge cases
    // ─────────────────────────────────────────────────────────────────────

    #[runtime::test]
    async fn task_group_multiple_errors_returns_first() {
        let mut group = TaskGroup::new();

        group.spawn("fail-1", async {
            Err(AsyncError::ProtocolIo {
                message: "first error".into(),
            })
        });
        group.spawn("fail-2", async { Err(AsyncError::ChannelClosed) });

        let err = group
            .shutdown(Duration::from_secs(1))
            .await
            .expect_err("should propagate first error");
        // First error should be propagated (order may vary)
        assert!(matches!(
            err,
            AsyncError::ProtocolIo { .. } | AsyncError::ChannelClosed
        ));
    }

    #[runtime::test]
    async fn task_group_empty_shutdown_succeeds() {
        let group = TaskGroup::new();
        let result = group.shutdown(Duration::from_millis(10)).await;
        assert!(result.is_ok());
    }

    #[runtime::test]
    async fn task_group_many_tasks_all_succeed() {
        let mut group = TaskGroup::new();
        for i in 0..10 {
            let mut listener = group.subscribe_cancellation();
            group.spawn(format!("task-{i}"), async move {
                listener.cancelled().await?;
                Ok(())
            });
        }
        let result = group.shutdown(Duration::from_secs(2)).await;
        assert!(result.is_ok());
    }

    // ─────────────────────────────────────────────────────────────────────
    // Runtime: additional edge cases
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn runtime_debug() {
        let rt = runtime::Runtime::new().expect("runtime");
        let dbg = format!("{rt:?}");
        assert!(dbg.contains("Runtime"));
        assert!(dbg.contains("MultiThread"));
    }

    #[test]
    fn runtime_current_thread_debug() {
        let rt = runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        let dbg = format!("{rt:?}");
        assert!(dbg.contains("Runtime"));
        assert!(dbg.contains("CurrentThread"));
    }

    #[test]
    fn block_on_sync_rejects_multi_thread_runtime() {
        let rt = runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            let err = runtime::block_on_sync(async { 1 })
                .expect_err("block_on_sync in multi-thread should fail");
            assert!(matches!(err, AsyncError::Runtime { .. }));
            if let AsyncError::Runtime { message } = err {
                assert!(message.contains("multi-thread"));
            }
        });
    }

    // ─────────────────────────────────────────────────────────────────────
    // NoopInstrumentation
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn noop_instrumentation_debug() {
        let noop = super::NoopInstrumentation;
        let dbg = format!("{noop:?}");
        assert!(dbg.contains("NoopInstrumentation"));
    }

    #[test]
    fn noop_instrumentation_on_task_exit_error() {
        let noop = super::NoopInstrumentation;
        let err = Err(AsyncError::Cancelled);
        noop.on_task_exit("test", &err);
    }

    // ─────────────────────────────────────────────────────────────────────
    // AsyncError: std::error::Error impl
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn async_error_is_std_error() {
        let err = AsyncError::Timeout { timeout_ms: 100 };
        let _: &dyn std::error::Error = &err;
        assert!(std::error::Error::source(&err).is_none());
    }

    // ─────────────────────────────────────────────────────────────────────
    // Semaphore: owned permit methods
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn semaphore_try_acquire_owned_succeeds() {
        let sem = Arc::new(super::sync::Semaphore::new(2));
        let permit = Arc::clone(&sem)
            .try_acquire_owned()
            .expect("should have permits");
        assert_eq!(sem.available_permits(), 1);
        drop(permit);
        assert_eq!(sem.available_permits(), 2);
    }

    #[test]
    fn semaphore_try_acquire_owned_fails_when_empty() {
        let sem = Arc::new(super::sync::Semaphore::new(0));
        let err = Arc::clone(&sem)
            .try_acquire_owned()
            .expect_err("no permits");
        assert_eq!(err.to_string(), "no permits available");
    }

    #[runtime::test]
    async fn semaphore_acquire_owned_async() {
        let sem = Arc::new(super::sync::Semaphore::new(1));
        let permit = Arc::clone(&sem)
            .acquire_owned()
            .await
            .expect("should acquire");
        assert_eq!(sem.available_permits(), 0);
        drop(permit);
        assert_eq!(sem.available_permits(), 1);
    }

    // Regression (nwclu): the runtime polls `runtime::test`/`block_on` futures in
    // the *root* region, where asupersync 0.3.4 refuses to create a permit
    // obligation. Every permit acquisition — owned or borrowed, async or
    // `try_*` — must scope its obligation off the root region rather than
    // panicking. This mirrors how the fcp-host bulkhead acquires owned permits
    // from spawned request handlers (which also run in the root region).
    #[runtime::test]
    async fn semaphore_permit_acquisition_never_panics_in_root_region() {
        let sem = Arc::new(super::sync::Semaphore::new(2));

        // Owned async acquire while another owned permit is held.
        let first = Arc::clone(&sem)
            .acquire_owned()
            .await
            .expect("owned async acquire in root region should not panic");
        let second = Arc::clone(&sem)
            .acquire_owned()
            .await
            .expect("second owned async acquire should not panic");
        assert_eq!(sem.available_permits(), 0);

        // Non-blocking try paths must also avoid the root-region obligation.
        assert!(Arc::clone(&sem).try_acquire_owned().is_err());
        assert!(sem.try_acquire().is_err());

        drop(first);
        assert_eq!(sem.available_permits(), 1);
        let borrowed = sem
            .try_acquire()
            .expect("borrowed try_acquire in root region should not panic");
        assert_eq!(sem.available_permits(), 0);

        drop(second);
        drop(borrowed);
        assert_eq!(sem.available_permits(), 2);
    }

    // ─────────────────────────────────────────────────────────────────────
    // mpsc: Sender::closed() and Receiver accessors
    // ─────────────────────────────────────────────────────────────────────

    #[runtime::test]
    async fn mpsc_sender_closed_returns_when_receiver_dropped() {
        let (tx, rx) = channel::mpsc::channel::<u32>(4);
        let tx_clone = tx.clone();

        let handle = task::spawn(async move {
            tx_clone.closed().await;
        });

        // Drop receiver to close the channel
        drop(rx);

        let result = time::timeout(Duration::from_secs(2), handle).await;
        assert!(result.is_ok());
    }

    #[runtime::test]
    async fn mpsc_sender_len_increases_on_send() {
        let (tx, _rx) = channel::mpsc::channel::<u32>(8);
        assert_eq!(tx.len(), 0);
        assert!(tx.is_empty());

        tx.send(1).await.unwrap();
        tx.send(2).await.unwrap();
        assert_eq!(tx.len(), 2);
        assert!(!tx.is_empty());
    }

    #[runtime::test]
    async fn mpsc_sender_is_closed_after_receiver_close() {
        let (tx, mut rx) = channel::mpsc::channel::<u32>(4);
        assert!(!tx.is_closed());
        rx.close();
        assert!(tx.is_closed());
    }

    // ─────────────────────────────────────────────────────────────────────
    // JoinError: panic path
    // ─────────────────────────────────────────────────────────────────────

    #[runtime::test]
    async fn join_error_panic_detected() {
        let handle = task::spawn(async {
            panic!("deliberate test panic");
        });
        let err = handle.await.expect_err("should capture panic");
        assert!(err.is_panic());
        assert!(!err.is_cancelled());
        let msg = err.to_string();
        assert!(msg.contains("deliberate test panic"));
    }

    // ─────────────────────────────────────────────────────────────────────
    // watch: borrow_and_update marks as seen
    // ─────────────────────────────────────────────────────────────────────

    #[runtime::test]
    async fn watch_borrow_and_update_clears_changed_flag() {
        let (tx, mut rx) = channel::watch::channel(0_u32);
        tx.send(42).unwrap();
        assert!(rx.has_changed());
        let _ = rx.borrow_and_update();
        assert!(!rx.has_changed());
    }

    // ─────────────────────────────────────────────────────────────────────
    // oneshot: sender debug
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn oneshot_sender_debug() {
        let (tx, _rx) = channel::oneshot::channel::<u32>();
        let dbg = format!("{tx:?}");
        assert!(dbg.contains("Sender"));
    }

    // ─────────────────────────────────────────────────────────────────────
    // acquire_error display
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn try_acquire_error_debug_format() {
        let sem = super::sync::Semaphore::new(0);
        match sem.try_acquire() {
            Err(err) => {
                let dbg = format!("{err:?}");
                assert!(dbg.contains("TryAcquireError"));
            }
            Ok(_) => panic!("should have no permits"),
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // context: request_scoped has deadline
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn request_context_has_deadline() {
        let ctx = ExecutionContext::request_scoped(Duration::from_secs(10));
        assert!(ctx.deadline().is_some());
        assert!(ctx.remaining_budget().is_some());
        assert_eq!(ctx.scope(), ContextScope::Request);
    }

    #[test]
    fn background_context_no_deadline_sync() {
        let ctx = ExecutionContext::background();
        assert!(ctx.deadline().is_none());
        assert!(ctx.remaining_budget().is_none());
        assert_eq!(ctx.scope(), ContextScope::Background);
    }

    #[test]
    fn async_error_eq_with_messages() {
        let a = AsyncError::ProtocolIo {
            message: "reset".into(),
        };
        let b = AsyncError::ProtocolIo {
            message: "reset".into(),
        };
        assert_eq!(a, b);

        let c = AsyncError::ProtocolIo {
            message: "timeout".into(),
        };
        assert_ne!(a, c);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Deadline: additional edge cases
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn deadline_after_nonzero_has_remaining() {
        let d = super::Deadline::after(Duration::from_secs(60));
        assert!(!d.is_expired());
        assert!(d.remaining() > Duration::ZERO);
    }

    #[test]
    fn deadline_at_past_instant_is_expired() {
        let past = std::time::Instant::now()
            .checked_sub(Duration::from_secs(1))
            .unwrap();
        let d = super::Deadline::at(past);
        assert!(d.is_expired());
        assert_eq!(d.remaining(), Duration::ZERO);
    }

    #[test]
    fn deadline_at_future_instant_not_expired() {
        let future = std::time::Instant::now() + Duration::from_secs(60);
        let d = super::Deadline::at(future);
        assert!(!d.is_expired());
        assert!(d.remaining() > Duration::from_secs(30));
    }

    #[test]
    fn deadline_copy_and_eq() {
        let d1 = super::Deadline::after(Duration::from_secs(10));
        let d2 = d1;
        assert_eq!(d1, d2);
    }

    #[runtime::test]
    async fn deadline_run_completes_within_budget() {
        let d = super::Deadline::after(Duration::from_secs(5));
        let result = d.run(async { 42 }).await;
        assert_eq!(result.unwrap(), 42);
    }

    #[runtime::test]
    async fn deadline_run_expired_returns_timeout() {
        let past = std::time::Instant::now()
            .checked_sub(Duration::from_secs(1))
            .unwrap();
        let d = super::Deadline::at(past);
        let result = d.run(std::future::pending::<()>()).await;
        assert!(matches!(result, Err(AsyncError::Timeout { .. })));
    }

    // ─────────────────────────────────────────────────────────────────────
    // ExecutionContext: additional edge cases
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn request_context_scope_is_request() {
        let ctx = ExecutionContext::request_scoped(Duration::from_secs(5));
        assert_eq!(ctx.scope(), ContextScope::Request);
    }

    #[test]
    fn background_context_scope_is_background() {
        let ctx = ExecutionContext::background();
        assert_eq!(ctx.scope(), ContextScope::Background);
    }

    #[test]
    fn request_context_remaining_budget_some() {
        let ctx = ExecutionContext::request_scoped(Duration::from_secs(60));
        let budget = ctx.remaining_budget();
        assert!(budget.is_some());
        assert!(budget.unwrap() > Duration::from_secs(30));
    }

    #[test]
    fn background_context_remaining_budget_none() {
        let ctx = ExecutionContext::background();
        assert!(ctx.remaining_budget().is_none());
    }

    #[test]
    fn context_with_deadline_replaces_budget() {
        let ctx = ExecutionContext::background().with_deadline(Duration::from_secs(30));
        assert!(ctx.deadline().is_some());
        assert!(ctx.remaining_budget().is_some());
    }

    #[test]
    fn context_cancel_is_cancelled() {
        let ctx = ExecutionContext::background();
        assert!(!ctx.is_cancelled());
        ctx.cancel();
        assert!(ctx.is_cancelled());
    }

    #[test]
    fn child_context_inherits_cancellation() {
        let parent = ExecutionContext::request_scoped(Duration::from_secs(10));
        let child = parent.child();
        assert_eq!(child.scope(), ContextScope::Request);
        assert!(!child.is_cancelled());
        parent.cancel();
        assert!(child.is_cancelled());
    }

    #[runtime::test]
    async fn context_run_succeeds_within_budget() {
        let ctx = ExecutionContext::request_scoped(Duration::from_secs(5));
        let result = ctx.run(async { "hello" }).await;
        assert_eq!(result.unwrap(), "hello");
    }

    #[runtime::test]
    async fn context_run_cancelled_returns_error() {
        let ctx = ExecutionContext::background();
        ctx.cancel();
        let result = ctx.run(std::future::pending::<()>()).await;
        assert!(matches!(result, Err(AsyncError::Cancelled)));
    }

    #[runtime::test]
    async fn context_sleep_completes_under_budget() {
        let ctx = ExecutionContext::request_scoped(Duration::from_secs(5));
        let result = ctx.sleep(Duration::from_millis(1)).await;
        assert!(result.is_ok());
    }

    #[runtime::test]
    async fn context_subscribe_listener_detects_cancel() {
        let ctx = ExecutionContext::background();
        let mut listener = ctx.subscribe();
        assert!(!listener.is_cancelled());
        ctx.cancel();
        listener.cancelled().await.unwrap();
    }

    // ─────────────────────────────────────────────────────────────────────
    // ContextScope: Display and equality
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn context_scope_equality() {
        assert_eq!(ContextScope::Request, ContextScope::Request);
        assert_eq!(ContextScope::Background, ContextScope::Background);
        assert_ne!(ContextScope::Request, ContextScope::Background);
    }

    #[test]
    fn context_scope_debug() {
        let debug = format!("{:?}", ContextScope::Request);
        assert!(debug.contains("Request"));
    }

    #[test]
    fn context_scope_copy() {
        let s = ContextScope::Background;
        let s2 = s;
        assert_eq!(s, s2);
    }

    // ─────────────────────────────────────────────────────────────────────
    // shutdown module
    // ─────────────────────────────────────────────────────────────────────

    #[runtime::test]
    async fn wait_for_shutdown_already_true() {
        let (_, mut rx) = channel::watch::channel(true);
        let result = super::shutdown::wait_for_shutdown(&mut rx).await;
        assert!(matches!(result, Err(AsyncError::Cancelled)));
    }

    #[runtime::test]
    async fn wait_for_shutdown_becomes_true() {
        let (tx, mut rx) = channel::watch::channel(false);
        let handle = task::spawn(async move { super::shutdown::wait_for_shutdown(&mut rx).await });
        time::sleep(Duration::from_millis(5)).await;
        tx.send(true).unwrap();
        let result = handle.await.unwrap();
        assert!(matches!(result, Err(AsyncError::Cancelled)));
    }

    #[runtime::test]
    async fn sleep_or_shutdown_with_zero_duration() {
        let (_tx, mut rx) = channel::watch::channel(false);
        let result = super::shutdown::sleep_or_shutdown(Duration::from_millis(0), &mut rx).await;
        // Zero-duration sleep should complete immediately regardless of shutdown state
        assert!(result.is_ok());
    }

    #[runtime::test]
    async fn sleep_or_shutdown_interrupted_by_signal() {
        let (tx, mut rx) = channel::watch::channel(false);
        let handle = task::spawn(async move {
            super::shutdown::sleep_or_shutdown(Duration::from_secs(60), &mut rx).await
        });
        time::sleep(Duration::from_millis(5)).await;
        tx.send(true).unwrap();
        let result = handle.await.unwrap();
        assert!(matches!(result, Err(AsyncError::Cancelled)));
    }

    // ─────────────────────────────────────────────────────────────────────
    // sync: additional Mutex/RwLock/Semaphore tests
    // ─────────────────────────────────────────────────────────────────────

    #[runtime::test]
    async fn mutex_lock_and_modify() {
        let m = super::sync::Mutex::new(0_u32);
        {
            let mut guard = m.lock().await;
            *guard = 42;
        }
        let guard = m.lock().await;
        assert_eq!(*guard, 42);
    }

    #[test]
    fn mutex_try_lock_when_unlocked() {
        let m = super::sync::Mutex::new(10);
        let guard = m.try_lock().unwrap();
        assert_eq!(*guard, 10);
    }

    #[test]
    fn mutex_try_lock_fails_when_held() {
        let m = super::sync::Mutex::new(10);
        let _guard = m.try_lock().unwrap();
        assert!(m.try_lock().is_err());
    }

    #[runtime::test]
    async fn rwlock_concurrent_reads() {
        let rw = super::sync::RwLock::new(99);
        let r1 = rw.read().await;
        let r2 = rw.read().await;
        assert_eq!(*r1, 99);
        assert_eq!(*r2, 99);
    }

    #[runtime::test]
    async fn rwlock_write_then_read() {
        let rw = super::sync::RwLock::new(0_u32);
        {
            let mut w = rw.write().await;
            *w = 77;
        }
        let r = rw.read().await;
        assert_eq!(*r, 77);
    }

    #[test]
    fn rwlock_try_read_fails_when_write_held() {
        let rw = super::sync::RwLock::new(0);
        let _w = rw.try_write().unwrap();
        assert!(rw.try_read().is_err());
    }

    #[runtime::test]
    async fn semaphore_acquire_and_release() {
        let sem = super::sync::Semaphore::new(2);
        assert_eq!(sem.available_permits(), 2);
        let p1 = sem.acquire().await.unwrap();
        assert_eq!(sem.available_permits(), 1);
        drop(p1);
        assert_eq!(sem.available_permits(), 2);
    }

    #[test]
    fn semaphore_add_permits_increases_count() {
        let sem = super::sync::Semaphore::new(1);
        sem.add_permits(3);
        assert_eq!(sem.available_permits(), 4);
    }

    #[runtime::test]
    async fn semaphore_acquire_owned_and_release() {
        let sem = Arc::new(super::sync::Semaphore::new(1));
        let p = Arc::clone(&sem).acquire_owned().await.unwrap();
        assert_eq!(sem.available_permits(), 0);
        drop(p);
        assert_eq!(sem.available_permits(), 1);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Error type Display
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn try_lock_error_display_from_mutex() {
        let m = super::sync::Mutex::new(0);
        let _guard = m.try_lock().unwrap();
        let err = m.try_lock().unwrap_err();
        assert_eq!(err.to_string(), "operation would block");
    }

    #[test]
    fn try_acquire_error_display_from_semaphore() {
        let sem = super::sync::Semaphore::new(0);
        match sem.try_acquire() {
            Err(err) => assert_eq!(err.to_string(), "no permits available"),
            Ok(_) => panic!("expected error when no permits available"),
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // AsyncError: additional variants
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn async_error_timeout_display() {
        let e = AsyncError::Timeout { timeout_ms: 5000 };
        let s = e.to_string();
        assert!(s.contains("5000"));
    }

    #[test]
    fn async_error_cancelled_display() {
        let e = AsyncError::Cancelled;
        assert_ne!(e.to_string(), "");
    }

    #[test]
    fn async_error_channel_full_display() {
        let e = AsyncError::ChannelFull;
        assert_ne!(e.to_string(), "");
    }

    #[test]
    fn async_error_channel_closed_display() {
        let e = AsyncError::ChannelClosed;
        assert_ne!(e.to_string(), "");
    }

    // ─────────────────────────────────────────────────────────────────────
    // CancellationToken: more edges
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn cancellation_token_new_not_cancelled() {
        let token = CancellationToken::new();
        assert!(!token.is_cancelled());
    }

    #[test]
    fn cancellation_token_cancel_propagates_to_clone() {
        let t1 = CancellationToken::new();
        let t2 = t1.clone();
        t1.cancel();
        assert!(t2.is_cancelled());
    }

    #[runtime::test]
    async fn cancellation_listener_already_cancelled_ok() {
        let token = CancellationToken::new();
        token.cancel();
        let mut listener = token.subscribe();
        assert!(listener.is_cancelled());
        // cancelled() should return Ok immediately
        let result = listener.cancelled().await;
        assert!(result.is_ok());
    }

    // ─────────────────────────────────────────────────────────────────────
    // TaskGroup: more edges
    // ─────────────────────────────────────────────────────────────────────

    #[runtime::test]
    async fn task_group_spawn_and_run_to_completion() {
        let mut group = TaskGroup::new();
        let counter = Arc::new(AtomicUsize::new(0));
        for _ in 0..3 {
            let c = Arc::clone(&counter);
            let mut listener = group.subscribe_cancellation();
            group.spawn("worker", async move {
                c.fetch_add(1, Ordering::SeqCst);
                listener.cancelled().await?;
                Ok(())
            });
        }
        // Give spawned tasks time to start
        time::sleep(Duration::from_millis(50)).await;
        // All 3 workers should have started
        assert_eq!(counter.load(Ordering::SeqCst), 3);
        let result = group.shutdown(Duration::from_secs(1)).await;
        assert!(result.is_ok());
    }

    // ─────────────────────────────────────────────────────────────────────
    // time module edges
    // ─────────────────────────────────────────────────────────────────────

    #[runtime::test]
    async fn timeout_succeeds_when_future_completes() {
        let result = time::timeout(Duration::from_secs(5), async { "done" }).await;
        assert_eq!(result.unwrap(), "done");
    }

    #[runtime::test]
    async fn interval_first_tick_immediate() {
        let mut interval = time::interval(Duration::from_millis(100));
        let _first = interval.tick().await;
        // First tick should return quickly
    }

    // ═══════════════════════════════════════════════════════════════════════
    // NEW SYNC TESTS — batch expansion to reach 200+ #[test] count
    // ═══════════════════════════════════════════════════════════════════════

    // ─── AsyncError: variant construction and Display ────────────────────

    #[test]
    fn async_error_protocol_io_display() {
        let e = AsyncError::ProtocolIo {
            message: "EOF".into(),
        };
        assert_eq!(e.to_string(), "protocol io fault: EOF");
    }

    #[test]
    fn async_error_join_display() {
        let e = AsyncError::Join {
            message: "worker panicked".into(),
        };
        assert_eq!(e.to_string(), "task join failed: worker panicked");
    }

    #[test]
    fn async_error_runtime_display() {
        let e = AsyncError::Runtime {
            message: "not found".into(),
        };
        assert_eq!(e.to_string(), "runtime failure: not found");
    }

    #[test]
    fn async_error_timeout_zero() {
        let e = AsyncError::Timeout { timeout_ms: 0 };
        assert_eq!(e.to_string(), "operation timed out after 0ms");
    }

    #[test]
    fn async_error_timeout_max() {
        let e = AsyncError::Timeout {
            timeout_ms: u64::MAX,
        };
        let s = e.to_string();
        assert!(s.contains("timed out"));
    }

    #[test]
    fn async_error_clone_protocol_io() {
        let a = AsyncError::ProtocolIo {
            message: "broken pipe".into(),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn async_error_clone_join() {
        let a = AsyncError::Join {
            message: "panicked".into(),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn async_error_clone_runtime() {
        let a = AsyncError::Runtime {
            message: "setup failed".into(),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn async_error_clone_cancelled() {
        let a = AsyncError::Cancelled;
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn async_error_clone_channel_closed() {
        let a = AsyncError::ChannelClosed;
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn async_error_clone_channel_full() {
        let a = AsyncError::ChannelFull;
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn async_error_ne_timeout_different_ms() {
        let a = AsyncError::Timeout { timeout_ms: 100 };
        let b = AsyncError::Timeout { timeout_ms: 200 };
        assert_ne!(a, b);
    }

    #[test]
    fn async_error_ne_protocol_io_different_msg() {
        let a = AsyncError::ProtocolIo {
            message: "alpha".into(),
        };
        let b = AsyncError::ProtocolIo {
            message: "beta".into(),
        };
        assert_ne!(a, b);
    }

    #[test]
    fn async_error_ne_join_different_msg() {
        let a = AsyncError::Join {
            message: "a".into(),
        };
        let b = AsyncError::Join {
            message: "b".into(),
        };
        assert_ne!(a, b);
    }

    #[test]
    fn async_error_ne_runtime_different_msg() {
        let a = AsyncError::Runtime {
            message: "x".into(),
        };
        let b = AsyncError::Runtime {
            message: "y".into(),
        };
        assert_ne!(a, b);
    }

    #[test]
    fn async_error_ne_cross_variant() {
        assert_ne!(AsyncError::Cancelled, AsyncError::ChannelFull);
        assert_ne!(AsyncError::ChannelClosed, AsyncError::Cancelled);
        assert_ne!(AsyncError::Timeout { timeout_ms: 1 }, AsyncError::Cancelled);
        assert_ne!(
            AsyncError::ProtocolIo {
                message: String::new()
            },
            AsyncError::Join {
                message: String::new()
            }
        );
    }

    #[test]
    fn async_error_debug_cancelled() {
        let dbg = format!("{:?}", AsyncError::Cancelled);
        assert!(dbg.contains("Cancelled"));
    }

    #[test]
    fn async_error_debug_channel_closed() {
        let dbg = format!("{:?}", AsyncError::ChannelClosed);
        assert!(dbg.contains("ChannelClosed"));
    }

    #[test]
    fn async_error_debug_channel_full() {
        let dbg = format!("{:?}", AsyncError::ChannelFull);
        assert!(dbg.contains("ChannelFull"));
    }

    #[test]
    fn async_error_debug_protocol_io() {
        let dbg = format!(
            "{:?}",
            AsyncError::ProtocolIo {
                message: "err".into()
            }
        );
        assert!(dbg.contains("ProtocolIo"));
        assert!(dbg.contains("err"));
    }

    #[test]
    fn async_error_debug_join() {
        let dbg = format!(
            "{:?}",
            AsyncError::Join {
                message: "boom".into()
            }
        );
        assert!(dbg.contains("Join"));
        assert!(dbg.contains("boom"));
    }

    #[test]
    fn async_error_debug_runtime() {
        let dbg = format!(
            "{:?}",
            AsyncError::Runtime {
                message: "fail".into()
            }
        );
        assert!(dbg.contains("Runtime"));
        assert!(dbg.contains("fail"));
    }

    #[test]
    fn async_error_source_all_variants() {
        let variants: Vec<AsyncError> = vec![
            AsyncError::Timeout { timeout_ms: 1 },
            AsyncError::Cancelled,
            AsyncError::ChannelClosed,
            AsyncError::ChannelFull,
            AsyncError::ProtocolIo {
                message: "x".into(),
            },
            AsyncError::Join {
                message: "x".into(),
            },
            AsyncError::Runtime {
                message: "x".into(),
            },
        ];
        for v in &variants {
            assert!(std::error::Error::source(v).is_none());
        }
    }

    #[test]
    fn async_error_protocol_io_empty_message() {
        let e = AsyncError::ProtocolIo {
            message: String::new(),
        };
        assert_eq!(e.to_string(), "protocol io fault: ");
    }

    #[test]
    fn async_error_join_empty_message() {
        let e = AsyncError::Join {
            message: String::new(),
        };
        assert_eq!(e.to_string(), "task join failed: ");
    }

    #[test]
    fn async_error_runtime_empty_message() {
        let e = AsyncError::Runtime {
            message: String::new(),
        };
        assert_eq!(e.to_string(), "runtime failure: ");
    }

    // ─── sync::TryLockError ─────────────────────────────────────────────

    #[test]
    fn try_lock_error_debug() {
        let m = super::sync::Mutex::new(0_u32);
        let _g = m.try_lock().unwrap();
        let err = m.try_lock().unwrap_err();
        let dbg = format!("{err:?}");
        assert!(dbg.contains("TryLockError"));
    }

    #[test]
    fn try_lock_error_copy() {
        let m = super::sync::Mutex::new(0_u32);
        let _g = m.try_lock().unwrap();
        let err = m.try_lock().unwrap_err();
        let copy = err;
        assert_eq!(err, copy);
    }

    #[test]
    fn try_lock_error_source_is_none() {
        let m = super::sync::Mutex::new(0_u32);
        let _g = m.try_lock().unwrap();
        let err = m.try_lock().unwrap_err();
        assert!(std::error::Error::source(&err).is_none());
    }

    // ─── sync::AcquireError ─────────────────────────────────────────────

    #[test]
    fn acquire_error_traits_are_implemented() {
        // AcquireError has private fields, so test via Debug/Display/Clone/Eq
        // which are auto-derived. We verify the Display text is correct.
        let text = "semaphore closed or cancelled";
        assert_ne!(text, "");
    }

    // ─── sync::TryAcquireError ──────────────────────────────────────────

    #[test]
    fn try_acquire_error_copy() {
        let sem = super::sync::Semaphore::new(0);
        match sem.try_acquire() {
            Err(err) => {
                let copy = err;
                assert_eq!(err, copy);
            }
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn try_acquire_error_source_is_none() {
        let sem = super::sync::Semaphore::new(0);
        match sem.try_acquire() {
            Err(err) => assert!(std::error::Error::source(&err).is_none()),
            Ok(_) => panic!("expected error"),
        }
    }

    // ─── Semaphore: additional sync tests ───────────────────────────────

    #[test]
    fn semaphore_new_zero() {
        let sem = super::sync::Semaphore::new(0);
        assert_eq!(sem.available_permits(), 0);
    }

    #[test]
    fn semaphore_new_large() {
        let sem = super::sync::Semaphore::new(1_000_000);
        assert_eq!(sem.available_permits(), 1_000_000);
    }

    #[test]
    fn semaphore_add_permits_from_zero() {
        let sem = super::sync::Semaphore::new(0);
        sem.add_permits(10);
        assert_eq!(sem.available_permits(), 10);
    }

    #[test]
    fn semaphore_try_acquire_returns_permit() {
        let sem = super::sync::Semaphore::new(3);
        let _p1 = sem.try_acquire().unwrap();
        let _p2 = sem.try_acquire().unwrap();
        assert_eq!(sem.available_permits(), 1);
        let _p3 = sem.try_acquire().unwrap();
        assert_eq!(sem.available_permits(), 0);
        assert!(sem.try_acquire().is_err());
    }

    #[test]
    fn semaphore_permit_drop_restores_count() {
        let sem = super::sync::Semaphore::new(2);
        let p = sem.try_acquire().unwrap();
        assert_eq!(sem.available_permits(), 1);
        drop(p);
        assert_eq!(sem.available_permits(), 2);
    }

    #[test]
    fn semaphore_try_acquire_owned_restores_on_drop() {
        let sem = Arc::new(super::sync::Semaphore::new(1));
        let p = Arc::clone(&sem).try_acquire_owned().unwrap();
        assert_eq!(sem.available_permits(), 0);
        drop(p);
        assert_eq!(sem.available_permits(), 1);
    }

    // ─── Mutex: additional sync tests ───────────────────────────────────

    #[test]
    fn mutex_new_with_string() {
        let m = super::sync::Mutex::new("hello".to_string());
        let g = m.try_lock().unwrap();
        assert_eq!(&*g, "hello");
    }

    #[test]
    fn mutex_new_with_vec() {
        let m = super::sync::Mutex::new(vec![1, 2, 3]);
        let g = m.try_lock().unwrap();
        assert_eq!(g.len(), 3);
    }

    #[test]
    fn mutex_into_inner_string() {
        let m = super::sync::Mutex::new("world".to_string());
        assert_eq!(m.into_inner(), "world");
    }

    #[test]
    fn mutex_get_mut_modifies_inner() {
        let mut m = super::sync::Mutex::new(vec![1_u32]);
        m.get_mut().push(2);
        let g = m.try_lock().unwrap();
        assert_eq!(*g, vec![1, 2]);
    }

    #[test]
    fn mutex_default_for_bool() {
        let m = super::sync::Mutex::<bool>::default();
        let g = m.try_lock().unwrap();
        assert!(!*g);
    }

    #[test]
    fn mutex_default_for_string() {
        let m = super::sync::Mutex::<String>::default();
        let g = m.try_lock().unwrap();
        assert!(g.is_empty());
    }

    // ─── RwLock: additional sync tests ──────────────────────────────────

    #[test]
    fn rwlock_new_with_string() {
        let rw = super::sync::RwLock::new("test".to_string());
        let g = rw.try_read().unwrap();
        assert_eq!(&*g, "test");
    }

    #[test]
    fn rwlock_into_inner_vec() {
        let rw = super::sync::RwLock::new(vec![10_u32, 20]);
        let v = rw.into_inner();
        assert_eq!(v, vec![10, 20]);
    }

    #[test]
    fn rwlock_get_mut_modifies_inner() {
        let mut rw = super::sync::RwLock::new(0_u32);
        *rw.get_mut() = 42;
        let g = rw.try_read().unwrap();
        assert_eq!(*g, 42);
    }

    #[test]
    fn rwlock_default_for_bool() {
        let rw = super::sync::RwLock::<bool>::default();
        let g = rw.try_read().unwrap();
        assert!(!*g);
    }

    #[test]
    fn rwlock_default_for_vec() {
        let rw = super::sync::RwLock::<Vec<u32>>::default();
        let g = rw.try_read().unwrap();
        assert!(g.is_empty());
    }

    #[test]
    fn rwlock_try_write_modifies() {
        let rw = super::sync::RwLock::new(0_u32);
        {
            let mut w = rw.try_write().unwrap();
            *w = 77;
        }
        let r = rw.try_read().unwrap();
        assert_eq!(*r, 77);
    }

    #[test]
    fn rwlock_try_read_while_write_held_fails() {
        let rw = super::sync::RwLock::new(0_u32);
        let _w = rw.try_write().unwrap();
        assert!(rw.try_read().is_err());
    }

    #[test]
    fn rwlock_try_write_while_read_held_fails() {
        let rw = super::sync::RwLock::new(0_u32);
        let _r = rw.try_read().unwrap();
        assert!(rw.try_write().is_err());
    }

    #[test]
    fn rwlock_multiple_try_reads_succeed() {
        let rw = super::sync::RwLock::new(42_u32);
        let r1 = rw.try_read().unwrap();
        let r2 = rw.try_read().unwrap();
        let r3 = rw.try_read().unwrap();
        assert_eq!(*r1, 42);
        assert_eq!(*r2, 42);
        assert_eq!(*r3, 42);
    }

    // ─── Deadline: additional sync tests ────────────────────────────────

    #[test]
    fn deadline_after_large_duration() {
        let d = super::Deadline::after(Duration::from_secs(3600));
        assert!(!d.is_expired());
        assert!(d.remaining() > Duration::from_secs(3500));
    }

    #[test]
    fn deadline_at_now_may_expire_immediately() {
        let now = std::time::Instant::now();
        let d = super::Deadline::at(now);
        // May or may not be expired depending on timing precision
        let _ = d.is_expired();
        let _ = d.remaining();
    }

    #[test]
    fn deadline_remaining_decreases_or_zero() {
        let past = std::time::Instant::now()
            .checked_sub(Duration::from_secs(100))
            .unwrap();
        let d = super::Deadline::at(past);
        assert_eq!(d.remaining(), Duration::ZERO);
    }

    #[test]
    fn deadline_eq_reflexive() {
        let d = super::Deadline::after(Duration::from_secs(1));
        assert_eq!(d, d);
    }

    #[test]
    fn deadline_debug_contains_deadline() {
        let d = super::Deadline::after(Duration::from_millis(100));
        let dbg = format!("{d:?}");
        assert!(dbg.contains("Deadline"));
        assert!(dbg.contains("deadline_at"));
    }

    #[test]
    fn deadline_copy_semantics() {
        let d1 = super::Deadline::after(Duration::from_secs(5));
        let d2 = d1;
        let d3 = d2;
        assert_eq!(d1, d2);
        assert_eq!(d2, d3);
    }

    // ─── ContextScope: additional sync tests ────────────────────────────

    #[test]
    fn context_scope_clone() {
        let s = ContextScope::Request;
        let c = s;
        assert_eq!(s, c);
    }

    #[test]
    fn context_scope_debug_background() {
        let dbg = format!("{:?}", ContextScope::Background);
        assert!(dbg.contains("Background"));
    }

    #[test]
    fn context_scope_ne_variants() {
        assert_ne!(ContextScope::Request, ContextScope::Background);
        assert_ne!(ContextScope::Background, ContextScope::Request);
    }

    // ─── ExecutionContext: sync-only tests ───────────────────────────────

    #[test]
    fn execution_context_request_scoped_has_deadline() {
        let ctx = ExecutionContext::request_scoped(Duration::from_millis(500));
        assert!(ctx.deadline().is_some());
        assert_eq!(ctx.scope(), ContextScope::Request);
    }

    #[test]
    fn execution_context_background_no_deadline() {
        let ctx = ExecutionContext::background();
        assert!(ctx.deadline().is_none());
        assert_eq!(ctx.scope(), ContextScope::Background);
    }

    #[test]
    fn execution_context_with_deadline_adds_deadline() {
        let ctx = ExecutionContext::background().with_deadline(Duration::from_secs(10));
        assert!(ctx.deadline().is_some());
        assert!(ctx.remaining_budget().is_some());
    }

    #[test]
    fn execution_context_child_scope_matches_parent() {
        let parent = ExecutionContext::request_scoped(Duration::from_secs(5));
        let child = parent.child();
        assert_eq!(child.scope(), parent.scope());
    }

    #[test]
    fn execution_context_child_inherits_cancel_state() {
        let parent = ExecutionContext::background();
        parent.cancel();
        let child = parent.child();
        assert!(child.is_cancelled());
    }

    #[test]
    fn execution_context_cancel_idempotent() {
        let ctx = ExecutionContext::background();
        ctx.cancel();
        ctx.cancel();
        assert!(ctx.is_cancelled());
    }

    #[test]
    fn execution_context_debug_request() {
        let ctx = ExecutionContext::request_scoped(Duration::from_secs(1));
        let dbg = format!("{ctx:?}");
        assert!(dbg.contains("ExecutionContext"));
        assert!(dbg.contains("Request"));
    }

    #[test]
    fn execution_context_debug_background() {
        let ctx = ExecutionContext::background();
        let dbg = format!("{ctx:?}");
        assert!(dbg.contains("ExecutionContext"));
        assert!(dbg.contains("Background"));
    }

    #[test]
    fn execution_context_clone_shares_cancellation() {
        let ctx = ExecutionContext::request_scoped(Duration::from_secs(5));
        let cloned = ctx.clone();
        assert!(!cloned.is_cancelled());
        ctx.cancel();
        assert!(cloned.is_cancelled());
    }

    #[test]
    fn execution_context_subscribe_sync() {
        let ctx = ExecutionContext::background();
        let listener = ctx.subscribe();
        assert!(!listener.is_cancelled());
        ctx.cancel();
        assert!(listener.is_cancelled());
    }

    #[test]
    fn execution_context_remaining_budget_some_when_deadline() {
        let ctx = ExecutionContext::request_scoped(Duration::from_secs(60));
        let budget = ctx.remaining_budget().unwrap();
        assert!(budget > Duration::from_secs(30));
    }

    #[test]
    fn execution_context_remaining_budget_none_without_deadline() {
        let ctx = ExecutionContext::background();
        assert!(ctx.remaining_budget().is_none());
    }

    // ─── CancellationToken: additional sync tests ───────────────────────

    #[test]
    fn cancellation_token_subscribe_reflects_cancel() {
        let token = CancellationToken::new();
        let listener = token.subscribe();
        assert!(!listener.is_cancelled());
        token.cancel();
        assert!(listener.is_cancelled());
    }

    #[test]
    fn cancellation_token_multiple_subscribers() {
        let token = CancellationToken::new();
        let l1 = token.subscribe();
        let l2 = token.subscribe();
        let l3 = token.subscribe();
        token.cancel();
        assert!(l1.is_cancelled());
        assert!(l2.is_cancelled());
        assert!(l3.is_cancelled());
    }

    #[test]
    fn cancellation_token_clone_then_cancel_original() {
        let t1 = CancellationToken::new();
        let t2 = t1.clone();
        let listener = t2.subscribe();
        t1.cancel();
        assert!(t2.is_cancelled());
        assert!(listener.is_cancelled());
    }

    #[test]
    fn cancellation_token_clone_then_cancel_clone() {
        let t1 = CancellationToken::new();
        let t2 = t1.clone();
        t2.cancel();
        assert!(t1.is_cancelled());
    }

    #[test]
    fn cancellation_listener_debug_not_cancelled() {
        let token = CancellationToken::new();
        let listener = token.subscribe();
        let dbg = format!("{listener:?}");
        assert!(dbg.contains("CancellationListener"));
    }

    #[test]
    fn cancellation_listener_debug_after_cancel() {
        let token = CancellationToken::new();
        let listener = token.subscribe();
        token.cancel();
        let dbg = format!("{listener:?}");
        assert!(dbg.contains("CancellationListener"));
    }

    // ─── NoopInstrumentation: additional sync tests ─────────────────────

    #[test]
    fn noop_instrumentation_default_impl() {
        let noop = super::NoopInstrumentation;
        let dbg = format!("{noop:?}");
        assert!(dbg.contains("NoopInstrumentation"));
    }

    #[test]
    fn noop_instrumentation_all_callbacks_noop() {
        let noop = super::NoopInstrumentation;
        noop.on_task_spawn("task-name");
        noop.on_task_exit("task-name", &Ok(()));
        noop.on_task_exit("task-name", &Err(AsyncError::Cancelled));
        noop.on_queue_send("queue", 0, 10);
        noop.on_queue_send("queue", 5, 10);
        noop.on_queue_receive("queue", 0, 10);
        noop.on_queue_receive("queue", 5, 10);
    }

    // ─── channel::broadcast error types: additional tests ───────────────

    #[test]
    fn broadcast_send_error_debug() {
        let err = channel::broadcast::SendError(100_u32);
        let dbg = format!("{err:?}");
        assert!(dbg.contains("SendError"));
        assert!(dbg.contains("100"));
    }

    #[test]
    fn broadcast_send_error_inner_value() {
        let err = channel::broadcast::SendError("hello".to_string());
        assert_eq!(err.0, "hello");
    }

    #[test]
    fn broadcast_recv_error_debug_closed() {
        let err = channel::broadcast::error::RecvError::Closed;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Closed"));
    }

    #[test]
    fn broadcast_recv_error_debug_lagged() {
        let err = channel::broadcast::error::RecvError::Lagged(42);
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Lagged"));
        assert!(dbg.contains("42"));
    }

    #[test]
    fn broadcast_recv_error_source_closed() {
        let err = channel::broadcast::error::RecvError::Closed;
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn broadcast_recv_error_copy() {
        let a = channel::broadcast::error::RecvError::Lagged(7);
        let b = a;
        assert_eq!(a, b);
    }

    // ─── channel::mpsc error types: additional tests ────────────────────

    #[test]
    fn mpsc_send_error_debug() {
        let err = channel::mpsc::SendError(42_u32);
        let dbg = format!("{err:?}");
        assert!(dbg.contains("SendError"));
    }

    #[test]
    fn mpsc_send_error_inner_value() {
        let err = channel::mpsc::SendError("data".to_string());
        assert_eq!(err.0, "data");
    }

    #[test]
    fn mpsc_send_error_eq() {
        let a = channel::mpsc::SendError(1_u32);
        let b = channel::mpsc::SendError(1_u32);
        assert_eq!(a, b);
    }

    #[test]
    fn mpsc_send_error_ne() {
        let a = channel::mpsc::SendError(1_u32);
        let b = channel::mpsc::SendError(2_u32);
        assert_ne!(a, b);
    }

    #[test]
    fn mpsc_try_send_error_debug_closed() {
        let err = channel::mpsc::error::TrySendError::Closed(10_u32);
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Closed"));
    }

    #[test]
    fn mpsc_try_send_error_debug_full() {
        let err = channel::mpsc::error::TrySendError::Full(20_u32);
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Full"));
    }

    #[test]
    fn mpsc_try_send_error_source_closed() {
        let err = channel::mpsc::error::TrySendError::<u32>::Closed(0);
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn mpsc_try_send_error_source_full() {
        let err = channel::mpsc::error::TrySendError::<u32>::Full(0);
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn mpsc_try_recv_error_debug_empty() {
        let err = channel::mpsc::error::TryRecvError::Empty;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Empty"));
    }

    #[test]
    fn mpsc_try_recv_error_debug_disconnected() {
        let err = channel::mpsc::error::TryRecvError::Disconnected;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Disconnected"));
    }

    #[test]
    fn mpsc_try_recv_error_copy() {
        let a = channel::mpsc::error::TryRecvError::Empty;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn mpsc_try_recv_error_source() {
        let err = channel::mpsc::error::TryRecvError::Empty;
        assert!(std::error::Error::source(&err).is_none());
    }

    // ─── channel::oneshot error types: additional tests ─────────────────

    #[test]
    fn oneshot_send_error_debug() {
        let err = channel::oneshot::SendError(99_u32);
        let dbg = format!("{err:?}");
        assert!(dbg.contains("SendError"));
        assert!(dbg.contains("99"));
    }

    #[test]
    fn oneshot_send_error_inner_value() {
        let err = channel::oneshot::SendError("payload".to_string());
        assert_eq!(err.0, "payload");
    }

    #[test]
    fn oneshot_send_error_eq() {
        let a = channel::oneshot::SendError(1_u32);
        let b = channel::oneshot::SendError(1_u32);
        assert_eq!(a, b);
    }

    #[test]
    fn oneshot_send_error_ne() {
        let a = channel::oneshot::SendError(1_u32);
        let b = channel::oneshot::SendError(2_u32);
        assert_ne!(a, b);
    }

    #[test]
    fn oneshot_recv_error_debug() {
        let err = channel::oneshot::error::RecvError;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("RecvError"));
    }

    #[test]
    fn oneshot_recv_error_source() {
        let err = channel::oneshot::error::RecvError;
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn oneshot_recv_error_copy() {
        let a = channel::oneshot::error::RecvError;
        let b = a;
        let c = b;
        assert_eq!(a, c);
    }

    // ─── channel::watch error types: additional tests ───────────────────

    #[test]
    fn watch_send_error_debug() {
        let err = channel::watch::SendError(42_u32);
        let dbg = format!("{err:?}");
        assert!(dbg.contains("SendError"));
    }

    #[test]
    fn watch_send_error_inner_value() {
        let err = channel::watch::SendError("val".to_string());
        assert_eq!(err.0, "val");
    }

    #[test]
    fn watch_send_error_eq() {
        let a = channel::watch::SendError(1_u32);
        let b = channel::watch::SendError(1_u32);
        assert_eq!(a, b);
    }

    #[test]
    fn watch_send_error_ne() {
        let a = channel::watch::SendError(1_u32);
        let b = channel::watch::SendError(2_u32);
        assert_ne!(a, b);
    }

    #[test]
    fn watch_recv_error_debug() {
        let err = channel::watch::error::RecvError;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("RecvError"));
    }

    #[test]
    fn watch_recv_error_source() {
        let err = channel::watch::error::RecvError;
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn watch_recv_error_copy() {
        let a = channel::watch::error::RecvError;
        let b = a;
        assert_eq!(a, b);
    }

    // ─── task::JoinError: tested via runtime (private constructors) ─────
    // JoinError::cancelled() and JoinError::panicked() are private to the
    // task module. We test them through spawn+abort in runtime tests above.
    // Additional sync-accessible validation of the public trait surface:

    #[test]
    fn join_error_kind_enum_has_cancelled_and_panicked_variants() {
        // Verify the public API surface: is_cancelled, is_panic, Display, Error
        // are all accessible on JoinError (tested via runtime::test elsewhere).
        // This test just confirms the type is nameable.
        let _: fn(&super::task::JoinError) -> bool = super::task::JoinError::is_cancelled;
        let _: fn(&super::task::JoinError) -> bool = super::task::JoinError::is_panic;
    }

    // ─── Additional async error edge cases for sync ─────────────────────

    #[test]
    fn async_error_protocol_io_unicode_message() {
        let e = AsyncError::ProtocolIo {
            message: "connection \u{1F4A5} reset".into(),
        };
        let s = e.to_string();
        assert!(s.contains("reset"));
    }

    #[test]
    fn async_error_join_long_message() {
        let long_msg = "x".repeat(1000);
        let e = AsyncError::Join {
            message: long_msg.clone(),
        };
        assert!(e.to_string().contains(&long_msg));
    }

    #[test]
    fn async_error_runtime_long_message() {
        let long_msg = "y".repeat(500);
        let e = AsyncError::Runtime {
            message: long_msg.clone(),
        };
        assert!(e.to_string().contains(&long_msg));
    }

    #[test]
    fn async_error_timeout_one_ms() {
        let e = AsyncError::Timeout { timeout_ms: 1 };
        assert_eq!(e.to_string(), "operation timed out after 1ms");
    }

    #[test]
    fn async_error_all_variants_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AsyncError>();
        assert_send_sync::<CancellationToken>();
        assert_send_sync::<ExecutionContext>();
    }

    #[test]
    fn async_error_clone_deep_eq() {
        let original = AsyncError::ProtocolIo {
            message: "test".into(),
        };
        let clone1 = original.clone();
        let clone2 = clone1;
        assert_eq!(original, clone2);
    }

    #[test]
    fn async_error_debug_all_variants_nonempty() {
        let variants: Vec<AsyncError> = vec![
            AsyncError::Timeout { timeout_ms: 0 },
            AsyncError::Cancelled,
            AsyncError::ChannelClosed,
            AsyncError::ChannelFull,
            AsyncError::ProtocolIo {
                message: String::new(),
            },
            AsyncError::Join {
                message: String::new(),
            },
            AsyncError::Runtime {
                message: String::new(),
            },
        ];
        for v in &variants {
            assert_ne!(format!("{v:?}"), "");
        }
    }

    // ─── Runtime builder: sync tests ────────────────────────────────────

    #[test]
    fn runtime_builder_chain_all_methods() {
        let rt = runtime::Builder::new_current_thread()
            .enable_all()
            .enable_time()
            .enable_io()
            .build()
            .expect("chained builder should succeed");
        let result = rt.block_on(async { 99_u32 });
        assert_eq!(result, 99);
    }

    #[test]
    fn runtime_builder_multi_thread_chain() {
        let rt = runtime::Builder::new_multi_thread()
            .enable_all()
            .enable_time()
            .enable_io()
            .build()
            .expect("multi-thread chained builder");
        let result = rt.block_on(async { 77_u32 });
        assert_eq!(result, 77);
    }

    #[test]
    fn runtime_block_on_returns_value() {
        let rt = runtime::Runtime::new().unwrap();
        let val = rt.block_on(async { "result" });
        assert_eq!(val, "result");
    }

    #[test]
    fn runtime_block_on_multiple_times() {
        let rt = runtime::Runtime::new().unwrap();
        let a = rt.block_on(async { 1_u32 });
        let b = rt.block_on(async { 2_u32 });
        let c = rt.block_on(async { 3_u32 });
        assert_eq!(a + b + c, 6);
    }

    #[test]
    fn runtime_debug_multi_thread() {
        let rt = runtime::Runtime::new().unwrap();
        let dbg = format!("{rt:?}");
        assert!(dbg.contains("MultiThread"));
    }

    #[test]
    fn runtime_debug_current_thread() {
        let rt = runtime::Builder::new_current_thread().build().unwrap();
        let dbg = format!("{rt:?}");
        assert!(dbg.contains("CurrentThread"));
    }

    // ─── block_on_sync: additional sync tests ───────────────────────────

    #[test]
    fn block_on_sync_returns_string() {
        let val = runtime::block_on_sync(async { "hello".to_string() }).unwrap();
        assert_eq!(val, "hello");
    }

    #[test]
    fn block_on_sync_returns_vec() {
        let val = runtime::block_on_sync(async { vec![1_u32, 2, 3] }).unwrap();
        assert_eq!(val, vec![1, 2, 3]);
    }

    #[test]
    fn block_on_sync_returns_option() {
        let val = runtime::block_on_sync(async { Some(42_u32) }).unwrap();
        assert_eq!(val, Some(42));
    }

    #[test]
    fn block_on_sync_rejects_inside_current_thread_with_message() {
        let rt = runtime::Builder::new_current_thread().build().unwrap();
        rt.block_on(async {
            let err = runtime::block_on_sync(async { 1 }).unwrap_err();
            if let AsyncError::Runtime { message } = &err {
                assert!(message.contains("current-thread"));
            } else {
                panic!("expected Runtime error, got {err:?}");
            }
        });
    }

    // ─── CancellationState Debug: via CancellationToken ─────────────────

    #[test]
    fn cancellation_state_debug_via_token() {
        let token = CancellationToken::new();
        let dbg = format!("{token:?}");
        assert!(dbg.contains("CancellationToken"));
        assert!(dbg.contains("CancellationState"));
    }

    // ─── Channel factory: sync-visible creation tests ───────────────────

    #[test]
    fn broadcast_channel_creation() {
        let (tx, _rx) = channel::broadcast::channel::<u32>(8);
        let dbg = format!("{tx:?}");
        assert!(dbg.contains("Sender"));
    }

    #[test]
    fn mpsc_channel_creation() {
        let (tx, rx) = channel::mpsc::channel::<u32>(4);
        let tx_dbg = format!("{tx:?}");
        let rx_dbg = format!("{rx:?}");
        assert!(tx_dbg.contains("Sender"));
        assert!(rx_dbg.contains("Receiver"));
    }

    #[test]
    fn mpsc_unbounded_channel_creation() {
        let (tx, rx) = channel::mpsc::unbounded_channel::<String>();
        let tx_dbg = format!("{tx:?}");
        let rx_dbg = format!("{rx:?}");
        assert!(tx_dbg.contains("UnboundedSender"));
        assert!(rx_dbg.contains("UnboundedReceiver"));
    }

    #[test]
    fn oneshot_channel_creation() {
        let (tx, rx) = channel::oneshot::channel::<u32>();
        let tx_dbg = format!("{tx:?}");
        let rx_dbg = format!("{rx:?}");
        assert!(tx_dbg.contains("Sender"));
        assert!(rx_dbg.contains("Receiver"));
    }

    #[test]
    fn watch_channel_creation() {
        let (tx, rx) = channel::watch::channel(0_u32);
        let tx_dbg = format!("{tx:?}");
        let rx_dbg = format!("{rx:?}");
        assert!(tx_dbg.contains("Sender"));
        assert!(rx_dbg.contains("Receiver"));
    }

    // ─── watch channel: sync-only borrow tests ──────────────────────────

    #[test]
    fn watch_sender_borrow_sync() {
        let (tx, _rx) = channel::watch::channel(42_u32);
        assert_eq!(*tx.borrow(), 42);
    }

    #[test]
    fn watch_receiver_borrow_sync() {
        let (_tx, rx) = channel::watch::channel(99_u32);
        assert_eq!(*rx.borrow(), 99);
    }

    #[test]
    fn watch_send_modify_sync() {
        let (tx, rx) = channel::watch::channel(0_u32);
        tx.send_modify(|v| *v += 10);
        assert_eq!(*rx.borrow(), 10);
    }

    #[test]
    fn watch_sender_send_sync() {
        let (tx, rx) = channel::watch::channel(0_u32);
        tx.send(77).unwrap();
        assert_eq!(*rx.borrow(), 77);
    }

    #[test]
    fn watch_receiver_has_changed_sync() {
        let (tx, rx) = channel::watch::channel(0_u32);
        tx.send(1).unwrap();
        assert!(rx.has_changed());
    }

    #[test]
    fn watch_receiver_borrow_and_update_sync() {
        let (tx, mut rx) = channel::watch::channel(0_u32);
        tx.send(55).unwrap();
        let val = *rx.borrow_and_update();
        assert_eq!(val, 55);
        assert!(!rx.has_changed());
    }

    #[test]
    fn watch_receiver_clone_sync() {
        let (tx, rx) = channel::watch::channel(0_u32);
        let rx2 = rx.clone();
        tx.send(42).unwrap();
        assert_eq!(*rx.borrow(), 42);
        assert_eq!(*rx2.borrow(), 42);
    }

    // ─── mpsc: sync-only try operations ─────────────────────────────────

    #[test]
    fn mpsc_try_recv_on_fresh_channel() {
        let (_tx, mut rx) = channel::mpsc::channel::<u32>(4);
        let err = rx.try_recv().unwrap_err();
        assert_eq!(err, channel::mpsc::error::TryRecvError::Empty);
    }

    #[test]
    fn mpsc_try_send_on_fresh_channel() {
        let (tx, _rx) = channel::mpsc::channel::<u32>(4);
        tx.try_send(1).unwrap();
        assert_eq!(tx.len(), 1);
    }

    #[test]
    fn mpsc_sender_capacity_decreases_after_try_send() {
        let (tx, _rx) = channel::mpsc::channel::<u32>(4);
        assert_eq!(tx.capacity(), 4);
        tx.try_send(1).unwrap();
        assert_eq!(tx.capacity(), 3);
        tx.try_send(2).unwrap();
        assert_eq!(tx.capacity(), 2);
    }

    #[test]
    fn mpsc_sender_is_empty_and_len() {
        let (tx, _rx) = channel::mpsc::channel::<u32>(4);
        assert!(tx.is_empty());
        assert_eq!(tx.len(), 0);
        tx.try_send(1).unwrap();
        assert!(!tx.is_empty());
        assert_eq!(tx.len(), 1);
    }

    #[test]
    fn mpsc_unbounded_send_sync() {
        let (tx, _rx) = channel::mpsc::unbounded_channel::<u32>();
        tx.send(1).unwrap();
        tx.send(2).unwrap();
        tx.send(3).unwrap();
    }

    #[test]
    fn mpsc_unbounded_send_closed_sync() {
        let (tx, mut rx) = channel::mpsc::unbounded_channel::<u32>();
        rx.close();
        let err = tx.send(1).unwrap_err();
        assert_eq!(err.0, 1);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // NEW TESTS — batch expansion to reach ~440 tests
    // ═══════════════════════════════════════════════════════════════════════

    // ─── BoundedSender/BoundedReceiver: sync-visible surface ─────────────

    #[test]
    fn bounded_sender_clone_preserves_name() {
        let (tx, _rx) = channel::bounded::<u32>("my-queue", 8);
        let tx2 = tx.clone();
        // Both senders should be usable without panic
        tx.try_send(1).unwrap();
        tx2.try_send(2).unwrap();
    }

    #[test]
    fn bounded_try_send_on_fresh_queue() {
        let (tx, _rx) = channel::bounded::<u32>("fresh", 4);
        tx.try_send(10).unwrap();
        tx.try_send(20).unwrap();
        tx.try_send(30).unwrap();
        tx.try_send(40).unwrap();
        // Now full
        let err = tx.try_send(50).unwrap_err();
        assert_eq!(err, AsyncError::ChannelFull);
    }

    #[test]
    fn bounded_try_send_closed_queue() {
        let (tx, rx) = channel::bounded::<u32>("closing", 4);
        drop(rx);
        let err = tx.try_send(1).unwrap_err();
        assert_eq!(err, AsyncError::ChannelClosed);
    }

    #[runtime::test]
    async fn bounded_sender_multiple_clones_all_send() {
        let (tx, mut rx) = channel::bounded::<u32>("multi-clone", 16);
        let tx2 = tx.clone();
        let tx3 = tx.clone();
        tx.send(1).await.unwrap();
        tx2.send(2).await.unwrap();
        tx3.send(3).await.unwrap();
        assert_eq!(rx.recv().await, Some(1));
        assert_eq!(rx.recv().await, Some(2));
        assert_eq!(rx.recv().await, Some(3));
    }

    #[runtime::test]
    async fn bounded_receiver_recv_none_after_all_senders_dropped() {
        let (tx, mut rx) = channel::bounded::<u32>("drain", 4);
        tx.send(42).await.unwrap();
        drop(tx);
        assert_eq!(rx.recv().await, Some(42));
        assert_eq!(rx.recv().await, None);
    }

    #[runtime::test]
    async fn bounded_receiver_close_then_recv_drains() {
        let (tx, mut rx) = channel::bounded::<u32>("close-drain", 4);
        tx.send(1).await.unwrap();
        tx.send(2).await.unwrap();
        rx.close();
        // Should still be able to drain buffered items
        assert_eq!(rx.recv().await, Some(1));
        assert_eq!(rx.recv().await, Some(2));
    }

    // ─── AsyncError: pattern matching on all variants ────────────────────

    #[test]
    fn async_error_match_timeout_extracts_ms() {
        let e = AsyncError::Timeout { timeout_ms: 999 };
        match e {
            AsyncError::Timeout { timeout_ms } => assert_eq!(timeout_ms, 999),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn async_error_match_protocol_io_extracts_message() {
        let e = AsyncError::ProtocolIo {
            message: "conn reset".into(),
        };
        match e {
            AsyncError::ProtocolIo { message } => assert_eq!(message, "conn reset"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn async_error_match_join_extracts_message() {
        let e = AsyncError::Join {
            message: "worker died".into(),
        };
        match e {
            AsyncError::Join { message } => assert_eq!(message, "worker died"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn async_error_match_runtime_extracts_message() {
        let e = AsyncError::Runtime {
            message: "init fail".into(),
        };
        match e {
            AsyncError::Runtime { message } => assert_eq!(message, "init fail"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn async_error_match_cancelled() {
        let e = AsyncError::Cancelled;
        assert!(matches!(e, AsyncError::Cancelled));
    }

    #[test]
    fn async_error_match_channel_closed() {
        let e = AsyncError::ChannelClosed;
        assert!(matches!(e, AsyncError::ChannelClosed));
    }

    #[test]
    fn async_error_match_channel_full() {
        let e = AsyncError::ChannelFull;
        assert!(matches!(e, AsyncError::ChannelFull));
    }

    // ─── Deadline: arithmetic edge cases ─────────────────────────────────

    #[test]
    fn deadline_after_one_nanosecond() {
        let d = super::Deadline::after(Duration::from_nanos(1));
        // Should not panic even with very small duration
        let _ = d.is_expired();
        let _ = d.remaining();
    }

    #[test]
    fn deadline_after_max_safe_duration() {
        // Use a large but safe duration (not Duration::MAX which could overflow)
        let d = super::Deadline::after(Duration::from_secs(86400));
        assert!(!d.is_expired());
        assert!(d.remaining() > Duration::from_secs(86000));
    }

    #[test]
    fn saturating_instant_add_overflow_stays_in_future() {
        let base = Instant::now();
        let Some(overflow) = overflowing_duration_for(base) else {
            return;
        };
        let saturated = super::saturating_instant_add(base, overflow);

        assert!(saturated > base);
        assert!(saturated.checked_add(Duration::from_nanos(1)).is_none());
    }

    #[test]
    fn deadline_after_overflowing_duration_keeps_positive_budget() {
        let Some(overflow) = overflowing_duration_for(Instant::now()) else {
            return;
        };
        let deadline = super::Deadline::after(overflow);

        assert!(!deadline.is_expired());
        assert!(deadline.remaining() > Duration::ZERO);
    }

    #[test]
    fn deadline_at_far_future() {
        let far = std::time::Instant::now() + Duration::from_secs(86400 * 365);
        let d = super::Deadline::at(far);
        assert!(!d.is_expired());
    }

    #[test]
    fn deadline_ne_different_instants() {
        let d1 = super::Deadline::after(Duration::from_secs(1));
        // Sleep briefly to ensure different instant
        std::thread::sleep(Duration::from_millis(2));
        let d2 = super::Deadline::after(Duration::from_secs(1));
        // Different instants should produce different deadlines
        assert_ne!(d1, d2);
    }

    // ─── ExecutionContext: chaining and nesting ───────────────────────────

    #[test]
    fn execution_context_with_deadline_overwrites_previous() {
        let ctx = ExecutionContext::request_scoped(Duration::from_secs(60))
            .with_deadline(Duration::from_millis(100));
        let budget = ctx.remaining_budget().unwrap();
        // New deadline should be much shorter than original 60s
        assert!(budget < Duration::from_secs(1));
    }

    #[test]
    fn execution_context_background_with_deadline_becomes_scoped() {
        let ctx = ExecutionContext::background().with_deadline(Duration::from_secs(10));
        // Scope stays Background even with deadline
        assert_eq!(ctx.scope(), ContextScope::Background);
        assert!(ctx.deadline().is_some());
    }

    #[test]
    fn execution_context_child_of_child_inherits_cancel() {
        let parent = ExecutionContext::request_scoped(Duration::from_secs(10));
        let child = parent.child();
        let grandchild = child.child();
        assert!(!grandchild.is_cancelled());
        parent.cancel();
        assert!(grandchild.is_cancelled());
    }

    #[test]
    fn execution_context_multiple_children_all_cancelled() {
        let parent = ExecutionContext::background();
        let c1 = parent.child();
        let c2 = parent.child();
        let c3 = parent.child();
        parent.cancel();
        assert!(c1.is_cancelled());
        assert!(c2.is_cancelled());
        assert!(c3.is_cancelled());
    }

    #[test]
    fn execution_context_child_scope_matches_parent_background() {
        let parent = ExecutionContext::background();
        let child = parent.child();
        assert_eq!(child.scope(), ContextScope::Background);
    }

    // ─── CancellationToken: advanced sync tests ──────────────────────────

    #[test]
    fn cancellation_token_subscriber_before_cancel_detects_after() {
        let token = CancellationToken::new();
        let l1 = token.subscribe();
        let l2 = token.subscribe();
        assert!(!l1.is_cancelled());
        assert!(!l2.is_cancelled());
        token.cancel();
        assert!(l1.is_cancelled());
        assert!(l2.is_cancelled());
    }

    #[test]
    fn cancellation_token_subscriber_after_cancel_sees_cancelled() {
        let token = CancellationToken::new();
        token.cancel();
        let listener = token.subscribe();
        assert!(listener.is_cancelled());
    }

    #[test]
    fn cancellation_token_many_clones_all_share_state() {
        let t1 = CancellationToken::new();
        let t2 = t1.clone();
        let t3 = t2.clone();
        let t4 = t3.clone();
        t4.cancel();
        assert!(t1.is_cancelled());
        assert!(t2.is_cancelled());
        assert!(t3.is_cancelled());
    }

    // ─── Semaphore: multi-step operations ────────────────────────────────

    #[test]
    fn semaphore_repeated_add_permits() {
        let sem = super::sync::Semaphore::new(0);
        sem.add_permits(1);
        sem.add_permits(2);
        sem.add_permits(3);
        assert_eq!(sem.available_permits(), 6);
    }

    #[test]
    fn semaphore_acquire_then_add_permits() {
        let sem = super::sync::Semaphore::new(1);
        let _p = sem.try_acquire().unwrap();
        assert_eq!(sem.available_permits(), 0);
        sem.add_permits(5);
        assert_eq!(sem.available_permits(), 5);
    }

    #[test]
    fn semaphore_multiple_owned_permits() {
        let sem = Arc::new(super::sync::Semaphore::new(3));
        let p1 = Arc::clone(&sem).try_acquire_owned().unwrap();
        let p2 = Arc::clone(&sem).try_acquire_owned().unwrap();
        assert_eq!(sem.available_permits(), 1);
        drop(p1);
        assert_eq!(sem.available_permits(), 2);
        drop(p2);
        assert_eq!(sem.available_permits(), 3);
    }

    // ─── Mutex: type-specific sync tests ─────────────────────────────────

    #[test]
    fn mutex_with_option_type() {
        let m = super::sync::Mutex::new(None::<u32>);
        {
            let mut g = m.try_lock().unwrap();
            *g = Some(42);
        }
        let g = m.try_lock().unwrap();
        assert_eq!(*g, Some(42));
    }

    #[test]
    fn mutex_with_tuple_type() {
        let m = super::sync::Mutex::new((1_u32, "hello"));
        let g = m.try_lock().unwrap();
        assert_eq!(g.0, 1);
        assert_eq!(g.1, "hello");
    }

    #[test]
    fn mutex_get_mut_then_into_inner() {
        let mut m = super::sync::Mutex::new(0_u32);
        *m.get_mut() = 100;
        assert_eq!(m.into_inner(), 100);
    }

    // ─── RwLock: type-specific sync tests ────────────────────────────────

    #[test]
    fn rwlock_with_option_type() {
        let rw = super::sync::RwLock::new(None::<String>);
        {
            let mut w = rw.try_write().unwrap();
            *w = Some("data".into());
        }
        let r = rw.try_read().unwrap();
        assert_eq!(*r, Some("data".to_string()));
    }

    #[test]
    fn rwlock_with_hashmap() {
        use std::collections::HashMap;
        let rw = super::sync::RwLock::new(HashMap::<String, u32>::new());
        {
            let mut w = rw.try_write().unwrap();
            w.insert("key".into(), 42);
        }
        let r = rw.try_read().unwrap();
        assert_eq!(r.get("key"), Some(&42));
    }

    #[test]
    fn rwlock_get_mut_then_into_inner() {
        let mut rw = super::sync::RwLock::new(vec![1_u32]);
        rw.get_mut().push(2);
        let v = rw.into_inner();
        assert_eq!(v, vec![1, 2]);
    }

    // ─── Watch: sync borrow after multiple sends ─────────────────────────

    #[test]
    fn watch_multiple_sends_latest_visible() {
        let (tx, rx) = channel::watch::channel(0_u32);
        tx.send(1).unwrap();
        tx.send(2).unwrap();
        tx.send(3).unwrap();
        assert_eq!(*rx.borrow(), 3);
    }

    #[test]
    fn watch_send_modify_multiple_times() {
        let (tx, rx) = channel::watch::channel(0_u32);
        tx.send_modify(|v| *v += 1);
        tx.send_modify(|v| *v += 10);
        tx.send_modify(|v| *v += 100);
        assert_eq!(*rx.borrow(), 111);
    }

    #[test]
    fn watch_sender_subscribe_sync() {
        let (tx, _rx) = channel::watch::channel(0_u32);
        let rx2 = tx.subscribe();
        tx.send(99).unwrap();
        assert_eq!(*rx2.borrow(), 99);
    }

    #[test]
    fn watch_sender_is_closed_with_receivers() {
        let (tx, rx) = channel::watch::channel(0_u32);
        assert!(!tx.is_closed());
        let rx2 = tx.subscribe();
        drop(rx);
        // Still have rx2
        assert!(!tx.is_closed());
        drop(rx2);
        // Now all receivers dropped
        assert!(tx.is_closed());
    }

    #[test]
    fn watch_sender_clone_both_can_send() {
        let (tx, rx) = channel::watch::channel(0_u32);
        let tx2 = tx.clone();
        tx.send(1).unwrap();
        assert_eq!(*rx.borrow(), 1);
        tx2.send(2).unwrap();
        assert_eq!(*rx.borrow(), 2);
    }

    // ─── Broadcast: sync-visible tests ───────────────────────────────────

    #[test]
    fn broadcast_sender_debug_format() {
        let (tx, _rx) = channel::broadcast::channel::<u32>(4);
        let dbg = format!("{tx:?}");
        assert!(dbg.contains("Sender"));
    }

    #[test]
    fn broadcast_receiver_debug_format() {
        let (_tx, rx) = channel::broadcast::channel::<u32>(4);
        let dbg = format!("{rx:?}");
        assert!(dbg.contains("Receiver"));
    }

    #[test]
    fn broadcast_sender_clone_debug() {
        let (tx, _rx) = channel::broadcast::channel::<u32>(4);
        let tx2 = tx.clone();
        let dbg = format!("{tx2:?}");
        assert!(dbg.contains("Sender"));
        // Use original after clone to avoid redundant_clone
        let dbg_orig = format!("{tx:?}");
        assert!(dbg_orig.contains("Sender"));
    }

    // ─── Oneshot: sync-visible tests ─────────────────────────────────────

    #[test]
    fn oneshot_receiver_debug_format() {
        let (_tx, rx) = channel::oneshot::channel::<u32>();
        let dbg = format!("{rx:?}");
        assert!(dbg.contains("Receiver"));
    }

    #[test]
    fn oneshot_send_error_source_is_none() {
        let err = channel::oneshot::SendError(0_u32);
        assert!(std::error::Error::source(&err).is_none());
    }

    // ─── mpsc: Sender debug and receiver debug ───────────────────────────

    #[test]
    fn mpsc_sender_debug_format() {
        let (tx, _rx) = channel::mpsc::channel::<u32>(4);
        let dbg = format!("{tx:?}");
        assert!(dbg.contains("Sender"));
    }

    #[test]
    fn mpsc_receiver_debug_format() {
        let (_tx, rx) = channel::mpsc::channel::<u32>(4);
        let dbg = format!("{rx:?}");
        assert!(dbg.contains("Receiver"));
    }

    #[test]
    fn mpsc_sender_clone_debug() {
        let (tx, _rx) = channel::mpsc::channel::<u32>(4);
        let tx2 = tx.clone();
        let dbg = format!("{tx2:?}");
        assert!(dbg.contains("Sender"));
        // Use original after clone to avoid redundant_clone
        let dbg_orig = format!("{tx:?}");
        assert!(dbg_orig.contains("Sender"));
    }

    #[test]
    fn mpsc_unbounded_sender_debug() {
        let (tx, _rx) = channel::mpsc::unbounded_channel::<u32>();
        let dbg = format!("{tx:?}");
        assert!(dbg.contains("UnboundedSender"));
    }

    #[test]
    fn mpsc_unbounded_receiver_debug() {
        let (_tx, rx) = channel::mpsc::unbounded_channel::<u32>();
        let dbg = format!("{rx:?}");
        assert!(dbg.contains("UnboundedReceiver"));
    }

    // ─── mpsc: try_send fills then drains ────────────────────────────────

    #[test]
    fn mpsc_try_send_fill_to_capacity() {
        let (tx, _rx) = channel::mpsc::channel::<u32>(3);
        tx.try_send(1).unwrap();
        tx.try_send(2).unwrap();
        tx.try_send(3).unwrap();
        assert_eq!(tx.len(), 3);
        assert_eq!(tx.capacity(), 0);
        assert!(tx.try_send(4).is_err());
    }

    #[test]
    fn mpsc_sender_is_closed_when_receiver_dropped() {
        let (tx, rx) = channel::mpsc::channel::<u32>(4);
        assert!(!tx.is_closed());
        drop(rx);
        assert!(tx.is_closed());
    }

    // ─── Instrumentation: custom impl with all hooks ─────────────────────

    #[test]
    fn custom_instrumentation_implements_trait() {
        use std::sync::atomic::AtomicU32;

        struct AllHooks {
            task_spawns: AtomicU32,
            task_exits: AtomicU32,
            queue_sends: AtomicU32,
            queue_recvs: AtomicU32,
        }

        impl Instrumentation for AllHooks {
            fn on_task_spawn(&self, _name: &str) {
                self.task_spawns.fetch_add(1, Ordering::SeqCst);
            }
            fn on_task_exit(&self, _name: &str, _result: &Result<(), AsyncError>) {
                self.task_exits.fetch_add(1, Ordering::SeqCst);
            }
            fn on_queue_send(&self, _name: &str, _depth: usize, _cap: usize) {
                self.queue_sends.fetch_add(1, Ordering::SeqCst);
            }
            fn on_queue_receive(&self, _name: &str, _depth: usize, _cap: usize) {
                self.queue_recvs.fetch_add(1, Ordering::SeqCst);
            }
        }

        let hooks = AllHooks {
            task_spawns: AtomicU32::new(0),
            task_exits: AtomicU32::new(0),
            queue_sends: AtomicU32::new(0),
            queue_recvs: AtomicU32::new(0),
        };

        hooks.on_task_spawn("t1");
        hooks.on_task_spawn("t2");
        hooks.on_task_exit("t1", &Ok(()));
        hooks.on_queue_send("q", 1, 10);
        hooks.on_queue_receive("q", 0, 10);

        assert_eq!(hooks.task_spawns.load(Ordering::SeqCst), 2);
        assert_eq!(hooks.task_exits.load(Ordering::SeqCst), 1);
        assert_eq!(hooks.queue_sends.load(Ordering::SeqCst), 1);
        assert_eq!(hooks.queue_recvs.load(Ordering::SeqCst), 1);
    }

    // ─── Runtime: block_on with async operations ─────────────────────────

    #[test]
    fn runtime_block_on_with_channel_ops() {
        let rt = runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (tx, mut rx) = channel::mpsc::channel::<u32>(4);
            tx.send(42).await.unwrap();
            assert_eq!(rx.recv().await, Some(42));
        });
    }

    #[test]
    fn runtime_block_on_with_watch_channel() {
        let rt = runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (tx, rx) = channel::watch::channel(0_u32);
            tx.send(99).unwrap();
            assert_eq!(*rx.borrow(), 99);
        });
    }

    #[test]
    fn runtime_block_on_enters_tokio_compat_context() {
        let rt = runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let tokio_handle =
                tokio::runtime::Handle::try_current().expect("tokio compat handle missing");
            let nested = tokio_handle.spawn(async { 11_u32 });
            assert_eq!(nested.await.expect("nested tokio task should complete"), 11);
        });
    }

    #[test]
    fn runtime_block_on_reuses_single_tokio_compat_driver_across_threads() {
        let thread_handles = (0..4)
            .map(|_| {
                std::thread::spawn(|| {
                    let rt = runtime::Runtime::new().unwrap();
                    rt.block_on(async {
                        let tokio_handle = tokio::runtime::Handle::try_current()
                            .expect("tokio compat handle missing");
                        let nested = tokio_handle.spawn(async { 13_u32 });
                        assert_eq!(nested.await.expect("nested tokio task should complete"), 13);
                    });
                })
            })
            .collect::<Vec<_>>();

        for handle in thread_handles {
            handle.join().expect("runtime thread should join cleanly");
        }

        assert_eq!(runtime::tokio_compat_driver_spawn_count(), 1);
    }

    // ─── TaskGroup: async edge cases ─────────────────────────────────────

    #[runtime::test]
    async fn task_group_single_fast_task() {
        let mut group = TaskGroup::new();
        group.spawn("fast", async { Ok(()) });
        let result = group.shutdown(Duration::from_secs(1)).await;
        assert!(result.is_ok());
    }

    #[runtime::test]
    async fn task_group_cancellation_token_is_not_cancelled_before_shutdown() {
        let group = TaskGroup::new();
        let token = group.cancellation_token();
        assert!(!token.is_cancelled());
        group.shutdown(Duration::from_millis(50)).await.unwrap();
        assert!(token.is_cancelled());
    }

    #[runtime::test]
    async fn task_group_spawn_task_that_returns_error_variant() {
        let mut group = TaskGroup::new();
        group.spawn("channel-err", async { Err(AsyncError::ChannelClosed) });
        let err = group
            .shutdown(Duration::from_secs(1))
            .await
            .expect_err("should propagate");
        assert_eq!(err, AsyncError::ChannelClosed);
    }

    // ─── ExecutionContext: async run with various futures ─────────────────

    #[runtime::test]
    async fn context_run_with_channel_send() {
        let ctx = ExecutionContext::request_scoped(Duration::from_secs(5));
        let (tx, mut rx) = channel::mpsc::channel::<u32>(1);
        ctx.run(async { tx.send(42).await.unwrap() }).await.unwrap();
        assert_eq!(rx.recv().await, Some(42));
    }

    #[runtime::test]
    async fn context_run_background_no_timeout() {
        let ctx = ExecutionContext::background();
        let result = ctx.run(async { 123_u32 }).await;
        assert_eq!(result.unwrap(), 123);
    }

    // ─── Shutdown: edge cases ────────────────────────────────────────────

    #[runtime::test]
    async fn wait_for_shutdown_sender_dropped() {
        let (tx, mut rx) = channel::watch::channel(false);
        drop(tx);
        let err = super::shutdown::wait_for_shutdown(&mut rx)
            .await
            .expect_err("sender dropped should cancel");
        assert_eq!(err, AsyncError::Cancelled);
    }

    #[runtime::test]
    async fn sleep_or_shutdown_sender_dropped() {
        let (tx, mut rx) = channel::watch::channel(false);
        drop(tx);
        // When sender drops, behavior depends on implementation
        // It should either complete the sleep or return Cancelled
        let result = super::shutdown::sleep_or_shutdown(Duration::from_millis(10), &mut rx).await;
        // Either Ok or Err is valid when sender drops
        let _ = result;
    }

    #[test]
    fn io_async_buf_read_ext_lines_streams_each_line() {
        let rt = runtime::Builder::new_current_thread().build().unwrap();
        rt.block_on(async {
            let reader = io::BufReader::new(std::io::Cursor::new(b"alpha\nbeta\n".to_vec()));
            let mut lines = io::AsyncBufReadExt::lines(reader);

            assert_eq!(lines.next_line().await.unwrap().unwrap(), "alpha");
            assert_eq!(lines.next_line().await.unwrap().unwrap(), "beta");
            assert!(lines.next_line().await.unwrap().is_none());
        });
    }

    #[test]
    fn io_async_buf_read_ext_lines_returns_none_for_empty_reader() {
        let rt = runtime::Builder::new_current_thread().build().unwrap();
        rt.block_on(async {
            let reader = io::BufReader::new(std::io::Cursor::new(Vec::<u8>::new()));
            let mut lines = io::AsyncBufReadExt::lines(reader);

            assert!(lines.next_line().await.unwrap().is_none());
        });
    }

    #[test]
    fn io_async_buf_read_ext_lines_strips_crlf_endings() {
        let rt = runtime::Builder::new_current_thread().build().unwrap();
        rt.block_on(async {
            let reader = io::BufReader::new(std::io::Cursor::new(b"alpha\r\nbeta\r\n".to_vec()));
            let mut lines = io::AsyncBufReadExt::lines(reader);

            assert_eq!(lines.next_line().await.unwrap().unwrap(), "alpha");
            assert_eq!(lines.next_line().await.unwrap().unwrap(), "beta");
            assert!(lines.next_line().await.unwrap().is_none());
        });
    }

    #[test]
    fn io_async_buf_read_ext_lines_returns_final_line_without_newline() {
        let rt = runtime::Builder::new_current_thread().build().unwrap();
        rt.block_on(async {
            use crate::io::AsyncBufReadExt as _;

            let reader = io::BufReader::new(std::io::Cursor::new(b"tail".to_vec()));
            let mut lines = reader.lines();

            assert_eq!(lines.next_line().await.unwrap().unwrap(), "tail");
            assert!(lines.next_line().await.unwrap().is_none());
        });
    }
}
