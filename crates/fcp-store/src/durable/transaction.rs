//! Keep admitted durable transactions alive independently of their caller.

use std::sync::Arc;

use tokio::sync::Mutex;

/// Acquire both ordering barriers before dispatching blocking work. Once
/// admitted, the worker owns the guards until the complete transaction returns;
/// dropping its async waiter cannot expose half-published state or admit a
/// second writer while the first one is still changing durable storage.
pub(crate) async fn run<T, R, F>(
    state: Arc<Mutex<T>>,
    writer: Arc<Mutex<()>>,
    commit: F,
) -> Result<R, tokio::task::JoinError>
where
    T: Send + 'static,
    R: Send + 'static,
    F: FnOnce(&mut T) -> R + Send + 'static,
{
    let writer_guard = writer.lock_owned().await;
    let mut state_guard = state.lock_owned().await;
    tokio::task::spawn_blocking(move || {
        let result = commit(&mut state_guard);
        drop(state_guard);
        drop(writer_guard);
        result
    })
    .await
}

#[cfg(test)]
mod tests {
    use std::future::{Future, poll_fn};
    use std::sync::mpsc;
    use std::task::Poll;
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn dropping_waiter_preserves_commit_and_blocks_readers_and_later_writers() {
        let state = Arc::new(Mutex::new(Vec::new()));
        let writer = Arc::new(Mutex::new(()));
        let (entered, started) = tokio::sync::oneshot::channel();
        let (release, resume) = mpsc::channel();
        let waiter = tokio::spawn(run(
            Arc::clone(&state),
            Arc::clone(&writer),
            move |state| {
                entered.send(()).unwrap();
                resume.recv_timeout(Duration::from_secs(5)).unwrap();
                state.push(1);
            },
        ));
        started.await.unwrap();
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        assert!(state.try_lock().is_err());
        assert!(writer.try_lock().is_err());

        let mut next = Box::pin(run(
            Arc::clone(&state),
            Arc::clone(&writer),
            |state| {
                assert_eq!(state.as_slice(), &[1]);
                state.push(2);
            },
        ));
        poll_fn(|cx| {
            assert!(next.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;

        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), next)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.lock().await.as_slice(), &[1, 2]);
    }

    #[tokio::test]
    async fn cancellation_before_admission_does_not_run_the_transaction() {
        let state = Arc::new(Mutex::new(0));
        let writer = Arc::new(Mutex::new(()));
        let held = Arc::clone(&writer).lock_owned().await;
        let mut waiter = Box::pin(run(
            Arc::clone(&state),
            Arc::clone(&writer),
            |state| *state = 1,
        ));
        poll_fn(|cx| {
            assert!(waiter.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(waiter);
        drop(held);
        assert_eq!(*state.lock().await, 0);
        assert!(writer.try_lock().is_ok());
    }

    #[tokio::test]
    async fn admitted_transaction_owns_state_after_all_external_handles_are_dropped() {
        let state = Arc::new(Mutex::new(false));
        let weak = Arc::downgrade(&state);
        let writer = Arc::new(Mutex::new(()));
        let (entered, started) = tokio::sync::oneshot::channel();
        let (release, resume) = mpsc::channel();
        let (finished, settled) = tokio::sync::oneshot::channel();
        let waiter = tokio::spawn(run(state, writer, move |state| {
            entered.send(()).unwrap();
            resume.recv_timeout(Duration::from_secs(5)).unwrap();
            *state = true;
            finished.send(()).unwrap();
        }));
        started.await.unwrap();
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        let retained = weak.upgrade().expect("admitted worker owns state");
        assert!(retained.try_lock().is_err());

        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), settled)
            .await
            .unwrap()
            .unwrap();
        assert!(*retained.lock().await);
    }
}
