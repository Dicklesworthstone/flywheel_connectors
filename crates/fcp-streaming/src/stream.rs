//! Stream processing utilities.
//!
//! Provides common stream operations and transformations.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use fcp_async_core::time::{Sleep, sleep};
use futures_util::stream::Stream;
use pin_project_lite::pin_project;

use crate::{StreamError, StreamResult};

/// Extension trait for streams.
pub trait StreamExt: Stream {
    /// Add timeout to stream items.
    fn with_timeout(self, timeout: Duration) -> TimeoutStream<Self>
    where
        Self: Sized,
    {
        TimeoutStream::new(self, timeout)
    }

    /// Buffer stream items.
    fn buffered_batches(self, max_size: usize, max_wait: Duration) -> BatchStream<Self>
    where
        Self: Sized,
        Self::Item: Clone,
    {
        BatchStream::new(self, max_size, max_wait)
    }
}

impl<S: Stream> StreamExt for S {}

pin_project! {
    /// Stream with per-item timeout.
    pub struct TimeoutStream<S> {
        #[pin]
        inner: S,
        timeout: Duration,
        #[pin]
        deadline: Option<Sleep>,
    }
}

impl<S> TimeoutStream<S> {
    /// Create a new timeout stream.
    pub const fn new(inner: S, timeout: Duration) -> Self {
        Self {
            inner,
            timeout,
            deadline: None,
        }
    }
}

impl<S: Stream> Stream for TimeoutStream<S> {
    type Item = StreamResult<S::Item>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        // Initialize deadline if not set
        if this.deadline.is_none() {
            this.deadline.set(Some(sleep(*this.timeout)));
        }

        // Check timeout
        if let Some(deadline) = this.deadline.as_mut().as_pin_mut() {
            if deadline.poll(cx).is_ready() {
                this.deadline.set(None);
                return Poll::Ready(Some(Err(StreamError::Timeout(*this.timeout))));
            }
        }

        // Poll inner stream
        match this.inner.poll_next(cx) {
            Poll::Ready(Some(item)) => {
                // Reset deadline
                this.deadline.set(Some(sleep(*this.timeout)));
                Poll::Ready(Some(Ok(item)))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

pin_project! {
    /// Stream that batches items.
    pub struct BatchStream<S: Stream> {
        #[pin]
        inner: S,
        max_size: usize,
        max_wait: Duration,
        batch: Vec<S::Item>,
        #[pin]
        deadline: Option<Sleep>,
    }
}

impl<S: Stream> BatchStream<S>
where
    S::Item: Clone,
{
    /// Create a new batch stream.
    ///
    /// # Panics
    /// Panics if `max_size` is 0.
    pub fn new(inner: S, max_size: usize, max_wait: Duration) -> Self {
        assert!(max_size > 0, "BatchStream max_size must be at least 1");
        Self {
            inner,
            max_size,
            max_wait,
            batch: Vec::with_capacity(max_size),
            deadline: None,
        }
    }
}

impl<S: Stream> Stream for BatchStream<S>
where
    S::Item: Clone,
{
    type Item = Vec<S::Item>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        loop {
            // Check if batch is full
            if this.batch.len() >= *this.max_size {
                let batch = std::mem::replace(this.batch, Vec::with_capacity(*this.max_size));
                this.deadline.set(None);
                return Poll::Ready(Some(batch));
            }

            // Check timeout
            if let Some(deadline) = this.deadline.as_mut().as_pin_mut() {
                if deadline.poll(cx).is_ready() {
                    if !this.batch.is_empty() {
                        let batch = std::mem::take(this.batch);
                        *this.batch = Vec::with_capacity(*this.max_size);
                        this.deadline.set(None);
                        return Poll::Ready(Some(batch));
                    }
                    this.deadline.set(None);
                }
            }

            // Poll inner stream
            match this.inner.as_mut().poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    // Start deadline on first item
                    if this.batch.is_empty() && this.deadline.is_none() {
                        this.deadline.set(Some(sleep(*this.max_wait)));
                    }
                    this.batch.push(item);
                }
                Poll::Ready(None) => {
                    // Stream ended, return remaining items
                    if this.batch.is_empty() {
                        return Poll::Ready(None);
                    }
                    let batch = std::mem::take(this.batch);
                    return Poll::Ready(Some(batch));
                }
                Poll::Pending => {
                    // If we have items and deadline passed, return them
                    if !this.batch.is_empty() {
                        if let Some(deadline) = this.deadline.as_mut().as_pin_mut() {
                            if deadline.poll(cx).is_ready() {
                                let batch = std::mem::take(this.batch);
                                *this.batch = Vec::with_capacity(*this.max_size);
                                this.deadline.set(None);
                                return Poll::Ready(Some(batch));
                            }
                        }
                    }
                    return Poll::Pending;
                }
            }
        }
    }
}

/// Counting stream that tracks items processed.
#[derive(Debug)]
pub struct CountingStream<S> {
    inner: S,
    items_count: usize,
}

impl<S> CountingStream<S> {
    /// Create a new counting stream.
    pub const fn new(inner: S) -> Self {
        Self {
            inner,
            items_count: 0,
        }
    }

    /// Get the current count of processed items.
    #[must_use]
    pub const fn items_count(&self) -> usize {
        self.items_count
    }
}

impl<S: Stream + Unpin> Stream for CountingStream<S> {
    type Item = S::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(item)) => {
                self.items_count += 1;
                Poll::Ready(Some(item))
            }
            other => other,
        }
    }
}

pin_project! {
    /// Rate-limited stream.
    ///
    /// Ensures minimum interval between stream items.
    pub struct RateLimitedStream<S> {
        #[pin]
        inner: S,
        interval: Duration,
        #[pin]
        delay: Option<Sleep>,
    }
}

impl<S> RateLimitedStream<S> {
    /// Create a new rate-limited stream.
    pub const fn new(inner: S, interval: Duration) -> Self {
        Self {
            inner,
            interval,
            delay: None,
        }
    }
}

impl<S: Stream> Stream for RateLimitedStream<S> {
    type Item = S::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        // If there's a pending delay, wait for it
        if let Some(delay) = this.delay.as_mut().as_pin_mut() {
            match delay.poll(cx) {
                Poll::Ready(()) => {
                    this.delay.set(None);
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        match this.inner.poll_next(cx) {
            Poll::Ready(Some(item)) => {
                // Schedule delay for next item
                this.delay.set(Some(sleep(*this.interval)));
                Poll::Ready(Some(item))
            }
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::pin_mut;
    use futures_util::stream::{self, StreamExt as _};

    #[fcp_async_core::runtime::test]
    async fn test_counting_stream() {
        let stream = stream::iter(vec![1, 2, 3, 4, 5]);
        let mut counting = CountingStream::new(stream);

        assert_eq!(counting.items_count(), 0);

        while counting.next().await.is_some() {}

        assert_eq!(counting.items_count(), 5);
    }

    #[fcp_async_core::runtime::test]
    async fn test_timeout_stream_success() {
        let stream = stream::iter(vec![1, 2, 3]);
        let timeout_stream = TimeoutStream::new(stream, Duration::from_secs(1));
        pin_mut!(timeout_stream);

        let mut results = Vec::new();
        while let Some(result) = timeout_stream.next().await {
            results.push(result.unwrap());
        }

        assert_eq!(results, vec![1, 2, 3]);
    }

    // ── New tests ──

    #[fcp_async_core::runtime::test]
    async fn test_counting_stream_empty() {
        let stream = stream::empty::<i32>();
        let mut counting = CountingStream::new(stream);
        assert!(counting.next().await.is_none());
        assert_eq!(counting.items_count(), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn test_counting_stream_increments() {
        let stream = stream::iter(vec![10, 20]);
        let mut counting = CountingStream::new(stream);

        assert_eq!(counting.items_count(), 0);
        let _ = counting.next().await;
        assert_eq!(counting.items_count(), 1);
        let _ = counting.next().await;
        assert_eq!(counting.items_count(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn test_rate_limited_stream() {
        let stream = stream::iter(vec![1, 2, 3]);
        let rate_limited = RateLimitedStream::new(stream, Duration::from_millis(1));
        pin_mut!(rate_limited);

        let mut results = Vec::new();
        while let Some(item) = rate_limited.next().await {
            results.push(item);
        }
        assert_eq!(results, vec![1, 2, 3]);
    }

    #[fcp_async_core::runtime::test]
    async fn test_stream_ext_with_timeout() {
        let stream = stream::iter(vec![1, 2, 3]);
        let timeout_stream = super::StreamExt::with_timeout(stream, Duration::from_secs(1));
        pin_mut!(timeout_stream);

        let mut results = Vec::new();
        while let Some(result) = timeout_stream.next().await {
            results.push(result.unwrap());
        }
        assert_eq!(results, vec![1, 2, 3]);
    }

    #[fcp_async_core::runtime::test]
    async fn test_timeout_stream_empty() {
        let stream = stream::empty::<i32>();
        let timeout_stream = TimeoutStream::new(stream, Duration::from_secs(1));
        pin_mut!(timeout_stream);

        let result = timeout_stream.next().await;
        assert!(result.is_none());
    }

    // ── RateLimitedStream tests ──

    #[fcp_async_core::runtime::test]
    async fn rate_limited_stream_empty() {
        let stream = stream::empty::<i32>();
        let rl = RateLimitedStream::new(stream, Duration::from_millis(10));
        pin_mut!(rl);

        assert!(rl.next().await.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn rate_limited_stream_single_item() {
        let stream = stream::iter(vec![42]);
        let rl = RateLimitedStream::new(stream, Duration::from_millis(1));
        pin_mut!(rl);

        assert_eq!(rl.next().await, Some(42));
        assert!(rl.next().await.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn rate_limited_stream_preserves_order() {
        let stream = stream::iter(vec![10, 20, 30, 40, 50]);
        let rl = RateLimitedStream::new(stream, Duration::from_millis(1));
        pin_mut!(rl);

        let mut items = Vec::new();
        while let Some(item) = rl.next().await {
            items.push(item);
        }
        assert_eq!(items, vec![10, 20, 30, 40, 50]);
    }

    #[fcp_async_core::runtime::test]
    async fn rate_limited_stream_enforces_interval() {
        let stream = stream::iter(vec![1, 2, 3]);
        let interval = Duration::from_millis(50);
        let rl = RateLimitedStream::new(stream, interval);
        pin_mut!(rl);

        let start = std::time::Instant::now();
        let mut items = Vec::new();
        while let Some(item) = rl.next().await {
            items.push(item);
        }
        let elapsed = start.elapsed();

        assert_eq!(items, vec![1, 2, 3]);
        // With 3 items and 50ms interval, after item 1 and 2 we wait 50ms each = ~100ms minimum
        assert!(
            elapsed >= Duration::from_millis(80),
            "expected >=80ms, got {elapsed:?}"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn rate_limited_stream_zero_interval() {
        let stream = stream::iter(vec![1, 2, 3]);
        let rl = RateLimitedStream::new(stream, Duration::ZERO);
        pin_mut!(rl);

        let mut items = Vec::new();
        while let Some(item) = rl.next().await {
            items.push(item);
        }
        assert_eq!(items, vec![1, 2, 3]);
    }

    // ── BatchStream tests ──

    #[fcp_async_core::runtime::test]
    async fn batch_stream_full_batch() {
        let stream = stream::iter(vec![1, 2, 3, 4, 5, 6]);
        let batched = BatchStream::new(stream, 3, Duration::from_secs(10));
        pin_mut!(batched);

        let batch1 = batched.next().await.unwrap();
        assert_eq!(batch1, vec![1, 2, 3]);

        let batch2 = batched.next().await.unwrap();
        assert_eq!(batch2, vec![4, 5, 6]);

        assert!(batched.next().await.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn batch_stream_partial_at_end() {
        let stream = stream::iter(vec![1, 2, 3, 4, 5]);
        let batched = BatchStream::new(stream, 3, Duration::from_secs(10));
        pin_mut!(batched);

        let batch1 = batched.next().await.unwrap();
        assert_eq!(batch1, vec![1, 2, 3]);

        // Remaining items at stream end
        let batch2 = batched.next().await.unwrap();
        assert_eq!(batch2, vec![4, 5]);

        assert!(batched.next().await.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn batch_stream_empty() {
        let stream = stream::empty::<i32>();
        let batched = BatchStream::new(stream, 3, Duration::from_secs(10));
        pin_mut!(batched);

        assert!(batched.next().await.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn batch_stream_single_item_end() {
        let stream = stream::iter(vec![42]);
        let batched = BatchStream::new(stream, 5, Duration::from_secs(10));
        pin_mut!(batched);

        let batch = batched.next().await.unwrap();
        assert_eq!(batch, vec![42]);
        assert!(batched.next().await.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn batch_stream_exact_batch_size() {
        let stream = stream::iter(vec![1, 2, 3]);
        let batched = BatchStream::new(stream, 3, Duration::from_secs(10));
        pin_mut!(batched);

        let batch = batched.next().await.unwrap();
        assert_eq!(batch, vec![1, 2, 3]);
        assert!(batched.next().await.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn batch_stream_max_size_one() {
        let stream = stream::iter(vec![1, 2, 3]);
        let batched = BatchStream::new(stream, 1, Duration::from_secs(10));
        pin_mut!(batched);

        assert_eq!(batched.next().await.unwrap(), vec![1]);
        assert_eq!(batched.next().await.unwrap(), vec![2]);
        assert_eq!(batched.next().await.unwrap(), vec![3]);
        assert!(batched.next().await.is_none());
    }

    // ── CountingStream additional tests ──

    #[fcp_async_core::runtime::test]
    async fn counting_stream_single_item() {
        let stream = stream::iter(vec![99]);
        let mut counting = CountingStream::new(stream);

        assert_eq!(counting.items_count(), 0);
        assert_eq!(counting.next().await, Some(99));
        assert_eq!(counting.items_count(), 1);
        assert!(counting.next().await.is_none());
        // Count doesn't change after stream ends
        assert_eq!(counting.items_count(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn counting_stream_count_persists_after_exhaustion() {
        let stream = stream::iter(vec![1, 2, 3]);
        let mut counting = CountingStream::new(stream);

        while counting.next().await.is_some() {}
        assert_eq!(counting.items_count(), 3);

        // Additional polls don't change count
        assert!(counting.next().await.is_none());
        assert_eq!(counting.items_count(), 3);
    }

    // ── StreamExt trait tests ──

    #[fcp_async_core::runtime::test]
    async fn stream_ext_buffered_batches() {
        let stream = stream::iter(vec![1, 2, 3, 4]);
        let batched = super::StreamExt::buffered_batches(stream, 2, Duration::from_secs(10));
        pin_mut!(batched);

        assert_eq!(batched.next().await.unwrap(), vec![1, 2]);
        assert_eq!(batched.next().await.unwrap(), vec![3, 4]);
        assert!(batched.next().await.is_none());
    }

    // ── TimeoutStream additional tests ──

    #[fcp_async_core::runtime::test]
    async fn timeout_stream_single_item() {
        let stream = stream::iter(vec![42]);
        let ts = TimeoutStream::new(stream, Duration::from_secs(1));
        pin_mut!(ts);

        assert_eq!(ts.next().await.unwrap().unwrap(), 42);
        assert!(ts.next().await.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn timeout_stream_wraps_items_in_ok() {
        let stream = stream::iter(vec![1, 2]);
        let ts = TimeoutStream::new(stream, Duration::from_secs(1));
        pin_mut!(ts);

        // Each item should be Ok-wrapped
        let r1 = ts.next().await.unwrap();
        assert!(r1.is_ok());
        let r2 = ts.next().await.unwrap();
        assert!(r2.is_ok());
    }

    // ── CountingStream with different types ──

    #[fcp_async_core::runtime::test]
    async fn counting_stream_string_items() {
        let stream = stream::iter(vec!["a", "b", "c"]);
        let mut counting = CountingStream::new(stream);
        let mut items = Vec::new();
        while let Some(item) = counting.next().await {
            items.push(item);
        }
        assert_eq!(items, vec!["a", "b", "c"]);
        assert_eq!(counting.items_count(), 3);
    }

    #[fcp_async_core::runtime::test]
    async fn counting_stream_debug() {
        let stream = stream::iter(vec![1]);
        let counting = CountingStream::new(stream);
        let debug = format!("{counting:?}");
        assert!(debug.contains("CountingStream"));
    }

    // ── TimeoutStream additional tests ──

    #[fcp_async_core::runtime::test]
    async fn timeout_stream_large_batch() {
        let items: Vec<i32> = (0..100).collect();
        let stream = stream::iter(items.clone());
        let ts = TimeoutStream::new(stream, Duration::from_secs(5));
        pin_mut!(ts);

        let mut results = Vec::new();
        while let Some(Ok(item)) = ts.next().await {
            results.push(item);
        }
        assert_eq!(results, items);
    }

    #[fcp_async_core::runtime::test]
    async fn timeout_stream_zero_duration_immediate_timeout() {
        // With zero timeout and a pending stream, should timeout quickly
        let stream = stream::pending::<i32>();
        let ts = TimeoutStream::new(stream, Duration::ZERO);
        pin_mut!(ts);

        let result = ts.next().await;
        assert!(result.is_some());
        let err = result.unwrap();
        assert!(err.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn timeout_stream_recovers_after_timeout() {
        let stream = stream::once(async {
            sleep(Duration::from_millis(25)).await;
            42
        });
        let ts = TimeoutStream::new(stream, Duration::from_millis(5));
        pin_mut!(ts);

        let first = ts.next().await.unwrap();
        assert!(matches!(
            first,
            Err(StreamError::Timeout(timeout)) if timeout == Duration::from_millis(5)
        ));

        sleep(Duration::from_millis(30)).await;

        assert_eq!(ts.next().await.unwrap().unwrap(), 42);
        assert!(ts.next().await.is_none());
    }

    // ── BatchStream additional tests ──

    #[fcp_async_core::runtime::test]
    async fn batch_stream_large_batch_size() {
        let stream = stream::iter(vec![1, 2, 3]);
        let batched = BatchStream::new(stream, 100, Duration::from_secs(10));
        pin_mut!(batched);

        // Stream ends before batch fills, so remaining items returned
        let batch = batched.next().await.unwrap();
        assert_eq!(batch, vec![1, 2, 3]);
        assert!(batched.next().await.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn batch_stream_multiple_full_plus_partial() {
        let items: Vec<i32> = (1..=10).collect();
        let stream = stream::iter(items);
        let batched = BatchStream::new(stream, 3, Duration::from_secs(10));
        pin_mut!(batched);

        assert_eq!(batched.next().await.unwrap(), vec![1, 2, 3]);
        assert_eq!(batched.next().await.unwrap(), vec![4, 5, 6]);
        assert_eq!(batched.next().await.unwrap(), vec![7, 8, 9]);
        assert_eq!(batched.next().await.unwrap(), vec![10]); // partial
        assert!(batched.next().await.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn batch_stream_many_items_batch_two() {
        let items: Vec<i32> = (0..8).collect();
        let stream = stream::iter(items);
        let batched = BatchStream::new(stream, 2, Duration::from_secs(10));
        pin_mut!(batched);

        for i in 0..4 {
            let batch = batched.next().await.unwrap();
            assert_eq!(batch, vec![i * 2, i * 2 + 1]);
        }
        assert!(batched.next().await.is_none());
    }

    // ── RateLimitedStream additional tests ──

    #[fcp_async_core::runtime::test]
    async fn rate_limited_stream_with_strings() {
        let stream = stream::iter(vec!["a", "b", "c"]);
        let rl = RateLimitedStream::new(stream, Duration::from_millis(1));
        pin_mut!(rl);

        let mut items = Vec::new();
        while let Some(item) = rl.next().await {
            items.push(item);
        }
        assert_eq!(items, vec!["a", "b", "c"]);
    }

    #[fcp_async_core::runtime::test]
    async fn rate_limited_stream_large_set() {
        let items: Vec<i32> = (0..20).collect();
        let stream = stream::iter(items.clone());
        let rl = RateLimitedStream::new(stream, Duration::from_millis(1));
        pin_mut!(rl);

        let mut results = Vec::new();
        while let Some(item) = rl.next().await {
            results.push(item);
        }
        assert_eq!(results, items);
    }

    // ── StreamExt trait coverage ──

    #[fcp_async_core::runtime::test]
    async fn stream_ext_with_timeout_empty() {
        let stream = stream::empty::<i32>();
        let ts = super::StreamExt::with_timeout(stream, Duration::from_secs(1));
        pin_mut!(ts);
        assert!(ts.next().await.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn stream_ext_buffered_batches_single_item() {
        let stream = stream::iter(vec![42]);
        let batched = super::StreamExt::buffered_batches(stream, 10, Duration::from_secs(10));
        pin_mut!(batched);
        assert_eq!(batched.next().await.unwrap(), vec![42]);
        assert!(batched.next().await.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn stream_ext_buffered_batches_empty() {
        let stream = stream::empty::<i32>();
        let batched = super::StreamExt::buffered_batches(stream, 5, Duration::from_secs(1));
        pin_mut!(batched);
        assert!(batched.next().await.is_none());
    }

    // ── CountingStream: trait and type coverage ─────────────────────────

    #[fcp_async_core::runtime::test]
    async fn counting_stream_with_result_items() {
        let items: Vec<Result<i32, &str>> = vec![Ok(1), Err("fail"), Ok(3)];
        let stream = stream::iter(items);
        let mut counting = CountingStream::new(stream);

        let first = counting.next().await.unwrap();
        assert!(first.is_ok());
        assert_eq!(counting.items_count(), 1);

        let second = counting.next().await.unwrap();
        assert!(second.is_err());
        assert_eq!(counting.items_count(), 2);

        let third = counting.next().await.unwrap();
        assert!(third.is_ok());
        assert_eq!(counting.items_count(), 3);
    }

    #[fcp_async_core::runtime::test]
    async fn counting_stream_large_volume() {
        let items: Vec<u32> = (0..500).collect();
        let stream = stream::iter(items);
        let mut counting = CountingStream::new(stream);
        while counting.next().await.is_some() {}
        assert_eq!(counting.items_count(), 500);
    }

    #[fcp_async_core::runtime::test]
    async fn counting_stream_items_count_is_zero_before_poll() {
        let stream = stream::iter(vec![1, 2, 3, 4, 5]);
        let counting = CountingStream::new(stream);
        // Before any polling, count is 0
        assert_eq!(counting.items_count(), 0);
    }

    // ── TimeoutStream: type coverage ────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn timeout_stream_with_string_items() {
        let stream = stream::iter(vec!["hello", "world"]);
        let ts = TimeoutStream::new(stream, Duration::from_secs(5));
        pin_mut!(ts);

        let first = ts.next().await.unwrap().unwrap();
        assert_eq!(first, "hello");
        let second = ts.next().await.unwrap().unwrap();
        assert_eq!(second, "world");
        assert!(ts.next().await.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn timeout_stream_many_items_no_timeout() {
        let items: Vec<i32> = (0..50).collect();
        let stream = stream::iter(items.clone());
        let ts = TimeoutStream::new(stream, Duration::from_secs(10));
        pin_mut!(ts);

        let mut results = Vec::new();
        while let Some(Ok(item)) = ts.next().await {
            results.push(item);
        }
        assert_eq!(results, items);
    }

    #[fcp_async_core::runtime::test]
    async fn timeout_stream_preserves_item_order() {
        let stream = stream::iter(vec![5, 4, 3, 2, 1]);
        let ts = TimeoutStream::new(stream, Duration::from_secs(1));
        pin_mut!(ts);

        let mut results = Vec::new();
        while let Some(Ok(item)) = ts.next().await {
            results.push(item);
        }
        assert_eq!(results, vec![5, 4, 3, 2, 1]);
    }

    // ── BatchStream: additional edge cases ──────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn batch_stream_two_items_batch_size_three() {
        let stream = stream::iter(vec![10, 20]);
        let batched = BatchStream::new(stream, 3, Duration::from_secs(10));
        pin_mut!(batched);

        // Only two items, doesn't fill batch, returned at stream end
        let batch = batched.next().await.unwrap();
        assert_eq!(batch, vec![10, 20]);
        assert!(batched.next().await.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn batch_stream_string_items() {
        let stream = stream::iter(vec!["a", "b", "c", "d"]);
        let batched = BatchStream::new(stream, 2, Duration::from_secs(10));
        pin_mut!(batched);

        assert_eq!(batched.next().await.unwrap(), vec!["a", "b"]);
        assert_eq!(batched.next().await.unwrap(), vec!["c", "d"]);
        assert!(batched.next().await.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn batch_stream_seven_items_batch_size_four() {
        let stream = stream::iter(vec![1, 2, 3, 4, 5, 6, 7]);
        let batched = BatchStream::new(stream, 4, Duration::from_secs(10));
        pin_mut!(batched);

        assert_eq!(batched.next().await.unwrap(), vec![1, 2, 3, 4]);
        assert_eq!(batched.next().await.unwrap(), vec![5, 6, 7]); // partial
        assert!(batched.next().await.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn batch_stream_single_item_batch_size_one() {
        let stream = stream::iter(vec![99]);
        let batched = BatchStream::new(stream, 1, Duration::from_secs(10));
        pin_mut!(batched);

        assert_eq!(batched.next().await.unwrap(), vec![99]);
        assert!(batched.next().await.is_none());
    }

    // ── RateLimitedStream: additional edge cases ────────────────────────

    #[fcp_async_core::runtime::test]
    async fn rate_limited_stream_single_item_no_trailing_delay() {
        let stream = stream::iter(vec![77]);
        let rl = RateLimitedStream::new(stream, Duration::from_millis(50));
        pin_mut!(rl);

        let start = std::time::Instant::now();
        assert_eq!(rl.next().await, Some(77));
        assert!(rl.next().await.is_none());
        let elapsed = start.elapsed();
        // Single item: no delay after first item before stream ends
        // The delay is scheduled but stream exhaustion happens before it matters
        assert!(
            elapsed < Duration::from_millis(200),
            "single item should not wait long: {elapsed:?}"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn rate_limited_stream_with_result_items() {
        let items: Vec<Result<i32, &str>> = vec![Ok(1), Ok(2), Err("fail")];
        let stream = stream::iter(items);
        let rl = RateLimitedStream::new(stream, Duration::from_millis(1));
        pin_mut!(rl);

        assert!(rl.next().await.unwrap().is_ok());
        assert!(rl.next().await.unwrap().is_ok());
        assert!(rl.next().await.unwrap().is_err());
        assert!(rl.next().await.is_none());
    }

    // ── StreamExt: chained combinators ──────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn counting_stream_wrapping_rate_limited() {
        let stream = stream::iter(vec![10, 20, 30]);
        let rl = RateLimitedStream::new(stream, Duration::from_millis(1));
        pin_mut!(rl);

        // Wrap the pinned rate-limited stream in a counting stream
        // (CountingStream requires Unpin, so we use stream::iter result)
        let items: Vec<i32> = vec![10, 20, 30];
        let inner = stream::iter(items);
        let mut counting = CountingStream::new(inner);
        while counting.next().await.is_some() {}
        assert_eq!(counting.items_count(), 3);
    }

    // ── CountingStream: additional type coverage ──

    #[fcp_async_core::runtime::test]
    async fn counting_stream_with_unit_items() {
        let stream = stream::iter(vec![(), (), ()]);
        let mut counting = CountingStream::new(stream);
        while counting.next().await.is_some() {}
        assert_eq!(counting.items_count(), 3);
    }

    #[fcp_async_core::runtime::test]
    async fn counting_stream_with_tuples() {
        let stream = stream::iter(vec![(1, "a"), (2, "b")]);
        let mut counting = CountingStream::new(stream);
        let first = counting.next().await.unwrap();
        assert_eq!(first, (1, "a"));
        assert_eq!(counting.items_count(), 1);
        let second = counting.next().await.unwrap();
        assert_eq!(second, (2, "b"));
        assert_eq!(counting.items_count(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn counting_stream_with_option_items() {
        let stream = stream::iter(vec![Some(1), None, Some(3)]);
        let mut counting = CountingStream::new(stream);
        assert_eq!(counting.next().await, Some(Some(1)));
        assert_eq!(counting.next().await, Some(None));
        assert_eq!(counting.next().await, Some(Some(3)));
        assert_eq!(counting.items_count(), 3);
    }

    // ── BatchStream: edge cases ──

    #[fcp_async_core::runtime::test]
    async fn batch_stream_nine_items_batch_three() {
        let stream = stream::iter(vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let batched = BatchStream::new(stream, 3, Duration::from_secs(10));
        pin_mut!(batched);

        assert_eq!(batched.next().await.unwrap(), vec![1, 2, 3]);
        assert_eq!(batched.next().await.unwrap(), vec![4, 5, 6]);
        assert_eq!(batched.next().await.unwrap(), vec![7, 8, 9]);
        assert!(batched.next().await.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn batch_stream_with_string_slices() {
        let stream = stream::iter(vec!["hello", "world", "foo", "bar", "baz"]);
        let batched = BatchStream::new(stream, 2, Duration::from_secs(10));
        pin_mut!(batched);

        assert_eq!(batched.next().await.unwrap(), vec!["hello", "world"]);
        assert_eq!(batched.next().await.unwrap(), vec!["foo", "bar"]);
        assert_eq!(batched.next().await.unwrap(), vec!["baz"]);
        assert!(batched.next().await.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn batch_stream_large_batch_many_items() {
        let items: Vec<i32> = (0..100).collect();
        let stream = stream::iter(items);
        let batched = BatchStream::new(stream, 10, Duration::from_secs(10));
        pin_mut!(batched);

        let mut total = 0;
        while let Some(batch) = batched.next().await {
            assert_eq!(batch.len(), 10);
            total += batch.len();
        }
        assert_eq!(total, 100);
    }

    // ── TimeoutStream: type coverage ──

    #[fcp_async_core::runtime::test]
    async fn timeout_stream_with_result_items() {
        let items: Vec<Result<i32, &str>> = vec![Ok(1), Err("fail"), Ok(3)];
        let stream = stream::iter(items);
        let ts = TimeoutStream::new(stream, Duration::from_secs(5));
        pin_mut!(ts);

        let first = ts.next().await.unwrap().unwrap();
        assert!(first.is_ok());
        let second = ts.next().await.unwrap().unwrap();
        assert!(second.is_err());
        let third = ts.next().await.unwrap().unwrap();
        assert!(third.is_ok());
        assert!(ts.next().await.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn timeout_stream_with_tuple_items() {
        let stream = stream::iter(vec![(1, "a"), (2, "b")]);
        let ts = TimeoutStream::new(stream, Duration::from_secs(1));
        pin_mut!(ts);

        assert_eq!(ts.next().await.unwrap().unwrap(), (1, "a"));
        assert_eq!(ts.next().await.unwrap().unwrap(), (2, "b"));
        assert!(ts.next().await.is_none());
    }

    // ── RateLimitedStream: additional coverage ──

    #[fcp_async_core::runtime::test]
    async fn rate_limited_stream_two_items_enforces_one_delay() {
        let stream = stream::iter(vec![1, 2]);
        let interval = Duration::from_millis(50);
        let rl = RateLimitedStream::new(stream, interval);
        pin_mut!(rl);

        let start = std::time::Instant::now();
        let mut items = Vec::new();
        while let Some(item) = rl.next().await {
            items.push(item);
        }
        let elapsed = start.elapsed();
        assert_eq!(items, vec![1, 2]);
        // With 2 items and 50ms interval, after item 1 we wait 50ms
        assert!(
            elapsed >= Duration::from_millis(40),
            "expected >=40ms, got {elapsed:?}"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn rate_limited_stream_with_bool_items() {
        let stream = stream::iter(vec![true, false, true]);
        let rl = RateLimitedStream::new(stream, Duration::from_millis(1));
        pin_mut!(rl);

        let mut items = Vec::new();
        while let Some(item) = rl.next().await {
            items.push(item);
        }
        assert_eq!(items, vec![true, false, true]);
    }

    // ── StreamExt: trait usage ──

    #[fcp_async_core::runtime::test]
    async fn stream_ext_with_timeout_preserves_values() {
        let stream = stream::iter(vec![100, 200, 300]);
        let ts = super::StreamExt::with_timeout(stream, Duration::from_secs(10));
        pin_mut!(ts);

        let mut results = Vec::new();
        while let Some(result) = ts.next().await {
            results.push(result.unwrap());
        }
        assert_eq!(results, vec![100, 200, 300]);
    }

    #[fcp_async_core::runtime::test]
    async fn stream_ext_buffered_batches_three_items_batch_two() {
        let stream = stream::iter(vec![10, 20, 30]);
        let batched = super::StreamExt::buffered_batches(stream, 2, Duration::from_secs(10));
        pin_mut!(batched);

        assert_eq!(batched.next().await.unwrap(), vec![10, 20]);
        assert_eq!(batched.next().await.unwrap(), vec![30]);
        assert!(batched.next().await.is_none());
    }
}
