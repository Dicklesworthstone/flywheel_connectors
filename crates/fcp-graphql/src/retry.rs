//! Retry policy helpers.

use std::time::Duration;

use rand::Rng;

use crate::error::GraphqlClientError;

/// Retry decision result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryDecision {
    /// Retry after a delay.
    RetryAfter(Duration),
    /// Do not retry.
    DoNotRetry,
}

/// Retry strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryStrategy {
    /// Never retry.
    Never,
    /// Retry only for idempotent operations.
    IdempotentOnly,
    /// Retry regardless of idempotency.
    Always,
}

/// Retry policy configuration.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Maximum number of attempts (including the initial attempt).
    pub max_attempts: usize,
    /// Base delay for exponential backoff.
    pub base_delay: Duration,
    /// Maximum permitted delay between retries. A longer provider minimum
    /// refuses retry rather than sending before the provider allows it.
    pub max_delay: Duration,
    /// Maximum jitter to add to delays.
    pub max_jitter: Duration,
    /// Retry strategy.
    pub strategy: RetryStrategy,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_delay: Duration::from_millis(200),
            max_delay: Duration::from_secs(5),
            max_jitter: Duration::from_millis(150),
            strategy: RetryStrategy::IdempotentOnly,
        }
    }
}

impl RetryPolicy {
    /// Decide whether to retry based on the error and attempt count.
    #[must_use]
    pub fn decide(
        &self,
        error: &GraphqlClientError,
        attempt: usize,
        idempotent: bool,
    ) -> RetryDecision {
        if attempt >= self.max_attempts {
            return RetryDecision::DoNotRetry;
        }
        if !error.is_retryable() {
            return RetryDecision::DoNotRetry;
        }

        match self.strategy {
            RetryStrategy::Never => RetryDecision::DoNotRetry,
            RetryStrategy::IdempotentOnly if !idempotent => RetryDecision::DoNotRetry,
            _ => {
                let provider_minimum = if let GraphqlClientError::HttpStatus {
                    retry_after: Some(delay),
                    ..
                } = error
                {
                    if *delay > self.max_delay {
                        return RetryDecision::DoNotRetry;
                    }
                    *delay
                } else {
                    Duration::ZERO
                };

                let base_ms = u64::try_from(self.base_delay.as_millis()).unwrap_or(u64::MAX);
                let exp = 2_u64
                    .saturating_pow(u32::try_from(attempt.saturating_sub(1)).unwrap_or(u32::MAX));
                let mut delay_ms = base_ms.saturating_mul(exp);
                let max_ms = u64::try_from(self.max_delay.as_millis()).unwrap_or(u64::MAX);
                if delay_ms > max_ms {
                    delay_ms = max_ms;
                }
                let jitter_ms = if self.max_jitter.as_millis() > 0 {
                    let mut rng = rand::thread_rng();
                    let jitter_max = u64::try_from(self.max_jitter.as_millis()).unwrap_or(u64::MAX);
                    rng.gen_range(0..=jitter_max)
                } else {
                    0
                };
                let delay_ms = delay_ms.saturating_add(jitter_ms).min(max_ms);
                RetryDecision::RetryAfter(Duration::from_millis(delay_ms).max(provider_minimum))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{GraphqlClientError, HttpErrorInfo};
    use fcp_async_core::http::StatusCode;

    fn retryable_error() -> GraphqlClientError {
        GraphqlClientError::Http(HttpErrorInfo {
            message: "timeout".into(),
            status_code: None,
            is_timeout: true,
            is_connect: false,
            is_request: false,
        })
    }

    fn non_retryable_error() -> GraphqlClientError {
        GraphqlClientError::Json("bad json".into())
    }

    // ---- RetryPolicy defaults ----

    #[test]
    fn default_policy() {
        let p = RetryPolicy::default();
        assert_eq!(p.max_attempts, 3);
        assert_eq!(p.base_delay, Duration::from_millis(200));
        assert_eq!(p.max_delay, Duration::from_secs(5));
        assert_eq!(p.max_jitter, Duration::from_millis(150));
        assert_eq!(p.strategy, RetryStrategy::IdempotentOnly);
    }

    // ---- decide: max_attempts boundary ----

    #[test]
    fn decide_at_max_attempts_returns_do_not_retry() {
        let p = RetryPolicy::default();
        let decision = p.decide(&retryable_error(), 3, true);
        assert_eq!(decision, RetryDecision::DoNotRetry);
    }

    #[test]
    fn decide_beyond_max_attempts_returns_do_not_retry() {
        let p = RetryPolicy::default();
        let decision = p.decide(&retryable_error(), 100, true);
        assert_eq!(decision, RetryDecision::DoNotRetry);
    }

    // ---- decide: non-retryable error ----

    #[test]
    fn decide_non_retryable_error_returns_do_not_retry() {
        let p = RetryPolicy::default();
        let decision = p.decide(&non_retryable_error(), 1, true);
        assert_eq!(decision, RetryDecision::DoNotRetry);
    }

    // ---- decide: strategy=Never ----

    #[test]
    fn decide_never_strategy_returns_do_not_retry() {
        let p = RetryPolicy {
            strategy: RetryStrategy::Never,
            ..RetryPolicy::default()
        };
        let decision = p.decide(&retryable_error(), 1, true);
        assert_eq!(decision, RetryDecision::DoNotRetry);
    }

    // ---- decide: strategy=IdempotentOnly ----

    #[test]
    fn decide_idempotent_only_non_idempotent_returns_do_not_retry() {
        let p = RetryPolicy::default();
        let decision = p.decide(&retryable_error(), 1, false);
        assert_eq!(decision, RetryDecision::DoNotRetry);
    }

    #[test]
    fn decide_idempotent_only_idempotent_returns_retry() {
        let p = RetryPolicy {
            max_jitter: Duration::ZERO,
            ..RetryPolicy::default()
        };
        let decision = p.decide(&retryable_error(), 1, true);
        match decision {
            RetryDecision::RetryAfter(d) => {
                assert_eq!(d, Duration::from_millis(200)); // 2^0 * 200
            }
            RetryDecision::DoNotRetry => panic!("should retry"),
        }
    }

    // ---- decide: strategy=Always ----

    #[test]
    fn decide_always_strategy_retries_non_idempotent() {
        let p = RetryPolicy {
            strategy: RetryStrategy::Always,
            max_jitter: Duration::ZERO,
            ..RetryPolicy::default()
        };
        let decision = p.decide(&retryable_error(), 1, false);
        match decision {
            RetryDecision::RetryAfter(_) => {}
            RetryDecision::DoNotRetry => panic!("should retry with Always strategy"),
        }
    }

    // ---- decide: exponential backoff ----

    #[test]
    fn decide_exponential_backoff_doubles() {
        let p = RetryPolicy {
            max_jitter: Duration::ZERO,
            max_delay: Duration::from_secs(60),
            base_delay: Duration::from_millis(100),
            ..RetryPolicy::default()
        };

        // attempt 1 → 2^0 * 100 = 100ms
        match p.decide(&retryable_error(), 1, true) {
            RetryDecision::RetryAfter(d) => assert_eq!(d, Duration::from_millis(100)),
            RetryDecision::DoNotRetry => panic!("should retry"),
        }

        // attempt 2 → 2^1 * 100 = 200ms
        match p.decide(&retryable_error(), 2, true) {
            RetryDecision::RetryAfter(d) => assert_eq!(d, Duration::from_millis(200)),
            RetryDecision::DoNotRetry => panic!("should retry"),
        }
    }

    // ---- decide: max_delay cap ----

    #[test]
    fn decide_caps_at_max_delay() {
        let p = RetryPolicy {
            max_attempts: 100,
            base_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(5),
            max_jitter: Duration::ZERO,
            strategy: RetryStrategy::Always,
        };
        // attempt 10 → 2^9 * 1000 = 512_000ms, capped at 5000ms
        match p.decide(&retryable_error(), 10, true) {
            RetryDecision::RetryAfter(d) => assert_eq!(d, Duration::from_secs(5)),
            RetryDecision::DoNotRetry => panic!("should retry"),
        }
    }

    #[test]
    fn decide_caps_jittered_delay_at_max_delay() {
        let p = RetryPolicy {
            max_attempts: 10,
            base_delay: Duration::from_millis(500),
            max_delay: Duration::from_millis(500),
            max_jitter: Duration::from_millis(500),
            strategy: RetryStrategy::Always,
        };

        for _ in 0..20 {
            match p.decide(&retryable_error(), 1, true) {
                RetryDecision::RetryAfter(d) => assert_eq!(d, Duration::from_millis(500)),
                RetryDecision::DoNotRetry => panic!("should retry"),
            }
        }
    }

    // ---- decide: jitter ----

    #[test]
    fn decide_with_jitter_adds_delay() {
        let p = RetryPolicy {
            max_jitter: Duration::from_millis(100),
            base_delay: Duration::from_millis(200),
            ..RetryPolicy::default()
        };
        // With jitter, delay should be >= base_delay (200ms)
        match p.decide(&retryable_error(), 1, true) {
            RetryDecision::RetryAfter(d) => {
                assert!(d >= Duration::from_millis(200));
                assert!(d <= Duration::from_millis(300));
            }
            RetryDecision::DoNotRetry => panic!("should retry"),
        }
    }

    // ---- decide: 429 with retry_after ----

    #[test]
    fn decide_retryable_http_status() {
        let p = RetryPolicy {
            max_jitter: Duration::ZERO,
            max_delay: Duration::from_secs(30),
            ..RetryPolicy::default()
        };
        let err = GraphqlClientError::HttpStatus {
            status: StatusCode::TOO_MANY_REQUESTS,
            body: String::new(),
            retry_after: Some(Duration::from_secs(10)),
        };
        match p.decide(&err, 1, true) {
            RetryDecision::RetryAfter(delay) => assert_eq!(delay, Duration::from_secs(10)),
            RetryDecision::DoNotRetry => panic!("429 should be retryable"),
        }
    }

    #[test]
    fn decide_retry_after_above_policy_refuses_retry() {
        let p = RetryPolicy {
            max_delay: Duration::from_secs(5),
            ..RetryPolicy::default()
        };
        let err = GraphqlClientError::HttpStatus {
            status: StatusCode::TOO_MANY_REQUESTS,
            body: String::new(),
            retry_after: Some(Duration::from_secs(60)),
        };

        assert_eq!(p.decide(&err, 1, true), RetryDecision::DoNotRetry);
    }

    #[test]
    fn provider_minimum_never_shortens_local_backoff() {
        let policy = RetryPolicy {
            base_delay: Duration::from_secs(2),
            max_jitter: Duration::ZERO,
            ..RetryPolicy::default()
        };
        for minimum in [Duration::ZERO, Duration::from_secs(1)] {
            let error = GraphqlClientError::HttpStatus {
                status: StatusCode::SERVICE_UNAVAILABLE,
                body: String::new(),
                retry_after: Some(minimum),
            };
            assert_eq!(
                policy.decide(&error, 1, true),
                RetryDecision::RetryAfter(Duration::from_secs(2))
            );
        }
    }

    #[test]
    fn provider_minimum_preserves_precision_and_policy_boundary() {
        let policy = RetryPolicy {
            max_jitter: Duration::ZERO,
            ..RetryPolicy::default()
        };
        for minimum in [Duration::from_nanos(200_000_001), policy.max_delay] {
            let error = GraphqlClientError::HttpStatus {
                status: StatusCode::TOO_MANY_REQUESTS,
                body: String::new(),
                retry_after: Some(minimum),
            };
            assert_eq!(
                policy.decide(&error, 1, true),
                RetryDecision::RetryAfter(minimum)
            );
            assert_eq!(policy.decide(&error, 1, false), RetryDecision::DoNotRetry);
        }
        for minimum in [policy.max_delay + Duration::from_nanos(1), Duration::MAX] {
            let error = GraphqlClientError::HttpStatus {
                status: StatusCode::TOO_MANY_REQUESTS,
                body: String::new(),
                retry_after: Some(minimum),
            };
            assert_eq!(policy.decide(&error, 1, true), RetryDecision::DoNotRetry);
        }
    }

    #[test]
    fn decide_delay_arithmetic_saturates() {
        let p = RetryPolicy {
            max_attempts: 3,
            base_delay: Duration::from_millis(u64::MAX),
            max_delay: Duration::from_millis(u64::MAX),
            max_jitter: Duration::from_millis(u64::MAX),
            strategy: RetryStrategy::Always,
        };

        match p.decide(&retryable_error(), 1, true) {
            RetryDecision::RetryAfter(delay) => {
                assert_eq!(delay, Duration::from_millis(u64::MAX));
            }
            RetryDecision::DoNotRetry => panic!("should retry"),
        }
    }

    // ---- RetryDecision equality ----

    #[test]
    fn retry_decision_eq() {
        assert_eq!(RetryDecision::DoNotRetry, RetryDecision::DoNotRetry);
        assert_eq!(
            RetryDecision::RetryAfter(Duration::from_millis(100)),
            RetryDecision::RetryAfter(Duration::from_millis(100))
        );
        assert_ne!(
            RetryDecision::RetryAfter(Duration::from_millis(100)),
            RetryDecision::DoNotRetry
        );
    }

    // ---- RetryStrategy equality ----

    #[test]
    fn retry_strategy_eq() {
        assert_eq!(RetryStrategy::Never, RetryStrategy::Never);
        assert_eq!(RetryStrategy::IdempotentOnly, RetryStrategy::IdempotentOnly);
        assert_eq!(RetryStrategy::Always, RetryStrategy::Always);
        assert_ne!(RetryStrategy::Never, RetryStrategy::Always);
    }

    // ---- RetryDecision Debug/Clone ----

    #[test]
    fn retry_decision_debug() {
        let d1 = RetryDecision::DoNotRetry;
        let d2 = RetryDecision::RetryAfter(Duration::from_millis(500));
        assert!(format!("{d1:?}").contains("DoNotRetry"));
        assert!(format!("{d2:?}").contains("RetryAfter"));
    }

    #[test]
    fn retry_decision_clone() {
        let d = RetryDecision::RetryAfter(Duration::from_millis(200));
        let cloned = d;
        assert_eq!(d, cloned);
    }

    // ---- RetryStrategy Debug/Clone ----

    #[test]
    fn retry_strategy_debug() {
        assert!(format!("{:?}", RetryStrategy::Never).contains("Never"));
        assert!(format!("{:?}", RetryStrategy::IdempotentOnly).contains("IdempotentOnly"));
        assert!(format!("{:?}", RetryStrategy::Always).contains("Always"));
    }

    #[test]
    fn retry_strategy_clone() {
        let s = RetryStrategy::Always;
        let cloned = s;
        assert_eq!(s, cloned);
    }

    // ---- RetryPolicy additional tests ----

    #[test]
    fn retry_policy_debug() {
        let p = RetryPolicy::default();
        let dbg = format!("{p:?}");
        assert!(dbg.contains("RetryPolicy"));
        assert!(dbg.contains("max_attempts"));
    }

    #[test]
    fn retry_policy_clone() {
        let p = RetryPolicy {
            max_attempts: 5,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
            max_jitter: Duration::from_millis(50),
            strategy: RetryStrategy::Always,
        };
        let cloned = p.clone();
        assert_eq!(cloned.max_attempts, p.max_attempts);
        assert_eq!(cloned.base_delay, p.base_delay);
        assert_eq!(cloned.max_delay, p.max_delay);
        assert_eq!(cloned.max_jitter, p.max_jitter);
        assert_eq!(cloned.strategy, p.strategy);
    }

    #[test]
    fn decide_first_attempt_returns_base_delay() {
        let p = RetryPolicy {
            max_jitter: Duration::ZERO,
            base_delay: Duration::from_millis(500),
            ..RetryPolicy::default()
        };
        match p.decide(&retryable_error(), 1, true) {
            RetryDecision::RetryAfter(d) => assert_eq!(d, Duration::from_millis(500)),
            RetryDecision::DoNotRetry => panic!("should retry"),
        }
    }

    #[test]
    fn decide_zero_max_attempts_always_do_not_retry() {
        let p = RetryPolicy {
            max_attempts: 0,
            ..RetryPolicy::default()
        };
        let decision = p.decide(&retryable_error(), 0, true);
        assert_eq!(decision, RetryDecision::DoNotRetry);
    }

    #[test]
    fn decide_single_attempt_policy() {
        let p = RetryPolicy {
            max_attempts: 1,
            ..RetryPolicy::default()
        };
        // attempt 1 >= max_attempts(1) → do not retry
        let decision = p.decide(&retryable_error(), 1, true);
        assert_eq!(decision, RetryDecision::DoNotRetry);
    }

    #[test]
    fn decide_retryable_502_status() {
        let p = RetryPolicy {
            max_jitter: Duration::ZERO,
            ..RetryPolicy::default()
        };
        let err = GraphqlClientError::HttpStatus {
            status: StatusCode::BAD_GATEWAY,
            body: String::new(),
            retry_after: None,
        };
        match p.decide(&err, 1, true) {
            RetryDecision::RetryAfter(_) => {}
            RetryDecision::DoNotRetry => panic!("502 should be retryable"),
        }
    }

    // ---- decide: exponential backoff progression ----

    #[test]
    fn decide_backoff_third_attempt() {
        let p = RetryPolicy {
            max_attempts: 10,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(60),
            max_jitter: Duration::ZERO,
            strategy: RetryStrategy::Always,
        };
        // attempt 3 → 2^2 * 100 = 400ms
        match p.decide(&retryable_error(), 3, true) {
            RetryDecision::RetryAfter(d) => assert_eq!(d, Duration::from_millis(400)),
            RetryDecision::DoNotRetry => panic!("should retry"),
        }
    }

    #[test]
    fn decide_backoff_fourth_attempt() {
        let p = RetryPolicy {
            max_attempts: 10,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(60),
            max_jitter: Duration::ZERO,
            strategy: RetryStrategy::Always,
        };
        // attempt 4 → 2^3 * 100 = 800ms
        match p.decide(&retryable_error(), 4, true) {
            RetryDecision::RetryAfter(d) => assert_eq!(d, Duration::from_millis(800)),
            RetryDecision::DoNotRetry => panic!("should retry"),
        }
    }

    // ---- decide: max_delay boundary cases ----

    #[test]
    fn decide_delay_exactly_at_max() {
        let p = RetryPolicy {
            max_attempts: 10,
            base_delay: Duration::from_millis(500),
            max_delay: Duration::from_millis(500),
            max_jitter: Duration::ZERO,
            strategy: RetryStrategy::Always,
        };
        // attempt 1 → 2^0 * 500 = 500ms, which equals max_delay
        match p.decide(&retryable_error(), 1, true) {
            RetryDecision::RetryAfter(d) => assert_eq!(d, Duration::from_millis(500)),
            RetryDecision::DoNotRetry => panic!("should retry"),
        }
    }

    #[test]
    fn decide_zero_base_delay() {
        let p = RetryPolicy {
            max_attempts: 5,
            base_delay: Duration::ZERO,
            max_delay: Duration::from_secs(10),
            max_jitter: Duration::ZERO,
            strategy: RetryStrategy::Always,
        };
        // 0 * 2^n = 0
        match p.decide(&retryable_error(), 1, true) {
            RetryDecision::RetryAfter(d) => assert_eq!(d, Duration::ZERO),
            RetryDecision::DoNotRetry => panic!("should retry"),
        }
    }

    // ---- decide: 503 service unavailable ----

    #[test]
    fn decide_retryable_503_status() {
        let p = RetryPolicy {
            max_jitter: Duration::ZERO,
            ..RetryPolicy::default()
        };
        let err = GraphqlClientError::HttpStatus {
            status: StatusCode::SERVICE_UNAVAILABLE,
            body: String::new(),
            retry_after: None,
        };
        match p.decide(&err, 1, true) {
            RetryDecision::RetryAfter(_) => {}
            RetryDecision::DoNotRetry => panic!("503 should be retryable"),
        }
    }

    // ---- decide: 504 gateway timeout ----

    #[test]
    fn decide_retryable_504_status() {
        let p = RetryPolicy {
            max_jitter: Duration::ZERO,
            ..RetryPolicy::default()
        };
        let err = GraphqlClientError::HttpStatus {
            status: StatusCode::GATEWAY_TIMEOUT,
            body: String::new(),
            retry_after: None,
        };
        match p.decide(&err, 1, true) {
            RetryDecision::RetryAfter(_) => {}
            RetryDecision::DoNotRetry => panic!("504 should be retryable"),
        }
    }

    // ---- decide: non-retryable variants ----

    #[test]
    fn decide_non_retryable_protocol_error() {
        let p = RetryPolicy::default();
        let err = GraphqlClientError::Protocol {
            message: "bad frame".into(),
        };
        let decision = p.decide(&err, 1, true);
        assert_eq!(decision, RetryDecision::DoNotRetry);
    }

    #[test]
    fn decide_non_retryable_schema_validation_error() {
        let p = RetryPolicy::default();
        let err = GraphqlClientError::SchemaValidation {
            message: "invalid".into(),
            errors: vec![],
        };
        let decision = p.decide(&err, 1, true);
        assert_eq!(decision, RetryDecision::DoNotRetry);
    }

    #[test]
    fn decide_non_retryable_retries_exhausted_error() {
        let p = RetryPolicy::default();
        let err = GraphqlClientError::RetriesExhausted { attempts: 3 };
        let decision = p.decide(&err, 1, true);
        assert_eq!(decision, RetryDecision::DoNotRetry);
    }

    #[test]
    fn decide_non_retryable_graphql_errors() {
        let p = RetryPolicy::default();
        let err = GraphqlClientError::GraphqlErrors { errors: vec![] };
        let decision = p.decide(&err, 1, true);
        assert_eq!(decision, RetryDecision::DoNotRetry);
    }

    // ---- decide: 400 not retryable ----

    #[test]
    fn decide_non_retryable_400_status() {
        let p = RetryPolicy::default();
        let err = GraphqlClientError::HttpStatus {
            status: StatusCode::BAD_REQUEST,
            body: "bad".into(),
            retry_after: None,
        };
        let decision = p.decide(&err, 1, true);
        assert_eq!(decision, RetryDecision::DoNotRetry);
    }

    // ---- decide: jitter range bounds ----

    #[test]
    fn decide_jitter_bounded_by_max() {
        let p = RetryPolicy {
            max_jitter: Duration::from_millis(50),
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(60),
            ..RetryPolicy::default()
        };
        for _ in 0..20 {
            match p.decide(&retryable_error(), 1, true) {
                RetryDecision::RetryAfter(d) => {
                    assert!(d >= Duration::from_millis(100));
                    assert!(d <= Duration::from_millis(150));
                }
                RetryDecision::DoNotRetry => panic!("should retry"),
            }
        }
    }

    // ---- RetryDecision inequality ----

    #[test]
    fn retry_decision_retry_after_different_durations() {
        let a = RetryDecision::RetryAfter(Duration::from_millis(100));
        let b = RetryDecision::RetryAfter(Duration::from_millis(200));
        assert_ne!(a, b);
    }

    // ---- RetryStrategy inequality ----

    #[test]
    fn retry_strategy_inequality_pairs() {
        assert_ne!(RetryStrategy::Never, RetryStrategy::IdempotentOnly);
        assert_ne!(RetryStrategy::IdempotentOnly, RetryStrategy::Always);
        assert_ne!(RetryStrategy::Always, RetryStrategy::Never);
    }

    // ---- RetryPolicy custom configs ----

    #[test]
    fn retry_policy_large_max_attempts() {
        let p = RetryPolicy {
            max_attempts: 1000,
            base_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(10),
            max_jitter: Duration::ZERO,
            strategy: RetryStrategy::Always,
        };
        match p.decide(&retryable_error(), 999, true) {
            RetryDecision::RetryAfter(d) => assert_eq!(d, Duration::from_millis(10)),
            RetryDecision::DoNotRetry => panic!("should retry"),
        }
    }

    #[test]
    fn retry_policy_max_attempts_boundary() {
        let p = RetryPolicy {
            max_attempts: 5,
            ..RetryPolicy::default()
        };
        // attempt 4 < 5: should decide to retry (if retryable)
        let d4 = p.decide(&retryable_error(), 4, true);
        assert_ne!(d4, RetryDecision::DoNotRetry);
        // attempt 5 >= 5: should NOT retry
        let d5 = p.decide(&retryable_error(), 5, true);
        assert_eq!(d5, RetryDecision::DoNotRetry);
    }

    // ---- decide: Always strategy retries idempotent too ----

    #[test]
    fn decide_always_strategy_retries_idempotent() {
        let p = RetryPolicy {
            strategy: RetryStrategy::Always,
            max_jitter: Duration::ZERO,
            ..RetryPolicy::default()
        };
        match p.decide(&retryable_error(), 1, true) {
            RetryDecision::RetryAfter(_) => {}
            RetryDecision::DoNotRetry => panic!("should retry"),
        }
    }

    // ---- decide: connect error is retryable ----

    #[test]
    fn decide_connect_error_is_retryable() {
        let p = RetryPolicy {
            max_jitter: Duration::ZERO,
            ..RetryPolicy::default()
        };
        let err = GraphqlClientError::Http(HttpErrorInfo {
            message: "connection refused".into(),
            status_code: None,
            is_timeout: false,
            is_connect: true,
            is_request: false,
        });
        match p.decide(&err, 1, true) {
            RetryDecision::RetryAfter(_) => {}
            RetryDecision::DoNotRetry => panic!("connect error should be retryable"),
        }
    }

    // ---- RetryDecision: Copy semantics ----

    #[test]
    fn retry_decision_copy_semantics() {
        let d = RetryDecision::RetryAfter(Duration::from_millis(300));
        let copied = d;
        let also_copied = d;
        assert_eq!(copied, also_copied);
    }

    // ---- RetryStrategy: Copy semantics ----

    #[test]
    fn retry_strategy_copy_semantics() {
        let s = RetryStrategy::IdempotentOnly;
        let copied = s;
        let also_copied = s;
        assert_eq!(copied, also_copied);
    }

    // ---- decide: request error retryable ----

    #[test]
    fn decide_request_error_is_retryable() {
        let p = RetryPolicy {
            max_jitter: Duration::ZERO,
            ..RetryPolicy::default()
        };
        let err = GraphqlClientError::Http(HttpErrorInfo {
            message: "request failed".into(),
            status_code: None,
            is_timeout: false,
            is_connect: false,
            is_request: true,
        });
        match p.decide(&err, 1, true) {
            RetryDecision::RetryAfter(_) => {}
            RetryDecision::DoNotRetry => panic!("request error should be retryable"),
        }
    }

    // ---- decide: attempt 0 behavior ----

    #[test]
    fn decide_attempt_zero_with_positive_max_retries() {
        let p = RetryPolicy {
            max_attempts: 3,
            max_jitter: Duration::ZERO,
            ..RetryPolicy::default()
        };
        // attempt 0 < 3: should retry
        match p.decide(&retryable_error(), 0, true) {
            RetryDecision::RetryAfter(_) => {}
            RetryDecision::DoNotRetry => panic!("attempt 0 should retry"),
        }
    }

    // ---- decide: backoff progression fifth attempt ----

    #[test]
    fn decide_backoff_fifth_attempt() {
        let p = RetryPolicy {
            max_attempts: 10,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(60),
            max_jitter: Duration::ZERO,
            strategy: RetryStrategy::Always,
        };
        // attempt 5 -> 2^4 * 100 = 1600ms
        match p.decide(&retryable_error(), 5, true) {
            RetryDecision::RetryAfter(d) => assert_eq!(d, Duration::from_millis(1600)),
            RetryDecision::DoNotRetry => panic!("should retry"),
        }
    }

    // ---- decide: max_delay zero ----

    #[test]
    fn decide_zero_max_delay_caps_at_zero() {
        let p = RetryPolicy {
            max_attempts: 5,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::ZERO,
            max_jitter: Duration::ZERO,
            strategy: RetryStrategy::Always,
        };
        match p.decide(&retryable_error(), 1, true) {
            RetryDecision::RetryAfter(d) => assert_eq!(d, Duration::ZERO),
            RetryDecision::DoNotRetry => panic!("should retry"),
        }
    }

    // ---- decide: non-retryable Json error with Always strategy ----

    #[test]
    fn decide_json_error_not_retryable_even_with_always() {
        let p = RetryPolicy {
            strategy: RetryStrategy::Always,
            ..RetryPolicy::default()
        };
        let decision = p.decide(&non_retryable_error(), 1, true);
        assert_eq!(decision, RetryDecision::DoNotRetry);
    }

    // ---- RetryPolicy: field access ----

    #[test]
    fn retry_policy_field_access() {
        let p = RetryPolicy {
            max_attempts: 7,
            base_delay: Duration::from_millis(250),
            max_delay: Duration::from_secs(15),
            max_jitter: Duration::from_millis(75),
            strategy: RetryStrategy::Never,
        };
        assert_eq!(p.max_attempts, 7);
        assert_eq!(p.base_delay, Duration::from_millis(250));
        assert_eq!(p.max_delay, Duration::from_secs(15));
        assert_eq!(p.max_jitter, Duration::from_millis(75));
        assert_eq!(p.strategy, RetryStrategy::Never);
    }

    // ---- decide: 429 retryable with Always + non-idempotent ----

    #[test]
    fn decide_429_retryable_always_non_idempotent() {
        let p = RetryPolicy {
            strategy: RetryStrategy::Always,
            max_jitter: Duration::ZERO,
            ..RetryPolicy::default()
        };
        let err = GraphqlClientError::HttpStatus {
            status: StatusCode::TOO_MANY_REQUESTS,
            body: String::new(),
            retry_after: Some(Duration::from_secs(5)),
        };
        match p.decide(&err, 1, false) {
            RetryDecision::RetryAfter(_) => {}
            RetryDecision::DoNotRetry => panic!("429 with Always strategy should retry"),
        }
    }
}
