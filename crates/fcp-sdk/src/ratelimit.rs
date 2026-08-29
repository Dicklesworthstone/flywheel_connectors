//! Rate limit tracking and error helpers for connector SDK.
//!
//! This module provides utilities for tracking rate limit pools and creating
//! rate limit violation errors with retry-after hints.
//!
//! # Example
//!
//! ```ignore
//! use fcp_sdk::ratelimit::{RateLimitTracker, RateLimitError};
//! use fcp_sdk::prelude::*;
//!
//! // Create a tracker from manifest declarations
//! let tracker = RateLimitTracker::from_declarations(&declarations);
//!
//! // Record an operation that consumes from pools
//! if let Some(err) = tracker.try_consume("send_message", 1) {
//!     return Err(err.into_fcp_error());
//! }
//! ```

use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::{
    FcpError, RateLimitConfig, RateLimitDeclarations, RateLimitEnforcement, RateLimitPool,
    RateLimitScope, RateLimitStatus, RateLimitUnit,
};
use serde::{Deserialize, Serialize};

const RATE_LIMIT_CHECKPOINT_FILE: &str = "ratelimit-checkpoints.json";
const RATE_LIMIT_CHECKPOINT_VERSION: u32 = 1;
const FCP_CONNECTOR_STATE_DIR_ENV: &str = "FCP_CONNECTOR_STATE_DIR";
const CONNECTOR_STATE_DIR_ENV: &str = "CONNECTOR_STATE";

/// Error returned when a rate limit is exceeded.
#[derive(Debug, Clone)]
pub struct RateLimitError {
    /// The pool that was exceeded.
    pub pool_id: String,
    /// The limit that was exceeded.
    pub limit: u32,
    /// The current usage.
    pub current: u32,
    /// Suggested retry delay in milliseconds.
    pub retry_after_ms: u64,
    /// The enforcement level of this limit.
    pub enforcement: RateLimitEnforcement,
    /// Human-readable message.
    pub message: String,
}

impl RateLimitError {
    /// Convert to an FCP-standard error with retry-after hints.
    #[must_use]
    pub fn into_fcp_error(self) -> FcpError {
        FcpError::RateLimited {
            retry_after_ms: self.retry_after_ms,
            violation: None,
        }
    }

    /// Create a rate limit error for a pool.
    #[must_use]
    pub fn for_pool(pool: &RateLimitPool, current: u32, retry_after_ms: u64) -> Self {
        Self {
            pool_id: pool.id.clone(),
            limit: pool.config.requests,
            current,
            retry_after_ms,
            enforcement: pool.enforcement,
            message: format!(
                "Rate limit exceeded for pool '{}': {} requests used of {} limit",
                pool.id, current, pool.config.requests
            ),
        }
    }

    /// Check if this is a soft limit (warning only).
    #[must_use]
    pub const fn is_soft(&self) -> bool {
        matches!(
            self.enforcement,
            RateLimitEnforcement::Soft | RateLimitEnforcement::Advisory
        )
    }
}

impl std::fmt::Display for RateLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for RateLimitError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RateLimitCheckpointFile {
    version: u32,
    pools: HashMap<String, PoolCheckpoint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PoolCheckpoint {
    prev_count: u32,
    curr_count: u32,
    window_start_unix_ms: u64,
}

impl RateLimitCheckpointFile {
    fn from_pools(pools: &HashMap<String, PoolState>) -> Self {
        Self {
            version: RATE_LIMIT_CHECKPOINT_VERSION,
            pools: pools
                .values()
                .map(|state| (rate_limit_checkpoint_key(&state.config), state.checkpoint()))
                .collect(),
        }
    }
}

#[derive(Debug, Clone)]
struct RateLimitCheckpointStore {
    path: PathBuf,
    // br-ogeov: serialize tempfile-write+rename so concurrent persists
    // never race on the same target path. Without this, two threads
    // truncating the file via File::create can produce torn or
    // interleaved bytes that fail JSON parse on next startup, silently
    // discarding all rate-limit state.
    io_lock: Arc<Mutex<()>>,
}

impl RateLimitCheckpointStore {
    fn from_state_dir(state_dir: impl AsRef<Path>) -> Self {
        Self {
            path: state_dir.as_ref().join(RATE_LIMIT_CHECKPOINT_FILE),
            io_lock: Arc::new(Mutex::new(())),
        }
    }

    fn from_env() -> Option<Self> {
        resolve_rate_limit_state_dir_from_env().map(Self::from_state_dir)
    }

    fn load_all(&self) -> HashMap<String, PoolCheckpoint> {
        let bytes = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return HashMap::new(),
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    path = %self.path.display(),
                    "Failed to read persisted rate limit checkpoints"
                );
                return HashMap::new();
            }
        };

        let checkpoint_file: RateLimitCheckpointFile = match serde_json::from_slice(&bytes) {
            Ok(file) => file,
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    path = %self.path.display(),
                    "Ignoring malformed rate limit checkpoint file"
                );
                return HashMap::new();
            }
        };

        if checkpoint_file.version != RATE_LIMIT_CHECKPOINT_VERSION {
            tracing::warn!(
                version = checkpoint_file.version,
                path = %self.path.display(),
                "Ignoring unsupported rate limit checkpoint version"
            );
            return HashMap::new();
        }

        checkpoint_file.pools
    }

    fn load_for_pool(&self, pool: &RateLimitPool) -> Option<PoolCheckpoint> {
        let mut checkpoints = self.load_all();
        checkpoints.remove(&rate_limit_checkpoint_key(pool))
    }

    fn persist_file(&self, checkpoint_file: &RateLimitCheckpointFile) -> std::io::Result<()> {
        let Some(parent) = self.path.parent() else {
            return Ok(());
        };
        fs::create_dir_all(parent)?;

        let bytes = serde_json::to_vec_pretty(checkpoint_file)
            .map_err(|err| std::io::Error::new(ErrorKind::InvalidData, err))?;

        // br-ogeov: hold the I/O lock across tempfile-write+rename so
        // (a) only one writer races for the target path at a time and
        // (b) a fresh-then-aborted writer can never expose the empty
        // truncated file. The unique-name temp suffix also defends
        // against races on the same `parent` from independent stores
        // pointed at the same directory.
        let _guard = self
            .io_lock
            .lock()
            .map_err(|_| std::io::Error::other("rate limit checkpoint io lock poisoned"))?;

        let temp_path = open_unique_checkpoint_temp_file(&self.path, &bytes)?;
        match fs::rename(&temp_path, &self.path) {
            Ok(()) => Ok(()),
            Err(rename_err) => {
                let _ = fs::remove_file(&temp_path);
                Err(rename_err)
            }
        }
    }
}

fn open_unique_checkpoint_temp_file(path: &Path, bytes: &[u8]) -> std::io::Result<PathBuf> {
    const MAX_TEMP_FILE_RETRIES: u32 = 32;

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| std::io::Error::new(ErrorKind::InvalidInput, "invalid checkpoint path"))?;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base_name = format!("{file_name}.tmp.{}.{nanos}", std::process::id());

    for suffix in 0..=MAX_TEMP_FILE_RETRIES {
        let candidate = if suffix == 0 {
            path.with_file_name(&base_name)
        } else {
            path.with_file_name(format!("{base_name}.{suffix}"))
        };

        match OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&candidate)
        {
            Ok(mut file) => {
                if let Err(write_err) = file.write_all(bytes) {
                    drop(file);
                    let _ = fs::remove_file(&candidate);
                    return Err(write_err);
                }
                if let Err(sync_err) = file.sync_all() {
                    drop(file);
                    let _ = fs::remove_file(&candidate);
                    return Err(sync_err);
                }
                drop(file);
                return Ok(candidate);
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }

    Err(std::io::Error::new(
        ErrorKind::AlreadyExists,
        format!(
            "exhausted unique-name retries for checkpoint temp file {}",
            path.display()
        ),
    ))
}

fn resolve_rate_limit_state_dir_from_env() -> Option<PathBuf> {
    std::env::var_os(FCP_CONNECTOR_STATE_DIR_ENV)
        .or_else(|| std::env::var_os(CONNECTOR_STATE_DIR_ENV))
        .map(PathBuf::from)
}

const fn rate_limit_scope_key(scope: RateLimitScope) -> &'static str {
    match scope {
        RateLimitScope::Instance => "instance",
        RateLimitScope::Credential => "credential",
        RateLimitScope::Global => "global",
    }
}

fn rate_limit_checkpoint_key(pool: &RateLimitPool) -> String {
    format!("{}::{}", rate_limit_scope_key(pool.scope), pool.id)
}

fn dedup_operation_pool_map(
    operation_map: &HashMap<String, Vec<String>>,
) -> HashMap<String, Vec<String>> {
    operation_map
        .iter()
        .map(|(operation, pool_ids)| {
            let mut seen = HashSet::new();
            let mut deduped = Vec::with_capacity(pool_ids.len());
            for pool_id in pool_ids {
                if seen.insert(pool_id.as_str()) {
                    deduped.push(pool_id.clone());
                }
            }
            (operation.clone(), deduped)
        })
        .collect()
}

/// Runtime state for a single rate limit pool.
///
/// Implements a two-counter sliding-window approximation rather than a hard
/// fixed-window reset. With a hard reset, an attacker can issue `limit`
/// requests just before the window boundary and another `limit` immediately
/// after, sustaining ~2× throughput across the boundary instant
/// (br-flywheel_connectors-e8v7i). The sliding-window approximation
/// estimates the effective in-window count as
/// `prev_count * (1 - elapsed_in_curr_window / window) + curr_count`,
/// closing the boundary-burst gap with two counters and a multiply.
#[derive(Debug)]
struct PoolState {
    /// Pool configuration.
    config: RateLimitPool,
    /// Counter from the immediately-preceding window (decays linearly to 0
    /// over the current window's duration via the sliding-window estimate).
    prev_count: u32,
    /// Counter for requests landing in the current window.
    curr_count: u32,
    /// Aligned start of the current window.
    window_start: Instant,
}

impl PoolState {
    fn new(config: RateLimitPool) -> Self {
        Self {
            config,
            prev_count: 0,
            curr_count: 0,
            window_start: Instant::now(),
        }
    }

    fn from_checkpoint(config: RateLimitPool, checkpoint: &PoolCheckpoint) -> Self {
        let mut state = Self::new(config);
        state.prev_count = checkpoint.prev_count;
        state.curr_count = checkpoint.curr_count;
        state.window_start =
            instant_from_unix_ms(checkpoint.window_start_unix_ms).unwrap_or_else(Instant::now);
        state.maybe_advance_window();
        state
    }

    /// Advance window state if the current window has fully elapsed.
    ///
    /// On a single-window roll-over, `prev_count := curr_count` and
    /// `curr_count := 0`. On multi-window gaps (e.g. the connector was idle
    /// for several windows), both counters reset — the previous window is
    /// no longer "immediately preceding" so it should not contribute.
    ///
    /// `window_start` is advanced by an exact integer number of windows so
    /// the rolling estimate stays anchored to the configured window grid;
    /// snapping to `Instant::now()` would shift the grid each call and let
    /// the boundary-burst gap reopen.
    fn maybe_advance_window(&mut self) {
        let window = self.config.config.window;
        let elapsed = self.window_start.elapsed();
        if elapsed < window || window.is_zero() {
            return;
        }
        let elapsed_nanos = elapsed.as_nanos();
        let window_nanos = window.as_nanos().max(1);
        let windows_elapsed = elapsed_nanos / window_nanos;
        if windows_elapsed >= 2 {
            // Idle gap of two or more full windows: previous window is no
            // longer immediately preceding the current one.
            self.prev_count = 0;
        } else {
            self.prev_count = self.curr_count;
        }
        self.curr_count = 0;
        let advance_nanos = windows_elapsed.saturating_mul(window_nanos);
        let advance = Duration::from_nanos(u64::try_from(advance_nanos).unwrap_or(u64::MAX));
        self.window_start = self
            .window_start
            .checked_add(advance)
            .unwrap_or_else(Instant::now);
    }

    /// Sliding-window effective count: `prev * (1 - fraction) + curr`.
    ///
    /// `fraction` is how far we are into the current window in `[0.0, 1.0]`.
    /// Saturates to `u32::MAX` so a pathological `prev_count` can't wrap.
    fn effective_count(&self) -> u32 {
        let window = self.config.config.window;
        if window.is_zero() {
            return self.curr_count;
        }
        let elapsed = self.window_start.elapsed();
        let fraction = (elapsed.as_secs_f64() / window.as_secs_f64()).clamp(0.0, 1.0);
        let prev_weight = (1.0 - fraction).clamp(0.0, 1.0);
        // round() to integer to avoid persistent off-by-fractional-request
        // bias. as-cast to u32 is saturating for negative/NaN inputs because
        // both prev_weight and prev_count are non-negative finite.
        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        let prev_contribution = (f64::from(self.prev_count) * prev_weight).round() as u32;
        self.curr_count.saturating_add(prev_contribution)
    }

    /// Try to consume requests, returns error if exceeded.
    fn try_consume(&mut self, amount: u32) -> Result<(), RateLimitError> {
        self.check_consume(amount)?;
        self.curr_count = self.curr_count.saturating_add(amount);
        Ok(())
    }

    /// Check if requests can be consumed without actually consuming them.
    fn check_consume(&mut self, amount: u32) -> Result<(), RateLimitError> {
        self.maybe_advance_window();

        let effective_limit = self
            .config
            .config
            .requests
            .saturating_add(self.config.config.burst.unwrap_or(0));

        let projected = self.effective_count().saturating_add(amount);
        if projected > effective_limit {
            let retry_after_ms = self.ms_until_reset();
            return Err(RateLimitError::for_pool(
                &self.config,
                self.effective_count(),
                retry_after_ms,
            ));
        }

        Ok(())
    }

    /// Force consume requests (used for soft limits).
    fn force_consume(&mut self, amount: u32) {
        self.maybe_advance_window();
        self.curr_count = self.curr_count.saturating_add(amount);
    }

    /// Get milliseconds until enough capacity returns to admit one more request.
    ///
    /// For the sliding-window estimator this is "time until the `prev_count`
    /// contribution decays enough to free one slot," which simplifies to the
    /// time remaining in the current window when `prev_count` > 0, and 0
    /// otherwise (the `curr_count` alone is over-limit and the next window
    /// roll-over is the relevant horizon).
    fn ms_until_reset(&self) -> u64 {
        let elapsed = self.window_start.elapsed();
        let window = self.config.config.window;
        if elapsed >= window {
            0
        } else {
            let remaining = window.checked_sub(elapsed).unwrap_or(Duration::ZERO);
            u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX)
        }
    }

    /// Get current status.
    fn status(&mut self) -> RateLimitStatus {
        self.maybe_advance_window();
        let effective_limit = self
            .config
            .config
            .requests
            .saturating_add(self.config.config.burst.unwrap_or(0));
        let remaining = effective_limit.saturating_sub(self.effective_count());
        let reset_at = {
            let elapsed_secs = self.window_start.elapsed().as_secs();
            let window_secs = self.config.config.window.as_secs();
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            now_secs + window_secs.saturating_sub(elapsed_secs)
        };

        RateLimitStatus {
            limit: effective_limit,
            remaining,
            reset_at,
            window_seconds: u32::try_from(self.config.config.window.as_secs()).unwrap_or(u32::MAX),
        }
    }

    fn checkpoint(&self) -> PoolCheckpoint {
        let elapsed_ms = u64::try_from(self.window_start.elapsed().as_millis()).unwrap_or(u64::MAX);
        PoolCheckpoint {
            prev_count: self.prev_count,
            curr_count: self.curr_count,
            window_start_unix_ms: unix_ms_now().saturating_sub(elapsed_ms),
        }
    }
}

/// Thread-safe rate limit tracker for connector pools.
///
/// Tracks multiple rate limit pools and enforces limits based on
/// manifest declarations.
#[derive(Debug, Clone)]
pub struct RateLimitTracker {
    pools: Arc<RwLock<HashMap<String, PoolState>>>,
    operation_map: Arc<HashMap<String, Vec<String>>>,
    checkpoint_store: Option<RateLimitCheckpointStore>,
}

impl Default for RateLimitTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimitTracker {
    /// Create an empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            pools: Arc::new(RwLock::new(HashMap::new())),
            operation_map: Arc::new(HashMap::new()),
            checkpoint_store: None,
        }
    }

    /// Create a tracker from rate limit declarations.
    #[must_use]
    pub fn from_declarations(decls: &RateLimitDeclarations) -> Self {
        Self::from_declarations_with_store(decls, RateLimitCheckpointStore::from_env())
    }

    /// Create a tracker from rate limit declarations with an explicit state directory.
    ///
    /// Persisted checkpoints are keyed by `scope + pool_id`, so `global` pools
    /// no longer silently reuse the same in-memory counter namespace as
    /// `instance` or `credential` pools after restart.
    #[must_use]
    pub fn from_declarations_with_state_dir(
        decls: &RateLimitDeclarations,
        state_dir: impl AsRef<Path>,
    ) -> Self {
        Self::from_declarations_with_store(
            decls,
            Some(RateLimitCheckpointStore::from_state_dir(state_dir)),
        )
    }

    fn from_declarations_with_store(
        decls: &RateLimitDeclarations,
        checkpoint_store: Option<RateLimitCheckpointStore>,
    ) -> Self {
        let checkpoints = checkpoint_store
            .as_ref()
            .map_or_else(HashMap::new, RateLimitCheckpointStore::load_all);
        let pools: HashMap<String, PoolState> = decls
            .limits
            .iter()
            .map(|pool| {
                let pool_state = checkpoints
                    .get(&rate_limit_checkpoint_key(pool))
                    .map_or_else(
                        || PoolState::new(pool.clone()),
                        |checkpoint| PoolState::from_checkpoint(pool.clone(), checkpoint),
                    );
                (pool.id.clone(), pool_state)
            })
            .collect();

        Self {
            pools: Arc::new(RwLock::new(pools)),
            operation_map: Arc::new(dedup_operation_pool_map(&decls.tool_pool_map)),
            checkpoint_store,
        }
    }

    /// Add a pool to the tracker.
    ///
    /// # Panics
    /// Panics if the internal lock is poisoned (indicates a prior panic during pool access).
    pub fn add_pool(&self, pool: RateLimitPool) {
        let checkpoint = self
            .checkpoint_store
            .as_ref()
            .and_then(|store| store.load_for_pool(&pool));
        let pool_id = pool.id.clone();
        let pool_state = match checkpoint {
            Some(checkpoint) => PoolState::from_checkpoint(pool, &checkpoint),
            None => PoolState::new(pool),
        };
        let checkpoint_file = {
            let mut pools = self.pools.write().expect("lock poisoned");
            pools.insert(pool_id, pool_state);
            let checkpoint_file = self.checkpoint_file_for_locked(&pools);
            drop(pools);
            checkpoint_file
        };
        self.persist_checkpoint_file(checkpoint_file);
    }

    /// Try to consume requests for an operation.
    ///
    /// Returns `Some(error)` if any pool is exceeded, `None` if all pools have capacity.
    /// For soft limits, logs a warning but returns `None`.
    ///
    /// # Fail-closed on unregistered pools
    ///
    /// If `operation_map` references a pool id that is not present in
    /// `pools`, this method returns a hard [`RateLimitError`] rather
    /// than silently admitting the operation
    /// (br-flywheel_connectors-83xt1). Silent skip would be fail-open
    /// — an admission-control primitive must fail closed by default.
    /// Callers that build a tracker by hand (not via
    /// [`Self::from_declarations`]) are responsible for keeping
    /// `operation_map` and `pools` consistent; inconsistencies are
    /// treated as a configuration error, not a free pass.
    ///
    /// # Panics
    /// Panics if the internal lock is poisoned.
    pub fn try_consume(&self, operation: &str, amount: u32) -> Option<RateLimitError> {
        let pool_ids = self.operation_map.get(operation)?;
        let checkpoint_file = {
            let mut pools = self.pools.write().expect("lock poisoned");

            // Fail-closed guard: reject up-front if any referenced pool is
            // missing, so the subsequent phases operate on a consistent set.
            for pool_id in pool_ids {
                if !pools.contains_key(pool_id) {
                    return Some(RateLimitError {
                        pool_id: pool_id.clone(),
                        limit: 0,
                        current: 0,
                        retry_after_ms: 0,
                        enforcement: RateLimitEnforcement::Hard,
                        message: format!(
                            "Rate limit pool '{pool_id}' referenced by operation \
                             '{operation}' is not registered; rejecting fail-closed"
                        ),
                    });
                }
            }

            // Phase 1: Check capacity (all-or-nothing)
            for pool_id in pool_ids {
                if let Some(pool_state) = pools.get_mut(pool_id) {
                    if let Err(err) = pool_state.check_consume(amount) {
                        if !err.is_soft() {
                            return Some(err);
                        }
                    }
                }
            }

            // Phase 2: Consume
            for pool_id in pool_ids {
                if let Some(pool_state) = pools.get_mut(pool_id) {
                    if let Err(err) = pool_state.try_consume(amount) {
                        if err.is_soft() {
                            tracing::warn!(
                                pool = %pool_id,
                                operation = %operation,
                                "Soft rate limit exceeded: {}",
                                err.message
                            );
                            pool_state.force_consume(amount);
                        }
                    }
                }
            }

            let checkpoint_file = self.checkpoint_file_for_locked(&pools);
            drop(pools);
            checkpoint_file
        };
        self.persist_checkpoint_file(checkpoint_file);

        None
    }

    /// Get the status of a specific pool.
    ///
    /// # Panics
    /// Panics if the internal lock is poisoned.
    #[must_use]
    pub fn pool_status(&self, pool_id: &str) -> Option<RateLimitStatus> {
        let mut pools = self.pools.write().expect("lock poisoned");
        pools.get_mut(pool_id).map(PoolState::status)
    }

    /// Get status for all pools affecting an operation.
    ///
    /// # Panics
    /// Panics if the internal lock is poisoned.
    #[must_use]
    pub fn operation_status(&self, operation: &str) -> Vec<(String, RateLimitStatus)> {
        let pool_ids = match self.operation_map.get(operation) {
            Some(ids) => ids.clone(),
            None => return Vec::new(),
        };

        let mut pools = self.pools.write().expect("lock poisoned");
        pool_ids
            .into_iter()
            .filter_map(|pool_id| {
                pools
                    .get_mut(&pool_id)
                    .map(|state| (pool_id, state.status()))
            })
            .collect()
    }

    /// Get the most constrained status for an operation.
    ///
    /// Returns the pool with the lowest remaining capacity.
    #[must_use]
    pub fn most_constrained_status(&self, operation: &str) -> Option<(String, RateLimitStatus)> {
        self.operation_status(operation)
            .into_iter()
            .min_by_key(|(_, status)| status.remaining)
    }

    /// Check if an operation is currently rate limited.
    #[must_use]
    pub fn is_limited(&self, operation: &str) -> bool {
        self.operation_status(operation)
            .iter()
            .any(|(_, status)| status.is_limited())
    }

    /// Get all pool statuses.
    ///
    /// # Panics
    /// Panics if the internal lock is poisoned.
    #[must_use]
    pub fn all_pool_statuses(&self) -> HashMap<String, RateLimitStatus> {
        let mut pools = self.pools.write().expect("lock poisoned");
        pools
            .iter_mut()
            .map(|(id, state)| (id.clone(), state.status()))
            .collect()
    }

    /// Reset all pools (for testing).
    ///
    /// # Panics
    /// Panics if the internal lock is poisoned.
    pub fn reset_all(&self) {
        let checkpoint_file = {
            let mut pools = self.pools.write().expect("lock poisoned");
            for state in pools.values_mut() {
                state.prev_count = 0;
                state.curr_count = 0;
                state.window_start = Instant::now();
            }
            let checkpoint_file = self.checkpoint_file_for_locked(&pools);
            drop(pools);
            checkpoint_file
        };
        self.persist_checkpoint_file(checkpoint_file);
    }

    fn checkpoint_file_for_locked(
        &self,
        pools: &HashMap<String, PoolState>,
    ) -> Option<RateLimitCheckpointFile> {
        self.checkpoint_store.as_ref()?;
        Some(RateLimitCheckpointFile::from_pools(pools))
    }

    fn persist_checkpoint_file(&self, checkpoint_file: Option<RateLimitCheckpointFile>) {
        let Some(checkpoint_file) = checkpoint_file else {
            return;
        };
        let Some(store) = &self.checkpoint_store else {
            return;
        };
        if let Err(err) = store.persist_file(&checkpoint_file) {
            tracing::warn!(
                error = %err,
                path = %store.path.display(),
                "Failed to persist rate limit checkpoints"
            );
        }
    }
}

fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

fn instant_from_unix_ms(unix_ms: u64) -> Option<Instant> {
    let checkpoint_time = UNIX_EPOCH.checked_add(Duration::from_millis(unix_ms))?;
    let elapsed = SystemTime::now()
        .duration_since(checkpoint_time)
        .unwrap_or(Duration::ZERO);
    Instant::now().checked_sub(elapsed)
}

/// Builder for creating rate limit pools with fluent API.
#[derive(Debug, Clone)]
pub struct RateLimitPoolBuilder {
    id: String,
    description: String,
    requests: u32,
    window: Duration,
    burst: Option<u32>,
    unit: RateLimitUnit,
    enforcement: RateLimitEnforcement,
    scope: RateLimitScope,
}

impl RateLimitPoolBuilder {
    /// Create a new pool builder with the given ID.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            description: String::new(),
            requests: 60,
            window: Duration::from_secs(60),
            burst: None,
            unit: RateLimitUnit::Requests,
            enforcement: RateLimitEnforcement::Hard,
            scope: RateLimitScope::Instance,
        }
    }

    /// Set the description.
    #[must_use]
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    /// Set requests per window.
    #[must_use]
    pub const fn requests(mut self, requests: u32) -> Self {
        self.requests = requests;
        self
    }

    /// Set window duration.
    #[must_use]
    pub const fn window(mut self, window: Duration) -> Self {
        self.window = window;
        self
    }

    /// Set window duration in seconds.
    #[must_use]
    pub const fn window_secs(mut self, secs: u64) -> Self {
        self.window = Duration::from_secs(secs);
        self
    }

    /// Set burst allowance.
    #[must_use]
    pub const fn burst(mut self, burst: u32) -> Self {
        self.burst = Some(burst);
        self
    }

    /// Set unit of measurement.
    #[must_use]
    pub const fn unit(mut self, unit: RateLimitUnit) -> Self {
        self.unit = unit;
        self
    }

    /// Set enforcement level.
    #[must_use]
    pub const fn enforcement(mut self, enforcement: RateLimitEnforcement) -> Self {
        self.enforcement = enforcement;
        self
    }

    /// Set scope.
    #[must_use]
    pub const fn scope(mut self, scope: RateLimitScope) -> Self {
        self.scope = scope;
        self
    }

    /// Build the rate limit pool.
    #[must_use]
    pub fn build(self) -> RateLimitPool {
        RateLimitPool {
            id: self.id,
            description: self.description,
            config: RateLimitConfig {
                requests: self.requests,
                window: self.window,
                burst: self.burst,
                unit: self.unit,
            },
            enforcement: self.enforcement,
            scope: self.scope,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pool(id: &str, requests: u32, window_secs: u64) -> RateLimitPool {
        RateLimitPoolBuilder::new(id)
            .requests(requests)
            .window_secs(window_secs)
            .build()
    }

    fn unique_state_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fcp-sdk-ratelimit-{label}-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).expect("state dir should be creatable");
        dir
    }

    #[test]
    fn tracker_from_declarations() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("api", 10, 60), test_pool("tokens", 1000, 3600)],
            tool_pool_map: HashMap::from([
                ("send".to_string(), vec!["api".to_string()]),
                (
                    "generate".to_string(),
                    vec!["api".to_string(), "tokens".to_string()],
                ),
            ]),
        };

        let tracker = RateLimitTracker::from_declarations(&decls);

        // Should have status for both pools
        assert!(tracker.pool_status("api").is_some());
        assert!(tracker.pool_status("tokens").is_some());
        assert!(tracker.pool_status("nonexistent").is_none());
    }

    #[test]
    fn tracker_consume_and_limit() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("api", 3, 60)],
            tool_pool_map: HashMap::from([("send".to_string(), vec!["api".to_string()])]),
        };

        let tracker = RateLimitTracker::from_declarations(&decls);

        // Should be able to consume 3 requests
        assert!(tracker.try_consume("send", 1).is_none());
        assert!(tracker.try_consume("send", 1).is_none());
        assert!(tracker.try_consume("send", 1).is_none());

        // Fourth should fail
        let err = tracker.try_consume("send", 1);
        assert!(err.is_some());
        let err = err.unwrap();
        assert_eq!(err.pool_id, "api");
        assert_eq!(err.limit, 3);
    }

    #[test]
    fn tracker_operation_status() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("api", 10, 60), test_pool("tokens", 1000, 3600)],
            tool_pool_map: HashMap::from([(
                "generate".to_string(),
                vec!["api".to_string(), "tokens".to_string()],
            )]),
        };

        let tracker = RateLimitTracker::from_declarations(&decls);
        tracker.try_consume("generate", 5);

        let statuses = tracker.operation_status("generate");
        assert_eq!(statuses.len(), 2);

        // Find api pool status
        let api_status = statuses.iter().find(|(id, _)| id == "api").unwrap();
        assert_eq!(api_status.1.remaining, 5);

        // Find tokens pool status
        let tokens_status = statuses.iter().find(|(id, _)| id == "tokens").unwrap();
        assert_eq!(tokens_status.1.remaining, 995);
    }

    #[test]
    fn pool_builder_fluent_api() {
        let pool = RateLimitPoolBuilder::new("my_pool")
            .description("My rate limit pool")
            .requests(100)
            .window_secs(60)
            .burst(20)
            .unit(RateLimitUnit::Tokens)
            .enforcement(RateLimitEnforcement::Soft)
            .scope(RateLimitScope::Credential)
            .build();

        assert_eq!(pool.id, "my_pool");
        assert_eq!(pool.description, "My rate limit pool");
        assert_eq!(pool.config.requests, 100);
        assert_eq!(pool.config.window, Duration::from_secs(60));
        assert_eq!(pool.config.burst, Some(20));
        assert_eq!(pool.config.unit, RateLimitUnit::Tokens);
        assert_eq!(pool.enforcement, RateLimitEnforcement::Soft);
        assert_eq!(pool.scope, RateLimitScope::Credential);
    }

    #[test]
    fn rate_limit_error_to_fcp_error() {
        let pool = test_pool("api", 10, 60);
        let err = RateLimitError::for_pool(&pool, 10, 5000);

        assert_eq!(err.pool_id, "api");
        assert_eq!(err.limit, 10);
        assert_eq!(err.retry_after_ms, 5000);

        let fcp_err = err.into_fcp_error();
        // Should be a rate limited error with retry after
        assert!(fcp_err.to_string().contains("Rate limited"));
        assert!(fcp_err.to_string().contains("5000"));
        assert!(fcp_err.is_retryable());
        assert_eq!(fcp_err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn soft_limit_allows_through() {
        let pool = RateLimitPoolBuilder::new("soft")
            .requests(1)
            .enforcement(RateLimitEnforcement::Soft)
            .build();

        let decls = RateLimitDeclarations {
            limits: vec![pool],
            tool_pool_map: HashMap::from([("op".to_string(), vec!["soft".to_string()])]),
        };

        let tracker = RateLimitTracker::from_declarations(&decls);

        // First request succeeds
        assert!(tracker.try_consume("op", 1).is_none());

        // Second request also "succeeds" (soft limit logs warning but doesn't block)
        assert!(tracker.try_consume("op", 1).is_none());
    }

    #[test]
    fn unknown_operation_returns_none() {
        let tracker = RateLimitTracker::new();
        // Unknown operation should not error
        assert!(tracker.try_consume("unknown_op", 1).is_none());
    }

    // ---- RateLimitError coverage ----

    #[test]
    fn rate_limit_error_display() {
        let pool = test_pool("api", 10, 60);
        let err = RateLimitError::for_pool(&pool, 8, 3000);
        let msg = err.to_string();
        assert!(msg.contains("api"));
        assert!(msg.contains('8'));
        assert!(msg.contains("10"));
    }

    #[test]
    fn rate_limit_error_is_soft_hard() {
        let err = RateLimitError {
            pool_id: "p".into(),
            limit: 10,
            current: 10,
            retry_after_ms: 1000,
            enforcement: RateLimitEnforcement::Hard,
            message: "test".into(),
        };
        assert!(!err.is_soft());
    }

    #[test]
    fn rate_limit_error_is_soft_advisory() {
        let err = RateLimitError {
            pool_id: "p".into(),
            limit: 10,
            current: 10,
            retry_after_ms: 1000,
            enforcement: RateLimitEnforcement::Advisory,
            message: "test".into(),
        };
        assert!(err.is_soft());
    }

    #[test]
    fn rate_limit_error_is_soft_soft() {
        let err = RateLimitError {
            pool_id: "p".into(),
            limit: 10,
            current: 10,
            retry_after_ms: 1000,
            enforcement: RateLimitEnforcement::Soft,
            message: "test".into(),
        };
        assert!(err.is_soft());
    }

    #[test]
    fn rate_limit_error_is_std_error() {
        let pool = test_pool("api", 10, 60);
        let err = RateLimitError::for_pool(&pool, 10, 1000);
        // Verify it implements std::error::Error
        let _: &dyn std::error::Error = &err;
    }

    // ---- Tracker: add_pool ----

    #[test]
    fn tracker_add_pool() {
        let tracker = RateLimitTracker::new();
        assert!(tracker.pool_status("dynamic").is_none());

        let pool = test_pool("dynamic", 5, 30);
        tracker.add_pool(pool);

        let status = tracker.pool_status("dynamic").unwrap();
        assert_eq!(status.limit, 5);
        assert_eq!(status.remaining, 5);
    }

    // ---- Tracker: reset_all ----

    #[test]
    fn tracker_reset_all() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("api", 3, 60)],
            tool_pool_map: HashMap::from([("op".to_string(), vec!["api".to_string()])]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);

        // Consume all
        tracker.try_consume("op", 3);
        assert!(tracker.try_consume("op", 1).is_some());

        // Reset
        tracker.reset_all();
        assert!(tracker.try_consume("op", 1).is_none());
        let status = tracker.pool_status("api").unwrap();
        assert_eq!(status.remaining, 2); // 3 - 1
    }

    // ---- Tracker: is_limited ----

    #[test]
    fn tracker_is_limited_false_initially() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("api", 10, 60)],
            tool_pool_map: HashMap::from([("op".to_string(), vec!["api".to_string()])]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);
        assert!(!tracker.is_limited("op"));
    }

    #[test]
    fn tracker_is_limited_true_when_exhausted() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("api", 2, 60)],
            tool_pool_map: HashMap::from([("op".to_string(), vec!["api".to_string()])]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);
        tracker.try_consume("op", 2);
        assert!(tracker.is_limited("op"));
    }

    #[test]
    fn tracker_is_limited_unknown_op() {
        let tracker = RateLimitTracker::new();
        assert!(!tracker.is_limited("nonexistent"));
    }

    // ---- Tracker: most_constrained_status ----

    #[test]
    fn tracker_most_constrained_status() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("big", 100, 60), test_pool("small", 5, 60)],
            tool_pool_map: HashMap::from([(
                "op".to_string(),
                vec!["big".to_string(), "small".to_string()],
            )]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);
        tracker.try_consume("op", 3);

        let (id, status) = tracker.most_constrained_status("op").unwrap();
        assert_eq!(id, "small");
        assert_eq!(status.remaining, 2);
    }

    #[test]
    fn tracker_most_constrained_status_unknown_op() {
        let tracker = RateLimitTracker::new();
        assert!(tracker.most_constrained_status("nope").is_none());
    }

    // ---- Tracker: all_pool_statuses ----

    #[test]
    fn tracker_all_pool_statuses() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("a", 10, 60), test_pool("b", 20, 120)],
            tool_pool_map: HashMap::new(),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);
        let all = tracker.all_pool_statuses();
        assert_eq!(all.len(), 2);
        assert!(all.contains_key("a"));
        assert!(all.contains_key("b"));
        assert_eq!(all["a"].limit, 10);
        assert_eq!(all["b"].limit, 20);
    }

    #[test]
    fn tracker_all_pool_statuses_empty() {
        let tracker = RateLimitTracker::new();
        assert!(tracker.all_pool_statuses().is_empty());
    }

    // ---- Tracker: operation_status unknown ----

    #[test]
    fn tracker_operation_status_unknown_op() {
        let tracker = RateLimitTracker::new();
        assert!(tracker.operation_status("missing").is_empty());
    }

    // ---- Burst handling ----

    #[test]
    fn tracker_burst_allows_over_base_limit() {
        let pool = RateLimitPoolBuilder::new("burst_pool")
            .requests(3)
            .burst(2)
            .window_secs(60)
            .build();

        let decls = RateLimitDeclarations {
            limits: vec![pool],
            tool_pool_map: HashMap::from([("op".to_string(), vec!["burst_pool".to_string()])]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);

        // Should allow 5 total (3 base + 2 burst)
        for _ in 0..5 {
            assert!(tracker.try_consume("op", 1).is_none());
        }
        // 6th should fail
        assert!(tracker.try_consume("op", 1).is_some());
    }

    #[test]
    fn tracker_burst_reflected_in_status() {
        let pool = RateLimitPoolBuilder::new("bp")
            .requests(10)
            .burst(5)
            .window_secs(60)
            .build();

        let decls = RateLimitDeclarations {
            limits: vec![pool],
            tool_pool_map: HashMap::new(),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);
        let status = tracker.pool_status("bp").unwrap();
        // Effective limit includes burst
        assert_eq!(status.limit, 15);
        assert_eq!(status.remaining, 15);
    }

    // ---- Consume amount > 1 ----

    #[test]
    fn tracker_consume_large_amount() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("api", 10, 60)],
            tool_pool_map: HashMap::from([("op".to_string(), vec!["api".to_string()])]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);

        // Consume 10 at once
        assert!(tracker.try_consume("op", 10).is_none());
        // Next should fail
        assert!(tracker.try_consume("op", 1).is_some());
    }

    #[test]
    fn tracker_consume_exceeds_in_single_call() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("api", 5, 60)],
            tool_pool_map: HashMap::from([("op".to_string(), vec!["api".to_string()])]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);
        // Trying to consume more than limit fails immediately
        let err = tracker.try_consume("op", 6).unwrap();
        assert_eq!(err.pool_id, "api");
        assert_eq!(err.current, 0);
    }

    // ---- RateLimitPoolBuilder defaults ----

    #[test]
    fn pool_builder_defaults() {
        let pool = RateLimitPoolBuilder::new("default_pool").build();
        assert_eq!(pool.id, "default_pool");
        assert_eq!(pool.description, "");
        assert_eq!(pool.config.requests, 60);
        assert_eq!(pool.config.window, Duration::from_secs(60));
        assert_eq!(pool.config.burst, None);
        assert_eq!(pool.config.unit, RateLimitUnit::Requests);
        assert_eq!(pool.enforcement, RateLimitEnforcement::Hard);
        assert_eq!(pool.scope, RateLimitScope::Instance);
    }

    #[test]
    fn pool_builder_window_duration() {
        let pool = RateLimitPoolBuilder::new("p")
            .window(Duration::from_millis(500))
            .build();
        assert_eq!(pool.config.window, Duration::from_millis(500));
    }

    // ---- Tracker: Default impl ----

    #[test]
    fn tracker_default() {
        let t1 = RateLimitTracker::new();
        let t2 = RateLimitTracker::default();
        // Both should be empty
        assert!(t1.all_pool_statuses().is_empty());
        assert!(t2.all_pool_statuses().is_empty());
    }

    // ---- Tracker: Clone shares state ----

    #[test]
    fn tracker_clone_shares_state() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("api", 5, 60)],
            tool_pool_map: HashMap::from([("op".to_string(), vec!["api".to_string()])]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);
        let cloned = tracker.clone();

        // Consume on original
        tracker.try_consume("op", 3);
        // Clone should see the same state (Arc)
        let status = cloned.pool_status("api").unwrap();
        assert_eq!(status.remaining, 2);
    }

    // ---- Advisory enforcement ----

    #[test]
    fn advisory_limit_allows_through() {
        let pool = RateLimitPoolBuilder::new("adv")
            .requests(1)
            .enforcement(RateLimitEnforcement::Advisory)
            .build();

        let decls = RateLimitDeclarations {
            limits: vec![pool],
            tool_pool_map: HashMap::from([("op".to_string(), vec!["adv".to_string()])]),
        };

        let tracker = RateLimitTracker::from_declarations(&decls);
        assert!(tracker.try_consume("op", 1).is_none());
        // Advisory should also allow through like soft
        assert!(tracker.try_consume("op", 1).is_none());
    }

    // ---- Multiple pools per operation ----

    #[test]
    fn tracker_multiple_pools_first_hard_limit_stops() {
        let pool1 = RateLimitPoolBuilder::new("tight")
            .requests(2)
            .enforcement(RateLimitEnforcement::Hard)
            .build();
        let pool2 = RateLimitPoolBuilder::new("loose")
            .requests(100)
            .enforcement(RateLimitEnforcement::Hard)
            .build();

        let decls = RateLimitDeclarations {
            limits: vec![pool1, pool2],
            tool_pool_map: HashMap::from([(
                "op".to_string(),
                vec!["loose".to_string(), "tight".to_string()], // Put loose first to ensure it's not consumed if tight fails
            )]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);

        tracker.try_consume("op", 2);
        let err = tracker.try_consume("op", 1).unwrap();
        assert_eq!(err.pool_id, "tight");

        let status = tracker.pool_status("loose").unwrap();
        // Since the 3rd operation failed on 'tight', 'loose' should not be consumed for the 3rd time
        assert_eq!(status.remaining, 98); // 100 - 2, not 97!
    }

    // ---- Pool status window_seconds ----

    #[test]
    fn pool_status_window_seconds() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("api", 10, 120)],
            tool_pool_map: HashMap::new(),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);
        let status = tracker.pool_status("api").unwrap();
        assert_eq!(status.window_seconds, 120);
    }

    // ---- RateLimitError: Clone ----

    #[test]
    fn rate_limit_error_clone() {
        let pool = test_pool("api", 10, 60);
        let err = RateLimitError::for_pool(&pool, 7, 2500);
        let cloned = err.clone();
        assert_eq!(err.pool_id, cloned.pool_id);
        assert_eq!(err.limit, cloned.limit);
        assert_eq!(err.current, cloned.current);
        assert_eq!(err.retry_after_ms, cloned.retry_after_ms);
        assert_eq!(err.message, cloned.message);
    }

    // ---- RateLimitError: Debug ----

    #[test]
    fn rate_limit_error_debug() {
        let pool = test_pool("api", 10, 60);
        let err = RateLimitError::for_pool(&pool, 10, 1000);
        let debug = format!("{err:?}");
        assert!(debug.contains("RateLimitError"));
        assert!(debug.contains("api"));
    }

    // ---- RateLimitError: message format ----

    #[test]
    fn rate_limit_error_message_format() {
        let pool = test_pool("my_pool", 50, 60);
        let err = RateLimitError::for_pool(&pool, 42, 7777);
        assert!(err.message.contains("my_pool"));
        assert!(err.message.contains("42"));
        assert!(err.message.contains("50"));
        assert!(err.message.contains("Rate limit exceeded"));
    }

    // ---- try_consume with amount 0 ----

    #[test]
    fn tracker_consume_zero_amount() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("api", 3, 60)],
            tool_pool_map: HashMap::from([("op".to_string(), vec!["api".to_string()])]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);

        // Consuming 0 should always succeed and not change state
        assert!(tracker.try_consume("op", 0).is_none());
        let status = tracker.pool_status("api").unwrap();
        assert_eq!(status.remaining, 3);
    }

    // ---- Multiple operations sharing a pool ----

    #[test]
    fn tracker_multiple_operations_share_pool() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("shared", 5, 60)],
            tool_pool_map: HashMap::from([
                ("op_a".to_string(), vec!["shared".to_string()]),
                ("op_b".to_string(), vec!["shared".to_string()]),
            ]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);

        // Consume from op_a
        assert!(tracker.try_consume("op_a", 3).is_none());
        // op_b shares the pool, so only 2 remaining
        assert!(tracker.try_consume("op_b", 2).is_none());
        // Pool is now exhausted for both
        assert!(tracker.try_consume("op_a", 1).is_some());
        assert!(tracker.try_consume("op_b", 1).is_some());
    }

    #[test]
    fn tracker_deduplicates_duplicate_pool_refs_per_operation() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("api", 3, 60)],
            tool_pool_map: HashMap::from([(
                "op".to_string(),
                vec!["api".to_string(), "api".to_string()],
            )]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);

        assert!(tracker.try_consume("op", 1).is_none());
        let status = tracker.pool_status("api").unwrap();
        assert_eq!(
            status.remaining, 2,
            "duplicate pool refs must not double-charge one operation"
        );
    }

    // ---- Operation mapped to nonexistent pool ----

    #[test]
    fn tracker_operation_maps_to_nonexistent_pool() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("real", 10, 60)],
            tool_pool_map: HashMap::from([(
                "op".to_string(),
                vec!["real".to_string(), "ghost".to_string()],
            )]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);

        // Missing pool references are configuration errors and must fail closed.
        let err = tracker
            .try_consume("op", 5)
            .expect("missing pool should reject fail-closed");
        assert_eq!(err.pool_id, "ghost");
        assert!(err.message.contains("not registered"));
        let status = tracker.pool_status("real").unwrap();
        assert_eq!(status.remaining, 10);
        assert!(tracker.pool_status("ghost").is_none());
    }

    // ---- add_pool replaces existing pool ----

    #[test]
    fn tracker_add_pool_replaces_existing() {
        let tracker = RateLimitTracker::new();

        let pool_v1 = test_pool("api", 10, 60);
        tracker.add_pool(pool_v1);

        let status1 = tracker.pool_status("api").unwrap();
        assert_eq!(status1.limit, 10);

        // Replace with different limit
        let pool_v2 = test_pool("api", 50, 120);
        tracker.add_pool(pool_v2);

        let status2 = tracker.pool_status("api").unwrap();
        assert_eq!(status2.limit, 50);
        assert_eq!(status2.remaining, 50);
        assert_eq!(status2.window_seconds, 120);
    }

    // ---- reset_all with multiple pools ----

    #[test]
    fn tracker_reset_all_multiple_pools() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("a", 10, 60), test_pool("b", 20, 60)],
            tool_pool_map: HashMap::from([
                ("op_a".to_string(), vec!["a".to_string()]),
                ("op_b".to_string(), vec!["b".to_string()]),
            ]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);

        tracker.try_consume("op_a", 8);
        tracker.try_consume("op_b", 15);

        let before_a = tracker.pool_status("a").unwrap();
        assert_eq!(before_a.remaining, 2);
        let before_b = tracker.pool_status("b").unwrap();
        assert_eq!(before_b.remaining, 5);

        tracker.reset_all();

        let after_a = tracker.pool_status("a").unwrap();
        assert_eq!(after_a.remaining, 10);
        let after_b = tracker.pool_status("b").unwrap();
        assert_eq!(after_b.remaining, 20);
    }

    // ---- all_pool_statuses after consumption ----

    #[test]
    fn tracker_all_pool_statuses_after_consumption() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("a", 10, 60), test_pool("b", 20, 60)],
            tool_pool_map: HashMap::from([
                ("op_a".to_string(), vec!["a".to_string()]),
                ("op_b".to_string(), vec!["b".to_string()]),
            ]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);

        tracker.try_consume("op_a", 7);
        tracker.try_consume("op_b", 3);

        let all = tracker.all_pool_statuses();
        assert_eq!(all["a"].remaining, 3);
        assert_eq!(all["b"].remaining, 17);
    }

    // ---- is_limited partial consumption ----

    #[test]
    fn tracker_is_limited_partial_consumption() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("api", 10, 60)],
            tool_pool_map: HashMap::from([("op".to_string(), vec!["api".to_string()])]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);

        tracker.try_consume("op", 5);
        // Not limited yet, 5 remaining
        assert!(!tracker.is_limited("op"));
    }

    // ---- most_constrained when equal remaining ----

    #[test]
    fn tracker_most_constrained_equal_remaining() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("a", 10, 60), test_pool("b", 10, 60)],
            tool_pool_map: HashMap::from([(
                "op".to_string(),
                vec!["a".to_string(), "b".to_string()],
            )]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);

        // Both pools have equal remaining
        let result = tracker.most_constrained_status("op");
        assert!(result.is_some());
        let (_, status) = result.unwrap();
        assert_eq!(status.remaining, 10);
    }

    // ---- operation_status with exhausted pools ----

    #[test]
    fn tracker_operation_status_exhausted() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("api", 5, 60)],
            tool_pool_map: HashMap::from([("op".to_string(), vec!["api".to_string()])]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);
        tracker.try_consume("op", 5);

        let statuses = tracker.operation_status("op");
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].1.remaining, 0);
        assert!(statuses[0].1.is_limited());
    }

    // ---- Overlapping pool mappings ----

    #[test]
    fn tracker_overlapping_pool_mappings() {
        let decls = RateLimitDeclarations {
            limits: vec![
                test_pool("global", 100, 60),
                test_pool("read_pool", 50, 60),
                test_pool("write_pool", 20, 60),
            ],
            tool_pool_map: HashMap::from([
                (
                    "read".to_string(),
                    vec!["global".to_string(), "read_pool".to_string()],
                ),
                (
                    "write".to_string(),
                    vec!["global".to_string(), "write_pool".to_string()],
                ),
            ]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);

        // Read consumes from global + read_pool
        tracker.try_consume("read", 10);
        // Write consumes from global + write_pool
        tracker.try_consume("write", 5);

        let global = tracker.pool_status("global").unwrap();
        assert_eq!(global.remaining, 85); // 100 - 10 - 5

        let read = tracker.pool_status("read_pool").unwrap();
        assert_eq!(read.remaining, 40); // 50 - 10

        let write = tracker.pool_status("write_pool").unwrap();
        assert_eq!(write.remaining, 15); // 20 - 5
    }

    // ---- Soft + Hard mixed pool enforcement ----

    #[test]
    fn tracker_mixed_soft_hard_enforcement() {
        let soft = RateLimitPoolBuilder::new("soft_pool")
            .requests(2)
            .enforcement(RateLimitEnforcement::Soft)
            .build();
        let hard = RateLimitPoolBuilder::new("hard_pool")
            .requests(5)
            .enforcement(RateLimitEnforcement::Hard)
            .build();

        let decls = RateLimitDeclarations {
            limits: vec![soft, hard],
            tool_pool_map: HashMap::from([(
                "op".to_string(),
                vec!["soft_pool".to_string(), "hard_pool".to_string()],
            )]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);

        // Consume 2: both within limits
        assert!(tracker.try_consume("op", 2).is_none());
        // Consume 1 more: soft pool exceeded but passes, hard pool still fine
        assert!(tracker.try_consume("op", 1).is_none());
        // Consume 2 more: soft pool exceeded but passes, hard pool at limit (5)
        assert!(tracker.try_consume("op", 2).is_none());
        // Now hard pool exhausted at 5
        let err = tracker.try_consume("op", 1);
        assert!(err.is_some());
        assert_eq!(err.unwrap().pool_id, "hard_pool");
    }

    // ---- Builder: scope variants ----

    #[test]
    fn pool_builder_scope_global() {
        let pool = RateLimitPoolBuilder::new("g")
            .scope(RateLimitScope::Global)
            .build();
        assert_eq!(pool.scope, RateLimitScope::Global);
    }

    // ---- Builder: unit variants ----

    #[test]
    fn pool_builder_unit_bytes() {
        let pool = RateLimitPoolBuilder::new("b")
            .unit(RateLimitUnit::Bytes)
            .build();
        assert_eq!(pool.config.unit, RateLimitUnit::Bytes);
    }

    #[test]
    fn pool_builder_unit_custom() {
        let pool = RateLimitPoolBuilder::new("c")
            .unit(RateLimitUnit::Custom)
            .build();
        assert_eq!(pool.config.unit, RateLimitUnit::Custom);
    }

    // ---- Builder: Clone and Debug ----

    #[test]
    fn pool_builder_clone() {
        let builder = RateLimitPoolBuilder::new("original")
            .requests(42)
            .burst(7)
            .description("test desc");
        let cloned = builder.clone();
        let pool1 = builder.build();
        let pool2 = cloned.build();
        assert_eq!(pool1.id, pool2.id);
        assert_eq!(pool1.config.requests, pool2.config.requests);
        assert_eq!(pool1.config.burst, pool2.config.burst);
        assert_eq!(pool1.description, pool2.description);
    }

    #[test]
    fn pool_builder_debug() {
        let builder = RateLimitPoolBuilder::new("dbg_pool").requests(99);
        let debug = format!("{builder:?}");
        assert!(debug.contains("RateLimitPoolBuilder"));
        assert!(debug.contains("dbg_pool"));
    }

    // ---- Consume exactly at limit boundary ----

    #[test]
    fn tracker_consume_exactly_at_limit() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("api", 10, 60)],
            tool_pool_map: HashMap::from([("op".to_string(), vec!["api".to_string()])]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);

        // Consume exactly the limit in one shot
        assert!(tracker.try_consume("op", 10).is_none());
        // Status should show 0 remaining
        let status = tracker.pool_status("api").unwrap();
        assert_eq!(status.remaining, 0);
        assert!(status.is_limited());
    }

    // ---- Consume with u32::MAX overflow protection ----

    #[test]
    fn tracker_consume_overflow_protection() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("api", u32::MAX, 60)],
            tool_pool_map: HashMap::from([("op".to_string(), vec!["api".to_string()])]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);

        // Consume a large amount, then try to consume more without overflow
        assert!(tracker.try_consume("op", u32::MAX - 1).is_none());
        // Status should show 1 remaining
        let status = tracker.pool_status("api").unwrap();
        assert_eq!(status.remaining, 1);
    }

    // ---- Status reset_at is in the future ----

    #[test]
    fn pool_status_reset_at_in_future() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("api", 10, 60)],
            tool_pool_map: HashMap::new(),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);
        let status = tracker.pool_status("api").unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // reset_at should be approximately now + 60 (within tolerance)
        assert!(status.reset_at >= now);
        assert!(status.reset_at <= now + 61);
    }

    // ---- Soft limit force_consume increments count ----

    #[test]
    fn soft_limit_force_consume_increments() {
        let pool = RateLimitPoolBuilder::new("soft")
            .requests(2)
            .enforcement(RateLimitEnforcement::Soft)
            .build();

        let decls = RateLimitDeclarations {
            limits: vec![pool],
            tool_pool_map: HashMap::from([("op".to_string(), vec!["soft".to_string()])]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);

        // Consume beyond the limit with soft enforcement
        assert!(tracker.try_consume("op", 2).is_none());
        assert!(tracker.try_consume("op", 1).is_none()); // soft, still passes

        // Status should reflect the overconsumption
        let status = tracker.pool_status("soft").unwrap();
        // count is 3 (2 + force_consume(1)), limit is 2, remaining saturating_sub = 0
        assert_eq!(status.remaining, 0);
    }

    // ---- Advisory enforcement is_soft ----

    #[test]
    fn advisory_error_is_soft() {
        let err = RateLimitError {
            pool_id: "adv".into(),
            limit: 5,
            current: 6,
            retry_after_ms: 500,
            enforcement: RateLimitEnforcement::Advisory,
            message: "advisory exceeded".into(),
        };
        assert!(err.is_soft());
        // Also verify display uses the message
        assert_eq!(err.to_string(), "advisory exceeded");
    }

    // ---- Multiple add_pool calls ----

    #[test]
    fn tracker_add_multiple_pools() {
        let tracker = RateLimitTracker::new();

        tracker.add_pool(test_pool("pool_1", 10, 60));
        tracker.add_pool(test_pool("pool_2", 20, 120));
        tracker.add_pool(test_pool("pool_3", 30, 180));

        let all = tracker.all_pool_statuses();
        assert_eq!(all.len(), 3);
        assert_eq!(all["pool_1"].limit, 10);
        assert_eq!(all["pool_2"].limit, 20);
        assert_eq!(all["pool_3"].limit, 30);
    }

    // ---- Error retry_after_ms propagation ----

    #[test]
    fn rate_limit_error_retry_after_propagated() {
        let pool = test_pool("api", 2, 60);
        let err = RateLimitError::for_pool(&pool, 2, 42_000);
        assert_eq!(err.retry_after_ms, 42_000);

        let fcp_err = err.into_fcp_error();
        assert_eq!(fcp_err.retry_after(), Some(Duration::from_secs(42)));
    }

    // ---- Burst + status remaining tracking ----

    #[test]
    fn tracker_burst_status_remaining_tracks_correctly() {
        let pool = RateLimitPoolBuilder::new("bp")
            .requests(5)
            .burst(3)
            .window_secs(60)
            .build();

        let decls = RateLimitDeclarations {
            limits: vec![pool],
            tool_pool_map: HashMap::from([("op".to_string(), vec!["bp".to_string()])]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);

        // Effective limit = 5 + 3 = 8
        tracker.try_consume("op", 6);
        let status = tracker.pool_status("bp").unwrap();
        assert_eq!(status.limit, 8);
        assert_eq!(status.remaining, 2);
    }

    // ---- for_pool enforcement field ----

    #[test]
    fn for_pool_captures_enforcement() {
        let pool = RateLimitPoolBuilder::new("hard_pool")
            .requests(10)
            .enforcement(RateLimitEnforcement::Hard)
            .build();
        let err = RateLimitError::for_pool(&pool, 10, 1000);
        assert!(!err.is_soft());

        let soft_pool = RateLimitPoolBuilder::new("soft_pool")
            .requests(10)
            .enforcement(RateLimitEnforcement::Soft)
            .build();
        let soft_err = RateLimitError::for_pool(&soft_pool, 10, 1000);
        assert!(soft_err.is_soft());
    }

    // ---- Tracker: from_declarations with empty limits ----

    #[test]
    fn tracker_from_declarations_empty() {
        let decls = RateLimitDeclarations {
            limits: vec![],
            tool_pool_map: HashMap::new(),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);
        assert!(tracker.all_pool_statuses().is_empty());
        // Operations on empty tracker should be no-ops
        assert!(tracker.try_consume("anything", 1).is_none());
        assert!(!tracker.is_limited("anything"));
    }

    // ---- Tracker: consume from same pool via different operations ----

    #[test]
    fn tracker_consume_interleaved_operations_same_pool() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("api", 6, 60)],
            tool_pool_map: HashMap::from([
                ("read".to_string(), vec!["api".to_string()]),
                ("write".to_string(), vec!["api".to_string()]),
                ("delete".to_string(), vec!["api".to_string()]),
            ]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);

        assert!(tracker.try_consume("read", 2).is_none());
        assert!(tracker.try_consume("write", 2).is_none());
        assert!(tracker.try_consume("delete", 2).is_none());

        // Pool exhausted, all operations blocked
        assert!(tracker.try_consume("read", 1).is_some());
        assert!(tracker.try_consume("write", 1).is_some());
        assert!(tracker.try_consume("delete", 1).is_some());
    }

    // ── NEW: RateLimitError field validation ────────────────────────────

    #[test]
    fn rate_limit_error_for_pool_field_values() {
        let pool = RateLimitPoolBuilder::new("test_pool")
            .requests(25)
            .enforcement(RateLimitEnforcement::Hard)
            .build();
        let err = RateLimitError::for_pool(&pool, 20, 15_000);
        assert_eq!(err.pool_id, "test_pool");
        assert_eq!(err.limit, 25);
        assert_eq!(err.current, 20);
        assert_eq!(err.retry_after_ms, 15_000);
        assert!(!err.is_soft());
    }

    #[test]
    fn rate_limit_error_for_pool_zero_current() {
        let pool = test_pool("api", 10, 60);
        let err = RateLimitError::for_pool(&pool, 0, 500);
        assert_eq!(err.current, 0);
        assert!(err.message.contains('0'));
    }

    #[test]
    fn rate_limit_error_for_pool_zero_retry_after() {
        let pool = test_pool("api", 5, 60);
        let err = RateLimitError::for_pool(&pool, 5, 0);
        assert_eq!(err.retry_after_ms, 0);
        let fcp_err = err.into_fcp_error();
        assert_eq!(fcp_err.retry_after(), Some(Duration::ZERO));
    }

    #[test]
    fn rate_limit_error_into_fcp_error_violation_is_none() {
        let err = RateLimitError {
            pool_id: "p".into(),
            limit: 10,
            current: 10,
            retry_after_ms: 1000,
            enforcement: RateLimitEnforcement::Hard,
            message: "exceeded".into(),
        };
        let fcp_err = err.into_fcp_error();
        match fcp_err {
            FcpError::RateLimited { violation, .. } => assert!(violation.is_none()),
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn rate_limit_error_display_equals_message() {
        let err = RateLimitError {
            pool_id: "pool".into(),
            limit: 5,
            current: 5,
            retry_after_ms: 100,
            enforcement: RateLimitEnforcement::Hard,
            message: "custom message here".into(),
        };
        assert_eq!(format!("{err}"), "custom message here");
    }

    #[test]
    fn rate_limit_error_std_error_source_is_none() {
        let err = RateLimitError {
            pool_id: "p".into(),
            limit: 1,
            current: 1,
            retry_after_ms: 0,
            enforcement: RateLimitEnforcement::Hard,
            message: "msg".into(),
        };
        // std::error::Error default source() returns None
        assert!(std::error::Error::source(&err).is_none());
    }

    // ── NEW: RateLimitPoolBuilder edge cases ────────────────────────────

    #[test]
    fn pool_builder_zero_requests() {
        let pool = RateLimitPoolBuilder::new("zero_pool").requests(0).build();
        assert_eq!(pool.config.requests, 0);
    }

    #[test]
    fn pool_builder_large_requests() {
        let pool = RateLimitPoolBuilder::new("big").requests(u32::MAX).build();
        assert_eq!(pool.config.requests, u32::MAX);
    }

    #[test]
    fn pool_builder_large_burst() {
        let pool = RateLimitPoolBuilder::new("burst_big")
            .requests(100)
            .burst(u32::MAX)
            .build();
        assert_eq!(pool.config.burst, Some(u32::MAX));
    }

    #[test]
    fn pool_builder_zero_window() {
        let pool = RateLimitPoolBuilder::new("zero_window")
            .window_secs(0)
            .build();
        assert_eq!(pool.config.window, Duration::ZERO);
    }

    #[test]
    fn pool_builder_sub_second_window() {
        let pool = RateLimitPoolBuilder::new("fast")
            .window(Duration::from_millis(100))
            .build();
        assert_eq!(pool.config.window, Duration::from_millis(100));
    }

    #[test]
    fn pool_builder_empty_id() {
        let pool = RateLimitPoolBuilder::new("").build();
        assert_eq!(pool.id, "");
    }

    #[test]
    fn pool_builder_long_description() {
        let desc = "x".repeat(1000);
        let pool = RateLimitPoolBuilder::new("p")
            .description(desc.as_str())
            .build();
        assert_eq!(pool.description.len(), 1000);
    }

    #[test]
    fn pool_builder_all_enforcement_variants() {
        for enforcement in [
            RateLimitEnforcement::Hard,
            RateLimitEnforcement::Soft,
            RateLimitEnforcement::Advisory,
        ] {
            let pool = RateLimitPoolBuilder::new("e")
                .enforcement(enforcement)
                .build();
            assert_eq!(pool.enforcement, enforcement);
        }
    }

    #[test]
    fn pool_builder_all_scope_variants() {
        for scope in [
            RateLimitScope::Instance,
            RateLimitScope::Credential,
            RateLimitScope::Global,
        ] {
            let pool = RateLimitPoolBuilder::new("s").scope(scope).build();
            assert_eq!(pool.scope, scope);
        }
    }

    #[test]
    fn pool_builder_all_unit_variants() {
        for unit in [
            RateLimitUnit::Requests,
            RateLimitUnit::Tokens,
            RateLimitUnit::Bytes,
            RateLimitUnit::Custom,
        ] {
            let pool = RateLimitPoolBuilder::new("u").unit(unit).build();
            assert_eq!(pool.config.unit, unit);
        }
    }

    // ── NEW: Tracker consume boundary tests ─────────────────────────────

    #[test]
    fn tracker_consume_one_less_than_limit() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("api", 5, 60)],
            tool_pool_map: HashMap::from([("op".to_string(), vec!["api".to_string()])]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);
        assert!(tracker.try_consume("op", 4).is_none());
        let status = tracker.pool_status("api").unwrap();
        assert_eq!(status.remaining, 1);
        assert!(!status.is_limited());
    }

    #[test]
    fn tracker_consume_one_more_than_limit() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("api", 5, 60)],
            tool_pool_map: HashMap::from([("op".to_string(), vec!["api".to_string()])]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);
        let err = tracker.try_consume("op", 6).unwrap();
        assert_eq!(err.limit, 5);
        assert_eq!(err.current, 0);
    }

    #[test]
    fn tracker_repeated_single_consume_to_exhaustion() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("api", 3, 60)],
            tool_pool_map: HashMap::from([("op".to_string(), vec!["api".to_string()])]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);
        for i in 0..3 {
            assert!(
                tracker.try_consume("op", 1).is_none(),
                "consume {i} should succeed"
            );
        }
        assert!(tracker.try_consume("op", 1).is_some());
    }

    // ── NEW: Tracker status validation ──────────────────────────────────

    #[test]
    fn tracker_pool_status_after_partial_consume() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("api", 10, 60)],
            tool_pool_map: HashMap::from([("op".to_string(), vec!["api".to_string()])]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);
        tracker.try_consume("op", 7);
        let status = tracker.pool_status("api").unwrap();
        assert_eq!(status.limit, 10);
        assert_eq!(status.remaining, 3);
        assert!(!status.is_limited());
    }

    #[test]
    fn tracker_pool_status_fully_consumed() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("api", 5, 60)],
            tool_pool_map: HashMap::from([("op".to_string(), vec!["api".to_string()])]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);
        tracker.try_consume("op", 5);
        let status = tracker.pool_status("api").unwrap();
        assert_eq!(status.remaining, 0);
        assert!(status.is_limited());
    }

    #[test]
    fn tracker_pool_status_nonexistent_returns_none() {
        let tracker = RateLimitTracker::new();
        assert!(tracker.pool_status("does_not_exist").is_none());
    }

    // ── NEW: Tracker operation_status details ───────────────────────────

    #[test]
    fn tracker_operation_status_multiple_pools_remaining() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("a", 10, 60), test_pool("b", 20, 60)],
            tool_pool_map: HashMap::from([(
                "op".to_string(),
                vec!["a".to_string(), "b".to_string()],
            )]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);
        tracker.try_consume("op", 3);

        let statuses = tracker.operation_status("op");
        let a_status = statuses.iter().find(|(id, _)| id == "a").unwrap();
        let b_status = statuses.iter().find(|(id, _)| id == "b").unwrap();
        assert_eq!(a_status.1.remaining, 7);
        assert_eq!(b_status.1.remaining, 17);
    }

    // ── NEW: Tracker most_constrained_status detailed ───────────────────

    #[test]
    fn tracker_most_constrained_after_asymmetric_consume() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("fast", 3, 60), test_pool("slow", 100, 60)],
            tool_pool_map: HashMap::from([(
                "op".to_string(),
                vec!["fast".to_string(), "slow".to_string()],
            )]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);
        tracker.try_consume("op", 2);

        let (id, status) = tracker.most_constrained_status("op").unwrap();
        assert_eq!(id, "fast");
        assert_eq!(status.remaining, 1);
    }

    // ── NEW: Tracker reset_all restores capacity ────────────────────────

    #[test]
    fn tracker_reset_all_restores_full_capacity() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("api", 10, 60)],
            tool_pool_map: HashMap::from([("op".to_string(), vec!["api".to_string()])]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);
        tracker.try_consume("op", 10);
        assert!(tracker.is_limited("op"));

        tracker.reset_all();
        assert!(!tracker.is_limited("op"));
        let status = tracker.pool_status("api").unwrap();
        assert_eq!(status.remaining, 10);
    }

    // ── NEW: Tracker with burst + consume behavior ──────────────────────

    #[test]
    fn tracker_burst_consume_exactly_at_effective_limit() {
        let pool = RateLimitPoolBuilder::new("bp").requests(5).burst(5).build();
        let decls = RateLimitDeclarations {
            limits: vec![pool],
            tool_pool_map: HashMap::from([("op".to_string(), vec!["bp".to_string()])]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);

        // Effective limit = 10
        assert!(tracker.try_consume("op", 10).is_none());
        let status = tracker.pool_status("bp").unwrap();
        assert_eq!(status.remaining, 0);
        assert!(status.is_limited());
    }

    #[test]
    fn tracker_burst_consume_one_over_effective_limit() {
        let pool = RateLimitPoolBuilder::new("bp").requests(5).burst(5).build();
        let decls = RateLimitDeclarations {
            limits: vec![pool],
            tool_pool_map: HashMap::from([("op".to_string(), vec!["bp".to_string()])]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);

        let err = tracker.try_consume("op", 11).unwrap();
        assert_eq!(err.pool_id, "bp");
    }

    // ── NEW: Tracker clone independence for operation_map ────────────────

    #[test]
    fn tracker_clone_shares_pools_via_arc() {
        let tracker = RateLimitTracker::new();
        tracker.add_pool(test_pool("p", 10, 60));
        let cloned = tracker.clone();

        // Both should see the same pool
        assert!(tracker.pool_status("p").is_some());
        assert!(cloned.pool_status("p").is_some());
    }

    // ── NEW: Advisory force_consume behavior ────────────────────────────

    #[test]
    fn advisory_limit_force_consume_tracks_count() {
        let pool = RateLimitPoolBuilder::new("adv")
            .requests(1)
            .enforcement(RateLimitEnforcement::Advisory)
            .build();
        let decls = RateLimitDeclarations {
            limits: vec![pool],
            tool_pool_map: HashMap::from([("op".to_string(), vec!["adv".to_string()])]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);

        // Advisory allows overconsumption
        assert!(tracker.try_consume("op", 1).is_none());
        assert!(tracker.try_consume("op", 1).is_none());
        assert!(tracker.try_consume("op", 1).is_none());
        // Count is now 3 but advisory never blocks
    }

    // ── NEW: Multiple pools with different windows ──────────────────────

    #[test]
    fn tracker_pools_different_windows() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("minute", 60, 60), test_pool("hour", 1000, 3600)],
            tool_pool_map: HashMap::from([(
                "op".to_string(),
                vec!["minute".to_string(), "hour".to_string()],
            )]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);

        let min_status = tracker.pool_status("minute").unwrap();
        assert_eq!(min_status.window_seconds, 60);

        let hour_status = tracker.pool_status("hour").unwrap();
        assert_eq!(hour_status.window_seconds, 3600);
    }

    // ── NEW: RateLimitError message contains pool name ──────────────────

    #[test]
    fn rate_limit_error_message_contains_all_info() {
        let pool = test_pool("special_pool", 42, 120);
        let err = RateLimitError::for_pool(&pool, 39, 5000);
        assert!(err.message.contains("special_pool"));
        assert!(err.message.contains("39"));
        assert!(err.message.contains("42"));
        assert!(err.message.contains("Rate limit exceeded"));
    }

    // ── NEW: Tracker is_limited with burst ──────────────────────────────

    #[test]
    fn tracker_is_limited_with_burst_not_limited_at_base() {
        let pool = RateLimitPoolBuilder::new("bp").requests(5).burst(5).build();
        let decls = RateLimitDeclarations {
            limits: vec![pool],
            tool_pool_map: HashMap::from([("op".to_string(), vec!["bp".to_string()])]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);
        tracker.try_consume("op", 5);
        // Not limited because burst capacity remains
        assert!(!tracker.is_limited("op"));
    }

    #[test]
    fn tracker_is_limited_with_burst_at_effective_limit() {
        let pool = RateLimitPoolBuilder::new("bp").requests(5).burst(5).build();
        let decls = RateLimitDeclarations {
            limits: vec![pool],
            tool_pool_map: HashMap::from([("op".to_string(), vec!["bp".to_string()])]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);
        tracker.try_consume("op", 10);
        assert!(tracker.is_limited("op"));
    }

    // ── NEW: Declarations with duplicate pool IDs ───────────────────────

    #[test]
    fn tracker_declarations_duplicate_pool_ids_last_wins() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("api", 10, 60), test_pool("api", 99, 120)],
            tool_pool_map: HashMap::new(),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);
        let status = tracker.pool_status("api").unwrap();
        // HashMap insert: last wins
        assert_eq!(status.limit, 99);
    }

    // ── NEW: all_pool_statuses reflects consumption ─────────────────────

    #[test]
    fn tracker_all_pool_statuses_after_mixed_ops() {
        let decls = RateLimitDeclarations {
            limits: vec![
                test_pool("a", 10, 60),
                test_pool("b", 20, 60),
                test_pool("c", 30, 60),
            ],
            tool_pool_map: HashMap::from([
                ("op_a".to_string(), vec!["a".to_string()]),
                ("op_b".to_string(), vec!["b".to_string()]),
            ]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);
        tracker.try_consume("op_a", 5);
        tracker.try_consume("op_b", 10);

        let all = tracker.all_pool_statuses();
        assert_eq!(all.len(), 3);
        assert_eq!(all["a"].remaining, 5);
        assert_eq!(all["b"].remaining, 10);
        assert_eq!(all["c"].remaining, 30); // untouched
    }

    // ── NEW: Tracker consume u32::MAX boundary ──────────────────────────

    #[test]
    fn tracker_consume_max_u32_succeeds_when_limit_is_max() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("big", u32::MAX, 60)],
            tool_pool_map: HashMap::from([("op".to_string(), vec!["big".to_string()])]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);
        assert!(tracker.try_consume("op", u32::MAX).is_none());
        let status = tracker.pool_status("big").unwrap();
        assert_eq!(status.remaining, 0);
    }

    // ── NEW: RateLimitError enforcement variants are preserved ──────────

    #[test]
    fn rate_limit_error_enforcement_hard() {
        let pool = RateLimitPoolBuilder::new("h")
            .enforcement(RateLimitEnforcement::Hard)
            .build();
        let err = RateLimitError::for_pool(&pool, 0, 0);
        assert_eq!(err.enforcement, RateLimitEnforcement::Hard);
        assert!(!err.is_soft());
    }

    #[test]
    fn rate_limit_error_enforcement_soft() {
        let pool = RateLimitPoolBuilder::new("s")
            .enforcement(RateLimitEnforcement::Soft)
            .build();
        let err = RateLimitError::for_pool(&pool, 0, 0);
        assert_eq!(err.enforcement, RateLimitEnforcement::Soft);
        assert!(err.is_soft());
    }

    #[test]
    fn rate_limit_error_enforcement_advisory() {
        let pool = RateLimitPoolBuilder::new("a")
            .enforcement(RateLimitEnforcement::Advisory)
            .build();
        let err = RateLimitError::for_pool(&pool, 0, 0);
        assert_eq!(err.enforcement, RateLimitEnforcement::Advisory);
        assert!(err.is_soft());
    }

    // ── br-flywheel_connectors-e8v7i: sliding-window boundary protection ──

    /// Build a `PoolState` directly so we can drive the time-of-day-style
    /// boundary scenarios without sleeping in tests. We splice the
    /// `window_start` to simulate "elapsed time" deterministically.
    fn pool_state(id: &str, requests: u32, window: Duration) -> PoolState {
        let pool = RateLimitPoolBuilder::new(id)
            .requests(requests)
            .window_secs(window.as_secs().max(1))
            .build();
        let mut state = PoolState::new(pool);
        // Use the requested window directly (build-from-secs only takes whole
        // seconds; we want to test sub-second windows too).
        state.config.config.window = window;
        state
    }

    #[test]
    fn sliding_window_blocks_boundary_burst_2x() {
        // Classic fixed-window exploit: consume `limit` near the end of window
        // N, then immediately consume `limit` more at the start of window N+1.
        // A hard fixed-window reset would admit all 2*limit requests in a few
        // milliseconds. The sliding-window estimator must reject the second
        // burst because prev_count still contributes most of its weight at
        // the start of the new window.
        let mut state = pool_state("burst", 10, Duration::from_secs(60));

        // Phase 1: consume the full limit in the first window.
        for _ in 0..10 {
            state.try_consume(1).expect("phase1 within limit");
        }

        // Cross the window boundary: rewind window_start by exactly one
        // window so maybe_advance_window rolls prev_count := curr_count = 10.
        state.window_start -= Duration::from_secs(60);
        state.maybe_advance_window();
        assert_eq!(state.prev_count, 10);
        assert_eq!(state.curr_count, 0);

        // We're effectively at "elapsed = 0" in the new window. The sliding
        // estimate is prev * (1 - 0) + curr = 10 + 0 = 10. The limit is 10,
        // so any further consumption MUST be rejected.
        let err = state
            .try_consume(1)
            .expect_err("boundary burst must be rejected");
        assert_eq!(err.current, 10, "effective count == prev_count at t=0");

        // Even consuming a single request must fail until the prev_count
        // contribution decays. Walk forward halfway through the new window:
        // estimate = 10 * 0.5 + 0 = 5, so we should be able to consume up
        // to 5 more.
        state.window_start -= Duration::from_secs(30);
        state.try_consume(5).expect("at t=window/2, 5 slots free");
        let err = state
            .try_consume(1)
            .expect_err("at t=window/2, the 6th request must be rejected");
        assert_eq!(err.current, 10);
    }

    #[test]
    fn sliding_window_full_idle_window_clears_prev_count() {
        // If the connector is idle for 2+ full windows, the previous window
        // is no longer "immediately preceding" so it must not contribute.
        let mut state = pool_state("idle", 10, Duration::from_secs(60));
        for _ in 0..10 {
            state.try_consume(1).expect("phase1");
        }

        // Skip two full windows.
        state.window_start -= Duration::from_secs(120);
        state.maybe_advance_window();
        assert_eq!(state.prev_count, 0, "two-window gap drops prev");
        assert_eq!(state.curr_count, 0);

        // Full capacity is available immediately.
        for _ in 0..10 {
            state.try_consume(1).expect("post-idle full capacity");
        }
    }

    #[test]
    fn sliding_window_within_window_behaves_like_fixed_window() {
        // Backward-compat sanity: simple sequential consume in a single
        // window must still admit exactly `limit` and reject the next.
        let mut state = pool_state("seq", 5, Duration::from_secs(60));
        for _ in 0..5 {
            state.try_consume(1).expect("within limit");
        }
        let err = state
            .try_consume(1)
            .expect_err("over limit within single window");
        assert_eq!(err.current, 5);
    }

    #[test]
    fn sliding_window_throughput_over_two_windows_bounded_by_2x() {
        // Across two windows, the total admitted requests must be at most
        // 2 * limit (and in the boundary-burst pattern, strictly less).
        let mut state = pool_state("throughput", 10, Duration::from_secs(60));

        // Window 1: consume to the limit.
        let mut admitted = 0u32;
        while state.try_consume(1).is_ok() {
            admitted += 1;
            if admitted >= 100 {
                break;
            }
        }
        assert_eq!(admitted, 10, "window 1 admits exactly limit");

        // Roll to window 2.
        state.window_start -= Duration::from_secs(60);
        state.maybe_advance_window();

        // Drain window 2 trying to maximize admission. Walk window in
        // small steps so the prev_count contribution decays.
        let step = Duration::from_millis(100);
        let mut window_extra = 0u32;
        while state.window_start.elapsed() < Duration::from_secs(60)
            && admitted + window_extra < 100
        {
            if state.try_consume(1).is_ok() {
                window_extra += 1;
            }
            state.window_start -= step;
        }

        // Total across the two windows must not exceed 2 * limit. With the
        // sliding estimator and 100ms steps, the achievable total is the
        // remainder after the prev_count's linear decay — comfortably
        // bounded below 2 * limit and never above it.
        let total = admitted + window_extra;
        assert!(
            total <= 20,
            "total admissions across two windows must not exceed 2*limit; got {total}"
        );
    }

    #[test]
    fn sliding_window_force_consume_increments_curr_only() {
        // Soft/advisory limits use force_consume; it must accumulate into
        // curr_count and roll over the same way under maybe_advance_window.
        let mut state = pool_state("soft", 10, Duration::from_secs(60));
        state.force_consume(7);
        assert_eq!(state.curr_count, 7);
        assert_eq!(state.prev_count, 0);

        state.window_start -= Duration::from_secs(60);
        state.maybe_advance_window();
        assert_eq!(state.prev_count, 7);
        assert_eq!(state.curr_count, 0);
    }

    #[test]
    fn tracker_restores_persisted_pool_usage_after_restart() {
        let state_dir = unique_state_dir("restart");
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("api", 3, 60)],
            tool_pool_map: HashMap::from([("send".to_string(), vec!["api".to_string()])]),
        };

        let tracker = RateLimitTracker::from_declarations_with_state_dir(&decls, &state_dir);
        assert!(tracker.try_consume("send", 1).is_none());
        assert!(tracker.try_consume("send", 1).is_none());

        let restarted = RateLimitTracker::from_declarations_with_state_dir(&decls, &state_dir);
        assert!(restarted.try_consume("send", 1).is_none());
        let err = restarted
            .try_consume("send", 1)
            .expect("restart should not reset the persisted bucket");
        assert_eq!(err.pool_id, "api");
    }

    #[test]
    fn persisted_checkpoints_are_namespaced_by_scope_and_pool_id() {
        let state_dir = unique_state_dir("scope-key");
        let global_decls = RateLimitDeclarations {
            limits: vec![
                RateLimitPoolBuilder::new("shared")
                    .requests(2)
                    .window_secs(60)
                    .scope(RateLimitScope::Global)
                    .build(),
            ],
            tool_pool_map: HashMap::from([("op".to_string(), vec!["shared".to_string()])]),
        };
        let global_tracker =
            RateLimitTracker::from_declarations_with_state_dir(&global_decls, &state_dir);
        assert!(global_tracker.try_consume("op", 1).is_none());

        let instance_decls = RateLimitDeclarations {
            limits: vec![
                RateLimitPoolBuilder::new("shared")
                    .requests(2)
                    .window_secs(60)
                    .scope(RateLimitScope::Instance)
                    .build(),
            ],
            tool_pool_map: HashMap::from([("op".to_string(), vec!["shared".to_string()])]),
        };
        let instance_tracker =
            RateLimitTracker::from_declarations_with_state_dir(&instance_decls, &state_dir);
        let status = instance_tracker
            .pool_status("shared")
            .expect("instance pool should be registered");
        assert_eq!(status.remaining, 2);
    }

    // ── br-ogeov: concurrent persist must not corrupt checkpoint file ──

    #[test]
    fn concurrent_try_consume_keeps_checkpoint_file_valid_json() {
        // br-ogeov regression: prior implementation released the
        // pools.write() lock before calling persist_file, which used
        // File::create + write_all on a single shared path with no
        // tempfile + rename and no I/O serialization. Two concurrent
        // try_consume calls could race and produce a torn or
        // interleaved checkpoint file that fails JSON parse on the
        // next startup, silently dropping all rate-limit state.
        //
        // The fix routes every persist through a unique temp file
        // followed by an atomic rename, with the rename body held
        // under an I/O Mutex on the store. This test spins many
        // threads racing on the same tracker and asserts that on
        // every iteration the file is still valid JSON of the
        // expected shape.
        const THREADS: usize = 16;
        const ITERS_PER_THREAD: usize = 250;

        let state_dir = unique_state_dir("concurrent-persist");
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("api", 1_000_000, 60)],
            tool_pool_map: HashMap::from([("op".to_string(), vec!["api".to_string()])]),
        };
        let tracker = Arc::new(RateLimitTracker::from_declarations_with_state_dir(
            &decls, &state_dir,
        ));
        let checkpoint_path = state_dir.join(RATE_LIMIT_CHECKPOINT_FILE);

        let mut handles = Vec::with_capacity(THREADS);
        for _ in 0..THREADS {
            let tracker = Arc::clone(&tracker);
            handles.push(std::thread::spawn(move || {
                for iteration in 0..ITERS_PER_THREAD {
                    assert!(
                        tracker.try_consume("op", 1).is_none(),
                        "try_consume rejected iteration {iteration}/{ITERS_PER_THREAD}; \
                         checkpoint pool state may have been lost mid-storm"
                    );
                }
            }));
        }

        // Reader thread continuously parses the file while writers
        // race. Any torn write surfaces as a parse failure here.
        let reader_path = checkpoint_path.clone();
        let reader_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reader_stop_clone = Arc::clone(&reader_stop);
        let reader = std::thread::spawn(move || {
            let mut observed_max_total: u64 = 0;
            while !reader_stop_clone.load(std::sync::atomic::Ordering::Relaxed) {
                let bytes = match std::fs::read(&reader_path) {
                    Ok(bytes) => bytes,
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(err) => panic!("reader hit unexpected io error: {err}"),
                };
                if bytes.is_empty() {
                    continue;
                }
                // br-mvl7c: on a torn read, the offending bytes are the only
                // evidence — print an excerpt with the parse error.
                let parsed: RateLimitCheckpointFile = serde_json::from_slice(&bytes)
                    .unwrap_or_else(|error| {
                        panic!(
                            "checkpoint file must always remain valid JSON under concurrent \
                             persist: parse error {error}; len={}; excerpt: {}",
                            bytes.len(),
                            String::from_utf8_lossy(&bytes[..bytes.len().min(256)])
                        )
                    });
                assert_eq!(parsed.version, RATE_LIMIT_CHECKPOINT_VERSION);
                let pool = parsed
                    .pools
                    .values()
                    .next()
                    .expect("expected one pool in checkpoint");
                let total = u64::from(pool.prev_count) + u64::from(pool.curr_count);
                observed_max_total = observed_max_total.max(total);
            }
            observed_max_total
        });

        for handle in handles {
            handle.join().expect("writer thread");
        }
        reader_stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let observed_max_total = reader.join().expect("reader thread");

        // Final on-disk state must also be valid and reflect every
        // accepted request (no lost writes after the storm settles).
        let final_bytes = std::fs::read(&checkpoint_path).expect("final checkpoint should exist");
        let final_parsed: RateLimitCheckpointFile = serde_json::from_slice(&final_bytes)
            .unwrap_or_else(|error| {
                panic!(
                    "final checkpoint must be valid JSON: parse error {error}; len={}; \
                     excerpt: {}",
                    final_bytes.len(),
                    String::from_utf8_lossy(&final_bytes[..final_bytes.len().min(256)])
                )
            });
        let final_pool = final_parsed
            .pools
            .values()
            .next()
            .expect("expected one pool");
        let final_total = u64::from(final_pool.prev_count) + u64::from(final_pool.curr_count);
        let expected = (THREADS * ITERS_PER_THREAD) as u64;
        assert_eq!(
            final_total, expected,
            "every accepted try_consume must be reflected in the final persisted snapshot"
        );
        assert!(
            observed_max_total <= expected,
            "reader observed total {observed_max_total} exceeding the expected {expected}; \
             that would indicate uninitialized data leaked into the parsed JSON"
        );
    }

    // ── br-flywheel_connectors-83xt1: fail-closed on unregistered pool ──

    #[test]
    fn try_consume_fails_closed_on_unregistered_pool() {
        // Directly construct a tracker whose operation_map references a
        // pool id that is NOT present in `pools`. Prior behavior silently
        // skipped the missing pool and admitted every request for that
        // operation. Fail-closed behavior must return a hard
        // RateLimitError naming the missing pool.
        let mut operation_map: HashMap<String, Vec<String>> = HashMap::new();
        operation_map.insert("send_message".into(), vec!["phantom_pool".into()]);

        let tracker = RateLimitTracker {
            pools: Arc::new(RwLock::new(HashMap::new())),
            operation_map: Arc::new(operation_map),
            checkpoint_store: None,
        };

        let err = tracker
            .try_consume("send_message", 1)
            .expect("missing pool must fail closed");
        assert_eq!(err.pool_id, "phantom_pool");
        assert!(!err.is_soft(), "unregistered-pool error must be hard");
        assert!(
            err.message.contains("phantom_pool") && err.message.contains("send_message"),
            "message must name both pool and operation: {}",
            err.message
        );
    }

    #[test]
    fn try_consume_unknown_operation_still_returns_none() {
        // An operation that doesn't appear in operation_map at all is a
        // separate case from an operation whose pools are missing — the
        // former means the caller is asking about an unknown op and the
        // tracker has no opinion. Preserved behavior: return None.
        let tracker = RateLimitTracker::new();
        assert!(tracker.try_consume("anything", 1).is_none());
    }

    #[test]
    fn try_consume_partial_missing_pool_fails_closed() {
        // operation_map points at two pools; only one is registered. The
        // missing-pool branch must fire before any capacity check so the
        // registered pool is never consumed-from.
        let pool = RateLimitPoolBuilder::new("real_pool")
            .requests(100)
            .window_secs(60)
            .build();

        let mut pools: HashMap<String, PoolState> = HashMap::new();
        pools.insert("real_pool".into(), PoolState::new(pool));

        let mut operation_map: HashMap<String, Vec<String>> = HashMap::new();
        operation_map.insert("op".into(), vec!["real_pool".into(), "ghost_pool".into()]);

        let tracker = RateLimitTracker {
            pools: Arc::new(RwLock::new(pools)),
            operation_map: Arc::new(operation_map),
            checkpoint_store: None,
        };

        let err = tracker.try_consume("op", 1).expect("must fail closed");
        assert_eq!(err.pool_id, "ghost_pool");

        // The registered pool's counter must be untouched: fail-closed
        // happens in the up-front guard, before Phase 2 consume.
        let status = tracker
            .pool_status("real_pool")
            .expect("real_pool is registered");
        assert_eq!(
            status.remaining, 100,
            "real_pool must not have been consumed"
        );
    }
}
