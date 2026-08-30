//! WASI Preview2 runtime for FCP2 connector execution.
//!
//! This module provides a WebAssembly System Interface (WASI) runtime that
//! enforces FCP2 sandbox policies for connector execution. All hostcalls are
//! capability-gated according to the `CompiledPolicy`:
//!
//! - **Filesystem**: Access scoped to manifest-declared readonly/writable paths
//! - **Network**: All egress routed through the Network Guard (egress proxy)
//! - **Clocks**: Deterministic or explicitly granted
//! - **Entropy**: Deterministic or explicitly granted
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    FCP2 WASI Runtime                            │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
//! │  │ WasiRuntime │──│CompiledPolicy│──│     EgressGuard         │  │
//! │  │  (wasmtime) │  │ (sandbox)   │  │  (network mediation)    │  │
//! │  └──────┬──────┘  └─────────────┘  └───────────┬─────────────┘  │
//! │         │                                      │                │
//! │         ▼                                      ▼                │
//! │  ┌─────────────────────────────────────────────────────────────┐│
//! │  │           Capability-Gated Hostcalls                        ││
//! │  │  ┌────────┐  ┌────────┐  ┌────────┐  ┌────────────────────┐ ││
//! │  │  │   FS   │  │ Clock  │  │ Random │  │      Network       │ ││
//! │  │  │(scoped)│  │(determ)│  │(determ)│  │ (via EgressGuard)  │ ││
//! │  │  └────────┘  └────────┘  └────────┘  └────────────────────┘ ││
//! │  └─────────────────────────────────────────────────────────────┘│
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use fcp_sandbox::{CompiledPolicy, WasiRuntime, WasiConfig};
//! use fcp_manifest::SandboxSection;
//!
//! // 1. Compile policy from manifest
//! let policy = CompiledPolicy::from_manifest(&manifest.sandbox, Some(state_dir))?;
//!
//! // 2. Create WASI runtime with policy
//! let config = WasiConfig::from_policy(&policy)?;
//! let runtime = WasiRuntime::new(config)?;
//!
//! // 3. Load and run connector component
//! let component = runtime.load_component(&wasm_bytes)?;
//! let args = vec!["--dry-run".to_string()];
//! let result = runtime.invoke(&component, "run", &args).await?;
//! assert_eq!(result.exit_code, 0);
//! ```

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use thiserror::Error;
use tracing::{debug, info, trace};
use wasmtime::{
    Config, Engine, Store,
    component::{Component, Linker, ResourceTable},
};
use wasmtime_wasi::{
    Deterministic, DirPerms, FilePerms, WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView,
    clocks::{HostMonotonicClock, HostWallClock},
    sockets::SocketAddrUse,
};

use crate::egress::{
    CredentialInjector, EgressDecision, EgressGuard, EgressHttpRequest, EgressRequest,
    EgressTcpConnectRequest, EgressTcpDecision,
};
use crate::sandbox::{CompiledPolicy, SandboxError, resolve_policy_path};
use fcp_manifest::NetworkConstraints;

// ============================================================================
// Errors
// ============================================================================

/// Errors from WASI runtime operations.
#[derive(Debug, Error)]
pub enum WasiError {
    /// Failed to create the WASI runtime engine.
    #[error("failed to create WASI engine: {0}")]
    EngineCreation(String),

    /// Failed to load a WebAssembly component.
    #[error("failed to load component: {0}")]
    ComponentLoad(String),

    /// Failed to instantiate the component.
    #[error("failed to instantiate component: {0}")]
    Instantiation(String),

    /// Component execution failed.
    #[error("component execution failed: {0}")]
    Execution(String),

    /// Resource limit exceeded during execution.
    #[error("resource limit exceeded: {0}")]
    ResourceLimit(String),

    /// Wall-clock timeout exceeded.
    #[error("wall-clock timeout exceeded")]
    Timeout,

    /// Filesystem access denied by policy.
    #[error("filesystem access denied: {path} ({reason})")]
    FsAccessDenied { path: String, reason: String },

    /// Network access denied by policy.
    #[error("network access denied: {0}")]
    NetworkAccessDenied(String),

    /// Clock access denied (determinism required).
    #[error("clock access denied: deterministic mode enabled")]
    ClockAccessDenied,

    /// Entropy access denied (determinism required).
    #[error("entropy access denied: deterministic mode enabled")]
    EntropyAccessDenied,

    /// Invalid component format.
    #[error("invalid component format: {0}")]
    InvalidComponent(String),

    /// Manifest extraction failed.
    #[error("manifest extraction failed: {0}")]
    ManifestExtraction(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Sandbox policy error.
    #[error("sandbox error: {0}")]
    Sandbox(#[from] SandboxError),
}

/// Result type for WASI operations.
pub type WasiResult<T> = Result<T, WasiError>;

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for the WASI runtime.
///
/// This is derived from `CompiledPolicy` and controls all aspects of the
/// sandbox enforcement within the WASI runtime.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct WasiConfig {
    /// Memory limit in bytes.
    pub memory_limit_bytes: u64,

    /// Wall-clock timeout for execution.
    pub wall_clock_timeout: Duration,

    /// Paths allowed for read-only access (absolute paths).
    pub readonly_paths: Vec<PathBuf>,

    /// Paths allowed for read-write access (absolute paths).
    pub writable_paths: Vec<PathBuf>,

    /// State directory for connector persistent data.
    pub state_dir: Option<PathBuf>,

    /// Whether to enable deterministic mode.
    ///
    /// In deterministic mode:
    /// - Clocks return fixed values
    /// - Entropy returns deterministic sequences
    pub deterministic_mode: bool,

    /// Fixed timestamp for deterministic mode (Unix epoch seconds).
    pub deterministic_timestamp: u64,

    /// Seed for deterministic random number generation.
    pub deterministic_seed: u64,

    /// Network constraints (if network access is allowed).
    pub network_constraints: Option<NetworkConstraints>,

    /// Whether direct network access is blocked.
    ///
    /// When true, all network access must go through the Network Guard.
    pub block_direct_network: bool,

    /// Maximum fuel (instruction count) before interruption.
    ///
    /// This provides CPU limiting. Set to 0 for unlimited.
    pub max_fuel: u64,

    /// Environment variables to expose to the component.
    pub env_vars: HashMap<String, String>,

    /// Command-line arguments to pass to the component.
    pub args: Vec<String>,

    /// Inherit stdout from the host process.
    pub inherit_stdout: bool,

    /// Inherit stderr from the host process.
    pub inherit_stderr: bool,
}

impl Default for WasiConfig {
    fn default() -> Self {
        Self {
            memory_limit_bytes: 256 * 1024 * 1024, // 256 MiB
            wall_clock_timeout: Duration::from_secs(30),
            readonly_paths: vec![],
            writable_paths: vec![],
            state_dir: None,
            deterministic_mode: false,
            deterministic_timestamp: 0,
            deterministic_seed: 0,
            network_constraints: None,
            block_direct_network: true,
            max_fuel: 0, // Unlimited by default
            env_vars: HashMap::new(),
            args: vec![],
            inherit_stdout: false,
            inherit_stderr: false,
        }
    }
}

impl WasiConfig {
    /// Create a WASI configuration from a compiled sandbox policy.
    ///
    /// # Errors
    ///
    /// Returns an error if the policy contains invalid paths.
    pub fn from_policy(policy: &CompiledPolicy) -> WasiResult<Self> {
        Ok(Self {
            memory_limit_bytes: policy.memory_limit_bytes,
            wall_clock_timeout: policy.wall_clock_timeout,
            readonly_paths: policy.readonly_paths.clone(),
            writable_paths: policy.writable_paths.clone(),
            state_dir: policy.state_dir.clone(),
            deterministic_mode: false, // Can be overridden
            deterministic_timestamp: 0,
            deterministic_seed: 0,
            network_constraints: None, // Set separately
            block_direct_network: policy.block_direct_network,
            max_fuel: Self::cpu_percent_to_fuel(policy.cpu_percent),
            env_vars: HashMap::new(),
            args: vec![],
            inherit_stdout: false,
            inherit_stderr: false,
        })
    }

    /// Convert CPU percentage to wasmtime fuel.
    ///
    /// This is a heuristic mapping. In practice, fuel consumption varies
    /// wildly between components, but this provides a deterministic upper bound.
    fn cpu_percent_to_fuel(cpu_percent: u8) -> u64 {
        if cpu_percent == 0 {
            1 // Minimal fuel: effectively prevents meaningful execution
        } else if cpu_percent >= 100 {
            // Even at 100% CPU, we should provide a very large finite bound to prevent infinite loops (DoS).
            // 1 trillion instructions should be enough for a single request, but finite.
            1_000_000_000_000
        } else {
            // Base fuel per "time slice" scaled by percentage
            let base_fuel: u64 = 10_000_000_000; // 10B instructions base
            base_fuel * u64::from(cpu_percent) / 100
        }
    }

    /// Set network constraints for the runtime.
    #[must_use]
    pub fn with_network_constraints(mut self, constraints: NetworkConstraints) -> Self {
        self.network_constraints = Some(constraints);
        self
    }

    /// Enable deterministic mode with fixed timestamp and seed.
    #[must_use]
    pub const fn with_deterministic_mode(mut self, timestamp: u64, seed: u64) -> Self {
        self.deterministic_mode = true;
        self.deterministic_timestamp = timestamp;
        self.deterministic_seed = seed;
        self
    }

    /// Set environment variables.
    #[must_use]
    pub fn with_env(mut self, env: HashMap<String, String>) -> Self {
        self.env_vars = env;
        self
    }

    /// Set command-line arguments.
    #[must_use]
    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.args = args;
        self
    }

    /// Inherit stdout/stderr from host.
    #[must_use]
    pub const fn with_inherit_stdio(mut self, stdout: bool, stderr: bool) -> Self {
        self.inherit_stdout = stdout;
        self.inherit_stderr = stderr;
        self
    }
}

// ============================================================================
// Filesystem Capability Gate
// ============================================================================

/// Filesystem capability gate that enforces path restrictions.
#[derive(Debug)]
pub struct FsCapabilityGate {
    /// Canonical readonly paths.
    readonly_paths: Vec<PathBuf>,
    /// Canonical writable paths.
    writable_paths: Vec<PathBuf>,
}

impl FsCapabilityGate {
    /// Create a new filesystem capability gate.
    #[must_use]
    pub fn new(readonly_paths: Vec<PathBuf>, writable_paths: Vec<PathBuf>) -> Self {
        // Canonicalize paths where possible
        let readonly_paths = readonly_paths
            .into_iter()
            .filter_map(|p| std::fs::canonicalize(&p).ok().or(Some(p)))
            .collect();
        let writable_paths = writable_paths
            .into_iter()
            .filter_map(|p| std::fs::canonicalize(&p).ok().or(Some(p)))
            .collect();

        Self {
            readonly_paths,
            writable_paths,
        }
    }

    /// Check if a path is allowed for the given access mode.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to check (will be canonicalized).
    /// * `write` - Whether write access is requested.
    ///
    /// # Errors
    ///
    /// Returns `WasiError::FsAccessDenied` if the path is not allowed.
    pub fn check_access(&self, path: &Path, write: bool) -> WasiResult<()> {
        // Canonicalize the requested path
        let canonical = match std::fs::canonicalize(path) {
            Ok(p) => p,
            Err(_) => {
                // For writes, align with the host sandbox path resolution logic:
                // resolve through the nearest existing ancestor so nested missing
                // paths still preserve symlink and `..` traversal semantics.
                if write {
                    resolve_policy_path(path)
                } else {
                    return Err(WasiError::FsAccessDenied {
                        path: path.display().to_string(),
                        reason: "path does not exist".into(),
                    });
                }
            }
        };

        // Check writable paths first (superset of read access)
        for allowed in &self.writable_paths {
            if canonical.starts_with(allowed) {
                trace!(path = %canonical.display(), allowed = %allowed.display(), "fs access granted (writable)");
                return Ok(());
            }
        }

        // If write access is requested, must be in writable paths
        if write {
            return Err(WasiError::FsAccessDenied {
                path: path.display().to_string(),
                reason: "write access not allowed".into(),
            });
        }

        // Check readonly paths
        for allowed in &self.readonly_paths {
            if canonical.starts_with(allowed) {
                trace!(path = %canonical.display(), allowed = %allowed.display(), "fs access granted (readonly)");
                return Ok(());
            }
        }

        Err(WasiError::FsAccessDenied {
            path: path.display().to_string(),
            reason: "path not in allowed list".into(),
        })
    }
}

// ============================================================================
// Network Capability Gate
// ============================================================================

/// Network capability gate that routes all traffic through the Network Guard.
#[derive(Debug)]
pub struct NetworkCapabilityGate {
    /// The egress guard for policy enforcement.
    guard: EgressGuard,
    /// Network constraints from the manifest.
    constraints: Option<NetworkConstraints>,
    /// Whether direct network access is blocked.
    block_direct: bool,
}

impl NetworkCapabilityGate {
    /// Create a new network capability gate.
    #[must_use]
    pub const fn new(constraints: Option<NetworkConstraints>, block_direct: bool) -> Self {
        Self {
            guard: EgressGuard::new(),
            constraints,
            block_direct,
        }
    }

    /// Check if an HTTP request is allowed.
    ///
    /// # Errors
    ///
    /// Returns `WasiError::NetworkAccessDenied` if the request violates policy.
    pub fn check_http(&self, url: &str, method: &str) -> WasiResult<()> {
        if self.block_direct && self.constraints.is_none() {
            return Err(WasiError::NetworkAccessDenied(
                "direct network access blocked and no constraints configured".into(),
            ));
        }

        let Some(constraints) = &self.constraints else {
            // No constraints = no network access
            return Err(WasiError::NetworkAccessDenied("no network policy".into()));
        };

        let request = EgressRequest::Http(EgressHttpRequest {
            url: url.to_string(),
            method: method.to_string(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        self.guard
            .evaluate(&request, constraints)
            .map_err(|e| WasiError::NetworkAccessDenied(e.to_string()))?;

        debug!(url = %url, method = %method, "HTTP request allowed");
        Ok(())
    }

    /// Check if a TCP connection is allowed.
    ///
    /// # Errors
    ///
    /// Returns `WasiError::NetworkAccessDenied` if the connection violates policy.
    pub fn check_tcp(&self, host: &str, port: u16, tls: bool) -> WasiResult<()> {
        if self.block_direct && self.constraints.is_none() {
            return Err(WasiError::NetworkAccessDenied(
                "direct network access blocked and no constraints configured".into(),
            ));
        }

        let Some(constraints) = &self.constraints else {
            return Err(WasiError::NetworkAccessDenied("no network policy".into()));
        };

        let request = EgressRequest::TcpConnect(EgressTcpConnectRequest {
            host: host.to_string(),
            port,
            tls,
            sni_override: None,
            credential_id: None,
        });

        self.guard
            .evaluate(&request, constraints)
            .map_err(|e| WasiError::NetworkAccessDenied(e.to_string()))?;

        debug!(host = %host, port = %port, tls = %tls, "TCP connection allowed");
        Ok(())
    }

    /// Authorize a mediated HTTP request and inject credentials when allowed.
    ///
    /// This is the credential-aware Network Guard path higher-level WASI
    /// `network_request`-style hostcalls should use. Raw Preview2 sockets stay
    /// disabled for strict profiles because they bypass this mediation layer.
    ///
    /// # Errors
    ///
    /// Returns `WasiError::NetworkAccessDenied` if policy or credential checks fail.
    pub fn authorize_http(
        &self,
        request: &mut EgressHttpRequest,
        injector: &dyn CredentialInjector,
        operation_id: &str,
        credential_allow: &[String],
    ) -> WasiResult<EgressDecision> {
        if self.block_direct && self.constraints.is_none() {
            return Err(WasiError::NetworkAccessDenied(
                "direct network access blocked and no constraints configured".into(),
            ));
        }

        let Some(constraints) = &self.constraints else {
            return Err(WasiError::NetworkAccessDenied("no network policy".into()));
        };

        self.guard
            .authorize_http(
                request,
                constraints,
                injector,
                operation_id,
                credential_allow,
            )
            .map_err(|e| WasiError::NetworkAccessDenied(e.to_string()))
    }

    /// Authorize a mediated TCP connect request and return any injected auth bytes.
    ///
    /// # Errors
    ///
    /// Returns `WasiError::NetworkAccessDenied` if policy or credential checks fail.
    pub fn authorize_tcp(
        &self,
        request: &EgressTcpConnectRequest,
        injector: &dyn CredentialInjector,
        operation_id: &str,
        credential_allow: &[String],
    ) -> WasiResult<EgressTcpDecision> {
        if self.block_direct && self.constraints.is_none() {
            return Err(WasiError::NetworkAccessDenied(
                "direct network access blocked and no constraints configured".into(),
            ));
        }

        let Some(constraints) = &self.constraints else {
            return Err(WasiError::NetworkAccessDenied("no network policy".into()));
        };

        self.guard
            .authorize_tcp(
                request,
                constraints,
                injector,
                operation_id,
                credential_allow,
            )
            .map_err(|e| WasiError::NetworkAccessDenied(e.to_string()))
    }
}

// ============================================================================
// WASI Host State
// ============================================================================

/// Host state for the WASI runtime.
///
/// This is the context passed to all hostcalls and contains the capability
/// gates and runtime state.
pub struct WasiHostState {
    /// WASI context from wasmtime-wasi.
    wasi_ctx: WasiCtx,
    /// Resource table for component model.
    resource_table: ResourceTable,
    /// Filesystem capability gate.
    #[allow(dead_code)]
    fs_gate: Arc<FsCapabilityGate>,
    /// Network capability gate.
    #[allow(dead_code)]
    net_gate: Arc<NetworkCapabilityGate>,
    /// Whether deterministic mode is enabled.
    deterministic_mode: bool,
    /// Fixed timestamp for deterministic mode.
    deterministic_timestamp: u64,
    /// Deterministic random state.
    deterministic_rng: Mutex<DeterministicRng>,
    /// Execution start time.
    start_time: Instant,
    /// Wall-clock timeout.
    timeout: Duration,
    /// Maximum allowed memory size in bytes.
    memory_limit_bytes: usize,
}

impl WasiHostState {
    /// Create new host state from configuration.
    fn new(config: &WasiConfig, wasi_ctx: WasiCtx) -> Self {
        let fs_gate = Arc::new(FsCapabilityGate::new(
            config.readonly_paths.clone(),
            config.writable_paths.clone(),
        ));

        let net_gate = Arc::new(NetworkCapabilityGate::new(
            config.network_constraints.clone(),
            config.block_direct_network,
        ));

        Self {
            wasi_ctx,
            resource_table: ResourceTable::new(),
            fs_gate,
            net_gate,
            deterministic_mode: config.deterministic_mode,
            deterministic_timestamp: config.deterministic_timestamp,
            deterministic_rng: Mutex::new(DeterministicRng::new(config.deterministic_seed)),
            start_time: Instant::now(),
            timeout: config.wall_clock_timeout,
            memory_limit_bytes: usize::try_from(config.memory_limit_bytes).unwrap_or(usize::MAX),
        }
    }

    /// Check if execution has exceeded the wall-clock timeout.
    pub fn check_timeout(&self) -> WasiResult<()> {
        if self.start_time.elapsed() > self.timeout {
            Err(WasiError::Timeout)
        } else {
            Ok(())
        }
    }

    /// Get the current time (respecting deterministic mode).
    pub fn current_time(&self) -> SystemTime {
        if self.deterministic_mode {
            SystemTime::UNIX_EPOCH + Duration::from_secs(self.deterministic_timestamp)
        } else {
            SystemTime::now()
        }
    }

    /// Get random bytes (respecting deterministic mode).
    pub fn get_random_bytes(&self, len: usize) -> Vec<u8> {
        if self.deterministic_mode {
            let mut rng = self
                .deterministic_rng
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            (0..len).map(|_| rng.next_byte()).collect()
        } else {
            use rand::RngCore;
            let mut bytes = vec![0u8; len];
            rand::thread_rng().fill_bytes(&mut bytes);
            bytes
        }
    }

    /// Get a reference to the filesystem capability gate.
    #[must_use]
    pub fn fs_gate(&self) -> &FsCapabilityGate {
        &self.fs_gate
    }

    /// Get a reference to the network capability gate.
    #[must_use]
    pub fn net_gate(&self) -> &NetworkCapabilityGate {
        &self.net_gate
    }

    /// Validate a filesystem access against the capability gate.
    ///
    /// This provides an additional enforcement layer beyond wasmtime-wasi's
    /// preopened directory restrictions.
    ///
    /// # Errors
    ///
    /// Returns `WasiError::FsAccessDenied` if the path is not allowed.
    pub fn validate_fs_access(&self, path: &Path, write: bool) -> WasiResult<()> {
        self.fs_gate.check_access(path, write)
    }

    /// Validate an HTTP request against the network capability gate.
    ///
    /// # Errors
    ///
    /// Returns `WasiError::NetworkAccessDenied` if the request violates policy.
    pub fn validate_http_access(&self, url: &str, method: &str) -> WasiResult<()> {
        self.net_gate.check_http(url, method)
    }

    /// Validate a TCP connection against the network capability gate.
    ///
    /// # Errors
    ///
    /// Returns `WasiError::NetworkAccessDenied` if the connection violates policy.
    pub fn validate_tcp_access(&self, host: &str, port: u16, tls: bool) -> WasiResult<()> {
        self.net_gate.check_tcp(host, port, tls)
    }

    /// Authorize a credential-aware HTTP request through the mediated Network Guard path.
    ///
    /// # Errors
    ///
    /// Returns `WasiError::NetworkAccessDenied` if policy or credential checks fail.
    pub fn authorize_http_request(
        &self,
        request: &mut EgressHttpRequest,
        injector: &dyn CredentialInjector,
        operation_id: &str,
        credential_allow: &[String],
    ) -> WasiResult<EgressDecision> {
        self.net_gate
            .authorize_http(request, injector, operation_id, credential_allow)
    }

    /// Authorize a credential-aware TCP connect through the mediated Network Guard path.
    ///
    /// # Errors
    ///
    /// Returns `WasiError::NetworkAccessDenied` if policy or credential checks fail.
    pub fn authorize_tcp_connect(
        &self,
        request: &EgressTcpConnectRequest,
        injector: &dyn CredentialInjector,
        operation_id: &str,
        credential_allow: &[String],
    ) -> WasiResult<EgressTcpDecision> {
        self.net_gate
            .authorize_tcp(request, injector, operation_id, credential_allow)
    }
}

impl wasmtime::ResourceLimiter for WasiHostState {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> Result<bool, wasmtime::Error> {
        // Enforce the memory limit bound
        Ok(desired <= self.memory_limit_bytes)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> Result<bool, wasmtime::Error> {
        // Tables are allowed to grow up to a sane limit to prevent OOM via unbounded growth
        const MAX_TABLE_ELEMENTS: usize = 100_000;
        Ok(desired <= MAX_TABLE_ELEMENTS)
    }
}

impl WasiView for WasiHostState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi_ctx,
            table: &mut self.resource_table,
        }
    }
}

/// Deterministic random number generator (xorshift64).
#[derive(Debug)]
struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    const fn new(seed: u64) -> Self {
        // Ensure non-zero state
        Self {
            state: if seed == 0 {
                0x853c_49e6_748f_ea9b
            } else {
                seed
            },
        }
    }

    const fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    const fn next_byte(&mut self) -> u8 {
        (self.next_u64() & 0xFF) as u8
    }
}

fn deterministic_seed_bytes(seed: u64) -> Vec<u8> {
    let mut rng = DeterministicRng::new(seed);
    (0..32).map(|_| rng.next_byte()).collect()
}

#[derive(Debug)]
struct FixedWallClock {
    timestamp: Duration,
    resolution: Duration,
}

impl FixedWallClock {
    const fn new(timestamp_secs: u64) -> Self {
        Self {
            timestamp: Duration::from_secs(timestamp_secs),
            resolution: Duration::from_nanos(1),
        }
    }
}

impl HostWallClock for FixedWallClock {
    fn resolution(&self) -> Duration {
        self.resolution
    }

    fn now(&self) -> Duration {
        self.timestamp
    }
}

#[derive(Debug)]
struct FixedMonotonicClock {
    next: AtomicU64,
    resolution_ns: u64,
    step_ns: u64,
}

impl FixedMonotonicClock {
    const fn new(step_ns: u64) -> Self {
        Self {
            next: AtomicU64::new(0),
            resolution_ns: 1,
            step_ns,
        }
    }
}

impl HostMonotonicClock for FixedMonotonicClock {
    fn resolution(&self) -> u64 {
        self.resolution_ns
    }

    fn now(&self) -> u64 {
        self.next.fetch_add(self.step_ns, Ordering::Relaxed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RawSocketHostPolicy {
    Disabled,
    Wildcard,
    ExactIpOnly,
}

fn raw_socket_host_policy(constraints: &NetworkConstraints) -> RawSocketHostPolicy {
    // Preview2 `socket_addr_check` only receives a resolved socket address, so
    // hostname-bound policy (host allowlists, SNI, SPKI pins) cannot be
    // enforced there. Only wildcard or exact-IP policy can be represented
    // safely at this layer.
    if constraints.require_sni || !constraints.spki_pins.is_empty() || constraints.deny_ip_literals
    {
        return RawSocketHostPolicy::Disabled;
    }

    if constraints.host_allow.iter().any(|pattern| pattern == "*") {
        return RawSocketHostPolicy::Wildcard;
    }

    if constraints
        .host_allow
        .iter()
        .all(|pattern| pattern.parse::<IpAddr>().is_ok())
    {
        if constraints.host_allow.is_empty() && constraints.ip_allow.is_empty() {
            return RawSocketHostPolicy::Disabled;
        }
        return RawSocketHostPolicy::ExactIpOnly;
    }

    RawSocketHostPolicy::Disabled
}

fn raw_socket_ip_allowed(constraints: &NetworkConstraints, ip: IpAddr) -> bool {
    match raw_socket_host_policy(constraints) {
        RawSocketHostPolicy::Disabled => false,
        RawSocketHostPolicy::Wildcard => true,
        RawSocketHostPolicy::ExactIpOnly => {
            constraints.ip_allow.contains(&ip)
                || constraints
                    .host_allow
                    .iter()
                    .filter_map(|pattern| pattern.parse::<IpAddr>().ok())
                    .any(|allowed_ip| allowed_ip == ip)
        }
    }
}

fn raw_socket_dns_lookup_allowed(constraints: &NetworkConstraints) -> bool {
    matches!(
        raw_socket_host_policy(constraints),
        RawSocketHostPolicy::Wildcard
    )
}

fn socket_addr_allowed(
    constraints: &NetworkConstraints,
    addr: SocketAddr,
    reason: SocketAddrUse,
) -> bool {
    if !matches!(reason, SocketAddrUse::TcpConnect) {
        return false;
    }

    if !constraints.port_allow.contains(&addr.port()) {
        return false;
    }

    if !raw_socket_ip_allowed(constraints, addr.ip()) {
        return false;
    }

    EgressGuard::new()
        .check_ip_constraints(addr.ip(), constraints)
        .is_ok()
}

// ============================================================================
// WASI Runtime
// ============================================================================

/// WASI Preview2 runtime for FCP2 connector execution.
///
/// This runtime provides capability-gated access to system resources according
/// to the `WasiConfig` (derived from `CompiledPolicy`).
pub struct WasiRuntime {
    /// Wasmtime engine (shared across components).
    engine: Engine,
    /// Runtime configuration.
    config: WasiConfig,
    /// Component linker with WASI bindings.
    linker: Linker<WasiHostState>,
}

impl WasiRuntime {
    /// Create a new WASI runtime with the given configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the runtime cannot be initialized.
    pub fn new(config: WasiConfig) -> WasiResult<Self> {
        validate_preopened_paths(&config)?;

        // Configure wasmtime engine
        let mut engine_config = Config::new();
        engine_config.wasm_component_model(true);
        engine_config.async_support(true);

        // ALWAYS enable fuel metering to ensure async yielding and timeout enforcement
        engine_config.consume_fuel(true);

        // Memory limits are set per-store, not engine-wide

        let engine =
            Engine::new(&engine_config).map_err(|e| WasiError::EngineCreation(e.to_string()))?;

        // Create linker with WASI bindings
        let mut linker: Linker<WasiHostState> = Linker::new(&engine);
        wasmtime_wasi::p2::add_to_linker_async(&mut linker)
            .map_err(|e| WasiError::EngineCreation(format!("failed to add WASI: {e}")))?;

        info!(
            memory_limit = config.memory_limit_bytes,
            timeout = ?config.wall_clock_timeout,
            deterministic = config.deterministic_mode,
            "WASI runtime initialized"
        );

        Ok(Self {
            engine,
            config,
            linker,
        })
    }

    /// Load a WebAssembly component from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the component is invalid or cannot be loaded.
    pub fn load_component(&self, wasm_bytes: &[u8]) -> WasiResult<Component> {
        Component::new(&self.engine, wasm_bytes)
            .map_err(|e| WasiError::ComponentLoad(e.to_string()))
    }

    /// Load a WebAssembly component from a file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or the component is invalid.
    pub fn load_component_from_file(&self, path: &Path) -> WasiResult<Component> {
        Component::from_file(&self.engine, path)
            .map_err(|e| WasiError::ComponentLoad(e.to_string()))
    }

    fn configure_determinism(&self, wasi_builder: &mut WasiCtxBuilder) {
        if !self.config.deterministic_mode {
            return;
        }

        let seed_bytes = deterministic_seed_bytes(self.config.deterministic_seed);
        let seed = (u128::from(self.config.deterministic_seed) << 64)
            | u128::from(self.config.deterministic_seed);

        wasi_builder
            .wall_clock(FixedWallClock::new(self.config.deterministic_timestamp))
            .monotonic_clock(FixedMonotonicClock::new(1_000_000))
            .secure_random(Deterministic::new(seed_bytes.clone()))
            .insecure_random(Deterministic::new(seed_bytes))
            .insecure_random_seed(seed);
    }

    fn configure_network_policy(&self, wasi_builder: &mut WasiCtxBuilder) {
        match (
            self.config.block_direct_network,
            &self.config.network_constraints,
        ) {
            // Strict and moderate sandbox profiles require all outbound traffic
            // to flow through the Network Guard. Preview2 socket hostcalls
            // bypass that mediation, so they must stay disabled even when
            // operation-level network constraints are present.
            (true, _) => {
                wasi_builder.allow_ip_name_lookup(false);
                wasi_builder.allow_tcp(false);
                wasi_builder.allow_udp(false);
            }
            (false, Some(constraints)) => {
                let constraints = Arc::new(constraints.clone());
                wasi_builder.allow_udp(false);
                match raw_socket_host_policy(constraints.as_ref()) {
                    RawSocketHostPolicy::Disabled => {
                        wasi_builder.allow_ip_name_lookup(false);
                        wasi_builder.allow_tcp(false);
                    }
                    RawSocketHostPolicy::Wildcard | RawSocketHostPolicy::ExactIpOnly => {
                        wasi_builder.allow_ip_name_lookup(raw_socket_dns_lookup_allowed(
                            constraints.as_ref(),
                        ));
                        wasi_builder.allow_tcp(true);
                        wasi_builder.socket_addr_check(move |addr, reason| {
                            let constraints = Arc::clone(&constraints);
                            Box::pin(async move {
                                socket_addr_allowed(constraints.as_ref(), addr, reason)
                            })
                        });
                    }
                }
            }
            (false, None) => {
                wasi_builder.inherit_network();
                wasi_builder.allow_ip_name_lookup(true);
                wasi_builder.allow_tcp(true);
                wasi_builder.allow_udp(true);
            }
        }
    }

    /// Create a new execution store with the configured WASI context.
    ///
    /// # Errors
    ///
    /// Returns an error if the store cannot be created.
    pub fn create_store(&self) -> WasiResult<Store<WasiHostState>> {
        self.create_store_for_args(None)
    }

    fn create_store_for_args(
        &self,
        args_override: Option<&[String]>,
    ) -> WasiResult<Store<WasiHostState>> {
        // Build WASI context
        let mut wasi_builder = WasiCtxBuilder::new();

        // Add environment variables
        for (key, value) in &self.config.env_vars {
            wasi_builder.env(key, value);
        }

        // Add arguments
        let args = args_override.unwrap_or(&self.config.args);
        wasi_builder.args(args);

        // Configure stdio
        if self.config.inherit_stdout {
            wasi_builder.inherit_stdout();
        }
        if self.config.inherit_stderr {
            wasi_builder.inherit_stderr();
        }

        self.configure_determinism(&mut wasi_builder);
        self.configure_network_policy(&mut wasi_builder);

        // Deduplicate directories to preopen to avoid Wasmtime errors
        let mut preopened_dirs = std::collections::HashMap::new();

        // Mount only explicitly allowed directories. Preopening a parent of a
        // file-scoped allowlist entry widens access to sibling paths.
        for path in &self.config.readonly_paths {
            let Some(host_dir) = prepare_preopened_dir(path, false)? else {
                continue;
            };
            let guest_path = path.display().to_string();
            preopened_dirs.insert(guest_path, (host_dir, DirPerms::READ, FilePerms::READ));
        }

        for path in &self.config.writable_paths {
            let Some(host_dir) = prepare_preopened_dir(path, true)? else {
                continue;
            };
            let guest_path = path.display().to_string();
            // Overwrite with writable permissions if there's a conflict
            preopened_dirs.insert(guest_path, (host_dir, DirPerms::all(), FilePerms::all()));
        }

        for (guest_path, (host_dir, d_perms, f_perms)) in preopened_dirs {
            wasi_builder
                .preopened_dir(&host_dir, &guest_path, d_perms, f_perms)
                .map_err(|e| {
                    WasiError::EngineCreation(format!(
                        "failed to mount {}: {e}",
                        host_dir.display()
                    ))
                })?;
        }

        let wasi_ctx = wasi_builder.build();
        let host_state = WasiHostState::new(&self.config, wasi_ctx);

        let mut store = Store::new(&self.engine, host_state);
        store.limiter(|state| state as &mut dyn wasmtime::ResourceLimiter);

        // Set fuel so async execution yields back to the host executor.
        if self.config.max_fuel > 0 {
            store
                .set_fuel(self.config.max_fuel)
                .map_err(|e| WasiError::EngineCreation(format!("failed to set fuel: {e}")))?;
        } else {
            // Unbounded execution still needs fuel so long-running guests yield.
            store
                .set_fuel(u64::MAX)
                .map_err(|e| WasiError::EngineCreation(format!("failed to set fuel: {e}")))?;
        }

        // Yield to the executor every 10,000 instructions so the timeout can trigger
        store
            .fuel_async_yield_interval(Some(10_000))
            .map_err(|e| WasiError::EngineCreation(format!("failed to set yield interval: {e}")))?;

        Ok(store)
    }

    async fn instantiate(
        &self,
        store: &mut Store<WasiHostState>,
        component: &Component,
    ) -> WasiResult<wasmtime::component::Instance> {
        self.linker
            .instantiate_async(store, component)
            .await
            .map_err(|e| WasiError::Instantiation(e.to_string()))
    }

    /// Instantiate a component and invoke a zero-argument exported function.
    ///
    /// The provided `args` override the runtime's configured CLI arguments for
    /// this invocation only. This is primarily intended for command-style
    /// connectors that expose a `run` export.
    ///
    /// # Errors
    ///
    /// Returns an error if the component cannot be instantiated, the export
    /// cannot be resolved, the export traps, or execution exceeds the
    /// configured wall-clock timeout.
    pub async fn invoke(
        &self,
        component: &Component,
        export_name: &str,
        args: &[String],
    ) -> WasiResult<ExecutionResult> {
        let started = Instant::now();
        let mut store = self.create_store_for_args(Some(args))?;
        let instance = self.instantiate(&mut store, component).await?;
        let func = instance
            .get_typed_func::<(), ()>(&mut store, export_name)
            .map_err(|e| {
                WasiError::Execution(format!(
                    "failed to resolve zero-arg export `{export_name}`: {e}"
                ))
            })?;

        fcp_async_core::time::timeout(self.config.wall_clock_timeout, async {
            func.call_async(&mut store, ()).await.map_err(|e| {
                WasiError::Execution(format!("component export `{export_name}` failed: {e}"))
            })?;
            func.post_return_async(&mut store).await.map_err(|e| {
                WasiError::Execution(format!(
                    "component export `{export_name}` post-return cleanup failed: {e}"
                ))
            })?;
            Ok::<(), WasiError>(())
        })
        .await
        .map_err(|_| WasiError::Timeout)??;

        let fuel_consumed = if self.config.max_fuel > 0 {
            let remaining_fuel = store.get_fuel().map_err(|e| {
                WasiError::Execution(format!("failed to query remaining fuel: {e}"))
            })?;
            Some(self.config.max_fuel.saturating_sub(remaining_fuel))
        } else {
            None
        };

        Ok(ExecutionResult {
            exit_code: 0,
            stdout: None,
            stderr: None,
            duration: started.elapsed(),
            fuel_consumed,
        })
    }

    /// Get a reference to the linker.
    #[must_use]
    pub const fn linker(&self) -> &Linker<WasiHostState> {
        &self.linker
    }

    /// Get the engine.
    #[must_use]
    pub const fn engine(&self) -> &Engine {
        &self.engine
    }
}

fn prepare_preopened_dir(path: &Path, writable: bool) -> WasiResult<Option<PathBuf>> {
    // First stability check: fails if the *declared* path already
    // resolves through a symlinked ancestor.
    let pre_create = ensure_preopen_path_is_stable(path, writable)?;

    if writable && !path.exists() {
        return Err(WasiError::FsAccessDenied {
            path: path.display().to_string(),
            reason: "writable WASI preopens must already exist as directories; refusing to widen a missing path into a writable directory grant".into(),
        });
    }

    if !path.exists() {
        return Ok(None);
    }

    if !path.is_dir() {
        return Ok(None);
    }

    // Reuse the canonical path from the stability check instead of
    // calling path.canonicalize() again. Two separate canonicalize
    // syscalls over the same declared path open a TOCTOU window: an
    // attacker can swap a regular dir for a symlink in between, and
    // the second call silently follows the link — widening the guest
    // mount to the attacker's chosen target. The stability check
    // already canonicalized (via resolve_policy_path) and verified
    // the resolved form matches the lexical normalization, so its
    // output is the safest available path to hand to wasmtime.
    Ok(Some(pre_create))
}

fn ensure_preopen_path_is_stable(path: &Path, writable: bool) -> WasiResult<PathBuf> {
    let requested = normalize_preopen_path(path);
    let resolved = resolve_policy_path(path);
    if requested != resolved {
        return Err(WasiError::FsAccessDenied {
            path: path.display().to_string(),
            reason: if writable {
                "writable preopen path resolves through a symlinked ancestor; refusing to create or mount outside the declared path".into()
            } else {
                "readonly preopen path resolves through a symlinked ancestor; refusing to mount outside the declared path".into()
            },
        });
    }
    Ok(resolved)
}

fn normalize_preopen_path(path: &Path) -> PathBuf {
    use std::path::Component;

    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

fn validate_preopened_paths(config: &WasiConfig) -> WasiResult<()> {
    for (mode, path) in config
        .readonly_paths
        .iter()
        .map(|path| ("readonly", path))
        .chain(config.writable_paths.iter().map(|path| ("writable", path)))
    {
        if path.exists() && !path.is_dir() {
            return Err(WasiError::FsAccessDenied {
                path: path.display().to_string(),
                reason: format!(
                    "{mode} WASI preopens must be directories; file paths would widen access to the parent directory"
                ),
            });
        }
    }

    Ok(())
}

// ============================================================================
// WASI Connector Runner
// ============================================================================

/// High-level adapter for running FCP2 connectors as WASI components.
///
/// This wraps `WasiRuntime` and adds connector-specific lifecycle management:
/// manifest validation, capability gate enforcement, and structured results.
///
/// # Usage
///
/// ```ignore
/// let runner = WasiConnectorRunner::from_policy(&policy)?;
/// let result = runner.load_and_validate(&wasm_bytes)?;
/// let exec = runner.execute(&result.component, &["--dry-run"]).await?;
/// ```
pub struct WasiConnectorRunner {
    runtime: WasiRuntime,
    fs_gate: Arc<FsCapabilityGate>,
    net_gate: Arc<NetworkCapabilityGate>,
}

/// Result of loading and validating a connector component.
pub struct ValidatedComponent {
    /// The loaded wasmtime component.
    pub component: Component,
    /// Whether an embedded manifest was found.
    pub has_manifest: bool,
}

impl WasiConnectorRunner {
    /// Create a connector runner from a compiled sandbox policy.
    ///
    /// # Errors
    ///
    /// Returns an error if the runtime cannot be initialized.
    pub fn from_policy(policy: &CompiledPolicy) -> WasiResult<Self> {
        let config = WasiConfig::from_policy(policy)?;
        Self::new(config)
    }

    /// Create a connector runner from a WASI configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the runtime cannot be initialized.
    pub fn new(config: WasiConfig) -> WasiResult<Self> {
        let fs_gate = Arc::new(FsCapabilityGate::new(
            config.readonly_paths.clone(),
            config.writable_paths.clone(),
        ));
        let net_gate = Arc::new(NetworkCapabilityGate::new(
            config.network_constraints.clone(),
            config.block_direct_network,
        ));
        let runtime = WasiRuntime::new(config)?;
        Ok(Self {
            runtime,
            fs_gate,
            net_gate,
        })
    }

    /// Load a component and validate it has the expected structure.
    ///
    /// Checks for an embedded `fcp-manifest` custom section. The component
    /// is still usable even if no manifest is found (for testing/dev).
    ///
    /// # Errors
    ///
    /// Returns an error if the component cannot be loaded.
    pub fn load_and_validate(&self, wasm_bytes: &[u8]) -> WasiResult<ValidatedComponent> {
        let component = self.runtime.load_component(wasm_bytes)?;
        let has_manifest = extract_custom_section(wasm_bytes, "fcp-manifest").is_some();

        info!(
            has_manifest = has_manifest,
            "connector component loaded and validated"
        );

        Ok(ValidatedComponent {
            component,
            has_manifest,
        })
    }

    /// Execute a connector component's export function.
    ///
    /// # Errors
    ///
    /// Returns an error if execution fails or exceeds the timeout.
    pub async fn execute(
        &self,
        component: &Component,
        args: &[String],
    ) -> WasiResult<ExecutionResult> {
        self.runtime.invoke(component, "run", args).await
    }

    /// Validate that a filesystem path is allowed by the connector's policy.
    ///
    /// # Errors
    ///
    /// Returns `WasiError::FsAccessDenied` if the path is not allowed.
    pub fn validate_fs_access(&self, path: &Path, write: bool) -> WasiResult<()> {
        self.fs_gate.check_access(path, write)
    }

    /// Validate that an HTTP request is allowed by the connector's network policy.
    ///
    /// # Errors
    ///
    /// Returns `WasiError::NetworkAccessDenied` if the request is not allowed.
    pub fn validate_http_access(&self, url: &str, method: &str) -> WasiResult<()> {
        self.net_gate.check_http(url, method)
    }

    /// Validate that a TCP connection is allowed by the connector's network policy.
    ///
    /// # Errors
    ///
    /// Returns `WasiError::NetworkAccessDenied` if the connection is not allowed.
    pub fn validate_tcp_access(&self, host: &str, port: u16, tls: bool) -> WasiResult<()> {
        self.net_gate.check_tcp(host, port, tls)
    }

    /// Get a reference to the underlying runtime.
    #[must_use]
    pub const fn runtime(&self) -> &WasiRuntime {
        &self.runtime
    }

    /// Get a reference to the filesystem capability gate.
    #[must_use]
    pub fn fs_gate(&self) -> &FsCapabilityGate {
        &self.fs_gate
    }

    /// Get a reference to the network capability gate.
    #[must_use]
    pub fn net_gate(&self) -> &NetworkCapabilityGate {
        &self.net_gate
    }
}

// ============================================================================
// Manifest Extraction
// ============================================================================

/// Extract the FCP2 manifest from a WASI component.
///
/// FCP2 connectors embed their manifest in a custom section named `fcp-manifest`.
/// This function extracts and parses it.
///
/// # Errors
///
/// Returns an error if the manifest cannot be extracted or parsed.
pub fn extract_manifest_from_component(
    wasm_bytes: &[u8],
) -> WasiResult<fcp_manifest::ConnectorManifest> {
    // Parse the component to find custom sections
    // Note: wasmtime doesn't expose custom sections directly, so we parse
    // the raw bytes directly.

    // First, try to find the manifest in the raw bytes
    // Custom sections in WASM components have a specific format
    let manifest_bytes = extract_custom_section(wasm_bytes, "fcp-manifest")
        .ok_or_else(|| WasiError::ManifestExtraction("no fcp-manifest section found".into()))?;

    // Parse the manifest (it's stored as JSON or CBOR)
    let manifest: fcp_manifest::ConnectorManifest = if manifest_bytes.starts_with(b"{") {
        serde_json::from_slice(&manifest_bytes)
            .map_err(|e| WasiError::ManifestExtraction(format!("invalid JSON manifest: {e}")))?
    } else {
        ciborium::from_reader(&manifest_bytes[..])
            .map_err(|e| WasiError::ManifestExtraction(format!("invalid CBOR manifest: {e}")))?
    };

    debug!(
        connector_id = %manifest.connector.id,
        version = %manifest.connector.version,
        "extracted manifest from component"
    );

    Ok(manifest)
}

/// Extract a custom section from raw WASM bytes.
fn extract_custom_section(wasm_bytes: &[u8], section_name: &str) -> Option<Vec<u8>> {
    // Simple WASM custom section parser
    // Custom sections have ID 0 and format: [name_len][name][payload]

    // Skip WASM magic + version (8 bytes)
    if wasm_bytes.len() < 8 {
        return None;
    }

    let mut pos = 8;

    while pos < wasm_bytes.len() {
        // Section ID (1 byte)
        let section_id = wasm_bytes[pos];
        pos = pos.checked_add(1)?;

        // Section size (LEB128)
        let (section_size, bytes_read) = read_leb128(&wasm_bytes[pos..])?;
        pos = pos.checked_add(bytes_read)?;

        if section_id == 0 {
            // Custom section - read name
            let section_start = pos;
            let (name_len, name_bytes_read) = read_leb128(&wasm_bytes[pos..])?;
            pos = pos.checked_add(name_bytes_read)?;

            if pos.checked_add(name_len)? > wasm_bytes.len() {
                return None;
            }

            let name = std::str::from_utf8(&wasm_bytes[pos..pos + name_len]).ok()?;
            pos = pos.checked_add(name_len)?;

            let header_size = pos.checked_sub(section_start)?;
            if section_size < header_size {
                return None; // Invalid section size
            }

            if name == section_name {
                // Found it - return the payload
                let payload_len = section_size - header_size;
                if pos.checked_add(payload_len)? > wasm_bytes.len() {
                    return None;
                }
                return Some(wasm_bytes[pos..pos + payload_len].to_vec());
            }

            // Skip to next section
            pos = section_start.checked_add(section_size)?;
        } else {
            // Skip non-custom section
            pos = pos.checked_add(section_size)?;
        }
    }

    None
}

/// Read a LEB128-encoded unsigned integer.
fn read_leb128(bytes: &[u8]) -> Option<(usize, usize)> {
    let mut result = 0;
    let mut shift = 0;
    let mut bytes_read = 0;

    for &byte in bytes {
        bytes_read += 1;
        let value = (byte & 0x7f) as usize;

        // Prevent panic: shift must be less than the target architecture's usize bits
        if shift >= usize::BITS {
            return None;
        }

        result |= value << shift;
        if byte & 0x80 == 0 {
            return Some((result, bytes_read));
        }
        shift += 7;
    }

    None
}

// ============================================================================
// Execution Result
// ============================================================================

/// Result of component execution.
#[derive(Debug)]
pub struct ExecutionResult {
    /// Exit code (0 = success).
    pub exit_code: i32,
    /// Stdout output (if captured).
    pub stdout: Option<Bytes>,
    /// Stderr output (if captured).
    pub stderr: Option<Bytes>,
    /// Execution duration.
    pub duration: Duration,
    /// Fuel consumed (if metering enabled).
    pub fuel_consumed: Option<u64>,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const fn minimal_command_component() -> &'static [u8] {
        br#"
        (component
            (core module $m
                (func (export "run"))
            )
            (core instance $i (instantiate $m))
            (func (export "run") (canon lift (core func $i "run")))
        )
        "#
    }

    #[test]
    fn test_wasi_config_default() {
        let config = WasiConfig::default();
        assert_eq!(config.memory_limit_bytes, 256 * 1024 * 1024);
        assert_eq!(config.wall_clock_timeout, Duration::from_secs(30));
        assert!(!config.deterministic_mode);
        assert!(config.block_direct_network);
    }

    #[test]
    fn test_wasi_config_with_deterministic_mode() {
        let config = WasiConfig::default().with_deterministic_mode(1_700_000_000, 42);

        assert!(config.deterministic_mode);
        assert_eq!(config.deterministic_timestamp, 1_700_000_000);
        assert_eq!(config.deterministic_seed, 42);
    }

    #[test]
    fn test_wasi_config_with_env() {
        let mut env = HashMap::new();
        env.insert("KEY".into(), "VALUE".into());
        let config = WasiConfig::default().with_env(env);
        assert_eq!(config.env_vars.get("KEY"), Some(&"VALUE".into()));
    }

    #[test]
    fn test_wasi_config_with_args() {
        let config = WasiConfig::default().with_args(vec!["arg1".into(), "arg2".into()]);
        assert_eq!(config.args.len(), 2);
        assert_eq!(config.args[0], "arg1");
    }

    #[test]
    fn test_wasi_config_with_inherit_stdio() {
        let config = WasiConfig::default().with_inherit_stdio(true, true);
        assert!(config.inherit_stdout);
        assert!(config.inherit_stderr);

        let config = WasiConfig::default().with_inherit_stdio(false, true);
        assert!(!config.inherit_stdout);
        assert!(config.inherit_stderr);
    }

    #[test]
    fn test_wasi_config_from_policy() {
        use crate::sandbox::{CompiledPolicy, PlatformFlags};
        use fcp_manifest::SandboxProfile;
        let policy = CompiledPolicy {
            profile: SandboxProfile::Strict,
            memory_limit_bytes: 512 * 1024 * 1024,
            cpu_percent: 75,
            wall_clock_timeout: Duration::from_secs(60),
            readonly_paths: vec![PathBuf::from("/usr")],
            writable_paths: vec![PathBuf::from("/tmp/data")],
            deny_exec: true,
            deny_ptrace: true,
            block_direct_network: true,
            state_dir: Some(PathBuf::from("/tmp/data")),
            platform_flags: PlatformFlags::default(),
        };

        let config = WasiConfig::from_policy(&policy).unwrap();
        assert_eq!(config.memory_limit_bytes, 512 * 1024 * 1024);
        assert_eq!(config.wall_clock_timeout, Duration::from_secs(60));
        assert!(config.block_direct_network);
        assert_eq!(config.readonly_paths.len(), 1);
        assert_eq!(config.writable_paths.len(), 1);
        assert_eq!(config.state_dir, Some(PathBuf::from("/tmp/data")));
    }

    #[test]
    fn test_deterministic_rng_zero_seed_uses_default() {
        let mut rng = DeterministicRng::new(0);
        // Zero seed should use a non-zero default
        let val = rng.next_u64();
        assert_ne!(val, 0);
    }

    #[test]
    fn test_deterministic_rng_next_byte() {
        let mut rng1 = DeterministicRng::new(42);
        let mut rng2 = DeterministicRng::new(42);
        // Same seed produces same byte sequence
        for _ in 0..10 {
            assert_eq!(rng1.next_byte(), rng2.next_byte());
        }
    }

    #[test]
    fn test_network_capability_gate_check_tcp_no_constraints() {
        let gate = NetworkCapabilityGate::new(None, true);
        let result = gate.check_tcp("db.example.com", 5432, true);
        assert!(result.is_err());
    }

    #[test]
    fn test_network_capability_gate_not_blocked_no_constraints() {
        // block_direct=false, no constraints = should error with "no network policy"
        let gate = NetworkCapabilityGate::new(None, false);
        let result = gate.check_http("https://example.com/", "GET");
        assert!(result.is_err());
    }

    #[test]
    fn test_network_capability_gate_with_constraints() {
        use fcp_manifest::NetworkConstraints;
        let constraints = NetworkConstraints {
            host_allow: vec!["api.example.com".into()],
            port_allow: vec![443],
            ip_allow: vec![],
            cidr_deny: vec![],
            deny_localhost: true,
            deny_private_ranges: true,
            deny_tailnet_ranges: true,
            require_sni: false,
            spki_pins: vec![],
            deny_ip_literals: true,
            require_host_canonicalization: false,
            dns_max_ips: 16,
            max_redirects: 5,
            connect_timeout_ms: 10_000,
            total_timeout_ms: 60_000,
            max_response_bytes: 10_485_760,
        };

        let gate = NetworkCapabilityGate::new(Some(constraints), true);
        let result = gate.check_http("https://api.example.com/data", "GET");
        assert!(result.is_ok());

        // Denied host
        let result = gate.check_http("https://evil.com/", "GET");
        assert!(result.is_err());
    }

    #[test]
    fn test_leb128_empty_input() {
        assert_eq!(read_leb128(&[]), None);
    }

    #[test]
    fn test_leb128_single_byte_max() {
        assert_eq!(read_leb128(&[0x7F]), Some((127, 1)));
    }

    #[test]
    fn test_leb128_multi_byte() {
        // 300 = 0xAC 0x02
        assert_eq!(read_leb128(&[0xAC, 0x02]), Some((300, 2)));
    }

    #[test]
    fn test_leb128_incomplete() {
        // High bit set but no continuation byte
        assert_eq!(read_leb128(&[0x80]), None);
    }

    #[test]
    fn test_cpu_percent_to_fuel_zero() {
        // cpu_percent=0 must not grant unlimited CPU (defense-in-depth;
        // the manifest validator already rejects 0, but the function
        // should be correct on its own).
        assert_eq!(WasiConfig::cpu_percent_to_fuel(0), 1);
    }

    #[test]
    fn test_cpu_percent_to_fuel_one() {
        assert_eq!(WasiConfig::cpu_percent_to_fuel(1), 100_000_000);
    }

    #[test]
    fn test_cpu_percent_to_fuel_above_100() {
        // Should clamp or treat as 100%. The current code checks >= 100.
        assert_eq!(WasiConfig::cpu_percent_to_fuel(200), 1_000_000_000_000);
    }

    #[test]
    fn test_extract_custom_section_too_short() {
        // Less than 8 bytes (WASM magic + version)
        assert!(extract_custom_section(&[0, 1, 2], "anything").is_none());
    }

    #[test]
    fn test_extract_custom_section_empty_wasm() {
        // Valid WASM magic + version but no sections
        let wasm = b"\0asm\x01\0\0\0";
        assert!(extract_custom_section(wasm, "fcp-manifest").is_none());
    }

    #[test]
    fn test_wasi_config_default_comprehensive() {
        let config = WasiConfig::default();
        assert_eq!(config.memory_limit_bytes, 256 * 1024 * 1024);
        assert_eq!(config.wall_clock_timeout, Duration::from_secs(30));
        assert!(config.readonly_paths.is_empty());
        assert!(config.writable_paths.is_empty());
        assert!(config.state_dir.is_none());
        assert!(!config.deterministic_mode);
        assert_eq!(config.deterministic_timestamp, 0);
        assert_eq!(config.deterministic_seed, 0);
        assert!(config.network_constraints.is_none());
        assert!(config.block_direct_network);
        assert_eq!(config.max_fuel, 0);
        assert!(config.env_vars.is_empty());
        assert!(config.args.is_empty());
        assert!(!config.inherit_stdout);
        assert!(!config.inherit_stderr);
    }

    #[test]
    fn test_fs_capability_gate_empty() {
        let gate = FsCapabilityGate::new(vec![], vec![]);
        assert!(gate.readonly_paths.is_empty());
        assert!(gate.writable_paths.is_empty());
    }

    // ── Additional coverage (bead 2ct9j) ──

    #[test]
    fn test_wasi_config_with_network_constraints() {
        use fcp_manifest::NetworkConstraints;
        let constraints = NetworkConstraints {
            host_allow: vec!["api.example.com".into()],
            port_allow: vec![443],
            ip_allow: vec![],
            cidr_deny: vec![],
            deny_localhost: true,
            deny_private_ranges: true,
            deny_tailnet_ranges: true,
            require_sni: false,
            spki_pins: vec![],
            deny_ip_literals: true,
            require_host_canonicalization: false,
            dns_max_ips: 16,
            max_redirects: 5,
            connect_timeout_ms: 10_000,
            total_timeout_ms: 60_000,
            max_response_bytes: 10_485_760,
        };
        let config = WasiConfig::default().with_network_constraints(constraints);
        assert!(config.network_constraints.is_some());
        let nc = config.network_constraints.unwrap();
        assert_eq!(nc.host_allow, vec!["api.example.com"]);
        assert_eq!(nc.port_allow, vec![443]);
    }

    #[test]
    fn test_wasi_config_builder_chaining() {
        let mut env = HashMap::new();
        env.insert("APP_ENV".into(), "test".into());
        let config = WasiConfig::default()
            .with_deterministic_mode(1_700_000_000, 99)
            .with_env(env)
            .with_args(vec!["--verbose".into()])
            .with_inherit_stdio(true, false);

        assert!(config.deterministic_mode);
        assert_eq!(config.deterministic_seed, 99);
        assert_eq!(config.env_vars.get("APP_ENV"), Some(&"test".into()));
        assert_eq!(config.args, vec!["--verbose"]);
        assert!(config.inherit_stdout);
        assert!(!config.inherit_stderr);
    }

    #[test]
    fn test_wasi_host_state_check_timeout_not_expired() {
        let config = WasiConfig::default(); // 30s timeout
        let wasi_ctx = WasiCtxBuilder::new().build();
        let state = WasiHostState::new(&config, wasi_ctx);
        // Just created, should not be timed out
        assert!(state.check_timeout().is_ok());
    }

    #[test]
    fn test_wasi_host_state_check_timeout_expired() {
        let config = WasiConfig {
            wall_clock_timeout: Duration::from_nanos(1), // Effectively zero
            ..WasiConfig::default()
        };
        let wasi_ctx = WasiCtxBuilder::new().build();
        let state = WasiHostState::new(&config, wasi_ctx);
        // Sleep briefly to ensure expiry
        std::thread::sleep(Duration::from_millis(1));
        assert!(matches!(state.check_timeout(), Err(WasiError::Timeout)));
    }

    #[test]
    fn test_wasi_host_state_current_time_deterministic() {
        let config = WasiConfig::default().with_deterministic_mode(1_700_000_000, 0);
        let wasi_ctx = WasiCtxBuilder::new().build();
        let state = WasiHostState::new(&config, wasi_ctx);
        let time = state.current_time();
        let expected = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        assert_eq!(time, expected);
    }

    #[test]
    fn test_wasi_host_state_current_time_real() {
        let config = WasiConfig::default(); // deterministic_mode = false
        let wasi_ctx = WasiCtxBuilder::new().build();
        let state = WasiHostState::new(&config, wasi_ctx);
        let before = SystemTime::now();
        let time = state.current_time();
        let after = SystemTime::now();
        assert!(time >= before);
        assert!(time <= after);
    }

    #[test]
    fn test_wasi_host_state_get_random_bytes_deterministic() {
        let config = WasiConfig::default().with_deterministic_mode(0, 42);
        let wasi_ctx = WasiCtxBuilder::new().build();
        let state = WasiHostState::new(&config, wasi_ctx);
        let bytes = state.get_random_bytes(32);
        assert_eq!(bytes.len(), 32);
        // Extremely unlikely to be all zeros from a real RNG
        assert!(bytes.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_wasi_host_state_get_random_bytes_zero_length() {
        let config = WasiConfig::default().with_deterministic_mode(0, 1);
        let wasi_ctx = WasiCtxBuilder::new().build();
        let state = WasiHostState::new(&config, wasi_ctx);
        let bytes = state.get_random_bytes(0);
        assert!(bytes.is_empty());
    }

    #[test]
    fn test_wasi_host_state_get_random_bytes_real() {
        let config = WasiConfig::default(); // non-deterministic
        let wasi_ctx = WasiCtxBuilder::new().build();
        let state = WasiHostState::new(&config, wasi_ctx);
        let bytes = state.get_random_bytes(32);
        assert_eq!(bytes.len(), 32);
        // Extremely unlikely to be all zeros from a real RNG
        assert!(bytes.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_resource_limiter_memory_growing() {
        use wasmtime::ResourceLimiter;
        let config = WasiConfig {
            memory_limit_bytes: 1024,
            ..WasiConfig::default()
        };
        let wasi_ctx = WasiCtxBuilder::new().build();
        let mut state = WasiHostState::new(&config, wasi_ctx);

        // Within limit
        assert!(state.memory_growing(0, 512, None).unwrap());
        assert!(state.memory_growing(0, 1024, None).unwrap());
        // Exceeds limit
        assert!(!state.memory_growing(0, 1025, None).unwrap());
        assert!(!state.memory_growing(0, 2048, None).unwrap());
    }

    #[test]
    fn test_resource_limiter_table_growing() {
        use wasmtime::ResourceLimiter;
        let config = WasiConfig::default();
        let wasi_ctx = WasiCtxBuilder::new().build();
        let mut state = WasiHostState::new(&config, wasi_ctx);

        // Tables allowed to grow up to MAX_TABLE_ELEMENTS
        assert!(state.table_growing(0, 1000, None).unwrap());
        assert!(state.table_growing(0, 100_000, None).unwrap());
        assert!(!state.table_growing(0, 100_001, None).unwrap());
        assert!(!state.table_growing(0, 1_000_000, None).unwrap());
    }

    #[test]
    fn test_execution_result_debug() {
        let result = ExecutionResult {
            exit_code: 0,
            stdout: Some(Bytes::from_static(b"hello")),
            stderr: None,
            duration: Duration::from_millis(42),
            fuel_consumed: Some(1234),
        };
        let dbg = format!("{result:?}");
        assert!(dbg.contains("exit_code"));
        assert!(dbg.contains("fuel_consumed"));
    }

    #[test]
    fn test_wasi_error_from_sandbox_error() {
        let sandbox_err = SandboxError::Timeout;
        let wasi_err = WasiError::from(sandbox_err);
        assert!(wasi_err.to_string().contains("timeout"));
    }

    #[test]
    fn test_wasi_error_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "forbidden");
        let wasi_err = WasiError::from(io_err);
        assert!(wasi_err.to_string().contains("forbidden"));
    }

    #[test]
    fn test_wasi_error_debug() {
        let err = WasiError::Timeout;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Timeout"));

        let err = WasiError::FsAccessDenied {
            path: "/secret".into(),
            reason: "nope".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("FsAccessDenied"));
        assert!(dbg.contains("/secret"));
    }

    #[test]
    fn test_network_gate_check_tcp_with_constraints() {
        use fcp_manifest::NetworkConstraints;
        let constraints = NetworkConstraints {
            host_allow: vec!["db.internal.com".into()],
            port_allow: vec![5432],
            ip_allow: vec![],
            cidr_deny: vec![],
            deny_localhost: true,
            deny_private_ranges: false,
            deny_tailnet_ranges: true,
            require_sni: false,
            spki_pins: vec![],
            deny_ip_literals: true,
            require_host_canonicalization: false,
            dns_max_ips: 16,
            max_redirects: 5,
            connect_timeout_ms: 10_000,
            total_timeout_ms: 60_000,
            max_response_bytes: 10_485_760,
        };

        let gate = NetworkCapabilityGate::new(Some(constraints), true);
        // Allowed host+port
        let result = gate.check_tcp("db.internal.com", 5432, true);
        assert!(result.is_ok());
        // Denied host
        let result = gate.check_tcp("evil.com", 5432, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_network_gate_check_tcp_blocked_no_constraints() {
        let gate = NetworkCapabilityGate::new(None, false);
        let result = gate.check_tcp("anything.com", 80, false);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("no network policy"));
    }

    #[test]
    fn test_fs_capability_gate_check_access_read_tmp() {
        // /tmp always exists on macOS/Linux
        let gate = FsCapabilityGate::new(vec![PathBuf::from("/tmp")], vec![]);
        assert!(gate.check_access(Path::new("/tmp"), false).is_ok());
        // Write should be denied (only in readonly list)
        assert!(gate.check_access(Path::new("/tmp"), true).is_err());
    }

    #[test]
    fn test_fs_capability_gate_check_access_write_allowed() {
        let gate = FsCapabilityGate::new(vec![], vec![PathBuf::from("/tmp")]);
        // Writable paths grant both read and write
        assert!(gate.check_access(Path::new("/tmp"), false).is_ok());
        assert!(gate.check_access(Path::new("/tmp"), true).is_ok());
    }

    #[test]
    fn test_fs_capability_gate_check_access_denied() {
        let gate = FsCapabilityGate::new(vec![PathBuf::from("/tmp")], vec![]);
        // /etc is not in the allow list
        let result = gate.check_access(Path::new("/etc"), false);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("not in allowed list"));
    }

    #[test]
    fn test_fs_capability_gate_check_access_nonexistent_read() {
        let gate = FsCapabilityGate::new(vec![PathBuf::from("/tmp")], vec![]);
        let result = gate.check_access(Path::new("/tmp/nonexistent_12345_test"), false);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("does not exist"));
    }

    #[test]
    fn test_fs_capability_gate_check_access_nested_missing_write_allowed() {
        use std::fs;
        use std::time::{SystemTime, UNIX_EPOCH};

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after epoch")
            .as_nanos();
        let allowed =
            std::env::temp_dir().join(format!("fcp-wasi-fs-gate-{}-{unique}", std::process::id()));
        fs::create_dir_all(&allowed).expect("allowed directory should exist");

        let gate = FsCapabilityGate::new(vec![], vec![allowed.clone()]);
        let pending_write = allowed.join("nested").join("deeper").join("future.txt");

        assert!(
            gate.check_access(&pending_write, true).is_ok(),
            "nested missing writes under an allowed writable root should be permitted",
        );
    }

    #[test]
    fn test_extract_custom_section_with_valid_wasm() {
        // Construct a minimal valid WASM with a custom section named "fcp-manifest"
        let section_name = b"fcp-manifest";
        let payload = b"{\"test\":true}";
        let name_len = section_name.len();
        let section_content_len = 1 + name_len + payload.len(); // 1 byte for name LEB128 len

        let mut wasm = Vec::new();
        // WASM magic + version
        wasm.extend_from_slice(b"\0asm\x01\0\0\0");
        // Custom section (id=0)
        wasm.push(0);
        wasm.push(section_content_len as u8);
        // Name length (LEB128)
        wasm.push(name_len as u8);
        // Name
        wasm.extend_from_slice(section_name);
        // Payload
        wasm.extend_from_slice(payload);

        let result = extract_custom_section(&wasm, "fcp-manifest");
        assert_eq!(result, Some(payload.to_vec()));
    }

    #[test]
    fn test_extract_custom_section_wrong_name() {
        let section_name = b"other-section";
        let payload = b"data";
        let name_len = section_name.len();
        let section_content_len = 1 + name_len + payload.len();

        let mut wasm = Vec::new();
        wasm.extend_from_slice(b"\0asm\x01\0\0\0");
        wasm.push(0);
        wasm.push(section_content_len as u8);
        wasm.push(name_len as u8);
        wasm.extend_from_slice(section_name);
        wasm.extend_from_slice(payload);

        let result = extract_custom_section(&wasm, "fcp-manifest");
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_custom_section_skips_non_custom() {
        let mut wasm = Vec::new();
        // WASM magic + version
        wasm.extend_from_slice(b"\0asm\x01\0\0\0");
        // Type section (id=1) with 2 bytes of data
        wasm.push(1);
        wasm.push(2);
        wasm.extend_from_slice(&[0, 0]);
        // Custom section with fcp-manifest
        let section_name = b"fcp-manifest";
        let payload = b"found-it";
        let name_len = section_name.len();
        let section_content_len = 1 + name_len + payload.len();
        wasm.push(0);
        wasm.push(section_content_len as u8);
        wasm.push(name_len as u8);
        wasm.extend_from_slice(section_name);
        wasm.extend_from_slice(payload);

        let result = extract_custom_section(&wasm, "fcp-manifest");
        assert_eq!(result, Some(payload.to_vec()));
    }

    #[test]
    fn test_leb128_overflow_guard() {
        // Craft a sequence that would shift beyond usize::BITS
        // Each continuation byte adds 7 bits; 10 bytes = 70 bits > 64 bits
        let mut bytes = vec![0x80u8; 10]; // 10 continuation bytes
        bytes.push(0x01); // terminator
        // Should return None due to shift overflow
        assert!(read_leb128(&bytes).is_none());
    }

    #[test]
    fn test_deterministic_rng_produces_full_byte_range() {
        let mut rng = DeterministicRng::new(1);
        let mut seen = [false; 256];
        // Generate enough bytes to cover most of the byte range
        for _ in 0..10_000 {
            seen[rng.next_byte() as usize] = true;
        }
        // Should see at least 200 distinct values from a good xorshift
        let distinct = seen.iter().filter(|&&s| s).count();
        assert!(
            distinct > 200,
            "only {distinct} distinct byte values in 10k samples"
        );
    }

    #[test]
    fn test_wasi_runtime_new() {
        let config = WasiConfig::default();
        let runtime = WasiRuntime::new(config);
        assert!(runtime.is_ok());
    }

    #[test]
    fn test_wasi_runtime_new_with_fuel() {
        let config = WasiConfig {
            max_fuel: 1_000_000,
            ..WasiConfig::default()
        };
        let runtime = WasiRuntime::new(config);
        assert!(runtime.is_ok());
    }

    #[test]
    fn test_wasi_runtime_rejects_existing_readonly_file_preopen() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "fcp-wasi-readonly-file-{}-{unique}",
            std::process::id()
        ));
        let file = dir.join("readonly.txt");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&file, b"data").unwrap();

        let Err(err) = WasiRuntime::new(WasiConfig {
            readonly_paths: vec![file.clone()],
            ..WasiConfig::default()
        }) else {
            panic!("expected readonly file preopen to be rejected");
        };

        assert!(matches!(err, WasiError::FsAccessDenied { .. }));
        assert!(err.to_string().contains("must be directories"));
        assert!(err.to_string().contains(&file.display().to_string()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_wasi_runtime_rejects_existing_writable_file_preopen() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "fcp-wasi-writable-file-{}-{unique}",
            std::process::id()
        ));
        let file = dir.join("writable.txt");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&file, b"data").unwrap();

        let Err(err) = WasiRuntime::new(WasiConfig {
            writable_paths: vec![file.clone()],
            ..WasiConfig::default()
        }) else {
            panic!("expected writable file preopen to be rejected");
        };

        assert!(matches!(err, WasiError::FsAccessDenied { .. }));
        assert!(err.to_string().contains("must be directories"));
        assert!(err.to_string().contains(&file.display().to_string()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_wasi_runtime_rejects_missing_writable_file_like_preopen() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "fcp-wasi-missing-writable-file-{}-{unique}",
            std::process::id()
        ));

        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let dir = std::fs::canonicalize(&dir).unwrap();
        let missing = dir.join("state.json");

        let runtime = WasiRuntime::new(WasiConfig {
            writable_paths: vec![missing.clone()],
            ..WasiConfig::default()
        })
        .expect("runtime construction should succeed before store creation");
        let Err(err) = runtime.create_store() else {
            panic!("expected missing writable file-like preopen to be rejected");
        };

        assert!(matches!(err, WasiError::FsAccessDenied { .. }));
        assert!(
            err.to_string()
                .contains("must already exist as directories")
        );
        assert!(err.to_string().contains(&missing.display().to_string()));
        assert!(
            !missing.exists(),
            "missing file-like preopen should not be auto-created"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn test_wasi_runtime_rejects_readonly_symlink_escape_preopen() {
        use std::os::unix::fs::symlink;
        use std::time::{SystemTime, UNIX_EPOCH};

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "fcp-wasi-readonly-symlink-{}-{unique}",
            std::process::id()
        ));
        let escaped = dir.join("escaped");
        let link = dir.join("link");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::create_dir_all(&escaped).unwrap();
        symlink(&escaped, &link).unwrap();

        let runtime = WasiRuntime::new(WasiConfig {
            readonly_paths: vec![link.clone()],
            ..WasiConfig::default()
        })
        .expect("runtime construction should succeed before store creation");
        let Err(err) = runtime.create_store() else {
            panic!("expected symlinked readonly preopen to be rejected");
        };

        assert!(matches!(err, WasiError::FsAccessDenied { .. }));
        assert!(err.to_string().contains("symlinked ancestor"));
        assert!(err.to_string().contains(&link.display().to_string()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn test_wasi_runtime_rejects_writable_symlink_escape_preopen() {
        use std::os::unix::fs::symlink;
        use std::time::{SystemTime, UNIX_EPOCH};

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "fcp-wasi-writable-symlink-{}-{unique}",
            std::process::id()
        ));
        let state = dir.join("state");
        let escaped = dir.join("escaped");
        let link = state.join("link");
        let pending = link.join("nested");

        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&state).unwrap();
        std::fs::create_dir_all(&escaped).unwrap();
        symlink(&escaped, &link).unwrap();

        let runtime = WasiRuntime::new(WasiConfig {
            writable_paths: vec![pending.clone()],
            ..WasiConfig::default()
        })
        .expect("runtime construction should succeed before store creation");
        let Err(err) = runtime.create_store() else {
            panic!("expected symlinked writable preopen to be rejected");
        };

        assert!(matches!(err, WasiError::FsAccessDenied { .. }));
        assert!(err.to_string().contains("symlinked ancestor"));
        assert!(err.to_string().contains(&pending.display().to_string()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_wasi_runtime_load_invalid_component() {
        let config = WasiConfig::default();
        let runtime = WasiRuntime::new(config).unwrap();
        let result = runtime.load_component(b"not valid wasm");
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_wasi_runtime_invoke_component_export() {
        let config = WasiConfig {
            max_fuel: 10_000,
            ..WasiConfig::default()
        };
        let runtime = WasiRuntime::new(config).unwrap();
        let component = runtime.load_component(minimal_command_component()).unwrap();
        let args = vec!["--dry-run".to_string()];

        let result = runtime.invoke(&component, "run", &args).await.unwrap();

        assert_eq!(result.exit_code, 0);
        assert!(result.duration >= Duration::ZERO);
        assert!(result.fuel_consumed.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_wasi_runtime_invoke_missing_export() {
        let runtime = WasiRuntime::new(WasiConfig::default()).unwrap();
        let component = runtime.load_component(minimal_command_component()).unwrap();
        let args = Vec::new();

        let err = runtime
            .invoke(&component, "missing", &args)
            .await
            .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("missing"));
        assert!(message.contains("failed to resolve"));
    }

    #[test]
    fn test_wasi_runtime_create_store() {
        let config = WasiConfig {
            max_fuel: 500_000,
            ..WasiConfig::default()
        };
        let runtime = WasiRuntime::new(config).unwrap();
        let store = runtime.create_store();
        assert!(store.is_ok());
    }

    #[test]
    fn test_wasi_runtime_create_store_with_env_and_args() {
        let mut env = HashMap::new();
        env.insert("TEST".into(), "1".into());
        let config = WasiConfig::default()
            .with_env(env)
            .with_args(vec!["--flag".into()]);
        let runtime = WasiRuntime::new(config).unwrap();
        let store = runtime.create_store();
        assert!(store.is_ok());
    }

    // ── New tests: WasiError display all variants ──

    #[test]
    fn test_wasi_error_display_engine_creation() {
        let e = WasiError::EngineCreation("bad config".into());
        assert!(e.to_string().contains("bad config"));
    }

    #[test]
    fn test_wasi_error_display_component_load() {
        let e = WasiError::ComponentLoad("invalid wasm".into());
        assert!(e.to_string().contains("invalid wasm"));
    }

    #[test]
    fn test_wasi_error_display_instantiation() {
        let e = WasiError::Instantiation("missing import".into());
        assert!(e.to_string().contains("missing import"));
    }

    #[test]
    fn test_wasi_error_display_execution() {
        let e = WasiError::Execution("trap".into());
        assert!(e.to_string().contains("trap"));
    }

    #[test]
    fn test_wasi_error_display_resource_limit() {
        let e = WasiError::ResourceLimit("memory exceeded".into());
        assert!(e.to_string().contains("memory exceeded"));
    }

    #[test]
    fn test_wasi_error_display_fs_access_denied() {
        let e = WasiError::FsAccessDenied {
            path: "/etc/shadow".into(),
            reason: "not in allowed list".into(),
        };
        let msg = e.to_string();
        assert!(msg.contains("/etc/shadow"));
        assert!(msg.contains("not in allowed list"));
    }

    #[test]
    fn test_wasi_error_display_network_access_denied() {
        let e = WasiError::NetworkAccessDenied("no policy".into());
        assert!(e.to_string().contains("no policy"));
    }

    #[test]
    fn test_wasi_error_display_clock_access_denied() {
        let e = WasiError::ClockAccessDenied;
        assert!(e.to_string().contains("clock"));
    }

    #[test]
    fn test_wasi_error_display_entropy_access_denied() {
        let e = WasiError::EntropyAccessDenied;
        assert!(e.to_string().contains("entropy"));
    }

    #[test]
    fn test_wasi_error_display_invalid_component() {
        let e = WasiError::InvalidComponent("not wasm".into());
        assert!(e.to_string().contains("not wasm"));
    }

    #[test]
    fn test_wasi_error_display_manifest_extraction() {
        let e = WasiError::ManifestExtraction("no section".into());
        assert!(e.to_string().contains("no section"));
    }

    // ── New tests: DeterministicRng ──

    #[test]
    fn test_deterministic_rng_different_seeds_produce_different_sequences() {
        let mut rng1 = DeterministicRng::new(1);
        let mut rng2 = DeterministicRng::new(2);
        let bytes1: Vec<u8> = (0..16).map(|_| rng1.next_byte()).collect();
        let bytes2: Vec<u8> = (0..16).map(|_| rng2.next_byte()).collect();
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn test_deterministic_rng_same_seed_same_u64() {
        let mut rng1 = DeterministicRng::new(42);
        let mut rng2 = DeterministicRng::new(42);
        for _ in 0..100 {
            assert_eq!(rng1.next_u64(), rng2.next_u64());
        }
    }

    #[test]
    fn test_deterministic_rng_never_returns_zero_state() {
        // xorshift should never reach zero state from a non-zero seed
        let mut rng = DeterministicRng::new(1);
        for _ in 0..1000 {
            let val = rng.next_u64();
            assert_ne!(val, 0, "xorshift64 should never produce zero");
        }
    }

    #[test]
    fn test_deterministic_rng_debug() {
        let rng = DeterministicRng::new(42);
        let debug = format!("{rng:?}");
        assert!(debug.contains("DeterministicRng"));
    }

    // ── New tests: WasiConfig edge cases ──

    #[test]
    fn test_cpu_percent_to_fuel_50() {
        assert_eq!(WasiConfig::cpu_percent_to_fuel(50), 5_000_000_000);
    }

    #[test]
    fn test_cpu_percent_to_fuel_100() {
        assert_eq!(WasiConfig::cpu_percent_to_fuel(100), 1_000_000_000_000);
    }

    #[test]
    fn test_cpu_percent_to_fuel_99() {
        assert_eq!(WasiConfig::cpu_percent_to_fuel(99), 9_900_000_000);
    }

    #[test]
    fn test_wasi_config_clone() {
        let original = WasiConfig::default()
            .with_deterministic_mode(1_000_000, 99)
            .with_args(vec!["--test".into()])
            .with_inherit_stdio(true, true);
        let cloned = original.clone();
        assert_eq!(original.memory_limit_bytes, cloned.memory_limit_bytes);
        assert_eq!(original.deterministic_mode, cloned.deterministic_mode);
        assert_eq!(
            original.deterministic_timestamp,
            cloned.deterministic_timestamp
        );
        assert_eq!(original.deterministic_seed, cloned.deterministic_seed);
        assert_eq!(original.args, cloned.args);
        assert_eq!(original.inherit_stdout, cloned.inherit_stdout);
        assert_eq!(original.inherit_stderr, cloned.inherit_stderr);
    }

    #[test]
    fn test_wasi_config_debug() {
        let config = WasiConfig::default();
        let debug = format!("{config:?}");
        assert!(debug.contains("WasiConfig"));
    }

    // ── New tests: NetworkCapabilityGate ──

    #[test]
    fn test_network_gate_debug() {
        let gate = NetworkCapabilityGate::new(None, false);
        let debug = format!("{gate:?}");
        assert!(debug.contains("NetworkCapabilityGate"));
    }

    #[test]
    fn test_network_gate_blocked_direct_no_constraints_http() {
        let gate = NetworkCapabilityGate::new(None, true);
        let result = gate.check_http("https://example.com/", "GET");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("blocked"));
    }

    #[test]
    fn test_network_gate_blocked_direct_no_constraints_tcp() {
        let gate = NetworkCapabilityGate::new(None, true);
        let result = gate.check_tcp("example.com", 443, true);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("blocked"));
    }

    // ── New tests: FsCapabilityGate ──

    #[test]
    fn test_fs_capability_gate_debug() {
        let gate = FsCapabilityGate::new(vec![PathBuf::from("/usr")], vec![PathBuf::from("/tmp")]);
        let debug = format!("{gate:?}");
        assert!(debug.contains("FsCapabilityGate"));
    }

    #[test]
    fn test_fs_capability_gate_read_in_writable_path() {
        // Writable paths also grant read
        let gate = FsCapabilityGate::new(vec![], vec![PathBuf::from("/tmp")]);
        let result = gate.check_access(Path::new("/tmp"), false);
        assert!(result.is_ok());
    }

    // ── New tests: ExecutionResult ──

    #[test]
    fn test_execution_result_no_fuel() {
        let result = ExecutionResult {
            exit_code: 1,
            stdout: None,
            stderr: Some(Bytes::from_static(b"error")),
            duration: Duration::from_secs(5),
            fuel_consumed: None,
        };
        assert_eq!(result.exit_code, 1);
        assert!(result.stdout.is_none());
        assert!(result.stderr.is_some());
        assert!(result.fuel_consumed.is_none());
    }

    #[test]
    fn test_execution_result_debug_fields() {
        let result = ExecutionResult {
            exit_code: 0,
            stdout: None,
            stderr: None,
            duration: Duration::from_millis(100),
            fuel_consumed: None,
        };
        let debug = format!("{result:?}");
        assert!(debug.contains("exit_code"));
        assert!(debug.contains("duration"));
    }

    // ── New tests: LEB128 edge cases ──

    #[test]
    fn test_leb128_zero() {
        assert_eq!(read_leb128(&[0x00]), Some((0, 1)));
    }

    #[test]
    fn test_leb128_one() {
        assert_eq!(read_leb128(&[0x01]), Some((1, 1)));
    }

    #[test]
    fn test_leb128_128() {
        // LEB128(128) = 0x80 0x01; [0x80, 0x02] actually encodes 256
        assert_eq!(read_leb128(&[0x80, 0x01]), Some((128, 2)));
    }

    #[test]
    fn test_leb128_large_value() {
        // 624485 = 0xE5 0x8E 0x26
        assert_eq!(read_leb128(&[0xE5, 0x8E, 0x26]), Some((624_485, 3)));
    }

    // ── New tests: extract_custom_section ──

    #[test]
    fn test_extract_custom_section_multiple_custom_sections() {
        let mut wasm = Vec::new();
        wasm.extend_from_slice(b"\0asm\x01\0\0\0");

        // First custom section: "other"
        let name1 = b"other";
        let payload1 = b"data1";
        let content_len1 = 1 + name1.len() + payload1.len();
        wasm.push(0); // custom section id
        wasm.push(content_len1 as u8);
        wasm.push(name1.len() as u8);
        wasm.extend_from_slice(name1);
        wasm.extend_from_slice(payload1);

        // Second custom section: "fcp-manifest"
        let name2 = b"fcp-manifest";
        let payload2 = b"manifest-data";
        let content_len2 = 1 + name2.len() + payload2.len();
        wasm.push(0);
        wasm.push(content_len2 as u8);
        wasm.push(name2.len() as u8);
        wasm.extend_from_slice(name2);
        wasm.extend_from_slice(payload2);

        let result = extract_custom_section(&wasm, "fcp-manifest");
        assert_eq!(result, Some(payload2.to_vec()));
    }

    #[test]
    fn test_extract_custom_section_exact_8_bytes() {
        // Exactly WASM magic + version, no sections
        let wasm = b"\0asm\x01\0\0\0";
        assert!(extract_custom_section(wasm, "test").is_none());
    }

    // ── WasiHostState capability gate accessors ──

    #[test]
    fn test_host_state_fs_gate_accessor() {
        let config = WasiConfig {
            readonly_paths: vec![PathBuf::from("/tmp")],
            writable_paths: vec![PathBuf::from("/tmp/out")],
            ..WasiConfig::default()
        };
        let wasi_ctx = WasiCtxBuilder::new().build();
        let state = WasiHostState::new(&config, wasi_ctx);
        // Verify accessor returns a gate with the configured paths
        let gate = state.fs_gate();
        assert!(!gate.readonly_paths.is_empty());
        assert!(!gate.writable_paths.is_empty());
    }

    #[test]
    fn test_host_state_net_gate_accessor() {
        let config = WasiConfig {
            block_direct_network: true,
            ..WasiConfig::default()
        };
        let wasi_ctx = WasiCtxBuilder::new().build();
        let state = WasiHostState::new(&config, wasi_ctx);
        let gate = state.net_gate();
        assert!(gate.block_direct);
    }

    #[test]
    fn test_host_state_validate_fs_access() {
        let config = WasiConfig {
            readonly_paths: vec![PathBuf::from("/tmp")],
            ..WasiConfig::default()
        };
        let wasi_ctx = WasiCtxBuilder::new().build();
        let state = WasiHostState::new(&config, wasi_ctx);
        // Read access to /tmp should be allowed
        assert!(state.validate_fs_access(Path::new("/tmp"), false).is_ok());
        // Write access to /tmp should be denied (only in readonly)
        assert!(state.validate_fs_access(Path::new("/tmp"), true).is_err());
    }

    #[test]
    fn test_host_state_validate_http_access_blocked() {
        let config = WasiConfig {
            block_direct_network: true,
            network_constraints: None,
            ..WasiConfig::default()
        };
        let wasi_ctx = WasiCtxBuilder::new().build();
        let state = WasiHostState::new(&config, wasi_ctx);
        let result = state.validate_http_access("https://example.com/", "GET");
        assert!(result.is_err());
    }

    #[test]
    fn test_host_state_validate_http_access_allowed() {
        let constraints = NetworkConstraints {
            host_allow: vec!["api.example.com".into()],
            port_allow: vec![443],
            ip_allow: vec![],
            cidr_deny: vec![],
            deny_localhost: true,
            deny_private_ranges: true,
            deny_tailnet_ranges: true,
            require_sni: false,
            spki_pins: vec![],
            deny_ip_literals: true,
            require_host_canonicalization: false,
            dns_max_ips: 16,
            max_redirects: 5,
            connect_timeout_ms: 10_000,
            total_timeout_ms: 60_000,
            max_response_bytes: 10_485_760,
        };
        let config = WasiConfig {
            network_constraints: Some(constraints),
            block_direct_network: true,
            ..WasiConfig::default()
        };
        let wasi_ctx = WasiCtxBuilder::new().build();
        let state = WasiHostState::new(&config, wasi_ctx);
        // Allowed host
        assert!(
            state
                .validate_http_access("https://api.example.com/data", "GET")
                .is_ok()
        );
        // Denied host
        assert!(
            state
                .validate_http_access("https://evil.com/", "GET")
                .is_err()
        );
    }

    #[test]
    fn test_host_state_validate_tcp_access_blocked() {
        let config = WasiConfig {
            block_direct_network: true,
            network_constraints: None,
            ..WasiConfig::default()
        };
        let wasi_ctx = WasiCtxBuilder::new().build();
        let state = WasiHostState::new(&config, wasi_ctx);
        let result = state.validate_tcp_access("db.example.com", 5432, true);
        assert!(result.is_err());
    }

    #[test]
    fn test_host_state_validate_tcp_access_allowed() {
        let constraints = NetworkConstraints {
            host_allow: vec!["db.internal.com".into()],
            port_allow: vec![5432],
            ip_allow: vec![],
            cidr_deny: vec![],
            deny_localhost: true,
            deny_private_ranges: false,
            deny_tailnet_ranges: true,
            require_sni: false,
            spki_pins: vec![],
            deny_ip_literals: true,
            require_host_canonicalization: false,
            dns_max_ips: 16,
            max_redirects: 5,
            connect_timeout_ms: 10_000,
            total_timeout_ms: 60_000,
            max_response_bytes: 10_485_760,
        };
        let config = WasiConfig {
            network_constraints: Some(constraints),
            block_direct_network: true,
            ..WasiConfig::default()
        };
        let wasi_ctx = WasiCtxBuilder::new().build();
        let state = WasiHostState::new(&config, wasi_ctx);
        assert!(
            state
                .validate_tcp_access("db.internal.com", 5432, true)
                .is_ok()
        );
        assert!(state.validate_tcp_access("evil.com", 5432, false).is_err());
    }

    // ── WasiConnectorRunner tests ──

    #[test]
    fn test_connector_runner_new() {
        let config = WasiConfig::default();
        let runner = WasiConnectorRunner::new(config);
        assert!(runner.is_ok());
    }

    #[test]
    fn test_connector_runner_from_policy() {
        use crate::sandbox::{CompiledPolicy, PlatformFlags};
        use fcp_manifest::SandboxProfile;
        let policy = CompiledPolicy {
            profile: SandboxProfile::Strict,
            memory_limit_bytes: 128 * 1024 * 1024,
            cpu_percent: 50,
            wall_clock_timeout: Duration::from_secs(30),
            readonly_paths: vec![PathBuf::from("/usr/lib")],
            writable_paths: vec![PathBuf::from("/tmp/state")],
            deny_exec: true,
            deny_ptrace: true,
            block_direct_network: true,
            state_dir: Some(PathBuf::from("/tmp/state")),
            platform_flags: PlatformFlags::default(),
        };
        let runner = WasiConnectorRunner::from_policy(&policy);
        assert!(runner.is_ok());
    }

    #[test]
    fn test_connector_runner_fs_gate_accessor() {
        let config = WasiConfig {
            readonly_paths: vec![PathBuf::from("/tmp")],
            writable_paths: vec![PathBuf::from("/tmp/data")],
            ..WasiConfig::default()
        };
        let runner = WasiConnectorRunner::new(config).unwrap();
        let gate = runner.fs_gate();
        assert!(!gate.readonly_paths.is_empty());
        assert!(!gate.writable_paths.is_empty());
    }

    #[test]
    fn test_connector_runner_net_gate_accessor() {
        let config = WasiConfig {
            block_direct_network: true,
            ..WasiConfig::default()
        };
        let runner = WasiConnectorRunner::new(config).unwrap();
        let gate = runner.net_gate();
        assert!(gate.block_direct);
    }

    #[test]
    fn test_connector_runner_validate_fs_read_allowed() {
        let config = WasiConfig {
            readonly_paths: vec![PathBuf::from("/tmp")],
            ..WasiConfig::default()
        };
        let runner = WasiConnectorRunner::new(config).unwrap();
        assert!(runner.validate_fs_access(Path::new("/tmp"), false).is_ok());
    }

    #[test]
    fn test_connector_runner_validate_fs_write_denied_readonly() {
        let config = WasiConfig {
            readonly_paths: vec![PathBuf::from("/tmp")],
            writable_paths: vec![],
            ..WasiConfig::default()
        };
        let runner = WasiConnectorRunner::new(config).unwrap();
        assert!(runner.validate_fs_access(Path::new("/tmp"), true).is_err());
    }

    #[test]
    fn test_connector_runner_validate_fs_write_allowed() {
        let config = WasiConfig {
            writable_paths: vec![PathBuf::from("/tmp")],
            ..WasiConfig::default()
        };
        let runner = WasiConnectorRunner::new(config).unwrap();
        assert!(runner.validate_fs_access(Path::new("/tmp"), true).is_ok());
    }

    #[test]
    fn test_connector_runner_validate_fs_denied_path() {
        let config = WasiConfig {
            readonly_paths: vec![PathBuf::from("/tmp")],
            writable_paths: vec![],
            ..WasiConfig::default()
        };
        let runner = WasiConnectorRunner::new(config).unwrap();
        let result = runner.validate_fs_access(Path::new("/etc"), false);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("not in allowed list")
        );
    }

    #[test]
    fn test_connector_runner_validate_http_blocked() {
        let config = WasiConfig {
            block_direct_network: true,
            network_constraints: None,
            ..WasiConfig::default()
        };
        let runner = WasiConnectorRunner::new(config).unwrap();
        let result = runner.validate_http_access("https://example.com/", "GET");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("blocked"));
    }

    #[test]
    fn test_connector_runner_validate_http_allowed() {
        let constraints = NetworkConstraints {
            host_allow: vec!["api.stripe.com".into()],
            port_allow: vec![443],
            ip_allow: vec![],
            cidr_deny: vec![],
            deny_localhost: true,
            deny_private_ranges: true,
            deny_tailnet_ranges: true,
            require_sni: false,
            spki_pins: vec![],
            deny_ip_literals: true,
            require_host_canonicalization: false,
            dns_max_ips: 16,
            max_redirects: 5,
            connect_timeout_ms: 10_000,
            total_timeout_ms: 60_000,
            max_response_bytes: 10_485_760,
        };
        let config = WasiConfig {
            network_constraints: Some(constraints),
            block_direct_network: true,
            ..WasiConfig::default()
        };
        let runner = WasiConnectorRunner::new(config).unwrap();
        assert!(
            runner
                .validate_http_access("https://api.stripe.com/v1/charges", "POST")
                .is_ok()
        );
        // GET to an allowed host is also permitted (constraints are host-based, not method-based)
        assert!(
            runner
                .validate_http_access("https://api.stripe.com/v1/charges", "GET")
                .is_ok()
        );
        // PayPal is not in host_allow, so it should be denied
        assert!(
            runner
                .validate_http_access("https://api.paypal.com/v1", "GET")
                .is_err()
        );
    }

    #[test]
    fn test_connector_runner_validate_tcp_blocked() {
        let config = WasiConfig {
            block_direct_network: true,
            network_constraints: None,
            ..WasiConfig::default()
        };
        let runner = WasiConnectorRunner::new(config).unwrap();
        assert!(
            runner
                .validate_tcp_access("api.stripe.com", 443, true)
                .is_err()
        );
    }

    #[test]
    fn test_connector_runner_validate_tcp_allowed() {
        let constraints = NetworkConstraints {
            host_allow: vec!["api.stripe.com".into()],
            port_allow: vec![443, 8080],
            ip_allow: vec![],
            cidr_deny: vec![],
            deny_localhost: true,
            deny_private_ranges: false,
            deny_tailnet_ranges: true,
            require_sni: false,
            spki_pins: vec![],
            deny_ip_literals: true,
            require_host_canonicalization: false,
            dns_max_ips: 16,
            max_redirects: 5,
            connect_timeout_ms: 10_000,
            total_timeout_ms: 60_000,
            max_response_bytes: 10_485_760,
        };
        let config = WasiConfig {
            network_constraints: Some(constraints),
            block_direct_network: true,
            ..WasiConfig::default()
        };
        let runner = WasiConnectorRunner::new(config).unwrap();
        assert!(
            runner
                .validate_tcp_access("api.stripe.com", 443, true)
                .is_ok()
        );
        assert!(
            runner
                .validate_tcp_access("api.stripe.com", 8080, false)
                .is_ok()
        );
        assert!(
            runner
                .validate_tcp_access("api.stripe.com", 80, false)
                .is_err()
        );
        assert!(runner.validate_tcp_access("evil.com", 443, true).is_err());
    }

    #[test]
    fn test_connector_runner_runtime_accessor() {
        let config = WasiConfig::default();
        let runner = WasiConnectorRunner::new(config).unwrap();
        let _runtime = runner.runtime();
        // Can access engine through runtime
        let _engine = runner.runtime().engine();
    }

    #[test]
    fn test_connector_runner_load_invalid_component() {
        let config = WasiConfig::default();
        let runner = WasiConnectorRunner::new(config).unwrap();
        let result = runner.load_and_validate(b"not valid wasm");
        assert!(result.is_err());
    }

    #[test]
    fn test_connector_runner_load_component_no_manifest() {
        let config = WasiConfig::default();
        let runner = WasiConnectorRunner::new(config).unwrap();
        let result = runner.load_and_validate(minimal_command_component());
        assert!(result.is_ok());
        let validated = result.unwrap();
        assert!(!validated.has_manifest);
    }

    #[test]
    fn test_connector_runner_load_component_with_manifest_section() {
        let config = WasiConfig::default();
        let runner = WasiConnectorRunner::new(config).unwrap();

        // Build a minimal WASM with an fcp-manifest custom section
        let mut wasm = Vec::new();
        wasm.extend_from_slice(b"\0asm\x01\0\0\0");
        let section_name = b"fcp-manifest";
        let payload = b"{}"; // minimal JSON
        let name_len = section_name.len();
        let content_len = 1 + name_len + payload.len();
        wasm.push(0); // custom section id
        wasm.push(content_len as u8);
        wasm.push(name_len as u8);
        wasm.extend_from_slice(section_name);
        wasm.extend_from_slice(payload);

        // This will fail to load as a valid component (it's not a real component)
        // but validates our manifest detection logic
        let result = runner.load_and_validate(&wasm);
        // The component load will fail because it's not a valid WASM component
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_connector_runner_execute() {
        let config = WasiConfig {
            max_fuel: 10_000,
            ..WasiConfig::default()
        };
        let runner = WasiConnectorRunner::new(config).unwrap();
        let validated = runner
            .load_and_validate(minimal_command_component())
            .unwrap();
        let args: Vec<String> = vec!["--test".into()];
        let result = runner.execute(&validated.component, &args).await;
        assert!(result.is_ok());
        let exec = result.unwrap();
        assert_eq!(exec.exit_code, 0);
        assert!(exec.fuel_consumed.is_some());
    }

    // ── Capability gate integration: end-to-end scenarios ──

    #[test]
    fn test_strict_policy_denies_all_network() {
        // Strict policy with no network constraints = deny all
        let config = WasiConfig {
            block_direct_network: true,
            network_constraints: None,
            ..WasiConfig::default()
        };
        let runner = WasiConnectorRunner::new(config).unwrap();
        assert!(
            runner
                .validate_http_access("https://any.com/", "GET")
                .is_err()
        );
        assert!(runner.validate_tcp_access("any.com", 443, true).is_err());
    }

    #[test]
    fn test_strict_policy_allows_declared_hosts_only() {
        let constraints = NetworkConstraints {
            host_allow: vec!["api.stripe.com".into()],
            port_allow: vec![443],
            ip_allow: vec![],
            cidr_deny: vec![],
            deny_localhost: true,
            deny_private_ranges: true,
            deny_tailnet_ranges: true,
            require_sni: false,
            spki_pins: vec![],
            deny_ip_literals: true,
            require_host_canonicalization: false,
            dns_max_ips: 16,
            max_redirects: 5,
            connect_timeout_ms: 10_000,
            total_timeout_ms: 60_000,
            max_response_bytes: 10_485_760,
        };
        let config = WasiConfig {
            block_direct_network: true,
            network_constraints: Some(constraints),
            ..WasiConfig::default()
        };
        let runner = WasiConnectorRunner::new(config).unwrap();
        // Allowed
        assert!(
            runner
                .validate_http_access("https://api.stripe.com/v1/charges", "POST")
                .is_ok()
        );
        // Port mismatch
        assert!(
            runner
                .validate_tcp_access("api.stripe.com", 80, false)
                .is_err()
        );
        // Host mismatch
        assert!(
            runner
                .validate_http_access("https://api.paypal.com/v1", "GET")
                .is_err()
        );
    }

    #[test]
    fn test_filesystem_isolation_readonly_vs_writable() {
        let config = WasiConfig {
            readonly_paths: vec![PathBuf::from("/usr/share")],
            writable_paths: vec![PathBuf::from("/tmp")],
            ..WasiConfig::default()
        };
        let runner = WasiConnectorRunner::new(config).unwrap();
        // Read from readonly - allowed
        assert!(
            runner
                .validate_fs_access(Path::new("/usr/share"), false)
                .is_ok()
        );
        // Write to readonly - denied
        assert!(
            runner
                .validate_fs_access(Path::new("/usr/share"), true)
                .is_err()
        );
        // Read from writable - allowed (writable implies readable)
        assert!(runner.validate_fs_access(Path::new("/tmp"), false).is_ok());
        // Write to writable - allowed
        assert!(runner.validate_fs_access(Path::new("/tmp"), true).is_ok());
        // Access outside both lists - denied
        assert!(runner.validate_fs_access(Path::new("/etc"), false).is_err());
    }

    #[test]
    fn test_deterministic_mode_combined_with_gates() {
        let constraints = NetworkConstraints {
            host_allow: vec!["api.example.com".into()],
            port_allow: vec![443],
            ip_allow: vec![],
            cidr_deny: vec![],
            deny_localhost: true,
            deny_private_ranges: true,
            deny_tailnet_ranges: true,
            require_sni: false,
            spki_pins: vec![],
            deny_ip_literals: true,
            require_host_canonicalization: false,
            dns_max_ips: 16,
            max_redirects: 5,
            connect_timeout_ms: 10_000,
            total_timeout_ms: 60_000,
            max_response_bytes: 10_485_760,
        };
        let config = WasiConfig::default()
            .with_deterministic_mode(1_700_000_000, 42)
            .with_network_constraints(constraints);
        let runner = WasiConnectorRunner::new(config).unwrap();
        // Network gates still work in deterministic mode
        assert!(
            runner
                .validate_http_access("https://api.example.com/", "GET")
                .is_ok()
        );
        assert!(
            runner
                .validate_http_access("https://evil.com/", "GET")
                .is_err()
        );
    }

    #[test]
    fn test_socket_addr_allowed_tcp_connect() {
        // Must have explicit IP allowlist for raw socket access per
        // raw_socket_host_policy security tightening (empty host_allow +
        // empty ip_allow → Disabled).
        let constraints = NetworkConstraints {
            host_allow: vec![],
            port_allow: vec![443, 8080],
            ip_allow: vec!["1.2.3.4".parse().unwrap()],
            cidr_deny: vec![],
            deny_localhost: false,
            deny_private_ranges: false,
            deny_tailnet_ranges: false,
            require_sni: false,
            spki_pins: vec![],
            deny_ip_literals: false,
            require_host_canonicalization: false,
            dns_max_ips: 16,
            max_redirects: 5,
            connect_timeout_ms: 10_000,
            total_timeout_ms: 60_000,
            max_response_bytes: 10_485_760,
        };
        let addr_allowed: SocketAddr = "1.2.3.4:443".parse().unwrap();
        let addr_denied: SocketAddr = "1.2.3.4:9999".parse().unwrap();
        assert!(socket_addr_allowed(
            &constraints,
            addr_allowed,
            SocketAddrUse::TcpConnect
        ));
        assert!(!socket_addr_allowed(
            &constraints,
            addr_denied,
            SocketAddrUse::TcpConnect
        ));
    }

    #[test]
    fn test_socket_addr_allowed_non_tcp_connect_denied() {
        let constraints = NetworkConstraints {
            host_allow: vec![],
            port_allow: vec![443],
            ip_allow: vec![],
            cidr_deny: vec![],
            deny_localhost: false,
            deny_private_ranges: false,
            deny_tailnet_ranges: false,
            require_sni: false,
            spki_pins: vec![],
            deny_ip_literals: false,
            require_host_canonicalization: false,
            dns_max_ips: 16,
            max_redirects: 5,
            connect_timeout_ms: 10_000,
            total_timeout_ms: 60_000,
            max_response_bytes: 10_485_760,
        };
        let addr: SocketAddr = "1.2.3.4:443".parse().unwrap();
        // TcpBind should be denied even if port matches
        assert!(!socket_addr_allowed(
            &constraints,
            addr,
            SocketAddrUse::TcpBind
        ));
    }

    #[test]
    fn test_socket_addr_allowed_rejects_hostname_bound_policy() {
        let constraints = NetworkConstraints {
            host_allow: vec!["api.example.com".into()],
            port_allow: vec![443],
            ip_allow: vec![],
            cidr_deny: vec![],
            deny_localhost: false,
            deny_private_ranges: false,
            deny_tailnet_ranges: false,
            require_sni: false,
            spki_pins: vec![],
            deny_ip_literals: false,
            require_host_canonicalization: false,
            dns_max_ips: 16,
            max_redirects: 5,
            connect_timeout_ms: 10_000,
            total_timeout_ms: 60_000,
            max_response_bytes: 10_485_760,
        };
        let addr: SocketAddr = "93.184.216.34:443".parse().unwrap();

        assert!(!socket_addr_allowed(
            &constraints,
            addr,
            SocketAddrUse::TcpConnect
        ));
    }

    #[test]
    fn test_raw_socket_dns_lookup_allowed_only_for_wildcard_policy() {
        let wildcard = NetworkConstraints {
            host_allow: vec!["*".into()],
            port_allow: vec![443],
            ip_allow: vec![],
            cidr_deny: vec![],
            deny_localhost: false,
            deny_private_ranges: false,
            deny_tailnet_ranges: false,
            require_sni: false,
            spki_pins: vec![],
            deny_ip_literals: false,
            require_host_canonicalization: false,
            dns_max_ips: 16,
            max_redirects: 5,
            connect_timeout_ms: 10_000,
            total_timeout_ms: 60_000,
            max_response_bytes: 10_485_760,
        };
        assert!(raw_socket_dns_lookup_allowed(&wildcard));

        let exact_ip = NetworkConstraints {
            host_allow: vec!["1.2.3.4".into()],
            port_allow: vec![443],
            ip_allow: vec![],
            cidr_deny: vec![],
            deny_localhost: false,
            deny_private_ranges: false,
            deny_tailnet_ranges: false,
            require_sni: false,
            spki_pins: vec![],
            deny_ip_literals: false,
            require_host_canonicalization: false,
            dns_max_ips: 16,
            max_redirects: 5,
            connect_timeout_ms: 10_000,
            total_timeout_ms: 60_000,
            max_response_bytes: 10_485_760,
        };
        assert!(!raw_socket_dns_lookup_allowed(&exact_ip));

        let hostname_bound = NetworkConstraints {
            host_allow: vec!["api.example.com".into()],
            port_allow: vec![443],
            ip_allow: vec![],
            cidr_deny: vec![],
            deny_localhost: false,
            deny_private_ranges: false,
            deny_tailnet_ranges: false,
            require_sni: false,
            spki_pins: vec![],
            deny_ip_literals: false,
            require_host_canonicalization: false,
            dns_max_ips: 16,
            max_redirects: 5,
            connect_timeout_ms: 10_000,
            total_timeout_ms: 60_000,
            max_response_bytes: 10_485_760,
        };
        assert!(!raw_socket_dns_lookup_allowed(&hostname_bound));
    }

    #[test]
    fn test_socket_addr_allowed_exact_ip_literal_policy() {
        let constraints = NetworkConstraints {
            host_allow: vec!["1.2.3.4".into()],
            port_allow: vec![443],
            ip_allow: vec![],
            cidr_deny: vec![],
            deny_localhost: false,
            deny_private_ranges: false,
            deny_tailnet_ranges: false,
            require_sni: false,
            spki_pins: vec![],
            deny_ip_literals: false,
            require_host_canonicalization: false,
            dns_max_ips: 16,
            max_redirects: 5,
            connect_timeout_ms: 10_000,
            total_timeout_ms: 60_000,
            max_response_bytes: 10_485_760,
        };
        let allowed_addr: SocketAddr = "1.2.3.4:443".parse().unwrap();
        let denied_addr: SocketAddr = "5.6.7.8:443".parse().unwrap();

        assert!(socket_addr_allowed(
            &constraints,
            allowed_addr,
            SocketAddrUse::TcpConnect
        ));
        assert!(!socket_addr_allowed(
            &constraints,
            denied_addr,
            SocketAddrUse::TcpConnect
        ));
    }

    #[test]
    fn test_validated_component_fields() {
        let config = WasiConfig::default();
        let runner = WasiConnectorRunner::new(config).unwrap();
        let validated = runner
            .load_and_validate(minimal_command_component())
            .unwrap();
        assert!(!validated.has_manifest);
        // Component is usable
        let _engine = runner.runtime().engine();
    }

    // ── New batch: WasiError display completeness ──

    #[test]
    fn test_wasi_error_display_timeout() {
        let e = WasiError::Timeout;
        assert!(e.to_string().contains("timeout"));
    }

    #[test]
    fn test_wasi_error_display_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe broken");
        let e = WasiError::from(io_err);
        assert!(e.to_string().contains("pipe broken"));
    }

    #[test]
    fn test_wasi_error_display_sandbox() {
        let sandbox_err = SandboxError::InvalidConfig("bad config".into());
        let e = WasiError::from(sandbox_err);
        assert!(e.to_string().contains("bad config"));
    }

    // ── New batch: DeterministicRng ──

    #[test]
    fn test_deterministic_rng_large_seed() {
        let mut rng = DeterministicRng::new(u64::MAX);
        let val = rng.next_u64();
        assert_ne!(val, 0);
    }

    #[test]
    fn test_deterministic_rng_sequential_values_differ() {
        let mut rng = DeterministicRng::new(42);
        let v1 = rng.next_u64();
        let v2 = rng.next_u64();
        let v3 = rng.next_u64();
        assert_ne!(v1, v2);
        assert_ne!(v2, v3);
    }

    #[test]
    fn test_deterministic_seed_bytes_deterministic() {
        let bytes1 = deterministic_seed_bytes(42);
        let bytes2 = deterministic_seed_bytes(42);
        assert_eq!(bytes1, bytes2);
        assert_eq!(bytes1.len(), 32);
    }

    #[test]
    fn test_deterministic_seed_bytes_different_seeds() {
        let bytes1 = deterministic_seed_bytes(1);
        let bytes2 = deterministic_seed_bytes(2);
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn test_deterministic_seed_bytes_zero_seed() {
        let bytes = deterministic_seed_bytes(0);
        assert_eq!(bytes.len(), 32);
        // Zero seed uses fallback non-zero state, so bytes should not be all zeros
        assert!(bytes.iter().any(|&b| b != 0));
    }

    // ── New batch: WasiConfig from_policy ──

    #[test]
    fn test_wasi_config_from_policy_zero_cpu() {
        use crate::sandbox::{CompiledPolicy, PlatformFlags};
        use fcp_manifest::SandboxProfile;
        let policy = CompiledPolicy {
            profile: SandboxProfile::Strict,
            memory_limit_bytes: 128 * 1024 * 1024,
            cpu_percent: 0,
            wall_clock_timeout: Duration::from_secs(10),
            readonly_paths: vec![],
            writable_paths: vec![],
            deny_exec: true,
            deny_ptrace: true,
            block_direct_network: true,
            state_dir: None,
            platform_flags: PlatformFlags::default(),
        };
        let config = WasiConfig::from_policy(&policy).unwrap();
        assert_eq!(config.max_fuel, 1); // cpu_percent=0 -> minimal fuel
    }

    #[test]
    fn test_wasi_config_from_policy_max_cpu() {
        use crate::sandbox::{CompiledPolicy, PlatformFlags};
        use fcp_manifest::SandboxProfile;
        let policy = CompiledPolicy {
            profile: SandboxProfile::Permissive,
            memory_limit_bytes: 1024 * 1024 * 1024,
            cpu_percent: 100,
            wall_clock_timeout: Duration::from_secs(120),
            readonly_paths: vec![],
            writable_paths: vec![],
            deny_exec: false,
            deny_ptrace: false,
            block_direct_network: false,
            state_dir: None,
            platform_flags: PlatformFlags::default(),
        };
        let config = WasiConfig::from_policy(&policy).unwrap();
        assert_eq!(config.max_fuel, 1_000_000_000_000);
        assert!(!config.block_direct_network);
    }

    // ── New batch: WasiRuntime linker/engine accessors ──

    #[test]
    fn test_wasi_runtime_engine_accessor() {
        let config = WasiConfig::default();
        let runtime = WasiRuntime::new(config).unwrap();
        let _engine = runtime.engine();
        let _linker = runtime.linker();
    }

    // ── New batch: extract_custom_section edge cases ──

    #[test]
    fn test_extract_custom_section_empty_payload() {
        let section_name = b"empty";
        let name_len = section_name.len();
        // section content = name_len_byte + name + (empty payload)
        let content_len = 1 + name_len;

        let mut wasm = Vec::new();
        wasm.extend_from_slice(b"\0asm\x01\0\0\0");
        wasm.push(0); // custom section id
        wasm.push(content_len as u8);
        wasm.push(name_len as u8);
        wasm.extend_from_slice(section_name);
        // no payload

        let result = extract_custom_section(&wasm, "empty");
        assert_eq!(result, Some(vec![]));
    }

    #[test]
    fn test_extract_custom_section_7_bytes_too_short() {
        // Exactly 7 bytes, less than required 8 for WASM magic
        assert!(extract_custom_section(&[0, 1, 2, 3, 4, 5, 6], "x").is_none());
    }

    // ── New batch: LEB128 edge cases ──

    #[test]
    fn test_leb128_max_single_byte() {
        // 0x7F = 127, single byte, no continuation
        assert_eq!(read_leb128(&[0x7F]), Some((127, 1)));
    }

    #[test]
    fn test_leb128_two_byte_256() {
        // 256 = 0x80 0x02
        assert_eq!(read_leb128(&[0x80, 0x02]), Some((256, 2)));
    }

    #[test]
    fn test_leb128_trailing_bytes_ignored() {
        // Only reads until terminator; trailing bytes are not consumed
        let result = read_leb128(&[0x05, 0xFF, 0xFF]);
        assert_eq!(result, Some((5, 1)));
    }
}
