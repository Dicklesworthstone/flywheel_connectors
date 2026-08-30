//! FCP2 performance benchmark suite.
//!
//! This module implements the `fwc bench` command with subcommands for various
//! benchmark targets. All benchmarks emit machine-readable JSON output with
//! environment metadata for regression tracking.
//!
//! ## Canonical Targets (README-aligned)
//!
//! - Cold start (connector activate): p50 < 100ms / p99 < 500ms
//! - Local invoke latency (same node): p50 < 2ms / p99 < 10ms
//! - Tailnet invoke latency (LAN/direct): p50 < 20ms / p99 < 100ms
//! - Tailnet invoke latency (DERP): p50 < 150ms / p99 < 500ms
//! - Symbol reconstruction (1MB): p50 < 50ms / p99 < 250ms
//! - Secret reconstruction (k-of-n): p50 < 150ms / p99 < 750ms
//! - Memory overhead: < 10MB per connector (idle)
//! - CPU overhead: < 1% idle (event-driven)
//! - Binary size: < 20MB compressed

use anyhow::{anyhow, bail};
use chrono::{DateTime, Utc};
use clap::{Args, Subcommand};
use fcp_kernel::CapabilityId;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Instant;

// ─── Types ──────────────────────────────────────────────────────────────────

/// Complete benchmark report including environment metadata and all results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BenchmarkReport {
    /// Schema version for forward/backward compatibility.
    pub schema_version: String,

    /// Timestamp when the report was generated.
    pub generated_at: DateTime<Utc>,

    /// Environment information for reproducibility.
    pub environment: EnvironmentInfo,

    /// Individual benchmark results.
    pub results: Vec<BenchmarkResult>,
}

impl BenchmarkReport {
    /// Create a new benchmark report with the given environment and results.
    #[must_use]
    pub fn new(environment: EnvironmentInfo, results: Vec<BenchmarkResult>) -> Self {
        Self {
            schema_version: "1.0.0".to_string(),
            generated_at: Utc::now(),
            environment,
            results,
        }
    }
}

/// Environment information for reproducibility and regression tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct EnvironmentInfo {
    /// Operating system name (e.g., `linux`, `macos`, `windows`).
    pub os: String,

    /// Operating system version.
    pub os_version: String,

    /// CPU architecture (e.g., `x86_64`, `aarch64`).
    pub arch: String,

    /// Number of logical CPUs.
    pub cpu_count: usize,

    /// Total system memory in bytes (if available).
    pub memory_bytes: Option<u64>,

    /// Git commit hash (if in a git repository).
    pub git_commit: Option<String>,

    /// Git branch (if in a git repository).
    pub git_branch: Option<String>,

    /// Whether the working directory is clean (no uncommitted changes).
    pub git_dirty: Option<bool>,

    /// FCP CLI version.
    pub fcp_version: String,

    /// Rust compiler version used to build the CLI.
    pub rustc_version: Option<String>,

    /// Timestamp when the benchmark started.
    pub timestamp: DateTime<Utc>,
}

/// Result of a single benchmark.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BenchmarkResult {
    /// Unique benchmark name (e.g., "cbor-serialize", "connector-activate").
    pub name: String,

    /// Human-readable description of what was measured.
    pub description: String,

    /// Parameters used for this benchmark run.
    pub parameters: serde_json::Value,

    /// Number of samples taken.
    pub sample_count: u32,

    /// Number of warmup iterations performed.
    pub warmup_count: u32,

    /// Percentile statistics (if benchmark completed successfully).
    pub percentiles: Option<Percentiles>,

    /// Whether this benchmark passed its target thresholds.
    pub passed: Option<bool>,

    /// Target thresholds for pass/fail determination.
    pub targets: Option<Targets>,

    /// Additional notes (e.g., "not yet implemented").
    pub note: Option<String>,

    /// Any outliers detected during measurement.
    pub outliers_detected: u32,
}

impl BenchmarkResult {
    /// Create a new benchmark result with the given measurements.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        sample_count: u32,
        warmup_count: u32,
        percentiles: Percentiles,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            parameters: serde_json::Value::Object(serde_json::Map::new()),
            sample_count,
            warmup_count,
            percentiles: Some(percentiles),
            passed: None,
            targets: None,
            note: None,
            outliers_detected: 0,
        }
    }

    /// Create a placeholder result for unimplemented benchmarks.
    #[must_use]
    pub fn placeholder(name: impl Into<String>, note: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: "Not yet implemented".to_string(),
            parameters: serde_json::Value::Object(serde_json::Map::new()),
            sample_count: 0,
            warmup_count: 0,
            percentiles: None,
            passed: None,
            targets: None,
            note: Some(note.into()),
            outliers_detected: 0,
        }
    }

    /// Set parameters for this benchmark.
    #[must_use]
    pub fn with_parameters(mut self, parameters: serde_json::Value) -> Self {
        self.parameters = parameters;
        self
    }

    /// Set target thresholds and determine pass/fail.
    #[must_use]
    pub fn with_targets(mut self, targets: Targets) -> Self {
        if self.sample_count > 0
            && let Some(ref p) = self.percentiles
        {
            self.passed =
                Some(p.p50_ms <= targets.p50_target_ms && p.p99_ms <= targets.p99_target_ms);
        }
        self.targets = Some(targets);
        self
    }
}

/// Percentile statistics for benchmark measurements.
///
/// All fields are in milliseconds. The `_ms` suffix is intentional to indicate units
/// in the JSON output schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_field_names)]
pub(crate) struct Percentiles {
    /// 50th percentile (median) in milliseconds.
    pub p50_ms: f64,

    /// 90th percentile in milliseconds.
    pub p90_ms: f64,

    /// 95th percentile in milliseconds.
    pub p95_ms: f64,

    /// 99th percentile in milliseconds.
    pub p99_ms: f64,

    /// Minimum measurement in milliseconds.
    pub min_ms: f64,

    /// Maximum measurement in milliseconds.
    pub max_ms: f64,

    /// Mean (average) in milliseconds.
    pub mean_ms: f64,

    /// Standard deviation in milliseconds.
    pub stddev_ms: f64,
}

/// Target thresholds for pass/fail determination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Targets {
    /// Target p50 latency in milliseconds.
    pub p50_target_ms: f64,

    /// Target p99 latency in milliseconds.
    pub p99_target_ms: f64,
}

// ─── Runner (statistical analysis) ──────────────────────────────────────────

/// Run a benchmark function that returns a value (to prevent optimization).
///
/// The return value is passed to `std::hint::black_box` to prevent
/// the compiler from optimizing away the computation.
///
/// # Returns
/// A tuple of (`Percentiles`, outlier count).
#[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
fn run_benchmark_with_result<F, R>(warmup: u32, iterations: u32, mut f: F) -> (Percentiles, u32)
where
    F: FnMut() -> R,
{
    // Warmup iterations (not measured).
    for _ in 0..warmup {
        std::hint::black_box(f());
    }

    // Measured iterations.
    let mut durations_ns: Vec<u64> = Vec::with_capacity(iterations as usize);
    for _ in 0..iterations {
        let start = Instant::now();
        let result = f();
        let elapsed = start.elapsed();
        std::hint::black_box(result);
        // Note: as_nanos() returns u128, but benchmark durations should fit in u64
        // (max ~584 years in nanoseconds).
        durations_ns.push(elapsed.as_nanos() as u64);
    }

    // Sort for percentile calculation.
    durations_ns.sort_unstable();

    // Detect outliers using IQR method.
    let outlier_count = count_outliers(&durations_ns);

    // Calculate statistics.
    let percentiles = calculate_percentiles(&durations_ns);

    (percentiles, outlier_count)
}

#[allow(clippy::cast_possible_truncation)]
fn run_fallible_benchmark_with_result<F, R>(
    warmup: u32,
    iterations: u32,
    mut f: F,
) -> anyhow::Result<(Percentiles, u32)>
where
    F: FnMut() -> anyhow::Result<R>,
{
    for _ in 0..warmup {
        std::hint::black_box(f()?);
    }

    let mut durations_ns: Vec<u64> = Vec::with_capacity(iterations as usize);
    for _ in 0..iterations {
        let start = Instant::now();
        let result = f()?;
        let elapsed = start.elapsed();
        std::hint::black_box(result);
        durations_ns.push(elapsed.as_nanos() as u64);
    }

    durations_ns.sort_unstable();
    let outlier_count = count_outliers(&durations_ns);
    let percentiles = calculate_percentiles(&durations_ns);
    Ok((percentiles, outlier_count))
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]
fn calculate_percentiles(sorted_ns: &[u64]) -> Percentiles {
    let len = sorted_ns.len();
    if len == 0 {
        return Percentiles {
            p50_ms: 0.0,
            p90_ms: 0.0,
            p95_ms: 0.0,
            p99_ms: 0.0,
            min_ms: 0.0,
            max_ms: 0.0,
            mean_ms: 0.0,
            stddev_ms: 0.0,
        };
    }

    // Convert nanoseconds to milliseconds directly.
    let ns_to_ms = |ns: u64| ns as f64 / 1_000_000.0;

    let p50_idx = (len as f64 * 0.50) as usize;
    let p90_idx = (len as f64 * 0.90) as usize;
    let p95_idx = (len as f64 * 0.95) as usize;
    let p99_idx = (len as f64 * 0.99) as usize;

    let p50_ms = ns_to_ms(sorted_ns[p50_idx.min(len - 1)]);
    let p90_ms = ns_to_ms(sorted_ns[p90_idx.min(len - 1)]);
    let p95_ms = ns_to_ms(sorted_ns[p95_idx.min(len - 1)]);
    let p99_ms = ns_to_ms(sorted_ns[p99_idx.min(len - 1)]);
    let min_ms = ns_to_ms(sorted_ns[0]);
    let max_ms = ns_to_ms(sorted_ns[len - 1]);

    // Calculate mean.
    let sum: u64 = sorted_ns.iter().sum();
    let mean_nanoseconds = sum as f64 / len as f64;
    let mean_ms = mean_nanoseconds / 1_000_000.0;

    // Calculate standard deviation.
    let variance: f64 = sorted_ns
        .iter()
        .map(|&ns| {
            let diff = ns as f64 - mean_nanoseconds;
            diff * diff
        })
        .sum::<f64>()
        / len as f64;
    let stddev_nanoseconds = variance.sqrt();
    let stddev_ms = stddev_nanoseconds / 1_000_000.0;

    Percentiles {
        p50_ms,
        p90_ms,
        p95_ms,
        p99_ms,
        min_ms,
        max_ms,
        mean_ms,
        stddev_ms,
    }
}

#[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
fn count_outliers(sorted_ns: &[u64]) -> u32 {
    let len = sorted_ns.len();
    if len < 4 {
        return 0;
    }

    // Calculate IQR (Interquartile Range).
    let q1_idx = len / 4;
    let q3_idx = (3 * len) / 4;
    let q1 = sorted_ns[q1_idx] as f64;
    let q3 = sorted_ns[q3_idx] as f64;
    let iqr = q3 - q1;

    // Outlier bounds: Q1 - 1.5*IQR and Q3 + 1.5*IQR.
    let lower_bound = 1.5f64.mul_add(-iqr, q1);
    let upper_bound = 1.5f64.mul_add(iqr, q3);

    // Count values outside bounds.
    sorted_ns
        .iter()
        .filter(|&&ns| (ns as f64) < lower_bound || (ns as f64) > upper_bound)
        .count() as u32
}

// ─── Environment ────────────────────────────────────────────────────────────

/// Collect environment information for the benchmark report.
///
/// This function gathers:
/// - OS name and version
/// - CPU architecture and count
/// - Memory (if available via `/proc/meminfo` on Linux)
/// - Git commit, branch, and dirty status
/// - FCP CLI and rustc versions
fn collect_environment() -> EnvironmentInfo {
    let os = std::env::consts::OS.to_string();
    let arch = std::env::consts::ARCH.to_string();
    let cpu_count = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);

    let os_version = get_os_version();
    let memory_bytes = get_memory_bytes();
    let (git_commit, git_branch, git_dirty) = get_git_info();
    let rustc_version = get_rustc_version();

    EnvironmentInfo {
        os,
        os_version,
        arch,
        cpu_count,
        memory_bytes,
        git_commit,
        git_branch,
        git_dirty,
        fcp_version: env!("CARGO_PKG_VERSION").to_string(),
        rustc_version,
        timestamp: Utc::now(),
    }
}

fn get_os_version() -> String {
    #[cfg(target_os = "linux")]
    {
        // Try to read /etc/os-release for distribution info.
        if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
            for line in content.lines() {
                if let Some(version) = line.strip_prefix("PRETTY_NAME=") {
                    return version.trim_matches('"').to_string();
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = Command::new("sw_vers").arg("-productVersion").output() {
            if output.status.success() {
                return String::from_utf8_lossy(&output.stdout).trim().to_string();
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = Command::new("cmd").args(["/C", "ver"]).output() {
            if output.status.success() {
                return String::from_utf8_lossy(&output.stdout).trim().to_string();
            }
        }
    }

    "unknown".to_string()
}

#[allow(clippy::missing_const_for_fn)]
fn get_memory_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/proc/meminfo") {
            for line in content.lines() {
                if let Some(value) = line.strip_prefix("MemTotal:") {
                    let parts: Vec<&str> = value.split_whitespace().collect();
                    if let Some(kb_str) = parts.first() {
                        if let Ok(kb) = kb_str.parse::<u64>() {
                            return Some(kb * 1024); // Convert KB to bytes.
                        }
                    }
                }
            }
        }
        None
    }

    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

fn get_git_info() -> (Option<String>, Option<String>, Option<bool>) {
    let commit = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());

    let branch = Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());

    let dirty = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| !o.stdout.is_empty());

    (commit, branch, dirty)
}

fn get_rustc_version() -> Option<String> {
    Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

// ─── CBOR benchmarks ────────────────────────────────────────────────────────

/// Run CBOR benchmarks based on the specified target.
fn run_cbor_benchmarks(target: CborTarget, iterations: u32, warmup: u32) -> Vec<BenchmarkResult> {
    let mut results = Vec::new();

    if target == CborTarget::SchemaHash || target == CborTarget::All {
        results.push(bench_schema_hash(iterations, warmup));
    }

    if target == CborTarget::Serialize || target == CborTarget::All {
        results.push(bench_serialize_small(iterations, warmup));
        results.push(bench_serialize_medium(iterations, warmup));
    }

    if target == CborTarget::Deserialize || target == CborTarget::All {
        results.push(bench_deserialize_small(iterations, warmup));
        results.push(bench_deserialize_medium(iterations, warmup));
    }

    results
}

/// Small test struct for serialization benchmarks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct SmallObject {
    id: u64,
    name: String,
    active: bool,
}

/// Medium test struct for serialization benchmarks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct MediumObject {
    id: u64,
    name: String,
    description: String,
    tags: Vec<String>,
    metadata: std::collections::HashMap<String, String>,
    created_at: i64,
    updated_at: i64,
    version: u32,
    active: bool,
}

fn make_test_schema() -> fcp_cbor::SchemaId {
    fcp_cbor::SchemaId::new("fcp.bench", "TestObject", semver::Version::new(1, 0, 0))
}

fn make_small_object() -> SmallObject {
    SmallObject {
        id: 12345,
        name: "benchmark-test".to_string(),
        active: true,
    }
}

fn make_medium_object() -> MediumObject {
    let mut metadata = std::collections::HashMap::new();
    metadata.insert("key1".to_string(), "value1".to_string());
    metadata.insert("key2".to_string(), "value2".to_string());
    metadata.insert("key3".to_string(), "value3".to_string());

    MediumObject {
        id: 12345,
        name: "benchmark-test-medium".to_string(),
        description: "This is a medium-sized object for benchmarking canonical CBOR serialization performance. It includes multiple fields of varying types.".to_string(),
        tags: vec![
            "benchmark".to_string(),
            "cbor".to_string(),
            "serialization".to_string(),
            "performance".to_string(),
        ],
        metadata,
        created_at: 1_705_000_000,
        updated_at: 1_705_100_000,
        version: 42,
        active: true,
    }
}

fn bench_schema_hash(iterations: u32, warmup: u32) -> BenchmarkResult {
    let schema = make_test_schema();

    let (percentiles, outliers) = run_benchmark_with_result(warmup, iterations, || schema.hash());

    let mut result = BenchmarkResult::new(
        "cbor-schema-hash",
        "Compute BLAKE3 schema hash from SchemaId",
        iterations,
        warmup,
        percentiles,
    )
    .with_parameters(serde_json::json!({
        "schema": format!("{}:{}@{}", schema.namespace, schema.name, schema.version),
    }))
    .with_targets(Targets {
        p50_target_ms: 0.01, // 10 microseconds target.
        p99_target_ms: 0.1,  // 100 microseconds target.
    });

    result.outliers_detected = outliers;
    result
}

fn bench_serialize_small(iterations: u32, warmup: u32) -> BenchmarkResult {
    use fcp_cbor::CanonicalSerializer;

    let schema = make_test_schema();
    let obj = make_small_object();

    let (percentiles, outliers) = run_benchmark_with_result(warmup, iterations, || {
        CanonicalSerializer::serialize(&obj, &schema).expect("serialization should not fail")
    });

    let mut result = BenchmarkResult::new(
        "cbor-serialize-small",
        "Serialize small object to canonical CBOR with schema prefix",
        iterations,
        warmup,
        percentiles,
    )
    .with_parameters(serde_json::json!({
        "object_type": "SmallObject",
        "fields": 3,
    }))
    .with_targets(Targets {
        p50_target_ms: 0.05, // 50 microseconds target.
        p99_target_ms: 0.5,  // 500 microseconds target.
    });

    result.outliers_detected = outliers;
    result
}

fn bench_serialize_medium(iterations: u32, warmup: u32) -> BenchmarkResult {
    use fcp_cbor::CanonicalSerializer;

    let schema = make_test_schema();
    let obj = make_medium_object();

    let (percentiles, outliers) = run_benchmark_with_result(warmup, iterations, || {
        CanonicalSerializer::serialize(&obj, &schema).expect("serialization should not fail")
    });

    let mut result = BenchmarkResult::new(
        "cbor-serialize-medium",
        "Serialize medium object to canonical CBOR with schema prefix",
        iterations,
        warmup,
        percentiles,
    )
    .with_parameters(serde_json::json!({
        "object_type": "MediumObject",
        "fields": 9,
    }))
    .with_targets(Targets {
        p50_target_ms: 0.1, // 100 microseconds target.
        p99_target_ms: 1.0, // 1 millisecond target.
    });

    result.outliers_detected = outliers;
    result
}

fn bench_deserialize_small(iterations: u32, warmup: u32) -> BenchmarkResult {
    use fcp_cbor::CanonicalSerializer;

    let schema = make_test_schema();
    let obj = make_small_object();
    let bytes =
        CanonicalSerializer::serialize(&obj, &schema).expect("serialization should not fail");

    let (percentiles, outliers) = run_benchmark_with_result(warmup, iterations, || {
        CanonicalSerializer::deserialize::<SmallObject>(&bytes, &schema)
            .expect("deserialization should not fail")
    });

    let mut result = BenchmarkResult::new(
        "cbor-deserialize-small",
        "Deserialize small object from canonical CBOR with schema verification",
        iterations,
        warmup,
        percentiles,
    )
    .with_parameters(serde_json::json!({
        "object_type": "SmallObject",
        "fields": 3,
        "bytes": bytes.len(),
    }))
    .with_targets(Targets {
        p50_target_ms: 0.1, // 100 microseconds target.
        p99_target_ms: 1.0, // 1 millisecond target.
    });

    result.outliers_detected = outliers;
    result
}

fn bench_deserialize_medium(iterations: u32, warmup: u32) -> BenchmarkResult {
    use fcp_cbor::CanonicalSerializer;

    let schema = make_test_schema();
    let obj = make_medium_object();
    let bytes =
        CanonicalSerializer::serialize(&obj, &schema).expect("serialization should not fail");

    let (percentiles, outliers) = run_benchmark_with_result(warmup, iterations, || {
        CanonicalSerializer::deserialize::<MediumObject>(&bytes, &schema)
            .expect("deserialization should not fail")
    });

    let mut result = BenchmarkResult::new(
        "cbor-deserialize-medium",
        "Deserialize medium object from canonical CBOR with schema verification",
        iterations,
        warmup,
        percentiles,
    )
    .with_parameters(serde_json::json!({
        "object_type": "MediumObject",
        "fields": 9,
        "bytes": bytes.len(),
    }))
    .with_targets(Targets {
        p50_target_ms: 0.2, // 200 microseconds target.
        p99_target_ms: 2.0, // 2 milliseconds target.
    });

    result.outliers_detected = outliers;
    result
}

// ─── CLI Args & Dispatch ────────────────────────────────────────────────────

/// Arguments for the `fwc bench` command.
#[derive(Args, Debug)]
pub(crate) struct BenchArgs {
    #[command(subcommand)]
    command: BenchCommand,

    /// Output format: json (machine-readable) or human (pretty-printed).
    #[arg(long, default_value = "json")]
    format: OutputFormat,

    /// Number of iterations for each benchmark.
    #[arg(long, default_value = "100")]
    iterations: u32,

    /// Number of warmup iterations before measurement.
    #[arg(long, default_value = "10")]
    warmup: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum OutputFormat {
    Json,
    Human,
}

#[derive(Debug, Subcommand)]
enum BenchCommand {
    /// Benchmark connector cold start time.
    ///
    /// Target: p50 < 100ms / p99 < 500ms (stretch goal: p50 < 50ms)
    ConnectorActivate {
        /// Path to connector binary.
        #[arg(long)]
        connector: Option<String>,
    },

    /// Benchmark local invoke latency (same node).
    ///
    /// Target: p50 < 2ms / p99 < 10ms
    InvokeLocal,

    /// Benchmark mesh invoke latency.
    ///
    /// Target (direct/LAN): p50 < 20ms / p99 < 100ms
    /// Target (DERP): p50 < 150ms / p99 < 500ms
    InvokeMesh {
        /// Network path: direct (LAN) or derp (relay).
        #[arg(long)]
        path: MeshPath,
    },

    /// Benchmark `RaptorQ` symbol encoding/decoding.
    ///
    /// Target (1MB): p50 < 50ms / p99 < 250ms
    Raptorq {
        /// Payload size (e.g., "1mb", "100kb").
        #[arg(long, default_value = "1mb")]
        size: String,
    },

    /// Benchmark `RaptorQ` presets (LAN/DERP profiles).
    ///
    /// Emits separate results per profile.
    RaptorqPresets {
        /// Payload size (e.g., "1mb", "100kb").
        #[arg(long, default_value = "1mb")]
        size: String,
    },

    /// Benchmark secret reconstruction (Shamir k-of-n).
    ///
    /// Target: p50 < 150ms / p99 < 750ms
    Secrets {
        /// Threshold (k) for reconstruction.
        #[arg(long, default_value = "3")]
        k: u32,

        /// Total shares (n).
        #[arg(long, default_value = "5")]
        n: u32,
    },

    /// Benchmark canonical CBOR serialization.
    ///
    /// Microbenches for hot primitives in fcp-cbor.
    Cbor {
        /// Specific sub-benchmark (schema-hash, serialize, deserialize, all).
        #[arg(long, default_value = "all")]
        target: CborTarget,
    },

    /// Microbenchmarks for hot primitives (`ObjectId`, capability verification, session MAC).
    Primitives {
        /// Specific sub-benchmark (object-id, capability-verify, session-mac, fcps-frame, all).
        #[arg(long, default_value = "all")]
        target: PrimitiveTarget,
    },

    /// Benchmark CUAL search performance (index build + query latency).
    ///
    /// Target: < 1ms search latency for 500 operations
    Search {
        /// Number of operations to index.
        #[arg(long, default_value = "500")]
        operations: u32,
    },

    /// Benchmark CUAL batch/map throughput.
    ///
    /// Target: < 5% overhead vs sequential for non-throttled batches
    Batch {
        /// Number of items to process.
        #[arg(long, default_value = "100")]
        items: u32,
    },

    /// Benchmark MCP server tool listing and routing latency.
    ///
    /// Target: < 5ms tools/list for 100 connectors
    Mcp {
        /// Number of connectors to register.
        #[arg(long, default_value = "100")]
        connectors: u32,
    },

    /// Benchmark pipeline setup and scheduling overhead.
    ///
    /// Target: < 10ms pipeline setup for 10 steps
    Pipeline {
        /// Number of pipeline steps.
        #[arg(long, default_value = "10")]
        steps: u32,
    },

    /// Run all benchmarks and produce a complete report.
    All,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum MeshPath {
    Direct,
    Derp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum CborTarget {
    SchemaHash,
    Serialize,
    Deserialize,
    All,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum PrimitiveTarget {
    ObjectId,
    CapabilityVerify,
    SessionMac,
    FcpsFrame,
    All,
}

/// Run the benchmark command.
#[allow(clippy::too_many_lines)]
pub(crate) fn run(args: &BenchArgs) -> anyhow::Result<()> {
    if args.iterations == 0 {
        bail!("--iterations must be greater than 0");
    }

    let env = collect_environment();

    let results = match &args.command {
        BenchCommand::ConnectorActivate { connector } => {
            vec![bench_connector_activate(
                connector.as_deref(),
                args.iterations,
                args.warmup,
            )?]
        }
        BenchCommand::InvokeLocal => {
            vec![bench_invoke_local(args.iterations, args.warmup)]
        }
        BenchCommand::InvokeMesh { path } => {
            vec![bench_invoke_mesh(path, args.iterations, args.warmup)]
        }
        BenchCommand::Raptorq { size } => {
            let size_label = normalize_size_label(&size);
            let size_bytes = parse_size_bytes(&size_label)?;
            vec![bench_raptorq(
                &size_label,
                size_bytes,
                args.iterations,
                args.warmup,
            )?]
        }
        BenchCommand::RaptorqPresets { size } => {
            let size_label = normalize_size_label(&size);
            let size_bytes = parse_size_bytes(&size_label)?;
            bench_raptorq_presets(&size_label, size_bytes, args.iterations, args.warmup)?
        }
        BenchCommand::Secrets { k, n } => {
            vec![bench_secrets(*k, *n, args.iterations, args.warmup)]
        }
        BenchCommand::Cbor { target } => run_cbor_benchmarks(*target, args.iterations, args.warmup),
        BenchCommand::Primitives { target } => {
            run_primitives(*target, args.iterations, args.warmup)
        }
        BenchCommand::Search { operations } => {
            vec![
                bench_search_index(*operations, args.iterations, args.warmup),
                bench_search_query(*operations, args.iterations, args.warmup),
            ]
        }
        BenchCommand::Batch { items } => {
            vec![bench_batch_throughput(*items, args.iterations, args.warmup)]
        }
        BenchCommand::Mcp { connectors } => {
            vec![
                bench_mcp_tool_list(*connectors, args.iterations, args.warmup),
                bench_mcp_tool_route(*connectors, args.iterations, args.warmup),
            ]
        }
        BenchCommand::Pipeline { steps } => {
            vec![bench_pipeline_setup(*steps, args.iterations, args.warmup)]
        }
        BenchCommand::All => {
            let mut all_results = Vec::new();

            // Run CBOR benchmarks (the only ones currently implemented).
            all_results.extend(run_cbor_benchmarks(
                CborTarget::All,
                args.iterations,
                args.warmup,
            ));

            // Run hot primitive microbenches.
            all_results.extend(run_primitives(
                PrimitiveTarget::All,
                args.iterations,
                args.warmup,
            ));

            // Run default RaptorQ benchmark (1MB payload).
            let raptorq_size = "1mb";
            let raptorq_bytes = parse_size_bytes(raptorq_size)?;
            all_results.push(bench_raptorq(
                raptorq_size,
                raptorq_bytes,
                args.iterations,
                args.warmup,
            )?);

            // Mixed local benchmarks: connector activation uses the explicit
            // default fixture unless the operator supplies a binary path.
            all_results.push(bench_connector_activate(
                None,
                args.iterations,
                args.warmup,
            )?);
            all_results.push(bench_invoke_local(args.iterations, args.warmup));
            all_results.push(bench_invoke_mesh(
                &MeshPath::Direct,
                args.iterations,
                args.warmup,
            ));
            all_results.push(bench_invoke_mesh(
                &MeshPath::Derp,
                args.iterations,
                args.warmup,
            ));
            all_results.push(bench_secrets(3, 5, args.iterations, args.warmup));

            // CUAL benchmarks (search, batch, MCP, pipeline).
            all_results.push(bench_search_index(500, args.iterations, args.warmup));
            all_results.push(bench_search_query(500, args.iterations, args.warmup));
            all_results.push(bench_batch_throughput(100, args.iterations, args.warmup));
            all_results.push(bench_mcp_tool_list(100, args.iterations, args.warmup));
            all_results.push(bench_mcp_tool_route(100, args.iterations, args.warmup));
            all_results.push(bench_pipeline_setup(10, args.iterations, args.warmup));

            all_results
        }
    };

    for result in &results {
        tracing::info!(
            bench = %result.name,
            params = %result.parameters,
            samples = result.sample_count,
            warmup = result.warmup_count,
            outliers = result.outliers_detected,
            note = ?result.note,
            "benchmark completed"
        );
    }

    let report = BenchmarkReport::new(env, results);

    match args.format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        OutputFormat::Human => {
            print_human_report(&report);
        }
    }

    Ok(())
}

fn print_human_report(report: &BenchmarkReport) {
    println!("FCP2 Benchmark Report");
    println!("=====================");
    println!();
    println!("Environment:");
    println!(
        "  OS:      {} {}",
        report.environment.os, report.environment.os_version
    );
    println!("  Arch:    {}", report.environment.arch);
    println!("  CPUs:    {}", report.environment.cpu_count);
    if let Some(ref commit) = report.environment.git_commit {
        println!("  Commit:  {commit}");
    }
    println!("  Time:    {}", report.environment.timestamp);
    println!();

    for result in &report.results {
        println!("{}:", result.name);
        if let Some(note) = &result.note {
            println!("  Note: {note}");
        }
        if let Some(ref p) = result.percentiles {
            println!("  p50:  {:>10.3} ms", p.p50_ms);
            println!("  p90:  {:>10.3} ms", p.p90_ms);
            println!("  p95:  {:>10.3} ms", p.p95_ms);
            println!("  p99:  {:>10.3} ms", p.p99_ms);
            println!("  min:  {:>10.3} ms", p.min_ms);
            println!("  max:  {:>10.3} ms", p.max_ms);
        }
        println!("  Samples: {}", result.sample_count);
        println!();
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn normalize_size_label(size: &str) -> String {
    size.trim().to_ascii_lowercase()
}

fn parse_size_bytes(size: &str) -> anyhow::Result<usize> {
    let size = size.trim().to_ascii_lowercase();
    if size.is_empty() {
        bail!("size must not be empty");
    }

    let (number, multiplier) = match size.as_str() {
        s if s.ends_with("kb") => (s.trim_end_matches("kb"), 1024_u64),
        s if s.ends_with("mb") => (s.trim_end_matches("mb"), 1024_u64 * 1024),
        s if s.ends_with("gb") => (s.trim_end_matches("gb"), 1024_u64 * 1024 * 1024),
        s if s.ends_with('b') => (s.trim_end_matches('b'), 1_u64),
        _ => (size.as_str(), 1_u64),
    };

    let number = number.trim().replace('_', "");
    if number.is_empty() {
        bail!("size value missing in '{size}'");
    }

    let value: u64 = number
        .parse()
        .map_err(|_| anyhow!("invalid size value '{number}'"))?;
    let bytes = value
        .checked_mul(multiplier)
        .ok_or_else(|| anyhow!("size overflow for '{size}'"))?;

    if bytes == 0 {
        bail!("size must be greater than zero");
    }

    usize::try_from(bytes).map_err(|_| anyhow!("size too large for platform"))
}

// ─── RaptorQ benchmarks ─────────────────────────────────────────────────────

fn bench_raptorq(
    size_label: &str,
    size_bytes: usize,
    iterations: u32,
    warmup: u32,
) -> anyhow::Result<BenchmarkResult> {
    use fcp_raptorq::RaptorQConfig;

    let config = RaptorQConfig::default();
    bench_raptorq_with_config(
        format!("raptorq-{size_label}"),
        size_label,
        size_bytes,
        iterations,
        warmup,
        &config,
        None,
    )
}

fn bench_raptorq_presets(
    size_label: &str,
    size_bytes: usize,
    iterations: u32,
    warmup: u32,
) -> anyhow::Result<Vec<BenchmarkResult>> {
    use fcp_raptorq::{RaptorQConfig, RaptorQPathProfile, RaptorQPreset};

    let mut results = Vec::new();
    let presets = [
        (RaptorQPathProfile::Lan, "lan"),
        (RaptorQPathProfile::Derp, "derp"),
    ];

    for (profile, label) in presets {
        let preset = RaptorQPreset::for_profile(profile);
        let config = RaptorQConfig::from_preset(preset)
            .ok_or_else(|| anyhow!("invalid RaptorQ preset for profile {label}"))?;
        results.push(bench_raptorq_with_config(
            format!("raptorq-{label}-{size_label}"),
            size_label,
            size_bytes,
            iterations,
            warmup,
            &config,
            Some(preset),
        )?);
    }

    Ok(results)
}

fn bench_raptorq_with_config(
    name: String,
    size_label: &str,
    size_bytes: usize,
    iterations: u32,
    warmup: u32,
    config: &fcp_raptorq::RaptorQConfig,
    preset: Option<fcp_raptorq::RaptorQPreset>,
) -> anyhow::Result<BenchmarkResult> {
    use fcp_raptorq::{RaptorQDecoder, RaptorQEncoder};

    if usize::try_from(config.max_object_size).map_or(true, |max| size_bytes > max) {
        bail!(
            "size {} exceeds RaptorQ max_object_size {}",
            size_bytes,
            config.max_object_size
        );
    }

    let payload = vec![0xAB_u8; size_bytes];
    let encoder = RaptorQEncoder::new(&payload, config)
        .map_err(|err| anyhow!("raptorq encode init failed: {err}"))?;

    let symbol_size = encoder.symbol_size();
    let source_symbols = encoder.source_symbols();
    let repair_symbols = encoder.repair_symbols();
    let total_symbols = encoder.total_symbols();

    let (percentiles, outliers) = run_benchmark_with_result(warmup, iterations, || {
        let encoder = RaptorQEncoder::new(&payload, config).expect("encoder init");
        let symbols = encoder.encode_all();
        let mut decoder = RaptorQDecoder::new(encoder.transmission_info(), config);

        let mut decoded_payload = None;
        for (esi, data) in symbols {
            if let Some(payload) = decoder
                .add_symbol(esi, data)
                .expect("raptorq decode should succeed")
            {
                decoded_payload = Some(payload);
                break;
            }
        }

        decoded_payload
            .expect("raptorq decode did not complete")
            .len()
    });

    let mut parameters = serde_json::json!({
        "size": size_label,
        "size_bytes": size_bytes,
        "symbol_size": symbol_size,
        "source_symbols": source_symbols,
        "repair_symbols": repair_symbols,
        "total_symbols": total_symbols,
        "decode_timeout_ms": config.decode_timeout.as_millis(),
        "max_object_size": config.max_object_size,
    });

    if let Some(preset) = preset {
        let profile = match preset.profile {
            fcp_raptorq::RaptorQPathProfile::Lan => "lan",
            fcp_raptorq::RaptorQPathProfile::Derp => "derp",
        };
        if let Some(map) = parameters.as_object_mut() {
            map.insert(
                "profile".to_string(),
                serde_json::Value::String(profile.to_string()),
            );
            map.insert(
                "max_datagram_bytes".to_string(),
                serde_json::Value::from(preset.max_datagram_bytes),
            );
            map.insert(
                "symbols_per_frame".to_string(),
                serde_json::Value::from(preset.symbols_per_frame),
            );
            map.insert(
                "preferred_symbol_size".to_string(),
                serde_json::Value::from(preset.preferred_symbol_size),
            );
            map.insert(
                "repair_ratio_bps".to_string(),
                serde_json::Value::from(preset.repair_ratio_bps),
            );
        }
    }

    let mut result = BenchmarkResult::new(
        name,
        "RaptorQ encode + decode wall time",
        iterations,
        warmup,
        percentiles,
    )
    .with_parameters(parameters);

    if size_bytes == 1024 * 1024 {
        result = result.with_targets(Targets {
            p50_target_ms: 50.0,
            p99_target_ms: 250.0,
        });
    }

    result.outliers_detected = outliers;
    Ok(result)
}

// ─── Primitive benchmarks ───────────────────────────────────────────────────

fn run_primitives(target: PrimitiveTarget, iterations: u32, warmup: u32) -> Vec<BenchmarkResult> {
    let mut results = Vec::new();

    if target == PrimitiveTarget::ObjectId || target == PrimitiveTarget::All {
        results.push(bench_object_id(iterations, warmup));
    }

    if target == PrimitiveTarget::CapabilityVerify || target == PrimitiveTarget::All {
        results.push(bench_capability_verify(iterations, warmup));
    }

    if target == PrimitiveTarget::SessionMac || target == PrimitiveTarget::All {
        results.push(bench_session_mac(iterations, warmup));
    }

    if target == PrimitiveTarget::FcpsFrame || target == PrimitiveTarget::All {
        results.push(bench_fcps_frame_parse_mac(iterations, warmup));
    }

    results
}

fn bench_object_id(iterations: u32, warmup: u32) -> BenchmarkResult {
    use fcp_cbor::SchemaId;
    use fcp_kernel::{ObjectId, ZoneId};
    use fcp_prelude::ObjectIdKey;
    use semver::Version;

    let zone = ZoneId::work();
    let schema = SchemaId::new("fcp.bench", "ObjectIdPayload", Version::new(1, 0, 0));
    let key = ObjectIdKey::from_bytes([0x11_u8; 32]);
    let payload = vec![0xAB_u8; 1024];

    let (percentiles, outliers) = run_benchmark_with_result(warmup, iterations, || {
        ObjectId::new(&payload, &zone, &schema, &key)
    });

    let mut result = BenchmarkResult::new(
        "object-id-derive",
        "Derive ObjectId from payload, zone, schema, and ObjectIdKey",
        iterations,
        warmup,
        percentiles,
    )
    .with_parameters(serde_json::json!({
        "payload_bytes": payload.len(),
        "zone": zone.as_str(),
        "schema": format!("{}:{}@{}", schema.namespace, schema.name, schema.version),
    }))
    .with_targets(Targets {
        p50_target_ms: 0.02,
        p99_target_ms: 0.2,
    });

    result.outliers_detected = outliers;
    result
}

fn bench_capability_verify(iterations: u32, warmup: u32) -> BenchmarkResult {
    use fcp_cbor::to_canonical_cbor;
    use fcp_crypto::{CapabilityTokenBuilder as CapabilityBuilder, Ed25519SigningKey};
    use fcp_kernel::{InstanceId, OperationId, ZoneId};
    use fcp_policy::{CapabilityToken as CapabilityArtifact, CapabilityVerifier};
    use fcp_prelude::CapabilityConstraints;

    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let pub_bytes = verifying_key.to_bytes();

    let now = chrono::Utc::now();
    let expires = now + chrono::Duration::hours(1);
    let zone = ZoneId::work();
    let ops = ["op.test"];

    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let constraints_cbor = to_canonical_cbor(&constraints).expect("constraints should serialize");

    let instance = InstanceId::new();
    let cose_capability = CapabilityBuilder::new()
        .capability_id("cap.test")
        .zone_id(zone.as_str())
        .principal("principal:test")
        .operations(&ops)
        .issuer("node:test")
        .target_instance(instance.as_str())
        .validity(now, expires)
        .try_constraints_cbor(&constraints_cbor)
        .expect("constraints should parse")
        .sign(&signing_key)
        .expect("capability token should sign");

    let capability = CapabilityArtifact::from_raw(cose_capability);

    let verifier = CapabilityVerifier::new(pub_bytes, zone.clone(), instance);
    let op = OperationId::new("op.test").expect("operation id must be canonical");
    let cap = CapabilityId::new("cap.test").expect("capability id must be canonical");

    let (percentiles, outliers) = run_benchmark_with_result(warmup, iterations, || {
        verifier
            .verify_bound(capability.clone(), &cap, &op, &[])
            .expect("capability verification should succeed");
    });

    let mut result = BenchmarkResult::new(
        "capability-verify",
        "Verify capability token signature, expiry, zone binding, and grants",
        iterations,
        warmup,
        percentiles,
    )
    .with_parameters(serde_json::json!({
        "ops": ops.len(),
        "zone": zone.as_str(),
        "instance_bound": false,
    }))
    .with_targets(Targets {
        p50_target_ms: 0.2,
        p99_target_ms: 1.5,
    });

    result.outliers_detected = outliers;
    result
}

fn bench_session_mac(iterations: u32, warmup: u32) -> BenchmarkResult {
    use fcp_crypto::{Blake3Mac, MacKey};

    let key = MacKey::from_bytes([0x3C_u8; 32]);
    let mac = Blake3Mac::new(&key);
    let message = vec![0x5A_u8; 2048];
    let tag = mac.compute(&message);

    let (percentiles, outliers) = run_benchmark_with_result(warmup, iterations, || {
        mac.verify(&message, &tag)
            .expect("session MAC should verify");
    });

    let mut result = BenchmarkResult::new(
        "session-mac-verify",
        "Verify BLAKE3 session MAC over frame payload",
        iterations,
        warmup,
        percentiles,
    )
    .with_parameters(serde_json::json!({
        "message_bytes": message.len(),
        "mac": "blake3",
        "tag_bytes": fcp_crypto::mac::MAC_SIZE,
    }))
    .with_targets(Targets {
        p50_target_ms: 0.05,
        p99_target_ms: 0.5,
    });

    result.outliers_detected = outliers;
    result
}

const FCPS_HEADER_LEN: usize = 114;

#[derive(Clone, Copy)]
struct FcpsHeader {
    frame_seq: u64,
}

fn parse_fcps_header(bytes: &[u8]) -> Option<FcpsHeader> {
    if bytes.len() < FCPS_HEADER_LEN {
        return None;
    }

    let magic = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
    if magic != u32::from_le_bytes(*b"FCPS") {
        return None;
    }

    let frame_seq = u64::from_le_bytes(bytes[106..114].try_into().ok()?);

    Some(FcpsHeader { frame_seq })
}

fn bench_fcps_frame_parse_mac(iterations: u32, warmup: u32) -> BenchmarkResult {
    use fcp_crypto::{Blake3Mac, MacKey};

    let symbol_size: u16 = 1024;
    let payload_len: usize = 16 * symbol_size as usize;
    let frame_len = FCPS_HEADER_LEN + payload_len;
    let mut frame = vec![0u8; frame_len];

    frame[0..4].copy_from_slice(b"FCPS");
    frame[4..6].copy_from_slice(&1_u16.to_le_bytes());
    frame[6..8].copy_from_slice(&0_u16.to_le_bytes());

    let payload_len_u32 = u32::try_from(payload_len).expect("payload length fits u32");
    let symbol_size_u32 = u32::from(symbol_size);
    frame[8..12].copy_from_slice(&(payload_len_u32 / symbol_size_u32).to_le_bytes());
    frame[12..16].copy_from_slice(&payload_len_u32.to_le_bytes());
    frame[16..48].copy_from_slice(&[0x11_u8; 32]);
    frame[48..50].copy_from_slice(&symbol_size.to_le_bytes());
    frame[50..58].copy_from_slice(&42_u64.to_le_bytes());
    frame[58..90].copy_from_slice(&[0x22_u8; 32]);
    frame[90..98].copy_from_slice(&7_u64.to_le_bytes());
    frame[98..106].copy_from_slice(&99_u64.to_le_bytes());
    frame[106..114].copy_from_slice(&12345_u64.to_le_bytes());

    let key = MacKey::from_bytes([0x9A_u8; 32]);
    let mac = Blake3Mac::new(&key);
    let tag = mac.compute(&frame);

    let (percentiles, outliers) = run_benchmark_with_result(warmup, iterations, || {
        let header = parse_fcps_header(&frame).expect("valid header");
        mac.verify(&frame, &tag).expect("frame MAC should verify");
        header.frame_seq
    });

    let mut result = BenchmarkResult::new(
        "fcps-frame-parse-mac",
        "Parse FCPS header and verify session MAC",
        iterations,
        warmup,
        percentiles,
    )
    .with_parameters(serde_json::json!({
        "frame_bytes": frame_len,
        "payload_bytes": payload_len,
        "symbol_size": symbol_size,
        "mac": "blake3",
    }))
    .with_targets(Targets {
        p50_target_ms: 0.2,
        p99_target_ms: 1.0,
    });

    result.outliers_detected = outliers;
    result
}

// ─── CUAL Benchmarks ─────────────────────────────────────────────────────────

/// Benchmark search index building time.
fn bench_search_index(operation_count: u32, iterations: u32, warmup: u32) -> BenchmarkResult {
    let operations: Vec<String> = (0..operation_count)
        .map(|i| format!("connector_{}.operation_{}", i / 10, i % 10))
        .collect();

    let (percentiles, outliers) = run_benchmark_with_result(warmup, iterations, || {
        let mut index = std::collections::BTreeMap::<String, Vec<String>>::new();
        for op in &operations {
            for word in op.split('.') {
                index.entry(word.to_owned()).or_default().push(op.clone());
            }
        }
        index
    });

    let mut result = BenchmarkResult::new(
        format!("search-index-build-{operation_count}"),
        format!("Build search index for {operation_count} operations"),
        iterations,
        warmup,
        percentiles,
    )
    .with_parameters(serde_json::json!({ "operations": operation_count }))
    .with_targets(Targets {
        p50_target_ms: 5.0,
        p99_target_ms: 20.0,
    });
    result.outliers_detected = outliers;
    result
}

/// Benchmark search query latency.
fn bench_search_query(operation_count: u32, iterations: u32, warmup: u32) -> BenchmarkResult {
    let operations: Vec<String> = (0..operation_count)
        .map(|i| format!("connector_{}.operation_{}", i / 10, i % 10))
        .collect();
    let mut index = std::collections::BTreeMap::<String, Vec<String>>::new();
    for op in &operations {
        for word in op.split('.') {
            index.entry(word.to_owned()).or_default().push(op.clone());
        }
    }
    let query = "connector_5".to_owned();

    let (percentiles, outliers) =
        run_benchmark_with_result(warmup, iterations, || index.get(&query).cloned());

    let mut result = BenchmarkResult::new(
        format!("search-query-{operation_count}"),
        format!("Search query latency with {operation_count} indexed operations"),
        iterations,
        warmup,
        percentiles,
    )
    .with_parameters(serde_json::json!({ "operations": operation_count, "query": query }))
    .with_targets(Targets {
        p50_target_ms: 1.0,
        p99_target_ms: 5.0,
    });
    result.outliers_detected = outliers;
    result
}

/// Benchmark batch throughput (map-over-inputs).
fn bench_batch_throughput(item_count: u32, iterations: u32, warmup: u32) -> BenchmarkResult {
    let items: Vec<serde_json::Value> = (0..item_count)
        .map(|i| serde_json::json!({ "id": i, "data": format!("payload_{i}") }))
        .collect();

    let (percentiles, outliers) = run_benchmark_with_result(warmup, iterations, || {
        items
            .iter()
            .map(|item| item["data"].as_str().unwrap_or("").to_uppercase())
            .collect::<Vec<String>>()
    });

    let mut result = BenchmarkResult::new(
        format!("batch-throughput-{item_count}"),
        format!("Batch map-over-inputs throughput for {item_count} items"),
        iterations,
        warmup,
        percentiles,
    )
    .with_parameters(serde_json::json!({ "items": item_count }))
    .with_targets(Targets {
        p50_target_ms: 1.0,
        p99_target_ms: 5.0,
    });
    result.outliers_detected = outliers;
    result
}

/// Benchmark MCP tools/list response time.
fn bench_mcp_tool_list(connector_count: u32, iterations: u32, warmup: u32) -> BenchmarkResult {
    let tools: Vec<(String, String)> = (0..connector_count)
        .flat_map(|c| (0..3).map(move |o| (format!("connector_{c}"), format!("op_{o}"))))
        .collect();

    let (percentiles, outliers) = run_benchmark_with_result(warmup, iterations, || {
        tools.iter()
            .map(|(c, o)| serde_json::json!({ "name": format!("{c}.{o}"), "connector": c, "operation": o }))
            .collect::<Vec<serde_json::Value>>()
    });

    let mut result = BenchmarkResult::new(
        format!("mcp-tool-list-{connector_count}"),
        format!(
            "MCP tools/list for {connector_count} connectors ({} tools)",
            connector_count * 3
        ),
        iterations,
        warmup,
        percentiles,
    )
    .with_parameters(
        serde_json::json!({ "connectors": connector_count, "tools": connector_count * 3 }),
    )
    .with_targets(Targets {
        p50_target_ms: 5.0,
        p99_target_ms: 20.0,
    });
    result.outliers_detected = outliers;
    result
}

/// Benchmark MCP tool routing latency.
fn bench_mcp_tool_route(connector_count: u32, iterations: u32, warmup: u32) -> BenchmarkResult {
    let mut tool_index = std::collections::BTreeMap::<String, (String, String)>::new();
    for c in 0..connector_count {
        for o in 0..3u32 {
            let name = format!("connector_{c}.op_{o}");
            tool_index.insert(name, (format!("connector_{c}"), format!("op_{o}")));
        }
    }
    let target = format!("connector_{}.op_1", connector_count / 2);

    let (percentiles, outliers) =
        run_benchmark_with_result(warmup, iterations, || tool_index.get(&target).cloned());

    let mut result = BenchmarkResult::new(
        format!("mcp-tool-route-{connector_count}"),
        format!("MCP tool routing for {connector_count} connectors"),
        iterations,
        warmup,
        percentiles,
    )
    .with_parameters(serde_json::json!({ "connectors": connector_count, "target": target }))
    .with_targets(Targets {
        p50_target_ms: 0.1,
        p99_target_ms: 1.0,
    });
    result.outliers_detected = outliers;
    result
}

/// Benchmark pipeline setup and scheduling overhead.
fn bench_pipeline_setup(step_count: u32, iterations: u32, warmup: u32) -> BenchmarkResult {
    let steps: Vec<serde_json::Value> = (0..step_count)
        .map(|i| {
            serde_json::json!({
                "name": format!("step_{i}"),
                "command": format!("connector_{}.op_{}", i / 3, i % 3),
                "depends_on": if i > 0 { vec![format!("step_{}", i - 1)] } else { vec![] },
            })
        })
        .collect();

    let (percentiles, outliers) = run_benchmark_with_result(warmup, iterations, || {
        let mut visited = std::collections::BTreeSet::new();
        for step in &steps {
            let name = step["name"].as_str().unwrap_or("");
            let deps = step["depends_on"].as_array().map_or(0, Vec::len);
            visited.insert(name.to_owned());
            std::hint::black_box(deps);
        }
        visited
    });

    let mut result = BenchmarkResult::new(
        format!("pipeline-setup-{step_count}"),
        format!("Pipeline setup and validation for {step_count} steps"),
        iterations,
        warmup,
        percentiles,
    )
    .with_parameters(serde_json::json!({ "steps": step_count }))
    .with_targets(Targets {
        p50_target_ms: 10.0,
        p99_target_ms: 50.0,
    });
    result.outliers_detected = outliers;
    result
}

// ─── Connector Activate Benchmark ──────────────────────────────────────────

fn connector_health_probe(connector_path: &Path) -> anyhow::Result<usize> {
    let mut child = Command::new(connector_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| {
            anyhow!(
                "failed to start connector binary '{}': {error}",
                connector_path.display()
            )
        })?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("failed to open connector stdin"))?;
    stdin.write_all(
        br#"{"jsonrpc":"2.0","id":"bench-health","method":"health","params":{}}
"#,
    )?;
    drop(stdin);

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("failed to open connector stdout"))?;
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    let bytes = reader.read_line(&mut line)?;
    if bytes == 0 {
        let status = child.wait()?;
        bail!(
            "connector binary '{}' exited without a health response: {status}",
            connector_path.display()
        );
    }

    let response: serde_json::Value = serde_json::from_str(line.trim_end()).map_err(|error| {
        anyhow!(
            "connector binary '{}' returned invalid JSON-RPC health response: {error}",
            connector_path.display()
        )
    })?;
    if response.get("result").is_none() {
        bail!(
            "connector binary '{}' health probe returned no result: {response}",
            connector_path.display()
        );
    }

    let status = child.wait()?;
    if !status.success() {
        bail!(
            "connector binary '{}' exited unsuccessfully after health probe: {status}",
            connector_path.display()
        );
    }

    Ok(bytes)
}

fn bench_connector_activate(
    connector_path: Option<&str>,
    iterations: u32,
    warmup: u32,
) -> anyhow::Result<BenchmarkResult> {
    use fcp_kernel::{ConnectorId, SessionId, ZoneId};

    if let Some(path) = connector_path {
        let path = Path::new(path);
        if !path.is_file() {
            bail!("connector binary '{}' does not exist", path.display());
        }

        let (percentiles, outliers) =
            run_fallible_benchmark_with_result(warmup, iterations, || {
                connector_health_probe(path)
            })?;

        let mut result = BenchmarkResult::new(
            format!(
                "connector-activate-{}",
                path.file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("custom")
            ),
            format!(
                "Connector cold start for '{}' through JSON-RPC health probe",
                path.display()
            ),
            iterations,
            warmup,
            percentiles,
        )
        .with_parameters(serde_json::json!({
            "connector_path": path.display().to_string(),
            "probe": "jsonrpc.health",
        }))
        .with_targets(Targets {
            p50_target_ms: 100.0,
            p99_target_ms: 500.0,
        });
        result.outliers_detected = outliers;
        return Ok(result);
    }

    // The default `fwc bench all` path has no connector binary to execute, so
    // keep the benchmark explicit: this is a local activation fixture, not a
    // measured external connector process.
    let config_str = serde_json::json!({
        "mode": "credential_ref",
        "credential_id": "00000000-0000-0000-0000-000000000000",
        "project_id": "bench-project",
        "retry": { "max_retries": 3 },
        "request_timeout_ms": 30_000,
        "connector_name": "default",
    })
    .to_string();

    let (percentiles, outliers) = run_benchmark_with_result(warmup, iterations, || {
        let parsed: serde_json::Value = serde_json::from_str(&config_str).unwrap();
        let _project = parsed["project_id"].as_str().unwrap();
        let _credential_id = parsed["credential_id"].as_str().unwrap();
        let _timeout = parsed["request_timeout_ms"].as_u64().unwrap();
        let _session = SessionId::new();
        let _connector_id = ConnectorId::from_static("fcp.bench");
        let _zone = ZoneId::work();
        std::hint::black_box(parsed.to_string().len())
    });

    let mut result = BenchmarkResult::new(
        "connector-activate-default-fixture",
        "Synthetic activation fixture: config parse + validation without a connector binary",
        iterations,
        warmup,
        percentiles,
    )
    .with_parameters(serde_json::json!({
        "connector": "default",
        "mode": "synthetic-fixture",
        "config_bytes": config_str.len(),
    }))
    .with_targets(Targets {
        p50_target_ms: 100.0,
        p99_target_ms: 500.0,
    });
    result.outliers_detected = outliers;
    Ok(result)
}

// ─── Invoke Local Benchmark ───────────────────────────────────────────────

fn bench_invoke_local(iterations: u32, warmup: u32) -> BenchmarkResult {
    // Benchmark the local invoke path: JSON-RPC request construction,
    // serialization, and response parsing — the irreducible overhead
    // of the local stdio connector protocol.

    let (percentiles, outliers) = run_benchmark_with_result(warmup, iterations, || {
        // Build a complete JSON-RPC invoke request
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "invoke",
            "id": 1,
            "params": {
                "operation": "bench.invoke_local",
                "connector_id": "fcp.bench",
                "zone_id": "z:work",
                "request_id": "bench-req-001",
                "input": {
                    "query": "benchmark test query",
                    "limit": 10,
                    "offset": 0
                }
            }
        });

        // Serialize to bytes (simulating stdio write)
        let serialized = serde_json::to_vec(&request).unwrap();

        // Simulate response parsing
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "status": "success",
                "data": { "items": [], "total": 0 }
            }
        });
        let _parsed: serde_json::Value =
            serde_json::from_slice(&serde_json::to_vec(&response).unwrap()).unwrap();

        std::hint::black_box(serialized.len())
    });

    let mut result = BenchmarkResult::new(
        "invoke-local",
        "Local invoke round-trip: JSON-RPC request serialization + response parsing",
        iterations,
        warmup,
        percentiles,
    )
    .with_targets(Targets {
        p50_target_ms: 2.0,
        p99_target_ms: 10.0,
    });
    result.outliers_detected = outliers;
    result
}

// ─── Invoke Mesh Benchmark ────────────────────────────────────────────────

fn bench_invoke_mesh(path: &MeshPath, iterations: u32, warmup: u32) -> BenchmarkResult {
    use fcp_crypto::Ed25519SigningKey;

    let path_name = match path {
        MeshPath::Direct => "direct",
        MeshPath::Derp => "derp",
    };

    // Benchmark the mesh invoke overhead: FCPS frame construction,
    // session MAC computation, and payload serialization — the fixed
    // cost added by mesh routing on top of local invoke.
    let signing_key = Ed25519SigningKey::generate();
    let payload = serde_json::json!({
        "operation": "bench.mesh_invoke",
        "input": { "query": "mesh benchmark", "limit": 10 }
    });
    let payload_bytes = serde_json::to_vec(&payload).unwrap();

    let (percentiles, outliers) = run_benchmark_with_result(warmup, iterations, || {
        // Simulate FCPS frame construction:
        // 1. Serialize payload
        let _serialized = serde_json::to_vec(&payload).unwrap();

        // 2. Sign the payload (simulating per-frame MAC)
        let sig = signing_key.sign(&payload_bytes);

        // 3. Build frame header (114 bytes fixed)
        let mut frame = Vec::with_capacity(114 + payload_bytes.len());
        frame.extend_from_slice(b"FCPS"); // magic
        frame.extend_from_slice(&1u16.to_le_bytes()); // version
        frame.extend_from_slice(&0u16.to_le_bytes()); // flags
        frame.extend_from_slice(&1u32.to_le_bytes()); // symbol count
        frame.extend_from_slice(&(payload_bytes.len() as u32).to_le_bytes()); // payload len
        frame.extend_from_slice(&[0u8; 32]); // object ID
        frame.extend_from_slice(&1024u16.to_le_bytes()); // symbol size
        frame.extend_from_slice(&[0u8; 8]); // zone key ID
        frame.extend_from_slice(&[0u8; 32]); // zone ID hash
        frame.extend_from_slice(&1u64.to_le_bytes()); // epoch
        frame.extend_from_slice(&1u64.to_le_bytes()); // sender instance
        frame.extend_from_slice(&1u64.to_le_bytes()); // frame seq
        frame.extend_from_slice(&payload_bytes);

        std::hint::black_box((frame.len(), sig))
    });

    let (p50_target, p99_target) = match path {
        MeshPath::Direct => (20.0, 100.0),
        MeshPath::Derp => (150.0, 500.0),
    };

    let mut result = BenchmarkResult::new(
        format!("invoke-mesh-{path_name}"),
        format!("Mesh invoke overhead ({path_name}): frame construction + MAC + serialization"),
        iterations,
        warmup,
        percentiles,
    )
    .with_parameters(serde_json::json!({
        "path": path_name,
        "payload_bytes": payload_bytes.len(),
    }))
    .with_targets(Targets {
        p50_target_ms: p50_target,
        p99_target_ms: p99_target,
    });
    result.outliers_detected = outliers;
    result
}

// ─── Secrets (Shamir) Benchmark ───────────────────────────────────────────

fn bench_secrets(k: u32, n: u32, iterations: u32, warmup: u32) -> BenchmarkResult {
    use fcp_crypto::shamir::{reconstruct_secret, split_secret};

    let k_u8 = u8::try_from(k).unwrap_or(3);
    let n_u8 = u8::try_from(n).unwrap_or(5);

    // Deterministic 32-byte fixture material for Shamir split/reconstruct timing.
    let fixture_material = [0xAB_u8; 32];

    // Pre-split the shares for the reconstruction benchmark
    let shares = split_secret(&fixture_material, k_u8, n_u8).expect("Shamir split should succeed");

    let (percentiles, outliers) = run_benchmark_with_result(warmup, iterations, || {
        // Benchmark the full split + reconstruct cycle
        let new_shares = split_secret(&fixture_material, k_u8, n_u8).expect("split");
        let k_shares: Vec<_> = new_shares.into_iter().take(k_u8 as usize).collect();
        let reconstructed = reconstruct_secret(&k_shares).expect("reconstruct");
        std::hint::black_box(reconstructed)
    });

    let mut result = BenchmarkResult::new(
        format!("secrets-{k}-of-{n}"),
        format!("Shamir secret sharing: split + reconstruct ({k}-of-{n}, 32-byte secret)"),
        iterations,
        warmup,
        percentiles,
    )
    .with_parameters(serde_json::json!({
        "k": k,
        "n": n,
        "material_bytes": fixture_material.len(),
    }))
    .with_targets(Targets {
        p50_target_ms: 150.0,
        p99_target_ms: 750.0,
    });
    result.outliers_detected = outliers;
    // Verify the pre-split shares can reconstruct (sanity check)
    let k_shares: Vec<_> = shares.into_iter().take(k_u8 as usize).collect();
    let _reconstructed = reconstruct_secret(&k_shares).expect("sanity: reconstruct should work");
    result
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use fcp_cbor::CanonicalSerializer;
    use serde_json::json;

    // ════════════════════════════════════════════════════════════════════════
    // Types tests
    // ════════════════════════════════════════════════════════════════════════

    fn test_percentiles() -> Percentiles {
        Percentiles {
            p50_ms: 1.0,
            p90_ms: 2.0,
            p95_ms: 2.5,
            p99_ms: 3.0,
            min_ms: 0.5,
            max_ms: 4.0,
            mean_ms: 1.5,
            stddev_ms: 0.2,
        }
    }

    // ── BenchmarkResult::new ────────────────────────────────────────────

    #[test]
    fn benchmark_result_new_defaults() {
        let result = BenchmarkResult::new("test", "description", 100, 10, test_percentiles());
        assert_eq!(result.name, "test");
        assert_eq!(result.description, "description");
        assert_eq!(result.sample_count, 100);
        assert_eq!(result.warmup_count, 10);
        assert!(result.percentiles.is_some());
        assert!(result.passed.is_none());
        assert!(result.targets.is_none());
        assert!(result.note.is_none());
        assert_eq!(result.outliers_detected, 0);
        assert!(result.parameters.is_object());
        assert!(result.parameters.as_object().unwrap().is_empty());
    }

    // ── with_parameters ────────────────────────────────────────────────

    #[test]
    fn benchmark_result_with_parameters() {
        let result = BenchmarkResult::new("test", "desc", 50, 5, test_percentiles())
            .with_parameters(json!({"size": "1mb", "count": 42}));
        assert_eq!(result.parameters["size"], "1mb");
        assert_eq!(result.parameters["count"], 42);
    }

    // ── with_targets pass/fail logic ────────────────────────────────────

    #[test]
    fn with_targets_passes_when_within() {
        let result = BenchmarkResult::new("test", "desc", 100, 10, test_percentiles())
            .with_targets(Targets {
                p50_target_ms: 5.0,
                p99_target_ms: 10.0,
            });
        assert_eq!(result.passed, Some(true));
        assert!(result.targets.is_some());
    }

    #[test]
    fn with_targets_fails_when_p50_exceeded() {
        let result = BenchmarkResult::new("test", "desc", 100, 10, test_percentiles())
            .with_targets(Targets {
                p50_target_ms: 0.5, // p50 is 1.0
                p99_target_ms: 10.0,
            });
        assert_eq!(result.passed, Some(false));
    }

    #[test]
    fn with_targets_fails_when_p99_exceeded() {
        let result = BenchmarkResult::new("test", "desc", 100, 10, test_percentiles())
            .with_targets(Targets {
                p50_target_ms: 5.0,
                p99_target_ms: 2.0, // p99 is 3.0
            });
        assert_eq!(result.passed, Some(false));
    }

    #[test]
    fn with_targets_passes_at_exact_boundary() {
        let result = BenchmarkResult::new("test", "desc", 100, 10, test_percentiles())
            .with_targets(Targets {
                p50_target_ms: 1.0, // p50 is exactly 1.0
                p99_target_ms: 3.0, // p99 is exactly 3.0
            });
        assert_eq!(result.passed, Some(true));
    }

    #[test]
    fn with_targets_placeholder_no_pass() {
        let result = BenchmarkResult::placeholder("test", "pending").with_targets(Targets {
            p50_target_ms: 5.0,
            p99_target_ms: 10.0,
        });
        // Placeholder has no percentiles, so passed stays None
        assert!(result.passed.is_none());
        assert!(result.targets.is_some());
    }

    #[test]
    fn with_targets_zero_sample_result_stays_unrated() {
        let result =
            BenchmarkResult::new("test", "desc", 0, 0, test_percentiles()).with_targets(Targets {
                p50_target_ms: 5.0,
                p99_target_ms: 10.0,
            });
        assert!(result.passed.is_none());
        assert!(result.targets.is_some());
    }

    #[test]
    fn run_rejects_zero_iterations() {
        let args = BenchArgs {
            command: BenchCommand::Cbor {
                target: CborTarget::SchemaHash,
            },
            format: OutputFormat::Json,
            iterations: 0,
            warmup: 0,
        };
        let error = run(&args).expect_err("zero iterations should be rejected");
        assert!(
            error
                .to_string()
                .contains("--iterations must be greater than 0")
        );
    }

    // ── BenchmarkReport::new ────────────────────────────────────────────

    #[test]
    fn benchmark_report_new_schema_version() {
        let env = EnvironmentInfo {
            os: "test".to_string(),
            os_version: "1.0".to_string(),
            arch: "x86_64".to_string(),
            cpu_count: 4,
            memory_bytes: None,
            git_commit: None,
            git_branch: None,
            git_dirty: None,
            fcp_version: "0.1.0".to_string(),
            rustc_version: None,
            timestamp: Utc::now(),
        };
        let report = BenchmarkReport::new(env, vec![]);
        assert_eq!(report.schema_version, "1.0.0");
        assert!(report.results.is_empty());
    }

    // ── Percentiles serde ───────────────────────────────────────────────

    #[test]
    fn percentiles_serde_roundtrip() {
        let p = test_percentiles();
        let json = serde_json::to_string(&p).unwrap();
        let back: Percentiles = serde_json::from_str(&json).unwrap();
        assert!((back.p50_ms - 1.0).abs() < f64::EPSILON);
        assert!((back.p99_ms - 3.0).abs() < f64::EPSILON);
        assert!((back.stddev_ms - 0.2).abs() < f64::EPSILON);
    }

    #[test]
    fn percentiles_debug() {
        let p = test_percentiles();
        let dbg = format!("{p:?}");
        assert!(dbg.contains("p50_ms"));
        assert!(dbg.contains("p99_ms"));
    }

    #[test]
    fn percentiles_clone() {
        let p = test_percentiles();
        let cloned = p.clone();
        assert!((cloned.p50_ms - p.p50_ms).abs() < f64::EPSILON);
    }

    // ── Targets serde ───────────────────────────────────────────────────

    #[test]
    fn targets_serde_roundtrip() {
        let t = Targets {
            p50_target_ms: 2.0,
            p99_target_ms: 10.0,
        };
        let json = serde_json::to_string(&t).unwrap();
        let back: Targets = serde_json::from_str(&json).unwrap();
        assert!((back.p50_target_ms - 2.0).abs() < f64::EPSILON);
        assert!((back.p99_target_ms - 10.0).abs() < f64::EPSILON);
    }

    // ── EnvironmentInfo serde ───────────────────────────────────────────

    #[test]
    fn environment_info_serde_roundtrip() {
        let env = EnvironmentInfo {
            os: "linux".to_string(),
            os_version: "6.6".to_string(),
            arch: "aarch64".to_string(),
            cpu_count: 8,
            memory_bytes: Some(16_000_000_000),
            git_commit: Some("abc123".to_string()),
            git_branch: Some("main".to_string()),
            git_dirty: Some(true),
            fcp_version: "0.2.0".to_string(),
            rustc_version: Some("1.85.0".to_string()),
            timestamp: Utc::now(),
        };
        let json = serde_json::to_string(&env).unwrap();
        let back: EnvironmentInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.os, "linux");
        assert_eq!(back.cpu_count, 8);
        assert_eq!(back.memory_bytes, Some(16_000_000_000));
        assert_eq!(back.git_dirty, Some(true));
    }

    #[test]
    fn environment_info_minimal() {
        let env = EnvironmentInfo {
            os: "test".to_string(),
            os_version: "0".to_string(),
            arch: "wasm".to_string(),
            cpu_count: 1,
            memory_bytes: None,
            git_commit: None,
            git_branch: None,
            git_dirty: None,
            fcp_version: "0.0.1".to_string(),
            rustc_version: None,
            timestamp: Utc::now(),
        };
        let json = serde_json::to_string(&env).unwrap();
        let back: EnvironmentInfo = serde_json::from_str(&json).unwrap();
        assert!(back.memory_bytes.is_none());
        assert!(back.git_commit.is_none());
    }

    // ── BenchmarkResult full serde ──────────────────────────────────────

    #[test]
    fn benchmark_result_full_serde_roundtrip() {
        let result = BenchmarkResult::new("bench-a", "Full bench", 200, 20, test_percentiles())
            .with_parameters(json!({"key": "value"}))
            .with_targets(Targets {
                p50_target_ms: 5.0,
                p99_target_ms: 15.0,
            });
        let json = serde_json::to_string(&result).unwrap();
        let back: BenchmarkResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "bench-a");
        assert_eq!(back.sample_count, 200);
        assert_eq!(back.passed, Some(true));
        assert!(back.percentiles.is_some());
        assert!(back.targets.is_some());
    }

    // ── Snapshot test ───────────────────────────────────────────────────

    #[test]
    fn benchmark_report_json_snapshot() {
        let generated_at = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let env = EnvironmentInfo {
            os: "linux".to_string(),
            os_version: "6.6.0".to_string(),
            arch: "x86_64".to_string(),
            cpu_count: 16,
            memory_bytes: Some(32_000_000_000),
            git_commit: Some("deadbeef".to_string()),
            git_branch: Some("main".to_string()),
            git_dirty: Some(false),
            fcp_version: "0.1.0".to_string(),
            rustc_version: Some("rustc 1.85.0".to_string()),
            timestamp: generated_at,
        };

        let percentiles = Percentiles {
            p50_ms: 1.0,
            p90_ms: 2.0,
            p95_ms: 2.5,
            p99_ms: 3.0,
            min_ms: 0.5,
            max_ms: 4.0,
            mean_ms: 1.5,
            stddev_ms: 0.2,
        };
        let mut result = BenchmarkResult::new(
            "cbor-serialize",
            "CBOR canonical serialization",
            100,
            10,
            percentiles,
        )
        .with_parameters(json!({ "payload_bytes": 1024 }))
        .with_targets(Targets {
            p50_target_ms: 2.0,
            p99_target_ms: 5.0,
        });
        result.outliers_detected = 1;
        let report = BenchmarkReport {
            schema_version: "1.0.0".to_string(),
            generated_at,
            environment: env,
            results: vec![result],
        };

        let json = serde_json::to_string_pretty(&report).unwrap();
        let expected = r#"{
  "schema_version": "1.0.0",
  "generated_at": "2026-01-01T00:00:00Z",
  "environment": {
    "os": "linux",
    "os_version": "6.6.0",
    "arch": "x86_64",
    "cpu_count": 16,
    "memory_bytes": 32000000000,
    "git_commit": "deadbeef",
    "git_branch": "main",
    "git_dirty": false,
    "fcp_version": "0.1.0",
    "rustc_version": "rustc 1.85.0",
    "timestamp": "2026-01-01T00:00:00Z"
  },
  "results": [
    {
      "name": "cbor-serialize",
      "description": "CBOR canonical serialization",
      "parameters": {
        "payload_bytes": 1024
      },
      "sample_count": 100,
      "warmup_count": 10,
      "percentiles": {
        "p50_ms": 1.0,
        "p90_ms": 2.0,
        "p95_ms": 2.5,
        "p99_ms": 3.0,
        "min_ms": 0.5,
        "max_ms": 4.0,
        "mean_ms": 1.5,
        "stddev_ms": 0.2
      },
      "passed": true,
      "targets": {
        "p50_target_ms": 2.0,
        "p99_target_ms": 5.0
      },
      "note": null,
      "outliers_detected": 1
    }
  ]
}"#;

        assert_eq!(json, expected);
    }

    // ════════════════════════════════════════════════════════════════════════
    // Runner tests
    // ════════════════════════════════════════════════════════════════════════

    // ── calculate_percentiles edge cases ────────────────────────────────

    #[test]
    fn percentiles_empty() {
        let p = calculate_percentiles(&[]);
        assert!((p.p50_ms).abs() < f64::EPSILON);
        assert!((p.mean_ms).abs() < f64::EPSILON);
        assert!((p.stddev_ms).abs() < f64::EPSILON);
    }

    #[test]
    fn percentiles_single_element() {
        let sorted = vec![5_000_000_u64]; // 5ms
        let p = calculate_percentiles(&sorted);
        assert!((p.p50_ms - 5.0).abs() < 0.01);
        assert!((p.min_ms - 5.0).abs() < 0.01);
        assert!((p.max_ms - 5.0).abs() < 0.01);
        assert!((p.mean_ms - 5.0).abs() < 0.01);
        assert!((p.stddev_ms).abs() < 0.01); // zero variance
    }

    #[test]
    fn percentiles_two_elements() {
        let sorted = vec![1_000_000_u64, 3_000_000]; // 1ms, 3ms
        let p = calculate_percentiles(&sorted);
        assert!((p.min_ms - 1.0).abs() < 0.01);
        assert!((p.max_ms - 3.0).abs() < 0.01);
        assert!((p.mean_ms - 2.0).abs() < 0.01);
    }

    #[test]
    fn percentiles_uniform_values() {
        let sorted = vec![10_000_000_u64; 50]; // 50 x 10ms
        let p = calculate_percentiles(&sorted);
        assert!((p.p50_ms - 10.0).abs() < 0.01);
        assert!((p.p99_ms - 10.0).abs() < 0.01);
        assert!((p.stddev_ms).abs() < 0.01); // zero stddev
    }

    // ── count_outliers edge cases ───────────────────────────────────────

    #[test]
    fn count_outliers_too_few_elements() {
        assert_eq!(count_outliers(&[1, 2, 3]), 0);
        assert_eq!(count_outliers(&[1]), 0);
        assert_eq!(count_outliers(&[]), 0);
    }

    #[test]
    fn count_outliers_no_outliers() {
        let sorted: Vec<u64> = (1..=20).collect();
        let outliers = count_outliers(&sorted);
        assert_eq!(outliers, 0);
    }

    #[test]
    fn count_outliers_with_extreme() {
        let mut sorted: Vec<u64> = (1..=50).collect();
        sorted.push(10_000); // extreme outlier
        sorted.sort_unstable();
        let outliers = count_outliers(&sorted);
        assert!(outliers >= 1);
    }

    // ── run_benchmark_with_result ───────────────────────────────────────

    #[test]
    fn run_benchmark_basic() {
        let (percentiles, _outliers) = run_benchmark_with_result(2, 10, || 42_u64);
        assert!(percentiles.min_ms >= 0.0);
        assert!(percentiles.max_ms >= percentiles.min_ms);
        assert!(percentiles.mean_ms >= 0.0);
    }

    #[test]
    fn run_benchmark_zero_warmup() {
        let (percentiles, _) = run_benchmark_with_result(0, 5, || "hello");
        assert!(percentiles.min_ms >= 0.0);
    }

    // ── Original runner tests ───────────────────────────────────────────

    #[test]
    fn percentiles_calculation() {
        // Create a simple sorted array: 1, 2, 3, ..., 100.
        let sorted: Vec<u64> = (1..=100).map(|x| x * 1_000_000).collect(); // In nanoseconds.

        let p = calculate_percentiles(&sorted);

        // p50 should be around 50ms, p90 around 90ms, p99 around 99ms.
        assert!((p.p50_ms - 50.0).abs() < 2.0);
        assert!((p.p90_ms - 90.0).abs() < 2.0);
        assert!((p.p95_ms - 95.0).abs() < 2.0);
        assert!((p.p99_ms - 99.0).abs() < 2.0);
        assert!((p.min_ms - 1.0).abs() < 0.01);
        assert!((p.max_ms - 100.0).abs() < 0.01);
    }

    #[test]
    fn outlier_detection() {
        // Normal values with one extreme outlier.
        let mut sorted: Vec<u64> = (1..=99).collect();
        sorted.push(1000); // Outlier.
        sorted.sort_unstable();

        let outliers = count_outliers(&sorted);
        assert!(outliers >= 1);
    }

    // ── percentile ordering invariants ──────────────────────────────────

    #[test]
    fn percentiles_ordering_invariant() {
        let sorted: Vec<u64> = (1..=200).map(|x| x * 500_000).collect();
        let p = calculate_percentiles(&sorted);
        assert!(p.min_ms <= p.p50_ms);
        assert!(p.p50_ms <= p.p90_ms);
        assert!(p.p90_ms <= p.p95_ms);
        assert!(p.p95_ms <= p.p99_ms);
        assert!(p.p99_ms <= p.max_ms);
    }

    #[test]
    fn percentiles_mean_between_min_and_max() {
        let sorted: Vec<u64> = (1..=100).map(|x| x * 1_000_000).collect();
        let p = calculate_percentiles(&sorted);
        assert!(p.mean_ms >= p.min_ms);
        assert!(p.mean_ms <= p.max_ms);
    }

    #[test]
    fn percentiles_stddev_non_negative() {
        let sorted: Vec<u64> = vec![1, 5, 10, 50, 100, 500, 1000];
        let p = calculate_percentiles(&sorted);
        assert!(p.stddev_ms >= 0.0);
    }

    // ── count_outliers boundary ─────────────────────────────────────────

    #[test]
    fn count_outliers_exactly_four_elements() {
        let sorted = vec![10_u64, 20, 30, 40];
        let outliers = count_outliers(&sorted);
        assert_eq!(outliers, 0); // no outliers in tight range
    }

    #[test]
    fn count_outliers_uniform_data() {
        let sorted = vec![100_u64; 50];
        let outliers = count_outliers(&sorted);
        assert_eq!(outliers, 0); // IQR=0 -> all equal -> no outliers
    }

    #[test]
    fn count_outliers_multiple_extremes() {
        let mut sorted: Vec<u64> = (1..=50).collect();
        sorted.push(50_000);
        sorted.push(60_000);
        sorted.push(70_000);
        sorted.sort_unstable();
        let outliers = count_outliers(&sorted);
        assert!(outliers >= 3);
    }

    // ── run_benchmark_with_result additional ────────────────────────────

    #[test]
    fn run_benchmark_returns_non_zero_durations() {
        let (percentiles, _) = run_benchmark_with_result(1, 20, || {
            // busy spin to ensure measurable time
            let mut sum = 0_u64;
            for i in 0..100 {
                sum = sum.wrapping_add(i);
            }
            std::hint::black_box(sum)
        });
        // With 20 samples, we should get valid statistics
        assert!(percentiles.max_ms >= 0.0);
        assert!(percentiles.mean_ms >= 0.0);
    }

    #[test]
    fn run_benchmark_single_iteration() {
        let (percentiles, _) = run_benchmark_with_result(0, 1, || 99_u32);
        // single sample: min == max == p50 == mean
        assert!((percentiles.min_ms - percentiles.max_ms).abs() < f64::EPSILON);
        assert!((percentiles.min_ms - percentiles.mean_ms).abs() < f64::EPSILON);
    }

    // ── percentile precision ────────────────────────────────────────────

    #[test]
    fn percentiles_known_values() {
        // 10 samples: 1ms, 2ms, ..., 10ms (in nanoseconds)
        let sorted: Vec<u64> = (1..=10).map(|x| x * 1_000_000).collect();
        let p = calculate_percentiles(&sorted);
        assert!((p.min_ms - 1.0).abs() < 0.001);
        assert!((p.max_ms - 10.0).abs() < 0.001);
        assert!((p.mean_ms - 5.5).abs() < 0.001);
    }

    // ════════════════════════════════════════════════════════════════════════
    // Environment tests
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn collect_returns_valid_os() {
        let info = collect_environment();
        assert!(!info.os.is_empty(), "os should not be empty");
        let valid_os = ["linux", "macos", "windows"];
        assert!(
            valid_os.contains(&info.os.as_str()),
            "unexpected os: {}",
            info.os
        );
    }

    #[test]
    fn collect_returns_valid_arch() {
        let info = collect_environment();
        assert!(!info.arch.is_empty());
        let valid_arch = ["x86_64", "aarch64", "x86", "arm"];
        assert!(
            valid_arch.contains(&info.arch.as_str()),
            "unexpected arch: {}",
            info.arch
        );
    }

    #[test]
    fn collect_returns_positive_cpu_count() {
        let info = collect_environment();
        assert!(info.cpu_count >= 1);
    }

    #[test]
    fn collect_returns_nonempty_fcp_version() {
        let info = collect_environment();
        assert!(!info.fcp_version.is_empty());
    }

    #[test]
    fn collect_returns_timestamp_not_epoch() {
        let info = collect_environment();
        assert!(info.timestamp.timestamp() > 0);
    }

    #[test]
    fn collect_os_version_not_empty() {
        let info = collect_environment();
        assert!(!info.os_version.is_empty());
    }

    #[test]
    fn get_os_version_returns_string() {
        let version = get_os_version();
        assert!(!version.is_empty());
    }

    #[test]
    fn get_git_info_returns_some_in_repo() {
        // rch workers and other git-less checkouts legitimately yield None.
        let in_repo = std::process::Command::new("git")
            .args(["rev-parse", "--git-dir"])
            .output()
            .is_ok_and(|output| output.status.success());
        let (commit, branch, dirty) = get_git_info();
        if !in_repo {
            assert!(commit.is_none() && branch.is_none() && dirty.is_none());
            return;
        }
        assert!(commit.is_some(), "expected git commit");
        assert!(branch.is_some(), "expected git branch");
        assert!(dirty.is_some(), "expected git dirty status");
    }

    #[test]
    fn get_git_commit_is_short_hash() {
        let (commit, _, _) = get_git_info();
        if let Some(c) = commit {
            assert!(
                c.len() >= 7 && c.len() <= 12,
                "short hash length: {}",
                c.len()
            );
            assert!(c.chars().all(|ch| ch.is_ascii_hexdigit()), "not hex: {c}");
        }
    }

    #[test]
    fn get_git_branch_is_nonempty() {
        let (_, branch, _) = get_git_info();
        if let Some(b) = branch {
            assert!(!b.is_empty());
        }
    }

    #[test]
    fn get_rustc_version_returns_some() {
        let version = get_rustc_version();
        assert!(version.is_some());
        let v = version.unwrap();
        assert!(v.starts_with("rustc "), "expected 'rustc ...' got '{v}'");
    }

    #[test]
    fn collect_deterministic_static_fields() {
        let info1 = collect_environment();
        let info2 = collect_environment();
        assert_eq!(info1.os, info2.os);
        assert_eq!(info1.arch, info2.arch);
        assert_eq!(info1.cpu_count, info2.cpu_count);
        assert_eq!(info1.fcp_version, info2.fcp_version);
    }

    #[test]
    fn collect_git_branch_is_main() {
        let info = collect_environment();
        // Per AGENTS.md, we always use main
        if let Some(ref branch) = info.git_branch {
            assert_eq!(branch, "main", "expected main branch");
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // CBOR benchmark tests
    // ════════════════════════════════════════════════════════════════════════

    // ── Test data generators ────────────────────────────────────────────

    #[test]
    fn make_test_schema_fields() {
        let schema = make_test_schema();
        assert_eq!(schema.namespace, "fcp.bench");
        assert_eq!(schema.name, "TestObject");
        assert_eq!(schema.version, semver::Version::new(1, 0, 0));
    }

    #[test]
    fn make_small_object_fields() {
        let obj = make_small_object();
        assert_eq!(obj.id, 12345);
        assert_eq!(obj.name, "benchmark-test");
        assert!(obj.active);
    }

    #[test]
    fn make_medium_object_fields() {
        let obj = make_medium_object();
        assert_eq!(obj.id, 12345);
        assert_eq!(obj.tags.len(), 4);
        assert_eq!(obj.metadata.len(), 3);
        assert_eq!(obj.version, 42);
        assert!(obj.active);
    }

    // ── Schema hash determinism ─────────────────────────────────────────

    #[test]
    fn schema_hash_deterministic() {
        let s1 = make_test_schema();
        let s2 = make_test_schema();
        assert_eq!(s1.hash(), s2.hash());
    }

    // ── Serialization roundtrips ────────────────────────────────────────

    #[test]
    fn small_object_cbor_roundtrip() {
        let schema = make_test_schema();
        let obj = make_small_object();
        let bytes = CanonicalSerializer::serialize(&obj, &schema).unwrap();
        let back: SmallObject = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(back, obj);
    }

    #[test]
    fn medium_object_cbor_roundtrip() {
        let schema = make_test_schema();
        let obj = make_medium_object();
        let bytes = CanonicalSerializer::serialize(&obj, &schema).unwrap();
        let back: MediumObject = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(back, obj);
    }

    #[test]
    fn small_object_serialization_deterministic() {
        let schema = make_test_schema();
        let obj = make_small_object();
        let bytes1 = CanonicalSerializer::serialize(&obj, &schema).unwrap();
        let bytes2 = CanonicalSerializer::serialize(&obj, &schema).unwrap();
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn medium_object_serialization_deterministic() {
        let schema = make_test_schema();
        let obj = make_medium_object();
        let bytes1 = CanonicalSerializer::serialize(&obj, &schema).unwrap();
        let bytes2 = CanonicalSerializer::serialize(&obj, &schema).unwrap();
        assert_eq!(bytes1, bytes2);
    }

    // ── run_cbor_benchmarks dispatch ────────────────────────────────────

    #[test]
    fn run_cbor_benchmarks_schema_hash_returns_one() {
        let results = run_cbor_benchmarks(CborTarget::SchemaHash, 5, 1);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "cbor-schema-hash");
    }

    #[test]
    fn run_cbor_benchmarks_serialize_returns_two() {
        let results = run_cbor_benchmarks(CborTarget::Serialize, 5, 1);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].name, "cbor-serialize-small");
        assert_eq!(results[1].name, "cbor-serialize-medium");
    }

    #[test]
    fn run_cbor_benchmarks_deserialize_returns_two() {
        let results = run_cbor_benchmarks(CborTarget::Deserialize, 5, 1);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].name, "cbor-deserialize-small");
        assert_eq!(results[1].name, "cbor-deserialize-medium");
    }

    #[test]
    fn run_cbor_benchmarks_all_returns_five() {
        let results = run_cbor_benchmarks(CborTarget::All, 5, 1);
        assert_eq!(results.len(), 5);
    }

    #[test]
    fn cbor_benchmark_results_have_percentiles() {
        let results = run_cbor_benchmarks(CborTarget::All, 5, 1);
        for r in &results {
            assert!(
                r.percentiles.is_some(),
                "missing percentiles for {}",
                r.name
            );
        }
    }

    #[test]
    fn cbor_benchmark_results_have_targets() {
        let results = run_cbor_benchmarks(CborTarget::All, 5, 1);
        for r in &results {
            assert!(r.targets.is_some(), "missing targets for {}", r.name);
            assert!(r.passed.is_some(), "missing passed for {}", r.name);
        }
    }

    // ── Small/medium serde (JSON) ───────────────────────────────────────

    #[test]
    fn small_object_json_roundtrip() {
        let obj = make_small_object();
        let json = serde_json::to_string(&obj).unwrap();
        let back: SmallObject = serde_json::from_str(&json).unwrap();
        assert_eq!(back, obj);
    }

    #[test]
    fn medium_object_json_roundtrip() {
        let obj = make_medium_object();
        let json = serde_json::to_string(&obj).unwrap();
        let back: MediumObject = serde_json::from_str(&json).unwrap();
        assert_eq!(back, obj);
    }

    // ════════════════════════════════════════════════════════════════════════
    // Main bench module tests
    // ════════════════════════════════════════════════════════════════════════

    // ── normalize_size_label ────────────────────────────────────────────

    #[test]
    fn normalize_size_label_lowercase() {
        assert_eq!(normalize_size_label("1MB"), "1mb");
    }

    #[test]
    fn normalize_size_label_already_lower() {
        assert_eq!(normalize_size_label("100kb"), "100kb");
    }

    #[test]
    fn normalize_size_label_trims_whitespace() {
        assert_eq!(normalize_size_label("  2gb  "), "2gb");
    }

    #[test]
    fn normalize_size_label_mixed_case() {
        assert_eq!(normalize_size_label("512Kb"), "512kb");
    }

    // ── parse_size_bytes ────────────────────────────────────────────────

    #[test]
    fn parse_size_bytes_megabytes() {
        assert_eq!(parse_size_bytes("1mb").unwrap(), 1024 * 1024);
    }

    #[test]
    fn parse_size_bytes_kilobytes() {
        assert_eq!(parse_size_bytes("100kb").unwrap(), 100 * 1024);
    }

    #[test]
    fn parse_size_bytes_gigabytes() {
        assert_eq!(parse_size_bytes("2gb").unwrap(), 2 * 1024 * 1024 * 1024);
    }

    #[test]
    fn parse_size_bytes_raw_bytes_suffix() {
        assert_eq!(parse_size_bytes("512b").unwrap(), 512);
    }

    #[test]
    fn parse_size_bytes_raw_number() {
        assert_eq!(parse_size_bytes("1024").unwrap(), 1024);
    }

    #[test]
    fn connector_activate_default_is_explicit_synthetic_fixture() {
        let result = bench_connector_activate(None, 2, 1).expect("default fixture benchmark");
        assert_eq!(result.name, "connector-activate-default-fixture");
        assert_eq!(result.parameters["mode"], "synthetic-fixture");
        assert!(result.description.contains("Synthetic activation fixture"));
        assert!(result.percentiles.is_some());
    }

    #[test]
    fn connector_activate_missing_binary_errors_instead_of_faking_measurement() {
        let missing = "/definitely/not/a/fcp/connector/binary";
        let error = bench_connector_activate(Some(missing), 1, 0).unwrap_err();
        assert!(error.to_string().contains("does not exist"));
    }

    #[test]
    fn parse_size_bytes_with_underscores() {
        assert_eq!(parse_size_bytes("1_000kb").unwrap(), 1000 * 1024);
    }

    #[test]
    fn parse_size_bytes_uppercase() {
        assert_eq!(parse_size_bytes("1MB").unwrap(), 1024 * 1024);
    }

    #[test]
    fn parse_size_bytes_whitespace() {
        assert_eq!(parse_size_bytes("  512kb  ").unwrap(), 512 * 1024);
    }

    #[test]
    fn parse_size_bytes_empty() {
        let err = parse_size_bytes("").unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn parse_size_bytes_zero() {
        let err = parse_size_bytes("0kb").unwrap_err();
        assert!(err.to_string().contains("greater than zero"));
    }

    #[test]
    fn parse_size_bytes_zero_raw() {
        let err = parse_size_bytes("0").unwrap_err();
        assert!(err.to_string().contains("greater than zero"));
    }

    #[test]
    fn parse_size_bytes_invalid_number() {
        let err = parse_size_bytes("abcmb").unwrap_err();
        assert!(err.to_string().contains("invalid size value"));
    }

    #[test]
    fn parse_size_bytes_just_suffix() {
        let err = parse_size_bytes("mb").unwrap_err();
        assert!(err.to_string().contains("size value missing"));
    }

    #[test]
    fn parse_size_bytes_overflow() {
        let err = parse_size_bytes("999999999999999gb").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("overflow") || msg.contains("too large") || msg.contains("invalid"));
    }

    // ── parse_fcps_header ───────────────────────────────────────────────

    #[test]
    fn parse_fcps_header_valid() {
        let mut frame = vec![0u8; FCPS_HEADER_LEN];
        frame[0..4].copy_from_slice(b"FCPS");
        frame[106..114].copy_from_slice(&42_u64.to_le_bytes());
        let header = parse_fcps_header(&frame).unwrap();
        assert_eq!(header.frame_seq, 42);
    }

    #[test]
    fn parse_fcps_header_too_short() {
        let frame = vec![0u8; FCPS_HEADER_LEN - 1];
        assert!(parse_fcps_header(&frame).is_none());
    }

    #[test]
    fn parse_fcps_header_wrong_magic() {
        let mut frame = vec![0u8; FCPS_HEADER_LEN];
        frame[0..4].copy_from_slice(b"NOPE");
        assert!(parse_fcps_header(&frame).is_none());
    }

    #[test]
    fn parse_fcps_header_empty() {
        assert!(parse_fcps_header(&[]).is_none());
    }

    #[test]
    fn parse_fcps_header_exact_size() {
        let mut frame = vec![0u8; FCPS_HEADER_LEN];
        frame[0..4].copy_from_slice(b"FCPS");
        frame[106..114].copy_from_slice(&99_u64.to_le_bytes());
        let header = parse_fcps_header(&frame).unwrap();
        assert_eq!(header.frame_seq, 99);
    }

    #[test]
    fn parse_fcps_header_large_seq() {
        let mut frame = vec![0u8; FCPS_HEADER_LEN + 100];
        frame[0..4].copy_from_slice(b"FCPS");
        frame[106..114].copy_from_slice(&u64::MAX.to_le_bytes());
        let header = parse_fcps_header(&frame).unwrap();
        assert_eq!(header.frame_seq, u64::MAX);
    }

    // ── FCPS_HEADER_LEN ────────────────────────────────────────────────

    #[test]
    fn fcps_header_len_is_114() {
        assert_eq!(FCPS_HEADER_LEN, 114);
    }

    // ── BenchmarkResult::placeholder ────────────────────────────────────

    #[test]
    fn placeholder_result_fields() {
        let result = BenchmarkResult::placeholder("test-bench", "not ready");
        assert_eq!(result.name, "test-bench");
        assert_eq!(result.description, "Not yet implemented");
        assert!(result.percentiles.is_none());
        assert_eq!(result.sample_count, 0);
        assert_eq!(result.warmup_count, 0);
        assert_eq!(result.note.as_deref(), Some("not ready"));
        assert!(result.passed.is_none());
        assert!(result.targets.is_none());
    }

    #[test]
    fn placeholder_result_serde_roundtrip() {
        let result = BenchmarkResult::placeholder("bench-x", "pending");
        let json = serde_json::to_string(&result).unwrap();
        let back: BenchmarkResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "bench-x");
        assert_eq!(back.note.as_deref(), Some("pending"));
        assert!(back.percentiles.is_none());
    }

    // ── FcpsHeader clone/copy ───────────────────────────────────────────

    #[test]
    fn fcps_header_clone_copy() {
        let header = FcpsHeader { frame_seq: 7 };
        let cloned = header;
        let copied = cloned;
        assert_eq!(copied.frame_seq, 7);
    }

    // ── normalize_size_label additional ─────────────────────────────────

    #[test]
    fn normalize_size_label_empty_string() {
        assert_eq!(normalize_size_label(""), "");
    }

    #[test]
    fn normalize_size_label_only_whitespace() {
        assert_eq!(normalize_size_label("   "), "");
    }

    #[test]
    fn normalize_size_label_numeric_only() {
        assert_eq!(normalize_size_label("1024"), "1024");
    }

    // ── parse_size_bytes additional boundaries ──────────────────────────

    #[test]
    fn parse_size_bytes_one_byte() {
        assert_eq!(parse_size_bytes("1b").unwrap(), 1);
    }

    #[test]
    fn parse_size_bytes_one_raw() {
        assert_eq!(parse_size_bytes("1").unwrap(), 1);
    }

    #[test]
    fn parse_size_bytes_large_kb() {
        assert_eq!(parse_size_bytes("10_000kb").unwrap(), 10_000 * 1024);
    }

    #[test]
    fn parse_size_bytes_negative_rejected() {
        let err = parse_size_bytes("-1mb").unwrap_err();
        assert!(err.to_string().contains("invalid size value"));
    }

    #[test]
    fn parse_size_bytes_decimal_rejected() {
        let err = parse_size_bytes("1.5mb").unwrap_err();
        assert!(err.to_string().contains("invalid size value"));
    }

    #[test]
    fn parse_size_bytes_only_underscores_in_number() {
        // "___mb" -> number portion is "___", stripped to "" -> "size value missing"
        let err = parse_size_bytes("___mb").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("size value missing") || msg.contains("invalid size value"));
    }

    // ── parse_fcps_header additional ────────────────────────────────────

    #[test]
    fn parse_fcps_header_zero_seq() {
        let mut frame = vec![0u8; FCPS_HEADER_LEN];
        frame[0..4].copy_from_slice(b"FCPS");
        // frame_seq at 106..114 is already 0
        let header = parse_fcps_header(&frame).unwrap();
        assert_eq!(header.frame_seq, 0);
    }

    #[test]
    fn parse_fcps_header_partial_magic() {
        let mut frame = vec![0u8; FCPS_HEADER_LEN];
        frame[0..3].copy_from_slice(b"FCP");
        // 4th byte is 0, not 'S'
        assert!(parse_fcps_header(&frame).is_none());
    }

    #[test]
    fn parse_fcps_header_one_byte_short() {
        let frame = vec![0u8; FCPS_HEADER_LEN - 1];
        assert!(parse_fcps_header(&frame).is_none());
    }

    #[test]
    fn parse_fcps_header_extra_data_after() {
        let mut frame = vec![0xFFu8; FCPS_HEADER_LEN + 1000];
        frame[0..4].copy_from_slice(b"FCPS");
        frame[106..114].copy_from_slice(&1_u64.to_le_bytes());
        let header = parse_fcps_header(&frame).unwrap();
        assert_eq!(header.frame_seq, 1);
    }

    // ── enum variant equality ───────────────────────────────────────────

    #[test]
    fn output_format_equality() {
        assert_eq!(OutputFormat::Json, OutputFormat::Json);
        assert_eq!(OutputFormat::Human, OutputFormat::Human);
        assert_ne!(OutputFormat::Json, OutputFormat::Human);
    }

    #[test]
    fn mesh_path_equality() {
        assert_eq!(MeshPath::Direct, MeshPath::Direct);
        assert_eq!(MeshPath::Derp, MeshPath::Derp);
        assert_ne!(MeshPath::Direct, MeshPath::Derp);
    }

    #[test]
    fn cbor_target_equality() {
        assert_eq!(CborTarget::All, CborTarget::All);
        assert_eq!(CborTarget::SchemaHash, CborTarget::SchemaHash);
        assert_ne!(CborTarget::Serialize, CborTarget::Deserialize);
    }

    #[test]
    fn primitive_target_equality() {
        assert_eq!(PrimitiveTarget::All, PrimitiveTarget::All);
        assert_eq!(PrimitiveTarget::ObjectId, PrimitiveTarget::ObjectId);
        assert_ne!(PrimitiveTarget::SessionMac, PrimitiveTarget::FcpsFrame);
    }

    // ── placeholder with format! name ───────────────────────────────────

    #[test]
    fn placeholder_with_dynamic_name() {
        let k = 3;
        let n = 5;
        let result = BenchmarkResult::placeholder(format!("secrets-{k}-of-{n}"), "not implemented");
        assert_eq!(result.name, "secrets-3-of-5");
    }

    #[test]
    fn placeholder_with_mesh_path_name() {
        for path_name in &["direct", "derp"] {
            let result = BenchmarkResult::placeholder(
                format!("invoke-mesh-{path_name}"),
                "fcp-mesh not yet implemented",
            );
            assert!(result.name.starts_with("invoke-mesh-"));
            assert_eq!(result.sample_count, 0);
        }
    }

    // ── FCPS_HEADER_LEN constant ────────────────────────────────────────

    #[test]
    fn fcps_header_len_matches_field_layout() {
        // Layout: magic(4) + version(2) + flags(2) + symbol_count(4) + payload_len(4)
        // + zone_hash(32) + symbol_size(2) + epoch(8) + object_hash(32) +
        // base_esi(8) + ack_epoch(8) + frame_seq(8) = 114
        let computed = 4 + 2 + 2 + 4 + 4 + 32 + 2 + 8 + 32 + 8 + 8 + 8;
        assert_eq!(FCPS_HEADER_LEN, computed);
    }

    // ════════════════════════════════════════════════════════════════════════
    // Additional BenchmarkResult / BenchmarkReport coverage
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn benchmark_result_new_empty_name() {
        let r = BenchmarkResult::new("", "desc", 1, 0, test_percentiles());
        assert_eq!(r.name, "");
        assert_eq!(r.sample_count, 1);
    }

    #[test]
    fn benchmark_result_new_string_into() {
        let name = "bench-foo".to_string();
        let r = BenchmarkResult::new(name, "desc", 10, 5, test_percentiles());
        assert_eq!(r.name, "bench-foo");
    }

    #[test]
    fn benchmark_result_with_parameters_replaces_empty() {
        let r = BenchmarkResult::new("x", "y", 1, 0, test_percentiles());
        assert!(r.parameters.as_object().unwrap().is_empty());
        let r2 = r.with_parameters(json!({"k": "v"}));
        assert_eq!(r2.parameters["k"], "v");
    }

    #[test]
    fn benchmark_result_with_parameters_chained() {
        let r = BenchmarkResult::new("x", "y", 1, 0, test_percentiles())
            .with_parameters(json!({"a": 1}))
            .with_parameters(json!({"b": 2}));
        // Second call overwrites first (no merge)
        assert_eq!(r.parameters["b"], 2);
        assert!(r.parameters.get("a").is_none());
    }

    #[test]
    fn benchmark_result_targets_stored_correctly() {
        let r = BenchmarkResult::new("x", "y", 1, 0, test_percentiles()).with_targets(Targets {
            p50_target_ms: 3.5,
            p99_target_ms: 7.25,
        });
        let targets = r.targets.unwrap();
        assert!((targets.p50_target_ms - 3.5).abs() < f64::EPSILON);
        assert!((targets.p99_target_ms - 7.25).abs() < f64::EPSILON);
    }

    #[test]
    fn benchmark_result_outliers_detected_default_zero() {
        let r = BenchmarkResult::new("x", "y", 5, 1, test_percentiles());
        assert_eq!(r.outliers_detected, 0);
    }

    #[test]
    fn benchmark_result_outliers_can_be_set() {
        let mut r = BenchmarkResult::new("x", "y", 5, 1, test_percentiles());
        r.outliers_detected = 3;
        assert_eq!(r.outliers_detected, 3);
    }

    #[test]
    fn benchmark_result_note_from_placeholder() {
        let r = BenchmarkResult::placeholder("p", "reason");
        assert!(r.note.is_some());
        assert_eq!(r.note.as_deref(), Some("reason"));
    }

    #[test]
    fn benchmark_result_description_from_placeholder() {
        let r = BenchmarkResult::placeholder("p", "n");
        assert_eq!(r.description, "Not yet implemented");
    }

    #[test]
    fn benchmark_result_warmup_count_preserved() {
        let r = BenchmarkResult::new("x", "y", 50, 25, test_percentiles());
        assert_eq!(r.warmup_count, 25);
        assert_eq!(r.sample_count, 50);
    }

    #[test]
    fn benchmark_report_contains_all_results() {
        let env = EnvironmentInfo {
            os: "linux".to_string(),
            os_version: "6.0".to_string(),
            arch: "x86_64".to_string(),
            cpu_count: 4,
            memory_bytes: None,
            git_commit: None,
            git_branch: None,
            git_dirty: None,
            fcp_version: "0.1.0".to_string(),
            rustc_version: None,
            timestamp: Utc::now(),
        };
        let r1 = BenchmarkResult::placeholder("a", "n1");
        let r2 = BenchmarkResult::placeholder("b", "n2");
        let report = BenchmarkReport::new(env, vec![r1, r2]);
        assert_eq!(report.results.len(), 2);
    }

    #[test]
    fn benchmark_report_clone() {
        let env = EnvironmentInfo {
            os: "test".to_string(),
            os_version: "0".to_string(),
            arch: "x86_64".to_string(),
            cpu_count: 1,
            memory_bytes: None,
            git_commit: None,
            git_branch: None,
            git_dirty: None,
            fcp_version: "0.0.1".to_string(),
            rustc_version: None,
            timestamp: Utc::now(),
        };
        let report = BenchmarkReport::new(env, vec![]);
        let cloned = report.clone();
        assert_eq!(cloned.schema_version, report.schema_version);
        assert_eq!(cloned.environment.os, report.environment.os);
    }

    #[test]
    fn benchmark_report_debug() {
        let env = EnvironmentInfo {
            os: "test".to_string(),
            os_version: "0".to_string(),
            arch: "arm".to_string(),
            cpu_count: 2,
            memory_bytes: None,
            git_commit: None,
            git_branch: None,
            git_dirty: None,
            fcp_version: "0.0.1".to_string(),
            rustc_version: None,
            timestamp: Utc::now(),
        };
        let report = BenchmarkReport::new(env, vec![]);
        let dbg = format!("{report:?}");
        assert!(dbg.contains("BenchmarkReport"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // Percentiles statistics edge cases
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn percentiles_three_elements() {
        let sorted = vec![1_000_000_u64, 5_000_000, 9_000_000]; // 1ms, 5ms, 9ms
        let p = calculate_percentiles(&sorted);
        assert!((p.min_ms - 1.0).abs() < 0.01);
        assert!((p.max_ms - 9.0).abs() < 0.01);
        // Mean = (1+5+9)/3 = 5
        assert!((p.mean_ms - 5.0).abs() < 0.01);
    }

    #[test]
    fn percentiles_large_dataset() {
        let sorted: Vec<u64> = (1..=1000).map(|x| x * 1_000_000).collect();
        let p = calculate_percentiles(&sorted);
        // p50 ~ 500ms, p99 ~ 990ms
        assert!(p.p50_ms > 400.0 && p.p50_ms < 600.0);
        assert!(p.p99_ms > 900.0 && p.p99_ms < 1001.0);
    }

    #[test]
    fn percentiles_stddev_increases_with_spread() {
        let tight: Vec<u64> = (10..=20).map(|x| x * 1_000_000_u64).collect();
        let wide: Vec<u64> = (1..=100).map(|x| x * 1_000_000_u64).collect();
        let p_tight = calculate_percentiles(&tight);
        let p_wide = calculate_percentiles(&wide);
        assert!(p_wide.stddev_ms > p_tight.stddev_ms);
    }

    #[test]
    fn percentiles_min_is_first_element() {
        let sorted = vec![500_000_u64, 1_000_000, 2_000_000];
        let p = calculate_percentiles(&sorted);
        assert!((p.min_ms - 0.5).abs() < 0.001);
    }

    #[test]
    fn percentiles_max_is_last_element() {
        let sorted = vec![500_000_u64, 1_000_000, 2_000_000];
        let p = calculate_percentiles(&sorted);
        assert!((p.max_ms - 2.0).abs() < 0.001);
    }

    // ════════════════════════════════════════════════════════════════════════
    // count_outliers additional coverage
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn count_outliers_exactly_three_returns_zero() {
        let sorted = vec![1_u64, 2, 3];
        assert_eq!(count_outliers(&sorted), 0);
    }

    #[test]
    fn count_outliers_two_extreme_outliers() {
        let mut sorted: Vec<u64> = (100..=200).collect();
        sorted.push(100_000_u64);
        sorted.push(200_000_u64);
        sorted.sort_unstable();
        let outliers = count_outliers(&sorted);
        assert!(outliers >= 2);
    }

    #[test]
    fn count_outliers_all_same_no_outliers() {
        let sorted = vec![42_u64; 10];
        assert_eq!(count_outliers(&sorted), 0);
    }

    // ════════════════════════════════════════════════════════════════════════
    // run_benchmark_with_result additional coverage
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn run_benchmark_with_multiple_warmup_iterations() {
        let mut counter = 0_u32;
        let (p, _) = run_benchmark_with_result(5, 10, || {
            counter += 1;
            counter
        });
        // 5 warmup + 10 measured = 15 total calls
        assert_eq!(counter, 15);
        assert!(p.min_ms >= 0.0);
    }

    #[test]
    fn run_benchmark_percentile_ordering_holds() {
        let (p, _) = run_benchmark_with_result(2, 20, || {
            let mut v = 0_u64;
            for i in 0..50 {
                v = v.wrapping_add(i);
            }
            v
        });
        assert!(p.min_ms <= p.p50_ms);
        assert!(p.p50_ms <= p.p90_ms);
        assert!(p.p90_ms <= p.p95_ms);
        assert!(p.p95_ms <= p.p99_ms);
        assert!(p.p99_ms <= p.max_ms);
    }

    #[test]
    fn run_benchmark_mean_within_range() {
        let (p, _) = run_benchmark_with_result(1, 50, || 7_u32);
        assert!(p.mean_ms >= p.min_ms);
        assert!(p.mean_ms <= p.max_ms);
    }

    // ════════════════════════════════════════════════════════════════════════
    // parse_size_bytes: more boundary and format coverage
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn parse_size_bytes_256b() {
        assert_eq!(parse_size_bytes("256b").unwrap(), 256);
    }

    #[test]
    fn parse_size_bytes_4gb() {
        assert_eq!(parse_size_bytes("4gb").unwrap(), 4 * 1024 * 1024 * 1024);
    }

    #[test]
    fn parse_size_bytes_1kb_case_insensitive() {
        assert_eq!(parse_size_bytes("1KB").unwrap(), 1024);
    }

    #[test]
    fn parse_size_bytes_mixed_underscores() {
        // "1_0kb" -> "10kb"
        assert_eq!(parse_size_bytes("1_0kb").unwrap(), 10 * 1024);
    }

    #[test]
    fn parse_size_bytes_whitespace_only_suffix() {
        // "   " normalizes to "" -> error
        let err = parse_size_bytes("   ").unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn parse_size_bytes_just_b_suffix() {
        // "b" -> number portion is "" -> "size value missing"
        let err = parse_size_bytes("b").unwrap_err();
        assert!(err.to_string().contains("size value missing"));
    }

    #[test]
    fn parse_size_bytes_zero_gb() {
        let err = parse_size_bytes("0gb").unwrap_err();
        assert!(err.to_string().contains("greater than zero"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // Enum equality and Debug traits
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn output_format_debug() {
        let dbg = format!("{:?}", OutputFormat::Json);
        assert!(dbg.contains("Json"));
        let dbg2 = format!("{:?}", OutputFormat::Human);
        assert!(dbg2.contains("Human"));
    }

    #[test]
    fn mesh_path_debug() {
        let dbg = format!("{:?}", MeshPath::Direct);
        assert!(dbg.contains("Direct"));
        let dbg2 = format!("{:?}", MeshPath::Derp);
        assert!(dbg2.contains("Derp"));
    }

    #[test]
    fn cbor_target_debug() {
        let dbg = format!("{:?}", CborTarget::All);
        assert!(dbg.contains("All"));
        let dbg2 = format!("{:?}", CborTarget::Serialize);
        assert!(dbg2.contains("Serialize"));
    }

    #[test]
    fn primitive_target_debug() {
        let dbg = format!("{:?}", PrimitiveTarget::FcpsFrame);
        assert!(dbg.contains("FcpsFrame"));
    }

    #[test]
    fn cbor_target_all_variants_not_equal() {
        assert_ne!(CborTarget::SchemaHash, CborTarget::Serialize);
        assert_ne!(CborTarget::Serialize, CborTarget::Deserialize);
        assert_ne!(CborTarget::Deserialize, CborTarget::All);
    }

    #[test]
    fn primitive_target_all_variants_not_equal() {
        assert_ne!(PrimitiveTarget::ObjectId, PrimitiveTarget::CapabilityVerify);
        assert_ne!(
            PrimitiveTarget::CapabilityVerify,
            PrimitiveTarget::SessionMac
        );
        assert_ne!(PrimitiveTarget::SessionMac, PrimitiveTarget::FcpsFrame);
        assert_ne!(PrimitiveTarget::FcpsFrame, PrimitiveTarget::All);
    }

    // ════════════════════════════════════════════════════════════════════════
    // run_primitives dispatch coverage
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn run_primitives_object_id_returns_one() {
        let results = run_primitives(PrimitiveTarget::ObjectId, 3, 1);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "object-id-derive");
    }

    #[test]
    fn run_primitives_capability_verify_returns_one() {
        let results = run_primitives(PrimitiveTarget::CapabilityVerify, 3, 1);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "capability-verify");
    }

    #[test]
    fn run_primitives_session_mac_returns_one() {
        let results = run_primitives(PrimitiveTarget::SessionMac, 3, 1);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "session-mac-verify");
    }

    #[test]
    fn run_primitives_fcps_frame_returns_one() {
        let results = run_primitives(PrimitiveTarget::FcpsFrame, 3, 1);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "fcps-frame-parse-mac");
    }

    #[test]
    fn run_primitives_all_returns_four() {
        let results = run_primitives(PrimitiveTarget::All, 3, 1);
        assert_eq!(results.len(), 4);
        let names: Vec<&str> = results.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"object-id-derive"));
        assert!(names.contains(&"capability-verify"));
        assert!(names.contains(&"session-mac-verify"));
        assert!(names.contains(&"fcps-frame-parse-mac"));
    }

    #[test]
    fn run_primitives_all_have_percentiles() {
        let results = run_primitives(PrimitiveTarget::All, 3, 1);
        for r in &results {
            assert!(
                r.percentiles.is_some(),
                "missing percentiles for {}",
                r.name
            );
        }
    }

    #[test]
    fn run_primitives_all_have_targets() {
        let results = run_primitives(PrimitiveTarget::All, 3, 1);
        for r in &results {
            assert!(r.targets.is_some(), "missing targets for {}", r.name);
        }
    }

    #[test]
    fn run_primitives_all_have_passed_set() {
        let results = run_primitives(PrimitiveTarget::All, 3, 1);
        for r in &results {
            assert!(r.passed.is_some(), "passed not set for {}", r.name);
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // CBOR benchmark function-level coverage
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn bench_schema_hash_result_name() {
        let result = bench_schema_hash(3, 1);
        assert_eq!(result.name, "cbor-schema-hash");
    }

    #[test]
    fn bench_schema_hash_sample_count_matches() {
        let result = bench_schema_hash(7, 1);
        assert_eq!(result.sample_count, 7);
        assert_eq!(result.warmup_count, 1);
    }

    #[test]
    fn bench_serialize_small_result_name() {
        let result = bench_serialize_small(3, 1);
        assert_eq!(result.name, "cbor-serialize-small");
    }

    #[test]
    fn bench_serialize_medium_result_name() {
        let result = bench_serialize_medium(3, 1);
        assert_eq!(result.name, "cbor-serialize-medium");
    }

    #[test]
    fn bench_deserialize_small_result_name() {
        let result = bench_deserialize_small(3, 1);
        assert_eq!(result.name, "cbor-deserialize-small");
    }

    #[test]
    fn bench_deserialize_medium_result_name() {
        let result = bench_deserialize_medium(3, 1);
        assert_eq!(result.name, "cbor-deserialize-medium");
    }

    #[test]
    fn cbor_benchmarks_parameters_include_object_type() {
        let r = bench_serialize_small(3, 1);
        assert_eq!(r.parameters["object_type"], "SmallObject");
        assert_eq!(r.parameters["fields"], 3);
    }

    #[test]
    fn cbor_benchmarks_medium_parameters_include_fields() {
        let r = bench_serialize_medium(3, 1);
        assert_eq!(r.parameters["fields"], 9);
    }

    #[test]
    fn bench_schema_hash_parameters_include_schema_string() {
        let r = bench_schema_hash(3, 1);
        let schema_param = r.parameters["schema"].as_str().unwrap();
        assert!(schema_param.contains("fcp.bench"));
        assert!(schema_param.contains("TestObject"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // Environment fields completeness
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn environment_info_clone() {
        let env = EnvironmentInfo {
            os: "linux".to_string(),
            os_version: "6.0".to_string(),
            arch: "x86_64".to_string(),
            cpu_count: 4,
            memory_bytes: Some(8_000_000_000),
            git_commit: Some("abc".to_string()),
            git_branch: Some("main".to_string()),
            git_dirty: Some(false),
            fcp_version: "0.1.0".to_string(),
            rustc_version: Some("1.85.0".to_string()),
            timestamp: Utc::now(),
        };
        let cloned = env.clone();
        assert_eq!(cloned.os, env.os);
        assert_eq!(cloned.cpu_count, env.cpu_count);
        assert_eq!(cloned.memory_bytes, env.memory_bytes);
    }

    #[test]
    fn environment_info_debug() {
        let env = EnvironmentInfo {
            os: "test".to_string(),
            os_version: "0".to_string(),
            arch: "x86_64".to_string(),
            cpu_count: 1,
            memory_bytes: None,
            git_commit: None,
            git_branch: None,
            git_dirty: None,
            fcp_version: "0.0.1".to_string(),
            rustc_version: None,
            timestamp: Utc::now(),
        };
        let dbg = format!("{env:?}");
        assert!(dbg.contains("EnvironmentInfo"));
    }

    #[test]
    fn targets_clone() {
        let t = Targets {
            p50_target_ms: 1.0,
            p99_target_ms: 5.0,
        };
        let cloned = t.clone();
        assert!((cloned.p50_target_ms - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn targets_debug() {
        let t = Targets {
            p50_target_ms: 1.0,
            p99_target_ms: 5.0,
        };
        let dbg = format!("{t:?}");
        assert!(dbg.contains("Targets"));
        assert!(dbg.contains("p50_target_ms"));
    }

    #[test]
    fn benchmark_result_debug() {
        let r = BenchmarkResult::placeholder("p", "n");
        let dbg = format!("{r:?}");
        assert!(dbg.contains("BenchmarkResult"));
    }

    #[test]
    fn benchmark_result_clone() {
        let r = BenchmarkResult::new("x", "y", 1, 0, test_percentiles())
            .with_parameters(json!({"key": "val"}));
        let cloned = r.clone();
        assert_eq!(cloned.name, r.name);
        assert_eq!(cloned.parameters["key"], "val");
    }

    // ── CUAL benchmark tests ────────────────────────────────────────

    #[test]
    fn bench_search_index_result_name() {
        let r = bench_search_index(100, 5, 2);
        assert_eq!(r.name, "search-index-build-100");
        assert!(r.sample_count > 0);
        assert!(r.percentiles.is_some());
    }

    #[test]
    fn bench_search_index_parameters() {
        let r = bench_search_index(200, 5, 2);
        assert_eq!(r.parameters["operations"], 200);
    }

    #[test]
    fn bench_search_query_result_name() {
        let r = bench_search_query(100, 5, 2);
        assert_eq!(r.name, "search-query-100");
        assert!(r.sample_count > 0);
    }

    #[test]
    fn bench_search_query_has_targets() {
        let r = bench_search_query(500, 5, 2);
        assert!(r.targets.is_some());
        assert!(r.passed.is_some());
    }

    #[test]
    fn bench_batch_throughput_result_name() {
        let r = bench_batch_throughput(50, 5, 2);
        assert_eq!(r.name, "batch-throughput-50");
    }

    #[test]
    fn bench_batch_throughput_parameters() {
        let r = bench_batch_throughput(100, 5, 2);
        assert_eq!(r.parameters["items"], 100);
    }

    #[test]
    fn bench_mcp_tool_list_result_name() {
        let r = bench_mcp_tool_list(50, 5, 2);
        assert_eq!(r.name, "mcp-tool-list-50");
    }

    #[test]
    fn bench_mcp_tool_list_parameters() {
        let r = bench_mcp_tool_list(100, 5, 2);
        assert_eq!(r.parameters["connectors"], 100);
        assert_eq!(r.parameters["tools"], 300);
    }

    #[test]
    fn bench_mcp_tool_route_result_name() {
        let r = bench_mcp_tool_route(100, 5, 2);
        assert_eq!(r.name, "mcp-tool-route-100");
    }

    #[test]
    fn bench_mcp_tool_route_has_percentiles() {
        let r = bench_mcp_tool_route(50, 5, 2);
        assert!(r.percentiles.is_some());
    }

    #[test]
    fn bench_pipeline_setup_result_name() {
        let r = bench_pipeline_setup(10, 5, 2);
        assert_eq!(r.name, "pipeline-setup-10");
    }

    #[test]
    fn bench_pipeline_setup_parameters() {
        let r = bench_pipeline_setup(20, 5, 2);
        assert_eq!(r.parameters["steps"], 20);
    }

    #[test]
    fn bench_pipeline_setup_has_targets() {
        let r = bench_pipeline_setup(10, 5, 2);
        assert!(r.targets.is_some());
    }

    #[test]
    fn cual_benchmarks_all_serialize() {
        let benchmarks = vec![
            bench_search_index(10, 3, 1),
            bench_search_query(10, 3, 1),
            bench_batch_throughput(10, 3, 1),
            bench_mcp_tool_list(10, 3, 1),
            bench_mcp_tool_route(10, 3, 1),
            bench_pipeline_setup(5, 3, 1),
        ];
        for b in &benchmarks {
            let json = serde_json::to_string(b).unwrap();
            assert!(json.contains(&b.name));
        }
    }
}
