//! Export formats for telemetry data.
//!
//! Supports Prometheus exposition format and OTLP export.

use std::{
    io::{self, BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::OnceLock,
    thread,
    time::Duration,
};

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
#[cfg(feature = "otlp")]
use opentelemetry::KeyValue;
#[cfg(feature = "otlp")]
use opentelemetry_otlp::{WithExportConfig, WithTonicConfig};
#[cfg(feature = "otlp")]
use opentelemetry_sdk::{
    Resource,
    error::{OTelSdkError, OTelSdkResult},
    logs::{LogBatch, LogExporter, SdkLoggerProvider},
    metrics::{SdkMeterProvider, data::ResourceMetrics, exporter::PushMetricExporter},
    trace::{RandomIdGenerator, Sampler, SdkTracerProvider, SpanData, SpanExporter},
};

use crate::{
    OtlpHeader, OtlpResourceAttribute, TelemetryError, validate_otlp_endpoint,
    validate_otlp_headers, validate_otlp_resource_attributes,
};

static PROMETHEUS_HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();
#[cfg(feature = "otlp")]
static OTLP_TRACER_PROVIDER: OnceLock<SdkTracerProvider> = OnceLock::new();
#[cfg(feature = "otlp")]
static OTLP_METER_PROVIDER: OnceLock<SdkMeterProvider> = OnceLock::new();
#[cfg(feature = "otlp")]
static OTLP_LOGGER_PROVIDER: OnceLock<SdkLoggerProvider> = OnceLock::new();

/// Explicit OTLP retry/backoff policy for transient collector export failures.
///
/// The OpenTelemetry SDK delegates retry behavior to exporters, so the default
/// fcp-telemetry init path keeps one-attempt behavior unless callers select one
/// of the `*_and_retry` initializers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OtlpRetryPolicy {
    /// Total export attempts, including the first attempt.
    pub max_attempts: u8,

    /// Backoff before the first retry attempt.
    pub initial_backoff: Duration,

    /// Maximum backoff between retry attempts.
    pub max_backoff: Duration,
}

impl OtlpRetryPolicy {
    /// Disable retry behavior while still documenting the one-attempt policy.
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            max_attempts: 1,
            initial_backoff: Duration::ZERO,
            max_backoff: Duration::ZERO,
        }
    }

    /// Build a bounded retry policy.
    #[must_use]
    pub const fn new(max_attempts: u8, initial_backoff: Duration, max_backoff: Duration) -> Self {
        Self {
            max_attempts,
            initial_backoff,
            max_backoff,
        }
    }

    const fn is_enabled(self) -> bool {
        self.max_attempts > 1
    }
}

#[cfg(feature = "otlp")]
impl OtlpRetryPolicy {
    fn should_retry(self, attempt: u8, error: &OTelSdkError) -> bool {
        self.is_enabled()
            && attempt < self.max_attempts
            && classify_retryable_otlp_error(error).is_some()
    }

    fn next_backoff(self, current: Duration) -> Duration {
        current.saturating_mul(2).min(self.max_backoff)
    }
}

/// Initialize the Prometheus metrics exporter.
///
/// This starts an HTTP server on the specified port that exposes metrics
/// in Prometheus exposition format at `/metrics`.
///
/// # Errors
/// Returns `TelemetryError::MetricsInit` if the exporter cannot be started.
pub fn init_prometheus_exporter(port: u16) -> Result<(), TelemetryError> {
    let addr: SocketAddr = ([0, 0, 0, 0], port).into();
    let listener =
        TcpListener::bind(addr).map_err(|e| TelemetryError::MetricsInit(e.to_string()))?;
    let handle = PrometheusBuilder::new()
        .install_recorder()
        .map_err(|e| TelemetryError::MetricsInit(e.to_string()))?;
    let server_handle = handle.clone();
    thread::Builder::new()
        .name(format!("fcp-telemetry-prometheus-{port}"))
        .spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        if let Err(error) = serve_prometheus_connection(stream, &server_handle) {
                            tracing::warn!(?error, "Prometheus scrape failed");
                        }
                    }
                    Err(error) => {
                        tracing::warn!(?error, "Prometheus listener accept failed");
                    }
                }
            }
        })
        .map_err(|e| TelemetryError::MetricsInit(e.to_string()))?;

    let _ = PROMETHEUS_HANDLE.set(handle);

    tracing::info!(port = port, "Prometheus metrics exporter started");

    Ok(())
}

/// Initialize the OTLP trace exporter with a fixed `AlwaysOn` sampler.
///
/// Kept for backward compatibility. New callers should use
/// [`init_otlp_tracer_with_sample_rate`] so the
/// [`TelemetryConfig::trace_sample_rate`](crate::TelemetryConfig::trace_sample_rate)
/// actually reaches the SDK. Historically this function ignored the
/// configured sample rate entirely, so a service configured with
/// `with_sample_rate(0.01)` still exported 100% of spans — the opposite
/// of what the operator asked for, and a material cost/PII-volume
/// regression on hot paths.
///
/// # Errors
/// Returns `TelemetryError::TracingInit` if the exporter cannot be initialized.
pub fn init_otlp_tracer(service_name: &str, endpoint: &str) -> Result<(), TelemetryError> {
    init_otlp_tracer_with_sample_rate(service_name, endpoint, 1.0)
}

/// Initialize the OTLP trace exporter with a configurable head-sampling rate.
///
/// `sample_rate` is clamped to `[0.0, 1.0]`. The sampler honors upstream
/// sampling decisions carried in `traceparent` (parent-based wrapper),
/// so a service behaving as a downstream node follows whatever the
/// edge decided rather than re-rolling the dice per hop.
///
/// Special-cases:
/// * rate >= 1.0 → `Sampler::AlwaysOn` (no per-span RNG, matches the
///   historical default).
/// * rate <= 0.0 → `Sampler::AlwaysOff` (exports nothing; local spans
///   still run but no OTLP traffic is generated).
/// * otherwise → `ParentBased(TraceIdRatioBased(rate))`.
///
/// # Errors
/// Returns `TelemetryError::TracingInit` if the exporter cannot be initialized.
pub fn init_otlp_tracer_with_sample_rate(
    service_name: &str,
    endpoint: &str,
    sample_rate: f64,
) -> Result<(), TelemetryError> {
    init_otlp_tracer_with_sample_rate_and_options(service_name, endpoint, sample_rate, &[], &[])
}

/// Initialize the OTLP trace exporter with collector headers and resource attributes.
///
/// Header values are only used to configure the exporter and are never emitted
/// in diagnostics from this crate.
///
/// # Errors
/// Returns [`TelemetryError::Config`] for malformed OTLP settings, or
/// [`TelemetryError::TracingInit`] if the exporter cannot be initialized.
pub fn init_otlp_tracer_with_sample_rate_and_options(
    service_name: &str,
    endpoint: &str,
    sample_rate: f64,
    headers: &[OtlpHeader],
    resource_attributes: &[OtlpResourceAttribute],
) -> Result<(), TelemetryError> {
    init_otlp_tracer_with_sample_rate_options_and_timeout(
        service_name,
        endpoint,
        sample_rate,
        headers,
        resource_attributes,
        None,
    )
}

/// Initialize the OTLP trace exporter with collector headers, resource attributes,
/// and an optional collector RPC timeout.
///
/// This is primarily useful for e2e/failure probes and host integrations that need
/// bounded unavailable-collector behavior instead of relying on SDK defaults.
///
/// Header values are only used to configure the exporter and are never emitted
/// in diagnostics from this crate.
///
/// # Errors
/// Returns [`TelemetryError::Config`] for malformed OTLP settings, or
/// [`TelemetryError::TracingInit`] if the exporter cannot be initialized.
pub fn init_otlp_tracer_with_sample_rate_options_and_timeout(
    service_name: &str,
    endpoint: &str,
    sample_rate: f64,
    headers: &[OtlpHeader],
    resource_attributes: &[OtlpResourceAttribute],
    export_timeout: Option<Duration>,
) -> Result<(), TelemetryError> {
    validate_otlp_endpoint(endpoint)?;
    validate_otlp_headers(headers)?;
    validate_otlp_resource_attributes(resource_attributes)?;
    validate_otlp_export_timeout(export_timeout)?;
    validate_otlp_retry_policy(OtlpRetryPolicy::disabled())?;
    init_otlp_tracer_with_sample_rate_impl(
        service_name,
        endpoint,
        sample_rate,
        headers,
        resource_attributes,
        export_timeout,
        OtlpRetryPolicy::disabled(),
    )
}

/// Initialize the OTLP trace exporter with an explicit retry/backoff policy.
///
/// This keeps the default SDK one-attempt behavior opt-in stable while allowing
/// host integrations and e2e probes to prove bounded retry behavior for
/// transient collector failures.
///
/// # Errors
/// Returns [`TelemetryError::Config`] for malformed OTLP settings or retry
/// policy, or [`TelemetryError::TracingInit`] if the exporter cannot be
/// initialized.
pub fn init_otlp_tracer_with_sample_rate_options_timeout_and_retry(
    service_name: &str,
    endpoint: &str,
    sample_rate: f64,
    headers: &[OtlpHeader],
    resource_attributes: &[OtlpResourceAttribute],
    export_timeout: Option<Duration>,
    retry_policy: OtlpRetryPolicy,
) -> Result<(), TelemetryError> {
    validate_otlp_endpoint(endpoint)?;
    validate_otlp_headers(headers)?;
    validate_otlp_resource_attributes(resource_attributes)?;
    validate_otlp_export_timeout(export_timeout)?;
    validate_otlp_retry_policy(retry_policy)?;
    init_otlp_tracer_with_sample_rate_impl(
        service_name,
        endpoint,
        sample_rate,
        headers,
        resource_attributes,
        export_timeout,
        retry_policy,
    )
}

/// Initialize the OTLP metrics exporter with collector headers and resource attributes.
///
/// Header values are only used to configure the exporter and are never emitted
/// in diagnostics from this crate.
///
/// # Errors
/// Returns [`TelemetryError::Config`] for malformed OTLP settings, or
/// [`TelemetryError::MetricsInit`] if the exporter cannot be initialized.
pub fn init_otlp_metrics_with_options(
    service_name: &str,
    endpoint: &str,
    headers: &[OtlpHeader],
    resource_attributes: &[OtlpResourceAttribute],
) -> Result<(), TelemetryError> {
    init_otlp_metrics_with_options_and_timeout(
        service_name,
        endpoint,
        headers,
        resource_attributes,
        None,
    )
}

/// Initialize the OTLP metrics exporter with an optional collector RPC timeout.
///
/// This installs an OpenTelemetry SDK meter provider. Callers can then emit
/// metrics through `opentelemetry::global::meter(...)` and use
/// [`flush_otlp_metrics`] to force an export before shutdown.
///
/// # Errors
/// Returns [`TelemetryError::Config`] for malformed OTLP settings, or
/// [`TelemetryError::MetricsInit`] if the exporter cannot be initialized.
pub fn init_otlp_metrics_with_options_and_timeout(
    service_name: &str,
    endpoint: &str,
    headers: &[OtlpHeader],
    resource_attributes: &[OtlpResourceAttribute],
    export_timeout: Option<Duration>,
) -> Result<(), TelemetryError> {
    validate_otlp_endpoint(endpoint)?;
    validate_otlp_headers(headers)?;
    validate_otlp_resource_attributes(resource_attributes)?;
    validate_otlp_export_timeout(export_timeout)?;
    validate_otlp_retry_policy(OtlpRetryPolicy::disabled())?;
    init_otlp_metrics_with_options_impl(
        service_name,
        endpoint,
        headers,
        resource_attributes,
        export_timeout,
        OtlpRetryPolicy::disabled(),
    )
}

/// Initialize the OTLP metrics exporter with an explicit retry/backoff policy.
///
/// # Errors
/// Returns [`TelemetryError::Config`] for malformed OTLP settings or retry
/// policy, or [`TelemetryError::MetricsInit`] if the exporter cannot be
/// initialized.
pub fn init_otlp_metrics_with_options_timeout_and_retry(
    service_name: &str,
    endpoint: &str,
    headers: &[OtlpHeader],
    resource_attributes: &[OtlpResourceAttribute],
    export_timeout: Option<Duration>,
    retry_policy: OtlpRetryPolicy,
) -> Result<(), TelemetryError> {
    validate_otlp_endpoint(endpoint)?;
    validate_otlp_headers(headers)?;
    validate_otlp_resource_attributes(resource_attributes)?;
    validate_otlp_export_timeout(export_timeout)?;
    validate_otlp_retry_policy(retry_policy)?;
    init_otlp_metrics_with_options_impl(
        service_name,
        endpoint,
        headers,
        resource_attributes,
        export_timeout,
        retry_policy,
    )
}

/// Initialize the OTLP logs exporter with collector headers and resource attributes.
///
/// Header values are only used to configure the exporter and are never emitted
/// in diagnostics from this crate. Once initialized, [`init_logging`](crate::init_logging)
/// installs a tracing bridge layer that exports `tracing` events as OTLP logs.
///
/// # Errors
/// Returns [`TelemetryError::Config`] for malformed OTLP settings, or
/// [`TelemetryError::LoggingInit`] if the exporter cannot be initialized.
pub fn init_otlp_logs_with_options(
    service_name: &str,
    endpoint: &str,
    headers: &[OtlpHeader],
    resource_attributes: &[OtlpResourceAttribute],
) -> Result<(), TelemetryError> {
    init_otlp_logs_with_options_and_timeout(
        service_name,
        endpoint,
        headers,
        resource_attributes,
        None,
    )
}

/// Initialize the OTLP logs exporter with an optional collector RPC timeout.
///
/// This installs an OpenTelemetry SDK logger provider. Callers should initialize
/// this before installing the tracing subscriber so `init_logging` can attach
/// the tracing-to-OpenTelemetry log bridge.
///
/// # Errors
/// Returns [`TelemetryError::Config`] for malformed OTLP settings, or
/// [`TelemetryError::LoggingInit`] if the exporter cannot be initialized.
pub fn init_otlp_logs_with_options_and_timeout(
    service_name: &str,
    endpoint: &str,
    headers: &[OtlpHeader],
    resource_attributes: &[OtlpResourceAttribute],
    export_timeout: Option<Duration>,
) -> Result<(), TelemetryError> {
    validate_otlp_endpoint(endpoint)?;
    validate_otlp_headers(headers)?;
    validate_otlp_resource_attributes(resource_attributes)?;
    validate_otlp_export_timeout(export_timeout)?;
    validate_otlp_retry_policy(OtlpRetryPolicy::disabled())?;
    init_otlp_logs_with_options_impl(
        service_name,
        endpoint,
        headers,
        resource_attributes,
        export_timeout,
        OtlpRetryPolicy::disabled(),
    )
}

/// Initialize the OTLP logs exporter with an explicit retry/backoff policy.
///
/// # Errors
/// Returns [`TelemetryError::Config`] for malformed OTLP settings or retry
/// policy, or [`TelemetryError::LoggingInit`] if the exporter cannot be
/// initialized.
pub fn init_otlp_logs_with_options_timeout_and_retry(
    service_name: &str,
    endpoint: &str,
    headers: &[OtlpHeader],
    resource_attributes: &[OtlpResourceAttribute],
    export_timeout: Option<Duration>,
    retry_policy: OtlpRetryPolicy,
) -> Result<(), TelemetryError> {
    validate_otlp_endpoint(endpoint)?;
    validate_otlp_headers(headers)?;
    validate_otlp_resource_attributes(resource_attributes)?;
    validate_otlp_export_timeout(export_timeout)?;
    validate_otlp_retry_policy(retry_policy)?;
    init_otlp_logs_with_options_impl(
        service_name,
        endpoint,
        headers,
        resource_attributes,
        export_timeout,
        retry_policy,
    )
}

fn validate_otlp_export_timeout(export_timeout: Option<Duration>) -> Result<(), TelemetryError> {
    if export_timeout.is_some_and(|timeout| timeout.is_zero()) {
        return Err(TelemetryError::Config(
            "OTLP export timeout must be greater than zero".to_string(),
        ));
    }
    Ok(())
}

fn validate_otlp_retry_policy(retry_policy: OtlpRetryPolicy) -> Result<(), TelemetryError> {
    if retry_policy.max_attempts == 0 {
        return Err(TelemetryError::Config(
            "OTLP retry max_attempts must be greater than zero".to_string(),
        ));
    }
    if retry_policy.max_attempts > 8 {
        return Err(TelemetryError::Config(
            "OTLP retry max_attempts must be 8 or less".to_string(),
        ));
    }
    if retry_policy.is_enabled() && retry_policy.initial_backoff.is_zero() {
        return Err(TelemetryError::Config(
            "OTLP retry initial_backoff must be greater than zero when retries are enabled"
                .to_string(),
        ));
    }
    if retry_policy.max_backoff < retry_policy.initial_backoff {
        return Err(TelemetryError::Config(
            "OTLP retry max_backoff must be greater than or equal to initial_backoff".to_string(),
        ));
    }
    Ok(())
}

#[cfg(feature = "otlp")]
pub fn otlp_logger_provider() -> Option<SdkLoggerProvider> {
    OTLP_LOGGER_PROVIDER.get().cloned()
}

#[cfg(feature = "otlp")]
fn init_otlp_tracer_with_sample_rate_impl(
    service_name: &str,
    endpoint: &str,
    sample_rate: f64,
    headers: &[OtlpHeader],
    resource_attributes: &[OtlpResourceAttribute],
    export_timeout: Option<Duration>,
    retry_policy: OtlpRetryPolicy,
) -> Result<(), TelemetryError> {
    let mut exporter_builder = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint);

    if let Some(timeout) = export_timeout {
        exporter_builder = exporter_builder.with_timeout(timeout);
    }

    if !headers.is_empty() {
        exporter_builder = exporter_builder.with_metadata(otlp_metadata_from_headers(headers)?);
    }

    let exporter = exporter_builder
        .build()
        .map_err(|e| TelemetryError::TracingInit(e.to_string()))?;
    let exporter = RetryingSpanExporter::new(exporter, retry_policy);

    let resource = otlp_resource(service_name, resource_attributes);

    // NaN maps to AlwaysOff (clamp + compare: NaN != NaN so both
    // `>= 1.0` and `<= 0.0` are false, but we want fail-safe behavior
    // — an insane input must not silently default to AlwaysOn).
    let clamped = if sample_rate.is_nan() {
        0.0
    } else {
        sample_rate.clamp(0.0, 1.0)
    };
    let sampler = if clamped >= 1.0 {
        Sampler::AlwaysOn
    } else if clamped <= 0.0 {
        Sampler::AlwaysOff
    } else {
        Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(clamped)))
    };

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_sampler(sampler)
        .with_id_generator(RandomIdGenerator::default())
        .with_resource(resource)
        .build();

    opentelemetry::global::set_tracer_provider(provider.clone());
    let _ = OTLP_TRACER_PROVIDER.set(provider);

    tracing::info!(
        endpoint = %otlp_endpoint_log_label(endpoint),
        sample_rate = clamped,
        collector_header_count = headers.len(),
        resource_attribute_count = resource_attributes.len(),
        export_timeout_ms = export_timeout.map(|timeout| timeout.as_millis()),
        "OTLP trace exporter initialized"
    );

    Ok(())
}

#[cfg(feature = "otlp")]
fn init_otlp_logs_with_options_impl(
    service_name: &str,
    endpoint: &str,
    headers: &[OtlpHeader],
    resource_attributes: &[OtlpResourceAttribute],
    export_timeout: Option<Duration>,
    retry_policy: OtlpRetryPolicy,
) -> Result<(), TelemetryError> {
    let mut exporter_builder = opentelemetry_otlp::LogExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint);

    if let Some(timeout) = export_timeout {
        exporter_builder = exporter_builder.with_timeout(timeout);
    }

    if !headers.is_empty() {
        exporter_builder = exporter_builder.with_metadata(otlp_metadata_from_headers(headers)?);
    }

    let exporter = exporter_builder
        .build()
        .map_err(|e| TelemetryError::LoggingInit(e.to_string()))?;
    let exporter = RetryingLogExporter::new(exporter, retry_policy);
    let provider = SdkLoggerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(otlp_resource(service_name, resource_attributes))
        .build();

    let _ = OTLP_LOGGER_PROVIDER.set(provider);

    tracing::info!(
        endpoint = %otlp_endpoint_log_label(endpoint),
        collector_header_count = headers.len(),
        resource_attribute_count = resource_attributes.len(),
        export_timeout_ms = export_timeout.map(|timeout| timeout.as_millis()),
        "OTLP logs exporter initialized"
    );

    Ok(())
}

#[cfg(feature = "otlp")]
fn init_otlp_metrics_with_options_impl(
    service_name: &str,
    endpoint: &str,
    headers: &[OtlpHeader],
    resource_attributes: &[OtlpResourceAttribute],
    export_timeout: Option<Duration>,
    retry_policy: OtlpRetryPolicy,
) -> Result<(), TelemetryError> {
    let mut exporter_builder = opentelemetry_otlp::MetricExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint);

    if let Some(timeout) = export_timeout {
        exporter_builder = exporter_builder.with_timeout(timeout);
    }

    if !headers.is_empty() {
        exporter_builder = exporter_builder.with_metadata(otlp_metadata_from_headers(headers)?);
    }

    let exporter = exporter_builder
        .build()
        .map_err(|e| TelemetryError::MetricsInit(e.to_string()))?;
    let exporter = RetryingMetricExporter::new(exporter, retry_policy);
    let provider = SdkMeterProvider::builder()
        .with_periodic_exporter(exporter)
        .with_resource(otlp_resource(service_name, resource_attributes))
        .build();

    opentelemetry::global::set_meter_provider(provider.clone());
    let _ = OTLP_METER_PROVIDER.set(provider);

    tracing::info!(
        endpoint = %otlp_endpoint_log_label(endpoint),
        collector_header_count = headers.len(),
        resource_attribute_count = resource_attributes.len(),
        export_timeout_ms = export_timeout.map(|timeout| timeout.as_millis()),
        "OTLP metrics exporter initialized"
    );

    Ok(())
}

#[cfg(feature = "otlp")]
#[derive(Debug)]
struct RetryingSpanExporter {
    inner: opentelemetry_otlp::SpanExporter,
    retry_policy: OtlpRetryPolicy,
}

#[cfg(feature = "otlp")]
impl RetryingSpanExporter {
    const fn new(inner: opentelemetry_otlp::SpanExporter, retry_policy: OtlpRetryPolicy) -> Self {
        Self {
            inner,
            retry_policy,
        }
    }
}

#[cfg(feature = "otlp")]
impl SpanExporter for RetryingSpanExporter {
    async fn export(&self, batch: Vec<SpanData>) -> OTelSdkResult {
        let mut attempt = 1;
        let mut backoff = self.retry_policy.initial_backoff;
        loop {
            let result = self.inner.export(batch.clone()).await;
            match result {
                Ok(()) => return Ok(()),
                Err(error) if self.retry_policy.should_retry(attempt, &error) => {
                    let error_kind = classify_retryable_otlp_error(&error).unwrap_or("unknown");
                    tracing::warn!(
                        attempt,
                        max_attempts = self.retry_policy.max_attempts,
                        backoff_ms = backoff.as_millis(),
                        error_kind,
                        "Retrying OTLP trace export after transient collector failure"
                    );
                    fcp_async_core::time::sleep(backoff).await;
                    attempt = attempt.saturating_add(1);
                    backoff = self.retry_policy.next_backoff(backoff);
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn set_resource(&mut self, resource: &Resource) {
        self.inner.set_resource(resource);
    }
}

#[cfg(feature = "otlp")]
#[derive(Debug)]
struct RetryingMetricExporter {
    inner: opentelemetry_otlp::MetricExporter,
    retry_policy: OtlpRetryPolicy,
}

#[cfg(feature = "otlp")]
impl RetryingMetricExporter {
    const fn new(inner: opentelemetry_otlp::MetricExporter, retry_policy: OtlpRetryPolicy) -> Self {
        Self {
            inner,
            retry_policy,
        }
    }
}

#[cfg(feature = "otlp")]
impl PushMetricExporter for RetryingMetricExporter {
    async fn export(&self, metrics: &ResourceMetrics) -> OTelSdkResult {
        let mut attempt = 1;
        let mut backoff = self.retry_policy.initial_backoff;
        loop {
            let result = self.inner.export(metrics).await;
            match result {
                Ok(()) => return Ok(()),
                Err(error) if self.retry_policy.should_retry(attempt, &error) => {
                    let error_kind = classify_retryable_otlp_error(&error).unwrap_or("unknown");
                    tracing::warn!(
                        attempt,
                        max_attempts = self.retry_policy.max_attempts,
                        backoff_ms = backoff.as_millis(),
                        error_kind,
                        "Retrying OTLP metric export after transient collector failure"
                    );
                    fcp_async_core::time::sleep(backoff).await;
                    attempt = attempt.saturating_add(1);
                    backoff = self.retry_policy.next_backoff(backoff);
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn force_flush(&self) -> OTelSdkResult {
        self.inner.force_flush()
    }

    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        self.inner.shutdown_with_timeout(timeout)
    }

    fn temporality(&self) -> opentelemetry_sdk::metrics::Temporality {
        self.inner.temporality()
    }
}

#[cfg(feature = "otlp")]
#[derive(Debug)]
struct RetryingLogExporter {
    inner: opentelemetry_otlp::LogExporter,
    retry_policy: OtlpRetryPolicy,
}

#[cfg(feature = "otlp")]
impl RetryingLogExporter {
    const fn new(inner: opentelemetry_otlp::LogExporter, retry_policy: OtlpRetryPolicy) -> Self {
        Self {
            inner,
            retry_policy,
        }
    }
}

#[cfg(feature = "otlp")]
impl LogExporter for RetryingLogExporter {
    async fn export(&self, batch: LogBatch<'_>) -> OTelSdkResult {
        let records: Vec<_> = batch.iter().collect();
        let mut attempt = 1;
        let mut backoff = self.retry_policy.initial_backoff;
        loop {
            let result = self.inner.export(LogBatch::new(&records)).await;
            match result {
                Ok(()) => return Ok(()),
                Err(error) if self.retry_policy.should_retry(attempt, &error) => {
                    let error_kind = classify_retryable_otlp_error(&error).unwrap_or("unknown");
                    tracing::warn!(
                        attempt,
                        max_attempts = self.retry_policy.max_attempts,
                        backoff_ms = backoff.as_millis(),
                        error_kind,
                        "Retrying OTLP log export after transient collector failure"
                    );
                    fcp_async_core::time::sleep(backoff).await;
                    attempt = attempt.saturating_add(1);
                    backoff = self.retry_policy.next_backoff(backoff);
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        self.inner.shutdown_with_timeout(timeout)
    }

    fn set_resource(&mut self, resource: &Resource) {
        self.inner.set_resource(resource);
    }
}

#[cfg(feature = "otlp")]
fn classify_retryable_otlp_error(error: &OTelSdkError) -> Option<&'static str> {
    match error {
        OTelSdkError::Timeout(_) => Some("timeout"),
        OTelSdkError::InternalFailure(message) => {
            let message = message.to_ascii_lowercase();
            if message.contains("unavailable") {
                Some("unavailable")
            } else if message.contains("resource exhausted")
                || message.contains("resource_exhausted")
                || message.contains("resource has been exhausted")
            {
                Some("resource_exhausted")
            } else if message.contains("deadline exceeded") || message.contains("deadline_exceeded")
            {
                Some("deadline_exceeded")
            } else {
                None
            }
        }
        OTelSdkError::AlreadyShutdown => None,
    }
}

/// Force-flush the installed OTLP logger provider, if one has been installed.
///
/// # Errors
///
/// Returns [`TelemetryError::LoggingInit`] if the SDK reports a flush failure.
#[cfg(feature = "otlp")]
pub fn flush_otlp_logs() -> Result<(), TelemetryError> {
    if let Some(provider) = OTLP_LOGGER_PROVIDER.get() {
        provider.force_flush().map_err(|e| {
            TelemetryError::LoggingInit(format!("OTLP logs force_flush failed: {e}"))
        })?;
    }
    Ok(())
}

/// Force-flush the installed OTLP logger provider, if one has been installed.
///
/// # Errors
///
/// This build has no OTLP provider, so flushing is a no-op.
#[cfg(not(feature = "otlp"))]
pub const fn flush_otlp_logs() -> Result<(), TelemetryError> {
    Ok(())
}

/// Shut down the installed OTLP logger provider, if one has been installed.
///
/// # Errors
///
/// Returns [`TelemetryError::LoggingInit`] if the SDK reports a shutdown failure.
#[cfg(feature = "otlp")]
pub fn shutdown_otlp_logs() -> Result<(), TelemetryError> {
    if let Some(provider) = OTLP_LOGGER_PROVIDER.get() {
        provider
            .shutdown()
            .map_err(|e| TelemetryError::LoggingInit(format!("OTLP logs shutdown failed: {e}")))?;
    }
    Ok(())
}

/// Shut down the installed OTLP logger provider, if one has been installed.
///
/// # Errors
///
/// This build has no OTLP provider, so shutdown is a no-op.
#[cfg(not(feature = "otlp"))]
pub const fn shutdown_otlp_logs() -> Result<(), TelemetryError> {
    Ok(())
}

/// Force-flush the installed OTLP meter provider, if one has been installed.
///
/// # Errors
///
/// Returns [`TelemetryError::MetricsInit`] if the SDK reports a flush failure.
#[cfg(feature = "otlp")]
pub fn flush_otlp_metrics() -> Result<(), TelemetryError> {
    if let Some(provider) = OTLP_METER_PROVIDER.get() {
        provider.force_flush().map_err(|e| {
            TelemetryError::MetricsInit(format!("OTLP metrics force_flush failed: {e}"))
        })?;
    }
    Ok(())
}

/// Force-flush the installed OTLP meter provider, if one has been installed.
///
/// # Errors
///
/// This build has no OTLP provider, so flushing is a no-op.
#[cfg(not(feature = "otlp"))]
pub const fn flush_otlp_metrics() -> Result<(), TelemetryError> {
    Ok(())
}

/// Shut down the installed OTLP meter provider, if one has been installed.
///
/// # Errors
///
/// Returns [`TelemetryError::MetricsInit`] if the SDK reports a shutdown failure.
#[cfg(feature = "otlp")]
pub fn shutdown_otlp_metrics() -> Result<(), TelemetryError> {
    if let Some(provider) = OTLP_METER_PROVIDER.get() {
        provider.shutdown().map_err(|e| {
            TelemetryError::MetricsInit(format!("OTLP metrics shutdown failed: {e}"))
        })?;
    }
    Ok(())
}

/// Shut down the installed OTLP meter provider, if one has been installed.
///
/// # Errors
///
/// This build has no OTLP provider, so shutdown is a no-op.
#[cfg(not(feature = "otlp"))]
pub const fn shutdown_otlp_metrics() -> Result<(), TelemetryError> {
    Ok(())
}

/// Force-flush the installed OTLP tracer provider, if one has been installed.
///
/// # Errors
///
/// Returns [`TelemetryError::TracingInit`] if the SDK reports a flush failure.
#[cfg(feature = "otlp")]
pub fn flush_otlp_tracer() -> Result<(), TelemetryError> {
    if let Some(provider) = OTLP_TRACER_PROVIDER.get() {
        provider
            .force_flush()
            .map_err(|e| TelemetryError::TracingInit(format!("OTLP force_flush failed: {e}")))?;
    }
    Ok(())
}

/// Force-flush the installed OTLP tracer provider, if one has been installed.
///
/// # Errors
///
/// This build has no OTLP provider, so flushing is a no-op.
#[cfg(not(feature = "otlp"))]
pub const fn flush_otlp_tracer() -> Result<(), TelemetryError> {
    Ok(())
}

/// Shut down the installed OTLP tracer provider, if one has been installed.
///
/// # Errors
///
/// Returns [`TelemetryError::TracingInit`] if the SDK reports a shutdown failure.
#[cfg(feature = "otlp")]
pub fn shutdown_otlp_tracer() -> Result<(), TelemetryError> {
    if let Some(provider) = OTLP_TRACER_PROVIDER.get() {
        provider
            .shutdown()
            .map_err(|e| TelemetryError::TracingInit(format!("OTLP shutdown failed: {e}")))?;
    }
    Ok(())
}

/// Shut down the installed OTLP tracer provider, if one has been installed.
///
/// # Errors
///
/// This build has no OTLP provider, so shutdown is a no-op.
#[cfg(not(feature = "otlp"))]
pub const fn shutdown_otlp_tracer() -> Result<(), TelemetryError> {
    Ok(())
}

#[cfg(not(feature = "otlp"))]
fn init_otlp_tracer_with_sample_rate_impl(
    _service_name: &str,
    _endpoint: &str,
    _sample_rate: f64,
    _headers: &[OtlpHeader],
    _resource_attributes: &[OtlpResourceAttribute],
    _export_timeout: Option<Duration>,
    _retry_policy: OtlpRetryPolicy,
) -> Result<(), TelemetryError> {
    Err(TelemetryError::Config(
        "OTLP export requires fcp-telemetry to be built with the `otlp` feature".to_string(),
    ))
}

#[cfg(not(feature = "otlp"))]
fn init_otlp_metrics_with_options_impl(
    _service_name: &str,
    _endpoint: &str,
    _headers: &[OtlpHeader],
    _resource_attributes: &[OtlpResourceAttribute],
    _export_timeout: Option<Duration>,
    _retry_policy: OtlpRetryPolicy,
) -> Result<(), TelemetryError> {
    Err(TelemetryError::Config(
        "OTLP export requires fcp-telemetry to be built with the `otlp` feature".to_string(),
    ))
}

#[cfg(not(feature = "otlp"))]
fn init_otlp_logs_with_options_impl(
    _service_name: &str,
    _endpoint: &str,
    _headers: &[OtlpHeader],
    _resource_attributes: &[OtlpResourceAttribute],
    _export_timeout: Option<Duration>,
    _retry_policy: OtlpRetryPolicy,
) -> Result<(), TelemetryError> {
    Err(TelemetryError::Config(
        "OTLP export requires fcp-telemetry to be built with the `otlp` feature".to_string(),
    ))
}

#[cfg(feature = "otlp")]
fn otlp_resource(service_name: &str, resource_attributes: &[OtlpResourceAttribute]) -> Resource {
    let mut resource_values = Vec::with_capacity(resource_attributes.len() + 1);
    resource_values.push(KeyValue::new("service.name", service_name.to_string()));
    resource_values.extend(
        resource_attributes
            .iter()
            .filter(|attribute| attribute.key != "service.name")
            .map(|attribute| KeyValue::new(attribute.key.clone(), attribute.value.clone())),
    );

    Resource::builder_empty()
        .with_attributes(resource_values)
        .build()
}

#[cfg(feature = "otlp")]
fn otlp_metadata_from_headers(
    headers: &[OtlpHeader],
) -> Result<tonic::metadata::MetadataMap, TelemetryError> {
    let mut metadata = tonic::metadata::MetadataMap::with_capacity(headers.len());
    for header in headers {
        let key = header
            .name
            .parse::<tonic::metadata::MetadataKey<tonic::metadata::Ascii>>()
            .map_err(|_| {
                TelemetryError::Config(format!(
                    "OTLP header `{}` is invalid for gRPC metadata",
                    header.name
                ))
            })?;
        let value =
            tonic::metadata::MetadataValue::try_from(header.value.as_str()).map_err(|_| {
                TelemetryError::Config(format!(
                    "OTLP header `{}` value is invalid for gRPC metadata",
                    header.name
                ))
            })?;
        metadata.insert(key, value);
    }
    Ok(metadata)
}

#[cfg(any(feature = "otlp", test))]
fn otlp_endpoint_log_label(endpoint: &str) -> String {
    let Some((scheme, rest)) = endpoint
        .strip_prefix("http://")
        .map(|rest| ("http://", rest))
        .or_else(|| {
            endpoint
                .strip_prefix("https://")
                .map(|rest| ("https://", rest))
        })
    else {
        return "[invalid-otlp-endpoint]".to_string();
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let redacted_authority = authority.rsplit('@').next().unwrap_or(authority);
    if redacted_authority.is_empty() {
        "[invalid-otlp-endpoint]".to_string()
    } else {
        format!("{scheme}{redacted_authority}")
    }
}

fn render_prometheus_handle(handle: &PrometheusHandle) -> String {
    handle.run_upkeep();
    handle.render()
}

/// Maximum bytes accepted for the HTTP request line before the
/// scrape handler rejects with `414 URI Too Long`. 8 KiB matches
/// common HTTP server defaults (nginx `large_client_header_buffers`
/// 8k, Apache `LimitRequestLine` 8190, golang net/http
/// `DefaultMaxHeaderBytes`/8 = 128 KiB but the request line slice
/// is bounded much tighter in practice). 8 KiB is far above the
/// length any legitimate Prometheus scrape needs (`GET /metrics
/// HTTP/1.1\r\n` is < 32 bytes) and well below a memory-pressure
/// threshold for the scrape thread.
///
/// br-87yi2: prior code used `BufRead::read_line` into an
/// unbounded `String`, so a hostile peer could stream a multi-MB
/// request line without `\n` and force proportional heap growth
/// on the metrics exporter before the handler ever decided whether
/// to serve `/metrics`.
const MAX_REQUEST_LINE_BYTES: usize = 8 * 1024;

/// Per-connection socket deadline for the Prometheus scrape server.
///
/// The accept loop in [`init_prometheus_exporter`] handles connections
/// serially on a single thread, so without a deadline one peer that opens a
/// connection and then sends nothing (or streams bytes without a terminating
/// `\n`, or never drains the response) parks the handler in `read_until` /
/// `write` forever and blackouts every subsequent scrape. The `MAX_REQUEST_
/// LINE_BYTES` cap (br-87yi2) bounds heap growth but not blocking time; this
/// timeout bounds the time. A legitimate scrape sends a <32-byte request line
/// and drains a small response well within this window, so any peer that
/// exceeds it is a stall we want to drop.
const PROMETHEUS_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

fn serve_prometheus_connection(stream: TcpStream, handle: &PrometheusHandle) -> io::Result<()> {
    serve_prometheus_connection_with_timeout(stream, handle, PROMETHEUS_CONNECTION_TIMEOUT)
}

fn serve_prometheus_connection_with_timeout(
    mut stream: TcpStream,
    handle: &PrometheusHandle,
    timeout: Duration,
) -> io::Result<()> {
    // Fail closed on a slow/idle peer instead of blocking the single-threaded
    // accept loop indefinitely.
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let request_line_result = {
        let mut reader = BufReader::new(stream.try_clone()?);
        // Read at most MAX_REQUEST_LINE_BYTES + 1 — the +1 lets us
        // distinguish "exactly at the cap, line ended" from "ran past
        // the cap, line never ended". `take` short-circuits the
        // underlying read, so a peer that streams gigabytes without
        // `\n` only consumes 8 KiB+1 of buffer before we surface the
        // rejection.
        let mut line = Vec::with_capacity(128);
        let limit = u64::try_from(MAX_REQUEST_LINE_BYTES + 1).unwrap_or(u64::MAX);
        let mut bounded = (&mut reader).take(limit);
        bounded.read_until(b'\n', &mut line)?;
        if line.len() > MAX_REQUEST_LINE_BYTES
            || (line.len() == MAX_REQUEST_LINE_BYTES + 1 && !line.ends_with(b"\n"))
            || (!line.is_empty() && !line.ends_with(b"\n"))
        {
            // Either: (a) we read more than the cap (impossible because
            // of `take`, but defensive); (b) we hit the cap+1 byte and
            // the last byte was NOT `\n`, meaning the peer's line is
            // longer than the cap; or (c) the peer closed the
            // connection mid-line.
            Err(())
        } else {
            // SAFETY: HTTP request lines are ASCII per RFC 7230 §3.1.1.
            // A non-UTF8 byte sequence here is a malformed request
            // and is rejected the same way an oversized line is.
            String::from_utf8(line).map_err(|_| ())
        }
    };

    let (status_line, content_type, body) = match request_line_result {
        Err(()) => (
            "HTTP/1.1 414 URI Too Long",
            "text/plain; charset=utf-8",
            "Request line too long\n".to_string(),
        ),
        Ok(request_line) if request_line.starts_with("GET /metrics ") => (
            "HTTP/1.1 200 OK",
            "text/plain; version=0.0.4; charset=utf-8",
            render_prometheus_handle(handle),
        ),
        Ok(_) => (
            "HTTP/1.1 404 Not Found",
            "text/plain; charset=utf-8",
            "Not Found\n".to_string(),
        ),
    };

    write!(
        stream,
        "{status_line}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    stream.flush()
}

/// Generate Prometheus exposition format text from current metrics.
///
/// This is useful for embedding metrics in custom HTTP handlers after
/// [`init_prometheus_exporter`] has installed a recorder.
#[must_use]
pub fn prometheus_text_format() -> String {
    PROMETHEUS_HANDLE.get().map_or_else(
        || {
            "# Prometheus exporter not initialized; call init_prometheus_exporter first\n"
                .to_string()
        },
        render_prometheus_handle,
    )
}

/// Health check endpoint response.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HealthResponse {
    /// Service status.
    pub status: String,

    /// Service version.
    pub version: String,

    /// Uptime in seconds.
    pub uptime_seconds: u64,

    /// Additional checks.
    pub checks: Vec<HealthCheck>,
}

/// Individual health check result.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HealthCheck {
    /// Check name.
    pub name: String,

    /// Check status.
    pub status: String,

    /// Optional message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl HealthResponse {
    /// Create a healthy response.
    #[must_use]
    pub fn healthy(version: &str, uptime_seconds: u64) -> Self {
        Self {
            status: "healthy".to_string(),
            version: version.to_string(),
            uptime_seconds,
            checks: Vec::new(),
        }
    }

    /// Create an unhealthy response.
    #[must_use]
    pub fn unhealthy(version: &str, uptime_seconds: u64, message: &str) -> Self {
        Self {
            status: "unhealthy".to_string(),
            version: version.to_string(),
            uptime_seconds,
            checks: vec![HealthCheck {
                name: "main".to_string(),
                status: "fail".to_string(),
                message: Some(message.to_string()),
            }],
        }
    }

    /// Add a health check.
    #[must_use]
    pub fn with_check(mut self, name: &str, passed: bool, message: Option<&str>) -> Self {
        self.checks.push(HealthCheck {
            name: name.to_string(),
            status: if passed { "pass" } else { "fail" }.to_string(),
            message: message.map(String::from),
        });
        self
    }

    /// Check if all checks passed.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.status == "healthy" && self.checks.iter().all(|c| c.status == "pass")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        thread,
    };

    use metrics::{Key, Recorder};

    static METADATA: metrics::Metadata =
        metrics::Metadata::new(module_path!(), metrics::Level::INFO, Some(module_path!()));

    #[test]
    fn test_otlp_endpoint_log_label_removes_paths_queries_and_userinfo() {
        assert_eq!(
            otlp_endpoint_log_label("https://collector.example.com:4317/v1/traces"),
            "https://collector.example.com:4317"
        );
        assert_eq!(
            otlp_endpoint_log_label("https://userinfo@collector.example.com:4317?label=value"),
            "https://collector.example.com:4317"
        );
        assert_eq!(
            otlp_endpoint_log_label("grpc://collector.example.com:4317"),
            "[invalid-otlp-endpoint]"
        );
    }

    #[cfg(not(feature = "otlp"))]
    #[test]
    fn test_otlp_exporter_requires_feature_flag() {
        let result = init_otlp_tracer_with_sample_rate(
            "fcp-test",
            "https://collector.example.com:4317",
            1.0,
        );

        assert!(
            matches!(result, Err(TelemetryError::Config(message)) if message.contains("`otlp` feature"))
        );
    }

    #[cfg(feature = "otlp")]
    #[test]
    fn test_otlp_metadata_from_headers_builds_grpc_metadata() -> Result<(), TelemetryError> {
        let headers = vec![
            OtlpHeader::new("Authorization", "Bearer secret")?,
            OtlpHeader::new("x-tenant", "prod")?,
        ];

        let metadata = otlp_metadata_from_headers(&headers)?;
        let authorization = metadata.get("authorization").ok_or_else(|| {
            TelemetryError::Config("authorization metadata was not populated".to_string())
        })?;
        let tenant = metadata.get("x-tenant").ok_or_else(|| {
            TelemetryError::Config("x-tenant metadata was not populated".to_string())
        })?;
        let expected_authorization = tonic::metadata::MetadataValue::try_from("Bearer secret")
            .map_err(|_| {
                TelemetryError::Config("expected authorization metadata is invalid".to_string())
            })?;
        let expected_tenant = tonic::metadata::MetadataValue::try_from("prod").map_err(|_| {
            TelemetryError::Config("expected tenant metadata is invalid".to_string())
        })?;

        assert_eq!(authorization, &expected_authorization);
        assert_eq!(tenant, &expected_tenant);
        Ok(())
    }

    #[test]
    fn test_health_response_healthy() {
        let response = HealthResponse::healthy("1.0.0", 3600);
        assert!(response.is_healthy());
        assert_eq!(response.status, "healthy");
    }

    #[test]
    fn test_health_response_with_checks() {
        let response = HealthResponse::healthy("1.0.0", 3600)
            .with_check("database", true, None)
            .with_check("cache", true, Some("Connected"));

        assert!(response.is_healthy());
        assert_eq!(response.checks.len(), 2);
    }

    #[test]
    fn test_health_response_unhealthy() {
        let response = HealthResponse::unhealthy("1.0.0", 3600, "Database connection failed");
        assert!(!response.is_healthy());
        assert_eq!(response.status, "unhealthy");
    }

    #[test]
    fn test_health_response_fields() {
        let response = HealthResponse::healthy("2.0.0", 7200);
        assert_eq!(response.version, "2.0.0");
        assert_eq!(response.uptime_seconds, 7200);
        assert!(response.checks.is_empty());
    }

    #[test]
    fn test_health_response_unhealthy_fields() {
        let response = HealthResponse::unhealthy("1.5.0", 1000, "Service unavailable");
        assert_eq!(response.version, "1.5.0");
        assert_eq!(response.uptime_seconds, 1000);
        assert_eq!(response.checks.len(), 1);
        assert_eq!(response.checks[0].name, "main");
        assert_eq!(response.checks[0].status, "fail");
        assert_eq!(
            response.checks[0].message,
            Some("Service unavailable".to_string())
        );
    }

    #[test]
    fn test_health_check_passed() {
        let response = HealthResponse::healthy("1.0.0", 100).with_check("api", true, None);

        assert_eq!(response.checks.len(), 1);
        assert_eq!(response.checks[0].name, "api");
        assert_eq!(response.checks[0].status, "pass");
        assert!(response.checks[0].message.is_none());
    }

    #[test]
    fn test_health_check_failed() {
        let response =
            HealthResponse::healthy("1.0.0", 100).with_check("database", false, Some("Timeout"));

        assert_eq!(response.checks.len(), 1);
        assert_eq!(response.checks[0].name, "database");
        assert_eq!(response.checks[0].status, "fail");
        assert_eq!(response.checks[0].message, Some("Timeout".to_string()));
    }

    #[test]
    fn test_health_response_mixed_checks() {
        let response = HealthResponse::healthy("1.0.0", 100)
            .with_check("database", true, None)
            .with_check("cache", false, Some("Connection refused"))
            .with_check("api", true, Some("OK"));

        // Even with healthy status, if any check fails, is_healthy returns false
        assert!(!response.is_healthy());
        assert_eq!(response.checks.len(), 3);
    }

    #[test]
    fn test_health_response_all_checks_pass() {
        let response = HealthResponse::healthy("1.0.0", 100)
            .with_check("database", true, None)
            .with_check("cache", true, None)
            .with_check("api", true, None);

        assert!(response.is_healthy());
    }

    #[test]
    fn test_health_check_clone() {
        let check = HealthCheck {
            name: "test".to_string(),
            status: "pass".to_string(),
            message: Some("OK".to_string()),
        };

        let cloned = check.clone();
        assert_eq!(check.name, cloned.name);
        assert_eq!(check.status, cloned.status);
        assert_eq!(check.message, cloned.message);
    }

    #[test]
    fn test_health_response_clone() {
        let response = HealthResponse::healthy("1.0.0", 100).with_check("db", true, None);

        let cloned = response.clone();
        assert_eq!(response.status, cloned.status);
        assert_eq!(response.version, cloned.version);
        assert_eq!(response.uptime_seconds, cloned.uptime_seconds);
        assert_eq!(response.checks.len(), cloned.checks.len());
    }

    #[test]
    fn test_health_check_debug() {
        let check = HealthCheck {
            name: "test".to_string(),
            status: "pass".to_string(),
            message: None,
        };

        let debug_str = format!("{check:?}");
        assert!(debug_str.contains("HealthCheck"));
        assert!(debug_str.contains("test"));
    }

    #[test]
    fn test_health_response_debug() {
        let response = HealthResponse::healthy("1.0.0", 100);
        let debug_str = format!("{response:?}");
        assert!(debug_str.contains("HealthResponse"));
    }

    #[test]
    fn test_health_response_json_serialization() {
        let response =
            HealthResponse::healthy("1.0.0", 3600).with_check("database", true, Some("Connected"));

        let json = serde_json::to_string(&response).unwrap();

        assert!(json.contains("\"status\":\"healthy\""));
        assert!(json.contains("\"version\":\"1.0.0\""));
        assert!(json.contains("\"uptime_seconds\":3600"));
        assert!(json.contains("\"name\":\"database\""));
        assert!(json.contains("\"message\":\"Connected\""));
    }

    #[test]
    fn test_health_response_json_skip_none_message() {
        let response = HealthResponse::healthy("1.0.0", 100).with_check("api", true, None);

        let json = serde_json::to_string(&response).unwrap();

        // The message field should be skipped when None
        assert!(!json.contains("\"message\":null"));
    }

    #[test]
    fn test_health_response_zero_uptime() {
        let response = HealthResponse::healthy("0.1.0", 0);
        assert_eq!(response.uptime_seconds, 0);
        assert!(response.is_healthy());
    }

    #[test]
    fn test_health_response_long_uptime() {
        let one_year_seconds = 365 * 24 * 60 * 60;
        let response = HealthResponse::healthy("1.0.0", one_year_seconds);
        assert_eq!(response.uptime_seconds, one_year_seconds);
    }

    #[test]
    fn test_health_response_empty_version() {
        let response = HealthResponse::healthy("", 100);
        assert_eq!(response.version, "");
        assert!(response.is_healthy());
    }

    #[test]
    fn test_health_response_semver_version() {
        let response = HealthResponse::healthy("1.2.3-beta.1+build.456", 100);
        assert_eq!(response.version, "1.2.3-beta.1+build.456");
    }

    #[test]
    fn test_health_check_long_message() {
        let long_message = "a".repeat(1000);
        let response =
            HealthResponse::healthy("1.0.0", 100).with_check("test", false, Some(&long_message));

        assert_eq!(response.checks[0].message, Some(long_message));
    }

    #[test]
    fn test_health_check_special_characters() {
        let response = HealthResponse::healthy("1.0.0", 100).with_check(
            "test/check",
            true,
            Some("Status: OK! <test>"),
        );

        assert_eq!(response.checks[0].name, "test/check");
        assert_eq!(
            response.checks[0].message,
            Some("Status: OK! <test>".to_string())
        );
    }

    #[test]
    fn test_prometheus_text_format() {
        let text = prometheus_text_format();
        assert!(!text.is_empty());
    }

    #[test]
    fn test_render_prometheus_handle_smoke() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let counter = recorder.register_counter(&Key::from_name("fcp_test_counter"), &METADATA);
        counter.increment(3);

        let rendered = render_prometheus_handle(&recorder.handle());
        assert!(rendered.contains("# TYPE fcp_test_counter counter"));
        assert!(rendered.contains("fcp_test_counter 3"));
    }

    #[test]
    fn test_prometheus_http_scrape_smoke() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let counter = recorder.register_counter(&Key::from_name("fcp_http_counter"), &METADATA);
        counter.increment(7);

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            serve_prometheus_connection(stream, &handle).unwrap();
        });

        let mut client = TcpStream::connect(addr).unwrap();
        client
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();

        // ConnectionReset on read is a tolerable outcome here — it
        // means the server flushed its small reject/404 response and
        // closed before the client finished reading. We care about
        // the bytes that DID arrive matching the expected status line.
        let response = read_tolerating_close(&mut client).unwrap();
        server.join().unwrap();

        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.contains("# TYPE fcp_http_counter counter"));
        assert!(response.contains("fcp_http_counter 7"));
    }

    /// Write `payload` to `stream` tolerating early-close errors. The
    /// 414/404 fast-reject path closes the socket as soon as the
    /// server's response is flushed, so a client streaming a large
    /// payload may see `ConnectionReset` or `BrokenPipe` mid-write —
    /// that is the success signal for the cap, not a failure.
    fn is_tolerable_connection_close(kind: io::ErrorKind) -> bool {
        matches!(
            kind,
            io::ErrorKind::ConnectionReset
                | io::ErrorKind::BrokenPipe
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::UnexpectedEof
        )
    }

    fn read_tolerating_close(stream: &mut TcpStream) -> io::Result<String> {
        let mut response = String::new();
        match stream.read_to_string(&mut response) {
            Ok(_) => Ok(response),
            Err(err) if is_tolerable_connection_close(err.kind()) => Ok(response),
            Err(err) => Err(err),
        }
    }

    fn write_tolerating_close(stream: &mut TcpStream, payload: &[u8]) -> io::Result<()> {
        if let Err(err) = stream.write_all(payload) {
            if is_tolerable_connection_close(err.kind()) {
                Ok(())
            } else {
                Err(err)
            }
        } else {
            Ok(())
        }
    }

    /// br-87yi2: an oversized request line (> `MAX_REQUEST_LINE_BYTES`)
    /// must be rejected with `414 URI Too Long` instead of allocating
    /// proportionally on the scrape thread. The serve handler MUST
    /// stop reading at the cap so a hostile peer that streams
    /// gigabytes without `\n` only consumes ~8 KiB before responding.
    #[test]
    fn test_prometheus_oversized_request_line_rejected_with_414() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            serve_prometheus_connection(stream, &handle).unwrap();
        });

        let mut client = TcpStream::connect(addr).unwrap();
        // Build a request line that exceeds MAX_REQUEST_LINE_BYTES
        // (8 KiB) by ~16 KiB of `A` padding inside the path. No `\n`
        // is sent before the cap is hit — the server reads
        // MAX_REQUEST_LINE_BYTES + 1 bytes via `take`, sees no
        // newline, and rejects with 414.
        let mut payload = b"GET /".to_vec();
        payload.extend(std::iter::repeat_n(b'A', 16 * 1024));
        payload.extend(b" HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        write_tolerating_close(&mut client, &payload).unwrap();
        // Best-effort shutdown — may fail if peer already closed.
        let _ = client.shutdown(std::net::Shutdown::Write);

        // ConnectionReset on read is a tolerable outcome here — it
        // means the server flushed its small reject/404 response and
        // closed before the client finished reading. We care about
        // the bytes that DID arrive matching the expected status line.
        let response = read_tolerating_close(&mut client).unwrap();
        server.join().unwrap();

        // Status-line check is the load-bearing assertion. The body
        // sentinel ("Request line too long") MAY arrive too if the
        // client drains the kernel buffer fully before the server's
        // RST reaches it, but is not required — we only need to
        // confirm the 414 fast-reject path was taken.
        assert!(
            response.contains("HTTP/1.1 414 URI Too Long"),
            "oversized request line must yield 414, got: {response}"
        );
    }

    /// A peer that opens a connection and sends nothing (a slowloris /
    /// idle-connection stall) must NOT park the single-threaded accept loop
    /// forever: the per-connection read timeout makes the handler return
    /// promptly with a timeout error instead. Without the fix this test would
    /// hang until the harness kills it.
    #[test]
    fn test_prometheus_idle_connection_times_out_instead_of_hanging() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            // Short timeout keeps the test fast while exercising the exact
            // deadline path the production wrapper uses.
            serve_prometheus_connection_with_timeout(stream, &handle, Duration::from_millis(200))
        });

        // Connect but never send a request line and never close the write
        // half — the classic idle-peer stall.
        let _client = TcpStream::connect(addr).unwrap();

        let started = std::time::Instant::now();
        let result = server.join().unwrap();
        let elapsed = started.elapsed();

        assert!(
            result.is_err(),
            "an idle peer must surface a timeout error, not a served response"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "handler must return promptly on an idle peer (took {elapsed:?})"
        );
    }

    /// br-87yi2: a normal-sized request line for a non-`/metrics`
    /// path still produces 404, not 414 — proving the cap doesn't
    /// false-trigger on legitimate requests.
    #[test]
    fn test_prometheus_normal_unknown_path_yields_404_not_414() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            serve_prometheus_connection(stream, &handle).unwrap();
        });

        let mut client = TcpStream::connect(addr).unwrap();
        client
            .write_all(b"GET /unknown HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();

        // ConnectionReset on read is a tolerable outcome here — it
        // means the server flushed its small reject/404 response and
        // closed before the client finished reading. We care about
        // the bytes that DID arrive matching the expected status line.
        let response = read_tolerating_close(&mut client).unwrap();
        server.join().unwrap();

        assert!(response.contains("HTTP/1.1 404 Not Found"));
        assert!(!response.contains("414"));
    }

    /// br-87yi2: a request line at EXACTLY the cap with `\n` at the
    /// last byte must NOT be rejected. The cap is inclusive of the
    /// trailing newline; only lines that exceed it are 414. This
    /// guards against off-by-one false-positives.
    #[test]
    fn test_prometheus_request_line_at_exact_cap_accepted() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            serve_prometheus_connection(stream, &handle).unwrap();
        });

        let mut client = TcpStream::connect(addr).unwrap();
        // Construct a line of length MAX_REQUEST_LINE_BYTES ending in
        // `\n`. The path is padded with `A` so the line is well-formed
        // but unknown — server should respond 404, not 414.
        let prefix = b"GET /".to_vec();
        let suffix = b" HTTP/1.1\r\n";
        let pad_len = MAX_REQUEST_LINE_BYTES - prefix.len() - suffix.len();
        let mut payload = prefix;
        payload.extend(std::iter::repeat_n(b'A', pad_len));
        payload.extend(suffix);
        assert_eq!(payload.len(), MAX_REQUEST_LINE_BYTES);
        // Add header tail so the connection drains cleanly.
        payload.extend(b"Host: 127.0.0.1\r\n\r\n");
        write_tolerating_close(&mut client, &payload).unwrap();
        let _ = client.shutdown(std::net::Shutdown::Write);

        // ConnectionReset on read is a tolerable outcome here — it
        // means the server flushed its small reject/404 response and
        // closed before the client finished reading. We care about
        // the bytes that DID arrive matching the expected status line.
        let response = read_tolerating_close(&mut client).unwrap();
        server.join().unwrap();

        assert!(
            response.contains("HTTP/1.1 404 Not Found"),
            "exact-cap line must be 404, got: {response}"
        );
        assert!(!response.contains("414"));
    }

    #[test]
    fn test_multiple_unhealthy_checks() {
        let response = HealthResponse::healthy("1.0.0", 100)
            .with_check("db", false, Some("Connection timeout"))
            .with_check("cache", false, Some("Memory full"))
            .with_check("api", false, Some("Rate limited"));

        assert!(!response.is_healthy());
        assert_eq!(response.checks.len(), 3);
        assert!(response.checks.iter().all(|c| c.status == "fail"));
    }

    #[test]
    fn test_health_response_chain() {
        // Test that builder pattern chains correctly
        let response = HealthResponse::healthy("1.0.0", 100)
            .with_check("check1", true, None)
            .with_check("check2", true, Some("OK"))
            .with_check("check3", true, None)
            .with_check("check4", true, Some("All good"));

        assert_eq!(response.checks.len(), 4);
        assert!(response.is_healthy());
    }

    #[test]
    fn test_health_response_json_value() {
        let response =
            HealthResponse::healthy("2.0.0", 500).with_check("db", true, Some("connected"));
        let val: serde_json::Value = serde_json::to_value(&response).unwrap();
        assert_eq!(val["status"], "healthy");
        assert_eq!(val["version"], "2.0.0");
        assert_eq!(val["uptime_seconds"], 500);
        assert_eq!(val["checks"][0]["name"], "db");
        assert_eq!(val["checks"][0]["status"], "pass");
        assert_eq!(val["checks"][0]["message"], "connected");
    }

    #[test]
    fn test_health_response_unhealthy_check_message() {
        let response = HealthResponse::unhealthy("1.0.0", 0, "boot failure");
        assert_eq!(response.checks.len(), 1);
        assert_eq!(response.checks[0].message, Some("boot failure".to_string()));
        assert_eq!(response.checks[0].name, "main");
    }

    #[test]
    fn test_health_response_unhealthy_is_not_healthy() {
        let response =
            HealthResponse::unhealthy("1.0.0", 100, "down").with_check("api", true, None);
        // status is unhealthy so overall is_healthy is false
        assert!(!response.is_healthy());
    }

    #[test]
    fn test_health_check_no_message_debug() {
        let check = HealthCheck {
            name: "api".to_string(),
            status: "pass".to_string(),
            message: None,
        };
        let debug = format!("{check:?}");
        assert!(debug.contains("None"));
    }

    #[test]
    fn test_health_response_many_checks() {
        let mut response = HealthResponse::healthy("1.0.0", 100);
        for i in 0..50 {
            response = response.with_check(&format!("check_{i}"), true, None);
        }
        assert_eq!(response.checks.len(), 50);
        assert!(response.is_healthy());
    }

    #[test]
    fn test_health_response_max_uptime() {
        let response = HealthResponse::healthy("1.0.0", u64::MAX);
        assert_eq!(response.uptime_seconds, u64::MAX);
    }

    #[test]
    fn test_health_check_clone_independence() {
        let check = HealthCheck {
            name: "original".to_string(),
            status: "pass".to_string(),
            message: Some("ok".to_string()),
        };
        let mut cloned = check.clone();
        cloned.name = "modified".to_string();
        assert_eq!(check.name, "original");
    }

    #[test]
    fn test_health_response_clone_independence() {
        let response = HealthResponse::healthy("1.0.0", 100).with_check("db", true, None);
        let cloned = response.clone();
        assert_eq!(response.checks.len(), cloned.checks.len());
        assert_eq!(response.status, cloned.status);
    }

    #[test]
    fn test_health_response_json_array_checks() {
        let response = HealthResponse::healthy("1.0.0", 100)
            .with_check("a", true, None)
            .with_check("b", false, Some("err"));
        let json = serde_json::to_string(&response).unwrap();
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(val["checks"].is_array());
        assert_eq!(val["checks"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_prometheus_text_format_is_not_empty() {
        let text = prometheus_text_format();
        assert!(text.len() > 5);
    }

    #[test]
    fn test_health_response_unicode_version() {
        let response = HealthResponse::healthy("v1.0-日本語", 100);
        assert_eq!(response.version, "v1.0-日本語");
    }

    #[test]
    fn test_health_check_with_empty_name() {
        let response = HealthResponse::healthy("1.0.0", 100).with_check("", true, None);
        assert_eq!(response.checks[0].name, "");
        assert!(response.is_healthy());
    }

    #[test]
    fn test_health_response_unhealthy_with_additional_passing_checks() {
        let response = HealthResponse::unhealthy("1.0.0", 100, "main failure")
            .with_check("db", true, None)
            .with_check("cache", true, None);
        // Main status is unhealthy, so is_healthy returns false even with passing checks
        assert!(!response.is_healthy());
        assert_eq!(response.checks.len(), 3); // main + db + cache
    }

    #[test]
    fn test_health_response_json_roundtrip() {
        let response = HealthResponse::healthy("2.1.0", 12345)
            .with_check("api", true, Some("OK"))
            .with_check("db", false, Some("Timeout"));
        let json = serde_json::to_string(&response).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["status"], "healthy");
        assert_eq!(parsed["version"], "2.1.0");
        assert_eq!(parsed["uptime_seconds"], 12345);
    }

    #[test]
    fn test_health_check_message_with_newlines() {
        let response = HealthResponse::healthy("1.0.0", 100).with_check(
            "test",
            false,
            Some("Line 1\nLine 2\nLine 3"),
        );
        assert_eq!(
            response.checks[0].message,
            Some("Line 1\nLine 2\nLine 3".to_string())
        );
    }

    #[test]
    fn test_health_response_healthy_no_checks_is_healthy() {
        let response = HealthResponse::healthy("1.0.0", 100);
        assert!(response.is_healthy());
        assert!(response.checks.is_empty());
    }

    #[test]
    fn test_health_response_unhealthy_zero_uptime() {
        let response = HealthResponse::unhealthy("1.0.0", 0, "not started");
        assert!(!response.is_healthy());
        assert_eq!(response.uptime_seconds, 0);
    }

    #[test]
    fn test_health_check_json_serialization_with_message() {
        let check = HealthCheck {
            name: "test_check".to_string(),
            status: "pass".to_string(),
            message: Some("all good".to_string()),
        };
        let json = serde_json::to_string(&check).unwrap();
        assert!(json.contains("\"message\":\"all good\""));
    }

    #[test]
    fn test_health_check_json_serialization_without_message() {
        let check = HealthCheck {
            name: "test_check".to_string(),
            status: "pass".to_string(),
            message: None,
        };
        let json = serde_json::to_string(&check).unwrap();
        // message should be skipped when None
        assert!(!json.contains("message"));
    }

    #[test]
    fn test_health_response_single_failing_check() {
        let response =
            HealthResponse::healthy("1.0.0", 100).with_check("critical", false, Some("Down"));
        assert!(!response.is_healthy());
        assert_eq!(response.checks.len(), 1);
    }

    #[test]
    fn test_health_response_clone_deep_independence() {
        let response = HealthResponse::healthy("1.0.0", 100)
            .with_check("a", true, Some("ok"))
            .with_check("b", false, Some("err"));
        let mut cloned = response.clone();
        cloned.status = "degraded".to_string();
        cloned.checks.clear();
        // Original should be unaffected
        assert_eq!(response.status, "healthy");
        assert_eq!(response.checks.len(), 2);
    }

    // --- Acceptance: prometheus_text_format ---

    #[test]
    fn prometheus_text_format_returns_non_empty() {
        let text = prometheus_text_format();
        assert!(
            !text.is_empty(),
            "prometheus text format should return content"
        );
        assert!(text.starts_with('#'), "should start with comment line");
    }

    // --- Acceptance: health response JSON contract ---

    #[test]
    fn health_response_json_has_required_fields() {
        let response = HealthResponse::healthy("2.0.0", 7200)
            .with_check("store", true, None)
            .with_check("mesh", true, Some("all nodes reachable"));
        let json = serde_json::to_string(&response).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["status"], "healthy");
        assert_eq!(parsed["version"], "2.0.0");
        assert_eq!(parsed["uptime_seconds"], 7200);
        assert!(parsed["checks"].is_array());
        assert_eq!(parsed["checks"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn health_response_json_omits_null_messages() {
        let response = HealthResponse::healthy("1.0.0", 0).with_check("db", true, None);
        let json = serde_json::to_string(&response).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(
            parsed["checks"][0].get("message").is_none(),
            "None message should be omitted from JSON"
        );
    }

    #[test]
    fn unhealthy_response_includes_failure_check() {
        let response = HealthResponse::unhealthy("1.0.0", 100, "connection refused");
        let json = serde_json::to_string(&response).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["status"], "unhealthy");
        assert_eq!(parsed["checks"][0]["name"], "main");
        assert_eq!(parsed["checks"][0]["status"], "fail");
        assert_eq!(parsed["checks"][0]["message"], "connection refused");
    }

    // --- Acceptance: mixed health check scenarios ---

    #[test]
    fn health_with_all_passing_checks_is_healthy() {
        let response = HealthResponse::healthy("1.0.0", 500)
            .with_check("store", true, None)
            .with_check("mesh", true, None)
            .with_check("audit", true, None);
        assert!(response.is_healthy());
        assert_eq!(response.checks.len(), 3);
    }

    #[test]
    fn health_with_one_failing_check_is_unhealthy() {
        let response = HealthResponse::healthy("1.0.0", 500)
            .with_check("store", true, None)
            .with_check("mesh", false, Some("2 nodes unreachable"))
            .with_check("audit", true, None);
        assert!(!response.is_healthy());
    }

    #[test]
    fn health_with_many_checks_serializes_all() {
        let mut response = HealthResponse::healthy("1.0.0", 0);
        for i in 0..20 {
            response = response.with_check(
                &format!("check_{i}"),
                i % 3 != 0,
                Some(&format!("detail {i}")),
            );
        }
        let json = serde_json::to_string(&response).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["checks"].as_array().unwrap().len(), 20);
    }

    #[test]
    fn health_response_version_preserved_exactly() {
        let response = HealthResponse::healthy("0.1.0-alpha.3+build.456", 1);
        assert_eq!(response.version, "0.1.0-alpha.3+build.456");
    }
}
