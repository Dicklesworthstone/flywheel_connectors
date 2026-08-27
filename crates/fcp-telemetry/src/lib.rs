//! FCP Telemetry - Unified Metrics, Logging, and Tracing for FCP Connectors
//!
//! This crate provides comprehensive observability infrastructure for FCP connectors:
//!
//! - **Structured Logging**: JSON-formatted logs with automatic field injection
//! - **Metrics Collection**: Counters, gauges, histograms with Prometheus export
//! - **Distributed Tracing**: Span creation with W3C Trace Context propagation
//! - **Optional OTLP Export**: Host/runtime-level OpenTelemetry export for
//!   traces, metrics, and logs when the `otlp` Cargo feature is enabled
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use fcp_telemetry::{TelemetryConfig, init_telemetry};
//!
//! // Initialize with defaults
//! init_telemetry(TelemetryConfig::default())?;
//!
//! // Use tracing macros as normal
//! tracing::info!(connector_id = "my-connector", "Starting up");
//!
//! // Record metrics
//! fcp_telemetry::metrics::increment_counter("requests_total", &[("connector", "my-connector")]);
//! ```
//!
//! # OTLP Export
//!
//! OTLP is intentionally implemented as a crate-level host/runtime feature, not
//! as a sandboxed connector binary. Operators enable it with the `otlp` feature
//! and standard OpenTelemetry environment variables such as
//! `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_HEADERS`,
//! `OTEL_SERVICE_NAME`, and `OTEL_RESOURCE_ATTRIBUTES`. Use
//! [`otlp_readiness`] to surface a redaction-safe admin/readiness summary before
//! starting exporters.

#![forbid(unsafe_code)]
// Lint groups come from [workspace.lints.clippy]; duplicating them here would
// override that table and defeat its allow entries.
#![allow(clippy::module_name_repetitions)]

mod context;
mod export;
mod logging;
pub mod metrics;
pub mod trace_capture;
mod tracing_layer;
mod usage;

pub use context::*;
pub use export::{
    HealthCheck, HealthResponse, OtlpRetryPolicy, flush_otlp_logs, flush_otlp_metrics,
    flush_otlp_tracer, init_otlp_logs_with_options, init_otlp_logs_with_options_and_timeout,
    init_otlp_logs_with_options_timeout_and_retry, init_otlp_metrics_with_options,
    init_otlp_metrics_with_options_and_timeout, init_otlp_metrics_with_options_timeout_and_retry,
    init_otlp_tracer, init_otlp_tracer_with_sample_rate,
    init_otlp_tracer_with_sample_rate_and_options,
    init_otlp_tracer_with_sample_rate_options_and_timeout,
    init_otlp_tracer_with_sample_rate_options_timeout_and_retry, init_prometheus_exporter,
    prometheus_text_format, shutdown_otlp_logs, shutdown_otlp_metrics, shutdown_otlp_tracer,
};
pub use logging::*;
pub use usage::*;
// Re-export tracing_layer items explicitly to avoid TraceContext collision
// (we prefer context::TraceContext which is the proper W3C binary implementation)
pub use tracing_layer::{
    FcpSpan, SpanGuard, TRACEPARENT_HEADER, TRACESTATE_HEADER, extract_trace_context,
    inject_trace_context,
};
// Export the legacy string-based TraceContext under a distinct name
pub use tracing_layer::TraceContext as LegacyTraceContext;

use std::{
    fmt,
    sync::{Mutex, OnceLock},
};

/// Global telemetry state.
static TELEMETRY: OnceLock<TelemetryState> = OnceLock::new();
static TELEMETRY_INIT_LOCK: Mutex<()> = Mutex::new(());

/// Internal telemetry state.
struct TelemetryState {
    #[allow(dead_code)]
    config: TelemetryConfig,
}

/// Compiled-in fallback for the Prometheus metrics endpoint port.
pub const DEFAULT_PROMETHEUS_PORT: u16 = 9090;

/// Environment variables checked for the Prometheus metrics endpoint port, in precedence order.
pub const PROMETHEUS_PORT_ENV_VARS: [&str; 4] = [
    "FCP_TELEMETRY_PROMETHEUS_PORT",
    "FCP_TELEMETRY_PORT",
    "FCP_PROMETHEUS_PORT",
    "PROMETHEUS_PORT",
];

/// Maximum accepted OTLP endpoint length.
pub const MAX_OTLP_ENDPOINT_LEN: usize = 2048;

/// Maximum accepted OTLP header count.
pub const MAX_OTLP_HEADER_COUNT: usize = 32;

/// Maximum accepted OTLP header name length.
pub const MAX_OTLP_HEADER_NAME_LEN: usize = 128;

/// Maximum accepted OTLP header value length.
pub const MAX_OTLP_HEADER_VALUE_LEN: usize = 4096;

/// Maximum accepted OTLP resource attribute count.
pub const MAX_OTLP_RESOURCE_ATTRIBUTE_COUNT: usize = 64;

/// Maximum accepted OTLP resource attribute key length.
pub const MAX_OTLP_RESOURCE_ATTRIBUTE_KEY_LEN: usize = 128;

/// Maximum accepted OTLP resource attribute value length.
pub const MAX_OTLP_RESOURCE_ATTRIBUTE_VALUE_LEN: usize = 4096;

/// OpenTelemetry service name environment variable.
pub const OTEL_SERVICE_NAME_ENV_VAR: &str = "OTEL_SERVICE_NAME";

/// OpenTelemetry resource attributes environment variable.
pub const OTEL_RESOURCE_ATTRIBUTES_ENV_VAR: &str = "OTEL_RESOURCE_ATTRIBUTES";

/// OTLP endpoint environment variables, in precedence order.
pub const OTLP_ENDPOINT_ENV_VARS: [&str; 2] = [
    "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
    "OTEL_EXPORTER_OTLP_ENDPOINT",
];

/// OTLP header environment variables, in merge order. Signal-specific values override generic ones.
pub const OTLP_HEADERS_ENV_VARS: [&str; 2] = [
    "OTEL_EXPORTER_OTLP_HEADERS",
    "OTEL_EXPORTER_OTLP_TRACES_HEADERS",
];

/// Host/runtime boundary used by the OTLP exporter.
pub const OTLP_EXPORT_BOUNDARY: &str = "fcp-telemetry-crate";

/// OTLP signal export support for the current config/build.
#[derive(Debug, Clone, Copy, serde::Serialize, PartialEq, Eq)]
pub struct OtlpSignalSupport {
    /// Whether trace export can be initialized.
    pub traces: bool,

    /// Whether metric export can be initialized.
    pub metrics: bool,

    /// Whether log export can be initialized.
    pub logs: bool,
}

impl OtlpSignalSupport {
    const NONE: Self = Self {
        traces: false,
        metrics: false,
        logs: false,
    };

    const ALL: Self = Self {
        traces: true,
        metrics: true,
        logs: true,
    };
}

/// Redaction-safe readiness summary for host/admin OTLP diagnostics.
///
/// This intentionally reports endpoint classes and counts instead of raw
/// endpoint URLs, collector headers, or resource attribute values. Host/admin
/// APIs can serialize this type directly without exposing bearer tokens,
/// account IDs, local paths, or collector hostnames.
#[derive(Debug, Clone, serde::Serialize, PartialEq)]
pub struct OtlpReadiness {
    /// Implementation boundary. OTLP export is a crate-level runtime feature,
    /// not a connector binary.
    pub boundary: &'static str,

    /// Stable readiness status: `disabled`, `unavailable`, `fail`, or `ready`.
    pub status: &'static str,

    /// Whether operator configuration requested OTLP export.
    pub enabled: bool,

    /// Whether this build includes the optional `otlp` feature.
    pub feature_compiled: bool,

    /// Whether a non-empty OTLP endpoint was configured.
    pub endpoint_configured: bool,

    /// Redaction-safe endpoint class, never the raw endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_class: Option<&'static str>,

    /// Signal export support for this config/build.
    pub signals: OtlpSignalSupport,

    /// Number of validated collector headers. Header values are never exposed.
    pub collector_header_count: usize,

    /// Number of validated resource attributes. Attribute values are never exposed.
    pub resource_attribute_count: usize,

    /// Operator configured trace sample rate.
    pub trace_sample_rate: f64,

    /// Stable class for the configured sample rate.
    pub trace_sample_rate_class: &'static str,

    /// Redaction-safe message suitable for admin/readiness output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

fn resolve_prometheus_port() -> u16 {
    resolve_prometheus_port_with(|key| std::env::var(key).ok())
}

fn resolve_prometheus_port_with<F>(mut get_env: F) -> u16
where
    F: FnMut(&str) -> Option<String>,
{
    for key in PROMETHEUS_PORT_ENV_VARS {
        let Some(value) = get_env(key) else {
            continue;
        };
        let trimmed = value.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(port) = trimmed.parse::<u16>() {
            return port;
        }
    }
    DEFAULT_PROMETHEUS_PORT
}

/// Validated OTLP collector header.
///
/// Header values are intentionally redacted from [`Debug`] so bearer tokens and
/// API keys cannot leak through config diagnostics.
#[derive(Clone, PartialEq, Eq)]
pub struct OtlpHeader {
    /// Lowercase header/metadata name.
    pub name: String,

    /// Header/metadata value.
    pub value: String,
}

impl OtlpHeader {
    /// Build a validated OTLP collector header.
    ///
    /// Header names are normalized to lowercase because OTLP over gRPC uses
    /// HTTP/2 metadata names.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryError::Config`] when the header name or value cannot
    /// be represented safely as OTLP collector metadata.
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Result<Self, TelemetryError> {
        let name = name.into();
        let value = value.into();
        let name = normalize_otlp_header_name(&name)?;
        let value = normalize_otlp_header_value(&value)?;
        Ok(Self { name, value })
    }
}

impl fmt::Debug for OtlpHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OtlpHeader")
            .field("name", &self.name)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// Validated OTLP resource attribute.
///
/// Attribute values are redacted from [`Debug`] because operators can source
/// them from environment variables, and not every deployment keeps resource
/// labels free of hostnames, account IDs, or other sensitive material.
#[derive(Clone, PartialEq, Eq)]
pub struct OtlpResourceAttribute {
    /// Resource attribute key.
    pub key: String,

    /// Resource attribute value.
    pub value: String,
}

impl OtlpResourceAttribute {
    /// Build a validated OTLP resource attribute.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryError::Config`] when the key or value is malformed.
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Result<Self, TelemetryError> {
        let key = key.into();
        let value = value.into();
        let key = normalize_otlp_resource_key(&key)?;
        let value = normalize_otlp_resource_value(&value)?;
        Ok(Self { key, value })
    }
}

impl fmt::Debug for OtlpResourceAttribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OtlpResourceAttribute")
            .field("key", &self.key)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// Configuration for telemetry initialization.
///
/// The Prometheus metrics port can be overridden at startup via, in precedence order:
/// `FCP_TELEMETRY_PROMETHEUS_PORT`, `FCP_TELEMETRY_PORT`, `FCP_PROMETHEUS_PORT`,
/// or `PROMETHEUS_PORT`.
#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    /// Service/connector name for identifying logs and metrics.
    pub service_name: String,

    /// Log level filter (e.g., "info", "debug", "trace").
    pub log_level: String,

    /// Enable JSON log output.
    pub json_logs: bool,

    /// Enable Prometheus metrics endpoint.
    pub prometheus_enabled: bool,

    /// Prometheus metrics endpoint port.
    pub prometheus_port: u16,

    /// Enable OTLP trace, metric, and log export.
    pub otlp_enabled: bool,

    /// OTLP endpoint URL.
    pub otlp_endpoint: Option<String>,

    /// OTLP collector headers/metadata.
    pub otlp_headers: Vec<OtlpHeader>,

    /// OTLP resource attributes attached to exported telemetry.
    pub otlp_resource_attributes: Vec<OtlpResourceAttribute>,

    /// Sample rate for tracing (0.0 to 1.0).
    pub trace_sample_rate: f64,

    /// Fields to redact from logs (sensitive data).
    pub redact_fields: Vec<String>,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            service_name: "fcp-connector".to_string(),
            log_level: "info".to_string(),
            json_logs: true,
            prometheus_enabled: false,
            prometheus_port: resolve_prometheus_port(),
            otlp_enabled: false,
            otlp_endpoint: None,
            otlp_headers: Vec::new(),
            otlp_resource_attributes: Vec::new(),
            trace_sample_rate: 1.0,
            redact_fields: vec![
                "password".to_string(),
                "api_key".to_string(),
                "secret".to_string(),
                "token".to_string(),
                "authorization".to_string(),
            ],
        }
    }
}

/// Return the currently initialized telemetry configuration, if telemetry has already started.
#[must_use]
pub fn current_telemetry_config() -> Option<&'static TelemetryConfig> {
    TELEMETRY.get().map(|state| &state.config)
}

/// Return whether this build can initialize OTLP exporters.
#[must_use]
pub const fn otlp_feature_compiled() -> bool {
    cfg!(feature = "otlp")
}

/// Build a redaction-safe OTLP readiness summary for host/admin diagnostics.
///
/// The returned value is safe to serialize into readiness APIs and evidence
/// logs. It validates the same endpoint/header/resource settings used during
/// exporter initialization, but it reports only endpoint class and counts.
#[must_use]
pub fn otlp_readiness(config: &TelemetryConfig) -> OtlpReadiness {
    let endpoint = config.otlp_endpoint.as_deref().and_then(non_empty_trimmed);
    let endpoint_class = endpoint
        .as_deref()
        .map(classify_otlp_endpoint)
        .or_else(|| config.otlp_endpoint.as_deref().map(|_| "invalid"));
    let feature_compiled = otlp_feature_compiled();
    let trace_sample_rate_class = trace_sample_rate_class(config.trace_sample_rate);
    let base = OtlpReadiness {
        boundary: OTLP_EXPORT_BOUNDARY,
        status: "disabled",
        enabled: false,
        feature_compiled,
        endpoint_configured: endpoint.is_some(),
        endpoint_class,
        signals: OtlpSignalSupport::NONE,
        collector_header_count: config.otlp_headers.len(),
        resource_attribute_count: config.otlp_resource_attributes.len(),
        trace_sample_rate: config.trace_sample_rate,
        trace_sample_rate_class,
        message: None,
    };

    if !config.otlp_enabled {
        return OtlpReadiness {
            message: Some("OTLP export is disabled by configuration".to_string()),
            ..base
        };
    }

    let Some(endpoint) = endpoint else {
        return OtlpReadiness {
            status: "fail",
            enabled: true,
            endpoint_configured: false,
            message: Some("OTLP export is enabled but no endpoint is configured".to_string()),
            ..base
        };
    };

    let validation = validate_otlp_endpoint(&endpoint)
        .and_then(|()| validate_otlp_headers(&config.otlp_headers))
        .and_then(|()| validate_otlp_resource_attributes(&config.otlp_resource_attributes));

    if let Err(error) = validation {
        return OtlpReadiness {
            status: "fail",
            enabled: true,
            endpoint_configured: true,
            endpoint_class: Some("invalid"),
            message: Some(error.to_string()),
            ..base
        };
    }

    if !feature_compiled {
        return OtlpReadiness {
            status: "unavailable",
            enabled: true,
            endpoint_configured: true,
            message: Some(
                "OTLP export requires fcp-telemetry to be built with the `otlp` feature"
                    .to_string(),
            ),
            ..base
        };
    }

    OtlpReadiness {
        status: "ready",
        enabled: true,
        endpoint_configured: true,
        signals: OtlpSignalSupport::ALL,
        ..base
    }
}

impl TelemetryConfig {
    /// Create a new configuration with the given service name.
    #[must_use]
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
            ..Default::default()
        }
    }

    /// Build telemetry configuration from the standard OpenTelemetry environment variables.
    ///
    /// Recognized variables include `OTEL_SERVICE_NAME`,
    /// `OTEL_RESOURCE_ATTRIBUTES`, `OTEL_EXPORTER_OTLP_ENDPOINT`,
    /// `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`, `OTEL_EXPORTER_OTLP_HEADERS`, and
    /// `OTEL_EXPORTER_OTLP_TRACES_HEADERS`. Trace-specific endpoint/header
    /// variables take precedence over generic OTLP variables.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryError::Config`] when any operator-provided OTLP value
    /// is malformed.
    pub fn from_env() -> Result<Self, TelemetryError> {
        Self::from_env_with(|key| std::env::var(key).ok())
    }

    fn from_env_with<F>(mut get_env: F) -> Result<Self, TelemetryError>
    where
        F: FnMut(&str) -> Option<String>,
    {
        let prometheus_port = resolve_prometheus_port_with(&mut get_env);
        let resource_attributes = parse_otlp_resource_attributes_env(
            get_env(OTEL_RESOURCE_ATTRIBUTES_ENV_VAR).as_deref(),
        )?;
        let service_name = get_env(OTEL_SERVICE_NAME_ENV_VAR)
            .and_then(|value| non_empty_trimmed(&value))
            .or_else(|| {
                resource_attributes
                    .iter()
                    .find(|attr| attr.key == "service.name")
                    .map(|attr| attr.value.clone())
            })
            .unwrap_or_else(|| "fcp-connector".to_string());

        let mut config = Self::new(service_name);
        config.prometheus_port = prometheus_port;
        config.otlp_resource_attributes = resource_attributes;

        if let Some(endpoint) =
            first_non_empty_env_value(&mut get_env, OTLP_ENDPOINT_ENV_VARS.iter().copied())
        {
            config = config.with_otlp(endpoint);
        }

        config.otlp_headers = parse_otlp_headers_env(&mut get_env)?;

        Ok(config)
    }

    /// Set the log level.
    #[must_use]
    pub fn with_log_level(mut self, level: impl Into<String>) -> Self {
        self.log_level = level.into();
        self
    }

    /// Enable or disable JSON logs.
    #[must_use]
    pub const fn with_json_logs(mut self, enabled: bool) -> Self {
        self.json_logs = enabled;
        self
    }

    /// Enable Prometheus metrics on the given port.
    #[must_use]
    pub const fn with_prometheus(mut self, port: u16) -> Self {
        self.prometheus_enabled = true;
        self.prometheus_port = port;
        self
    }

    /// Enable OTLP trace, metric, and log export to the given endpoint.
    #[must_use]
    pub fn with_otlp(mut self, endpoint: impl Into<String>) -> Self {
        self.otlp_enabled = true;
        self.otlp_endpoint = Some(endpoint.into());
        self
    }

    /// Set the trace sampling rate (0.0 to 1.0).
    #[must_use]
    pub const fn with_sample_rate(mut self, rate: f64) -> Self {
        self.trace_sample_rate = rate;
        self
    }

    /// Add fields to redact from logs.
    #[must_use]
    pub fn with_redact_fields(mut self, fields: Vec<String>) -> Self {
        self.redact_fields.extend(fields);
        self
    }

    /// Attach validated OTLP collector headers.
    #[must_use]
    pub fn with_otlp_headers(mut self, headers: Vec<OtlpHeader>) -> Self {
        self.otlp_headers = headers;
        self
    }

    /// Parse and attach OTLP collector headers from a comma-separated
    /// `key=value,key2=value2` string.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryError::Config`] when the header string is malformed
    /// or contains metadata that cannot safely be sent to the collector.
    pub fn try_with_otlp_headers(mut self, headers: &str) -> Result<Self, TelemetryError> {
        self.otlp_headers = parse_otlp_headers(headers)?;
        Ok(self)
    }

    /// Attach validated OTLP resource attributes.
    #[must_use]
    pub fn with_otlp_resource_attributes(mut self, attributes: Vec<OtlpResourceAttribute>) -> Self {
        self.otlp_resource_attributes = attributes;
        self
    }

    /// Parse and attach OTLP resource attributes from a comma-separated
    /// `key=value,key2=value2` string.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryError::Config`] when the attribute string is
    /// malformed.
    pub fn try_with_otlp_resource_attributes(
        mut self,
        attributes: &str,
    ) -> Result<Self, TelemetryError> {
        self.otlp_resource_attributes = parse_otlp_resource_attributes(attributes)?;
        Ok(self)
    }
}

fn non_empty_trimmed(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn first_non_empty_env_value<'a, F, I>(get_env: &mut F, keys: I) -> Option<String>
where
    F: FnMut(&str) -> Option<String>,
    I: IntoIterator<Item = &'a str>,
{
    keys.into_iter()
        .find_map(|key| get_env(key).and_then(|value| non_empty_trimmed(&value)))
}

fn classify_otlp_endpoint(endpoint: &str) -> &'static str {
    let Some(rest) = endpoint.strip_prefix("https://") else {
        let Some(rest) = endpoint.strip_prefix("http://") else {
            return "invalid";
        };
        return if is_loopback_otlp_authority(rest) {
            "http_loopback"
        } else {
            "http_plaintext"
        };
    };

    if is_loopback_otlp_authority(rest) {
        "https_loopback"
    } else {
        "https"
    }
}

fn is_loopback_otlp_authority(rest: &str) -> bool {
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    if let Some(host) = authority
        .strip_prefix('[')
        .and_then(|value| value.split(']').next())
    {
        return host == "::1";
    }
    let host = authority
        .rsplit_once(':')
        .map_or(authority, |(host, _port)| host);
    matches!(host, "localhost" | "127.0.0.1" | "::1")
        || host.ends_with(".localhost")
        || host.starts_with("127.")
}

const fn trace_sample_rate_class(rate: f64) -> &'static str {
    if rate.is_nan() {
        "disabled_invalid"
    } else if rate <= 0.0 {
        "disabled_zero"
    } else if rate >= 1.0 {
        "always_on"
    } else {
        "ratio"
    }
}

const fn is_valid_otlp_name_char(ch: char) -> bool {
    matches!(ch, 'a'..='z' | '0'..='9' | '-' | '_' | '.')
}

fn normalize_otlp_header_name(name: &str) -> Result<String, TelemetryError> {
    let normalized = name.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(TelemetryError::Config(
            "OTLP header name must not be empty".to_string(),
        ));
    }
    if normalized.len() > MAX_OTLP_HEADER_NAME_LEN {
        return Err(TelemetryError::Config(format!(
            "OTLP header name length must not exceed {MAX_OTLP_HEADER_NAME_LEN} bytes"
        )));
    }
    if normalized
        .chars()
        .any(|ch| !ch.is_ascii() || !is_valid_otlp_name_char(ch))
    {
        return Err(TelemetryError::Config(
            "OTLP header names may only contain lowercase ASCII letters, digits, '-', '_' and '.'"
                .to_string(),
        ));
    }
    if normalized.ends_with("-bin") {
        return Err(TelemetryError::Config(
            "OTLP binary metadata headers are not supported".to_string(),
        ));
    }
    Ok(normalized)
}

fn normalize_otlp_header_value(value: &str) -> Result<String, TelemetryError> {
    let normalized = value.trim().to_string();
    if normalized.is_empty() {
        return Err(TelemetryError::Config(
            "OTLP header value must not be empty".to_string(),
        ));
    }
    if normalized.len() > MAX_OTLP_HEADER_VALUE_LEN {
        return Err(TelemetryError::Config(format!(
            "OTLP header value length must not exceed {MAX_OTLP_HEADER_VALUE_LEN} bytes"
        )));
    }
    if normalized
        .chars()
        .any(|ch| !ch.is_ascii() || ch.is_control())
    {
        return Err(TelemetryError::Config(
            "OTLP header values must be printable ASCII".to_string(),
        ));
    }
    Ok(normalized)
}

fn normalize_otlp_resource_key(key: &str) -> Result<String, TelemetryError> {
    let normalized = key.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(TelemetryError::Config(
            "OTLP resource attribute key must not be empty".to_string(),
        ));
    }
    if normalized.len() > MAX_OTLP_RESOURCE_ATTRIBUTE_KEY_LEN {
        return Err(TelemetryError::Config(format!(
            "OTLP resource attribute key length must not exceed {MAX_OTLP_RESOURCE_ATTRIBUTE_KEY_LEN} bytes"
        )));
    }
    if normalized
        .chars()
        .any(|ch| !ch.is_ascii() || !is_valid_otlp_name_char(ch))
    {
        return Err(TelemetryError::Config(
            "OTLP resource attribute keys may only contain ASCII letters, digits, '-', '_' and '.'"
                .to_string(),
        ));
    }
    Ok(normalized)
}

fn normalize_otlp_resource_value(value: &str) -> Result<String, TelemetryError> {
    let normalized = value.trim().to_string();
    if normalized.is_empty() {
        return Err(TelemetryError::Config(
            "OTLP resource attribute value must not be empty".to_string(),
        ));
    }
    if normalized.len() > MAX_OTLP_RESOURCE_ATTRIBUTE_VALUE_LEN {
        return Err(TelemetryError::Config(format!(
            "OTLP resource attribute value length must not exceed {MAX_OTLP_RESOURCE_ATTRIBUTE_VALUE_LEN} bytes"
        )));
    }
    if normalized.chars().any(char::is_control) {
        return Err(TelemetryError::Config(
            "OTLP resource attribute values must not contain control characters".to_string(),
        ));
    }
    Ok(normalized)
}

fn percent_decode_otlp_value(value: &str) -> Result<String, TelemetryError> {
    let mut decoded = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;
    while let Some(byte) = bytes.get(index).copied() {
        if byte == b'%' {
            let Some(first) = bytes.get(index + 1).copied() else {
                return Err(TelemetryError::Config(
                    "OTLP percent-encoded value is truncated".to_string(),
                ));
            };
            let Some(second) = bytes.get(index + 2).copied() else {
                return Err(TelemetryError::Config(
                    "OTLP percent-encoded value is truncated".to_string(),
                ));
            };
            let high = hex_digit(first).ok_or_else(|| {
                TelemetryError::Config("OTLP percent-encoded value is invalid".to_string())
            })?;
            let low = hex_digit(second).ok_or_else(|| {
                TelemetryError::Config("OTLP percent-encoded value is invalid".to_string())
            })?;
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(byte);
            index += 1;
        }
    }
    String::from_utf8(decoded)
        .map_err(|_| TelemetryError::Config("OTLP percent-encoded value is not UTF-8".to_string()))
}

const fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Parse OTLP collector headers from a comma-separated environment string.
///
/// # Errors
///
/// Returns [`TelemetryError::Config`] when any pair is malformed or invalid.
pub fn parse_otlp_headers(headers: &str) -> Result<Vec<OtlpHeader>, TelemetryError> {
    let mut parsed = Vec::new();
    for pair in headers.split_terminator(',').map(str::trim) {
        if pair.is_empty() {
            continue;
        }
        let (name, value) = pair.split_once('=').ok_or_else(|| {
            TelemetryError::Config("OTLP header entries must use key=value syntax".to_string())
        })?;
        upsert_otlp_header(
            &mut parsed,
            OtlpHeader::new(name, percent_decode_otlp_value(value.trim())?)?,
        );
        if parsed.len() > MAX_OTLP_HEADER_COUNT {
            return Err(TelemetryError::Config(format!(
                "OTLP header count must not exceed {MAX_OTLP_HEADER_COUNT}"
            )));
        }
    }
    Ok(parsed)
}

fn upsert_otlp_header(headers: &mut Vec<OtlpHeader>, header: OtlpHeader) {
    if let Some(existing) = headers
        .iter_mut()
        .find(|existing| existing.name == header.name)
    {
        *existing = header;
    } else {
        headers.push(header);
    }
}

fn parse_otlp_headers_env<F>(get_env: &mut F) -> Result<Vec<OtlpHeader>, TelemetryError>
where
    F: FnMut(&str) -> Option<String>,
{
    let mut headers = Vec::new();
    for key in OTLP_HEADERS_ENV_VARS {
        let Some(value) = get_env(key).and_then(|value| non_empty_trimmed(&value)) else {
            continue;
        };
        for header in parse_otlp_headers(&value)? {
            upsert_otlp_header(&mut headers, header);
        }
    }
    validate_otlp_headers(&headers)?;
    Ok(headers)
}

/// Parse OTLP resource attributes from a comma-separated environment string.
///
/// # Errors
///
/// Returns [`TelemetryError::Config`] when any pair is malformed or invalid.
pub fn parse_otlp_resource_attributes(
    attributes: &str,
) -> Result<Vec<OtlpResourceAttribute>, TelemetryError> {
    let mut parsed = Vec::new();
    for pair in attributes.split_terminator(',').map(str::trim) {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=').ok_or_else(|| {
            TelemetryError::Config("OTLP resource attributes must use key=value syntax".to_string())
        })?;
        upsert_otlp_resource_attribute(
            &mut parsed,
            OtlpResourceAttribute::new(key, percent_decode_otlp_value(value.trim())?)?,
        );
        if parsed.len() > MAX_OTLP_RESOURCE_ATTRIBUTE_COUNT {
            return Err(TelemetryError::Config(format!(
                "OTLP resource attribute count must not exceed {MAX_OTLP_RESOURCE_ATTRIBUTE_COUNT}"
            )));
        }
    }
    Ok(parsed)
}

fn upsert_otlp_resource_attribute(
    attributes: &mut Vec<OtlpResourceAttribute>,
    attribute: OtlpResourceAttribute,
) {
    if let Some(existing) = attributes
        .iter_mut()
        .find(|existing| existing.key == attribute.key)
    {
        *existing = attribute;
    } else {
        attributes.push(attribute);
    }
}

fn parse_otlp_resource_attributes_env(
    value: Option<&str>,
) -> Result<Vec<OtlpResourceAttribute>, TelemetryError> {
    let Some(value) = value.and_then(non_empty_trimmed) else {
        return Ok(Vec::new());
    };
    let attributes = parse_otlp_resource_attributes(&value)?;
    validate_otlp_resource_attributes(&attributes)?;
    Ok(attributes)
}

/// Validate OTLP collector headers.
///
/// # Errors
///
/// Returns [`TelemetryError::Config`] when the header set is malformed.
pub fn validate_otlp_headers(headers: &[OtlpHeader]) -> Result<(), TelemetryError> {
    if headers.len() > MAX_OTLP_HEADER_COUNT {
        return Err(TelemetryError::Config(format!(
            "OTLP header count must not exceed {MAX_OTLP_HEADER_COUNT}"
        )));
    }
    for header in headers {
        let normalized = OtlpHeader::new(header.name.as_str(), header.value.as_str())?;
        if normalized != *header {
            return Err(TelemetryError::Config(
                "OTLP headers must be stored in normalized form".to_string(),
            ));
        }
    }
    Ok(())
}

/// Validate OTLP resource attributes.
///
/// # Errors
///
/// Returns [`TelemetryError::Config`] when the attribute set is malformed.
pub fn validate_otlp_resource_attributes(
    attributes: &[OtlpResourceAttribute],
) -> Result<(), TelemetryError> {
    if attributes.len() > MAX_OTLP_RESOURCE_ATTRIBUTE_COUNT {
        return Err(TelemetryError::Config(format!(
            "OTLP resource attribute count must not exceed {MAX_OTLP_RESOURCE_ATTRIBUTE_COUNT}"
        )));
    }
    for attribute in attributes {
        let normalized =
            OtlpResourceAttribute::new(attribute.key.as_str(), attribute.value.as_str())?;
        if normalized != *attribute {
            return Err(TelemetryError::Config(
                "OTLP resource attributes must be stored in normalized form".to_string(),
            ));
        }
    }
    Ok(())
}

fn is_valid_otlp_port(port: &str) -> bool {
    !port.is_empty() && port.parse::<u16>().is_ok()
}

fn validate_otlp_authority(authority: &str) -> bool {
    if authority.is_empty() {
        return false;
    }

    if authority.starts_with('[') {
        let Some(close_bracket) = authority.find(']') else {
            return false;
        };
        if close_bracket == 1 {
            return false;
        }
        let after_bracket = &authority[close_bracket + 1..];
        return after_bracket.is_empty()
            || after_bracket
                .strip_prefix(':')
                .is_some_and(is_valid_otlp_port);
    }

    let (host, port) = authority
        .rsplit_once(':')
        .map_or((authority, None), |(host, port)| (host, Some(port)));
    !host.is_empty() && !host.contains(':') && port.is_none_or(is_valid_otlp_port)
}

/// Validate an operator-provided OTLP endpoint before initializing exporters.
///
/// The endpoint must be a whitespace-free `http://` or `https://` URL with a
/// host and optional valid port. User-info, query strings, and fragments are
/// rejected because they frequently carry API keys or bearer material and would
/// be too easy to leak through SDK errors or logs.
///
/// # Errors
///
/// Returns [`TelemetryError::Config`] when the endpoint is empty, malformed, or
/// secret-bearing.
pub fn validate_otlp_endpoint(endpoint: &str) -> Result<(), TelemetryError> {
    if endpoint.trim().is_empty() {
        return Err(TelemetryError::Config(
            "OTLP endpoint must not be empty".to_string(),
        ));
    }
    if endpoint.trim() != endpoint {
        return Err(TelemetryError::Config(
            "OTLP endpoint must not contain leading or trailing whitespace".to_string(),
        ));
    }
    if endpoint.len() > MAX_OTLP_ENDPOINT_LEN {
        return Err(TelemetryError::Config(format!(
            "OTLP endpoint length must not exceed {MAX_OTLP_ENDPOINT_LEN} bytes"
        )));
    }
    if endpoint
        .chars()
        .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        return Err(TelemetryError::Config(
            "OTLP endpoint must not contain whitespace or control characters".to_string(),
        ));
    }

    let rest = endpoint
        .strip_prefix("http://")
        .or_else(|| endpoint.strip_prefix("https://"))
        .ok_or_else(|| {
            TelemetryError::Config("OTLP endpoint must use http:// or https://".to_string())
        })?;
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];

    if !validate_otlp_authority(authority) {
        return Err(TelemetryError::Config(
            "OTLP endpoint must include a valid host and optional port".to_string(),
        ));
    }
    if authority.contains('@') {
        return Err(TelemetryError::Config(
            "OTLP endpoint must not contain user-info credentials".to_string(),
        ));
    }
    if endpoint.contains('?') || endpoint.contains('#') {
        return Err(TelemetryError::Config(
            "OTLP endpoint must not contain query strings or fragments".to_string(),
        ));
    }

    Ok(())
}

fn init_telemetry_with<L, P, M, G, T>(
    state: &OnceLock<TelemetryState>,
    config: TelemetryConfig,
    init_logging_fn: L,
    init_prometheus_fn: P,
    init_otlp_metrics_fn: M,
    init_otlp_logs_fn: G,
    init_otlp_traces_fn: T,
) -> Result<(), TelemetryError>
where
    L: Fn(&TelemetryConfig) -> Result<(), TelemetryError>,
    P: Fn(u16) -> Result<(), TelemetryError>,
    M: Fn(&str, &str, &[OtlpHeader], &[OtlpResourceAttribute]) -> Result<(), TelemetryError>,
    G: Fn(&str, &str, &[OtlpHeader], &[OtlpResourceAttribute]) -> Result<(), TelemetryError>,
    T: Fn(&str, &str, f64, &[OtlpHeader], &[OtlpResourceAttribute]) -> Result<(), TelemetryError>,
{
    if state.get().is_some() {
        return Ok(());
    }

    let _guard = TELEMETRY_INIT_LOCK
        .lock()
        .map_err(|_| TelemetryError::Config("telemetry init lock poisoned".to_string()))?;

    if state.get().is_some() {
        return Ok(());
    }

    let otlp_endpoint = if config.otlp_enabled {
        config.otlp_endpoint.as_deref()
    } else {
        None
    };
    if let Some(endpoint) = otlp_endpoint {
        validate_otlp_endpoint(endpoint)?;
    }
    validate_otlp_headers(&config.otlp_headers)?;
    validate_otlp_resource_attributes(&config.otlp_resource_attributes)?;

    if let Some(endpoint) = otlp_endpoint {
        init_otlp_metrics_fn(
            &config.service_name,
            endpoint,
            &config.otlp_headers,
            &config.otlp_resource_attributes,
        )?;
        init_otlp_logs_fn(
            &config.service_name,
            endpoint,
            &config.otlp_headers,
            &config.otlp_resource_attributes,
        )?;
    }

    init_logging_fn(&config)?;

    if config.prometheus_enabled {
        init_prometheus_fn(config.prometheus_port)?;
    }

    if let Some(endpoint) = otlp_endpoint {
        // Thread the operator-configured sample rate through to the
        // SDK so `with_sample_rate(0.01)` actually results in a 1%
        // sampling rate rather than silently exporting 100% of
        // spans. Prior behavior silently dropped the rate on the
        // floor and used Sampler::AlwaysOn unconditionally.
        init_otlp_traces_fn(
            &config.service_name,
            endpoint,
            config.trace_sample_rate,
            &config.otlp_headers,
            &config.otlp_resource_attributes,
        )?;
    }

    let _ = state.set(TelemetryState { config });

    Ok(())
}

/// Initialize the telemetry system.
///
/// This should be called once at application startup. Subsequent calls are no-ops.
///
/// # Errors
///
/// Returns an error if telemetry initialization fails.
pub fn init_telemetry(config: TelemetryConfig) -> Result<(), TelemetryError> {
    init_telemetry_with(
        &TELEMETRY,
        config,
        init_logging,
        init_prometheus_exporter,
        init_otlp_metrics_with_options,
        init_otlp_logs_with_options,
        init_otlp_tracer_with_sample_rate_and_options,
    )
}

/// Initialize telemetry synchronously (for simple use cases without OTLP).
///
/// # Errors
///
/// Returns an error if initialization fails.
pub fn init_telemetry_sync(config: TelemetryConfig) -> Result<(), TelemetryError> {
    let mut config = config;
    config.otlp_enabled = false;
    init_telemetry_with(
        &TELEMETRY,
        config,
        init_logging,
        init_prometheus_exporter,
        init_otlp_metrics_with_options,
        init_otlp_logs_with_options,
        init_otlp_tracer_with_sample_rate_and_options,
    )
}

/// Telemetry error type.
#[derive(Debug, thiserror::Error)]
pub enum TelemetryError {
    /// Failed to initialize logging.
    #[error("Failed to initialize logging: {0}")]
    LoggingInit(String),

    /// Failed to initialize metrics.
    #[error("Failed to initialize metrics: {0}")]
    MetricsInit(String),

    /// Failed to initialize tracing.
    #[error("Failed to initialize tracing: {0}")]
    TracingInit(String),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),
}

/// Shutdown telemetry gracefully.
///
/// This flushes any pending metrics and traces.
/// Note: In opentelemetry 0.31+, shutdown is handled by the `SdkTracerProvider`
/// directly. Call `.shutdown()` on the provider instance returned by `init_otlp_tracer`
/// if you need explicit flush behavior.
pub fn shutdown_telemetry() {
    tracing::info!("Telemetry shutdown requested");
    if let Err(error) = crate::export::shutdown_otlp_metrics() {
        tracing::warn!(?error, "OTLP metrics shutdown failed");
    }
    if let Err(error) = crate::export::shutdown_otlp_tracer() {
        tracing::warn!(?error, "OTLP tracer shutdown failed");
    }
    if let Err(error) = crate::export::shutdown_otlp_logs() {
        tracing::warn!(?error, "OTLP logs shutdown failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    type CapturedOtlpConfig = Option<(usize, usize, String, String)>;

    fn capture_otlp_config(
        captured: &std::sync::Mutex<CapturedOtlpConfig>,
        signal: &str,
        headers: &[OtlpHeader],
        attributes: &[OtlpResourceAttribute],
    ) -> Result<(), TelemetryError> {
        let header_name = headers
            .first()
            .ok_or_else(|| TelemetryError::Config("expected OTLP header".to_string()))?
            .name
            .clone();
        let attribute_key = attributes
            .first()
            .ok_or_else(|| TelemetryError::Config("expected OTLP resource attribute".to_string()))?
            .key
            .clone();
        *captured.lock().map_err(|_| {
            TelemetryError::Config(format!("captured OTLP {signal} config lock poisoned"))
        })? = Some((headers.len(), attributes.len(), header_name, attribute_key));
        Ok(())
    }

    fn captured_otlp_config(
        captured: std::sync::Mutex<CapturedOtlpConfig>,
        signal: &str,
    ) -> Result<CapturedOtlpConfig, TelemetryError> {
        captured.into_inner().map_err(|_| {
            TelemetryError::Config(format!("captured OTLP {signal} config lock poisoned"))
        })
    }

    #[test]
    #[allow(clippy::float_cmp)] // exact float comparison is safe for sample rate
    fn test_telemetry_config_default() {
        let config = TelemetryConfig::default();

        assert_eq!(config.service_name, "fcp-connector");
        assert_eq!(config.log_level, "info");
        assert!(config.json_logs);
        assert!(!config.prometheus_enabled);
        assert_eq!(config.prometheus_port, DEFAULT_PROMETHEUS_PORT);
        assert!(!config.otlp_enabled);
        assert!(config.otlp_endpoint.is_none());
        assert!(config.otlp_headers.is_empty());
        assert!(config.otlp_resource_attributes.is_empty());
        assert_eq!(config.trace_sample_rate, 1.0);
        assert!(!config.redact_fields.is_empty());
    }

    #[test]
    fn test_resolve_prometheus_port_uses_first_valid_env_var() {
        let resolved = resolve_prometheus_port_with(|key| match key {
            "FCP_TELEMETRY_PROMETHEUS_PORT" => Some("9200".to_string()),
            "FCP_TELEMETRY_PORT" => Some("9300".to_string()),
            _ => None,
        });

        assert_eq!(resolved, 9200);
    }

    #[test]
    fn test_resolve_prometheus_port_falls_back_to_lower_priority_env_var() {
        let resolved = resolve_prometheus_port_with(|key| match key {
            "FCP_TELEMETRY_PROMETHEUS_PORT" => Some("not-a-port".to_string()),
            "FCP_TELEMETRY_PORT" => Some("   ".to_string()),
            "FCP_PROMETHEUS_PORT" => Some("9400".to_string()),
            _ => None,
        });

        assert_eq!(resolved, 9400);
    }

    #[test]
    fn test_resolve_prometheus_port_uses_compiled_default_when_no_env_is_valid() {
        let resolved = resolve_prometheus_port_with(|key| match key {
            "FCP_TELEMETRY_PROMETHEUS_PORT" => Some("70000".to_string()),
            "PROMETHEUS_PORT" => Some("invalid".to_string()),
            _ => None,
        });

        assert_eq!(resolved, DEFAULT_PROMETHEUS_PORT);
    }

    #[test]
    fn test_telemetry_config_new() {
        let config = TelemetryConfig::new("my-service");

        assert_eq!(config.service_name, "my-service");
        // Other fields should be defaults
        assert_eq!(config.log_level, "info");
    }

    #[test]
    fn test_telemetry_config_with_log_level() {
        let config = TelemetryConfig::new("test").with_log_level("debug");

        assert_eq!(config.log_level, "debug");
    }

    #[test]
    fn test_telemetry_config_with_json_logs_enabled() {
        let config = TelemetryConfig::new("test").with_json_logs(true);

        assert!(config.json_logs);
    }

    #[test]
    fn test_telemetry_config_with_json_logs_disabled() {
        let config = TelemetryConfig::new("test").with_json_logs(false);

        assert!(!config.json_logs);
    }

    #[test]
    fn test_telemetry_config_with_prometheus() {
        let config = TelemetryConfig::new("test").with_prometheus(8080);

        assert!(config.prometheus_enabled);
        assert_eq!(config.prometheus_port, 8080);
    }

    #[test]
    fn test_telemetry_config_with_otlp() {
        let config = TelemetryConfig::new("test").with_otlp("http://localhost:4317");

        assert!(config.otlp_enabled);
        assert_eq!(
            config.otlp_endpoint,
            Some("http://localhost:4317".to_string())
        );
    }

    #[test]
    #[allow(clippy::float_cmp)] // exact float comparison is safe for sample rate
    fn test_telemetry_config_with_sample_rate() {
        let config = TelemetryConfig::new("test").with_sample_rate(0.5);

        assert_eq!(config.trace_sample_rate, 0.5);
    }

    #[test]
    fn test_telemetry_config_with_redact_fields() {
        let config =
            TelemetryConfig::new("test").with_redact_fields(vec!["custom_secret".to_string()]);

        assert!(config.redact_fields.contains(&"custom_secret".to_string()));
        // Should also still have the default fields
        assert!(config.redact_fields.contains(&"password".to_string()));
    }

    #[test]
    #[allow(clippy::float_cmp)] // exact float comparison is safe for sample rate
    fn test_telemetry_config_builder_chain() {
        let config = TelemetryConfig::new("my-connector")
            .with_log_level("trace")
            .with_json_logs(true)
            .with_prometheus(9091)
            .with_otlp("http://collector:4317")
            .with_sample_rate(0.1)
            .with_redact_fields(vec!["api_secret".to_string()]);

        assert_eq!(config.service_name, "my-connector");
        assert_eq!(config.log_level, "trace");
        assert!(config.json_logs);
        assert!(config.prometheus_enabled);
        assert_eq!(config.prometheus_port, 9091);
        assert!(config.otlp_enabled);
        assert_eq!(
            config.otlp_endpoint,
            Some("http://collector:4317".to_string())
        );
        assert_eq!(config.trace_sample_rate, 0.1);
        assert!(config.redact_fields.contains(&"api_secret".to_string()));
    }

    #[test]
    fn test_otlp_header_parse_normalizes_overrides_and_redacts_debug() -> Result<(), TelemetryError>
    {
        let headers = parse_otlp_headers(
            "Authorization=Bearer%20token,x-tenant=alpha,authorization=Basic%20token",
        )?;

        assert_eq!(headers.len(), 2);
        assert_eq!(
            headers.first().map(|header| header.name.as_str()),
            Some("authorization")
        );
        assert_eq!(
            headers.first().map(|header| header.value.as_str()),
            Some("Basic token")
        );
        assert_eq!(
            headers.get(1).map(|header| header.name.as_str()),
            Some("x-tenant")
        );
        assert_eq!(
            headers.get(1).map(|header| header.value.as_str()),
            Some("alpha")
        );

        let debug = format!(
            "{:?}",
            headers.first().ok_or_else(|| TelemetryError::Config(
                "expected authorization header".to_string()
            ))?
        );
        assert!(debug.contains("authorization"));
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("Basic token"));
        Ok(())
    }

    #[test]
    fn test_otlp_header_parse_rejects_malformed_or_unsafe_values() {
        for headers in [
            "authorization",
            "authorization=",
            "x-trace-bin=abc",
            "bad:name=value",
            "authorization=Bearer%ZZ",
            "authorization=Bearer%0Atoken",
            "authorization=tokén",
        ] {
            assert!(
                matches!(parse_otlp_headers(headers), Err(TelemetryError::Config(_))),
                "{headers:?} should be rejected",
            );
        }
    }

    #[test]
    fn test_otlp_resource_attribute_parse_overrides_and_redacts_debug() -> Result<(), TelemetryError>
    {
        let attributes = parse_otlp_resource_attributes(
            "service.version=1.2.3,deployment.environment=prod,service.version=1.2.4",
        )?;

        assert_eq!(attributes.len(), 2);
        assert_eq!(
            attributes.first().map(|attribute| attribute.key.as_str()),
            Some("service.version"),
        );
        assert_eq!(
            attributes.first().map(|attribute| attribute.value.as_str()),
            Some("1.2.4"),
        );
        assert_eq!(
            attributes.get(1).map(|attribute| attribute.key.as_str()),
            Some("deployment.environment"),
        );

        let debug = format!(
            "{:?}",
            attributes.first().ok_or_else(|| TelemetryError::Config(
                "expected service.version attribute".to_string()
            ))?
        );
        assert!(debug.contains("service.version"));
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("1.2.4"));
        Ok(())
    }

    #[test]
    fn test_telemetry_config_from_env_uses_otel_precedence() -> Result<(), TelemetryError> {
        let config = TelemetryConfig::from_env_with(|key| match key {
            "OTEL_SERVICE_NAME" => Some("env-service".to_string()),
            "OTEL_RESOURCE_ATTRIBUTES" => {
                Some("service.name=resource-service,service.version=1.0.0".to_string())
            }
            "OTEL_EXPORTER_OTLP_ENDPOINT" => Some("http://generic:4317".to_string()),
            "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT" => Some("https://traces:4317".to_string()),
            "OTEL_EXPORTER_OTLP_HEADERS" => Some("authorization=Bearer%20generic".to_string()),
            "OTEL_EXPORTER_OTLP_TRACES_HEADERS" => {
                Some("authorization=Bearer%20trace,x-tenant=prod".to_string())
            }
            _ => None,
        })?;

        assert_eq!(config.service_name, "env-service");
        assert!(config.otlp_enabled);
        assert_eq!(
            config.otlp_endpoint,
            Some("https://traces:4317".to_string())
        );
        assert_eq!(config.otlp_headers.len(), 2);
        assert_eq!(
            config
                .otlp_headers
                .first()
                .map(|header| header.name.as_str()),
            Some("authorization"),
        );
        assert_eq!(
            config
                .otlp_headers
                .first()
                .map(|header| header.value.as_str()),
            Some("Bearer trace"),
        );
        assert_eq!(
            config
                .otlp_headers
                .get(1)
                .map(|header| header.name.as_str()),
            Some("x-tenant"),
        );
        assert_eq!(config.otlp_resource_attributes.len(), 2);
        Ok(())
    }

    #[test]
    fn test_telemetry_config_debug_redacts_otlp_secrets() -> Result<(), TelemetryError> {
        let config = TelemetryConfig::new("svc")
            .with_otlp("http://otel:4317")
            .try_with_otlp_headers("authorization=Bearer%20secret-token")?
            .try_with_otlp_resource_attributes("cloud.account.id=123456789")?;

        let debug = format!("{config:?}");
        assert!(debug.contains("authorization"));
        assert!(debug.contains("cloud.account.id"));
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("secret-token"));
        assert!(!debug.contains("123456789"));
        Ok(())
    }

    #[test]
    fn test_otlp_readiness_disabled_is_redaction_safe() -> Result<(), TelemetryError> {
        let config = TelemetryConfig::new("svc")
            .try_with_otlp_headers("authorization=Bearer%20secret-token")?
            .try_with_otlp_resource_attributes("cloud.account.id=123456789")?;

        let readiness = otlp_readiness(&config);
        assert_eq!(readiness.boundary, OTLP_EXPORT_BOUNDARY);
        assert_eq!(readiness.status, "disabled");
        assert!(!readiness.enabled);
        assert!(!readiness.endpoint_configured);
        assert!(!readiness.signals.traces);
        assert_eq!(readiness.collector_header_count, 1);
        assert_eq!(readiness.resource_attribute_count, 1);

        let rendered = serde_json::to_string(&readiness)
            .map_err(|error| TelemetryError::Config(error.to_string()))?;
        assert!(rendered.contains("fcp-telemetry-crate"));
        assert!(!rendered.contains("secret-token"));
        assert!(!rendered.contains("123456789"));
        Ok(())
    }

    #[test]
    fn test_otlp_readiness_reports_feature_and_signal_support() -> Result<(), TelemetryError> {
        let config = TelemetryConfig::new("svc")
            .with_otlp("https://collector.example.com:4317/v1/traces")
            .with_sample_rate(0.25)
            .try_with_otlp_headers("authorization=Bearer%20secret-token")?
            .try_with_otlp_resource_attributes("cloud.account.id=123456789")?;

        let readiness = otlp_readiness(&config);
        assert!(readiness.enabled);
        if cfg!(feature = "otlp") {
            assert!(readiness.feature_compiled);
        } else {
            assert!(!readiness.feature_compiled);
        }
        assert!(readiness.endpoint_configured);
        assert_eq!(readiness.endpoint_class, Some("https"));
        assert_eq!(readiness.collector_header_count, 1);
        assert_eq!(readiness.resource_attribute_count, 1);
        assert_eq!(readiness.trace_sample_rate_class, "ratio");
        if cfg!(feature = "otlp") {
            assert_eq!(readiness.status, "ready");
            assert!(readiness.signals.traces);
            assert!(readiness.signals.metrics);
            assert!(readiness.signals.logs);
            assert!(readiness.message.is_none());
        } else {
            assert_eq!(readiness.status, "unavailable");
            assert!(!readiness.signals.traces);
            assert!(!readiness.signals.metrics);
            assert!(!readiness.signals.logs);
            assert!(
                readiness
                    .message
                    .as_deref()
                    .is_some_and(|message| message.contains("`otlp` feature"))
            );
        }

        let rendered = serde_json::to_string(&readiness)
            .map_err(|error| TelemetryError::Config(error.to_string()))?;
        assert!(!rendered.contains("collector.example.com"));
        assert!(!rendered.contains("secret-token"));
        assert!(!rendered.contains("123456789"));
        Ok(())
    }

    #[test]
    fn test_otlp_readiness_reports_invalid_config_before_feature_availability()
    -> Result<(), TelemetryError> {
        let config = TelemetryConfig::new("svc").with_otlp("https://api-key@collector:4317");

        let readiness = otlp_readiness(&config);
        assert_eq!(readiness.status, "fail");
        assert!(readiness.enabled);
        assert_eq!(readiness.endpoint_class, Some("invalid"));
        assert!(!readiness.signals.traces);
        assert!(
            readiness
                .message
                .as_deref()
                .is_some_and(|message| message.contains("user-info credentials"))
        );

        let rendered = serde_json::to_string(&readiness)
            .map_err(|error| TelemetryError::Config(error.to_string()))?;
        assert!(!rendered.contains("api-key"));
        assert!(!rendered.contains("collector:4317"));
        Ok(())
    }

    #[test]
    fn test_telemetry_config_debug() {
        let config = TelemetryConfig::default();
        let debug_str = format!("{config:?}");

        assert!(debug_str.contains("TelemetryConfig"));
        assert!(debug_str.contains("service_name"));
    }

    #[test]
    fn test_telemetry_config_clone() {
        let config = TelemetryConfig::new("test")
            .with_prometheus(8080)
            .with_log_level("debug");

        let cloned = config.clone();

        assert_eq!(config.service_name, cloned.service_name);
        assert_eq!(config.prometheus_port, cloned.prometheus_port);
        assert_eq!(config.log_level, cloned.log_level);
    }

    #[test]
    fn test_telemetry_error_logging_init() {
        let error = TelemetryError::LoggingInit("test error".to_string());
        let error_str = format!("{error}");

        assert!(error_str.contains("Failed to initialize logging"));
        assert!(error_str.contains("test error"));
    }

    #[test]
    fn test_telemetry_error_metrics_init() {
        let error = TelemetryError::MetricsInit("metrics error".to_string());
        let error_str = format!("{error}");

        assert!(error_str.contains("Failed to initialize metrics"));
        assert!(error_str.contains("metrics error"));
    }

    #[test]
    fn test_telemetry_error_tracing_init() {
        let error = TelemetryError::TracingInit("tracing error".to_string());
        let error_str = format!("{error}");

        assert!(error_str.contains("Failed to initialize tracing"));
        assert!(error_str.contains("tracing error"));
    }

    #[test]
    fn test_telemetry_error_config() {
        let error = TelemetryError::Config("config error".to_string());
        let error_str = format!("{error}");

        assert!(error_str.contains("Configuration error"));
        assert!(error_str.contains("config error"));
    }

    #[test]
    fn test_telemetry_error_debug() {
        let error = TelemetryError::LoggingInit("debug test".to_string());
        let debug_str = format!("{error:?}");

        assert!(debug_str.contains("LoggingInit"));
    }

    #[test]
    fn test_default_redact_fields() {
        let config = TelemetryConfig::default();

        assert!(config.redact_fields.contains(&"password".to_string()));
        assert!(config.redact_fields.contains(&"api_key".to_string()));
        assert!(config.redact_fields.contains(&"secret".to_string()));
        assert!(config.redact_fields.contains(&"token".to_string()));
        assert!(config.redact_fields.contains(&"authorization".to_string()));
    }

    #[test]
    #[allow(clippy::float_cmp)] // exact float comparison is safe for sample rate bounds
    fn test_telemetry_config_sample_rate_bounds() {
        // Test edge cases for sample rate
        let config_zero = TelemetryConfig::new("test").with_sample_rate(0.0);
        assert_eq!(config_zero.trace_sample_rate, 0.0);

        let config_one = TelemetryConfig::new("test").with_sample_rate(1.0);
        assert_eq!(config_one.trace_sample_rate, 1.0);
    }

    #[test]
    fn test_telemetry_config_new_from_string() {
        let name = String::from("dynamic-service");
        let config = TelemetryConfig::new(name);
        assert_eq!(config.service_name, "dynamic-service");
    }

    #[test]
    fn test_telemetry_config_with_log_level_from_string() {
        let level = String::from("warn");
        let config = TelemetryConfig::new("test").with_log_level(level);
        assert_eq!(config.log_level, "warn");
    }

    #[test]
    fn test_telemetry_config_with_otlp_from_string() {
        let endpoint = String::from("http://otel:4317");
        let config = TelemetryConfig::new("test").with_otlp(endpoint);
        assert!(config.otlp_enabled);
        assert_eq!(config.otlp_endpoint, Some("http://otel:4317".to_string()));
    }

    #[test]
    fn test_telemetry_config_default_otlp_disabled() {
        let config = TelemetryConfig::default();
        assert!(!config.otlp_enabled);
        assert!(config.otlp_endpoint.is_none());
    }

    #[test]
    fn test_telemetry_config_redact_fields_extend() {
        let config = TelemetryConfig::new("test")
            .with_redact_fields(vec!["field_a".to_string()])
            .with_redact_fields(vec!["field_b".to_string()]);
        assert!(config.redact_fields.contains(&"field_a".to_string()));
        assert!(config.redact_fields.contains(&"field_b".to_string()));
        // Original defaults should still be present
        assert!(config.redact_fields.contains(&"password".to_string()));
    }

    #[test]
    fn test_telemetry_config_default_redact_count() {
        let config = TelemetryConfig::default();
        assert_eq!(config.redact_fields.len(), 5);
    }

    #[test]
    fn test_telemetry_config_clone_independence() {
        let config = TelemetryConfig::new("original").with_prometheus(8080);
        let mut cloned = config.clone();
        cloned.service_name = "modified".to_string();
        // Original should not be affected
        assert_eq!(config.service_name, "original");
    }

    #[test]
    fn test_telemetry_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(TelemetryError::Config("test".to_string()));
        assert!(err.to_string().contains("Configuration error"));
    }

    #[test]
    fn test_telemetry_error_debug_all_variants() {
        let variants: Vec<TelemetryError> = vec![
            TelemetryError::LoggingInit("a".to_string()),
            TelemetryError::MetricsInit("b".to_string()),
            TelemetryError::TracingInit("c".to_string()),
            TelemetryError::Config("d".to_string()),
        ];
        for v in &variants {
            let debug = format!("{v:?}");
            assert!(!debug.is_empty());
        }
    }

    #[test]
    fn test_telemetry_config_empty_service_name() {
        let config = TelemetryConfig::new("");
        assert_eq!(config.service_name, "");
    }

    #[test]
    fn test_telemetry_config_unicode_service_name() {
        let config = TelemetryConfig::new("service-日本語");
        assert_eq!(config.service_name, "service-日本語");
    }

    #[test]
    fn test_shutdown_telemetry_no_panic() {
        // Shutdown should never panic even without init
        shutdown_telemetry();
    }

    #[test]
    fn test_init_telemetry_with_is_idempotent() {
        let state = OnceLock::new();
        let logging_calls = AtomicUsize::new(0);
        let prometheus_calls = AtomicUsize::new(0);
        let otlp_metric_calls = AtomicUsize::new(0);
        let otlp_log_calls = AtomicUsize::new(0);
        let otlp_trace_calls = AtomicUsize::new(0);

        let config = TelemetryConfig::new("test-service")
            .with_prometheus(9091)
            .with_otlp("http://collector:4317");

        init_telemetry_with(
            &state,
            config.clone(),
            |_| {
                logging_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            |_| {
                prometheus_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            |_, _, _, _| {
                otlp_metric_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            |_, _, _, _| {
                otlp_log_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            |_, _, _, _, _| {
                otlp_trace_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .unwrap();

        init_telemetry_with(
            &state,
            config,
            |_| {
                logging_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            |_| {
                prometheus_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            |_, _, _, _| {
                otlp_metric_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            |_, _, _, _| {
                otlp_log_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            |_, _, _, _, _| {
                otlp_trace_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(logging_calls.load(Ordering::SeqCst), 1);
        assert_eq!(prometheus_calls.load(Ordering::SeqCst), 1);
        assert_eq!(otlp_metric_calls.load(Ordering::SeqCst), 1);
        assert_eq!(otlp_log_calls.load(Ordering::SeqCst), 1);
        assert_eq!(otlp_trace_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            state.get().unwrap().config.service_name,
            "test-service".to_string()
        );
    }

    #[test]
    fn test_init_telemetry_with_failed_attempt_can_retry() {
        let state = OnceLock::new();
        let logging_calls = AtomicUsize::new(0);

        let first = init_telemetry_with(
            &state,
            TelemetryConfig::new("first-attempt"),
            |_| {
                logging_calls.fetch_add(1, Ordering::SeqCst);
                Err(TelemetryError::LoggingInit("boom".to_string()))
            },
            |_| Ok(()),
            |_, _, _, _| Ok(()),
            |_, _, _, _| Ok(()),
            |_, _, _, _, _| Ok(()),
        );

        assert!(matches!(first, Err(TelemetryError::LoggingInit(_))));
        assert!(state.get().is_none());

        init_telemetry_with(
            &state,
            TelemetryConfig::new("second-attempt"),
            |_| {
                logging_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            |_| Ok(()),
            |_, _, _, _| Ok(()),
            |_, _, _, _| Ok(()),
            |_, _, _, _, _| Ok(()),
        )
        .unwrap();

        assert_eq!(logging_calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            state.get().unwrap().config.service_name,
            "second-attempt".to_string()
        );
    }

    /// Regression for the silently-ignored sample rate: whatever the
    /// operator configures via `with_sample_rate` MUST reach the OTLP
    /// init function, not get dropped by `init_telemetry_with`. Prior
    /// behavior threaded only (`service_name`, `endpoint`) through, so the
    /// SDK sampler was `AlwaysOn` regardless of config.
    #[test]
    #[allow(clippy::float_cmp)]
    fn test_init_telemetry_threads_sample_rate_to_otlp() {
        let state = OnceLock::new();
        let captured_rate: std::sync::Mutex<Option<f64>> = std::sync::Mutex::new(None);

        init_telemetry_with(
            &state,
            TelemetryConfig::new("sample-rate-test")
                .with_otlp("http://collector:4317")
                .with_sample_rate(0.05),
            |_| Ok(()),
            |_| Ok(()),
            |_, _, _, _| Ok(()),
            |_, _, _, _| Ok(()),
            |_, _, rate, _, _| {
                *captured_rate.lock().expect("lock") = Some(rate);
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(
            *captured_rate.lock().expect("lock"),
            Some(0.05),
            "configured sample rate must reach the OTLP initializer",
        );
    }

    #[test]
    fn test_init_telemetry_threads_otlp_headers_and_resource_attributes()
    -> Result<(), TelemetryError> {
        let state = OnceLock::new();
        let captured_logs: std::sync::Mutex<Option<(usize, usize, String, String)>> =
            std::sync::Mutex::new(None);
        let captured_metrics: std::sync::Mutex<Option<(usize, usize, String, String)>> =
            std::sync::Mutex::new(None);
        let captured_traces: std::sync::Mutex<Option<(usize, usize, String, String)>> =
            std::sync::Mutex::new(None);
        let headers = vec![OtlpHeader::new("authorization", "Bearer secret")?];
        let attributes = vec![OtlpResourceAttribute::new(
            "deployment.environment",
            "test",
        )?];

        init_telemetry_with(
            &state,
            TelemetryConfig::new("config-threading")
                .with_otlp("http://collector:4317")
                .with_otlp_headers(headers)
                .with_otlp_resource_attributes(attributes),
            |_| Ok(()),
            |_| Ok(()),
            |_, _, headers, attributes| {
                capture_otlp_config(&captured_metrics, "metrics", headers, attributes)
            },
            |_, _, headers, attributes| {
                capture_otlp_config(&captured_logs, "logs", headers, attributes)
            },
            |_, _, _, headers, attributes| {
                capture_otlp_config(&captured_traces, "traces", headers, attributes)
            },
        )?;

        let captured_logs = captured_otlp_config(captured_logs, "logs")?;
        let captured_metrics = captured_otlp_config(captured_metrics, "metrics")?;
        let captured_traces = captured_otlp_config(captured_traces, "traces")?;
        assert_eq!(
            captured_logs,
            Some((
                1,
                1,
                "authorization".to_string(),
                "deployment.environment".to_string(),
            )),
        );
        assert_eq!(
            captured_metrics,
            Some((
                1,
                1,
                "authorization".to_string(),
                "deployment.environment".to_string(),
            )),
        );
        assert_eq!(
            captured_traces,
            Some((
                1,
                1,
                "authorization".to_string(),
                "deployment.environment".to_string(),
            )),
        );
        Ok(())
    }

    #[test]
    fn test_init_telemetry_sync_skips_otlp_side_effects() {
        let state = OnceLock::new();
        let otlp_metric_calls = AtomicUsize::new(0);
        let otlp_log_calls = AtomicUsize::new(0);
        let otlp_trace_calls = AtomicUsize::new(0);
        let mut config = TelemetryConfig::new("sync").with_otlp("http://collector:4317");
        config.otlp_enabled = false;

        init_telemetry_with(
            &state,
            config,
            |_| Ok(()),
            |_| Ok(()),
            |_, _, _, _| {
                otlp_metric_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            |_, _, _, _| {
                otlp_log_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            |_, _, _, _, _| {
                otlp_trace_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(otlp_metric_calls.load(Ordering::SeqCst), 0);
        assert_eq!(otlp_log_calls.load(Ordering::SeqCst), 0);
        assert_eq!(otlp_trace_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_telemetry_config_with_prometheus_default_port() {
        let config = TelemetryConfig::new("test").with_prometheus(0);
        assert!(config.prometheus_enabled);
        assert_eq!(config.prometheus_port, 0);
    }

    #[test]
    fn test_telemetry_config_with_prometheus_max_port() {
        let config = TelemetryConfig::new("test").with_prometheus(u16::MAX);
        assert_eq!(config.prometheus_port, u16::MAX);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_telemetry_config_sample_rate_negative() {
        // Negative sample rate should be stored as-is (validation is caller's responsibility)
        let config = TelemetryConfig::new("test").with_sample_rate(-1.0);
        assert_eq!(config.trace_sample_rate, -1.0);
    }

    #[test]
    fn test_telemetry_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<TelemetryError>();
    }

    #[test]
    fn test_telemetry_config_long_service_name() {
        let long_name = "a".repeat(1000);
        let config = TelemetryConfig::new(&long_name);
        assert_eq!(config.service_name.len(), 1000);
    }

    #[test]
    fn test_telemetry_config_with_empty_redact_fields() {
        let config = TelemetryConfig::new("test").with_redact_fields(vec![]);
        // Original defaults should still be present
        assert_eq!(config.redact_fields.len(), 5);
    }

    #[test]
    fn test_telemetry_config_with_otlp_empty_endpoint() {
        let config = TelemetryConfig::new("test").with_otlp("");
        assert!(config.otlp_enabled);
        assert_eq!(config.otlp_endpoint, Some(String::new()));
    }

    #[test]
    fn test_validate_otlp_endpoint_accepts_safe_http_and_https_urls() {
        for endpoint in [
            "http://localhost:4317",
            "https://collector.example.com:4317",
            "https://collector.example.com/v1/traces",
            "http://[::1]:4317",
        ] {
            let result = validate_otlp_endpoint(endpoint);
            assert!(
                result.is_ok(),
                "{endpoint} should be a valid OTLP endpoint: {result:?}",
            );
        }
    }

    #[test]
    fn test_validate_otlp_endpoint_rejects_invalid_or_secret_bearing_urls() {
        for endpoint in [
            "",
            "   ",
            " http://localhost:4317",
            "grpc://localhost:4317",
            "http://",
            "http://:4317",
            "http://collector.example.com:abc",
            "http://collector.example.com:70000",
            "http://user:pass@collector.example.com:4317",
            "https://collector.example.com:4317?label=value",
            "https://collector.example.com:4317#fragment",
            "https://collector.example.com/path with space",
        ] {
            let result = validate_otlp_endpoint(endpoint);
            assert!(
                matches!(result, Err(TelemetryError::Config(_))),
                "{endpoint:?} should be rejected",
            );
        }
    }

    #[test]
    fn test_init_telemetry_rejects_invalid_otlp_before_side_effects() {
        let state = OnceLock::new();
        let logging_calls = AtomicUsize::new(0);
        let prometheus_calls = AtomicUsize::new(0);
        let otlp_metric_calls = AtomicUsize::new(0);
        let otlp_log_calls = AtomicUsize::new(0);
        let otlp_trace_calls = AtomicUsize::new(0);

        let result = init_telemetry_with(
            &state,
            TelemetryConfig::new("bad-otlp")
                .with_prometheus(9091)
                .with_otlp("https://api-key@collector.example.com:4317"),
            |_| {
                logging_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            |_| {
                prometheus_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            |_, _, _, _| {
                otlp_metric_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            |_, _, _, _| {
                otlp_log_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            |_, _, _, _, _| {
                otlp_trace_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        );

        assert!(matches!(result, Err(TelemetryError::Config(_))));
        assert!(state.get().is_none());
        assert_eq!(logging_calls.load(Ordering::SeqCst), 0);
        assert_eq!(prometheus_calls.load(Ordering::SeqCst), 0);
        assert_eq!(otlp_metric_calls.load(Ordering::SeqCst), 0);
        assert_eq!(otlp_log_calls.load(Ordering::SeqCst), 0);
        assert_eq!(otlp_trace_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_init_telemetry_rejects_invalid_otlp_headers_before_side_effects() {
        let state = OnceLock::new();
        let logging_calls = AtomicUsize::new(0);
        let mut config = TelemetryConfig::new("bad-header").with_otlp("http://collector:4317");
        config.otlp_headers.push(OtlpHeader {
            name: "bad:name".to_string(),
            value: "secret".to_string(),
        });

        let result = init_telemetry_with(
            &state,
            config,
            |_| {
                logging_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            |_| Ok(()),
            |_, _, _, _| Ok(()),
            |_, _, _, _| Ok(()),
            |_, _, _, _, _| Ok(()),
        );

        assert!(matches!(result, Err(TelemetryError::Config(_))));
        assert!(state.get().is_none());
        assert_eq!(logging_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_telemetry_error_display_long_message() {
        let long_msg = "x".repeat(500);
        let error = TelemetryError::Config(long_msg.clone());
        let display = format!("{error}");
        assert!(display.contains(&long_msg));
    }

    #[test]
    fn test_telemetry_error_source_is_none() {
        let error = TelemetryError::LoggingInit("test".to_string());
        assert!(std::error::Error::source(&error).is_none());
    }

    #[test]
    fn test_telemetry_config_debug_contains_all_fields() {
        let config = TelemetryConfig::new("svc")
            .with_log_level("debug")
            .with_prometheus(DEFAULT_PROMETHEUS_PORT)
            .with_otlp("http://otel:4317")
            .with_sample_rate(0.5);
        let debug = format!("{config:?}");
        assert!(debug.contains("svc"));
        assert!(debug.contains("debug"));
        assert!(debug.contains(&DEFAULT_PROMETHEUS_PORT.to_string()));
        assert!(debug.contains("otel"));
    }
}
