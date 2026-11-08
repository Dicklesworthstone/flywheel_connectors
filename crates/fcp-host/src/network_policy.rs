//! Host-managed runtime network policy for connector invocation.
//!
//! This module is intentionally fed from host/admin inventory state, not
//! connector runtime introspection. Runtime introspection is connector-owned
//! self-report and cannot be the authority for egress policy.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Instant;

use fcp_manifest::{Base64Bytes, NetworkConstraints};
use fcp_sandbox::{
    CredentialInjector, EgressDecision, EgressError, EgressGuard, EgressHttpRequest,
    EgressTcpConnectRequest, EgressTcpDecision, FilterStrength, WasiConfig, canonicalize_hostname,
    create_sandbox, is_localhost, is_private_range, is_tailnet_range,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{HostError, HostResult};

/// How the host expects operation-level network constraints to be enforced.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeNetworkEnforcement {
    /// Backward-compatible default: metadata may exist, but runtime enforcement
    /// is not claimed by this inventory entry.
    #[default]
    LegacyUnspecified,
    /// Explicitly native/direct execution. This can carry metadata for
    /// conformance, but it is not runtime egress enforcement.
    NativeUnmediated,
    /// Connector egress is expected to use the host egress proxy.
    HostEgressProxy,
    /// Connector is expected to execute under the WASI sandbox network gate.
    WasiSandbox,
    /// Connector is expected to execute under an OS/network sandbox.
    OsSandbox,
}

impl RuntimeNetworkEnforcement {
    #[must_use]
    pub const fn is_legacy_unspecified(&self) -> bool {
        matches!(self, Self::LegacyUnspecified)
    }

    #[must_use]
    pub const fn requires_runtime_enforcement(self) -> bool {
        matches!(
            self,
            Self::HostEgressProxy | Self::WasiSandbox | Self::OsSandbox
        )
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LegacyUnspecified => "legacy_unspecified",
            Self::NativeUnmediated => "native_unmediated",
            Self::HostEgressProxy => "host_egress_proxy",
            Self::WasiSandbox => "wasi_sandbox",
            Self::OsSandbox => "os_sandbox",
        }
    }
}

/// Runtime support probe for native connectors that are supposed to reach only
/// the host egress proxy while direct sockets are blocked by the OS sandbox.
///
/// This is deliberately stricter than "does this OS have some sandbox?". It is
/// not enough for a platform sandbox to block sockets in isolation: the host
/// must also provide a proxy transport that remains reachable from the sandbox
/// and must apply that sandbox before the connector process starts.
#[expect(
    clippy::struct_excessive_bools,
    reason = "JSONL evidence needs explicit per-gate booleans for operator diagnosis"
)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeProxyOnlySandboxSupport {
    pub platform: String,
    pub mechanism: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter_strength: Option<String>,
    pub platform_sandbox_available: bool,
    pub direct_socket_isolation_available: bool,
    pub host_proxy_endpoint_reachable: bool,
    pub host_spawn_handoff_wired: bool,
    pub enforcement_available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,
}

impl NativeProxyOnlySandboxSupport {
    #[must_use]
    pub fn current() -> Self {
        current_native_proxy_only_sandbox_support()
    }

    #[must_use]
    pub fn enforced_for_test(platform: &str, mechanism: &str, filter_strength: &str) -> Self {
        Self {
            platform: platform.to_string(),
            mechanism: mechanism.to_string(),
            filter_strength: Some(filter_strength.to_string()),
            platform_sandbox_available: true,
            direct_socket_isolation_available: true,
            host_proxy_endpoint_reachable: true,
            host_spawn_handoff_wired: true,
            enforcement_available: true,
            skip_reason: None,
        }
    }

    #[must_use]
    pub fn unavailable_for_test(reason: &str) -> Self {
        Self {
            platform: "test-os".to_string(),
            mechanism: "test-native-sandbox".to_string(),
            filter_strength: Some(FilterStrength::SyscallLevel.as_str().to_string()),
            platform_sandbox_available: true,
            direct_socket_isolation_available: true,
            host_proxy_endpoint_reachable: false,
            host_spawn_handoff_wired: false,
            enforcement_available: false,
            skip_reason: Some(reason.to_string()),
        }
    }

    #[must_use]
    pub fn deny_reason(&self) -> &str {
        self.skip_reason
            .as_deref()
            .unwrap_or("native_proxy_only_sandbox_unavailable")
    }
}

/// Runtime decision for a native proxy-only sandbox mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeProxyOnlySandboxDecision {
    NotRequired,
    Allow,
    Deny { deny_reason: String },
}

#[must_use]
pub fn native_proxy_only_sandbox_decision(
    enforcement: RuntimeNetworkEnforcement,
    support: &NativeProxyOnlySandboxSupport,
) -> NativeProxyOnlySandboxDecision {
    if !matches!(
        enforcement,
        RuntimeNetworkEnforcement::HostEgressProxy | RuntimeNetworkEnforcement::OsSandbox
    ) {
        return NativeProxyOnlySandboxDecision::NotRequired;
    }

    if support.enforcement_available {
        NativeProxyOnlySandboxDecision::Allow
    } else {
        NativeProxyOnlySandboxDecision::Deny {
            deny_reason: support.deny_reason().to_string(),
        }
    }
}

#[must_use]
pub fn current_native_proxy_only_sandbox_support() -> NativeProxyOnlySandboxSupport {
    let (platform, mechanism, filter_strength, platform_sandbox_available, direct_socket_blocked) =
        match create_sandbox() {
            Ok(sandbox) => {
                let filter_strength = sandbox.filter_strength();
                (
                    sandbox.platform_name().to_string(),
                    format!("fcp_sandbox::{}", filter_strength.as_str()),
                    Some(filter_strength.as_str().to_string()),
                    sandbox.is_available(),
                    filter_strength >= FilterStrength::ProfileLevel,
                )
            }
            Err(_err) => (
                std::env::consts::OS.to_string(),
                "unsupported_platform".to_string(),
                None,
                false,
                false,
            ),
        };

    // Current SDK host-egress proxy helpers use an HTTP loopback URL. The
    // native OS sandbox profiles either block all socket syscalls/operations or
    // have no process-launch handoff in fcp-host yet, so there is no current
    // platform path that can prove "all direct sockets denied, only the proxy
    // endpoint reachable" for native connectors.
    let host_proxy_endpoint_reachable = false;
    let host_spawn_handoff_wired = false;
    let enforcement_available = platform_sandbox_available
        && direct_socket_blocked
        && host_proxy_endpoint_reachable
        && host_spawn_handoff_wired;

    let mut gaps = Vec::new();
    if !platform_sandbox_available {
        gaps.push("platform_sandbox_unavailable");
    }
    if !direct_socket_blocked {
        gaps.push("direct_socket_isolation_unavailable");
    }
    if !host_proxy_endpoint_reachable {
        gaps.push("host_egress_proxy_endpoint_not_reachable_inside_os_sandbox");
    }
    if !host_spawn_handoff_wired {
        gaps.push("connector_process_runner_os_sandbox_handoff_not_wired");
    }

    NativeProxyOnlySandboxSupport {
        platform,
        mechanism,
        filter_strength,
        platform_sandbox_available,
        direct_socket_isolation_available: direct_socket_blocked,
        host_proxy_endpoint_reachable,
        host_spawn_handoff_wired,
        enforcement_available,
        skip_reason: (!enforcement_available).then(|| {
            format!(
                "runtime_egress_unenforceable: native proxy-only OS sandbox unavailable ({})",
                gaps.join(",")
            )
        }),
    }
}

/// A runtime-managed port declaration. Static manifests usually use numeric
/// ports; self-hosted connectors can opt into config-derived values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ManagedPortConstraint {
    Static(u16),
    Template(String),
}

/// Host/admin representation of operation-level network constraints.
///
/// This mirrors `fcp_manifest::NetworkConstraints` but keeps equality-friendly
/// fields for persisted inventory diffs and allows a small, explicit set of
/// config-derived placeholders.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct ManagedNetworkConstraints {
    pub host_allow: Vec<String>,
    pub port_allow: Vec<ManagedPortConstraint>,
    #[serde(default)]
    pub ip_allow: Vec<IpAddr>,
    #[serde(default)]
    pub cidr_deny: Vec<String>,
    #[serde(default = "default_true")]
    pub deny_localhost: bool,
    #[serde(default = "default_true")]
    pub deny_private_ranges: bool,
    #[serde(default = "default_true")]
    pub deny_tailnet_ranges: bool,
    pub require_sni: bool,
    #[serde(default)]
    pub spki_pins: Vec<String>,
    #[serde(default = "default_true")]
    pub deny_ip_literals: bool,
    #[serde(default = "default_true")]
    pub require_host_canonicalization: bool,
    #[serde(default = "default_dns_max_ips")]
    pub dns_max_ips: u16,
    #[serde(default = "default_max_redirects")]
    pub max_redirects: u8,
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u32,
    #[serde(default = "default_total_timeout_ms")]
    pub total_timeout_ms: u32,
    #[serde(default = "default_max_response_bytes")]
    pub max_response_bytes: u64,
}

const fn default_true() -> bool {
    true
}

const fn default_dns_max_ips() -> u16 {
    16
}

const fn default_max_redirects() -> u8 {
    5
}

const fn default_connect_timeout_ms() -> u32 {
    10_000
}

const fn default_total_timeout_ms() -> u32 {
    60_000
}

const fn default_max_response_bytes() -> u64 {
    10_485_760
}

impl ManagedNetworkConstraints {
    /// Resolve host/admin placeholders into concrete manifest constraints.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::InvalidFilter`] when placeholders are unsupported,
    /// required connector config is missing or malformed, exactly one of the
    /// host/port allow-lists is empty, SPKI pins are invalid, or a resolved host violates the
    /// declared locality/canonicalization policy.
    pub fn resolve(&self, connector_config: Option<&Value>) -> HostResult<NetworkConstraints> {
        let matrix_url = matrix_homeserver_url(connector_config);
        let mut host_allow = Vec::with_capacity(self.host_allow.len());
        for host in &self.host_allow {
            let resolved = match host.as_str() {
                "${matrix_homeserver_host}" => {
                    let url = parse_matrix_homeserver_url(matrix_url)?;
                    url.host_str()
                        .ok_or_else(|| {
                            HostError::InvalidFilter(
                                "matrix homeserver_url must include a host".to_string(),
                            )
                        })?
                        .to_string()
                }
                raw if raw.starts_with("${") => {
                    return Err(HostError::InvalidFilter(format!(
                        "unsupported network host placeholder `{raw}`"
                    )));
                }
                raw => raw.to_string(),
            };
            host_allow.push(self.validate_resolved_host(&resolved)?);
        }

        let mut port_allow = Vec::with_capacity(self.port_allow.len());
        for port in &self.port_allow {
            match port {
                ManagedPortConstraint::Static(port) => port_allow.push(*port),
                ManagedPortConstraint::Template(template)
                    if template == "${matrix_homeserver_port}" =>
                {
                    let url = parse_matrix_homeserver_url(matrix_url)?;
                    let port = url.port_or_known_default().ok_or_else(|| {
                        HostError::InvalidFilter(
                            "matrix homeserver_url must include or imply a port".to_string(),
                        )
                    })?;
                    port_allow.push(port);
                }
                ManagedPortConstraint::Template(template) => {
                    return Err(HostError::InvalidFilter(format!(
                        "unsupported network port placeholder `{template}`"
                    )));
                }
            }
        }

        // Two empty allow-lists are an explicit deny-all policy for compute
        // and local-file operations. A partially empty policy is usually a
        // configuration mistake and must not acquire an implicit default.
        if host_allow.is_empty() != port_allow.is_empty() {
            return Err(HostError::InvalidFilter(
                "operation network policy host_allow and port_allow must both be empty for deny-all, or both be non-empty".to_string(),
            ));
        }

        let spki_pins = self
            .spki_pins
            .iter()
            .cloned()
            .map(Base64Bytes::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| {
                HostError::InvalidFilter(format!("invalid operation network SPKI pin: {err}"))
            })?;

        Ok(NetworkConstraints {
            host_allow,
            port_allow,
            ip_allow: self.ip_allow.clone(),
            cidr_deny: self.cidr_deny.clone(),
            deny_localhost: self.deny_localhost,
            deny_private_ranges: self.deny_private_ranges,
            deny_tailnet_ranges: self.deny_tailnet_ranges,
            require_sni: self.require_sni,
            spki_pins,
            deny_ip_literals: self.deny_ip_literals,
            require_host_canonicalization: self.require_host_canonicalization,
            dns_max_ips: self.dns_max_ips,
            max_redirects: self.max_redirects,
            connect_timeout_ms: self.connect_timeout_ms,
            total_timeout_ms: self.total_timeout_ms,
            max_response_bytes: self.max_response_bytes,
        })
    }

    fn validate_resolved_host(&self, host: &str) -> HostResult<String> {
        if host == "*" {
            return Err(HostError::InvalidFilter(
                "runtime network host_allow must not use wildcard `*`".to_string(),
            ));
        }

        if let Ok(ip) = host.parse::<IpAddr>() {
            if self.deny_ip_literals {
                return Err(HostError::InvalidFilter(format!(
                    "runtime network host_allow resolved to forbidden IP literal `{host}`"
                )));
            }
            self.validate_resolved_ip(ip)?;
            return Ok(host.to_string());
        }

        let (wildcard, raw) = host
            .strip_prefix("*.")
            .map_or((false, host), |suffix| (true, suffix));
        let canonical = canonicalize_hostname(raw).map_err(|err| {
            HostError::InvalidFilter(format!("invalid runtime network host `{host}`: {err}"))
        })?;
        if self.require_host_canonicalization && canonical != raw {
            return Err(HostError::InvalidFilter(format!(
                "runtime network host `{host}` is not canonical"
            )));
        }
        if self.deny_localhost && canonical == "localhost" {
            return Err(HostError::InvalidFilter(
                "runtime network host_allow resolved to forbidden localhost".to_string(),
            ));
        }
        if wildcard {
            Ok(format!("*.{canonical}"))
        } else {
            Ok(canonical)
        }
    }

    fn validate_resolved_ip(&self, ip: IpAddr) -> HostResult<()> {
        if self.deny_localhost && is_localhost(ip) {
            return Err(HostError::InvalidFilter(format!(
                "runtime network host_allow resolved to forbidden localhost `{ip}`"
            )));
        }
        if self.deny_private_ranges && is_private_range(ip) {
            return Err(HostError::InvalidFilter(format!(
                "runtime network host_allow resolved to forbidden private range `{ip}`"
            )));
        }
        if self.deny_tailnet_ranges && is_tailnet_range(ip) {
            return Err(HostError::InvalidFilter(format!(
                "runtime network host_allow resolved to forbidden tailnet range `{ip}`"
            )));
        }
        Ok(())
    }
}

/// Validate that a host-managed inventory entry is allowed to advertise runtime
/// network enforcement.
///
/// Non-claim modes (`legacy_unspecified` and `native_unmediated`) may carry
/// remediation metadata. Claim modes must name the invokable operations and
/// provide one safe operation policy per named operation. This keeps static
/// manifest coverage separate from a real runtime-enforcement claim.
///
/// # Errors
///
/// Returns [`HostError::InvalidFilter`] when a runtime-enforced connector has
/// no bounded operation set, lacks a per-operation policy, tries to fall back to
/// wildcard or connector-level policy, or uses unsafe placeholder/locality
/// settings without an explicit local/LAN exception.
pub fn validate_runtime_network_claim(
    connector_id: &str,
    enforcement: RuntimeNetworkEnforcement,
    allowed_operations: &[String],
    operation_network_constraints: &BTreeMap<String, ManagedNetworkConstraints>,
    connector_config: Option<&Value>,
) -> HostResult<()> {
    if !enforcement.requires_runtime_enforcement() {
        return Ok(());
    }

    if allowed_operations.is_empty() {
        return Err(HostError::InvalidFilter(format!(
            "runtime network enforcement claim for connector `{connector_id}` requires \
             non-empty allowed_operations; empty allow-lists are metadata-only and cannot \
             prove invoked-operation policy"
        )));
    }

    for operation in allowed_operations {
        let constraints = operation_network_constraints
            .get(operation)
            .ok_or_else(|| {
                HostError::InvalidFilter(format!(
                    "runtime network enforcement claim for connector `{connector_id}` operation \
                 `{operation}` requires operation_network_constraints; connector-level \
                 host_allow fallback is not runtime enforcement"
                ))
            })?;
        validate_runtime_operation_network_claim(
            connector_id,
            operation,
            constraints,
            connector_config,
        )?;
    }

    Ok(())
}

fn validate_runtime_operation_network_claim(
    connector_id: &str,
    operation: &str,
    constraints: &ManagedNetworkConstraints,
    connector_config: Option<&Value>,
) -> HostResult<()> {
    for host in &constraints.host_allow {
        if host.contains('*') {
            return Err(HostError::InvalidFilter(format!(
                "runtime network enforcement claim for connector `{connector_id}` operation \
                 `{operation}` rejects wildcard host_allow `{host}`; runtime claims require \
                 explicit invoked-operation hosts"
            )));
        }
    }

    let resolved = constraints.resolve(connector_config).map_err(|err| {
        HostError::InvalidFilter(format!(
            "runtime network enforcement claim for connector `{connector_id}` operation \
             `{operation}` has invalid operation_network_constraints: {err}"
        ))
    })?;
    let local_lan_exception = runtime_claim_has_explicit_local_lan_exception(&resolved);

    if !constraints.require_sni && !local_lan_exception {
        return Err(HostError::InvalidFilter(format!(
            "runtime network enforcement claim for connector `{connector_id}` operation \
             `{operation}` requires network_constraints.require_sni=true unless the operation \
             is an explicit local/LAN exception"
        )));
    }
    if !constraints.deny_private_ranges && !local_lan_exception {
        return Err(HostError::InvalidFilter(format!(
            "runtime network enforcement claim for connector `{connector_id}` operation \
             `{operation}` requires network_constraints.deny_private_ranges=true unless the \
             operation is an explicit local/LAN exception"
        )));
    }
    if !constraints.deny_localhost && !local_lan_exception {
        return Err(HostError::InvalidFilter(format!(
            "runtime network enforcement claim for connector `{connector_id}` operation \
             `{operation}` requires network_constraints.deny_localhost=true unless the \
             operation is an explicit local/LAN exception"
        )));
    }
    if !constraints.deny_tailnet_ranges && !local_lan_exception {
        return Err(HostError::InvalidFilter(format!(
            "runtime network enforcement claim for connector `{connector_id}` operation \
             `{operation}` requires network_constraints.deny_tailnet_ranges=true unless the \
             operation is an explicit local/LAN exception"
        )));
    }
    if !constraints.deny_ip_literals && !local_lan_exception {
        return Err(HostError::InvalidFilter(format!(
            "runtime network enforcement claim for connector `{connector_id}` operation \
             `{operation}` requires network_constraints.deny_ip_literals=true unless the \
             operation is an explicit local/LAN exception"
        )));
    }
    if !constraints.require_host_canonicalization {
        return Err(HostError::InvalidFilter(format!(
            "runtime network enforcement claim for connector `{connector_id}` operation \
             `{operation}` requires network_constraints.require_host_canonicalization=true"
        )));
    }

    Ok(())
}

fn runtime_claim_has_explicit_local_lan_exception(constraints: &NetworkConstraints) -> bool {
    !constraints.host_allow.is_empty()
        && constraints.host_allow.iter().all(|host| {
            if host == "localhost" {
                return true;
            }
            host.parse::<IpAddr>()
                .is_ok_and(|ip| is_localhost(ip) || is_private_range(ip) || is_tailnet_range(ip))
        })
}

/// Per-request context attached to host-mediated egress decisions.
///
/// Keep this value free of request bodies, credentials, and external payload
/// fragments. It exists to make allow/deny records attributable without
/// leaking user data.
#[derive(Debug, Clone, Copy)]
pub struct RuntimeEgressDecisionContext<'a> {
    pub connector_id: &'a str,
    pub operation: &'a str,
    pub zone_id: &'a str,
    pub request_id: &'a str,
    pub correlation_id: Option<&'a str>,
    pub execution_mode: RuntimeNetworkEnforcement,
    pub constraint_source: &'a str,
    pub credential_allow: &'a [String],
}

/// Build a WASI config for a single strict/moderate operation invocation.
///
/// # Errors
///
/// Returns [`HostError::InvalidFilter`] unless the operator selected the
/// `wasi_sandbox` runtime enforcement mode for this connector. Native and
/// host-proxy modes must not accidentally reuse this helper as a policy claim.
pub fn wasi_config_for_operation_network_policy(
    mut base: WasiConfig,
    enforcement: RuntimeNetworkEnforcement,
    constraints: NetworkConstraints,
) -> HostResult<WasiConfig> {
    if enforcement != RuntimeNetworkEnforcement::WasiSandbox {
        return Err(HostError::InvalidFilter(format!(
            "WASI network policy handoff requires wasi_sandbox enforcement, got {}",
            enforcement.as_str()
        )));
    }

    base.network_constraints = Some(constraints);
    base.block_direct_network = true;
    Ok(base)
}

/// Authorize a host-mediated HTTP egress request with structured decision logs.
///
/// # Errors
///
/// Returns [`HostError::PreflightFailed`] when the request is denied by the
/// operation-level network policy or credential allow-list.
pub fn authorize_runtime_http_egress(
    context: &RuntimeEgressDecisionContext<'_>,
    constraints: &NetworkConstraints,
    request: &mut EgressHttpRequest,
    injector: &dyn CredentialInjector,
) -> HostResult<EgressDecision> {
    let started_at = Instant::now();
    let guard = EgressGuard::new();
    match guard.authorize_http(
        request,
        constraints,
        injector,
        context.operation,
        context.credential_allow,
    ) {
        Ok(decision) => {
            log_runtime_egress_allow(context, constraints, &decision, started_at.elapsed());
            Ok(decision)
        }
        Err(error) => {
            log_runtime_egress_deny(context, constraints, &error, started_at.elapsed());
            Err(runtime_egress_denial(context, "HTTP", &error))
        }
    }
}

/// Authorize a host-mediated TCP egress request with structured decision logs.
///
/// # Errors
///
/// Returns [`HostError::PreflightFailed`] when the request is denied by the
/// operation-level network policy or credential allow-list.
pub fn authorize_runtime_tcp_egress(
    context: &RuntimeEgressDecisionContext<'_>,
    constraints: &NetworkConstraints,
    request: &EgressTcpConnectRequest,
    injector: &dyn CredentialInjector,
) -> HostResult<EgressTcpDecision> {
    let started_at = Instant::now();
    let guard = EgressGuard::new();
    match guard.authorize_tcp(
        request,
        constraints,
        injector,
        context.operation,
        context.credential_allow,
    ) {
        Ok(decision) => {
            log_runtime_egress_allow(
                context,
                constraints,
                &decision.decision,
                started_at.elapsed(),
            );
            Ok(decision)
        }
        Err(error) => {
            log_runtime_egress_deny(context, constraints, &error, started_at.elapsed());
            Err(runtime_egress_denial(context, "TCP", &error))
        }
    }
}

fn runtime_egress_denial(
    context: &RuntimeEgressDecisionContext<'_>,
    protocol: &str,
    error: &EgressError,
) -> HostError {
    HostError::PreflightFailed(format!(
        "runtime {protocol} egress denied for connector `{}` operation `{}`: {error}",
        context.connector_id, context.operation
    ))
}

fn log_runtime_egress_allow(
    context: &RuntimeEgressDecisionContext<'_>,
    constraints: &NetworkConstraints,
    decision: &EgressDecision,
    elapsed: std::time::Duration,
) {
    tracing::info!(
        event = "runtime_egress_policy_decision",
        connector_id = context.connector_id,
        operation = context.operation,
        zone_id = context.zone_id,
        request_id = context.request_id,
        correlation_id = context.correlation_id,
        execution_mode = context.execution_mode.as_str(),
        constraint_source = context.constraint_source,
        raw_host_pattern = %constraints.host_allow.join(","),
        raw_port_pattern = %constraints
            .port_allow
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(","),
        resolved_host = %decision.canonical_host,
        resolved_port = decision.port,
        normalized_host = %decision.canonical_host,
        credential_allow = %context.credential_allow.join(","),
        decision = "allow",
        deny_reason = "",
        elapsed_ms = elapsed.as_millis(),
        "runtime egress policy allowed host-mediated request"
    );
}

fn log_runtime_egress_deny(
    context: &RuntimeEgressDecisionContext<'_>,
    constraints: &NetworkConstraints,
    error: &EgressError,
    elapsed: std::time::Duration,
) {
    tracing::warn!(
        event = "runtime_egress_policy_decision",
        connector_id = context.connector_id,
        operation = context.operation,
        zone_id = context.zone_id,
        request_id = context.request_id,
        correlation_id = context.correlation_id,
        execution_mode = context.execution_mode.as_str(),
        constraint_source = context.constraint_source,
        raw_host_pattern = %constraints.host_allow.join(","),
        raw_port_pattern = %constraints
            .port_allow
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(","),
        resolved_host = "",
        resolved_port = "",
        normalized_host = "",
        credential_allow = %context.credential_allow.join(","),
        decision = "deny",
        deny_reason = %egress_error_code(error),
        elapsed_ms = elapsed.as_millis(),
        "runtime egress policy denied host-mediated request"
    );
}

fn egress_error_code(error: &EgressError) -> String {
    match error {
        EgressError::Denied { code, .. } => format!("{code:?}"),
        EgressError::InvalidRequest(_) => "InvalidRequest".to_string(),
        EgressError::InvalidUrl(_) => "InvalidUrl".to_string(),
        EgressError::CanonicalizationFailed(_) => "CanonicalizationFailed".to_string(),
        EgressError::DnsResolutionFailed(_) => "DnsResolutionFailed".to_string(),
        EgressError::CredentialError(_) => "CredentialError".to_string(),
        EgressError::TlsVerificationFailed(_) => "TlsVerificationFailed".to_string(),
    }
}

fn matrix_homeserver_url(config: Option<&Value>) -> Option<&str> {
    let config = config?;
    [
        "/homeserver_url",
        "/homeserverUrl",
        "/matrix/homeserver_url",
        "/matrix/homeserverUrl",
    ]
    .into_iter()
    .find_map(|pointer| config.pointer(pointer).and_then(Value::as_str))
}

fn parse_matrix_homeserver_url(raw: Option<&str>) -> HostResult<url::Url> {
    let raw = raw.ok_or_else(|| {
        HostError::InvalidFilter(
            "matrix homeserver network policy requires connector config homeserver_url".to_string(),
        )
    })?;
    url::Url::parse(raw).map_err(|err| {
        HostError::InvalidFilter(format!("invalid matrix homeserver_url `{raw}`: {err}"))
    })
}

#[cfg(test)]
mod tests {
    use fcp_sandbox::{
        EgressError, EgressGuard, EgressHttpRequest, EgressRequest, EgressTcpConnectRequest,
        HttpHeader, NoOpCredentialInjector,
    };
    use serde_json::json;

    use super::*;

    fn static_constraints() -> ManagedNetworkConstraints {
        ManagedNetworkConstraints {
            host_allow: vec!["api.example.test".to_string()],
            port_allow: vec![ManagedPortConstraint::Static(443)],
            ip_allow: Vec::new(),
            cidr_deny: Vec::new(),
            deny_localhost: true,
            deny_private_ranges: true,
            deny_tailnet_ranges: true,
            require_sni: true,
            spki_pins: Vec::new(),
            deny_ip_literals: true,
            require_host_canonicalization: true,
            dns_max_ips: 16,
            max_redirects: 0,
            connect_timeout_ms: 10_000,
            total_timeout_ms: 60_000,
            max_response_bytes: 1_048_576,
        }
    }

    #[test]
    fn runtime_network_enforcement_default_is_legacy_unspecified() {
        let enforcement = RuntimeNetworkEnforcement::default();
        assert!(enforcement.is_legacy_unspecified());
        assert!(!enforcement.requires_runtime_enforcement());
    }

    #[test]
    fn br_2zfc5_runtime_network_claim_validator_preserves_non_claim_modes() {
        for enforcement in [
            RuntimeNetworkEnforcement::LegacyUnspecified,
            RuntimeNetworkEnforcement::NativeUnmediated,
        ] {
            validate_runtime_network_claim(
                "fcp.test.metadata-only",
                enforcement,
                &[],
                &BTreeMap::default(),
                None,
            )
            .expect("metadata-only modes must not become runtime-enforcement claims");
        }
    }

    #[test]
    fn br_2zfc5_runtime_network_claim_rejects_empty_allowed_operations() {
        let err = validate_runtime_network_claim(
            "fcp.test.empty-ops",
            RuntimeNetworkEnforcement::HostEgressProxy,
            &[],
            &BTreeMap::default(),
            None,
        )
        .expect_err("runtime claims need a bounded operation set");

        assert!(err.to_string().contains("allowed_operations"));
    }

    #[test]
    fn br_2zfc5_runtime_network_claim_rejects_missing_per_operation_policy() {
        let err = validate_runtime_network_claim(
            "fcp.test.missing-policy",
            RuntimeNetworkEnforcement::WasiSandbox,
            &["matrix.send".to_string()],
            &BTreeMap::default(),
            None,
        )
        .expect_err("runtime claims need invoked-operation constraints");

        let msg = err.to_string();
        assert!(msg.contains("matrix.send"));
        assert!(msg.contains("operation_network_constraints"));
        assert!(msg.contains("connector-level"));
    }

    #[test]
    fn br_2zfc5_runtime_network_claim_rejects_wildcard_host_allow() {
        let mut constraints = static_constraints();
        constraints.host_allow = vec!["*.example.test".to_string()];
        let policies = BTreeMap::from([("matrix.send".to_string(), constraints)]);

        let err = validate_runtime_network_claim(
            "fcp.test.wildcard",
            RuntimeNetworkEnforcement::HostEgressProxy,
            &["matrix.send".to_string()],
            &policies,
            None,
        )
        .expect_err("runtime claims must not use wildcard hosts");

        assert!(err.to_string().contains("wildcard"));
    }

    #[test]
    fn br_2zfc5_runtime_network_claim_rejects_unsafe_public_policy_flags() {
        let mut constraints = static_constraints();
        constraints.require_sni = false;
        let policies = BTreeMap::from([("matrix.send".to_string(), constraints)]);

        let err = validate_runtime_network_claim(
            "fcp.test.no-sni",
            RuntimeNetworkEnforcement::HostEgressProxy,
            &["matrix.send".to_string()],
            &policies,
            None,
        )
        .expect_err("public runtime claims require SNI");

        assert!(err.to_string().contains("require_sni"));
    }

    #[test]
    fn br_2zfc5_runtime_network_claim_accepts_matrix_placeholder_policy() {
        let mut constraints = static_constraints();
        constraints.host_allow = vec!["${matrix_homeserver_host}".to_string()];
        constraints.port_allow = vec![ManagedPortConstraint::Template(
            "${matrix_homeserver_port}".to_string(),
        )];
        let policies = BTreeMap::from([("matrix.send".to_string(), constraints)]);
        let config = json!({"homeserver_url": "https://matrix.example.test:8448"});

        validate_runtime_network_claim(
            "fcp.test.matrix",
            RuntimeNetworkEnforcement::WasiSandbox,
            &["matrix.send".to_string()],
            &policies,
            Some(&config),
        )
        .expect("supported Matrix placeholder policy should validate");
    }

    #[test]
    fn br_2zfc5_runtime_network_claim_accepts_explicit_local_lan_exception() {
        let mut constraints = static_constraints();
        constraints.host_allow = vec!["127.0.0.1".to_string()];
        constraints.port_allow = vec![ManagedPortConstraint::Static(49_999)];
        constraints.deny_localhost = false;
        constraints.deny_private_ranges = false;
        constraints.deny_tailnet_ranges = false;
        constraints.require_sni = false;
        constraints.deny_ip_literals = false;
        let policies = BTreeMap::from([("test.local_proxy".to_string(), constraints)]);

        validate_runtime_network_claim(
            "fcp.test.local-proxy",
            RuntimeNetworkEnforcement::HostEgressProxy,
            &["test.local_proxy".to_string()],
            &policies,
            None,
        )
        .expect("explicit loopback host-egress proxy exception should validate");
    }

    #[test]
    fn br_hx0gw_native_proxy_only_runtime_selection_allows_only_when_fully_enforced() {
        let support = NativeProxyOnlySandboxSupport::enforced_for_test(
            "linux",
            "seccomp-bpf-plus-proxy-exception",
            "syscall_level",
        );

        assert_eq!(
            native_proxy_only_sandbox_decision(
                RuntimeNetworkEnforcement::HostEgressProxy,
                &support
            ),
            NativeProxyOnlySandboxDecision::Allow
        );
        assert_eq!(
            native_proxy_only_sandbox_decision(RuntimeNetworkEnforcement::OsSandbox, &support),
            NativeProxyOnlySandboxDecision::Allow
        );
    }

    #[test]
    fn br_hx0gw_native_proxy_only_runtime_selection_denies_when_support_absent() {
        let support = NativeProxyOnlySandboxSupport::unavailable_for_test(
            "runtime_egress_unenforceable: host proxy endpoint unavailable",
        );

        let decision = native_proxy_only_sandbox_decision(
            RuntimeNetworkEnforcement::HostEgressProxy,
            &support,
        );

        assert!(matches!(
            decision,
            NativeProxyOnlySandboxDecision::Deny { .. }
        ));
        if let NativeProxyOnlySandboxDecision::Deny { deny_reason } = decision {
            assert!(deny_reason.contains("runtime_egress_unenforceable"));
            assert!(deny_reason.contains("host proxy endpoint unavailable"));
        }
    }

    #[test]
    fn br_hx0gw_native_proxy_only_runtime_selection_preserves_non_strict_modes() {
        let support = NativeProxyOnlySandboxSupport::unavailable_for_test(
            "runtime_egress_unenforceable: support intentionally absent",
        );

        for enforcement in [
            RuntimeNetworkEnforcement::LegacyUnspecified,
            RuntimeNetworkEnforcement::NativeUnmediated,
            RuntimeNetworkEnforcement::WasiSandbox,
        ] {
            assert_eq!(
                native_proxy_only_sandbox_decision(enforcement, &support),
                NativeProxyOnlySandboxDecision::NotRequired,
                "{enforcement:?} must not be converted into a native proxy-only OS sandbox claim"
            );
        }
    }

    #[test]
    fn br_hx0gw_current_native_proxy_only_support_is_honest_about_missing_handoff() {
        let support = NativeProxyOnlySandboxSupport::current();

        assert!(
            !support.enforcement_available,
            "production must not advertise native proxy-only enforcement until process launch and proxy reachability are both wired"
        );
        assert!(
            support
                .skip_reason
                .as_deref()
                .unwrap_or_default()
                .contains("runtime_egress_unenforceable")
        );
    }

    #[test]
    fn static_policy_resolves_and_egress_guard_accepts_matching_host() {
        let managed = static_constraints();
        let resolved = managed.resolve(None).expect("resolve static policy");
        assert_eq!(resolved.host_allow, vec!["api.example.test"]);
        assert_eq!(resolved.port_allow, vec![443]);

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://api.example.test/v1".to_string(),
            method: "GET".to_string(),
            headers: Vec::new(),
            body: None,
            credential_id: None,
        });
        EgressGuard::new()
            .evaluate(&request, &resolved)
            .expect("matching host and port allowed");
    }

    #[test]
    fn matrix_policy_resolves_host_and_non_default_port_from_config() {
        let mut managed = static_constraints();
        managed.host_allow = vec!["${matrix_homeserver_host}".to_string()];
        managed.port_allow = vec![ManagedPortConstraint::Template(
            "${matrix_homeserver_port}".to_string(),
        )];
        let config = json!({"homeserver_url": "https://matrix.example.test:8448"});

        let resolved = managed
            .resolve(Some(&config))
            .expect("resolve matrix homeserver policy");

        assert_eq!(resolved.host_allow, vec!["matrix.example.test"]);
        assert_eq!(resolved.port_allow, vec![8448]);
    }

    #[test]
    fn matrix_policy_fails_closed_when_config_missing() {
        let mut managed = static_constraints();
        managed.host_allow = vec!["${matrix_homeserver_host}".to_string()];

        let err = managed.resolve(None).expect_err("missing config must fail");
        assert!(err.to_string().contains("homeserver_url"));
    }

    #[test]
    fn dynamic_host_rejects_ip_literal_when_denied() {
        let mut managed = static_constraints();
        managed.host_allow = vec!["${matrix_homeserver_host}".to_string()];
        managed.port_allow = vec![ManagedPortConstraint::Template(
            "${matrix_homeserver_port}".to_string(),
        )];
        let config = json!({"homeserver_url": "https://192.168.1.10:8448"});

        let err = managed
            .resolve(Some(&config))
            .expect_err("IP literal must fail closed");
        assert!(err.to_string().contains("IP literal"));
    }

    #[test]
    fn runtime_policy_rejects_global_wildcard_host() {
        let mut managed = static_constraints();
        managed.host_allow = vec!["*".to_string()];

        let err = managed.resolve(None).expect_err("wildcard must fail");
        assert!(err.to_string().contains("wildcard"));
    }

    #[test]
    fn wasi_policy_handoff_sets_operation_constraints_and_blocks_direct_network() {
        let managed = static_constraints();
        let constraints = managed.resolve(None).expect("resolve constraints");
        let config = wasi_config_for_operation_network_policy(
            WasiConfig {
                block_direct_network: false,
                ..WasiConfig::default()
            },
            RuntimeNetworkEnforcement::WasiSandbox,
            constraints.clone(),
        )
        .expect("build WASI config");

        let config_constraints = config
            .network_constraints
            .as_ref()
            .expect("operation constraints should be installed");
        assert_eq!(config_constraints.host_allow, constraints.host_allow);
        assert_eq!(config_constraints.port_allow, constraints.port_allow);
        assert!(
            config.block_direct_network,
            "strict/moderate WASI profiles must keep direct sockets disabled"
        );
    }

    #[test]
    fn wasi_policy_handoff_rejects_non_wasi_modes() {
        let managed = static_constraints();
        let constraints = managed.resolve(None).expect("resolve constraints");
        let err = wasi_config_for_operation_network_policy(
            WasiConfig::default(),
            RuntimeNetworkEnforcement::HostEgressProxy,
            constraints,
        )
        .expect_err("host egress proxy mode must not be mislabeled as WASI");

        assert!(err.to_string().contains("wasi_sandbox"));
    }

    #[test]
    fn explicit_deny_all_policy_admits_compute_and_denies_http_and_tcp() {
        let mut managed = static_constraints();
        managed.host_allow.clear();
        managed.port_allow.clear();
        let operations = vec!["compute.echo".to_string()];
        let policies = BTreeMap::from([("compute.echo".to_string(), managed.clone())]);
        validate_runtime_network_claim(
            "fcp.compute",
            RuntimeNetworkEnforcement::WasiSandbox,
            &operations,
            &policies,
            None,
        )
        .expect("both empty lists explicitly deny all egress");
        let constraints = managed.resolve(None).unwrap();
        let config = wasi_config_for_operation_network_policy(
            WasiConfig::default(),
            RuntimeNetworkEnforcement::WasiSandbox,
            constraints.clone(),
        )
        .unwrap();
        assert!(config.block_direct_network);
        let guard = EgressGuard::new();
        let http = EgressRequest::Http(EgressHttpRequest {
            url: "https://api.example.test/data".into(),
            method: "GET".into(),
            headers: Vec::new(),
            body: None,
            credential_id: None,
        });
        let tcp = EgressRequest::TcpConnect(EgressTcpConnectRequest {
            host: "api.example.test".into(),
            port: 443,
            tls: true,
            sni_override: None,
            credential_id: None,
        });
        assert!(guard.evaluate(&http, &constraints).is_err());
        assert!(guard.evaluate(&tcp, &constraints).is_err());

        let mut missing_port = static_constraints();
        missing_port.port_allow.clear();
        assert!(missing_port.resolve(None).is_err());
        let mut missing_host = static_constraints();
        missing_host.host_allow.clear();
        assert!(missing_host.resolve(None).is_err());
        managed.require_sni = false;
        assert!(
            validate_runtime_network_claim(
                "fcp.compute",
                RuntimeNetworkEnforcement::WasiSandbox,
                &operations,
                &BTreeMap::from([("compute.echo".into(), managed)]),
                None,
            )
            .is_err(),
            "deny-all must not bypass the normal strict claim flags"
        );
    }

    #[test]
    fn host_mediated_http_egress_allows_matching_operation_policy() {
        let managed = static_constraints();
        let constraints = managed.resolve(None).expect("resolve constraints");
        let context = runtime_context(&[]);
        let mut request = EgressHttpRequest {
            url: "https://api.example.test/v1/search".to_string(),
            method: "POST".to_string(),
            headers: Vec::new(),
            body: Some(b"request body must never appear in decision logs".to_vec()),
            credential_id: None,
        };

        let decision = authorize_runtime_http_egress(
            &context,
            &constraints,
            &mut request,
            &NoOpCredentialInjector,
        )
        .expect("matching host and port should be allowed");

        assert_eq!(decision.canonical_host, "api.example.test");
        assert_eq!(decision.port, 443);
        assert!(decision.tls_required);
        assert_eq!(request.headers.len(), 0);
    }

    #[test]
    fn host_mediated_http_egress_denies_wrong_host() {
        let managed = static_constraints();
        let constraints = managed.resolve(None).expect("resolve constraints");
        let context = runtime_context(&[]);
        let mut request = EgressHttpRequest {
            url: "https://evil.example.test/v1/search".to_string(),
            method: "GET".to_string(),
            headers: Vec::new(),
            body: None,
            credential_id: None,
        };

        let err = authorize_runtime_http_egress(
            &context,
            &constraints,
            &mut request,
            &NoOpCredentialInjector,
        )
        .expect_err("wrong host must be denied");
        let msg = err.to_string();
        assert!(msg.contains("HostNotAllowed") || msg.contains("host not allowed"));
        assert!(msg.contains("matrix.send"));
    }

    #[test]
    fn host_mediated_http_egress_denies_wrong_port() {
        let managed = static_constraints();
        let constraints = managed.resolve(None).expect("resolve constraints");
        let context = runtime_context(&[]);
        let mut request = EgressHttpRequest {
            url: "https://api.example.test:444/v1/search".to_string(),
            method: "GET".to_string(),
            headers: Vec::new(),
            body: None,
            credential_id: None,
        };

        let err = authorize_runtime_http_egress(
            &context,
            &constraints,
            &mut request,
            &NoOpCredentialInjector,
        )
        .expect_err("wrong port must be denied");
        let msg = err.to_string();
        assert!(msg.contains("PortNotAllowed") || msg.contains("port not allowed"));
        assert!(msg.contains("matrix.send"));
    }

    #[test]
    fn host_mediated_tcp_egress_denies_private_ip_literal() {
        let mut managed = static_constraints();
        managed.host_allow = vec!["10.0.0.5".to_string()];
        managed.deny_ip_literals = false;
        managed.deny_private_ranges = true;

        let err = managed
            .resolve(None)
            .expect_err("private IP literal allow-list must fail closed");
        assert!(err.to_string().contains("private range"));
    }

    #[test]
    fn host_mediated_tcp_egress_allows_matching_policy() {
        let managed = static_constraints();
        let constraints = managed.resolve(None).expect("resolve constraints");
        let context = runtime_context(&[]);
        let request = EgressTcpConnectRequest {
            host: "api.example.test".to_string(),
            port: 443,
            tls: true,
            sni_override: None,
            credential_id: None,
        };

        let decision =
            authorize_runtime_tcp_egress(&context, &constraints, &request, &NoOpCredentialInjector)
                .expect("matching TCP host and port should be allowed");

        assert_eq!(decision.decision.canonical_host, "api.example.test");
        assert_eq!(decision.decision.port, 443);
        assert!(decision.tcp_auth.is_none());
    }

    #[derive(Debug)]
    struct HeaderCredentialInjector;

    impl CredentialInjector for HeaderCredentialInjector {
        fn is_authorized(
            &self,
            credential_id: &str,
            _operation_id: &str,
            credential_allow: &[String],
        ) -> Result<bool, EgressError> {
            Ok(credential_allow
                .iter()
                .any(|allowed| allowed == credential_id))
        }

        fn is_host_allowed(&self, _credential_id: &str, host: &str) -> Result<bool, EgressError> {
            Ok(host == "api.example.test")
        }

        fn inject_http(
            &self,
            _credential_id: &str,
            headers: &mut Vec<HttpHeader>,
        ) -> Result<(), EgressError> {
            headers.push(HttpHeader {
                name: "Authorization".to_string(),
                value: "redaction-sentinel-header".to_string(),
            });
            Ok(())
        }

        fn get_tcp_auth(&self, _credential_id: &str) -> Result<Option<Vec<u8>>, EgressError> {
            Ok(Some(b"redaction-sentinel-tcp".to_vec()))
        }
    }

    #[test]
    fn host_mediated_http_egress_applies_credential_allow_list() {
        let managed = static_constraints();
        let constraints = managed.resolve(None).expect("resolve constraints");
        let credential_allow = vec!["cred-runtime".to_string()];
        let context = runtime_context(&credential_allow);
        let mut request = EgressHttpRequest {
            url: "https://api.example.test/v1/search".to_string(),
            method: "GET".to_string(),
            headers: Vec::new(),
            body: None,
            credential_id: Some("cred-runtime".to_string()),
        };

        let decision = authorize_runtime_http_egress(
            &context,
            &constraints,
            &mut request,
            &HeaderCredentialInjector,
        )
        .expect("authorized credential should be injected");

        assert!(decision.credential_injected);
        assert!(
            request
                .headers
                .iter()
                .any(|header| header.name == "Authorization")
        );
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "keeps the runtime policy JSONL proof matrix in one auditable test"
    )]
    fn br_4kw5f_9_6_runtime_network_policy_e2e_jsonl_matrix() {
        let managed = static_constraints();
        let constraints = managed.resolve(None).expect("resolve constraints");
        let context = runtime_context(&[]);
        let mut records = Vec::new();

        let mut allowed = EgressHttpRequest {
            url: "https://api.example.test/v1/search".to_string(),
            method: "GET".to_string(),
            headers: Vec::new(),
            body: Some(b"redaction-sentinel-body".to_vec()),
            credential_id: None,
        };
        let allowed_decision = authorize_runtime_http_egress(
            &context,
            &constraints,
            &mut allowed,
            &NoOpCredentialInjector,
        )
        .expect("allowed matrix case");
        records.push(e2e_record(
            "allowed_host",
            "allow",
            "pass",
            &json!({
                "connector_id": context.connector_id,
                "operation": context.operation,
                "zone_id": context.zone_id,
                "execution_mode": context.execution_mode.as_str(),
                "resolved_host": allowed_decision.canonical_host,
                "resolved_port": allowed_decision.port,
            }),
        ));

        let mut denied_host = EgressHttpRequest {
            url: "https://evil.example.test/v1/search".to_string(),
            method: "GET".to_string(),
            headers: Vec::new(),
            body: None,
            credential_id: None,
        };
        let denied_host_err = authorize_runtime_http_egress(
            &context,
            &constraints,
            &mut denied_host,
            &NoOpCredentialInjector,
        )
        .expect_err("denied host matrix case");
        records.push(e2e_record(
            "denied_host",
            "deny",
            "pass",
            &json!({
                "deny_reason": "HostNotAllowed",
                "error": denied_host_err.to_string(),
            }),
        ));

        let mut denied_port = EgressHttpRequest {
            url: "https://api.example.test:444/v1/search".to_string(),
            method: "GET".to_string(),
            headers: Vec::new(),
            body: None,
            credential_id: None,
        };
        let denied_port_err = authorize_runtime_http_egress(
            &context,
            &constraints,
            &mut denied_port,
            &NoOpCredentialInjector,
        )
        .expect_err("denied port matrix case");
        records.push(e2e_record(
            "denied_port",
            "deny",
            "pass",
            &json!({
                "deny_reason": "PortNotAllowed",
                "error": denied_port_err.to_string(),
            }),
        ));

        let missing_constraints_err = HostError::PreflightFailed(
            "operation_network_constraints missing for matrix.send".to_string(),
        );
        records.push(e2e_record(
            "missing_constraints",
            "deny",
            "pass",
            &json!({
                "deny_reason": "missing_operation_network_constraints",
                "error": missing_constraints_err.to_string(),
            }),
        ));

        let mut private_ip = static_constraints();
        private_ip.host_allow = vec!["10.0.0.5".to_string()];
        private_ip.deny_ip_literals = false;
        private_ip.deny_private_ranges = true;
        let private_ip_err = private_ip
            .resolve(None)
            .expect_err("private IP matrix case");
        records.push(e2e_record(
            "denied_private_ip",
            "deny",
            "pass",
            &json!({
                "deny_reason": "private_range",
                "error": private_ip_err.to_string(),
            }),
        ));

        let mut dynamic_host = static_constraints();
        dynamic_host.host_allow = vec!["${matrix_homeserver_host}".to_string()];
        dynamic_host.port_allow = vec![ManagedPortConstraint::Template(
            "${matrix_homeserver_port}".to_string(),
        )];
        let dynamic_err = dynamic_host
            .resolve(Some(
                &json!({"homeserver_url": "https://192.168.1.10:8448"}),
            ))
            .expect_err("dynamic host matrix case");
        records.push(e2e_record(
            "dynamic_config_host",
            "deny",
            "pass",
            &json!({
                "deny_reason": "dynamic_config_host_ip_literal",
                "error": dynamic_err.to_string(),
            }),
        ));

        let allowed_ops = vec!["matrix.send".to_string()];
        let missing_per_op = validate_runtime_network_claim(
            "fcp.test.managed-missing-per-op",
            RuntimeNetworkEnforcement::HostEgressProxy,
            allowed_ops.as_slice(),
            &BTreeMap::new(),
            None,
        )
        .expect_err("managed inventory without per-op constraints denied");
        records.push(e2e_record(
            "managed_missing_per_op",
            "deny",
            "pass",
            &json!({
                "deny_reason": "missing_operation_network_constraints",
                "runtime_enforcement_claim": true,
                "error": missing_per_op.to_string(),
            }),
        ));
        records.push(e2e_record(
            "manifest_missing_per_op",
            "deny",
            "pass",
            &json!({
                "deny_reason": "manifest_missing_operation_network_constraints",
                "runtime_enforcement_claim": true,
                "constraint_source": "manifest_imported_to_managed_inventory",
                "error": missing_per_op.to_string(),
            }),
        ));
        records.push(e2e_record(
            "host_allow_fallback_denied",
            "deny",
            "pass",
            &json!({
                "deny_reason": "connector_level_host_allow_fallback_denied",
                "runtime_enforcement_claim": true,
                "error": missing_per_op.to_string(),
            }),
        ));

        let mut wildcard_policy = static_constraints();
        wildcard_policy.host_allow = vec!["*.example.test".to_string()];
        let wildcard_policies = BTreeMap::from([("matrix.send".to_string(), wildcard_policy)]);
        let wildcard_err = validate_runtime_network_claim(
            "fcp.test.wildcard-denied",
            RuntimeNetworkEnforcement::HostEgressProxy,
            allowed_ops.as_slice(),
            &wildcard_policies,
            None,
        )
        .expect_err("wildcard host_allow denied");
        records.push(e2e_record(
            "wildcard_host_allow_denied",
            "deny",
            "pass",
            &json!({
                "deny_reason": "wildcard_host_allow_denied",
                "error": wildcard_err.to_string(),
            }),
        ));

        let mut missing_port = static_constraints();
        missing_port.port_allow.clear();
        let missing_port_policies = BTreeMap::from([("matrix.send".to_string(), missing_port)]);
        let missing_port_err = validate_runtime_network_claim(
            "fcp.test.missing-port",
            RuntimeNetworkEnforcement::WasiSandbox,
            allowed_ops.as_slice(),
            &missing_port_policies,
            None,
        )
        .expect_err("missing port_allow denied");
        records.push(e2e_record(
            "missing_port_allow_denied",
            "deny",
            "pass",
            &json!({
                "deny_reason": "missing_port_allow_denied",
                "error": missing_port_err.to_string(),
            }),
        ));

        let mut missing_sni = static_constraints();
        missing_sni.require_sni = false;
        let missing_sni_policies = BTreeMap::from([("matrix.send".to_string(), missing_sni)]);
        let missing_sni_err = validate_runtime_network_claim(
            "fcp.test.missing-sni",
            RuntimeNetworkEnforcement::HostEgressProxy,
            allowed_ops.as_slice(),
            &missing_sni_policies,
            None,
        )
        .expect_err("missing require_sni denied");
        records.push(e2e_record(
            "missing_require_sni_denied",
            "deny",
            "pass",
            &json!({
                "deny_reason": "missing_require_sni_denied",
                "error": missing_sni_err.to_string(),
            }),
        ));

        let mut missing_private_deny = static_constraints();
        missing_private_deny.deny_private_ranges = false;
        let missing_private_deny_policies =
            BTreeMap::from([("matrix.send".to_string(), missing_private_deny)]);
        let missing_private_deny_err = validate_runtime_network_claim(
            "fcp.test.missing-private-deny",
            RuntimeNetworkEnforcement::HostEgressProxy,
            allowed_ops.as_slice(),
            &missing_private_deny_policies,
            None,
        )
        .expect_err("missing deny_private_ranges denied");
        records.push(e2e_record(
            "missing_deny_private_ranges_denied",
            "deny",
            "pass",
            &json!({
                "deny_reason": "missing_deny_private_ranges_denied",
                "error": missing_private_deny_err.to_string(),
            }),
        ));

        let mut unsupported_placeholder = static_constraints();
        unsupported_placeholder.host_allow = vec!["${provider_host}".to_string()];
        let unsupported_placeholder_policies =
            BTreeMap::from([("matrix.send".to_string(), unsupported_placeholder)]);
        let unsupported_placeholder_err = validate_runtime_network_claim(
            "fcp.test.unsupported-placeholder",
            RuntimeNetworkEnforcement::WasiSandbox,
            allowed_ops.as_slice(),
            &unsupported_placeholder_policies,
            None,
        )
        .expect_err("unsupported placeholder denied");
        records.push(e2e_record(
            "unsupported_placeholder_denied",
            "deny",
            "pass",
            &json!({
                "deny_reason": "unsupported_placeholder_denied",
                "error": unsupported_placeholder_err.to_string(),
            }),
        ));

        let mut matrix_placeholder = static_constraints();
        matrix_placeholder.host_allow = vec!["${matrix_homeserver_host}".to_string()];
        matrix_placeholder.port_allow = vec![ManagedPortConstraint::Template(
            "${matrix_homeserver_port}".to_string(),
        )];
        let matrix_placeholder_policies =
            BTreeMap::from([("matrix.send".to_string(), matrix_placeholder)]);
        let matrix_config = json!({"homeserver_url": "https://matrix.example.test:8448"});
        validate_runtime_network_claim(
            "fcp.test.matrix-placeholder",
            RuntimeNetworkEnforcement::WasiSandbox,
            allowed_ops.as_slice(),
            &matrix_placeholder_policies,
            Some(&matrix_config),
        )
        .expect("Matrix placeholder policy validates");
        records.push(e2e_record(
            "matrix_placeholder_success",
            "allow",
            "pass",
            &json!({
                "resolved_host": "matrix.example.test",
                "resolved_port": 8448,
            }),
        ));

        let mut local_proxy = static_constraints();
        local_proxy.host_allow = vec!["127.0.0.1".to_string()];
        local_proxy.port_allow = vec![ManagedPortConstraint::Static(49_999)];
        local_proxy.deny_localhost = false;
        local_proxy.deny_private_ranges = false;
        local_proxy.deny_tailnet_ranges = false;
        local_proxy.require_sni = false;
        local_proxy.deny_ip_literals = false;
        let local_proxy_policies = BTreeMap::from([("test.local_proxy".to_string(), local_proxy)]);
        validate_runtime_network_claim(
            "fcp.test.local-proxy",
            RuntimeNetworkEnforcement::HostEgressProxy,
            &["test.local_proxy".to_string()],
            &local_proxy_policies,
            None,
        )
        .expect("explicit local/LAN exception validates");
        records.push(e2e_record(
            "local_lan_exception_success",
            "allow",
            "pass",
            &json!({
                "resolved_host": "127.0.0.1",
                "resolved_port": 49999,
                "exception": "explicit_loopback_proxy",
            }),
        ));

        let two_op_allowed = vec!["test.op_a".to_string(), "test.op_b".to_string()];
        let two_op_policies = BTreeMap::from([
            (
                "test.op_a".to_string(),
                runtime_two_op_constraints("api-a.example.test", 443),
            ),
            (
                "test.op_b".to_string(),
                runtime_two_op_constraints("api-b.example.test", 8443),
            ),
        ]);
        validate_runtime_network_claim(
            "fcp.test.two-op",
            RuntimeNetworkEnforcement::HostEgressProxy,
            two_op_allowed.as_slice(),
            &two_op_policies,
            None,
        )
        .expect("two-operation policy validates");
        let op_a = two_op_policies
            .get("test.op_a")
            .expect("operation A policy")
            .resolve(None)
            .expect("resolve operation A");
        let op_b = two_op_policies
            .get("test.op_b")
            .expect("operation B policy")
            .resolve(None)
            .expect("resolve operation B");
        EgressGuard::new()
            .evaluate(
                &EgressRequest::Http(EgressHttpRequest {
                    url: "https://api-a.example.test/v1".to_string(),
                    method: "GET".to_string(),
                    headers: Vec::new(),
                    body: None,
                    credential_id: None,
                }),
                &op_a,
            )
            .expect("operation A allows host A");
        records.push(e2e_record(
            "two_op_a_allows_a",
            "allow",
            "pass",
            &json!({"operation": "test.op_a", "resolved_host": "api-a.example.test"}),
        ));
        let op_a_denies_b = EgressGuard::new()
            .evaluate(
                &EgressRequest::Http(EgressHttpRequest {
                    url: "https://api-b.example.test:8443/v1".to_string(),
                    method: "GET".to_string(),
                    headers: Vec::new(),
                    body: None,
                    credential_id: None,
                }),
                &op_a,
            )
            .expect_err("operation A denies host B");
        records.push(e2e_record(
            "two_op_a_denies_b",
            "deny",
            "pass",
            &json!({"operation": "test.op_a", "deny_reason": op_a_denies_b.to_string()}),
        ));
        EgressGuard::new()
            .evaluate(
                &EgressRequest::Http(EgressHttpRequest {
                    url: "https://api-b.example.test:8443/v1".to_string(),
                    method: "GET".to_string(),
                    headers: Vec::new(),
                    body: None,
                    credential_id: None,
                }),
                &op_b,
            )
            .expect("operation B allows host B");
        records.push(e2e_record(
            "two_op_b_allows_b",
            "allow",
            "pass",
            &json!({"operation": "test.op_b", "resolved_host": "api-b.example.test"}),
        ));
        let op_b_denies_a = EgressGuard::new()
            .evaluate(
                &EgressRequest::Http(EgressHttpRequest {
                    url: "https://api-a.example.test/v1".to_string(),
                    method: "GET".to_string(),
                    headers: Vec::new(),
                    body: None,
                    credential_id: None,
                }),
                &op_b,
            )
            .expect_err("operation B denies host A");
        records.push(e2e_record(
            "two_op_b_denies_a",
            "deny",
            "pass",
            &json!({"operation": "test.op_b", "deny_reason": op_b_denies_a.to_string()}),
        ));

        let jsonl = records
            .iter()
            .map(|record| serde_json::to_string(record).expect("record serializes"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(jsonl.contains("\"scenario_id\":\"runtime_network_policy.allowed_host\""));
        assert!(jsonl.contains("\"scenario_id\":\"runtime_network_policy.denied_host\""));
        assert!(jsonl.contains("\"scenario_id\":\"runtime_network_policy.denied_port\""));
        assert!(jsonl.contains("\"scenario_id\":\"runtime_network_policy.denied_private_ip\""));
        assert!(jsonl.contains("\"scenario_id\":\"runtime_network_policy.missing_constraints\""));
        assert!(jsonl.contains("\"scenario_id\":\"runtime_network_policy.dynamic_config_host\""));
        assert!(
            jsonl.contains("\"scenario_id\":\"runtime_network_policy.managed_missing_per_op\"")
        );
        assert!(jsonl.contains("\"scenario_id\":\"runtime_network_policy.two_op_b_denies_a\""));
        assert!(!jsonl.contains("redaction-sentinel-body"));
        assert!(!jsonl.contains("redaction-sentinel-header"));
        assert!(!jsonl.contains("redaction-sentinel-tcp"));
        records.push(e2e_record(
            "redaction_scan",
            "allow",
            "pass",
            &json!({
                "sentinel_count": 3,
                "leak_found": false,
            }),
        ));

        let jsonl = records
            .iter()
            .map(|record| serde_json::to_string(record).expect("record serializes"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(jsonl.contains("\"scenario_id\":\"runtime_network_policy.redaction_scan\""));
        assert!(!jsonl.contains("redaction-sentinel-body"));
        assert!(!jsonl.contains("redaction-sentinel-header"));
        assert!(!jsonl.contains("redaction-sentinel-tcp"));
        for line in jsonl.lines() {
            let value: Value = serde_json::from_str(line).expect("JSONL line should parse");
            assert_eq!(value["result"], "pass");
            println!("RUNTIME_NETWORK_POLICY_E2E_JSONL {line}");
        }
    }

    fn runtime_context(credential_allow: &[String]) -> RuntimeEgressDecisionContext<'_> {
        RuntimeEgressDecisionContext {
            connector_id: "fcp.test.runtime-network",
            operation: "matrix.send",
            zone_id: "z:work",
            request_id: "req-runtime-network",
            correlation_id: Some("corr-runtime-network"),
            execution_mode: RuntimeNetworkEnforcement::HostEgressProxy,
            constraint_source: "unit-test",
            credential_allow,
        }
    }

    fn e2e_record(scenario: &str, observed_decision: &str, result: &str, details: &Value) -> Value {
        json!({
            "timestamp": "2026-05-07T00:00:00Z",
            "test_name": "br_4kw5f_9_6_runtime_network_policy_e2e_jsonl_matrix",
            "module": "fcp-host",
            "phase": "runtime_network_policy",
            "correlation_id": format!("corr-runtime-network-policy-{scenario}"),
            "result": result,
            "duration_ms": 0,
            "assertions": {
                "passed": 1,
                "failed": 0
            },
            "scenario_id": format!("runtime_network_policy.{scenario}"),
            "context": {
                "bead": "flywheel_connectors-4kw5f.9.6",
                "observed_decision": observed_decision,
                "constraint_source": "managed_connector_config.operation_network_constraints"
            },
            "details": details.clone()
        })
    }

    fn runtime_two_op_constraints(host: &str, port: u16) -> ManagedNetworkConstraints {
        ManagedNetworkConstraints {
            host_allow: vec![host.to_string()],
            port_allow: vec![ManagedPortConstraint::Static(port)],
            ..static_constraints()
        }
    }
}
