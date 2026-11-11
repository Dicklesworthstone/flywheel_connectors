//! Network Guard (Egress Proxy) implementation.
//!
//! The Network Guard is the single outbound network path for connectors under
//! `strict`/`moderate` sandbox profiles. It enforces `NetworkConstraints` from
//! the connector manifest and provides credential injection without exposing
//! raw secrets to connector processes.

use std::{collections::BTreeMap, net::IpAddr, sync::Arc};

use fcp_crypto::SecretFetchHook;
use fcp_manifest::NetworkConstraints;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, warn};

// ============================================================================
// Errors
// ============================================================================

/// Errors from the Network Guard.
#[derive(Debug, Error)]
pub enum EgressError {
    /// Request denied due to policy violation.
    #[error("egress denied: {reason}")]
    Denied { reason: String, code: DenyReason },

    /// Invalid request format.
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// URL parsing failed.
    #[error("invalid URL: {0}")]
    InvalidUrl(String),

    /// Hostname canonicalization failed.
    #[error("hostname canonicalization failed: {0}")]
    CanonicalizationFailed(String),

    /// DNS resolution failed.
    #[error("DNS resolution failed: {0}")]
    DnsResolutionFailed(String),

    /// Credential not found or not authorized.
    #[error("credential error: {0}")]
    CredentialError(String),

    /// TLS verification failed.
    #[error("TLS verification failed: {0}")]
    TlsVerificationFailed(String),
}

/// Reason codes for denied requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    /// Host not in allow list.
    HostNotAllowed,
    /// Port not in allow list.
    PortNotAllowed,
    /// IP literal used when denied.
    IpLiteralDenied,
    /// Resolved IP is outside the configured `ip_allow` set (br-45tjy).
    IpNotAllowed,
    /// Localhost access denied.
    LocalhostDenied,
    /// Private range (RFC1918) access denied.
    PrivateRangeDenied,
    /// Tailnet range access denied.
    TailnetRangeDenied,
    /// Link-local range access denied.
    LinkLocalDenied,
    /// Custom CIDR deny rule matched.
    CidrDenyMatched,
    /// SNI mismatch.
    SniMismatch,
    /// SPKI pin mismatch.
    SpkiPinMismatch,
    /// Credential not authorized for this operation.
    CredentialNotAuthorized,
    /// Credential host binding does not allow the requested host.
    CredentialHostNotAllowed,
    /// Hostname not canonicalized.
    HostnameNotCanonical,
    /// Too many DNS responses.
    DnsMaxIpsExceeded,
    /// Max redirects exceeded.
    MaxRedirectsExceeded,
}

// ============================================================================
// Request Types
// ============================================================================

/// Egress request envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EgressRequest {
    /// HTTP/HTTPS request.
    Http(EgressHttpRequest),
    /// Raw TCP connection (for non-HTTP protocols like postgres, redis).
    TcpConnect(EgressTcpConnectRequest),
}

/// HTTP egress request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressHttpRequest {
    /// Target URL (must be absolute).
    pub url: String,
    /// HTTP method (GET, POST, etc.).
    pub method: String,
    /// Request headers (Authorization headers will be stripped for logging).
    pub headers: Vec<HttpHeader>,
    /// Request body (optional).
    #[serde(default)]
    pub body: Option<Vec<u8>>,
    /// Credential ID for injection (optional).
    /// If provided, the guard will inject the credential into the request.
    #[serde(default)]
    pub credential_id: Option<String>,
}

/// HTTP header key-value pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

/// TCP connect egress request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressTcpConnectRequest {
    /// Target hostname.
    pub host: String,
    /// Target port.
    pub port: u16,
    /// Whether to upgrade to TLS after connect.
    #[serde(default)]
    pub tls: bool,
    /// SNI hostname override (defaults to `host` if TLS enabled).
    #[serde(default)]
    pub sni_override: Option<String>,
    /// Credential ID for injection (optional).
    #[serde(default)]
    pub credential_id: Option<String>,
}

// ============================================================================
// Evaluation Result
// ============================================================================

/// Decision from the egress guard.
#[derive(Debug, Clone)]
pub struct EgressDecision {
    /// Whether the request is allowed.
    pub allowed: bool,
    /// Canonical hostname (after IDNA2008 + lowercase).
    pub canonical_host: String,
    /// Resolved IP addresses (after DNS resolution).
    pub resolved_ips: Vec<IpAddr>,
    /// Port to connect to.
    pub port: u16,
    /// Whether TLS is required.
    pub tls_required: bool,
    /// Expected SNI (for TLS verification).
    pub expected_sni: Option<String>,
    /// SPKI pins to verify (if any).
    pub spki_pins: Vec<Vec<u8>>,
    /// Injected credential (if any, already applied to request).
    pub credential_injected: bool,
}

/// TCP authorization decision with optional connection auth bytes.
#[derive(Debug, Clone)]
pub struct EgressTcpDecision {
    pub decision: EgressDecision,
    pub tcp_auth: Option<Vec<u8>>,
}

// ============================================================================
// CIDR Defaults
// ============================================================================

/// Default CIDR ranges that are denied when `deny_localhost` is true.
const LOCALHOST_CIDRS: &[&str] = &[
    "127.0.0.0/8", // IPv4 loopback
    "::1/128",     // IPv6 loopback
    "0.0.0.0/8",   // This network (localhost-ish)
    "::/128",      // Unspecified address
];

/// Default CIDR ranges that are denied when `deny_private_ranges` is true (RFC1918 + RFC4193).
const PRIVATE_CIDRS: &[&str] = &[
    "10.0.0.0/8",     // RFC1918 Class A
    "172.16.0.0/12",  // RFC1918 Class B
    "192.168.0.0/16", // RFC1918 Class C
    "fc00::/7",       // IPv6 Unique Local Addresses (ULA)
];

/// Link-local ranges (always denied alongside private ranges).
const LINK_LOCAL_CIDRS: &[&str] = &[
    "169.254.0.0/16", // IPv4 link-local
    "fe80::/10",      // IPv6 link-local
];

/// Default CIDR ranges that are denied when `deny_tailnet_ranges` is true.
/// Tailscale uses CGNAT space (100.64.0.0/10) for its mesh network.
const TAILNET_CIDRS: &[&str] = &[
    "100.64.0.0/10",       // CGNAT / Tailscale IPv4 address space
    "fd7a:115c:a1e0::/48", // Tailscale IPv6 address space
];

// ============================================================================
// Hostname Canonicalization
// ============================================================================

/// Canonicalize a hostname according to FCP2 rules:
/// 1. Convert to lowercase
/// 2. Apply IDNA2008 (Punycode encoding for internationalized domains)
/// 3. Strip trailing dot
///
/// # Errors
///
/// Returns an error if the hostname is invalid or cannot be encoded.
pub fn canonicalize_hostname(hostname: &str) -> Result<String, EgressError> {
    if hostname.is_empty() {
        return Err(EgressError::CanonicalizationFailed(
            "hostname is empty".into(),
        ));
    }

    // Strip trailing dot (FQDN notation)
    let hostname = hostname.strip_suffix('.').unwrap_or(hostname);

    // Apply IDNA2008 encoding (handles Unicode → Punycode)
    let ascii_host = idna::domain_to_ascii(hostname)
        .map_err(|e| EgressError::CanonicalizationFailed(e.to_string()))?;

    // Lowercase (IDNA should already produce lowercase ASCII, but be explicit)
    let canonical = ascii_host.to_ascii_lowercase();

    if canonical.is_empty() {
        return Err(EgressError::CanonicalizationFailed(
            "canonicalized hostname is empty".into(),
        ));
    }

    Ok(canonical)
}

fn canonicalize_host_pattern(pattern: &str) -> Option<String> {
    if pattern.is_empty() {
        return None;
    }

    if pattern == "*" {
        return Some("*".to_string());
    }

    let (wildcard, raw) = pattern
        .strip_prefix("*.")
        .map_or((false, pattern), |rest| (true, rest));

    let canonical = if raw.parse::<IpAddr>().is_ok() {
        raw.to_string()
    } else {
        canonicalize_hostname(raw).ok()?
    };

    if wildcard {
        Some(format!("*.{canonical}"))
    } else {
        Some(canonical)
    }
}

/// Check if a hostname is canonical (already in FCP2 canonical form).
#[must_use]
pub fn is_hostname_canonical(hostname: &str) -> bool {
    if hostname.is_empty() || hostname.ends_with('.') {
        return false;
    }

    // Must be ASCII
    if !hostname.is_ascii() {
        return false;
    }

    // Must be lowercase
    if hostname.bytes().any(|b| b.is_ascii_uppercase()) {
        return false;
    }

    // Check if IDNA encoding is idempotent
    idna::domain_to_ascii(hostname).is_ok_and(|encoded| encoded == hostname)
}

// ============================================================================
// CIDR Checking
// ============================================================================

/// Check if an IP address is contained in any of the given CIDR ranges.
fn ip_in_any_cidr(ip: IpAddr, cidrs: &[IpNet]) -> bool {
    // Normalize IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) to pure IPv4 to prevent SSRF
    // bypasses. Do NOT normalize IPv4-compatible addresses (::x.x.x.x) — those are distinct
    // IPv6 addresses and should be matched against IPv6 CIDR rules only.
    let check_ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    };
    cidrs.iter().any(|net| net.contains(&check_ip))
}

/// Parse a list of CIDR strings into `IpNet` values.
fn parse_cidr_list(cidrs: &[&str]) -> Vec<IpNet> {
    cidrs
        .iter()
        .filter_map(|s| s.parse::<IpNet>().ok())
        .collect()
}

/// Check if an IP address is a localhost address.
#[must_use]
pub fn is_localhost(ip: IpAddr) -> bool {
    static LOCALHOST_NETS: std::sync::LazyLock<Vec<IpNet>> =
        std::sync::LazyLock::new(|| parse_cidr_list(LOCALHOST_CIDRS));
    ip_in_any_cidr(ip, &LOCALHOST_NETS)
}

/// Check if an IP address is in a private range (RFC1918/RFC4193).
#[must_use]
pub fn is_private_range(ip: IpAddr) -> bool {
    static PRIVATE_NETS: std::sync::LazyLock<Vec<IpNet>> =
        std::sync::LazyLock::new(|| parse_cidr_list(PRIVATE_CIDRS));
    ip_in_any_cidr(ip, &PRIVATE_NETS)
}

/// Check if an IP address is in a link-local range.
#[must_use]
pub fn is_link_local(ip: IpAddr) -> bool {
    static LINK_LOCAL_NETS: std::sync::LazyLock<Vec<IpNet>> =
        std::sync::LazyLock::new(|| parse_cidr_list(LINK_LOCAL_CIDRS));
    ip_in_any_cidr(ip, &LINK_LOCAL_NETS)
}

/// Check if an IP address is in the Tailnet range (CGNAT 100.64.0.0/10).
#[must_use]
pub fn is_tailnet_range(ip: IpAddr) -> bool {
    static TAILNET_NETS: std::sync::LazyLock<Vec<IpNet>> =
        std::sync::LazyLock::new(|| parse_cidr_list(TAILNET_CIDRS));
    ip_in_any_cidr(ip, &TAILNET_NETS)
}

// ============================================================================
// Egress Guard
// ============================================================================

/// The Network Guard evaluates egress requests against `NetworkConstraints`.
///
/// This is the core policy enforcement point for all outbound network access.
#[derive(Debug, Default)]
pub struct EgressGuard {
    // Future: DNS resolver configuration, connection pool, etc.
}

impl EgressGuard {
    /// Create a new egress guard.
    #[must_use]
    pub const fn new() -> Self {
        Self {}
    }

    /// Evaluate an egress request against the given constraints.
    ///
    /// This performs all policy checks except actual DNS resolution and TLS
    /// verification (which happen at connection time).
    ///
    /// # Errors
    ///
    /// Returns `EgressError::Denied` if the request violates any constraint.
    pub fn evaluate(
        &self,
        request: &EgressRequest,
        constraints: &NetworkConstraints,
    ) -> Result<EgressDecision, EgressError> {
        match request {
            EgressRequest::Http(http) => self.evaluate_http(http, constraints),
            EgressRequest::TcpConnect(tcp) => self.evaluate_tcp(tcp, constraints),
        }
    }

    /// Evaluate an HTTP request and perform credential authorization/injection.
    ///
    /// This is the integrated "secretless egress" path: policy check + credential gating.
    ///
    /// # Errors
    /// Returns `EgressError::Denied` for policy or credential violations.
    pub fn authorize_http(
        &self,
        request: &mut EgressHttpRequest,
        constraints: &NetworkConstraints,
        injector: &dyn CredentialInjector,
        operation_id: &str,
        credential_allow: &[String],
    ) -> Result<EgressDecision, EgressError> {
        // br-z2tbh: skip the `EgressRequest::Http(request.clone())` wrap
        // that memcopied url + method + headers + body + credential_id
        // on every authorize call. evaluate_http already accepts a
        // borrowed &EgressHttpRequest, so drive it directly.
        let mut decision = self.evaluate_http(request, constraints)?;

        let Some(credential_id) = request.credential_id.as_deref() else {
            return Ok(decision);
        };

        let authorized = injector.is_authorized(credential_id, operation_id, credential_allow)?;
        if !authorized {
            return Err(EgressError::Denied {
                reason: format!(
                    "credential `{credential_id}` not authorized for operation `{operation_id}`"
                ),
                code: DenyReason::CredentialNotAuthorized,
            });
        }

        let host_allowed = injector.is_host_allowed(credential_id, &decision.canonical_host)?;
        if !host_allowed {
            return Err(EgressError::Denied {
                reason: format!(
                    "credential `{credential_id}` not allowed for host `{}`",
                    decision.canonical_host
                ),
                code: DenyReason::CredentialHostNotAllowed,
            });
        }

        // Signers may replace headers, never the method, URL, body or credential
        // identity which this guard already authorized. The body stays borrowed.
        request.headers = injector.inject_http_request(credential_id, request)?;
        decision.credential_injected = true;

        Ok(decision)
    }

    /// Evaluate a TCP connect request and perform credential authorization.
    ///
    /// Returns optional auth bytes to send after connection establishment.
    pub fn authorize_tcp(
        &self,
        request: &EgressTcpConnectRequest,
        constraints: &NetworkConstraints,
        injector: &dyn CredentialInjector,
        operation_id: &str,
        credential_allow: &[String],
    ) -> Result<EgressTcpDecision, EgressError> {
        // br-z2tbh: same zero-copy rework as authorize_http — skip the
        // `EgressRequest::TcpConnect(request.clone())` wrap and call
        // evaluate_tcp directly against the borrowed request.
        let mut decision = self.evaluate_tcp(request, constraints)?;

        let Some(credential_id) = request.credential_id.as_deref() else {
            return Ok(EgressTcpDecision {
                decision,
                tcp_auth: None,
            });
        };

        let authorized = injector.is_authorized(credential_id, operation_id, credential_allow)?;
        if !authorized {
            return Err(EgressError::Denied {
                reason: format!(
                    "credential `{credential_id}` not authorized for operation `{operation_id}`"
                ),
                code: DenyReason::CredentialNotAuthorized,
            });
        }

        let host_allowed = injector.is_host_allowed(credential_id, &decision.canonical_host)?;
        if !host_allowed {
            return Err(EgressError::Denied {
                reason: format!(
                    "credential `{credential_id}` not allowed for host `{}`",
                    decision.canonical_host
                ),
                code: DenyReason::CredentialHostNotAllowed,
            });
        }

        let tcp_auth = injector.get_tcp_auth(credential_id)?;
        if tcp_auth.is_some() {
            decision.credential_injected = true;
        }

        Ok(EgressTcpDecision { decision, tcp_auth })
    }

    /// Evaluate an HTTP request.
    fn evaluate_http(
        &self,
        request: &EgressHttpRequest,
        constraints: &NetworkConstraints,
    ) -> Result<EgressDecision, EgressError> {
        // Parse URL
        let url = url::Url::parse(&request.url)
            .map_err(|e| EgressError::InvalidUrl(format!("{}: {e}", request.url)))?;

        let scheme = url.scheme();
        if scheme != "http" && scheme != "https" {
            return Err(EgressError::InvalidUrl(format!(
                "HTTP egress URL scheme must be http or https, got {scheme}"
            )));
        }

        if !url.username().is_empty() || url.password().is_some() {
            return Err(EgressError::InvalidUrl(
                "HTTP egress URL must not include embedded credentials".into(),
            ));
        }

        // Extract host
        let host = url
            .host_str()
            .ok_or_else(|| EgressError::InvalidUrl("URL has no host".into()))?;

        // Extract port (default based on scheme)
        let port = url.port_or_known_default().ok_or_else(|| {
            EgressError::InvalidUrl(format!(
                "cannot determine port for scheme: {}",
                url.scheme()
            ))
        })?;

        // Determine if TLS is required
        let tls_required = scheme == "https";

        // Evaluate common constraints
        self.evaluate_host_port(host, port, tls_required, constraints)
    }

    /// Evaluate a TCP connect request.
    fn evaluate_tcp(
        &self,
        request: &EgressTcpConnectRequest,
        constraints: &NetworkConstraints,
    ) -> Result<EgressDecision, EgressError> {
        self.evaluate_host_port(&request.host, request.port, request.tls, constraints)
    }

    /// Core constraint evaluation for host:port.
    fn evaluate_host_port(
        &self,
        host: &str,
        port: u16,
        tls_required: bool,
        constraints: &NetworkConstraints,
    ) -> Result<EgressDecision, EgressError> {
        // Strip IPv6 brackets if present (url::Url::host_str() retains them)
        let clean_host = if host.starts_with('[') && host.ends_with(']') {
            &host[1..host.len() - 1]
        } else {
            host
        };

        // Step 1: Check if host is an IP literal
        let is_ip_literal = clean_host.parse::<IpAddr>().is_ok();
        if is_ip_literal && constraints.deny_ip_literals {
            warn!(host = %clean_host, "IP literal denied");
            return Err(EgressError::Denied {
                reason: format!("IP literals are not allowed: {clean_host}"),
                code: DenyReason::IpLiteralDenied,
            });
        }

        // Step 2: Canonicalize hostname
        let canonical_host = if is_ip_literal {
            clean_host.to_string()
        } else {
            let canonical = canonicalize_hostname(clean_host)?;
            if canonical != clean_host {
                if constraints.require_host_canonicalization {
                    return Err(EgressError::Denied {
                        reason: format!("hostname not canonical: {clean_host}"),
                        code: DenyReason::HostnameNotCanonical,
                    });
                }
                debug!(original = %clean_host, canonical = %canonical, "hostname canonicalized");
            }
            canonical
        };

        if let Ok(ip) = canonical_host.parse::<IpAddr>() {
            if !constraints.ip_allow.is_empty() && !ip_allow_contains(&constraints.ip_allow, ip) {
                return Err(EgressError::Denied {
                    reason: format!(
                        "IP literal {ip} not in ip_allow (size {})",
                        constraints.ip_allow.len()
                    ),
                    code: DenyReason::IpNotAllowed,
                });
            }
        }

        // Step 3: Check host against allow list
        if !self.host_matches_allow_list(&canonical_host, is_ip_literal, constraints) {
            warn!(host = %canonical_host, "host not in allow list");
            return Err(EgressError::Denied {
                reason: format!("host not allowed: {canonical_host}"),
                code: DenyReason::HostNotAllowed,
            });
        }

        // Step 4: Check port against allow list
        if !constraints.port_allow.contains(&port) {
            warn!(port = %port, "port not in allow list");
            return Err(EgressError::Denied {
                reason: format!("port not allowed: {port}"),
                code: DenyReason::PortNotAllowed,
            });
        }

        // Step 5: If it's an IP literal, check CIDR constraints immediately
        if let Ok(ip) = canonical_host.parse::<IpAddr>() {
            self.check_ip_constraints(ip, constraints)?;
        }

        // Build decision
        let expected_sni = if tls_required && constraints.require_sni {
            Some(canonical_host.clone())
        } else {
            None
        };

        let spki_pins: Vec<Vec<u8>> = constraints
            .spki_pins
            .iter()
            .map(|b| b.as_bytes().to_vec())
            .collect();

        Ok(EgressDecision {
            allowed: true,
            canonical_host,
            resolved_ips: vec![], // Populated at DNS resolution time
            port,
            tls_required,
            expected_sni,
            spki_pins,
            credential_injected: false,
        })
    }

    /// Check if a host matches the allow list.
    #[allow(clippy::unused_self)] // Will use self for caching in future
    fn host_matches_allow_list(
        &self,
        host: &str,
        is_ip_literal: bool,
        constraints: &NetworkConstraints,
    ) -> bool {
        Self::host_matches_allow_entries(
            host,
            is_ip_literal,
            &constraints.host_allow,
            &constraints.ip_allow,
        )
    }

    fn host_matches_allow_entries(
        host: &str,
        is_ip_literal: bool,
        host_allow: &[String],
        ip_allow: &[IpAddr],
    ) -> bool {
        // Check explicit IP allow list
        if is_ip_literal {
            if let Ok(ip) = host.parse::<IpAddr>() {
                if !ip_allow.is_empty() {
                    return ip_allow_contains(ip_allow, ip);
                }
            }
        }

        // Check hostname allow list
        for pattern in host_allow {
            let Some(canonical_pattern) = canonicalize_host_pattern(pattern) else {
                continue;
            };

            if canonical_pattern == "*" {
                return true;
            }

            if canonical_pattern.starts_with("*.") {
                // Wildcard match: *.example.com matches sub.example.com
                let suffix = &canonical_pattern[1..]; // ".example.com"
                if host.ends_with(suffix) && host.len() > suffix.len() {
                    // Ensure there's actually a subdomain (not just "example.com")
                    return true;
                }
            } else if canonical_pattern == host {
                return true;
            }
        }

        false
    }

    /// Check resolved IP against CIDR constraints.
    ///
    /// This is called after DNS resolution to verify the resolved IPs are allowed.
    ///
    /// # Errors
    ///
    /// Returns `EgressError::Denied` if the IP matches any deny rule.
    pub fn check_ip_constraints(
        &self,
        ip: IpAddr,
        constraints: &NetworkConstraints,
    ) -> Result<(), EgressError> {
        // Check localhost
        if constraints.deny_localhost && is_localhost(ip) {
            return Err(EgressError::Denied {
                reason: format!("localhost access denied: {ip}"),
                code: DenyReason::LocalhostDenied,
            });
        }

        // Check private ranges (RFC1918)
        if constraints.deny_private_ranges && is_private_range(ip) {
            return Err(EgressError::Denied {
                reason: format!("private range access denied: {ip}"),
                code: DenyReason::PrivateRangeDenied,
            });
        }

        // Check link-local (always denied with private ranges)
        if constraints.deny_private_ranges && is_link_local(ip) {
            return Err(EgressError::Denied {
                reason: format!("link-local access denied: {ip}"),
                code: DenyReason::LinkLocalDenied,
            });
        }

        // Check tailnet ranges
        if constraints.deny_tailnet_ranges && is_tailnet_range(ip) {
            return Err(EgressError::Denied {
                reason: format!("tailnet range access denied: {ip}"),
                code: DenyReason::TailnetRangeDenied,
            });
        }

        // Check custom CIDR deny list.
        // Normalize IPv4-mapped IPv6 (::ffff:x.x.x.x) to pure IPv4 so that
        // IPv4 CIDR deny rules cannot be bypassed with mapped addresses.
        let check_ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            IpAddr::V4(_) => ip,
        };
        // Validate ALL cidr_deny rules upfront so a malformed rule that sits after
        // a matching valid rule still fails-closed regardless of iteration order.
        // Without this pre-pass, an IP that matches an early valid CIDR would
        // short-circuit before reaching a malformed entry, letting operator
        // misconfigurations lurk silently until a non-matching IP arrives.
        let parsed_deny: Vec<IpNet> = constraints
            .cidr_deny
            .iter()
            .map(|cidr_str| {
                cidr_str.parse::<IpNet>().map_err(|e| {
                    warn!(cidr = %cidr_str, error = %e, "rejecting unparseable CIDR deny rule");
                    EgressError::InvalidRequest(format!("invalid cidr_deny rule `{cidr_str}`: {e}"))
                })
            })
            .collect::<Result<_, _>>()?;
        for (cidr, cidr_str) in parsed_deny.iter().zip(constraints.cidr_deny.iter()) {
            if cidr.contains(&check_ip) {
                return Err(EgressError::Denied {
                    reason: format!("CIDR deny rule matched: {ip} in {cidr_str}"),
                    code: DenyReason::CidrDenyMatched,
                });
            }
        }

        Ok(())
    }

    /// Validate resolved IPs from DNS resolution.
    ///
    /// Checks all resolved IPs against constraints and enforces `dns_max_ips`.
    /// When `constraints.ip_allow` is non-empty, EVERY resolved IP must
    /// be a member of the allow-list (br-45tjy). Previously only the
    /// CIDR deny rules + tailnet/private/loopback flags were enforced
    /// post-DNS, which let a hostname that happened to resolve to a
    /// public IP outside `ip_allow` bypass the explicit pin.
    ///
    /// # Errors
    ///
    /// Returns `EgressError::Denied` if any IP violates constraints or too many IPs returned.
    pub fn validate_dns_resolution(
        &self,
        ips: &[IpAddr],
        constraints: &NetworkConstraints,
    ) -> Result<Vec<IpAddr>, EgressError> {
        if ips.len() > constraints.dns_max_ips as usize {
            return Err(EgressError::Denied {
                reason: format!(
                    "DNS returned {} IPs, max allowed is {}",
                    ips.len(),
                    constraints.dns_max_ips
                ),
                code: DenyReason::DnsMaxIpsExceeded,
            });
        }

        let parsed_deny: Vec<IpNet> = constraints
            .cidr_deny
            .iter()
            .map(|cidr_str| {
                cidr_str.parse::<IpNet>().map_err(|e| {
                    warn!(cidr = %cidr_str, error = %e, "rejecting unparseable CIDR deny rule");
                    EgressError::InvalidRequest(format!("invalid cidr_deny rule `{cidr_str}`: {e}"))
                })
            })
            .collect::<Result<_, _>>()?;

        let mut allowed_ips = Vec::with_capacity(ips.len());
        for &ip in ips {
            // Check localhost
            if constraints.deny_localhost && is_localhost(ip) {
                return Err(EgressError::Denied {
                    reason: format!("localhost access denied: {ip}"),
                    code: DenyReason::LocalhostDenied,
                });
            }

            // Check private ranges (RFC1918)
            if constraints.deny_private_ranges && is_private_range(ip) {
                return Err(EgressError::Denied {
                    reason: format!("private range access denied: {ip}"),
                    code: DenyReason::PrivateRangeDenied,
                });
            }

            // Check link-local (always denied with private ranges)
            if constraints.deny_private_ranges && is_link_local(ip) {
                return Err(EgressError::Denied {
                    reason: format!("link-local access denied: {ip}"),
                    code: DenyReason::LinkLocalDenied,
                });
            }

            // Check tailnet ranges
            if constraints.deny_tailnet_ranges && is_tailnet_range(ip) {
                return Err(EgressError::Denied {
                    reason: format!("tailnet range access denied: {ip}"),
                    code: DenyReason::TailnetRangeDenied,
                });
            }

            // Check custom CIDR deny list.
            let check_ip = match ip {
                IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
                IpAddr::V4(_) => ip,
            };

            for (cidr, cidr_str) in parsed_deny.iter().zip(constraints.cidr_deny.iter()) {
                if cidr.contains(&check_ip) {
                    return Err(EgressError::Denied {
                        reason: format!("CIDR deny rule matched: {ip} in {cidr_str}"),
                        code: DenyReason::CidrDenyMatched,
                    });
                }
            }

            if !constraints.ip_allow.is_empty() && !ip_allow_contains(&constraints.ip_allow, ip) {
                return Err(EgressError::Denied {
                    reason: format!(
                        "resolved IP {ip} not in ip_allow (size {})",
                        constraints.ip_allow.len()
                    ),
                    code: DenyReason::IpNotAllowed,
                });
            }
            allowed_ips.push(ip);
        }

        Ok(allowed_ips)
    }
}

/// Check whether a host matches a manifest-style allow list using the production
/// canonicalization and wildcard rules.
#[must_use]
pub fn host_matches_allow_list(host: &str, host_allow: &[String]) -> bool {
    let Ok(canonical_host) = canonicalize_hostname(host) else {
        return false;
    };
    let is_ip_literal = canonical_host.parse::<IpAddr>().is_ok();
    EgressGuard::host_matches_allow_entries(&canonical_host, is_ip_literal, host_allow, &[])
}

/// Check whether `ip` is a member of the configured `ip_allow` list.
///
/// Normalizes IPv4-mapped IPv6 (`::ffff:x.x.x.x`) to pure IPv4 before
/// comparison so an attacker-controlled resolver cannot bypass an
/// IPv4-only allow-list by returning an IPv4-mapped AAAA record.
fn ip_allow_contains(ip_allow: &[IpAddr], ip: IpAddr) -> bool {
    let normalized = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    };
    ip_allow.iter().any(|entry| {
        let entry_normalized = match *entry {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(*entry, IpAddr::V4),
            IpAddr::V4(_) => *entry,
        };
        entry_normalized == normalized
    })
}

// ============================================================================
// Credential Injection
// ============================================================================

/// Credential injection context for the Network Guard.
///
/// This trait defines the interface for credential backends. The Network Guard
/// uses this to inject credentials into requests without exposing raw secret
/// bytes to connector processes.
pub trait CredentialInjector: Send + Sync {
    /// Check if a credential is authorized for the given operation.
    ///
    /// # Errors
    ///
    /// Returns an error if credential lookup or authorization check fails.
    fn is_authorized(
        &self,
        credential_id: &str,
        operation_id: &str,
        credential_allow: &[String],
    ) -> Result<bool, EgressError>;

    /// Check if a credential is allowed for the given destination host.
    ///
    /// Default: deny all hosts. Wrap a backend in [`AllowAllHosts`] when an
    /// operator explicitly wants credentials to be host-unbound.
    fn is_host_allowed(&self, _credential_id: &str, _host: &str) -> Result<bool, EgressError> {
        Ok(false)
    }

    /// Inject a credential into an HTTP request.
    ///
    /// The injector should modify the headers in-place to add authentication.
    ///
    /// # Errors
    ///
    /// Returns an error if the credential cannot be retrieved or injected.
    fn inject_http(
        &self,
        credential_id: &str,
        headers: &mut Vec<HttpHeader>,
    ) -> Result<(), EgressError>;

    /// Inject authentication using the complete, policy-authorized request.
    ///
    /// Request-signing schemes can inspect the method, URL, headers, and body
    /// before returning the authenticated headers. The request is immutable:
    /// its authorized destination and request identity cannot be rewritten by
    /// an injector. The guard publishes headers only after signing succeeds.
    ///
    /// The default uses header-only injection for authentication schemes that
    /// do not sign request content. Wrappers must forward this method to their
    /// inner injector so request-aware signing is preserved.
    ///
    /// # Errors
    ///
    /// Returns an error if the credential cannot be retrieved or the request
    /// cannot be authenticated.
    fn inject_http_request(
        &self,
        credential_id: &str,
        request: &EgressHttpRequest,
    ) -> Result<Vec<HttpHeader>, EgressError> {
        let mut headers = request.headers.clone();
        self.inject_http(credential_id, &mut headers)?;
        Ok(headers)
    }

    /// Get connection credentials for a TCP connection.
    ///
    /// Returns opaque bytes that should be sent after connection establishment
    /// (e.g., for database authentication).
    ///
    /// # Errors
    ///
    /// Returns an error if the credential cannot be retrieved.
    fn get_tcp_auth(&self, credential_id: &str) -> Result<Option<Vec<u8>>, EgressError>;
}

/// Explicit opt-in wrapper for host-unbound credential backends.
///
/// Credential injectors fail closed by default when they do not implement
/// host binding. This adapter makes the exceptional "allow every destination
/// host" policy visible at the construction site.
#[derive(Debug, Clone, Default)]
pub struct AllowAllHosts<I> {
    inner: I,
}

impl<I> AllowAllHosts<I> {
    /// Create a host-unbound credential injector wrapper.
    pub const fn new(inner: I) -> Self {
        Self { inner }
    }

    /// Return the wrapped injector by reference.
    #[must_use]
    pub const fn inner(&self) -> &I {
        &self.inner
    }

    /// Return the wrapped injector by mutable reference.
    #[must_use]
    pub const fn inner_mut(&mut self) -> &mut I {
        &mut self.inner
    }

    /// Consume the wrapper and return the wrapped injector.
    #[must_use]
    pub fn into_inner(self) -> I {
        self.inner
    }
}

impl<I: CredentialInjector> CredentialInjector for AllowAllHosts<I> {
    fn is_authorized(
        &self,
        credential_id: &str,
        operation_id: &str,
        credential_allow: &[String],
    ) -> Result<bool, EgressError> {
        self.inner
            .is_authorized(credential_id, operation_id, credential_allow)
    }

    fn is_host_allowed(&self, _credential_id: &str, _host: &str) -> Result<bool, EgressError> {
        Ok(true)
    }

    fn inject_http(
        &self,
        credential_id: &str,
        headers: &mut Vec<HttpHeader>,
    ) -> Result<(), EgressError> {
        self.inner.inject_http(credential_id, headers)
    }

    fn inject_http_request(
        &self,
        credential_id: &str,
        request: &EgressHttpRequest,
    ) -> Result<Vec<HttpHeader>, EgressError> {
        self.inner.inject_http_request(credential_id, request)
    }

    fn get_tcp_auth(&self, credential_id: &str) -> Result<Option<Vec<u8>>, EgressError> {
        self.inner.get_tcp_auth(credential_id)
    }
}

/// Credential injector backed by the host secret-fetch hook.
///
/// The connector-visible request carries only a credential identifier. This
/// adapter fetches the corresponding secret at the egress boundary, applies it
/// as a bearer token, and removes connector-local credential headers before the
/// request leaves the guard.
#[derive(Clone)]
pub struct SecretFetchCredentialInjector {
    hook: Arc<dyn SecretFetchHook>,
    allowed_hosts: BTreeMap<String, Vec<String>>,
}

impl SecretFetchCredentialInjector {
    /// Create a secret-fetch backed credential injector.
    #[must_use]
    pub fn new(hook: Arc<dyn SecretFetchHook>) -> Self {
        Self {
            hook,
            allowed_hosts: BTreeMap::new(),
        }
    }

    /// Bind a credential identifier to allowed destination host patterns.
    #[must_use]
    pub fn with_allowed_hosts<I, S>(mut self, credential_id: impl Into<String>, hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let allowed = self.allowed_hosts.entry(credential_id.into()).or_default();
        allowed.extend(hosts.into_iter().map(Into::into));
        self
    }

    fn fetch_bearer_header(&self, credential_id: &str) -> Result<HttpHeader, EgressError> {
        let secret = self.hook.fetch(credential_id).map_err(|error| {
            EgressError::CredentialError(format!("secret fetch failed: {error}"))
        })?;
        let value = secret.with_bytes(|bytes| {
            std::str::from_utf8(bytes)
                .map(|token| format!("Bearer {token}"))
                .map_err(|_| {
                    EgressError::CredentialError(
                        "secret fetch returned non-UTF-8 bearer token".to_string(),
                    )
                })
        })?;
        Ok(HttpHeader {
            name: "Authorization".to_string(),
            value,
        })
    }
}

impl std::fmt::Debug for SecretFetchCredentialInjector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretFetchCredentialInjector")
            .field("hook", &"<SecretFetchHook>")
            .field("allowed_credentials", &self.allowed_hosts.len())
            .finish_non_exhaustive()
    }
}

impl CredentialInjector for SecretFetchCredentialInjector {
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

    fn is_host_allowed(&self, credential_id: &str, host: &str) -> Result<bool, EgressError> {
        Ok(self
            .allowed_hosts
            .get(credential_id)
            .is_some_and(|allowed| host_matches_allow_list(host, allowed)))
    }

    fn inject_http(
        &self,
        credential_id: &str,
        headers: &mut Vec<HttpHeader>,
    ) -> Result<(), EgressError> {
        let authorization = self.fetch_bearer_header(credential_id)?;
        headers.retain(|header| {
            !header.name.eq_ignore_ascii_case("authorization")
                && !header.name.eq_ignore_ascii_case("x-fcp-credential-id")
        });
        headers.push(authorization);
        Ok(())
    }

    fn get_tcp_auth(&self, credential_id: &str) -> Result<Option<Vec<u8>>, EgressError> {
        let secret = self.hook.fetch(credential_id).map_err(|error| {
            EgressError::CredentialError(format!("secret fetch failed: {error}"))
        })?;
        Ok(Some(secret.with_bytes(<[u8]>::to_vec)))
    }
}

/// No-op credential injector for testing or when credentials are disabled.
#[derive(Debug, Default)]
pub struct NoOpCredentialInjector;

impl CredentialInjector for NoOpCredentialInjector {
    fn is_authorized(
        &self,
        _credential_id: &str,
        _operation_id: &str,
        _credential_allow: &[String],
    ) -> Result<bool, EgressError> {
        Ok(false)
    }

    fn inject_http(
        &self,
        credential_id: &str,
        _headers: &mut Vec<HttpHeader>,
    ) -> Result<(), EgressError> {
        Err(EgressError::CredentialError(format!(
            "credential injection not available: {credential_id}"
        )))
    }

    fn get_tcp_auth(&self, credential_id: &str) -> Result<Option<Vec<u8>>, EgressError> {
        Err(EgressError::CredentialError(format!(
            "credential injection not available: {credential_id}"
        )))
    }
}

// ============================================================================
// TLS Verification
// ============================================================================

/// TLS verification hooks for the Network Guard.
pub trait TlsVerifier: Send + Sync {
    /// Verify SNI matches the expected hostname.
    ///
    /// # Errors
    ///
    /// Returns `EgressError::Denied` with `SniMismatch` if names don't match.
    fn verify_sni(&self, actual_sni: &str, expected_sni: &str) -> Result<(), EgressError>;

    /// Verify SPKI pin matches one of the expected pins.
    ///
    /// # Errors
    ///
    /// Returns `EgressError::Denied` with `SpkiPinMismatch` if no pin matches.
    fn verify_spki(&self, cert_spki: &[u8], expected_pins: &[Vec<u8>]) -> Result<(), EgressError>;
}

/// Default TLS verifier implementation.
#[derive(Debug, Default)]
pub struct DefaultTlsVerifier;

impl TlsVerifier for DefaultTlsVerifier {
    fn verify_sni(&self, actual_sni: &str, expected_sni: &str) -> Result<(), EgressError> {
        if actual_sni != expected_sni {
            return Err(EgressError::Denied {
                reason: format!("SNI mismatch: expected `{expected_sni}`, got `{actual_sni}`"),
                code: DenyReason::SniMismatch,
            });
        }
        Ok(())
    }

    fn verify_spki(&self, cert_spki: &[u8], expected_pins: &[Vec<u8>]) -> Result<(), EgressError> {
        if expected_pins.is_empty() {
            return Ok(());
        }

        // Use constant-time comparison to prevent timing side-channel attacks
        // that could leak SPKI pin values byte-by-byte.
        let mut matched = false;
        for pin in expected_pins {
            if pin.len() == cert_spki.len() {
                let mut diff = 0u8;
                for (a, b) in cert_spki.iter().zip(pin.iter()) {
                    diff |= a ^ b;
                }
                if diff == 0 {
                    matched = true;
                }
            }
        }

        if matched {
            Ok(())
        } else {
            Err(EgressError::Denied {
                reason: "SPKI pin verification failed: no matching pin".into(),
                code: DenyReason::SpkiPinMismatch,
            })
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    struct StaticSecretHook {
        credential_id: String,
        secret: Vec<u8>,
    }

    impl StaticSecretHook {
        fn new(credential_id: &str, secret: &[u8]) -> Self {
            Self {
                credential_id: credential_id.to_string(),
                secret: secret.to_vec(),
            }
        }
    }

    impl fcp_crypto::SecretFetchHook for StaticSecretHook {
        fn fetch(
            &self,
            credential_id: &str,
        ) -> Result<fcp_crypto::ZeroizingSecret, fcp_crypto::SecretFetchError> {
            if credential_id == self.credential_id {
                Ok(fcp_crypto::ZeroizingSecret::new(self.secret.clone()))
            } else {
                Err(fcp_crypto::SecretFetchError::not_found(credential_id))
            }
        }

        fn rotate(
            &self,
            _credential_id: &str,
            _new_secret: fcp_crypto::ZeroizingSecret,
        ) -> Result<(), fcp_crypto::SecretFetchError> {
            Err(fcp_crypto::SecretFetchError::redacted(
                "static test hook is read-only",
            ))
        }

        fn revoke(&self, _credential_id: &str) -> Result<(), fcp_crypto::SecretFetchError> {
            Err(fcp_crypto::SecretFetchError::redacted(
                "static test hook is read-only",
            ))
        }
    }

    // ------------------------------------------------------------------------
    // Hostname Canonicalization Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_canonicalize_lowercase() {
        assert_eq!(
            canonicalize_hostname("API.Example.COM").unwrap(),
            "api.example.com"
        );
    }

    #[test]
    fn test_canonicalize_trailing_dot() {
        assert_eq!(
            canonicalize_hostname("example.com.").unwrap(),
            "example.com"
        );
    }

    #[test]
    fn test_canonicalize_idna() {
        // Internationalized domain name
        assert_eq!(
            canonicalize_hostname("münchen.example.com").unwrap(),
            "xn--mnchen-3ya.example.com"
        );
    }

    #[test]
    fn test_canonicalize_emoji_domain() {
        // Emoji domains get Punycode encoded
        let result = canonicalize_hostname("🏠.example.com");
        assert!(result.is_ok());
        let canonical = result.unwrap();
        assert!(canonical.starts_with("xn--"));
        assert!(canonical.ends_with(".example.com"));
    }

    #[test]
    fn test_canonicalize_empty() {
        assert!(canonicalize_hostname("").is_err());
    }

    #[test]
    fn test_is_hostname_canonical() {
        assert!(is_hostname_canonical("api.example.com"));
        assert!(!is_hostname_canonical("API.example.com"));
        assert!(!is_hostname_canonical("example.com."));
        assert!(!is_hostname_canonical("münchen.example.com"));
    }

    // ------------------------------------------------------------------------
    // CIDR Check Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_is_localhost_ipv4() {
        assert!(is_localhost("127.0.0.1".parse().unwrap()));
        assert!(is_localhost("127.0.0.2".parse().unwrap()));
        assert!(is_localhost("127.255.255.255".parse().unwrap()));
        assert!(!is_localhost("128.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_is_localhost_ipv6() {
        assert!(is_localhost("::1".parse().unwrap()));
        assert!(!is_localhost("::2".parse().unwrap()));
    }

    #[test]
    fn test_is_localhost_ipv4_mapped_ipv6() {
        assert!(is_localhost("::ffff:127.0.0.1".parse().unwrap()));
        assert!(is_localhost("::ffff:7f00:1".parse().unwrap()));
    }

    #[test]
    fn test_is_private_range() {
        // RFC1918 ranges
        assert!(is_private_range("10.0.0.1".parse().unwrap()));
        assert!(is_private_range("10.255.255.255".parse().unwrap()));
        assert!(is_private_range("172.16.0.1".parse().unwrap()));
        assert!(is_private_range("172.31.255.255".parse().unwrap()));
        assert!(is_private_range("192.168.0.1".parse().unwrap()));
        assert!(is_private_range("192.168.255.255".parse().unwrap()));

        // Not private
        assert!(!is_private_range("8.8.8.8".parse().unwrap()));
        assert!(!is_private_range("172.32.0.1".parse().unwrap()));
    }

    #[test]
    fn test_is_private_range_ipv4_mapped_ipv6() {
        assert!(is_private_range("::ffff:10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_is_link_local() {
        assert!(is_link_local("169.254.0.1".parse().unwrap()));
        assert!(is_link_local("169.254.255.255".parse().unwrap()));
        assert!(!is_link_local("169.255.0.1".parse().unwrap()));

        // IPv6 link-local
        assert!(is_link_local("fe80::1".parse().unwrap()));
    }

    #[test]
    fn test_is_tailnet_range() {
        assert!(is_tailnet_range("100.64.0.1".parse().unwrap()));
        assert!(is_tailnet_range("100.127.255.255".parse().unwrap()));
        assert!(!is_tailnet_range("100.128.0.1".parse().unwrap()));
        assert!(!is_tailnet_range("100.63.255.255".parse().unwrap()));

        // IPv6 Tailscale range
        assert!(is_tailnet_range("fd7a:115c:a1e0::1".parse().unwrap()));
        assert!(is_tailnet_range("fd7a:115c:a1e0::ffff".parse().unwrap()));
        assert!(!is_tailnet_range("fd7a:115c:a1e1::1".parse().unwrap()));
    }

    // ------------------------------------------------------------------------
    // Egress Guard Tests
    // ------------------------------------------------------------------------

    fn test_constraints() -> NetworkConstraints {
        NetworkConstraints {
            host_allow: vec!["api.example.com".into(), "*.test.com".into()],
            port_allow: vec![443, 8443],
            ip_allow: vec![],
            cidr_deny: vec![],
            deny_localhost: true,
            deny_private_ranges: true,
            deny_tailnet_ranges: true,
            require_sni: true,
            spki_pins: vec![],
            deny_ip_literals: true,
            require_host_canonicalization: true,
            dns_max_ips: 16,
            max_redirects: 5,
            connect_timeout_ms: 10_000,
            total_timeout_ms: 60_000,
            max_response_bytes: 10_485_760,
        }
    }

    #[test]
    fn test_evaluate_allowed_host() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://api.example.com/v1/data".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        let decision = guard.evaluate(&request, &constraints).unwrap();
        assert!(decision.allowed);
        assert_eq!(decision.canonical_host, "api.example.com");
        assert_eq!(decision.port, 443);
        assert!(decision.tls_required);
    }

    #[test]
    fn test_evaluate_wildcard_host() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://sub.test.com:443/path".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        let decision = guard.evaluate(&request, &constraints).unwrap();
        assert!(decision.allowed);
        assert_eq!(decision.canonical_host, "sub.test.com");
    }

    #[test]
    fn test_evaluate_denied_host() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://evil.com/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        let result = guard.evaluate(&request, &constraints);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::HostNotAllowed);
        }
    }

    #[test]
    fn test_evaluate_denied_port() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://api.example.com:9999/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        let result = guard.evaluate(&request, &constraints);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::PortNotAllowed);
        }
    }

    #[test]
    fn test_evaluate_ip_literal_denied() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://93.184.216.34/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        let result = guard.evaluate(&request, &constraints);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::IpLiteralDenied);
        }
    }

    #[test]
    fn test_evaluate_ipv6_literal_denied() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://[2001:db8::1]/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        let result = guard.evaluate(&request, &constraints);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::IpLiteralDenied);
        }
    }

    #[test]
    fn test_check_ip_localhost_denied() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();

        let result = guard.check_ip_constraints("127.0.0.1".parse().unwrap(), &constraints);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::LocalhostDenied);
        }
    }

    #[test]
    fn test_check_ip_private_denied() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();

        let result = guard.check_ip_constraints("192.168.1.1".parse().unwrap(), &constraints);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::PrivateRangeDenied);
        }
    }

    #[test]
    fn test_check_ip_tailnet_denied() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();

        let result = guard.check_ip_constraints("100.100.100.100".parse().unwrap(), &constraints);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::TailnetRangeDenied);
        }
    }

    #[test]
    fn test_check_ip_public_allowed() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();

        let result = guard.check_ip_constraints("8.8.8.8".parse().unwrap(), &constraints);
        assert!(result.is_ok());
    }

    #[test]
    fn test_tcp_connect_evaluation() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();

        let request = EgressRequest::TcpConnect(EgressTcpConnectRequest {
            host: "api.example.com".into(),
            port: 443,
            tls: true,
            sni_override: None,
            credential_id: None,
        });

        let decision = guard.evaluate(&request, &constraints).unwrap();
        assert!(decision.allowed);
        assert_eq!(decision.canonical_host, "api.example.com");
        assert!(decision.tls_required);
    }

    #[test]
    fn test_dns_max_ips_exceeded() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.dns_max_ips = 2;

        let ips: Vec<IpAddr> = vec![
            "8.8.8.8".parse().unwrap(),
            "8.8.4.4".parse().unwrap(),
            "1.1.1.1".parse().unwrap(),
        ];

        let result = guard.validate_dns_resolution(&ips, &constraints);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::DnsMaxIpsExceeded);
        }
    }

    // ------------------------------------------------------------------------
    // TLS Verifier Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_sni_verification() {
        let verifier = DefaultTlsVerifier;

        assert!(verifier.verify_sni("example.com", "example.com").is_ok());
        assert!(verifier.verify_sni("other.com", "example.com").is_err());
    }

    #[test]
    fn test_spki_verification() {
        let verifier = DefaultTlsVerifier;

        let pin1 = vec![1, 2, 3, 4];
        let pin2 = vec![5, 6, 7, 8];
        let allowed_pins = vec![pin1.clone(), pin2.clone()];

        assert!(verifier.verify_spki(&pin1, &allowed_pins).is_ok());
        assert!(verifier.verify_spki(&pin2, &allowed_pins).is_ok());
        assert!(verifier.verify_spki(&[9, 10], &allowed_pins).is_err());

        // Empty pins should pass
        assert!(verifier.verify_spki(&[1, 2], &[]).is_ok());
    }

    // ── New tests ──

    #[test]
    fn test_egress_error_display() {
        let e = EgressError::Denied {
            reason: "bad host".into(),
            code: DenyReason::HostNotAllowed,
        };
        assert!(e.to_string().contains("bad host"));

        let e = EgressError::InvalidRequest("malformed".into());
        assert!(e.to_string().contains("malformed"));

        let e = EgressError::InvalidUrl("no scheme".into());
        assert!(e.to_string().contains("no scheme"));

        let e = EgressError::CanonicalizationFailed("punycode".into());
        assert!(e.to_string().contains("punycode"));

        let e = EgressError::DnsResolutionFailed("NXDOMAIN".into());
        assert!(e.to_string().contains("NXDOMAIN"));

        let e = EgressError::CredentialError("not found".into());
        assert!(e.to_string().contains("not found"));

        let e = EgressError::TlsVerificationFailed("expired cert".into());
        assert!(e.to_string().contains("expired cert"));
    }

    #[test]
    fn test_deny_reason_serde_roundtrip() {
        let reasons = [
            DenyReason::HostNotAllowed,
            DenyReason::PortNotAllowed,
            DenyReason::IpLiteralDenied,
            DenyReason::LocalhostDenied,
            DenyReason::PrivateRangeDenied,
            DenyReason::TailnetRangeDenied,
            DenyReason::LinkLocalDenied,
            DenyReason::CidrDenyMatched,
            DenyReason::SniMismatch,
            DenyReason::SpkiPinMismatch,
            DenyReason::CredentialNotAuthorized,
            DenyReason::CredentialHostNotAllowed,
            DenyReason::HostnameNotCanonical,
            DenyReason::DnsMaxIpsExceeded,
            DenyReason::MaxRedirectsExceeded,
        ];
        for reason in reasons {
            let json = serde_json::to_string(&reason).unwrap();
            let roundtrip: DenyReason = serde_json::from_str(&json).unwrap();
            assert_eq!(roundtrip, reason);
        }
    }

    #[test]
    fn test_secret_fetch_credential_injector_injects_bearer_and_strips_local_headers() {
        let injector = SecretFetchCredentialInjector::new(std::sync::Arc::new(
            StaticSecretHook::new("cred-1", b"secret-token"),
        ))
        .with_allowed_hosts("cred-1", ["api.example.com"]);
        let credential_allow = vec!["cred-1".to_string()];
        let mut headers = vec![
            HttpHeader {
                name: "Authorization".to_string(),
                value: "Bearer connector-supplied".to_string(),
            },
            HttpHeader {
                name: "x-fcp-credential-id".to_string(),
                value: "cred-1".to_string(),
            },
            HttpHeader {
                name: "x-request-id".to_string(),
                value: "req-1".to_string(),
            },
        ];

        assert!(
            injector
                .is_authorized("cred-1", "gmail.list_messages", &credential_allow)
                .unwrap()
        );
        assert!(
            injector
                .is_host_allowed("cred-1", "api.example.com")
                .unwrap()
        );

        injector.inject_http("cred-1", &mut headers).unwrap();

        assert!(headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("authorization")
                && header.value == "Bearer secret-token"
        }));
        assert!(headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("x-request-id") && header.value == "req-1"
        }));
        assert!(
            !headers
                .iter()
                .any(|header| header.name.eq_ignore_ascii_case("x-fcp-credential-id"))
        );
        assert!(!headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("authorization")
                && header.value == "Bearer connector-supplied"
        }));
        assert_eq!(
            injector.get_tcp_auth("cred-1").unwrap(),
            Some(b"secret-token".to_vec())
        );
    }

    #[test]
    fn test_secret_fetch_credential_injector_fails_closed_for_unbound_hosts() {
        let injector = SecretFetchCredentialInjector::new(std::sync::Arc::new(
            StaticSecretHook::new("cred-1", b"secret-token"),
        ))
        .with_allowed_hosts("cred-1", ["api.example.com"]);

        assert!(
            !injector
                .is_authorized("cred-2", "gmail.list_messages", &["cred-1".to_string()])
                .unwrap()
        );
        assert!(
            !injector
                .is_host_allowed("cred-1", "evil.example.com")
                .unwrap()
        );
        assert!(
            !injector
                .is_host_allowed("cred-2", "api.example.com")
                .unwrap()
        );
    }

    #[test]
    fn test_egress_request_http_serde() {
        let req = EgressRequest::Http(EgressHttpRequest {
            url: "https://api.example.com/data".into(),
            method: "POST".into(),
            headers: vec![HttpHeader {
                name: "Content-Type".into(),
                value: "application/json".into(),
            }],
            body: Some(b"{}".to_vec()),
            credential_id: Some("cred-1".into()),
        });
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"type\":\"http\""));
        let roundtrip: EgressRequest = serde_json::from_str(&json).unwrap();
        if let EgressRequest::Http(http) = roundtrip {
            assert_eq!(http.url, "https://api.example.com/data");
            assert_eq!(http.method, "POST");
            assert_eq!(http.headers.len(), 1);
            assert_eq!(http.credential_id, Some("cred-1".into()));
        } else {
            panic!("expected Http variant");
        }
    }

    #[test]
    fn test_egress_request_tcp_serde() {
        let req = EgressRequest::TcpConnect(EgressTcpConnectRequest {
            host: "db.example.com".into(),
            port: 5432,
            tls: true,
            sni_override: Some("db.example.com".into()),
            credential_id: None,
        });
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"type\":\"tcp_connect\""));
        let roundtrip: EgressRequest = serde_json::from_str(&json).unwrap();
        if let EgressRequest::TcpConnect(tcp) = roundtrip {
            assert_eq!(tcp.host, "db.example.com");
            assert_eq!(tcp.port, 5432);
            assert!(tcp.tls);
            assert_eq!(tcp.sni_override, Some("db.example.com".into()));
        } else {
            panic!("expected TcpConnect variant");
        }
    }

    #[test]
    fn test_egress_guard_default() {
        let guard = EgressGuard::default();
        // Just verify it can be constructed via Default
        let _ = format!("{guard:?}");
    }

    #[test]
    fn test_canonicalize_idempotent() {
        // Already canonical hostname should pass through unchanged
        let canonical = canonicalize_hostname("api.example.com").unwrap();
        let double = canonicalize_hostname(&canonical).unwrap();
        assert_eq!(canonical, double);
    }

    #[test]
    fn test_is_hostname_canonical_empty() {
        assert!(!is_hostname_canonical(""));
    }

    #[test]
    fn test_is_hostname_canonical_non_ascii() {
        assert!(!is_hostname_canonical("münchen.example.com"));
    }

    #[test]
    fn test_noop_credential_injector() {
        let injector = NoOpCredentialInjector;

        // is_authorized always returns false
        let result = injector
            .is_authorized("cred-1", "op-1", &["cred-1".into()])
            .unwrap();
        assert!(!result);

        // inject_http returns error
        let mut headers = vec![];
        let result = injector.inject_http("cred-1", &mut headers);
        assert!(result.is_err());

        // get_tcp_auth returns error
        let result = injector.get_tcp_auth("cred-1");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_dns_resolution_valid() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();

        let ips: Vec<IpAddr> = vec!["8.8.8.8".parse().unwrap(), "8.8.4.4".parse().unwrap()];
        let result = guard.validate_dns_resolution(&ips, &constraints);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 2);
    }

    #[test]
    fn test_validate_dns_resolution_contains_denied() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();

        let ips: Vec<IpAddr> = vec![
            "8.8.8.8".parse().unwrap(),
            "127.0.0.1".parse().unwrap(), // localhost - denied
        ];
        let result = guard.validate_dns_resolution(&ips, &constraints);
        assert!(result.is_err());
    }

    #[test]
    fn test_check_ip_link_local_denied() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();

        let result = guard.check_ip_constraints("169.254.1.1".parse().unwrap(), &constraints);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::LinkLocalDenied);
        }
    }

    #[test]
    fn test_check_ip_custom_cidr_deny() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.cidr_deny = vec!["203.0.113.0/24".into()]; // TEST-NET-3

        let result = guard.check_ip_constraints("203.0.113.42".parse().unwrap(), &constraints);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::CidrDenyMatched);
        }

        // IP outside that CIDR should pass
        let result = guard.check_ip_constraints("203.0.114.1".parse().unwrap(), &constraints);
        assert!(result.is_ok());
    }

    #[test]
    fn test_evaluate_non_canonical_host_allowed_when_not_required() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.require_host_canonicalization = false;
        constraints.host_allow = vec!["api.example.com".into()];
        constraints.deny_ip_literals = false;

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://API.EXAMPLE.COM:443/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        let decision = guard.evaluate(&request, &constraints).unwrap();
        assert!(decision.allowed);
        assert_eq!(decision.canonical_host, "api.example.com");
    }

    #[test]
    fn test_evaluate_tcp_denied_port() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();

        let request = EgressRequest::TcpConnect(EgressTcpConnectRequest {
            host: "api.example.com".into(),
            port: 9999, // Not in port_allow
            tls: false,
            sni_override: None,
            credential_id: None,
        });

        let result = guard.evaluate(&request, &constraints);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::PortNotAllowed);
        }
    }

    #[test]
    fn test_evaluate_sni_decision() {
        let guard = EgressGuard::new();
        let constraints = test_constraints(); // require_sni = true

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://api.example.com/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        let decision = guard.evaluate(&request, &constraints).unwrap();
        assert!(decision.tls_required);
        assert_eq!(decision.expected_sni, Some("api.example.com".into()));
    }

    #[test]
    fn test_evaluate_no_sni_when_not_required() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.require_sni = false;

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://api.example.com/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        let decision = guard.evaluate(&request, &constraints).unwrap();
        assert!(decision.tls_required);
        assert_eq!(decision.expected_sni, None);
    }

    #[test]
    fn test_evaluate_spki_pins_in_decision() {
        use fcp_manifest::Base64Bytes;
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.spki_pins = vec![
            Base64Bytes::try_from("base64:cGluMQ==".to_string()).unwrap(),
            Base64Bytes::try_from("base64:cGluMg==".to_string()).unwrap(),
        ];

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://api.example.com/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        let decision = guard.evaluate(&request, &constraints).unwrap();
        assert_eq!(decision.spki_pins.len(), 2);
    }

    #[test]
    fn test_evaluate_invalid_url() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "not-a-url".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        let result = guard.evaluate(&request, &constraints);
        assert!(matches!(result, Err(EgressError::InvalidUrl(_))));
    }

    #[test]
    fn test_wildcard_does_not_match_bare_domain() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.host_allow = vec!["*.test.com".into()];
        constraints.deny_ip_literals = false;

        // Bare domain "test.com" should NOT match "*.test.com"
        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://test.com:443/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        let result = guard.evaluate(&request, &constraints);
        assert!(result.is_err());
    }

    #[test]
    fn test_ip_literal_in_ip_allow() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.deny_ip_literals = false;
        constraints.ip_allow = vec!["93.184.216.34".parse().unwrap()];
        constraints.port_allow = vec![443];

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://93.184.216.34/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        let decision = guard.evaluate(&request, &constraints).unwrap();
        assert!(decision.allowed);
    }

    #[test]
    fn test_is_localhost_unspecified() {
        assert!(is_localhost("0.0.0.0".parse().unwrap()));
    }

    #[test]
    fn test_is_private_range_ipv6_ula() {
        assert!(is_private_range("fd12:3456:789a::1".parse().unwrap()));
    }

    #[test]
    fn test_is_link_local_ipv6() {
        assert!(is_link_local("fe80::1".parse().unwrap()));
    }

    #[test]
    fn test_sni_verification_deny_code() {
        let verifier = DefaultTlsVerifier;
        let result = verifier.verify_sni("wrong.com", "expected.com");
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::SniMismatch);
        } else {
            panic!("expected Denied error");
        }
    }

    #[test]
    fn test_spki_verification_deny_code() {
        let verifier = DefaultTlsVerifier;
        let pins = vec![vec![1, 2, 3]];
        let result = verifier.verify_spki(&[4, 5, 6], &pins);
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::SpkiPinMismatch);
        } else {
            panic!("expected Denied error");
        }
    }

    #[test]
    fn test_http_header_serde() {
        let header = HttpHeader {
            name: "Authorization".into(),
            value: "Bearer token".into(),
        };
        let json = serde_json::to_string(&header).unwrap();
        let roundtrip: HttpHeader = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.name, "Authorization");
        assert_eq!(roundtrip.value, "Bearer token");
    }

    #[test]
    fn test_tcp_connect_defaults() {
        let json = r#"{"host":"db.example.com","port":5432}"#;
        let req: EgressTcpConnectRequest = serde_json::from_str(json).unwrap();
        assert!(!req.tls); // default false
        assert!(req.sni_override.is_none());
        assert!(req.credential_id.is_none());
    }

    // === canonicalize_host_pattern ===

    #[test]
    fn test_canonicalize_host_pattern_exact() {
        let pat = canonicalize_host_pattern("API.Example.COM").unwrap();
        assert_eq!(pat, "api.example.com");
    }

    #[test]
    fn test_canonicalize_host_pattern_wildcard() {
        let pat = canonicalize_host_pattern("*.API.Example.COM").unwrap();
        assert_eq!(pat, "*.api.example.com");
    }

    #[test]
    fn test_canonicalize_host_pattern_ip_literal() {
        let pat = canonicalize_host_pattern("10.0.0.1").unwrap();
        assert_eq!(pat, "10.0.0.1");
    }

    #[test]
    fn test_canonicalize_host_pattern_empty() {
        assert!(canonicalize_host_pattern("").is_none());
    }

    // === check_ip_constraints: deny flags disabled ===

    #[test]
    fn test_check_ip_localhost_allowed_when_deny_disabled() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.deny_localhost = false;
        let result = guard.check_ip_constraints("127.0.0.1".parse().unwrap(), &constraints);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_ip_private_allowed_when_deny_disabled() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.deny_private_ranges = false;
        let result = guard.check_ip_constraints("192.168.1.1".parse().unwrap(), &constraints);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_ip_tailnet_allowed_when_deny_disabled() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.deny_tailnet_ranges = false;
        let result = guard.check_ip_constraints("100.100.100.100".parse().unwrap(), &constraints);
        assert!(result.is_ok());
    }

    // === IPv4-mapped IPv6 CIDR bypass prevention ===

    #[test]
    fn test_check_ip_cidr_deny_ipv4_mapped_ipv6() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.deny_localhost = false;
        constraints.deny_private_ranges = false;
        constraints.cidr_deny = vec!["203.0.113.0/24".into()];

        // IPv4-mapped IPv6 should be normalized and matched
        let result =
            guard.check_ip_constraints("::ffff:203.0.113.42".parse().unwrap(), &constraints);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::CidrDenyMatched);
        }
    }

    // === validate_dns_resolution edge cases ===

    #[test]
    fn test_validate_dns_resolution_empty() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();
        let result = guard.validate_dns_resolution(&[], &constraints);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_validate_dns_resolution_exactly_at_limit() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.dns_max_ips = 2;
        let ips: Vec<IpAddr> = vec!["8.8.8.8".parse().unwrap(), "8.8.4.4".parse().unwrap()];
        let result = guard.validate_dns_resolution(&ips, &constraints);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 2);
    }

    // === EgressDecision field defaults ===

    #[test]
    fn test_egress_decision_fields() {
        let d = EgressDecision {
            allowed: true,
            canonical_host: "example.com".into(),
            resolved_ips: vec!["1.2.3.4".parse().unwrap()],
            port: 443,
            tls_required: true,
            expected_sni: Some("example.com".into()),
            spki_pins: vec![vec![1, 2, 3]],
            credential_injected: false,
        };
        assert!(d.allowed);
        assert_eq!(d.resolved_ips.len(), 1);
        assert!(!d.credential_injected);
    }

    #[test]
    fn test_egress_tcp_decision_fields() {
        let d = EgressTcpDecision {
            decision: EgressDecision {
                allowed: true,
                canonical_host: "db.test".into(),
                resolved_ips: vec![],
                port: 5432,
                tls_required: false,
                expected_sni: None,
                spki_pins: vec![],
                credential_injected: true,
            },
            tcp_auth: Some(b"AUTH bytes".to_vec()),
        };
        assert!(d.decision.credential_injected);
        assert!(d.tcp_auth.is_some());
    }

    // === HTTP no host URL ===

    #[test]
    fn test_evaluate_url_no_host() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();
        let request = EgressRequest::Http(EgressHttpRequest {
            url: "file:///etc/passwd".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });
        let result = guard.evaluate(&request, &constraints);
        assert!(matches!(result, Err(EgressError::InvalidUrl(_))));
    }

    // === HTTP port 80 from http:// scheme ===

    #[test]
    fn test_evaluate_http_scheme_port_80() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.port_allow = vec![80, 443];
        constraints.require_sni = false;
        let request = EgressRequest::Http(EgressHttpRequest {
            url: "http://api.example.com/data".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });
        let decision = guard.evaluate(&request, &constraints).unwrap();
        assert_eq!(decision.port, 80);
        assert!(!decision.tls_required);
    }

    // === Non-canonical host rejected when required ===

    #[test]
    fn test_evaluate_non_canonical_host_rejected() {
        // Use TCP path to bypass URL parser normalization (URL parser lowercases hosts)
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.require_host_canonicalization = true;
        constraints.deny_ip_literals = false;
        constraints.host_allow = vec!["api.example.com".into()];

        let request = EgressRequest::TcpConnect(EgressTcpConnectRequest {
            host: "API.EXAMPLE.COM".into(),
            port: 443,
            tls: true,
            sni_override: None,
            credential_id: None,
        });
        let result = guard.evaluate(&request, &constraints);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::HostnameNotCanonical);
        }
    }

    // === TCP connect without TLS ===

    #[test]
    fn test_tcp_connect_no_tls() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.require_sni = false;
        let request = EgressRequest::TcpConnect(EgressTcpConnectRequest {
            host: "api.example.com".into(),
            port: 443,
            tls: false,
            sni_override: None,
            credential_id: None,
        });
        let decision = guard.evaluate(&request, &constraints).unwrap();
        assert!(!decision.tls_required);
        assert!(decision.expected_sni.is_none());
    }

    // === authorize_http with mock injector ===

    struct MockInjector {
        authorized: bool,
        host_allowed: bool,
    }

    impl CredentialInjector for MockInjector {
        fn is_authorized(
            &self,
            _cred: &str,
            _op: &str,
            _allow: &[String],
        ) -> Result<bool, EgressError> {
            Ok(self.authorized)
        }

        fn is_host_allowed(&self, _cred: &str, _host: &str) -> Result<bool, EgressError> {
            Ok(self.host_allowed)
        }

        fn inject_http(
            &self,
            _cred: &str,
            headers: &mut Vec<HttpHeader>,
        ) -> Result<(), EgressError> {
            headers.push(HttpHeader {
                name: "Authorization".into(),
                value: "Bearer mock-token".into(),
            });
            Ok(())
        }

        fn get_tcp_auth(&self, _cred: &str) -> Result<Option<Vec<u8>>, EgressError> {
            Ok(Some(b"mock-auth".to_vec()))
        }
    }

    struct HostlessInjector;

    impl CredentialInjector for HostlessInjector {
        fn is_authorized(
            &self,
            _cred: &str,
            _op: &str,
            _allow: &[String],
        ) -> Result<bool, EgressError> {
            Ok(true)
        }

        fn inject_http(
            &self,
            _cred: &str,
            headers: &mut Vec<HttpHeader>,
        ) -> Result<(), EgressError> {
            headers.push(HttpHeader {
                name: "Authorization".into(),
                value: "Bearer hostless-token".into(),
            });
            Ok(())
        }

        fn get_tcp_auth(&self, _cred: &str) -> Result<Option<Vec<u8>>, EgressError> {
            Ok(Some(b"hostless-auth".to_vec()))
        }
    }

    struct RequestAwareInjector {
        host_allowed: bool,
        fail_signing: bool,
        calls: AtomicUsize,
    }

    impl RequestAwareInjector {
        const fn new(host_allowed: bool, fail_signing: bool) -> Self {
            Self {
                host_allowed,
                fail_signing,
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl CredentialInjector for RequestAwareInjector {
        fn is_authorized(
            &self,
            credential_id: &str,
            operation_id: &str,
            credential_allow: &[String],
        ) -> Result<bool, EgressError> {
            Ok(operation_id == "op" && credential_allow.iter().any(|id| id == credential_id))
        }

        fn is_host_allowed(&self, _credential_id: &str, _host: &str) -> Result<bool, EgressError> {
            Ok(self.host_allowed)
        }

        fn inject_http(
            &self,
            _credential_id: &str,
            _headers: &mut Vec<HttpHeader>,
        ) -> Result<(), EgressError> {
            Err(EgressError::CredentialError(
                "signing requires the complete request".into(),
            ))
        }

        fn inject_http_request(
            &self,
            credential_id: &str,
            request: &EgressHttpRequest,
        ) -> Result<Vec<HttpHeader>, EgressError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(credential_id, "cred-1");
            assert_eq!(request.credential_id.as_deref(), Some(credential_id));
            assert_eq!(request.method, "POST");
            assert_eq!(
                request.url,
                "https://api.example.com/messages?mode=send%20message&part=2"
            );
            assert_eq!(request.body.as_deref(), Some([0, 255, 1, 2].as_slice()));
            assert_eq!(request.headers.len(), 1);
            assert_eq!(request.headers[0].name, "Content-Type");
            assert_eq!(request.headers[0].value, "application/octet-stream");
            if self.fail_signing {
                return Err(EgressError::CredentialError(
                    "request signing failed".into(),
                ));
            }
            let mut headers = request.headers.clone();
            headers.push(HttpHeader {
                name: "Authorization".into(),
                value: "request-signature".into(),
            });
            Ok(headers)
        }

        fn get_tcp_auth(&self, _credential_id: &str) -> Result<Option<Vec<u8>>, EgressError> {
            Ok(None)
        }
    }

    fn request_for_signing() -> EgressHttpRequest {
        EgressHttpRequest {
            url: "https://api.example.com/messages?mode=send%20message&part=2".into(),
            method: "POST".into(),
            headers: vec![HttpHeader {
                name: "Content-Type".into(),
                value: "application/octet-stream".into(),
            }],
            body: Some(vec![0, 255, 1, 2]),
            credential_id: Some("cred-1".into()),
        }
    }

    #[test]
    fn test_authorize_http_signer_receives_original_request_context() {
        let guard = EgressGuard::new();
        let injector = RequestAwareInjector::new(true, false);
        let mut request = request_for_signing();
        let body_ptr = request.body.as_ref().unwrap().as_ptr();
        let url_ptr = request.url.as_ptr();

        let decision = guard
            .authorize_http(
                &mut request,
                &test_constraints(),
                &injector,
                "op",
                &["cred-1".into()],
            )
            .expect("request-aware signing should succeed");

        assert!(decision.credential_injected);
        assert_eq!(injector.calls.load(Ordering::SeqCst), 1);
        assert_eq!(request.body.as_ref().unwrap().as_ptr(), body_ptr);
        assert_eq!(request.url.as_ptr(), url_ptr);
        assert_eq!(request.headers[1].value, "request-signature");
        assert_eq!(request.credential_id.as_deref(), Some("cred-1"));
    }

    #[test]
    fn test_authorize_http_signer_is_not_called_after_policy_or_credential_denial() {
        let guard = EgressGuard::new();
        for (network_allowed, credential_allowed, host_allowed, expected_reason) in [
            (false, true, true, DenyReason::HostNotAllowed),
            (true, false, true, DenyReason::CredentialNotAuthorized),
            (true, true, false, DenyReason::CredentialHostNotAllowed),
        ] {
            let injector = RequestAwareInjector::new(host_allowed, false);
            let mut request = request_for_signing();
            let mut constraints = test_constraints();
            if !network_allowed {
                constraints.host_allow = vec!["other.example.com".into()];
            }
            let credential_allow = if credential_allowed {
                vec!["cred-1".into()]
            } else {
                vec![]
            };

            let error = guard
                .authorize_http(
                    &mut request,
                    &constraints,
                    &injector,
                    "op",
                    &credential_allow,
                )
                .expect_err("denied request must never reach the signer");

            assert!(matches!(error, EgressError::Denied { code, .. } if code == expected_reason));
            assert_eq!(injector.calls.load(Ordering::SeqCst), 0);
            assert_eq!(request.headers.len(), 1);
            assert_eq!(request.credential_id.as_deref(), Some("cred-1"));
        }
    }

    #[test]
    fn test_authorize_http_allow_all_hosts_preserves_request_aware_signing() {
        let guard = EgressGuard::new();
        let injector = AllowAllHosts::new(RequestAwareInjector::new(false, false));
        let mut request = request_for_signing();
        let body_ptr = request.body.as_ref().unwrap().as_ptr();
        let url_ptr = request.url.as_ptr();

        let decision = guard
            .authorize_http(
                &mut request,
                &test_constraints(),
                &injector,
                "op",
                &["cred-1".into()],
            )
            .expect("host wrapper must forward the complete request to the signer");

        assert!(decision.credential_injected);
        assert_eq!(injector.inner().calls.load(Ordering::SeqCst), 1);
        assert_eq!(request.body.as_ref().unwrap().as_ptr(), body_ptr);
        assert_eq!(request.body.as_deref(), Some([0, 255, 1, 2].as_slice()));
        assert_eq!(request.url.as_ptr(), url_ptr);
        assert_eq!(
            request.url,
            "https://api.example.com/messages?mode=send%20message&part=2"
        );
        assert_eq!(request.method, "POST");
        assert_eq!(request.headers[1].value, "request-signature");
    }

    #[test]
    fn test_authorize_http_propagates_request_signing_failure() {
        let guard = EgressGuard::new();
        let injector = RequestAwareInjector::new(true, true);
        let mut request = request_for_signing();

        let error = guard
            .authorize_http(
                &mut request,
                &test_constraints(),
                &injector,
                "op",
                &["cred-1".into()],
            )
            .expect_err("a signing failure must prevent authorization");

        assert!(matches!(error, EgressError::CredentialError(_)));
        assert_eq!(injector.calls.load(Ordering::SeqCst), 1);
        assert_eq!(request.headers.len(), 1);
        assert_eq!(request.credential_id.as_deref(), Some("cred-1"));
    }

    #[test]
    fn test_authorize_http_no_credential() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();
        let injector = MockInjector {
            authorized: true,
            host_allowed: true,
        };

        let mut req = EgressHttpRequest {
            url: "https://api.example.com/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        };

        let decision = guard
            .authorize_http(&mut req, &constraints, &injector, "op", &[])
            .unwrap();
        assert!(!decision.credential_injected);
    }

    #[test]
    fn test_authorize_http_credential_injected() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();
        let injector = MockInjector {
            authorized: true,
            host_allowed: true,
        };

        let mut req = EgressHttpRequest {
            url: "https://api.example.com/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: Some("cred-1".into()),
        };

        let decision = guard
            .authorize_http(&mut req, &constraints, &injector, "op", &["cred-1".into()])
            .unwrap();
        assert!(decision.credential_injected);
        assert!(req.headers.iter().any(|h| h.name == "Authorization"));
    }

    #[test]
    fn test_authorize_http_hostless_credential_injector_denies_all_hosts_by_default() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.host_allow = vec!["*".into()];
        let injector = HostlessInjector;

        for host in ["api.example.com", "service.test.com", "other.example.net"] {
            let mut req = EgressHttpRequest {
                url: format!("https://{host}/"),
                method: "GET".into(),
                headers: vec![],
                body: None,
                credential_id: Some("cred-1".into()),
            };

            let result =
                guard.authorize_http(&mut req, &constraints, &injector, "op", &["cred-1".into()]);
            assert!(result.is_err(), "hostless injector must reject {host}");
            if let Err(EgressError::Denied { code, .. }) = result {
                assert_eq!(code, DenyReason::CredentialHostNotAllowed);
            }
            assert!(
                req.headers.is_empty(),
                "credential headers must not be injected after host denial for {host}"
            );
        }
    }

    #[test]
    fn test_authorize_http_allow_all_hosts_wrapper_is_explicit_opt_in() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.host_allow = vec!["*".into()];
        let injector = AllowAllHosts::new(HostlessInjector);

        let mut req = EgressHttpRequest {
            url: "https://other.example.net/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: Some("cred-1".into()),
        };

        let decision = guard
            .authorize_http(&mut req, &constraints, &injector, "op", &["cred-1".into()])
            .expect("AllowAllHosts wrapper must opt into host-unbound credentials");
        assert!(decision.credential_injected);
        assert!(req.headers.iter().any(|h| h.name == "Authorization"));
    }

    // br-z2tbh: authorize_http must not clone the request body or any
    // other caller-owned field; it takes &mut EgressHttpRequest and the
    // body must stay in place. Test: construct a request with a
    // recognizable 1 MiB body, authorize it, assert the body's address
    // is unchanged and its length still 1 MiB (a clone would copy into
    // a fresh allocation, changing the pointer).
    #[test]
    fn test_authorize_http_preserves_body_in_place_no_clone() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();
        let injector = MockInjector {
            authorized: true,
            host_allowed: true,
        };

        let body: Vec<u8> = (0..1_048_576_u32).map(|i| (i & 0xFF) as u8).collect();
        let body_ptr_before = body.as_ptr();
        let body_len_before = body.len();

        let mut req = EgressHttpRequest {
            url: "https://api.example.com/data".into(),
            method: "POST".into(),
            headers: vec![],
            body: Some(body),
            credential_id: Some("cred-1".into()),
        };

        guard
            .authorize_http(&mut req, &constraints, &injector, "op", &["cred-1".into()])
            .expect("authorize should succeed");
        let body_after = req.body.as_ref().expect("body still present");
        assert_eq!(body_after.len(), body_len_before, "body len preserved");
        assert_eq!(
            body_after.as_ptr(),
            body_ptr_before,
            "authorize_http must NOT reallocate the body (br-z2tbh regression)"
        );
    }

    #[test]
    fn test_authorize_tcp_evaluates_without_cloning_request() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();
        let injector = MockInjector {
            authorized: true,
            host_allowed: true,
        };
        let req = EgressTcpConnectRequest {
            host: "api.example.com".into(),
            port: 443,
            tls: false,
            sni_override: None,
            credential_id: None,
        };
        // We can't observe "no clone" structurally for TCP (small
        // struct), but we can at least pin that the call path is the
        // direct evaluate_tcp one: authorize_tcp returns Ok without
        // panic and emits canonical_host matching the request host.
        let decision = guard
            .authorize_tcp(&req, &constraints, &injector, "op", &[])
            .expect("authorize_tcp must succeed on canonical input");
        assert_eq!(decision.decision.canonical_host, "api.example.com");
    }

    #[test]
    fn test_authorize_http_credential_not_authorized() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();
        let injector = MockInjector {
            authorized: false,
            host_allowed: true,
        };

        let mut req = EgressHttpRequest {
            url: "https://api.example.com/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: Some("cred-1".into()),
        };

        let result =
            guard.authorize_http(&mut req, &constraints, &injector, "op", &["cred-1".into()]);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::CredentialNotAuthorized);
        }
    }

    #[test]
    fn test_authorize_http_credential_host_not_allowed() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();
        let injector = MockInjector {
            authorized: true,
            host_allowed: false,
        };

        let mut req = EgressHttpRequest {
            url: "https://api.example.com/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: Some("cred-1".into()),
        };

        let result =
            guard.authorize_http(&mut req, &constraints, &injector, "op", &["cred-1".into()]);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::CredentialHostNotAllowed);
        }
    }

    // === authorize_tcp ===

    #[test]
    fn test_authorize_tcp_no_credential() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();
        let injector = MockInjector {
            authorized: true,
            host_allowed: true,
        };

        let req = EgressTcpConnectRequest {
            host: "api.example.com".into(),
            port: 443,
            tls: true,
            sni_override: None,
            credential_id: None,
        };

        let result = guard
            .authorize_tcp(&req, &constraints, &injector, "op", &[])
            .unwrap();
        assert!(result.tcp_auth.is_none());
        assert!(!result.decision.credential_injected);
    }

    #[test]
    fn test_authorize_tcp_with_credential() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();
        let injector = MockInjector {
            authorized: true,
            host_allowed: true,
        };

        let req = EgressTcpConnectRequest {
            host: "api.example.com".into(),
            port: 443,
            tls: true,
            sni_override: None,
            credential_id: Some("cred-1".into()),
        };

        let result = guard
            .authorize_tcp(&req, &constraints, &injector, "op", &["cred-1".into()])
            .unwrap();
        assert!(result.tcp_auth.is_some());
        assert!(result.decision.credential_injected);
    }

    #[test]
    fn test_authorize_tcp_credential_denied() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();
        let injector = MockInjector {
            authorized: false,
            host_allowed: true,
        };

        let req = EgressTcpConnectRequest {
            host: "api.example.com".into(),
            port: 443,
            tls: true,
            sni_override: None,
            credential_id: Some("cred-1".into()),
        };

        let result = guard.authorize_tcp(&req, &constraints, &injector, "op", &["cred-1".into()]);
        assert!(result.is_err());
    }

    // ── Security regression: constant-time SPKI comparison (1fcd949) ──

    #[test]
    fn test_spki_constant_time_match_first_pin() {
        let verifier = DefaultTlsVerifier;
        let pin1 = vec![0xAA; 32];
        let pin2 = vec![0xBB; 32];
        // Match against first pin
        assert!(verifier.verify_spki(&pin1, &[pin1.clone(), pin2]).is_ok());
    }

    #[test]
    fn test_spki_constant_time_match_last_pin() {
        let verifier = DefaultTlsVerifier;
        let pin1 = vec![0xAA; 32];
        let pin2 = vec![0xBB; 32];
        // Match against last pin — should still succeed (no early return)
        assert!(verifier.verify_spki(&pin2, &[pin1, pin2.clone()]).is_ok());
    }

    #[test]
    fn test_spki_no_match_different_content() {
        let verifier = DefaultTlsVerifier;
        let pin = vec![0xAA; 32];
        let cert = vec![0xCC; 32];
        let result = verifier.verify_spki(&cert, &[pin]);
        assert!(result.is_err());
    }

    #[test]
    fn test_spki_no_match_different_length() {
        let verifier = DefaultTlsVerifier;
        // Length mismatch should fail — the constant-time loop only runs
        // when lengths match, but the overall result must still deny.
        let pin = vec![0xAA; 32];
        let cert = vec![0xAA; 16]; // same prefix but shorter
        let result = verifier.verify_spki(&cert, &[pin]);
        assert!(result.is_err());
    }

    #[test]
    fn test_spki_empty_pins_allows_all() {
        let verifier = DefaultTlsVerifier;
        // Empty pin list means no pinning is configured → allow
        assert!(verifier.verify_spki(&[1, 2, 3], &[]).is_ok());
    }

    #[test]
    fn test_spki_single_byte_difference() {
        let verifier = DefaultTlsVerifier;
        let pin = vec![0x00; 32];
        let mut cert = vec![0x00; 32];
        // Differ only in the last byte — constant-time comparison must
        // still evaluate all bytes and reject.
        cert[31] = 0x01;
        let result = verifier.verify_spki(&cert, &[pin]);
        assert!(result.is_err());
    }

    // ── EgressError display ────────────────────────────────────────────

    #[test]
    fn test_egress_error_denied_display() {
        let err = EgressError::Denied {
            reason: "host not allowed".into(),
            code: DenyReason::HostNotAllowed,
        };
        assert!(err.to_string().contains("host not allowed"));
    }

    #[test]
    fn test_egress_error_all_variants_display() {
        let errors: Vec<EgressError> = vec![
            EgressError::InvalidRequest("bad".into()),
            EgressError::InvalidUrl("http://".into()),
            EgressError::CanonicalizationFailed("failed".into()),
            EgressError::DnsResolutionFailed("timeout".into()),
            EgressError::CredentialError("not found".into()),
            EgressError::TlsVerificationFailed("cert mismatch".into()),
        ];
        for err in &errors {
            assert!(!err.to_string().is_empty());
        }
    }

    // ── DenyReason serde roundtrip (all variants) ──────────────────────

    #[test]
    fn test_deny_reason_serde_all_variants() {
        let reasons = [
            DenyReason::HostNotAllowed,
            DenyReason::PortNotAllowed,
            DenyReason::IpLiteralDenied,
            DenyReason::LocalhostDenied,
            DenyReason::PrivateRangeDenied,
            DenyReason::TailnetRangeDenied,
            DenyReason::LinkLocalDenied,
            DenyReason::CidrDenyMatched,
            DenyReason::SniMismatch,
            DenyReason::SpkiPinMismatch,
            DenyReason::CredentialNotAuthorized,
            DenyReason::CredentialHostNotAllowed,
            DenyReason::HostnameNotCanonical,
            DenyReason::DnsMaxIpsExceeded,
            DenyReason::MaxRedirectsExceeded,
        ];
        for reason in reasons {
            let json = serde_json::to_string(&reason).unwrap();
            let deserialized: DenyReason = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, reason);
        }
    }

    #[test]
    fn test_deny_reason_snake_case_names() {
        assert_eq!(
            serde_json::to_string(&DenyReason::HostNotAllowed).unwrap(),
            "\"host_not_allowed\""
        );
        assert_eq!(
            serde_json::to_string(&DenyReason::IpLiteralDenied).unwrap(),
            "\"ip_literal_denied\""
        );
        assert_eq!(
            serde_json::to_string(&DenyReason::DnsMaxIpsExceeded).unwrap(),
            "\"dns_max_ips_exceeded\""
        );
    }

    // ── EgressRequest serde ────────────────────────────────────────────

    #[test]
    fn test_egress_request_http_serde_roundtrip() {
        let req = EgressRequest::Http(EgressHttpRequest {
            url: "https://api.example.com/data".into(),
            method: "GET".into(),
            headers: vec![HttpHeader {
                name: "Accept".into(),
                value: "application/json".into(),
            }],
            body: None,
            credential_id: None,
        });
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: EgressRequest = serde_json::from_str(&json).unwrap();
        match deserialized {
            EgressRequest::Http(http) => {
                assert_eq!(http.url, "https://api.example.com/data");
                assert_eq!(http.method, "GET");
                assert_eq!(http.headers.len(), 1);
                assert!(http.body.is_none());
            }
            EgressRequest::TcpConnect(_) => panic!("expected Http variant"),
        }
    }

    #[test]
    fn test_egress_request_tcp_serde_roundtrip() {
        let req = EgressRequest::TcpConnect(EgressTcpConnectRequest {
            host: "db.example.com".into(),
            port: 5432,
            tls: true,
            sni_override: Some("custom-sni.example.com".into()),
            credential_id: Some("pg-cred".into()),
        });
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: EgressRequest = serde_json::from_str(&json).unwrap();
        match deserialized {
            EgressRequest::TcpConnect(tcp) => {
                assert_eq!(tcp.host, "db.example.com");
                assert_eq!(tcp.port, 5432);
                assert!(tcp.tls);
                assert_eq!(tcp.sni_override.as_deref(), Some("custom-sni.example.com"));
                assert_eq!(tcp.credential_id.as_deref(), Some("pg-cred"));
            }
            EgressRequest::Http(_) => panic!("expected TcpConnect variant"),
        }
    }

    #[test]
    fn test_egress_http_request_with_body() {
        let req = EgressHttpRequest {
            url: "https://api.example.com/upload".into(),
            method: "POST".into(),
            headers: vec![],
            body: Some(vec![1, 2, 3, 4]),
            credential_id: Some("upload-key".into()),
        };
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: EgressHttpRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.body, Some(vec![1, 2, 3, 4]));
        assert_eq!(deserialized.credential_id.as_deref(), Some("upload-key"));
    }

    // ── IP range classification ────────────────────────────────────────

    #[test]
    fn test_is_localhost_ipv4_boundary() {
        assert!(is_localhost("127.0.0.1".parse().unwrap()));
        assert!(is_localhost("127.255.255.255".parse().unwrap()));
        assert!(!is_localhost("128.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_is_localhost_ipv6_loopback() {
        assert!(is_localhost("::1".parse().unwrap()));
        assert!(!is_localhost("::2".parse().unwrap()));
    }

    #[test]
    fn test_is_private_range_ipv4() {
        assert!(is_private_range("10.0.0.1".parse().unwrap()));
        assert!(is_private_range("172.16.0.1".parse().unwrap()));
        assert!(is_private_range("192.168.1.1".parse().unwrap()));
        assert!(!is_private_range("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_is_private_range_ipv6_ula_fc_fd() {
        assert!(is_private_range("fc00::1".parse().unwrap()));
        assert!(is_private_range("fd12:3456::1".parse().unwrap()));
        assert!(!is_private_range("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn test_is_link_local_ipv4_boundary() {
        assert!(is_link_local("169.254.0.1".parse().unwrap()));
        assert!(is_link_local("169.254.255.255".parse().unwrap()));
        assert!(!is_link_local("169.255.0.1".parse().unwrap()));
    }

    #[test]
    fn test_is_link_local_ipv6_fe80() {
        assert!(is_link_local("fe80::1".parse().unwrap()));
        assert!(!is_link_local("fe00::1".parse().unwrap()));
    }

    #[test]
    fn test_is_tailnet_range_boundaries() {
        assert!(is_tailnet_range("100.64.0.1".parse().unwrap()));
        assert!(is_tailnet_range("100.127.255.255".parse().unwrap()));
        assert!(!is_tailnet_range("100.128.0.1".parse().unwrap()));
        assert!(!is_tailnet_range("100.63.255.255".parse().unwrap()));
    }

    // ── canonicalize_host_pattern ──────────────────────────────────────

    #[test]
    fn test_canonicalize_host_pattern_empty_returns_none() {
        assert_eq!(canonicalize_host_pattern(""), None);
    }

    #[test]
    fn test_canonicalize_host_pattern_star() {
        assert_eq!(canonicalize_host_pattern("*"), Some("*".into()));
    }

    #[test]
    fn test_canonicalize_host_pattern_wildcard_lowercased() {
        assert_eq!(
            canonicalize_host_pattern("*.Example.COM"),
            Some("*.example.com".into())
        );
    }

    #[test]
    fn test_canonicalize_host_pattern_plain() {
        assert_eq!(
            canonicalize_host_pattern("API.Example.COM"),
            Some("api.example.com".into())
        );
    }

    #[test]
    fn test_canonicalize_host_pattern_ip_literal_passthrough() {
        assert_eq!(
            canonicalize_host_pattern("192.168.1.1"),
            Some("192.168.1.1".into())
        );
    }

    // ── is_hostname_canonical ──────────────────────────────────────────

    #[test]
    fn test_is_hostname_canonical_valid() {
        assert!(is_hostname_canonical("api.example.com"));
        assert!(is_hostname_canonical("a.b.c"));
    }

    #[test]
    fn test_is_hostname_canonical_empty_string() {
        assert!(!is_hostname_canonical(""));
    }

    #[test]
    fn test_is_hostname_canonical_trailing_dot() {
        assert!(!is_hostname_canonical("example.com."));
    }

    #[test]
    fn test_is_hostname_canonical_uppercase() {
        assert!(!is_hostname_canonical("API.Example.com"));
    }

    #[test]
    fn test_is_hostname_canonical_non_ascii_rejected() {
        assert!(!is_hostname_canonical("例え.jp"));
    }

    // ── SandboxError display ───────────────────────────────────────────

    #[test]
    fn test_sandbox_error_variants() {
        use crate::SandboxError;

        let errors: Vec<SandboxError> = vec![
            SandboxError::UnsupportedPlatform("plan9".into()),
            SandboxError::PolicyCompilationFailed("bad policy".into()),
            SandboxError::ApplyFailed("denied".into()),
            SandboxError::ResourceLimitExceeded("memory".into()),
            SandboxError::InvalidConfig("missing field".into()),
            SandboxError::SyscallFailed("seccomp".into()),
            SandboxError::Timeout,
        ];
        for err in &errors {
            assert!(!err.to_string().is_empty());
        }
        assert!(errors[0].to_string().contains("plan9"));
        assert!(errors[6].to_string().contains("timeout"));
    }

    // ── EgressGuard constructor ────────────────────────────────────────

    #[test]
    fn test_egress_guard_new() {
        let _guard = EgressGuard::new();
        let _guard2 = EgressGuard::default();
    }

    // ── HttpHeader serde ───────────────────────────────────────────────

    #[test]
    fn test_http_header_serde_roundtrip() {
        let header = HttpHeader {
            name: "X-Custom-Header".into(),
            value: "custom-value".into(),
        };
        let json = serde_json::to_string(&header).unwrap();
        let deserialized: HttpHeader = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, "X-Custom-Header");
        assert_eq!(deserialized.value, "custom-value");
    }

    // ── canonicalize_hostname edge cases ──────────────────────────────

    #[test]
    fn test_canonicalize_hostname_empty() {
        assert!(canonicalize_hostname("").is_err());
    }

    #[test]
    fn test_canonicalize_hostname_trailing_dot() {
        assert_eq!(
            canonicalize_hostname("example.com.").unwrap(),
            "example.com"
        );
    }

    #[test]
    fn test_canonicalize_hostname_idempotent() {
        let hostname = "api.example.com";
        let canonical = canonicalize_hostname(hostname).unwrap();
        let canonical2 = canonicalize_hostname(&canonical).unwrap();
        assert_eq!(canonical, canonical2);
    }

    // ── SSRF: IPv4-mapped IPv6 bypass prevention ─────────────────────

    #[test]
    fn test_ipv4_mapped_ipv6_localhost_detected() {
        // ::ffff:127.0.0.1 must be treated as localhost
        assert!(is_localhost("::ffff:127.0.0.1".parse().unwrap()));
        // Hex form of same address
        assert!(is_localhost("::ffff:7f00:1".parse().unwrap()));
    }

    #[test]
    fn test_ipv4_mapped_ipv6_private_range_detected() {
        // ::ffff:10.0.0.1 must be treated as private
        assert!(is_private_range("::ffff:10.0.0.1".parse().unwrap()));
        assert!(is_private_range("::ffff:192.168.1.1".parse().unwrap()));
        assert!(is_private_range("::ffff:172.16.0.1".parse().unwrap()));
    }

    #[test]
    fn test_ipv4_mapped_ipv6_not_private_when_public() {
        // ::ffff:8.8.8.8 is NOT private
        assert!(!is_private_range("::ffff:8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_ipv4_mapped_ipv6_cidr_deny_blocks_bypass() {
        // Attacker tries ::ffff:203.0.113.1 to bypass 203.0.113.0/24 deny
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.deny_localhost = false;
        constraints.deny_private_ranges = false;
        constraints.cidr_deny = vec!["203.0.113.0/24".into()];

        let result =
            guard.check_ip_constraints("::ffff:203.0.113.1".parse().unwrap(), &constraints);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::CidrDenyMatched);
        }
    }

    #[test]
    fn test_ipv4_compatible_ipv6_not_normalized_to_ipv4() {
        // IPv4-compatible (::x.x.x.x, NOT ::ffff:x.x.x.x) should NOT match IPv4 rules.
        // ::192.168.1.1 parses as ::c0a8:0101 in IPv6 — not a private range.
        let addr: IpAddr = "::192.168.1.1".parse().unwrap();
        // This is an IPv6 address, not IPv4-mapped, so it should NOT be treated as private IPv4
        assert!(!is_private_range(addr));
    }

    // ── Wildcard hostname SSRF edge cases ────────────────────────────

    #[test]
    fn test_wildcard_matches_subdomain() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.host_allow = vec!["*.example.com".into()];
        constraints.port_allow = vec![443];

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://api.example.com/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });
        assert!(guard.evaluate(&request, &constraints).is_ok());
    }

    #[test]
    fn test_wildcard_does_not_match_bare_parent_domain() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.host_allow = vec!["*.example.com".into()];
        constraints.port_allow = vec![443];

        // "example.com" itself should NOT match "*.example.com"
        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://example.com/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });
        assert!(guard.evaluate(&request, &constraints).is_err());
    }

    #[test]
    fn test_wildcard_matches_deep_subdomain() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.host_allow = vec!["*.example.com".into()];
        constraints.port_allow = vec![443];

        // "a.b.c.example.com" should match "*.example.com"
        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://a.b.c.example.com/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });
        assert!(guard.evaluate(&request, &constraints).is_ok());
    }

    #[test]
    fn test_wildcard_star_allows_any_host() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.host_allow = vec!["*".into()];
        constraints.port_allow = vec![443];

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://anything.example.org/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });
        assert!(guard.evaluate(&request, &constraints).is_ok());
    }

    #[test]
    fn test_empty_host_allow_denies_all() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.host_allow = vec![];
        constraints.port_allow = vec![443];

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://api.example.com/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });
        let result = guard.evaluate(&request, &constraints);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::HostNotAllowed);
        }
    }

    #[test]
    fn test_empty_port_allow_denies_all() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.port_allow = vec![];

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://api.example.com/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });
        let result = guard.evaluate(&request, &constraints);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::PortNotAllowed);
        }
    }

    // ── DNS resolution validation ────────────────────────────────────

    #[test]
    fn test_validate_dns_resolution_over_limit() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.dns_max_ips = 2;
        let ips: Vec<IpAddr> = vec![
            "8.8.8.8".parse().unwrap(),
            "8.8.4.4".parse().unwrap(),
            "1.1.1.1".parse().unwrap(),
        ];
        let result = guard.validate_dns_resolution(&ips, &constraints);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::DnsMaxIpsExceeded);
        }
    }

    #[test]
    fn test_validate_dns_resolution_bad_ip_at_end() {
        // Even if first IPs are fine, a bad one at the end must fail
        let guard = EgressGuard::new();
        let constraints = test_constraints(); // deny_localhost = true
        let ips: Vec<IpAddr> = vec![
            "8.8.8.8".parse().unwrap(),
            "8.8.4.4".parse().unwrap(),
            "127.0.0.1".parse().unwrap(), // localhost at end
        ];
        let result = guard.validate_dns_resolution(&ips, &constraints);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::LocalhostDenied);
        }
    }

    #[test]
    fn test_validate_dns_resolution_mixed_ipv4_ipv6() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();
        let ips: Vec<IpAddr> = vec![
            "8.8.8.8".parse().unwrap(),
            "2001:4860:4860::8888".parse().unwrap(),
        ];
        let result = guard.validate_dns_resolution(&ips, &constraints);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 2);
    }

    #[test]
    fn test_validate_dns_resolution_ipv4_mapped_ipv6_localhost_blocked() {
        // DNS returns ::ffff:127.0.0.1 — must be caught as localhost
        let guard = EgressGuard::new();
        let constraints = test_constraints(); // deny_localhost = true
        let ips: Vec<IpAddr> = vec!["::ffff:127.0.0.1".parse().unwrap()];
        let result = guard.validate_dns_resolution(&ips, &constraints);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::LocalhostDenied);
        }
    }

    // ── URL scheme edge cases ────────────────────────────────────────

    #[test]
    fn test_evaluate_http_rejects_non_http_scheme_even_when_port_allowed() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.host_allow = vec!["*".into()];
        constraints.port_allow = vec![21];

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "ftp://files.example.com/data".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });
        let result = guard.evaluate(&request, &constraints);
        assert!(matches!(result, Err(EgressError::InvalidUrl(_))));
    }

    #[test]
    fn test_evaluate_http_rejects_embedded_credentials() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.host_allow = vec!["api.example.com".into()];

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://user:pass@api.example.com/data".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });
        let result = guard.evaluate(&request, &constraints);
        assert!(matches!(result, Err(EgressError::InvalidUrl(_))));
    }

    #[test]
    fn test_evaluate_http_explicit_port_overrides_scheme_default() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.port_allow = vec![8080];
        constraints.host_allow = vec!["api.example.com".into()];

        // http:// defaults to 80, but explicit :8080 should be checked against port_allow
        let request = EgressRequest::Http(EgressHttpRequest {
            url: "http://api.example.com:8080/data".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });
        let result = guard.evaluate(&request, &constraints);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().port, 8080);
    }

    // ── IP literal handling ──────────────────────────────────────────

    #[test]
    fn test_ip_literal_denied_by_default() {
        let guard = EgressGuard::new();
        let constraints = test_constraints(); // deny_ip_literals = true

        let request = EgressRequest::TcpConnect(EgressTcpConnectRequest {
            host: "93.184.216.34".into(),
            port: 443,
            tls: true,
            sni_override: None,
            credential_id: None,
        });
        let result = guard.evaluate(&request, &constraints);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::IpLiteralDenied);
        }
    }

    #[test]
    fn test_ip_literal_allowed_when_deny_disabled_and_in_ip_allow() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.deny_ip_literals = false;
        constraints.ip_allow = vec!["93.184.216.34".parse().unwrap()];
        constraints.deny_localhost = false;
        constraints.deny_private_ranges = false;

        let request = EgressRequest::TcpConnect(EgressTcpConnectRequest {
            host: "93.184.216.34".into(),
            port: 443,
            tls: true,
            sni_override: None,
            credential_id: None,
        });
        let result = guard.evaluate(&request, &constraints);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ip_literal_not_in_ip_allow_denied() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.deny_ip_literals = false;
        constraints.ip_allow = vec!["1.2.3.4".parse().unwrap()];
        constraints.host_allow = vec![]; // no hostname match either

        let request = EgressRequest::TcpConnect(EgressTcpConnectRequest {
            host: "5.6.7.8".into(),
            port: 443,
            tls: true,
            sni_override: None,
            credential_id: None,
        });
        let result = guard.evaluate(&request, &constraints);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::IpNotAllowed);
        }
    }

    #[test]
    fn test_ip_literal_outside_ip_allow_denied_despite_wildcard_host_allow() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.deny_ip_literals = false;
        constraints.deny_private_ranges = false;
        constraints.deny_localhost = false;
        constraints.host_allow = vec!["*".into()];
        constraints.ip_allow = vec!["93.184.216.34".parse().unwrap()];
        constraints.port_allow = vec![443];

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://1.2.3.4/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });
        let result = guard.evaluate(&request, &constraints);
        assert!(matches!(
            result,
            Err(EgressError::Denied {
                code: DenyReason::IpNotAllowed,
                ..
            })
        ));
    }

    #[test]
    fn test_ip_literal_allow_list_normalizes_ipv4_mapped_ipv6() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.deny_ip_literals = false;
        constraints.deny_private_ranges = false;
        constraints.deny_localhost = false;
        constraints.host_allow = vec!["*".into()];
        constraints.ip_allow = vec!["93.184.216.34".parse().unwrap()];
        constraints.port_allow = vec![443];

        let request = EgressRequest::TcpConnect(EgressTcpConnectRequest {
            host: "::ffff:93.184.216.34".into(),
            port: 443,
            tls: true,
            sni_override: None,
            credential_id: None,
        });
        let result = guard.evaluate(&request, &constraints);
        assert!(
            result.is_ok(),
            "IPv4-mapped IPv6 literal must match pure IPv4 ip_allow: {result:?}"
        );
    }

    // ── Credential injection edge cases ──────────────────────────────

    struct HostBoundInjector {
        allowed_hosts: Vec<String>,
    }

    impl CredentialInjector for HostBoundInjector {
        fn is_authorized(
            &self,
            _cred: &str,
            _op: &str,
            _allow: &[String],
        ) -> Result<bool, EgressError> {
            Ok(true)
        }

        fn is_host_allowed(&self, _cred: &str, host: &str) -> Result<bool, EgressError> {
            Ok(self.allowed_hosts.iter().any(|h| h == host))
        }

        fn inject_http(
            &self,
            _cred: &str,
            headers: &mut Vec<HttpHeader>,
        ) -> Result<(), EgressError> {
            headers.push(HttpHeader {
                name: "Authorization".into(),
                value: "Bearer host-bound-token".into(),
            });
            Ok(())
        }

        fn get_tcp_auth(&self, _cred: &str) -> Result<Option<Vec<u8>>, EgressError> {
            Ok(Some(b"host-bound-auth".to_vec()))
        }
    }

    #[test]
    fn test_authorize_http_host_bound_credential_wrong_host() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();
        let injector = HostBoundInjector {
            allowed_hosts: vec!["other.example.com".into()],
        };

        let mut req = EgressHttpRequest {
            url: "https://api.example.com/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: Some("cred-1".into()),
        };

        let result =
            guard.authorize_http(&mut req, &constraints, &injector, "op", &["cred-1".into()]);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::CredentialHostNotAllowed);
        }
    }

    #[test]
    fn test_authorize_http_host_bound_credential_correct_host() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();
        let injector = HostBoundInjector {
            allowed_hosts: vec!["api.example.com".into()],
        };

        let mut req = EgressHttpRequest {
            url: "https://api.example.com/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: Some("cred-1".into()),
        };

        let result =
            guard.authorize_http(&mut req, &constraints, &injector, "op", &["cred-1".into()]);
        assert!(result.is_ok());
        assert!(result.unwrap().credential_injected);
    }

    #[test]
    fn test_authorize_tcp_host_not_allowed() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();
        let injector = HostBoundInjector {
            allowed_hosts: vec!["db.internal.com".into()],
        };

        let req = EgressTcpConnectRequest {
            host: "api.example.com".into(),
            port: 443,
            tls: true,
            sni_override: None,
            credential_id: Some("cred-1".into()),
        };

        let result = guard.authorize_tcp(&req, &constraints, &injector, "op", &["cred-1".into()]);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::CredentialHostNotAllowed);
        }
    }

    struct NullTcpAuthInjector;

    impl CredentialInjector for NullTcpAuthInjector {
        fn is_authorized(
            &self,
            _cred: &str,
            _op: &str,
            _allow: &[String],
        ) -> Result<bool, EgressError> {
            Ok(true)
        }

        fn inject_http(
            &self,
            _cred: &str,
            _headers: &mut Vec<HttpHeader>,
        ) -> Result<(), EgressError> {
            Ok(())
        }

        fn get_tcp_auth(&self, _cred: &str) -> Result<Option<Vec<u8>>, EgressError> {
            Ok(None) // No TCP auth bytes
        }
    }

    #[test]
    fn test_authorize_tcp_no_auth_bytes_credential_not_injected() {
        // When get_tcp_auth returns None, credential_injected should be false
        let guard = EgressGuard::new();
        let constraints = test_constraints();
        let injector = AllowAllHosts::new(NullTcpAuthInjector);

        let req = EgressTcpConnectRequest {
            host: "api.example.com".into(),
            port: 443,
            tls: true,
            sni_override: None,
            credential_id: Some("cred-1".into()),
        };

        let result = guard
            .authorize_tcp(&req, &constraints, &injector, "op", &["cred-1".into()])
            .unwrap();
        assert!(result.tcp_auth.is_none());
        assert!(!result.decision.credential_injected);
    }

    // ── NoOp injector behavior ───────────────────────────────────────

    #[test]
    fn test_noop_injector_denies_authorization() {
        let injector = NoOpCredentialInjector;
        let result = injector.is_authorized("cred-1", "op-1", &["cred-1".into()]);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_noop_injector_inject_http_errors() {
        let injector = NoOpCredentialInjector;
        let mut headers = vec![];
        let result = injector.inject_http("cred-1", &mut headers);
        assert!(matches!(result, Err(EgressError::CredentialError(_))));
    }

    #[test]
    fn test_noop_injector_get_tcp_auth_errors() {
        let injector = NoOpCredentialInjector;
        let result = injector.get_tcp_auth("cred-1");
        assert!(matches!(result, Err(EgressError::CredentialError(_))));
    }

    // ── TLS verification edge cases ──────────────────────────────────

    #[test]
    fn test_sni_verification_exact_match_succeeds() {
        let verifier = DefaultTlsVerifier;
        assert!(
            verifier
                .verify_sni("api.example.com", "api.example.com")
                .is_ok()
        );
    }

    #[test]
    fn test_sni_verification_case_sensitive() {
        // SNI should be case-sensitive (caller is responsible for canonicalization)
        let verifier = DefaultTlsVerifier;
        let result = verifier.verify_sni("API.EXAMPLE.COM", "api.example.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_spki_verification_multiple_pins_partial_length_match() {
        let verifier = DefaultTlsVerifier;
        let pin_short = vec![0xAA; 16];
        let pin_long = vec![0xAA; 32];
        let cert = vec![0xAA; 32];

        // Only the pin with matching length should be considered
        assert!(verifier.verify_spki(&cert, &[pin_short, pin_long]).is_ok());
    }

    #[test]
    fn test_spki_verification_zero_length_cert_and_pin() {
        let verifier = DefaultTlsVerifier;
        // Empty cert against empty pin — length matches, diff is 0
        assert!(verifier.verify_spki(&[], &[vec![]]).is_ok());
    }

    // ── CIDR deny edge cases ─────────────────────────────────────────

    #[test]
    fn test_cidr_deny_with_multiple_ranges() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.deny_localhost = false;
        constraints.deny_private_ranges = false;
        constraints.cidr_deny = vec!["198.51.100.0/24".into(), "203.0.113.0/24".into()];

        // First range
        assert!(
            guard
                .check_ip_constraints("198.51.100.42".parse().unwrap(), &constraints)
                .is_err()
        );
        // Second range
        assert!(
            guard
                .check_ip_constraints("203.0.113.1".parse().unwrap(), &constraints)
                .is_err()
        );
        // Outside both ranges
        assert!(
            guard
                .check_ip_constraints("8.8.8.8".parse().unwrap(), &constraints)
                .is_ok()
        );
    }

    #[test]
    fn test_cidr_deny_invalid_cidr_string_rejected() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.deny_localhost = false;
        constraints.deny_private_ranges = false;
        constraints.cidr_deny = vec!["not-a-cidr".into(), "203.0.113.0/24".into()];

        let err = guard
            .check_ip_constraints("8.8.8.8".parse().unwrap(), &constraints)
            .unwrap_err();
        assert!(matches!(err, EgressError::InvalidRequest(_)));
        assert!(err.to_string().contains("invalid cidr_deny rule"));
    }

    // ── Hostname canonicalization edge cases ──────────────────────────

    #[test]
    fn test_canonicalize_hostname_mixed_case_idna() {
        // Mixed case Unicode domain
        let result = canonicalize_hostname("München.EXAMPLE.COM").unwrap();
        assert!(result.starts_with("xn--"));
        assert!(result.ends_with(".example.com"));
    }

    #[test]
    fn test_canonicalize_hostname_only_dot() {
        // Just a trailing dot — after stripping it becomes empty
        let result = canonicalize_hostname(".");
        assert!(result.is_err());
    }

    #[test]
    fn test_canonicalize_host_pattern_unicode_wildcard() {
        // *.München.com → *.xn--mnchen-3ya.com (lowercased)
        let pat = canonicalize_host_pattern("*.München.com");
        assert!(pat.is_some());
        let p = pat.unwrap();
        assert!(p.starts_with("*.xn--"));
    }

    // ── TCP connect with canonicalization ─────────────────────────────

    #[test]
    fn test_tcp_connect_non_canonical_host_passes_when_not_required() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.require_host_canonicalization = false;
        constraints.host_allow = vec!["api.example.com".into()];

        // Non-canonical host should be canonicalized transparently
        let request = EgressRequest::TcpConnect(EgressTcpConnectRequest {
            host: "API.EXAMPLE.COM".into(),
            port: 443,
            tls: true,
            sni_override: None,
            credential_id: None,
        });
        let result = guard.evaluate(&request, &constraints);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().canonical_host, "api.example.com");
    }

    // ── ip_in_any_cidr direct tests ──────────────────────────────────

    #[test]
    fn test_ip_in_any_cidr_empty_list() {
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(!ip_in_any_cidr(ip, &[]));
    }

    #[test]
    fn test_ip_in_any_cidr_ipv6_not_mapped() {
        // Pure IPv6 address should NOT be normalized to IPv4
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        let cidrs = parse_cidr_list(&["10.0.0.0/8"]);
        assert!(!ip_in_any_cidr(ip, &cidrs));
    }

    #[test]
    fn test_ip_in_any_cidr_ipv4_mapped_matches_ipv4_cidr() {
        // ::ffff:10.0.0.1 should match 10.0.0.0/8 after normalization
        let ip: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
        let cidrs = parse_cidr_list(&["10.0.0.0/8"]);
        assert!(ip_in_any_cidr(ip, &cidrs));
    }

    // ── parse_cidr_list edge cases ───────────────────────────────────

    #[test]
    fn test_parse_cidr_list_skips_invalid() {
        let result = parse_cidr_list(&["10.0.0.0/8", "garbage", "192.168.0.0/16"]);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_parse_cidr_list_empty() {
        let result = parse_cidr_list(&[]);
        assert!(result.is_empty());
    }

    // ── New edge-case tests ────────────────────────────────────────────

    // -- International domain name edge cases --

    #[test]
    fn test_canonicalize_chinese_domain() {
        // Chinese characters should produce xn-- Punycode
        let result = canonicalize_hostname("例え.jp").unwrap();
        assert!(result.starts_with("xn--"));
        assert!(result.as_bytes().ends_with(b".jp"));
    }

    #[test]
    fn test_canonicalize_arabic_domain() {
        let result = canonicalize_hostname("مثال.com");
        // Arabic domains should either encode to punycode or fail gracefully
        assert!(result.is_ok() || result.is_err());
        if let Ok(canonical) = result {
            assert!(canonical.is_ascii());
        }
    }

    #[test]
    fn test_canonicalize_mixed_script_subdomain() {
        // Multiple Unicode subdomains
        let result = canonicalize_hostname("München.東京.example.com");
        if let Ok(canonical) = result {
            assert!(canonical.is_ascii());
            assert!(canonical.ends_with(".example.com"));
            // Each IDN label should be punycode-encoded
            assert!(canonical.contains("xn--"));
        }
    }

    #[test]
    fn test_canonicalize_punycode_passthrough() {
        // Already-encoded punycode should be idempotent
        let result = canonicalize_hostname("xn--mnchen-3ya.example.com").unwrap();
        assert_eq!(result, "xn--mnchen-3ya.example.com");
    }

    // -- URL with ports, query params, fragments --

    #[test]
    fn test_evaluate_url_with_query_params() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://api.example.com/v1/data?key=value&foo=bar".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        let decision = guard.evaluate(&request, &constraints).unwrap();
        assert!(decision.allowed);
        assert_eq!(decision.canonical_host, "api.example.com");
        assert_eq!(decision.port, 443);
    }

    #[test]
    fn test_evaluate_url_with_fragment() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://api.example.com/page#section".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        let decision = guard.evaluate(&request, &constraints).unwrap();
        assert!(decision.allowed);
        assert_eq!(decision.canonical_host, "api.example.com");
    }

    #[test]
    fn test_evaluate_url_with_explicit_default_port() {
        // https://host:443/ should resolve port 443 same as without explicit port
        let guard = EgressGuard::new();
        let constraints = test_constraints();

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://api.example.com:443/path".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        let decision = guard.evaluate(&request, &constraints).unwrap();
        assert_eq!(decision.port, 443);
    }

    #[test]
    fn test_evaluate_url_port_8443_allowed() {
        let guard = EgressGuard::new();
        let constraints = test_constraints(); // port_allow includes 8443

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://api.example.com:8443/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        let decision = guard.evaluate(&request, &constraints).unwrap();
        assert_eq!(decision.port, 8443);
        assert!(decision.tls_required);
    }

    // -- IPv6 literal URL handling --

    #[test]
    fn test_evaluate_ipv6_literal_allowed_when_in_ip_allow() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.deny_ip_literals = false;
        constraints.ip_allow = vec!["2001:db8::1".parse().unwrap()];
        constraints.port_allow = vec![443];

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://[2001:db8::1]/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        let decision = guard.evaluate(&request, &constraints).unwrap();
        assert!(decision.allowed);
        assert_eq!(decision.canonical_host, "2001:db8::1");
    }

    #[test]
    fn test_evaluate_ipv6_literal_with_port() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.deny_ip_literals = false;
        constraints.ip_allow = vec!["2001:db8::1".parse().unwrap()];
        constraints.port_allow = vec![8443];

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://[2001:db8::1]:8443/path".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        let decision = guard.evaluate(&request, &constraints).unwrap();
        assert_eq!(decision.port, 8443);
    }

    // -- IP literal CIDR check in evaluate_host_port --

    #[test]
    fn test_evaluate_ip_literal_localhost_cidr_check() {
        // When deny_ip_literals is false but deny_localhost is true,
        // an IP literal 127.0.0.1 should still be denied at CIDR step
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.deny_ip_literals = false;
        constraints.ip_allow = vec!["127.0.0.1".parse().unwrap()];
        constraints.port_allow = vec![443];

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://127.0.0.1/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        let result = guard.evaluate(&request, &constraints);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::LocalhostDenied);
        }
    }

    #[test]
    fn test_evaluate_ip_literal_private_range_check() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.deny_ip_literals = false;
        constraints.ip_allow = vec!["10.0.0.1".parse().unwrap()];
        constraints.port_allow = vec![443];
        // deny_private_ranges = true (default from test_constraints)

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://10.0.0.1/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        let result = guard.evaluate(&request, &constraints);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::PrivateRangeDenied);
        }
    }

    // -- DNS resolution edge cases --

    #[test]
    fn test_validate_dns_resolution_zero_max_ips() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.dns_max_ips = 0;

        // Even a single IP should exceed limit of 0
        let ips: Vec<IpAddr> = vec!["8.8.8.8".parse().unwrap()];
        let result = guard.validate_dns_resolution(&ips, &constraints);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::DnsMaxIpsExceeded);
        }
    }

    #[test]
    fn test_validate_dns_resolution_empty_with_zero_max() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.dns_max_ips = 0;

        // Empty list should be fine even with max 0
        let result = guard.validate_dns_resolution(&[], &constraints);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_dns_resolution_all_private_denied() {
        let guard = EgressGuard::new();
        let constraints = test_constraints(); // deny_private_ranges = true

        let ips: Vec<IpAddr> = vec![
            "10.0.0.1".parse().unwrap(),
            "172.16.0.1".parse().unwrap(),
            "192.168.1.1".parse().unwrap(),
        ];
        // First IP should trigger denial
        let result = guard.validate_dns_resolution(&ips, &constraints);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::PrivateRangeDenied);
        }
    }

    // -- CIDR deny with IPv6 ranges --

    #[test]
    fn test_cidr_deny_ipv6_range() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.deny_localhost = false;
        constraints.deny_private_ranges = false;
        constraints.cidr_deny = vec!["2001:db8::/32".into()];

        let result = guard.check_ip_constraints("2001:db8::1".parse().unwrap(), &constraints);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::CidrDenyMatched);
        }

        // Outside the range should pass
        let result = guard.check_ip_constraints("2001:db9::1".parse().unwrap(), &constraints);
        assert!(result.is_ok());
    }

    // -- Wildcard pattern edge cases --

    #[test]
    fn test_wildcard_does_not_match_suffix_without_dot() {
        // Ensure "evil-example.com" does NOT match "*.example.com"
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.host_allow = vec!["*.example.com".into()];
        constraints.port_allow = vec![443];

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://evil-example.com/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        let result = guard.evaluate(&request, &constraints);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::HostNotAllowed);
        }
    }

    #[test]
    fn test_host_allow_multiple_patterns_first_match_wins() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.host_allow = vec!["specific.example.com".into(), "*.example.com".into()];
        constraints.port_allow = vec![443];

        // Exact match should work
        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://specific.example.com/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });
        assert!(guard.evaluate(&request, &constraints).is_ok());

        // Wildcard match for different subdomain should also work
        let request2 = EgressRequest::Http(EgressHttpRequest {
            url: "https://other.example.com/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });
        assert!(guard.evaluate(&request2, &constraints).is_ok());
    }

    // -- Serde roundtrip for deny reason from raw JSON --

    #[test]
    fn test_deny_reason_from_raw_json_string() {
        let reason: DenyReason = serde_json::from_str("\"host_not_allowed\"").unwrap();
        assert_eq!(reason, DenyReason::HostNotAllowed);

        let reason: DenyReason = serde_json::from_str("\"max_redirects_exceeded\"").unwrap();
        assert_eq!(reason, DenyReason::MaxRedirectsExceeded);

        // Unknown variant should fail deserialization
        let result = serde_json::from_str::<DenyReason>("\"unknown_variant\"");
        assert!(result.is_err());
    }

    // -- EgressRequest clone and debug --

    #[test]
    fn test_egress_request_clone_http() {
        let req = EgressRequest::Http(EgressHttpRequest {
            url: "https://api.example.com/data".into(),
            method: "POST".into(),
            headers: vec![HttpHeader {
                name: "Content-Type".into(),
                value: "application/json".into(),
            }],
            body: Some(b"payload".to_vec()),
            credential_id: Some("cred-abc".into()),
        });
        let cloned = req.clone();
        drop(req);
        // Verify cloned data is intact
        if let EgressRequest::Http(http) = cloned {
            assert_eq!(http.url, "https://api.example.com/data");
            assert_eq!(http.method, "POST");
            assert_eq!(http.headers.len(), 1);
            assert_eq!(http.body, Some(b"payload".to_vec()));
            assert_eq!(http.credential_id.as_deref(), Some("cred-abc"));
        } else {
            panic!("expected Http variant after clone");
        }
    }

    #[test]
    fn test_egress_request_clone_tcp() {
        let req = EgressRequest::TcpConnect(EgressTcpConnectRequest {
            host: "db.example.com".into(),
            port: 5432,
            tls: true,
            sni_override: Some("custom.sni".into()),
            credential_id: Some("pg-cred".into()),
        });
        let cloned = req.clone();
        drop(req);
        if let EgressRequest::TcpConnect(tcp) = cloned {
            assert_eq!(tcp.host, "db.example.com");
            assert_eq!(tcp.port, 5432);
            assert!(tcp.tls);
            assert_eq!(tcp.sni_override.as_deref(), Some("custom.sni"));
        } else {
            panic!("expected TcpConnect variant after clone");
        }
    }

    #[test]
    fn test_egress_request_debug_format() {
        let req = EgressRequest::Http(EgressHttpRequest {
            url: "https://api.example.com/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });
        let debug = format!("{req:?}");
        assert!(debug.contains("Http"));
        assert!(debug.contains("api.example.com"));
    }

    // -- EgressDecision clone --

    #[test]
    fn test_egress_decision_clone() {
        let decision = EgressDecision {
            allowed: true,
            canonical_host: "api.example.com".into(),
            resolved_ips: vec!["8.8.8.8".parse().unwrap()],
            port: 443,
            tls_required: true,
            expected_sni: Some("api.example.com".into()),
            spki_pins: vec![vec![1, 2, 3]],
            credential_injected: true,
        };
        let cloned = decision.clone();
        drop(decision);
        assert!(cloned.allowed);
        assert_eq!(cloned.canonical_host, "api.example.com");
        assert_eq!(cloned.resolved_ips.len(), 1);
        assert!(cloned.credential_injected);
    }

    #[test]
    fn test_egress_tcp_decision_clone() {
        let tcp_decision = EgressTcpDecision {
            decision: EgressDecision {
                allowed: true,
                canonical_host: "db.test".into(),
                resolved_ips: vec![],
                port: 5432,
                tls_required: false,
                expected_sni: None,
                spki_pins: vec![],
                credential_injected: false,
            },
            tcp_auth: Some(b"auth-data".to_vec()),
        };
        let cloned = tcp_decision.clone();
        drop(tcp_decision);
        assert_eq!(cloned.tcp_auth, Some(b"auth-data".to_vec()));
        assert!(!cloned.decision.credential_injected);
    }

    // -- TCP authorize credential host not allowed --

    #[test]
    fn test_authorize_tcp_credential_not_authorized_code() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();
        let injector = MockInjector {
            authorized: false,
            host_allowed: true,
        };

        let req = EgressTcpConnectRequest {
            host: "api.example.com".into(),
            port: 443,
            tls: true,
            sni_override: None,
            credential_id: Some("cred-1".into()),
        };

        let result = guard.authorize_tcp(&req, &constraints, &injector, "op", &["cred-1".into()]);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, reason }) = result {
            assert_eq!(code, DenyReason::CredentialNotAuthorized);
            assert!(reason.contains("cred-1"));
            assert!(reason.contains("op"));
        }
    }

    // -- NoOp credential injector default trait --

    #[test]
    fn test_noop_credential_injector_default_host_denied() {
        // The default impl of is_host_allowed should fail closed.
        let injector = NoOpCredentialInjector;
        let result = injector.is_host_allowed("any-cred", "any-host");
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_noop_credential_injector_debug() {
        let injector = NoOpCredentialInjector;
        let debug = format!("{injector:?}");
        assert!(debug.contains("NoOpCredentialInjector"));
    }

    // -- DefaultTlsVerifier debug --

    #[test]
    fn test_default_tls_verifier_debug() {
        let verifier = DefaultTlsVerifier;
        let debug = format!("{verifier:?}");
        assert!(debug.contains("DefaultTlsVerifier"));
    }

    // -- HTTP request with empty body vs None --

    #[test]
    fn test_egress_http_request_serde_empty_body_vs_none() {
        // body: None should deserialize from missing field
        let json_no_body = r#"{"url":"https://x.com","method":"GET","headers":[]}"#;
        let req: EgressHttpRequest = serde_json::from_str(json_no_body).unwrap();
        assert!(req.body.is_none());
        assert!(req.credential_id.is_none());

        // body: Some(empty vec) should roundtrip correctly
        let req_with_empty = EgressHttpRequest {
            url: "https://x.com".into(),
            method: "POST".into(),
            headers: vec![],
            body: Some(vec![]),
            credential_id: None,
        };
        let json = serde_json::to_string(&req_with_empty).unwrap();
        let deserialized: EgressHttpRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.body, Some(vec![]));
    }

    // -- DenyReason Copy + Eq --

    #[test]
    fn test_deny_reason_copy_semantics() {
        let reason = DenyReason::HostNotAllowed;
        let copied = reason; // Copy
        assert_eq!(reason, copied);
        // Both should be usable after copy
        assert_eq!(format!("{reason:?}"), format!("{copied:?}"));
    }

    // ── New tests: IDN/Unicode hostname edge cases ──

    #[test]
    fn test_canonicalize_hostname_chinese_domain() {
        let result = canonicalize_hostname("例え.jp");
        assert!(result.is_ok());
        let canonical = result.unwrap();
        assert!(canonical.starts_with("xn--"));
    }

    #[test]
    fn test_canonicalize_hostname_arabic_domain() {
        let result = canonicalize_hostname("مثال.com");
        assert!(result.is_ok());
        let canonical = result.unwrap();
        assert!(canonical.starts_with("xn--"));
        assert!(canonical.is_ascii());
    }

    #[test]
    fn test_canonicalize_hostname_cyrillic_domain() {
        let result = canonicalize_hostname("пример.com");
        assert!(result.is_ok());
        let canonical = result.unwrap();
        assert!(canonical.starts_with("xn--"));
    }

    #[test]
    fn test_canonicalize_hostname_mixed_case_idn() {
        // Mixed case + IDN
        let result = canonicalize_hostname("München.Example.COM");
        assert!(result.is_ok());
        let canonical = result.unwrap();
        assert!(canonical.contains("xn--"));
        assert!(canonical.ends_with(".example.com"));
    }

    #[test]
    fn test_canonicalize_hostname_punycode_already_encoded() {
        // Already punycode-encoded should pass through unchanged
        let result = canonicalize_hostname("xn--mnchen-3ya.example.com");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "xn--mnchen-3ya.example.com");
    }

    #[test]
    fn test_canonicalize_hostname_single_label() {
        let result = canonicalize_hostname("localhost");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "localhost");
    }

    #[test]
    fn test_canonicalize_hostname_deeply_nested() {
        let result = canonicalize_hostname("a.b.c.d.e.f.example.com");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "a.b.c.d.e.f.example.com");
    }

    // ── New tests: IPv6 SSRF edge cases ──

    #[test]
    fn test_is_localhost_ipv4_mapped_boundary() {
        // ::ffff:0.0.0.0 - mapped unspecified
        assert!(is_localhost("::ffff:0.0.0.0".parse().unwrap()));
    }

    #[test]
    fn test_is_private_range_ipv4_mapped_172_boundary() {
        // ::ffff:172.15.255.255 is NOT private (just below 172.16.0.0/12)
        assert!(!is_private_range("::ffff:172.15.255.255".parse().unwrap()));
        // ::ffff:172.16.0.0 IS private
        assert!(is_private_range("::ffff:172.16.0.0".parse().unwrap()));
        // ::ffff:172.31.255.255 IS private (top of 172.16.0.0/12)
        assert!(is_private_range("::ffff:172.31.255.255".parse().unwrap()));
        // ::ffff:172.32.0.0 is NOT private
        assert!(!is_private_range("::ffff:172.32.0.0".parse().unwrap()));
    }

    #[test]
    fn test_is_tailnet_range_ipv4_mapped() {
        // ::ffff:100.64.0.1 maps to 100.64.0.1 which is tailnet
        assert!(is_tailnet_range("::ffff:100.64.0.1".parse().unwrap()));
    }

    #[test]
    fn test_is_link_local_ipv4_mapped() {
        // ::ffff:169.254.1.1 maps to link-local
        assert!(is_link_local("::ffff:169.254.1.1".parse().unwrap()));
    }

    #[test]
    fn test_is_tailnet_range_ipv6_ts() {
        // Tailscale IPv6 range fd7a:115c:a1e0::/48
        assert!(is_tailnet_range("fd7a:115c:a1e0::ffff".parse().unwrap()));
        // Just outside
        assert!(!is_tailnet_range("fd7a:115c:a1e1::1".parse().unwrap()));
    }

    // ── New tests: EgressDecision clone + debug ──

    #[test]
    fn test_egress_decision_clone_with_spki_pins() {
        let original = EgressDecision {
            allowed: true,
            canonical_host: "api.example.com".into(),
            resolved_ips: vec!["1.2.3.4".parse().unwrap()],
            port: 443,
            tls_required: true,
            expected_sni: Some("api.example.com".into()),
            spki_pins: vec![vec![1, 2, 3]],
            credential_injected: false,
        };
        let cloned = original.clone();
        assert_eq!(original.canonical_host, cloned.canonical_host);
        assert_eq!(original.port, cloned.port);
        assert_eq!(original.tls_required, cloned.tls_required);
        assert_eq!(original.resolved_ips, cloned.resolved_ips);
        assert_eq!(original.spki_pins, cloned.spki_pins);
    }

    #[test]
    fn test_egress_decision_debug_format() {
        let d = EgressDecision {
            allowed: true,
            canonical_host: "test.com".into(),
            resolved_ips: vec![],
            port: 80,
            tls_required: false,
            expected_sni: None,
            spki_pins: vec![],
            credential_injected: false,
        };
        let debug = format!("{d:?}");
        assert!(debug.contains("EgressDecision"));
        assert!(debug.contains("test.com"));
    }

    #[test]
    fn test_egress_tcp_decision_clone_with_auth() {
        let original = EgressTcpDecision {
            decision: EgressDecision {
                allowed: true,
                canonical_host: "db.test".into(),
                resolved_ips: vec![],
                port: 5432,
                tls_required: false,
                expected_sni: None,
                spki_pins: vec![],
                credential_injected: false,
            },
            tcp_auth: Some(b"auth-data".to_vec()),
        };
        let cloned = original.clone();
        assert_eq!(original.tcp_auth, cloned.tcp_auth);
        assert_eq!(
            original.decision.canonical_host,
            cloned.decision.canonical_host
        );
    }

    #[test]
    fn test_egress_tcp_decision_debug_format() {
        let d = EgressTcpDecision {
            decision: EgressDecision {
                allowed: true,
                canonical_host: "db.test".into(),
                resolved_ips: vec![],
                port: 5432,
                tls_required: false,
                expected_sni: None,
                spki_pins: vec![],
                credential_injected: false,
            },
            tcp_auth: None,
        };
        let debug = format!("{d:?}");
        assert!(debug.contains("EgressTcpDecision"));
    }

    // ── New tests: EgressHttpRequest clone + debug ──

    #[test]
    fn test_egress_http_request_clone() {
        let original = EgressHttpRequest {
            url: "https://example.com/api".into(),
            method: "POST".into(),
            headers: vec![HttpHeader {
                name: "Content-Type".into(),
                value: "application/json".into(),
            }],
            body: Some(b"payload".to_vec()),
            credential_id: Some("cred-abc".into()),
        };
        let cloned = original.clone();
        assert_eq!(original.url, cloned.url);
        assert_eq!(original.method, cloned.method);
        assert_eq!(original.headers.len(), cloned.headers.len());
        assert_eq!(original.body, cloned.body);
        assert_eq!(original.credential_id, cloned.credential_id);
    }

    #[test]
    fn test_egress_http_request_debug() {
        let req = EgressHttpRequest {
            url: "https://example.com".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        };
        let debug = format!("{req:?}");
        assert!(debug.contains("EgressHttpRequest"));
        assert!(debug.contains("example.com"));
    }

    #[test]
    fn test_egress_tcp_connect_request_clone() {
        let original = EgressTcpConnectRequest {
            host: "db.example.com".into(),
            port: 5432,
            tls: true,
            sni_override: Some("override.example.com".into()),
            credential_id: Some("pg-cred".into()),
        };
        let cloned = original.clone();
        assert_eq!(original.host, cloned.host);
        assert_eq!(original.port, cloned.port);
        assert_eq!(original.tls, cloned.tls);
        assert_eq!(original.sni_override, cloned.sni_override);
        assert_eq!(original.credential_id, cloned.credential_id);
    }

    #[test]
    fn test_http_header_clone() {
        let original = HttpHeader {
            name: "Authorization".into(),
            value: "Bearer token123".into(),
        };
        let cloned = original.clone();
        assert_eq!(original.name, cloned.name);
        assert_eq!(original.value, cloned.value);
    }

    #[test]
    fn test_http_header_debug() {
        let header = HttpHeader {
            name: "X-Request-Id".into(),
            value: "abc-123".into(),
        };
        let debug = format!("{header:?}");
        assert!(debug.contains("HttpHeader"));
        assert!(debug.contains("X-Request-Id"));
    }

    // ── New tests: Host allow list edge cases ──

    #[test]
    fn test_host_allow_list_exact_match_case_insensitive() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.host_allow = vec!["API.Example.COM".into()];
        constraints.require_host_canonicalization = false;
        constraints.port_allow = vec![443];

        // Pattern is canonicalized to api.example.com, host is also canonicalized
        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://api.example.com/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });
        assert!(guard.evaluate(&request, &constraints).is_ok());
    }

    #[test]
    fn test_wildcard_idn_pattern() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.host_allow = vec!["*.example.com".into()];
        constraints.require_host_canonicalization = false;
        constraints.port_allow = vec![443];

        // Subdomain under example.com
        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://sub.example.com/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });
        assert!(guard.evaluate(&request, &constraints).is_ok());
    }

    #[test]
    fn test_multiple_host_allow_entries() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.host_allow = vec![
            "api.first.com".into(),
            "api.second.com".into(),
            "api.third.com".into(),
        ];
        constraints.port_allow = vec![443];

        // All three should be allowed
        for host in &["first", "second", "third"] {
            let request = EgressRequest::Http(EgressHttpRequest {
                url: format!("https://api.{host}.com/"),
                method: "GET".into(),
                headers: vec![],
                body: None,
                credential_id: None,
            });
            assert!(
                guard.evaluate(&request, &constraints).is_ok(),
                "host api.{host}.com should be allowed"
            );
        }
    }

    // ── New tests: IP allow list ──

    #[test]
    fn test_ip_allow_ipv6() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.deny_ip_literals = false;
        constraints.ip_allow = vec!["2001:db8::1".parse().unwrap()];
        constraints.port_allow = vec![443];

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://[2001:db8::1]/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });
        assert!(guard.evaluate(&request, &constraints).is_ok());
    }

    #[test]
    fn test_ip_allow_not_in_list() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.deny_ip_literals = false;
        constraints.ip_allow = vec!["93.184.216.34".parse().unwrap()];
        constraints.port_allow = vec![443];

        // 1.2.3.4 is not in ip_allow
        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://1.2.3.4/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });
        let result = guard.evaluate(&request, &constraints);
        assert!(result.is_err());
    }

    // ── New tests: CIDR deny edge cases ──

    #[test]
    fn test_cidr_deny_multiple_ranges() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.deny_localhost = false;
        constraints.deny_private_ranges = false;
        constraints.cidr_deny = vec![
            "198.51.100.0/24".into(), // TEST-NET-2
            "203.0.113.0/24".into(),  // TEST-NET-3
        ];

        assert!(
            guard
                .check_ip_constraints("198.51.100.50".parse().unwrap(), &constraints)
                .is_err()
        );
        assert!(
            guard
                .check_ip_constraints("203.0.113.50".parse().unwrap(), &constraints)
                .is_err()
        );
        // Outside both ranges
        assert!(
            guard
                .check_ip_constraints("198.51.99.1".parse().unwrap(), &constraints)
                .is_ok()
        );
    }

    #[test]
    fn test_cidr_deny_ipv6_documentation_range() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.deny_localhost = false;
        constraints.deny_private_ranges = false;
        constraints.cidr_deny = vec!["2001:db8::/32".into()]; // Documentation range

        assert!(
            guard
                .check_ip_constraints("2001:db8::1".parse().unwrap(), &constraints)
                .is_err()
        );
        assert!(
            guard
                .check_ip_constraints("2001:db9::1".parse().unwrap(), &constraints)
                .is_ok()
        );
    }

    #[test]
    fn test_cidr_deny_invalid_cidr_rejected_before_valid_rules() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.deny_localhost = false;
        constraints.deny_private_ranges = false;
        constraints.cidr_deny = vec!["not-a-cidr".into(), "203.0.113.0/24".into()];

        let err = guard
            .check_ip_constraints("203.0.113.1".parse().unwrap(), &constraints)
            .unwrap_err();
        assert!(matches!(err, EgressError::InvalidRequest(_)));
        assert!(err.to_string().contains("not-a-cidr"));
    }

    // ── New tests: Egress request serde edge cases ──

    #[test]
    fn test_egress_http_request_serde_no_optional_fields() {
        let json = r#"{"url":"https://x.com","method":"GET","headers":[]}"#;
        let req: EgressHttpRequest = serde_json::from_str(json).unwrap();
        assert!(req.body.is_none());
        assert!(req.credential_id.is_none());
    }

    #[test]
    fn test_egress_tcp_connect_request_serde_minimal() {
        let json = r#"{"host":"db.test","port":3306}"#;
        let req: EgressTcpConnectRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.host, "db.test");
        assert_eq!(req.port, 3306);
        assert!(!req.tls);
        assert!(req.sni_override.is_none());
        assert!(req.credential_id.is_none());
    }

    #[test]
    fn test_egress_request_serde_http_tag() {
        let req = EgressRequest::Http(EgressHttpRequest {
            url: "https://x.com".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"type\":\"http\""));
    }

    #[test]
    fn test_egress_request_serde_tcp_connect_tag() {
        let req = EgressRequest::TcpConnect(EgressTcpConnectRequest {
            host: "db.test".into(),
            port: 5432,
            tls: false,
            sni_override: None,
            credential_id: None,
        });
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"type\":\"tcp_connect\""));
    }

    // ── New tests: NoOp credential injector default ──

    #[test]
    fn test_noop_credential_injector_debug_format() {
        let injector = NoOpCredentialInjector;
        let debug = format!("{injector:?}");
        assert!(debug.contains("NoOpCredentialInjector"));
    }

    #[test]
    fn test_noop_credential_injector_default() {
        let injector = NoOpCredentialInjector;
        let result = injector.is_authorized("any", "any", &[]);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_noop_credential_injector_host_denied_default() {
        let injector = NoOpCredentialInjector;
        // Default trait impl returns Ok(false).
        assert!(!injector.is_host_allowed("any-cred", "any-host").unwrap());
    }

    // ── New tests: DefaultTlsVerifier ──

    #[test]
    fn test_default_tls_verifier_sni_match_exact() {
        let verifier = DefaultTlsVerifier;
        assert!(
            verifier
                .verify_sni("api.example.com", "api.example.com")
                .is_ok()
        );
    }

    #[test]
    fn test_default_tls_verifier_sni_mismatch_case() {
        let verifier = DefaultTlsVerifier;
        // Case-sensitive comparison
        let result = verifier.verify_sni("API.example.com", "api.example.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_spki_multiple_pins_only_one_matches() {
        let verifier = DefaultTlsVerifier;
        let pin1 = vec![0xAA; 32];
        let pin2 = vec![0xBB; 32];
        let pin3 = vec![0xCC; 32];
        let cert = vec![0xBB; 32]; // Matches pin2 only
        assert!(verifier.verify_spki(&cert, &[pin1, pin2, pin3]).is_ok());
    }

    #[test]
    fn test_spki_zero_length_cert_vs_zero_length_pin() {
        let verifier = DefaultTlsVerifier;
        // Both empty slices - should match
        assert!(verifier.verify_spki(&[], &[vec![]]).is_ok());
    }

    // ── New tests: authorize_tcp host not allowed ──

    #[test]
    fn test_authorize_tcp_credential_host_denied() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();
        let injector = MockInjector {
            authorized: true,
            host_allowed: false,
        };

        let req = EgressTcpConnectRequest {
            host: "api.example.com".into(),
            port: 443,
            tls: true,
            sni_override: None,
            credential_id: Some("cred-1".into()),
        };

        let result = guard.authorize_tcp(&req, &constraints, &injector, "op", &["cred-1".into()]);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::CredentialHostNotAllowed);
        }
    }

    // ── New tests: evaluate with exotic URL schemes ──

    #[test]
    fn test_evaluate_unknown_scheme_no_port() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();

        // data: URLs have no host, so they fail with InvalidUrl
        let request = EgressRequest::Http(EgressHttpRequest {
            url: "data:text/plain,hello".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });
        let result = guard.evaluate(&request, &constraints);
        assert!(matches!(result, Err(EgressError::InvalidUrl(_))));
    }

    // ── New tests: DenyReason debug formatting ──

    #[test]
    fn test_deny_reason_debug_all_variants() {
        let reasons = [
            DenyReason::HostNotAllowed,
            DenyReason::PortNotAllowed,
            DenyReason::IpLiteralDenied,
            DenyReason::LocalhostDenied,
            DenyReason::PrivateRangeDenied,
            DenyReason::TailnetRangeDenied,
            DenyReason::LinkLocalDenied,
            DenyReason::CidrDenyMatched,
            DenyReason::SniMismatch,
            DenyReason::SpkiPinMismatch,
            DenyReason::CredentialNotAuthorized,
            DenyReason::CredentialHostNotAllowed,
            DenyReason::HostnameNotCanonical,
            DenyReason::DnsMaxIpsExceeded,
            DenyReason::MaxRedirectsExceeded,
        ];
        for reason in reasons {
            let debug = format!("{reason:?}");
            assert!(!debug.is_empty());
        }
    }

    #[test]
    fn test_deny_reason_clone() {
        let original = DenyReason::HostNotAllowed;
        let cloned = original;
        assert_eq!(original, cloned);
    }

    // ── New tests: is_hostname_canonical more edge cases ──

    #[test]
    fn test_is_hostname_canonical_with_numbers() {
        assert!(is_hostname_canonical("api123.example.com"));
    }

    #[test]
    fn test_is_hostname_canonical_with_hyphens() {
        assert!(is_hostname_canonical("my-api.example.com"));
    }

    #[test]
    fn test_is_hostname_canonical_single_char_labels() {
        assert!(is_hostname_canonical("a.b.c"));
    }

    // ── New tests: canonicalize_host_pattern more cases ──

    #[test]
    fn test_canonicalize_host_pattern_wildcard_idn() {
        let result = canonicalize_host_pattern("*.München.COM");
        assert!(result.is_some());
        let pat = result.unwrap();
        assert!(pat.starts_with("*.xn--"));
    }

    #[test]
    fn test_canonicalize_host_pattern_ipv6_literal() {
        // IPv6 addresses parse as IpAddr, passed through unchanged
        let result = canonicalize_host_pattern("::1");
        assert_eq!(result, Some("::1".into()));
    }

    // ── New batch: EgressDecision variations ──

    #[test]
    fn test_egress_decision_clone_all_fields_populated() {
        let original = EgressDecision {
            allowed: true,
            canonical_host: "full.example.com".into(),
            resolved_ips: vec!["1.2.3.4".parse().unwrap(), "5.6.7.8".parse().unwrap()],
            port: 8443,
            tls_required: true,
            expected_sni: Some("full.example.com".into()),
            spki_pins: vec![vec![0xAA, 0xBB], vec![0xCC, 0xDD]],
            credential_injected: true,
        };
        let cloned = original.clone();
        assert_eq!(original.resolved_ips.len(), 2);
        assert_eq!(cloned.spki_pins.len(), 2);
        assert_eq!(original.port, 8443);
    }

    #[test]
    fn test_egress_decision_debug_shows_port() {
        let d = EgressDecision {
            allowed: false,
            canonical_host: "dbg.com".into(),
            resolved_ips: vec![],
            port: 9090,
            tls_required: false,
            expected_sni: None,
            spki_pins: vec![],
            credential_injected: false,
        };
        let dbg = format!("{d:?}");
        assert!(dbg.contains("9090"));
    }

    #[test]
    fn test_egress_tcp_decision_clone_no_auth() {
        let original = EgressTcpDecision {
            decision: EgressDecision {
                allowed: true,
                canonical_host: "noauth.test".into(),
                resolved_ips: vec![],
                port: 3306,
                tls_required: false,
                expected_sni: None,
                spki_pins: vec![],
                credential_injected: false,
            },
            tcp_auth: None,
        };
        let cloned = original.clone();
        assert!(original.tcp_auth.is_none());
        assert_eq!(cloned.decision.port, 3306);
    }

    #[test]
    fn test_egress_tcp_decision_debug_shows_port() {
        let d = EgressTcpDecision {
            decision: EgressDecision {
                allowed: true,
                canonical_host: "h".into(),
                resolved_ips: vec![],
                port: 27017,
                tls_required: false,
                expected_sni: None,
                spki_pins: vec![],
                credential_injected: false,
            },
            tcp_auth: None,
        };
        let dbg = format!("{d:?}");
        assert!(dbg.contains("27017"));
    }

    // ── New batch: request type clone/debug variations ──

    #[test]
    fn test_egress_http_request_clone_empty_body() {
        let original = EgressHttpRequest {
            url: "https://empty.test/v2".into(),
            method: "PUT".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        };
        let cloned = original.clone();
        assert_eq!(original.url, "https://empty.test/v2");
        assert_eq!(cloned.method, "PUT");
        assert!(original.body.is_none());
    }

    #[test]
    fn test_egress_http_request_debug_shows_method() {
        let req = EgressHttpRequest {
            url: "https://method.test/".into(),
            method: "OPTIONS".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        };
        let dbg = format!("{req:?}");
        assert!(dbg.contains("OPTIONS"));
    }

    #[test]
    fn test_egress_tcp_request_clone_no_tls() {
        let original = EgressTcpConnectRequest {
            host: "notls.host.com".into(),
            port: 6379,
            tls: false,
            sni_override: None,
            credential_id: None,
        };
        let cloned = original.clone();
        assert_eq!(original.host, "notls.host.com");
        assert_eq!(cloned.port, 6379);
        assert!(!original.tls);
    }

    #[test]
    fn test_egress_tcp_request_debug_shows_host() {
        let req = EgressTcpConnectRequest {
            host: "myhost.internal".into(),
            port: 11211,
            tls: false,
            sni_override: None,
            credential_id: None,
        };
        let dbg = format!("{req:?}");
        assert!(dbg.contains("myhost.internal"));
    }

    // ── New batch: HttpHeader variations ──

    #[test]
    fn test_http_header_clone_preserves_value() {
        let original = HttpHeader {
            name: "X-Request-Id".into(),
            value: "abc-123-def".into(),
        };
        let cloned = original.clone();
        assert_eq!(original.name, "X-Request-Id");
        assert_eq!(cloned.value, "abc-123-def");
    }

    #[test]
    fn test_http_header_debug_shows_name() {
        let h = HttpHeader {
            name: "X-Trace-Id".into(),
            value: "trace-xyz".into(),
        };
        let dbg = format!("{h:?}");
        assert!(dbg.contains("X-Trace-Id"));
    }

    // ── New batch: DenyReason traits ──

    #[test]
    fn test_deny_reason_copy_port_not_allowed() {
        let reason = DenyReason::PortNotAllowed;
        let copied = reason;
        let copied2 = reason;
        assert_eq!(copied, DenyReason::PortNotAllowed);
        assert_eq!(copied2, DenyReason::PortNotAllowed);
    }

    #[test]
    fn test_deny_reason_debug_max_redirects() {
        let reason = DenyReason::MaxRedirectsExceeded;
        let dbg = format!("{reason:?}");
        assert!(dbg.contains("MaxRedirectsExceeded"));
    }

    // ── New batch: EgressError debug coverage ──

    #[test]
    fn test_egress_error_debug_invalid_url() {
        let e = EgressError::InvalidUrl("bad://url".into());
        let dbg = format!("{e:?}");
        assert!(dbg.contains("InvalidUrl"));
    }

    #[test]
    fn test_egress_error_debug_tls_failed() {
        let e = EgressError::TlsVerificationFailed("cert expired".into());
        let dbg = format!("{e:?}");
        assert!(dbg.contains("TlsVerificationFailed"));
    }

    // ── New batch: Verifier/Injector trait objects ──

    #[test]
    fn test_default_tls_verifier_debug_repr() {
        let v = DefaultTlsVerifier;
        let dbg = format!("{v:?}");
        assert_eq!(dbg, "DefaultTlsVerifier");
    }

    #[test]
    fn test_default_tls_verifier_default_construction() {
        let v = DefaultTlsVerifier;
        // Verify it works correctly
        assert!(v.verify_sni("same.com", "same.com").is_ok());
    }

    #[test]
    fn test_noop_injector_debug_repr() {
        let inj = NoOpCredentialInjector;
        let dbg = format!("{inj:?}");
        assert_eq!(dbg, "NoOpCredentialInjector");
    }

    #[test]
    fn test_noop_injector_default_always_denies() {
        let inj = NoOpCredentialInjector;
        let result = inj.is_authorized("cred", "op", &["cred".into()]);
        assert!(!result.unwrap());
    }

    // ── New batch: EgressGuard ──

    #[test]
    fn test_egress_guard_debug_repr() {
        let guard = EgressGuard::new();
        let dbg = format!("{guard:?}");
        assert_eq!(dbg, "EgressGuard");
    }

    // ── New batch: IPv6 CIDR checks ──

    #[test]
    fn test_check_ip_ipv6_google_public_allowed() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();
        let result =
            guard.check_ip_constraints("2001:4860:4860::8844".parse().unwrap(), &constraints);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_ip_ipv6_loopback_denied_code() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();
        let result = guard.check_ip_constraints("::1".parse().unwrap(), &constraints);
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::LocalhostDenied);
        } else {
            panic!("expected Denied");
        }
    }

    #[test]
    fn test_check_ip_ipv6_unspecified_denied_code() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();
        let result = guard.check_ip_constraints("::".parse().unwrap(), &constraints);
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::LocalhostDenied);
        } else {
            panic!("expected Denied");
        }
    }

    #[test]
    fn test_check_ip_ipv6_fe80_link_local_denied_code() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();
        let result = guard.check_ip_constraints("fe80::9999".parse().unwrap(), &constraints);
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::LinkLocalDenied);
        } else {
            panic!("expected Denied");
        }
    }

    #[test]
    fn test_check_ip_tailnet_ipv6_fd7a_denied_code() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        // Disable private range check so tailnet check is reached
        // (fd7a:115c:a1e0::/48 is inside fc00::/7 ULA)
        constraints.deny_private_ranges = false;
        let result =
            guard.check_ip_constraints("fd7a:115c:a1e0::99".parse().unwrap(), &constraints);
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::TailnetRangeDenied);
        } else {
            panic!("expected Denied");
        }
    }

    // ── New batch: EgressRequest variant matching ──

    #[test]
    fn test_egress_request_http_variant_clone_roundtrip() {
        let req = EgressRequest::Http(EgressHttpRequest {
            url: "https://roundtrip.test/".into(),
            method: "HEAD".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });
        let cloned = req.clone();
        if let EgressRequest::Http(http) = &req {
            assert_eq!(http.method, "HEAD");
        } else {
            panic!("expected Http");
        }
        drop(cloned);
    }

    #[test]
    fn test_egress_request_tcp_variant_clone_roundtrip() {
        let req = EgressRequest::TcpConnect(EgressTcpConnectRequest {
            host: "roundtrip.tcp".into(),
            port: 11211,
            tls: false,
            sni_override: None,
            credential_id: None,
        });
        let cloned = req.clone();
        if let EgressRequest::TcpConnect(tcp) = &req {
            assert_eq!(tcp.host, "roundtrip.tcp");
        } else {
            panic!("expected TcpConnect");
        }
        drop(cloned);
    }

    #[test]
    fn test_egress_request_debug_http_variant() {
        let req = EgressRequest::Http(EgressHttpRequest {
            url: "https://variant.req/".into(),
            method: "TRACE".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });
        let dbg = format!("{req:?}");
        assert!(dbg.contains("TRACE"));
    }

    #[test]
    fn test_egress_request_debug_tcp_variant() {
        let req = EgressRequest::TcpConnect(EgressTcpConnectRequest {
            host: "variant.tcp".into(),
            port: 5555,
            tls: true,
            sni_override: None,
            credential_id: None,
        });
        let dbg = format!("{req:?}");
        assert!(dbg.contains("5555"));
    }

    // ── New batch: DNS resolution single-element ──

    #[test]
    fn test_validate_dns_single_cloudflare_ip() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();
        let ips: Vec<IpAddr> = vec!["1.0.0.1".parse().unwrap()];
        let result = guard.validate_dns_resolution(&ips, &constraints);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1);
    }

    #[test]
    fn test_validate_dns_single_rfc1918_denied() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();
        let ips: Vec<IpAddr> = vec!["172.16.0.1".parse().unwrap()];
        let result = guard.validate_dns_resolution(&ips, &constraints);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::PrivateRangeDenied);
        }
    }

    // ── New batch: evaluate port 8443 ──

    #[test]
    fn test_evaluate_port_8443_with_tls() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();
        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://api.example.com:8443/v2/data".into(),
            method: "POST".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });
        let decision = guard.evaluate(&request, &constraints).unwrap();
        assert_eq!(decision.port, 8443);
        assert!(decision.tls_required);
    }

    // ── New batch: hostname canonical checks ──

    #[test]
    fn test_is_hostname_canonical_lowercase_subdomain() {
        assert!(is_hostname_canonical("sub.domain.example.com"));
    }

    #[test]
    fn test_is_hostname_canonical_with_digits() {
        assert!(is_hostname_canonical("api2.v3.example.com"));
    }

    #[test]
    fn test_is_hostname_canonical_with_dashes() {
        assert!(is_hostname_canonical("my-api.example-domain.com"));
    }

    #[test]
    fn test_is_hostname_canonical_single_word() {
        assert!(is_hostname_canonical("localhost"));
    }

    // === br-45tjy: ip_allow enforced against every DNS-resolved IP ===

    #[test]
    fn validate_dns_resolution_rejects_public_ip_outside_ip_allow() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        // Pin the allow-list to a single public IP — DNS returning any
        // other public address MUST be rejected pre-45tjy this slipped
        // through because only CIDR deny rules were checked post-DNS.
        constraints.ip_allow = vec!["93.184.216.34".parse().unwrap()];

        let ips = vec!["93.184.216.34".parse().unwrap(), "8.8.8.8".parse().unwrap()];
        let err = guard
            .validate_dns_resolution(&ips, &constraints)
            .expect_err("DNS answer outside ip_allow must fail closed");
        match err {
            EgressError::Denied { reason, code } => {
                assert_eq!(code, DenyReason::IpNotAllowed);
                assert!(
                    reason.contains("8.8.8.8"),
                    "reason must name offending IP: {reason}"
                );
            }
            other => panic!("expected Denied{{IpNotAllowed}}, got {other:?}"),
        }
    }

    #[test]
    fn validate_dns_resolution_accepts_every_ip_when_ip_allow_is_empty() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        assert!(
            constraints.ip_allow.is_empty(),
            "baseline: allow-list empty"
        );
        // Any public IPv4 that is not localhost / private / tailnet
        // must pass when ip_allow is unset — no regression on the open
        // default.
        constraints.deny_localhost = false;
        constraints.deny_private_ranges = false;
        constraints.deny_tailnet_ranges = false;
        let ips = vec!["8.8.8.8".parse().unwrap(), "1.1.1.1".parse().unwrap()];
        let ok = guard
            .validate_dns_resolution(&ips, &constraints)
            .expect("empty ip_allow => open default");
        assert_eq!(ok.len(), 2);
    }

    #[test]
    fn validate_dns_resolution_accepts_only_listed_ips() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.ip_allow = vec![
            "93.184.216.34".parse().unwrap(),
            "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap(),
        ];
        let ips = vec![
            "93.184.216.34".parse().unwrap(),
            "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap(),
        ];
        let ok = guard
            .validate_dns_resolution(&ips, &constraints)
            .expect("all resolved IPs on the allow-list must be accepted");
        assert_eq!(ok.len(), 2);
    }

    #[test]
    fn validate_dns_resolution_rejects_ipv4_mapped_ipv6_outside_ip_allow() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        // ip_allow pinned to a pure IPv4; an IPv4-mapped IPv6 for a
        // DIFFERENT address must be rejected (mapping must not become
        // an escape hatch).
        constraints.ip_allow = vec!["93.184.216.34".parse().unwrap()];
        let ips = vec!["::ffff:8.8.8.8".parse().unwrap()];
        let err = guard
            .validate_dns_resolution(&ips, &constraints)
            .expect_err("IPv4-mapped IPv6 for an unlisted address must fail closed");
        assert!(matches!(
            err,
            EgressError::Denied {
                code: DenyReason::IpNotAllowed,
                ..
            }
        ));
    }

    #[test]
    fn validate_dns_resolution_accepts_ipv4_mapped_ipv6_of_listed_ipv4() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.ip_allow = vec!["93.184.216.34".parse().unwrap()];
        // The resolver returned the IPv4-mapped IPv6 form of the listed
        // IPv4 address — the normalization path must accept it.
        let ips = vec!["::ffff:93.184.216.34".parse().unwrap()];
        let ok = guard
            .validate_dns_resolution(&ips, &constraints)
            .expect("IPv4-mapped IPv6 of an allow-listed IPv4 must be accepted");
        assert_eq!(ok.len(), 1);
    }

    #[test]
    fn ip_allow_contains_normalizes_ipv4_mapped_v6_in_allow_list() {
        let allow: Vec<IpAddr> = vec!["::ffff:93.184.216.34".parse().unwrap()];
        let pure_v4: IpAddr = "93.184.216.34".parse().unwrap();
        assert!(
            ip_allow_contains(&allow, pure_v4),
            "mapped v6 in allow-list must match pure v4 resolution"
        );
    }
}
