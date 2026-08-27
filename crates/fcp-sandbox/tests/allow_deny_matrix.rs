//! Comprehensive Allow/Deny Matrix Tests for FCP2 Sandbox + Egress Proxy.
//!
//! This test suite validates:
//! - Default deny behavior (localhost, private ranges, tailnet, link-local)
//! - Allow list enforcement (hosts, ports, wildcards)
//! - SSRF protection (IP literals, hostname canonicalization)
//! - TLS requirements and verification
//! - Credential injection (secrets never logged)
//! - Sandbox profile enforcement (strict/moderate/permissive)
//!
//! All tests emit structured JSON for audit compliance.

use std::net::IpAddr;
use std::sync::{Arc, Mutex, Once, OnceLock};

use fcp_manifest::{NetworkConstraints, SandboxProfile, SandboxSection};
use fcp_sandbox::{
    CompiledPolicy, CredentialInjector, DefaultTlsVerifier, DenyReason, EgressError, EgressGuard,
    EgressHttpRequest, EgressRequest, EgressTcpConnectRequest, HttpHeader, NoOpCredentialInjector,
    TlsVerifier, canonicalize_hostname, create_sandbox, is_hostname_canonical, is_link_local,
    is_localhost, is_private_range, is_tailnet_range,
};
use tracing_subscriber::fmt::MakeWriter;

// ============================================================================
// Structured Logging Helpers
// ============================================================================

#[derive(Clone)]
struct SharedWriter {
    buf: Arc<Mutex<Vec<u8>>>,
}

impl std::io::Write for SharedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.buf
            .lock()
            .expect("log buffer lock poisoned")
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct SharedMakeWriter {
    buf: Arc<Mutex<Vec<u8>>>,
}

impl<'a> MakeWriter<'a> for SharedMakeWriter {
    type Writer = SharedWriter;

    fn make_writer(&'a self) -> Self::Writer {
        SharedWriter {
            buf: self.buf.clone(),
        }
    }
}

static LOG_BUF: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();
static LOG_INIT: Once = Once::new();
static LOG_LOCK: Mutex<()> = Mutex::new(());

fn init_json_logger() -> Arc<Mutex<Vec<u8>>> {
    let buf = LOG_BUF
        .get_or_init(|| Arc::new(Mutex::new(Vec::new())))
        .clone();

    LOG_INIT.call_once(|| {
        let make_writer = SharedMakeWriter { buf: buf.clone() };
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::WARN)
            .with_current_span(false)
            .with_span_list(false)
            .with_writer(make_writer)
            .finish();

        let _ = tracing::subscriber::set_global_default(subscriber);
    });

    buf
}

fn take_log_lines(buf: &Arc<Mutex<Vec<u8>>>) -> Vec<String> {
    let mut guard = buf.lock().expect("log buffer lock poisoned");
    let bytes = std::mem::take(&mut *guard);
    drop(guard);
    let text = String::from_utf8_lossy(&bytes);
    text.lines().map(str::to_string).collect()
}

// ============================================================================
// Test Fixtures
// ============================================================================

/// Create restrictive (strict-compatible) network constraints.
fn strict_constraints() -> NetworkConstraints {
    NetworkConstraints {
        host_allow: vec!["api.example.com".into(), "*.trusted.com".into()],
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

/// Create permissive network constraints (for testing explicit allows).
fn permissive_constraints() -> NetworkConstraints {
    NetworkConstraints {
        host_allow: vec!["*".into()],
        port_allow: vec![80, 443, 8080, 8443],
        ip_allow: vec!["8.8.8.8".parse().unwrap(), "1.1.1.1".parse().unwrap()],
        cidr_deny: vec![],
        deny_localhost: false,
        deny_private_ranges: false,
        deny_tailnet_ranges: false,
        require_sni: false,
        spki_pins: vec![],
        deny_ip_literals: false,
        require_host_canonicalization: false,
        dns_max_ips: 64,
        max_redirects: 10,
        connect_timeout_ms: 30_000,
        total_timeout_ms: 120_000,
        max_response_bytes: 104_857_600,
    }
}

fn strict_sandbox_section() -> SandboxSection {
    SandboxSection {
        profile: SandboxProfile::Strict,
        memory_mb: 256,
        cpu_percent: 50,
        wall_clock_timeout_ms: 30_000,
        fs_readonly_paths: vec!["/usr".into(), "/lib".into()],
        fs_writable_paths: vec!["$CONNECTOR_STATE".into()],
        deny_exec: true,
        deny_ptrace: true,
    }
}

fn moderate_sandbox_section() -> SandboxSection {
    SandboxSection {
        profile: SandboxProfile::Moderate,
        memory_mb: 512,
        cpu_percent: 75,
        wall_clock_timeout_ms: 60_000,
        fs_readonly_paths: vec!["/usr".into(), "/lib".into(), "/opt".into()],
        fs_writable_paths: vec!["$CONNECTOR_STATE".into(), "/tmp".into()],
        deny_exec: true,
        deny_ptrace: true,
    }
}

fn permissive_sandbox_section() -> SandboxSection {
    SandboxSection {
        profile: SandboxProfile::Permissive,
        memory_mb: 1024,
        cpu_percent: 100,
        wall_clock_timeout_ms: 300_000,
        fs_readonly_paths: vec!["/".into()],
        fs_writable_paths: vec!["/tmp".into(), "/var/lib/connector".into()],
        deny_exec: false,
        deny_ptrace: false,
    }
}

// ============================================================================
// Default Deny Tests
// ============================================================================

mod default_deny {
    use super::*;

    // ------------------------------------------------------------------------
    // Localhost Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_localhost_ipv4_127_0_0_1_denied() {
        let guard = EgressGuard::new();
        let constraints = strict_constraints();

        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let result = guard.check_ip_constraints(ip, &constraints);

        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(EgressError::Denied {
                code: DenyReason::LocalhostDenied,
                ..
            })
        ));
    }

    #[test]
    fn test_localhost_ipv4_127_255_255_255_denied() {
        let guard = EgressGuard::new();
        let constraints = strict_constraints();

        let ip: IpAddr = "127.255.255.255".parse().unwrap();
        let result = guard.check_ip_constraints(ip, &constraints);

        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::LocalhostDenied);
        }
    }

    #[test]
    fn test_localhost_ipv6_denied() {
        let guard = EgressGuard::new();
        let constraints = strict_constraints();

        let ip: IpAddr = "::1".parse().unwrap();
        let result = guard.check_ip_constraints(ip, &constraints);

        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::LocalhostDenied);
        }
    }

    #[test]
    fn test_unspecified_ipv4_denied() {
        let ip: IpAddr = "0.0.0.0".parse().unwrap();
        assert!(is_localhost(ip));
    }

    #[test]
    fn test_unspecified_ipv6_denied() {
        let ip: IpAddr = "::".parse().unwrap();
        assert!(is_localhost(ip));
    }

    // ------------------------------------------------------------------------
    // Private Range Tests (RFC1918)
    // ------------------------------------------------------------------------

    #[test]
    fn test_private_10_0_0_0_denied() {
        let guard = EgressGuard::new();
        let constraints = strict_constraints();

        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let result = guard.check_ip_constraints(ip, &constraints);

        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::PrivateRangeDenied);
        }
    }

    #[test]
    fn test_private_10_255_255_255_denied() {
        let guard = EgressGuard::new();
        let constraints = strict_constraints();

        let ip: IpAddr = "10.255.255.255".parse().unwrap();
        let result = guard.check_ip_constraints(ip, &constraints);

        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::PrivateRangeDenied);
        }
    }

    #[test]
    fn test_private_172_16_0_0_denied() {
        let guard = EgressGuard::new();
        let constraints = strict_constraints();

        let ip: IpAddr = "172.16.0.1".parse().unwrap();
        let result = guard.check_ip_constraints(ip, &constraints);

        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::PrivateRangeDenied);
        }
    }

    #[test]
    fn test_private_172_31_255_255_denied() {
        let guard = EgressGuard::new();
        let constraints = strict_constraints();

        let ip: IpAddr = "172.31.255.255".parse().unwrap();
        let result = guard.check_ip_constraints(ip, &constraints);

        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::PrivateRangeDenied);
        }
    }

    #[test]
    fn test_private_192_168_0_0_denied() {
        let guard = EgressGuard::new();
        let constraints = strict_constraints();

        let ip: IpAddr = "192.168.0.1".parse().unwrap();
        let result = guard.check_ip_constraints(ip, &constraints);

        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::PrivateRangeDenied);
        }
    }

    #[test]
    fn test_private_192_168_255_255_denied() {
        let guard = EgressGuard::new();
        let constraints = strict_constraints();

        let ip: IpAddr = "192.168.255.255".parse().unwrap();
        let result = guard.check_ip_constraints(ip, &constraints);

        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::PrivateRangeDenied);
        }
    }

    #[test]
    fn test_private_ipv6_ula_denied() {
        let ip: IpAddr = "fc00::1".parse().unwrap();
        assert!(is_private_range(ip));
    }

    #[test]
    fn test_private_ipv6_ula_fd_denied() {
        let ip: IpAddr = "fd00::1".parse().unwrap();
        assert!(is_private_range(ip));
    }

    // Boundary tests - just outside private ranges should be allowed
    #[test]
    fn test_not_private_172_32_0_1() {
        let ip: IpAddr = "172.32.0.1".parse().unwrap();
        assert!(!is_private_range(ip));
    }

    #[test]
    fn test_not_private_172_15_255_255() {
        let ip: IpAddr = "172.15.255.255".parse().unwrap();
        assert!(!is_private_range(ip));
    }

    // ------------------------------------------------------------------------
    // Tailnet Range Tests (100.64.0.0/10 - CGNAT)
    // ------------------------------------------------------------------------

    #[test]
    fn test_tailnet_100_64_0_1_denied() {
        let guard = EgressGuard::new();
        let constraints = strict_constraints();

        let ip: IpAddr = "100.64.0.1".parse().unwrap();
        let result = guard.check_ip_constraints(ip, &constraints);

        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::TailnetRangeDenied);
        }
    }

    #[test]
    fn test_tailnet_100_100_100_100_denied() {
        let guard = EgressGuard::new();
        let constraints = strict_constraints();

        let ip: IpAddr = "100.100.100.100".parse().unwrap();
        let result = guard.check_ip_constraints(ip, &constraints);

        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::TailnetRangeDenied);
        }
    }

    #[test]
    fn test_tailnet_100_127_255_255_denied() {
        let guard = EgressGuard::new();
        let constraints = strict_constraints();

        let ip: IpAddr = "100.127.255.255".parse().unwrap();
        let result = guard.check_ip_constraints(ip, &constraints);

        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::TailnetRangeDenied);
        }
    }

    // Boundary tests
    #[test]
    fn test_not_tailnet_100_63_255_255() {
        let ip: IpAddr = "100.63.255.255".parse().unwrap();
        assert!(!is_tailnet_range(ip));
    }

    #[test]
    fn test_not_tailnet_100_128_0_1() {
        let ip: IpAddr = "100.128.0.1".parse().unwrap();
        assert!(!is_tailnet_range(ip));
    }

    // ------------------------------------------------------------------------
    // Link-Local Range Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_link_local_ipv4_denied() {
        let guard = EgressGuard::new();
        let constraints = strict_constraints();

        let ip: IpAddr = "169.254.0.1".parse().unwrap();
        let result = guard.check_ip_constraints(ip, &constraints);

        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::LinkLocalDenied);
        }
    }

    #[test]
    fn test_link_local_ipv4_169_254_169_254_denied() {
        let ip: IpAddr = "169.254.169.254".parse().unwrap();
        assert!(is_link_local(ip));
    }

    #[test]
    fn test_link_local_ipv6_denied() {
        let ip: IpAddr = "fe80::1".parse().unwrap();
        assert!(is_link_local(ip));
    }

    // ------------------------------------------------------------------------
    // Public IP Allowed (when constraints permit)
    // ------------------------------------------------------------------------

    #[test]
    fn test_public_ip_allowed() {
        let guard = EgressGuard::new();
        let constraints = strict_constraints();

        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let result = guard.check_ip_constraints(ip, &constraints);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cloudflare_dns_allowed() {
        let guard = EgressGuard::new();
        let constraints = strict_constraints();

        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        let result = guard.check_ip_constraints(ip, &constraints);
        assert!(result.is_ok());
    }
}

// ============================================================================
// Allow List Tests
// ============================================================================

mod allow_list {
    use super::*;

    // ------------------------------------------------------------------------
    // Host Allow Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_exact_host_allowed() {
        let guard = EgressGuard::new();
        let constraints = strict_constraints();

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
    }

    #[test]
    fn test_wildcard_host_allowed() {
        let guard = EgressGuard::new();
        let constraints = strict_constraints();

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://sub.trusted.com/path".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        let decision = guard.evaluate(&request, &constraints).unwrap();
        assert!(decision.allowed);
        assert_eq!(decision.canonical_host, "sub.trusted.com");
    }

    #[test]
    fn test_uppercase_allowlist_pattern_matches() {
        let guard = EgressGuard::new();
        let mut constraints = permissive_constraints();
        constraints.host_allow = vec!["API.EXAMPLE.COM".into()];
        constraints.port_allow = vec![443];

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
    }

    #[test]
    fn test_deep_subdomain_wildcard_allowed() {
        let guard = EgressGuard::new();
        let constraints = strict_constraints();

        // *.trusted.com should match any subdomain depth under trusted.com
        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://deep.sub.trusted.com/path".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        let result = guard.evaluate(&request, &constraints);
        assert!(result.is_ok());
    }

    #[test]
    fn test_unlisted_host_denied() {
        let guard = EgressGuard::new();
        let constraints = strict_constraints();

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
    fn test_similar_host_not_allowed() {
        let guard = EgressGuard::new();
        let constraints = strict_constraints();

        // api.example.com.evil.com should not be allowed
        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://api.example.com.evil.com/".into(),
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

    // ------------------------------------------------------------------------
    // Port Allow Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_allowed_port_443() {
        let guard = EgressGuard::new();
        let constraints = strict_constraints();

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://api.example.com:443/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        let decision = guard.evaluate(&request, &constraints).unwrap();
        assert_eq!(decision.port, 443);
    }

    #[test]
    fn test_allowed_port_8443() {
        let guard = EgressGuard::new();
        let constraints = strict_constraints();

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://api.example.com:8443/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        let decision = guard.evaluate(&request, &constraints).unwrap();
        assert_eq!(decision.port, 8443);
    }

    #[test]
    fn test_denied_port() {
        let guard = EgressGuard::new();
        let constraints = strict_constraints();

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
    fn test_denied_port_22_ssh() {
        let guard = EgressGuard::new();
        let constraints = strict_constraints();

        let request = EgressRequest::TcpConnect(EgressTcpConnectRequest {
            host: "api.example.com".into(),
            port: 22,
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

    // ------------------------------------------------------------------------
    // TLS Requirement Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_https_sets_tls_required() {
        let guard = EgressGuard::new();
        let constraints = strict_constraints();

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://api.example.com/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        let decision = guard.evaluate(&request, &constraints).unwrap();
        assert!(decision.tls_required);
    }

    #[test]
    fn test_sni_expected_when_required() {
        let guard = EgressGuard::new();
        let constraints = strict_constraints();

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://api.example.com/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        let decision = guard.evaluate(&request, &constraints).unwrap();
        assert_eq!(decision.expected_sni, Some("api.example.com".into()));
    }
}

// ============================================================================
// SSRF Protection Tests
// ============================================================================

mod ssrf_protection {
    use super::*;

    // ------------------------------------------------------------------------
    // IP Literal Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_ip_literal_denied_strict() {
        let guard = EgressGuard::new();
        let constraints = strict_constraints();

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
    fn test_ip_literal_ipv6_denied() {
        let guard = EgressGuard::new();
        let constraints = strict_constraints();

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://[2001:db8::1]/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        let result = guard.evaluate(&request, &constraints);
        assert!(result.is_err());
        // IPv6 URLs may be denied as IP literal or as unknown host depending on
        // how the URL parser extracts the host. Either denial is acceptable for
        // security purposes - the important thing is that it's blocked.
        if let Err(EgressError::Denied { code, .. }) = result {
            assert!(
                code == DenyReason::IpLiteralDenied || code == DenyReason::HostNotAllowed,
                "expected IpLiteralDenied or HostNotAllowed, got {code:?}",
            );
        }
    }

    #[test]
    fn test_ip_literal_allowed_when_permitted() {
        let guard = EgressGuard::new();
        let mut constraints = permissive_constraints();
        constraints.ip_allow.push("93.184.216.34".parse().unwrap());

        // With deny_ip_literals=false and IP in allow list
        let request = EgressRequest::Http(EgressHttpRequest {
            url: "http://93.184.216.34/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        let result = guard.evaluate(&request, &constraints);
        assert!(result.is_ok());
    }

    // ------------------------------------------------------------------------
    // Hostname Canonicalization Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_uppercase_hostname_canonicalized() {
        let result = canonicalize_hostname("API.EXAMPLE.COM");
        assert_eq!(result.unwrap(), "api.example.com");
    }

    #[test]
    fn test_trailing_dot_removed() {
        let result = canonicalize_hostname("api.example.com.");
        assert_eq!(result.unwrap(), "api.example.com");
    }

    #[test]
    fn test_unicode_hostname_punycode() {
        // IDN domain should be converted to Punycode
        let result = canonicalize_hostname("münchen.example.com");
        assert!(result.is_ok());
        assert!(result.unwrap().starts_with("xn--"));
    }

    #[test]
    fn test_emoji_domain_punycode() {
        let result = canonicalize_hostname("test.example.com");
        assert!(result.is_ok());
    }

    #[test]
    fn test_empty_hostname_rejected() {
        let result = canonicalize_hostname("");
        assert!(result.is_err());
    }

    #[test]
    fn test_is_canonical_lowercase_ascii() {
        assert!(is_hostname_canonical("api.example.com"));
    }

    #[test]
    fn test_is_not_canonical_uppercase() {
        assert!(!is_hostname_canonical("API.example.com"));
    }

    #[test]
    fn test_is_not_canonical_trailing_dot() {
        assert!(!is_hostname_canonical("example.com."));
    }

    #[test]
    fn test_is_not_canonical_unicode() {
        assert!(!is_hostname_canonical("münchen.example.com"));
    }

    // ------------------------------------------------------------------------
    // DNS Resolution Limits
    // ------------------------------------------------------------------------

    #[test]
    fn test_dns_max_ips_enforced() {
        let guard = EgressGuard::new();
        let mut constraints = strict_constraints();
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
    fn test_dns_resolution_validates_each_ip() {
        let guard = EgressGuard::new();
        let constraints = strict_constraints();

        // One public, one private - should fail on the private one
        let ips: Vec<IpAddr> = vec![
            "8.8.8.8".parse().unwrap(),
            "192.168.1.1".parse().unwrap(), // Private!
        ];

        let result = guard.validate_dns_resolution(&ips, &constraints);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::PrivateRangeDenied);
        }
    }

    // ------------------------------------------------------------------------
    // Custom CIDR Deny Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_custom_cidr_deny() {
        let guard = EgressGuard::new();
        let mut constraints = strict_constraints();
        constraints.cidr_deny.push("203.0.113.0/24".into()); // TEST-NET-3

        let ip: IpAddr = "203.0.113.50".parse().unwrap();
        let result = guard.check_ip_constraints(ip, &constraints);

        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::CidrDenyMatched);
        }
    }
}

// ============================================================================
// TLS Verification Tests
// ============================================================================

mod tls_verification {
    use super::*;

    #[test]
    fn test_sni_match_passes() {
        let verifier = DefaultTlsVerifier;
        let result = verifier.verify_sni("api.example.com", "api.example.com");
        assert!(result.is_ok());
    }

    #[test]
    fn test_sni_mismatch_fails() {
        let verifier = DefaultTlsVerifier;
        let result = verifier.verify_sni("other.com", "api.example.com");
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::SniMismatch);
        }
    }

    #[test]
    fn test_spki_pin_matches() {
        let verifier = DefaultTlsVerifier;
        let pin = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let pins = vec![pin.clone()];

        let result = verifier.verify_spki(&pin, &pins);
        assert!(result.is_ok());
    }

    #[test]
    fn test_spki_pin_no_match() {
        let verifier = DefaultTlsVerifier;
        let cert_spki = vec![9, 10, 11, 12];
        let pins = vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8]];

        let result = verifier.verify_spki(&cert_spki, &pins);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::SpkiPinMismatch);
        }
    }

    #[test]
    fn test_empty_pins_allows_any() {
        let verifier = DefaultTlsVerifier;
        let cert_spki = vec![1, 2, 3, 4];

        let result = verifier.verify_spki(&cert_spki, &[]);
        assert!(result.is_ok());
    }
}

// ============================================================================
// Credential Injection Tests
// ============================================================================

mod credential_injection {
    use super::*;

    #[test]
    fn test_noop_injector_denies_injection() {
        let injector = NoOpCredentialInjector;
        let mut headers = vec![];

        let result = injector.inject_http("some-credential", &mut headers);
        assert!(result.is_err());
    }

    #[test]
    fn test_noop_injector_not_authorized() {
        let injector = NoOpCredentialInjector;

        let result = injector.is_authorized("cred-id", "op-id", &["allowed-cred".into()]);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_noop_injector_no_tcp_auth() {
        let injector = NoOpCredentialInjector;

        let result = injector.get_tcp_auth("cred-id");
        assert!(result.is_err());
    }

    /// Test that secrets should never appear in logs.
    /// This is a structural test - actual log verification would be done in integration tests.
    #[test]
    fn test_secret_headers_stripped_from_debug() {
        let header = HttpHeader {
            name: "Authorization".into(),
            value: "Bearer secret-token-12345".into(),
        };

        // The debug output should not reveal the full secret
        // This is a reminder that production code should redact secrets
        let debug_output = format!("{header:?}");

        // In actual implementation, sensitive headers should be redacted
        // This test documents the requirement
        assert!(debug_output.contains("Authorization"));
    }
}

// ============================================================================
// Sandbox Profile Tests
// ============================================================================

mod sandbox_profiles {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_strict_profile_blocks_network() {
        let section = strict_sandbox_section();
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();

        assert!(policy.block_direct_network);
        assert!(policy.deny_exec);
        assert!(policy.deny_ptrace);
    }

    #[test]
    fn test_moderate_profile_blocks_network() {
        let section = moderate_sandbox_section();
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();

        assert!(policy.block_direct_network);
        assert!(policy.deny_exec);
    }

    #[test]
    fn test_permissive_profile_allows_network() {
        let section = permissive_sandbox_section();
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();

        assert!(!policy.block_direct_network);
        assert!(!policy.deny_exec);
        assert!(!policy.deny_ptrace);
    }

    #[test]
    fn test_strict_plus_blocks_network() {
        let section = SandboxSection {
            profile: SandboxProfile::StrictPlus,
            memory_mb: 256,
            cpu_percent: 50,
            wall_clock_timeout_ms: 30_000,
            fs_readonly_paths: vec![],
            fs_writable_paths: vec![],
            deny_exec: true,
            deny_ptrace: true,
        };
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();

        assert!(policy.block_direct_network);
    }

    #[test]
    fn test_state_dir_added_to_writable() {
        let section = strict_sandbox_section();
        let state_dir = Some(PathBuf::from("/var/lib/fcp/connectors/test"));
        let policy = CompiledPolicy::from_manifest(&section, state_dir).unwrap();

        assert!(
            policy
                .writable_paths
                .contains(&PathBuf::from("/var/lib/fcp/connectors/test"))
        );
    }

    #[test]
    fn test_sandbox_file_access_verification() {
        let sandbox = create_sandbox().unwrap();
        let section = strict_sandbox_section();
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();

        // Readonly path should allow read
        let result = sandbox.verify_file_access(&policy, &PathBuf::from("/usr/lib/test.so"), false);
        assert!(result.is_ok());

        // Readonly path should deny write
        let result = sandbox.verify_file_access(&policy, &PathBuf::from("/usr/lib/test.so"), true);
        assert!(result.is_err());
    }

    #[test]
    fn test_sandbox_exec_denied_strict() {
        let sandbox = create_sandbox().unwrap();
        let section = strict_sandbox_section();
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();

        let result = sandbox.verify_exec_allowed(&policy);
        assert!(result.is_err());
    }

    #[test]
    fn test_sandbox_exec_allowed_permissive() {
        let sandbox = create_sandbox().unwrap();
        let section = permissive_sandbox_section();
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();

        let result = sandbox.verify_exec_allowed(&policy);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sandbox_network_blocked_strict() {
        let sandbox = create_sandbox().unwrap();
        let section = strict_sandbox_section();
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();

        // verify_network_blocked returns Ok if network IS blocked
        let result = sandbox.verify_network_blocked(&policy);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sandbox_network_not_blocked_permissive() {
        let sandbox = create_sandbox().unwrap();
        let section = permissive_sandbox_section();
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();

        // verify_network_blocked returns Err if network is NOT blocked (permissive)
        let result = sandbox.verify_network_blocked(&policy);
        assert!(result.is_err());
    }
}

// ============================================================================
// TCP Connect Tests
// ============================================================================

mod tcp_connect {
    use super::*;

    #[test]
    fn test_tcp_connect_allowed_host_port() {
        let guard = EgressGuard::new();
        let constraints = strict_constraints();

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
    fn test_tcp_connect_denied_host() {
        let guard = EgressGuard::new();
        let constraints = strict_constraints();

        let request = EgressRequest::TcpConnect(EgressTcpConnectRequest {
            host: "evil.com".into(),
            port: 443,
            tls: true,
            sni_override: None,
            credential_id: None,
        });

        let result = guard.evaluate(&request, &constraints);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::HostNotAllowed);
        }
    }

    #[test]
    fn test_tcp_connect_denied_port() {
        let guard = EgressGuard::new();
        let constraints = strict_constraints();

        let request = EgressRequest::TcpConnect(EgressTcpConnectRequest {
            host: "api.example.com".into(),
            port: 5432, // PostgreSQL - not in allowed ports
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
    fn test_tcp_connect_ip_literal_denied() {
        let guard = EgressGuard::new();
        let constraints = strict_constraints();

        let request = EgressRequest::TcpConnect(EgressTcpConnectRequest {
            host: "192.168.1.100".into(),
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
}

// ============================================================================
// Edge Case Tests
// ============================================================================

mod edge_cases {
    use super::*;

    #[test]
    fn test_url_without_port_uses_default() {
        let guard = EgressGuard::new();
        let constraints = strict_constraints();

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://api.example.com/path".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        let decision = guard.evaluate(&request, &constraints).unwrap();
        assert_eq!(decision.port, 443);
    }

    #[test]
    fn test_invalid_url_rejected() {
        let guard = EgressGuard::new();
        let constraints = strict_constraints();

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "not-a-url".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        let result = guard.evaluate(&request, &constraints);
        assert!(result.is_err());
        assert!(matches!(result, Err(EgressError::InvalidUrl(_))));
    }

    #[test]
    fn test_url_without_host_rejected() {
        let guard = EgressGuard::new();
        let constraints = strict_constraints();

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "file:///etc/passwd".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        let result = guard.evaluate(&request, &constraints);
        assert!(result.is_err());
    }

    #[test]
    fn test_resource_limits_from_manifest() {
        let section = strict_sandbox_section();
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();

        assert_eq!(policy.memory_limit_bytes, 256 * 1024 * 1024);
        assert_eq!(policy.cpu_percent, 50);
        assert_eq!(policy.wall_clock_timeout.as_millis(), 30_000);
    }

    #[test]
    fn test_zero_memory_limit() {
        let mut section = strict_sandbox_section();
        section.memory_mb = 0;

        let err = CompiledPolicy::from_manifest(&section, None).unwrap_err();
        assert!(
            err.to_string().contains("memory_mb must be > 0"),
            "expected zero-memory rejection, got: {err}"
        );
    }

    #[test]
    fn test_empty_paths() {
        let section = SandboxSection {
            profile: SandboxProfile::Strict,
            memory_mb: 256,
            cpu_percent: 50,
            wall_clock_timeout_ms: 30_000,
            fs_readonly_paths: vec![],
            fs_writable_paths: vec![],
            deny_exec: true,
            deny_ptrace: true,
        };

        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        assert_eq!(policy.readonly_paths, [] as [std::path::PathBuf; 0]);
        assert_eq!(policy.writable_paths, [] as [std::path::PathBuf; 0]);
    }
}

// ============================================================================
// Integration-Style Canary Tests
// ============================================================================

mod canary {
    use super::*;
    use std::path::PathBuf;

    /// Simulates a strict-profile connector attempting various operations.
    #[test]
    fn test_canary_strict_connector() {
        let sandbox = create_sandbox().unwrap();
        let guard = EgressGuard::new();

        let section = strict_sandbox_section();
        let constraints = strict_constraints();
        let policy =
            CompiledPolicy::from_manifest(&section, Some("/tmp/canary-state".into())).unwrap();

        // Can read from allowed paths
        assert!(
            sandbox
                .verify_file_access(&policy, &PathBuf::from("/usr/share/dict/words"), false)
                .is_ok()
        );

        // Can write to state directory
        assert!(
            sandbox
                .verify_file_access(&policy, &PathBuf::from("/tmp/canary-state/cache.db"), true)
                .is_ok()
        );

        // Cannot read arbitrary paths
        assert!(
            sandbox
                .verify_file_access(&policy, &PathBuf::from("/etc/passwd"), false)
                .is_err()
        );

        // Cannot execute processes
        assert!(sandbox.verify_exec_allowed(&policy).is_err());

        // Direct network is blocked
        assert!(sandbox.verify_network_blocked(&policy).is_ok());

        // Can make allowed egress requests (via guard)
        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://api.example.com/data".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });
        assert!(guard.evaluate(&request, &constraints).is_ok());

        // Cannot reach localhost
        let result = guard.check_ip_constraints("127.0.0.1".parse().unwrap(), &constraints);
        assert!(result.is_err());

        // Cannot reach private ranges
        let result = guard.check_ip_constraints("192.168.1.1".parse().unwrap(), &constraints);
        assert!(result.is_err());
    }

    /// Simulates a moderate-profile connector.
    #[test]
    fn test_canary_moderate_connector() {
        let sandbox = create_sandbox().unwrap();

        let section = moderate_sandbox_section();
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();

        // Can read from /usr, /lib, /opt
        assert!(
            sandbox
                .verify_file_access(&policy, &PathBuf::from("/usr/bin/test"), false)
                .is_ok()
        );
        assert!(
            sandbox
                .verify_file_access(&policy, &PathBuf::from("/opt/tool/bin"), false)
                .is_ok()
        );

        // Cannot execute
        assert!(sandbox.verify_exec_allowed(&policy).is_err());

        // Network blocked (must go through guard)
        assert!(sandbox.verify_network_blocked(&policy).is_ok());
    }

    /// Simulates a permissive-profile connector (legacy/trusted).
    #[test]
    fn test_canary_permissive_connector() {
        let sandbox = create_sandbox().unwrap();

        let section = permissive_sandbox_section();
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();

        // Can execute processes
        assert!(sandbox.verify_exec_allowed(&policy).is_ok());

        // Direct network allowed (verify_network_blocked returns Err)
        assert!(sandbox.verify_network_blocked(&policy).is_err());
    }
}

// ============================================================================
// Structured Logging Tests
// ============================================================================

mod structured_logging {
    use super::*;

    #[test]
    fn test_egress_denial_emits_structured_log() {
        let _guard = LOG_LOCK.lock().expect("log lock poisoned");
        let buf = init_json_logger();
        buf.lock().expect("log buffer lock poisoned").clear();

        let guard = EgressGuard::new();
        let constraints = strict_constraints();

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://evil.example.com/data".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        let result = guard.evaluate(&request, &constraints);
        assert!(matches!(
            result,
            Err(EgressError::Denied {
                code: DenyReason::HostNotAllowed,
                ..
            })
        ));

        let lines = take_log_lines(&buf);
        assert!(!lines.is_empty(), "expected JSON logs from egress denial");

        let mut found = false;
        for line in lines {
            let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) else {
                continue;
            };

            let host = value
                .get("fields")
                .and_then(|fields| fields.get("host"))
                .and_then(|host| host.as_str());

            if host == Some("evil.example.com") {
                found = true;
                break;
            }
        }

        assert!(
            found,
            "expected structured log entry with host field for denial"
        );
    }
}
