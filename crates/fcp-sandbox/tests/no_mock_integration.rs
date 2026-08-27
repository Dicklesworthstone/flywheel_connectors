//! No-mock integration tests for `fcp-sandbox`.
//!
//! Tests cross-module interactions without external services:
//! - `EgressGuard` policy evaluation (host/port/IP constraints)
//! - Hostname canonicalization (IDNA, lowercase, SSRF prevention)
//! - `CompiledPolicy` from manifest sections
//! - `WasiConfig` builder and policy conversion
//! - `FsCapabilityGate` and `NetworkCapabilityGate`
//! - `WasiHostState` deterministic mode
//! - Credential injection pipeline
//! - `SandboxError` / `EgressError` / `WasiError` types

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use fcp_manifest::{NetworkConstraints, SandboxProfile, SandboxSection};
use fcp_sandbox::*;
use serde_json::{Value, json};
use wasmtime::{Store, component::Resource};
use wasmtime_wasi::{
    clocks::WasiClocksView,
    filesystem::WasiFilesystemView,
    p2::bindings::{
        clocks::{monotonic_clock, wall_clock},
        filesystem::{preopens, types},
        random::{insecure_seed, random},
        sockets::{instance_network, ip_name_lookup},
    },
    random::WasiRandomView,
    sockets::{SocketAddrUse, WasiSocketsView},
};

// ============================================================================
// Helpers
// ============================================================================

fn permissive_constraints() -> NetworkConstraints {
    NetworkConstraints {
        host_allow: vec!["api.example.com".to_string(), "*.github.com".to_string()],
        port_allow: vec![443, 8080],
        ip_allow: vec![],
        cidr_deny: vec![],
        deny_localhost: true,
        deny_private_ranges: true,
        deny_tailnet_ranges: true,
        require_sni: false,
        spki_pins: vec![],
        deny_ip_literals: true,
        require_host_canonicalization: true,
        dns_max_ips: 16,
        max_redirects: 5,
        connect_timeout_ms: 10_000,
        total_timeout_ms: 60_000,
        max_response_bytes: 10 * 1024 * 1024,
    }
}

fn open_constraints() -> NetworkConstraints {
    NetworkConstraints {
        host_allow: vec!["*".to_string()],
        port_allow: vec![443, 80],
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
        max_response_bytes: 10 * 1024 * 1024,
    }
}

fn mediated_constraints() -> NetworkConstraints {
    NetworkConstraints {
        host_allow: vec!["api.example.com".to_string()],
        port_allow: vec![443],
        ip_allow: vec![],
        cidr_deny: vec![
            "127.0.0.0/8".to_string(),
            "10.0.0.0/8".to_string(),
            "100.64.0.0/10".to_string(),
        ],
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
        max_response_bytes: 10 * 1024 * 1024,
    }
}

fn localhost_block_constraints() -> NetworkConstraints {
    NetworkConstraints {
        host_allow: vec!["*".to_string()],
        port_allow: vec![443, 80],
        ip_allow: vec![],
        cidr_deny: vec![
            "127.0.0.0/8".to_string(),
            "10.0.0.0/8".to_string(),
            "100.64.0.0/10".to_string(),
        ],
        deny_localhost: true,
        deny_private_ranges: true,
        deny_tailnet_ranges: true,
        require_sni: false,
        spki_pins: vec![],
        deny_ip_literals: false,
        require_host_canonicalization: false,
        dns_max_ips: 16,
        max_redirects: 5,
        connect_timeout_ms: 10_000,
        total_timeout_ms: 60_000,
        max_response_bytes: 10 * 1024 * 1024,
    }
}

#[derive(Debug)]
struct RecordingCredentialInjector {
    authorized: bool,
    allowed_hosts: Vec<String>,
    auth_header_value: String,
    tcp_auth: Option<Vec<u8>>,
}

impl RecordingCredentialInjector {
    fn bearer(allowed_hosts: &[&str]) -> Self {
        Self {
            authorized: true,
            allowed_hosts: allowed_hosts
                .iter()
                .map(|host| (*host).to_string())
                .collect(),
            auth_header_value: "Bearer test-token".to_string(),
            tcp_auth: Some(b"test-auth".to_vec()),
        }
    }

    fn unauthorized(allowed_hosts: &[&str]) -> Self {
        Self {
            authorized: false,
            allowed_hosts: allowed_hosts
                .iter()
                .map(|host| (*host).to_string())
                .collect(),
            auth_header_value: "Bearer test-token".to_string(),
            tcp_auth: Some(b"test-auth".to_vec()),
        }
    }
}

impl CredentialInjector for RecordingCredentialInjector {
    fn is_authorized(
        &self,
        _credential_id: &str,
        _operation_id: &str,
        _credential_allow: &[String],
    ) -> Result<bool, EgressError> {
        Ok(self.authorized)
    }

    fn is_host_allowed(&self, _credential_id: &str, host: &str) -> Result<bool, EgressError> {
        Ok(self.allowed_hosts.iter().any(|allowed| allowed == host))
    }

    fn inject_http(
        &self,
        _credential_id: &str,
        headers: &mut Vec<HttpHeader>,
    ) -> Result<(), EgressError> {
        headers.push(HttpHeader {
            name: "Authorization".to_string(),
            value: self.auth_header_value.clone(),
        });
        Ok(())
    }

    fn get_tcp_auth(&self, _credential_id: &str) -> Result<Option<Vec<u8>>, EgressError> {
        Ok(self.tcp_auth.clone())
    }
}

fn http_request(url: &str) -> EgressRequest {
    EgressRequest::Http(EgressHttpRequest {
        url: url.to_string(),
        method: "GET".to_string(),
        headers: vec![],
        body: None,
        credential_id: None,
    })
}

fn strict_sandbox_section() -> SandboxSection {
    SandboxSection {
        profile: SandboxProfile::Strict,
        memory_mb: 256,
        cpu_percent: 50,
        wall_clock_timeout_ms: 30_000,
        fs_readonly_paths: vec!["/etc/ssl/certs".to_string()],
        fs_writable_paths: vec!["$CONNECTOR_STATE".to_string()],
        deny_exec: true,
        deny_ptrace: true,
    }
}

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

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let mut path = std::env::temp_dir()
        .canonicalize()
        .unwrap_or_else(|_| std::env::temp_dir());
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    path.push(format!("{prefix}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn preopen_descriptor(
    store: &mut Store<WasiHostState>,
    guest_path: &str,
) -> Resource<types::Descriptor> {
    let mut filesystem = store.data_mut().filesystem();
    preopens::Host::get_directories(&mut filesystem)
        .unwrap()
        .into_iter()
        .find(|(_, path)| path == guest_path)
        .map(|(descriptor, _)| descriptor)
        .unwrap()
}

async fn read_preopened_file(
    store: &mut Store<WasiHostState>,
    guest_path: &str,
    relative_path: &str,
) -> (Vec<u8>, bool) {
    let descriptor = preopen_descriptor(store, guest_path);
    let mut filesystem = store.data_mut().filesystem();
    let file_descriptor = types::HostDescriptor::open_at(
        &mut filesystem,
        descriptor,
        types::PathFlags::empty(),
        relative_path.to_string(),
        types::OpenFlags::empty(),
        types::DescriptorFlags::READ,
    )
    .await
    .unwrap();

    types::HostDescriptor::read(&mut filesystem, file_descriptor, 64, 0)
        .await
        .unwrap()
}

async fn open_preopened_for_write_error(
    store: &mut Store<WasiHostState>,
    guest_path: &str,
    relative_path: &str,
) -> String {
    let descriptor = preopen_descriptor(store, guest_path);
    let mut filesystem = store.data_mut().filesystem();
    types::HostDescriptor::open_at(
        &mut filesystem,
        descriptor,
        types::PathFlags::empty(),
        relative_path.to_string(),
        types::OpenFlags::CREATE,
        types::DescriptorFlags::WRITE,
    )
    .await
    .unwrap_err()
    .to_string()
}

async fn write_preopened_file(
    store: &mut Store<WasiHostState>,
    guest_path: &str,
    relative_path: &str,
    bytes: Vec<u8>,
) -> u64 {
    let descriptor = preopen_descriptor(store, guest_path);
    let mut filesystem = store.data_mut().filesystem();
    let file_descriptor = types::HostDescriptor::open_at(
        &mut filesystem,
        descriptor,
        types::PathFlags::empty(),
        relative_path.to_string(),
        types::OpenFlags::CREATE | types::OpenFlags::TRUNCATE,
        types::DescriptorFlags::WRITE,
    )
    .await
    .unwrap();

    types::HostDescriptor::write(&mut filesystem, file_descriptor, bytes, 0)
        .await
        .unwrap()
}

// ============================================================================
// 1. EgressGuard - host allow/deny
// ============================================================================

#[test]
fn egress_allows_host_in_allow_list() {
    let guard = EgressGuard::new();
    let constraints = permissive_constraints();
    let req = http_request("https://api.example.com/v1/data");
    let decision = guard.evaluate(&req, &constraints).unwrap();
    assert!(decision.allowed);
    assert_eq!(decision.canonical_host, "api.example.com");
    assert_eq!(decision.port, 443);
}

#[test]
fn egress_denies_host_not_in_allow_list() {
    let guard = EgressGuard::new();
    let constraints = permissive_constraints();
    let req = http_request("https://evil.example.org/steal");
    let err = guard.evaluate(&req, &constraints).unwrap_err();
    assert!(matches!(
        err,
        EgressError::Denied {
            code: DenyReason::HostNotAllowed,
            ..
        }
    ));
}

#[test]
fn egress_allows_wildcard_subdomain() {
    let guard = EgressGuard::new();
    let constraints = permissive_constraints();
    let req = http_request("https://raw.github.com/file");
    let decision = guard.evaluate(&req, &constraints).unwrap();
    assert!(decision.allowed);
}

#[test]
fn egress_denies_port_not_in_allow_list() {
    let guard = EgressGuard::new();
    let constraints = permissive_constraints();
    let req = http_request("https://api.example.com:9999/v1/data");
    let err = guard.evaluate(&req, &constraints).unwrap_err();
    assert!(matches!(
        err,
        EgressError::Denied {
            code: DenyReason::PortNotAllowed,
            ..
        }
    ));
}

#[test]
fn egress_allows_port_in_allow_list() {
    let guard = EgressGuard::new();
    let constraints = permissive_constraints();
    let req = http_request("https://api.example.com:8080/v1/data");
    let decision = guard.evaluate(&req, &constraints).unwrap();
    assert!(decision.allowed);
    assert_eq!(decision.port, 8080);
}

// ============================================================================
// 2. IP literal and private range checks
// ============================================================================

#[test]
fn egress_denies_ip_literal_when_configured() {
    let guard = EgressGuard::new();
    let constraints = permissive_constraints();
    let req = http_request("https://1.2.3.4/path");
    let err = guard.evaluate(&req, &constraints).unwrap_err();
    assert!(matches!(
        err,
        EgressError::Denied {
            code: DenyReason::IpLiteralDenied,
            ..
        }
    ));
}

#[test]
fn egress_allows_ip_literal_when_not_denied() {
    let guard = EgressGuard::new();
    let mut constraints = open_constraints();
    constraints.host_allow = vec!["*".to_string()];
    let req = http_request("https://1.2.3.4/path");
    let decision = guard.evaluate(&req, &constraints).unwrap();
    assert!(decision.allowed);
}

#[test]
fn is_localhost_checks() {
    assert!(is_localhost(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    assert!(is_localhost(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    assert!(!is_localhost(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
}

#[test]
fn is_private_range_checks() {
    assert!(is_private_range(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    assert!(is_private_range(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    assert!(is_private_range(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
    assert!(!is_private_range(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
}

#[test]
fn is_link_local_checks() {
    assert!(is_link_local(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))));
    assert!(!is_link_local(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
}

#[test]
fn is_tailnet_range_checks() {
    assert!(is_tailnet_range(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
    assert!(is_tailnet_range(IpAddr::V4(Ipv4Addr::new(
        100, 127, 255, 254
    ))));
    assert!(!is_tailnet_range(IpAddr::V4(Ipv4Addr::new(100, 128, 0, 1))));
}

#[test]
fn check_ip_constraints_denies_localhost() {
    let guard = EgressGuard::new();
    let constraints = permissive_constraints();
    let err = guard
        .check_ip_constraints(IpAddr::V4(Ipv4Addr::LOCALHOST), &constraints)
        .unwrap_err();
    assert!(matches!(
        err,
        EgressError::Denied {
            code: DenyReason::LocalhostDenied,
            ..
        }
    ));
}

#[test]
fn check_ip_constraints_denies_private_range() {
    let guard = EgressGuard::new();
    let constraints = permissive_constraints();
    let err = guard
        .check_ip_constraints(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), &constraints)
        .unwrap_err();
    assert!(matches!(
        err,
        EgressError::Denied {
            code: DenyReason::PrivateRangeDenied,
            ..
        }
    ));
}

#[test]
fn check_ip_constraints_denies_tailnet() {
    let guard = EgressGuard::new();
    let constraints = permissive_constraints();
    let err = guard
        .check_ip_constraints(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)), &constraints)
        .unwrap_err();
    assert!(matches!(
        err,
        EgressError::Denied {
            code: DenyReason::TailnetRangeDenied,
            ..
        }
    ));
}

#[test]
fn check_ip_constraints_allows_public_ip() {
    let guard = EgressGuard::new();
    let constraints = permissive_constraints();
    guard
        .check_ip_constraints(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), &constraints)
        .unwrap();
}

#[test]
fn check_ip_constraints_denies_link_local() {
    let guard = EgressGuard::new();
    let constraints = permissive_constraints();
    let err = guard
        .check_ip_constraints(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)), &constraints)
        .unwrap_err();
    assert!(matches!(
        err,
        EgressError::Denied {
            code: DenyReason::LinkLocalDenied,
            ..
        }
    ));
}

// ============================================================================
// 3. Hostname canonicalization
// ============================================================================

#[test]
fn canonicalize_hostname_lowercases() {
    let canonical = canonicalize_hostname("API.Example.COM").unwrap();
    assert_eq!(canonical, "api.example.com");
}

#[test]
fn canonicalize_hostname_strips_trailing_dot() {
    let canonical = canonicalize_hostname("example.com.").unwrap();
    assert_eq!(canonical, "example.com");
}

#[test]
fn canonicalize_hostname_idna() {
    let canonical = canonicalize_hostname("münchen.de").unwrap();
    assert_eq!(canonical, "xn--mnchen-3ya.de");
}

#[test]
fn is_hostname_canonical_checks() {
    assert!(is_hostname_canonical("api.example.com"));
    assert!(!is_hostname_canonical("API.Example.COM"));
}

#[test]
fn canonicalize_hostname_empty_rejected() {
    let result = canonicalize_hostname("");
    assert!(result.is_err());
}

// ============================================================================
// 4. CIDR deny matching
// ============================================================================

#[test]
fn cidr_deny_blocks_matching_ip() {
    let guard = EgressGuard::new();
    let mut constraints = open_constraints();
    constraints.cidr_deny = vec!["203.0.113.0/24".to_string()];

    let err = guard
        .check_ip_constraints(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42)), &constraints)
        .unwrap_err();
    assert!(matches!(
        err,
        EgressError::Denied {
            code: DenyReason::CidrDenyMatched,
            ..
        }
    ));
}

#[test]
fn cidr_deny_allows_non_matching_ip() {
    let guard = EgressGuard::new();
    let mut constraints = open_constraints();
    constraints.cidr_deny = vec!["203.0.113.0/24".to_string()];

    guard
        .check_ip_constraints(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), &constraints)
        .unwrap();
}

// ============================================================================
// 5. DNS resolution validation
// ============================================================================

#[test]
fn validate_dns_resolution_rejects_when_private_ip_present() {
    let guard = EgressGuard::new();
    let constraints = permissive_constraints();
    let ips = vec![
        IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        IpAddr::V4(Ipv4Addr::LOCALHOST), // SSRF rebind attempt
    ];

    // DNS resolution rejects the entire batch when any IP is denied
    let result = guard.validate_dns_resolution(&ips, &constraints);
    assert!(result.is_err());
}

#[test]
fn validate_dns_resolution_allows_all_public_ips() {
    let guard = EgressGuard::new();
    let constraints = permissive_constraints();
    let ips = vec![
        IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
    ];

    let result = guard.validate_dns_resolution(&ips, &constraints);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 2);
}

// ============================================================================
// 6. TCP connect requests
// ============================================================================

#[test]
fn egress_evaluates_tcp_connect() {
    let guard = EgressGuard::new();
    let constraints = permissive_constraints();
    let req = EgressRequest::TcpConnect(EgressTcpConnectRequest {
        host: "api.example.com".to_string(),
        port: 443,
        tls: true,
        sni_override: None,
        credential_id: None,
    });
    let decision = guard.evaluate(&req, &constraints).unwrap();
    assert!(decision.allowed);
    assert!(decision.tls_required);
}

#[test]
fn egress_denies_tcp_to_wrong_host() {
    let guard = EgressGuard::new();
    let constraints = permissive_constraints();
    let req = EgressRequest::TcpConnect(EgressTcpConnectRequest {
        host: "evil.example.org".to_string(),
        port: 443,
        tls: true,
        sni_override: None,
        credential_id: None,
    });
    let err = guard.evaluate(&req, &constraints).unwrap_err();
    assert!(matches!(
        err,
        EgressError::Denied {
            code: DenyReason::HostNotAllowed,
            ..
        }
    ));
}

// ============================================================================
// 7. Credential injection
// ============================================================================

#[test]
fn noop_credential_injector_allows_nothing() {
    let injector = NoOpCredentialInjector;
    assert!(
        !injector
            .is_authorized("cred-1", "op.read", &["cred-1".to_string()])
            .unwrap()
    );
}

#[test]
fn noop_credential_injector_host_denied_by_default() {
    let injector = NoOpCredentialInjector;
    // Default trait impl returns Ok(false) — NoOp doesn't override it.
    assert!(
        !injector
            .is_host_allowed("cred-1", "api.example.com")
            .unwrap()
    );
}

#[test]
fn noop_credential_injector_inject_http_returns_error() {
    let injector = NoOpCredentialInjector;
    let mut headers = vec![];
    let err = injector.inject_http("cred-1", &mut headers).unwrap_err();
    assert!(matches!(err, EgressError::CredentialError(_)));
}

#[test]
fn noop_credential_injector_tcp_auth_returns_error() {
    let injector = NoOpCredentialInjector;
    let err = injector.get_tcp_auth("cred-1").unwrap_err();
    assert!(matches!(err, EgressError::CredentialError(_)));
}

// ============================================================================
// 8. TLS verification
// ============================================================================

#[test]
fn default_tls_verifier_sni_match() {
    let verifier = DefaultTlsVerifier;
    verifier
        .verify_sni("api.example.com", "api.example.com")
        .unwrap();
}

#[test]
fn default_tls_verifier_sni_mismatch() {
    let verifier = DefaultTlsVerifier;
    let err = verifier
        .verify_sni("evil.com", "api.example.com")
        .unwrap_err();
    assert!(matches!(
        err,
        EgressError::Denied {
            code: DenyReason::SniMismatch,
            ..
        }
    ));
}

#[test]
fn default_tls_verifier_spki_match() {
    let verifier = DefaultTlsVerifier;
    let pin = vec![1, 2, 3, 4];
    verifier
        .verify_spki(&pin, std::slice::from_ref(&pin))
        .unwrap();
}

#[test]
fn default_tls_verifier_spki_mismatch() {
    let verifier = DefaultTlsVerifier;
    let cert_spki = vec![1, 2, 3, 4];
    let expected = vec![vec![5, 6, 7, 8]];
    let err = verifier.verify_spki(&cert_spki, &expected).unwrap_err();
    assert!(matches!(
        err,
        EgressError::Denied {
            code: DenyReason::SpkiPinMismatch,
            ..
        }
    ));
}

// ============================================================================
// 9. CompiledPolicy from manifest
// ============================================================================

#[test]
fn compiled_policy_from_strict_manifest() {
    let section = strict_sandbox_section();
    let state_dir = Some(PathBuf::from("/tmp/fcp-test-state"));
    let policy = CompiledPolicy::from_manifest(&section, state_dir).unwrap();

    assert!(matches!(policy.profile, SandboxProfile::Strict));
    assert_eq!(policy.memory_limit_bytes, 256 * 1024 * 1024);
    assert_eq!(policy.cpu_percent, 50);
    assert!(policy.deny_exec);
    assert!(policy.deny_ptrace);
    assert!(policy.block_direct_network);
}

#[test]
fn compiled_policy_state_dir_expansion() {
    let section = strict_sandbox_section();
    let state_dir = Some(PathBuf::from("/var/lib/fcp/my-connector"));
    let policy = CompiledPolicy::from_manifest(&section, state_dir).unwrap();

    // $CONNECTOR_STATE should be expanded in writable paths
    assert!(
        policy
            .writable_paths
            .iter()
            .any(|p| p == Path::new("/var/lib/fcp/my-connector"))
    );
}

#[test]
fn compiled_policy_moderate_blocks_network() {
    let mut section = strict_sandbox_section();
    section.profile = SandboxProfile::Moderate;
    let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
    assert!(policy.block_direct_network);
}

#[test]
fn compiled_policy_permissive_allows_network() {
    let mut section = strict_sandbox_section();
    section.profile = SandboxProfile::Permissive;
    let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
    assert!(!policy.block_direct_network);
}

#[test]
fn compiled_policy_platform_flags() {
    let section = strict_sandbox_section();
    let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
    let flags = PlatformFlags {
        linux_use_landlock: true,
        linux_use_userns: false,
        macos_entitlements: vec!["com.apple.security.network.client".to_string()],
        windows_appcontainer_capabilities: vec![],
        windows_low_integrity: true,
    };
    let policy = policy.with_platform_flags(flags.clone());
    assert!(!flags.is_empty());
    assert!(policy.platform_flags.linux_use_landlock);
}

#[test]
fn windows_appcontainer_smoke_skip_artifact_is_redaction_safe_jsonl()
-> Result<(), Box<dyn std::error::Error>> {
    let mut section = strict_sandbox_section();
    section.profile = SandboxProfile::Permissive;
    let policy = CompiledPolicy::from_manifest(
        &section,
        Some(PathBuf::from("/tmp/fcp-windows-appcontainer-state")),
    )?
    .with_platform_flags(PlatformFlags {
        windows_low_integrity: true,
        windows_appcontainer_capabilities: vec![WINDOWS_APPCONTAINER_INTERNET_CLIENT.to_string()],
        ..PlatformFlags::default()
    });

    let connector_id = "fcp.secret-customer@example.com:windows-smoke";
    let profile = policy.windows_appcontainer_profile(connector_id)?;
    let raw_profile_name = profile.name.clone();
    let report = WindowsAppContainerLifecycleReport {
        profile,
        action: WindowsAppContainerLifecycleAction::SkippedInactive,
        sid_present: false,
        cleanup: WindowsAppContainerCleanupDecision::None,
        skip_reason: Some("host_os_not_windows_or_appcontainer_worker_unavailable".to_string()),
    };
    let evidence =
        WindowsAppContainerEvidence::from_lifecycle(connector_id, &report, false, "skip");
    let line = evidence.to_jsonl_line()?;
    let value: Value = serde_json::from_str(&line)?;

    assert_eq!(value["schema"], "fcp.windows_appcontainer_smoke.v1");
    assert_eq!(value["os"], "windows");
    assert_eq!(value["lifecycle_action"], "skipped_inactive");
    assert_eq!(value["sid_present"].as_bool(), Some(false));
    assert_eq!(value["job_object_attached"].as_bool(), Some(false));
    assert_eq!(value["cleanup"], "none");
    assert_eq!(value["capability_decision"], "mapped");
    assert_eq!(value["action_result"], "skip");
    assert_eq!(value["step_order"], json!(["appcontainer_lifecycle"]));
    assert_eq!(
        value["skip_reason"],
        "host_os_not_windows_or_appcontainer_worker_unavailable"
    );
    assert!(!line.contains(connector_id));
    assert!(!line.contains("secret-customer@example.com"));
    assert!(!line.contains(&raw_profile_name));
    Ok(())
}

#[test]
fn windows_appcontainer_process_launch_skip_artifact_is_redaction_safe_jsonl()
-> Result<(), Box<dyn std::error::Error>> {
    let mut section = strict_sandbox_section();
    section.profile = SandboxProfile::Permissive;
    let policy = CompiledPolicy::from_manifest(
        &section,
        Some(PathBuf::from("/tmp/fcp-windows-appcontainer-state")),
    )?
    .with_platform_flags(PlatformFlags {
        windows_low_integrity: true,
        windows_appcontainer_capabilities: vec![WINDOWS_APPCONTAINER_INTERNET_CLIENT.to_string()],
        ..PlatformFlags::default()
    });

    let connector_id = "fcp.secret-customer@example.com:windows-launch";
    let profile = policy.windows_appcontainer_profile(connector_id)?;
    let raw_profile_name = profile.name.clone();
    let report = WindowsAppContainerLifecycleReport {
        profile,
        action: WindowsAppContainerLifecycleAction::SkippedInactive,
        sid_present: false,
        cleanup: WindowsAppContainerCleanupDecision::None,
        skip_reason: Some("host_os_not_windows_or_appcontainer_worker_unavailable".to_string()),
    };
    let evidence = WindowsAppContainerProcessLaunchEvidence::from_lifecycle(
        connector_id,
        &report,
        WindowsAppContainerProcessLaunchMechanism::SkippedInactive,
        false,
        "skip",
        None,
    );
    let line = evidence.to_jsonl_line()?;
    let value: Value = serde_json::from_str(&line)?;

    assert_eq!(
        value["schema"],
        "fcp.windows_appcontainer_process_launch.v1"
    );
    assert_eq!(value["os"], "windows");
    assert_eq!(value["lifecycle_action"], "skipped_inactive");
    assert_eq!(value["sid_present"].as_bool(), Some(false));
    assert_eq!(value["launch_mechanism"], "skipped_inactive");
    assert_eq!(value["job_object_attached"].as_bool(), Some(false));
    assert_eq!(value["job_object_attachment_intent"], "none");
    assert_eq!(value["final_filter_strength"], "process_limit");
    assert_eq!(value["cleanup"], "none");
    assert_eq!(value["capability_decision"], "mapped");
    assert_eq!(value["action_result"], "skip");
    assert_eq!(value["step_order"], json!(["appcontainer_lifecycle"]));
    assert_eq!(
        value["skip_reason"],
        "host_os_not_windows_or_appcontainer_worker_unavailable"
    );
    assert!(value.get("process_id_hash").is_none());
    assert!(!line.contains(connector_id));
    assert!(!line.contains("secret-customer@example.com"));
    assert!(!line.contains(&raw_profile_name));
    Ok(())
}

// ============================================================================
// 10. NoOpSandbox
// ============================================================================

#[test]
fn noop_sandbox_is_available() {
    let sandbox = NoOpSandbox;
    assert!(sandbox.is_available());
}

#[test]
fn noop_sandbox_platform_name() {
    let sandbox = NoOpSandbox;
    let name = sandbox.platform_name();
    assert_ne!(name, "");
}

#[test]
fn noop_sandbox_apply_succeeds() {
    let sandbox = NoOpSandbox;
    let section = strict_sandbox_section();
    let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
    sandbox.apply(&policy).unwrap();
}

#[test]
fn noop_sandbox_verify_file_access() {
    let sandbox = NoOpSandbox;
    let section = strict_sandbox_section();
    let policy = CompiledPolicy::from_manifest(&section, None).unwrap();

    sandbox
        .verify_file_access(&policy, Path::new("/etc/ssl/certs/ca-bundle.crt"), false)
        .unwrap();

    assert!(
        sandbox
            .verify_file_access(&policy, Path::new("/etc/passwd"), false)
            .is_err()
    );
}

#[test]
fn noop_sandbox_verify_exec() {
    let sandbox = NoOpSandbox;
    let section = strict_sandbox_section();
    let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
    assert!(sandbox.verify_exec_allowed(&policy).is_err());
}

#[test]
fn noop_sandbox_verify_network() {
    let sandbox = NoOpSandbox;
    let section = strict_sandbox_section();
    let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
    sandbox.verify_network_blocked(&policy).unwrap();
}

// ============================================================================
// 11. create_sandbox factory
// ============================================================================

#[test]
fn create_sandbox_returns_platform_sandbox() {
    let sandbox = create_sandbox().unwrap();
    assert!(sandbox.is_available());
    let name = sandbox.platform_name();
    assert_ne!(name, "");
}

// ============================================================================
// 12. WasiConfig builder
// ============================================================================

#[test]
fn wasi_config_default() {
    let config = WasiConfig::default();
    assert!(config.memory_limit_bytes > 0);
    assert!(!config.deterministic_mode);
    assert_eq!(config.readonly_paths, [] as [std::path::PathBuf; 0]);
    assert_eq!(config.writable_paths, [] as [std::path::PathBuf; 0]);
}

#[test]
fn wasi_config_from_policy() {
    let section = strict_sandbox_section();
    let state_dir = Some(PathBuf::from("/tmp/fcp-wasi-state"));
    let policy = CompiledPolicy::from_manifest(&section, state_dir).unwrap();
    let config = WasiConfig::from_policy(&policy).unwrap();

    assert_eq!(config.memory_limit_bytes, 256 * 1024 * 1024);
    assert!(config.block_direct_network);
    assert_ne!(config.readonly_paths, [] as [std::path::PathBuf; 0]);
}

#[test]
fn wasi_config_deterministic_mode() {
    let config = WasiConfig::default().with_deterministic_mode(1_700_000_000, 42);
    assert!(config.deterministic_mode);
    assert_eq!(config.deterministic_timestamp, 1_700_000_000);
    assert_eq!(config.deterministic_seed, 42);
}

#[test]
fn wasi_config_env_and_args() {
    let env = std::collections::HashMap::from([("KEY".to_string(), "value".to_string())]);
    let args = vec!["--flag".to_string(), "arg1".to_string()];
    let config = WasiConfig::default().with_env(env).with_args(args);

    assert_eq!(config.env_vars.len(), 1);
    assert_eq!(config.args.len(), 2);
}

#[test]
fn wasi_config_stdio_inheritance() {
    let config = WasiConfig::default().with_inherit_stdio(true, false);
    assert!(config.inherit_stdout);
    assert!(!config.inherit_stderr);
}

#[test]
fn wasi_config_network_constraints() {
    let constraints = permissive_constraints();
    let config = WasiConfig::default().with_network_constraints(constraints);
    assert!(config.network_constraints.is_some());
}

// ============================================================================
// 13. FsCapabilityGate
// ============================================================================

#[test]
fn fs_gate_allows_read_in_readonly_path() {
    // Use /etc which exists on all platforms
    let gate = FsCapabilityGate::new(vec![PathBuf::from("/etc")], vec![]);
    // /etc/hosts exists on macOS and Linux
    gate.check_access(Path::new("/etc/hosts"), false).unwrap();
}

#[test]
fn fs_gate_denies_write_to_readonly_path() {
    let gate = FsCapabilityGate::new(vec![PathBuf::from("/etc")], vec![]);
    let err = gate
        .check_access(Path::new("/etc/hosts"), true)
        .unwrap_err();
    assert!(matches!(err, WasiError::FsAccessDenied { .. }));
}

#[test]
fn fs_gate_allows_write_to_writable_path() {
    let gate = FsCapabilityGate::new(vec![], vec![PathBuf::from("/tmp")]);
    gate.check_access(Path::new("/tmp/data.json"), true)
        .unwrap();
}

#[test]
fn fs_gate_denies_access_outside_any_path() {
    let gate = FsCapabilityGate::new(vec![PathBuf::from("/etc")], vec![PathBuf::from("/tmp")]);
    let err = gate
        .check_access(Path::new("/var/log/system.log"), false)
        .unwrap_err();
    assert!(matches!(err, WasiError::FsAccessDenied { .. }));
}

// ============================================================================
// 14. NetworkCapabilityGate
// ============================================================================

#[test]
fn net_gate_allows_http_when_host_allowed() {
    let gate = NetworkCapabilityGate::new(Some(permissive_constraints()), false);
    gate.check_http("https://api.example.com/v1/data", "GET")
        .unwrap();
}

#[test]
fn net_gate_denies_http_when_blocked_and_no_constraints() {
    // block_direct only triggers denial when constraints are None
    let gate = NetworkCapabilityGate::new(None, true);
    let err = gate
        .check_http("https://api.example.com/v1/data", "GET")
        .unwrap_err();
    assert!(matches!(err, WasiError::NetworkAccessDenied(_)));
}

#[test]
fn net_gate_denies_tcp_when_blocked_and_no_constraints() {
    // block_direct only triggers denial when constraints are None
    let gate = NetworkCapabilityGate::new(None, true);
    let err = gate.check_tcp("api.example.com", 443, true).unwrap_err();
    assert!(matches!(err, WasiError::NetworkAccessDenied(_)));
}

#[test]
fn net_gate_allows_tcp_when_not_blocked() {
    let gate = NetworkCapabilityGate::new(Some(permissive_constraints()), false);
    gate.check_tcp("api.example.com", 443, true).unwrap();
}

#[test]
fn net_gate_no_constraints_denies_all() {
    let gate = NetworkCapabilityGate::new(None, false);
    let err = gate
        .check_http("https://api.example.com/v1/data", "GET")
        .unwrap_err();
    assert!(matches!(err, WasiError::NetworkAccessDenied(_)));
}

// ============================================================================
// 15. WasiRuntime creation
// ============================================================================

#[test]
fn wasi_runtime_creates_successfully() {
    let config = WasiConfig::default();
    let runtime = WasiRuntime::new(config).unwrap();
    // Engine was created successfully — verify it exists
    let _engine = runtime.engine();
}

#[test]
fn wasi_runtime_deterministic_mode() {
    let config = WasiConfig::default().with_deterministic_mode(1_700_000_000, 42);
    let runtime = WasiRuntime::new(config).unwrap();
    let _store = runtime.create_store().unwrap();
}

#[test]
fn wasi_runtime_load_invalid_component() {
    let config = WasiConfig::default();
    let runtime = WasiRuntime::new(config).unwrap();
    let result = runtime.load_component(b"not valid wasm");
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn wasi_runtime_invokes_minimal_component() {
    let config = WasiConfig {
        max_fuel: 10_000,
        ..WasiConfig::default()
    };
    let runtime = WasiRuntime::new(config).unwrap();
    let component = runtime.load_component(minimal_command_component()).unwrap();
    let args = vec!["--dry-run".to_string()];

    let result = runtime.invoke(&component, "run", &args).await.unwrap();

    assert_eq!(result.exit_code, 0);
    assert!(result.duration >= std::time::Duration::ZERO);
    assert!(result.fuel_consumed.is_some());
}

#[fcp_async_core::runtime::test]
async fn wasi_runtime_reports_missing_export() {
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

#[fcp_async_core::runtime::test]
async fn wasi_runtime_hostcalls_enforce_preopened_filesystem_permissions() {
    let readonly_dir = unique_temp_dir("fcp-sandbox-wasi-readonly");
    let writable_dir = unique_temp_dir("fcp-sandbox-wasi-writable");
    std::fs::write(readonly_dir.join("input.txt"), b"readonly-ok").unwrap();

    let runtime = WasiRuntime::new(WasiConfig {
        readonly_paths: vec![readonly_dir.clone()],
        writable_paths: vec![writable_dir.clone()],
        ..WasiConfig::default()
    })
    .unwrap();
    let mut store = runtime.create_store().unwrap();

    let readonly_guest_path = readonly_dir.display().to_string();
    let writable_guest_path = writable_dir.display().to_string();

    let (bytes, eof) = read_preopened_file(&mut store, &readonly_guest_path, "input.txt").await;
    assert_eq!(bytes, b"readonly-ok");
    assert!(!eof);

    let readonly_err =
        open_preopened_for_write_error(&mut store, &readonly_guest_path, "blocked.txt").await;
    assert!(readonly_err.contains("not-permitted"));

    let written = write_preopened_file(
        &mut store,
        &writable_guest_path,
        "output.txt",
        b"written-ok".to_vec(),
    )
    .await;
    assert_eq!(written, 10);

    assert_eq!(
        std::fs::read(writable_dir.join("output.txt")).unwrap(),
        b"written-ok"
    );

    let escape_err =
        open_preopened_for_write_error(&mut store, &writable_guest_path, "../escape.txt").await;
    assert!(escape_err.contains("not-permitted"));
}

#[test]
fn wasi_runtime_deterministic_hostcalls_are_stable_across_stores() {
    let runtime =
        WasiRuntime::new(WasiConfig::default().with_deterministic_mode(1_700_000_000, 42)).unwrap();
    let mut store_a = runtime.create_store().unwrap();
    let mut store_b = runtime.create_store().unwrap();

    let wall_a = {
        let mut clocks = store_a.data_mut().clocks();
        wall_clock::Host::now(&mut clocks).unwrap()
    };
    let wall_b = {
        let mut clocks = store_b.data_mut().clocks();
        wall_clock::Host::now(&mut clocks).unwrap()
    };
    assert_eq!(wall_a.seconds, 1_700_000_000);
    assert_eq!(wall_a.seconds, wall_b.seconds);
    assert_eq!(wall_a.nanoseconds, wall_b.nanoseconds);

    let mono_a_1 = {
        let mut clocks = store_a.data_mut().clocks();
        monotonic_clock::Host::now(&mut clocks).unwrap()
    };
    let mono_a_2 = {
        let mut clocks = store_a.data_mut().clocks();
        monotonic_clock::Host::now(&mut clocks).unwrap()
    };
    let other_mono_start = {
        let mut clocks = store_b.data_mut().clocks();
        monotonic_clock::Host::now(&mut clocks).unwrap()
    };
    assert_eq!(mono_a_1, 0);
    assert_eq!(mono_a_2, 1_000_000);
    assert_eq!(other_mono_start, 0);

    let random_a = random::Host::get_random_bytes(store_a.data_mut().random(), 16).unwrap();
    let random_b = random::Host::get_random_bytes(store_b.data_mut().random(), 16).unwrap();
    assert_eq!(random_a, random_b);

    let seed = insecure_seed::Host::insecure_seed(store_a.data_mut().random()).unwrap();
    assert_eq!(seed, (42, 42));
}

#[fcp_async_core::runtime::test]
async fn wasi_runtime_network_policy_controls_preview2_socket_hostcalls() {
    let default_runtime = WasiRuntime::new(WasiConfig::default()).unwrap();
    let mut default_store = default_runtime.create_store().unwrap();
    {
        let mut sockets = default_store.data_mut().sockets();
        let network = instance_network::Host::instance_network(&mut sockets).unwrap();
        let err =
            ip_name_lookup::Host::resolve_addresses(&mut sockets, network, "example.com".into())
                .unwrap_err();
        assert!(err.to_string().contains("resolver-failure"));
    }

    let strict_runtime =
        WasiRuntime::new(WasiConfig::default().with_network_constraints(open_constraints()))
            .unwrap();
    let mut strict_store = strict_runtime.create_store().unwrap();
    {
        let mut sockets = strict_store.data_mut().sockets();
        let network = instance_network::Host::instance_network(&mut sockets).unwrap();
        let err =
            ip_name_lookup::Host::resolve_addresses(&mut sockets, network, "example.com".into())
                .unwrap_err();
        assert!(err.to_string().contains("resolver-failure"));
    }

    let permissive_runtime = WasiRuntime::new(WasiConfig {
        block_direct_network: false,
        ..WasiConfig::default().with_network_constraints(open_constraints())
    })
    .unwrap();
    let mut permissive_store = permissive_runtime.create_store().unwrap();
    {
        let mut sockets = permissive_store.data_mut().sockets();
        let lookup_network = instance_network::Host::instance_network(&mut sockets).unwrap();
        assert!(
            ip_name_lookup::Host::resolve_addresses(
                &mut sockets,
                lookup_network,
                "example.com".into()
            )
            .is_ok()
        );

        let allowed_network = instance_network::Host::instance_network(&mut sockets).unwrap();
        let allowed = sockets
            .table
            .get(&allowed_network)
            .unwrap()
            .check_socket_addr(
                "93.184.216.34:443".parse().unwrap(),
                SocketAddrUse::TcpConnect,
            )
            .await;
        assert!(allowed.is_ok());

        let blocked_port_network = instance_network::Host::instance_network(&mut sockets).unwrap();
        let blocked_port = sockets
            .table
            .get(&blocked_port_network)
            .unwrap()
            .check_socket_addr(
                "93.184.216.34:8443".parse().unwrap(),
                SocketAddrUse::TcpConnect,
            )
            .await;
        assert!(blocked_port.is_err());

        let blocked_bind_network = instance_network::Host::instance_network(&mut sockets).unwrap();
        let blocked_bind = sockets
            .table
            .get(&blocked_bind_network)
            .unwrap()
            .check_socket_addr("93.184.216.34:443".parse().unwrap(), SocketAddrUse::TcpBind)
            .await;
        assert!(blocked_bind.is_err());
    }
}

#[fcp_async_core::runtime::test]
async fn br_p3pd4_wasi_runner_receives_operation_constraints_and_blocks_raw_sockets() {
    let constraints = mediated_constraints();
    let config = WasiConfig::default().with_network_constraints(constraints);
    assert!(
        config.block_direct_network,
        "host handoff must keep raw Preview2 sockets disabled for mediated profiles"
    );

    let runner = WasiConnectorRunner::new(config.clone()).unwrap();
    runner
        .validate_http_access("https://api.example.com/v1/messages", "GET")
        .expect("operation host and port should reach NetworkCapabilityGate");
    assert!(
        runner
            .validate_http_access("https://api.other.example.com/v1/messages", "GET")
            .is_err(),
        "NetworkCapabilityGate must reject hosts outside the operation policy"
    );
    assert!(
        runner
            .validate_tcp_access("api.example.com", 8443, true)
            .is_err(),
        "NetworkCapabilityGate must reject ports outside the operation policy"
    );

    let runtime = WasiRuntime::new(config).unwrap();
    let mut store = runtime.create_store().unwrap();
    {
        let mut sockets = store.data_mut().sockets();
        let network = instance_network::Host::instance_network(&mut sockets).unwrap();
        let dns_err = ip_name_lookup::Host::resolve_addresses(
            &mut sockets,
            network,
            "api.example.com".into(),
        )
        .unwrap_err();
        assert!(
            dns_err.to_string().contains("resolver-failure"),
            "strict mediated profiles must deny raw DNS hostcalls"
        );

        let tcp_network = instance_network::Host::instance_network(&mut sockets).unwrap();
        let tcp_result = sockets
            .table
            .get(&tcp_network)
            .unwrap()
            .check_socket_addr(
                std::net::SocketAddr::from(([93, 184, 216, 34], 443)),
                SocketAddrUse::TcpConnect,
            )
            .await;
        assert!(
            tcp_result.is_err(),
            "strict mediated profiles must deny raw TCP hostcalls even for policy-shaped endpoints"
        );
    }
}

#[fcp_async_core::runtime::test]
async fn wasi_runtime_network_guard_authorizes_mediated_http_requests_inside_store() {
    let runtime =
        WasiRuntime::new(WasiConfig::default().with_network_constraints(mediated_constraints()))
            .unwrap();
    let mut store = runtime.create_store().unwrap();

    {
        let mut sockets = store.data_mut().sockets();
        let network = instance_network::Host::instance_network(&mut sockets).unwrap();
        let err = ip_name_lookup::Host::resolve_addresses(
            &mut sockets,
            network,
            "api.example.com".into(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("resolver-failure"));
    }

    let injector = RecordingCredentialInjector::bearer(&["api.example.com"]);
    let mut request = EgressHttpRequest {
        url: "https://api.example.com/v1/data".to_string(),
        method: "GET".to_string(),
        headers: vec![],
        body: None,
        credential_id: Some("test-cred".to_string()),
    };

    let decision = store
        .data()
        .authorize_http_request(
            &mut request,
            &injector,
            "sandbox.egress.read",
            &["test-cred".to_string()],
        )
        .unwrap();

    assert!(decision.allowed);
    assert!(decision.credential_injected);
    assert_eq!(decision.expected_sni.as_deref(), Some("api.example.com"));
    assert!(
        request.headers.iter().any(|header| {
            header.name == "Authorization" && header.value == "Bearer test-token"
        })
    );
}

#[test]
fn wasi_host_state_authorize_http_denies_disallowed_host_without_timeout() {
    let config = WasiConfig::default().with_network_constraints(mediated_constraints());
    let runtime = WasiRuntime::new(config).unwrap();
    let store = runtime.create_store().unwrap();
    let injector = RecordingCredentialInjector::bearer(&["api.example.com"]);
    let mut request = EgressHttpRequest {
        url: "https://evil.com/".to_string(),
        method: "GET".to_string(),
        headers: vec![],
        body: None,
        credential_id: Some("test-cred".to_string()),
    };

    let err = store
        .data()
        .authorize_http_request(
            &mut request,
            &injector,
            "sandbox.egress.read",
            &["test-cred".to_string()],
        )
        .unwrap_err();

    assert!(err.to_string().contains("host not allowed"));
    assert!(request.headers.is_empty());
}

#[test]
fn wasi_host_state_authorize_http_denies_localhost_via_egress_rules() {
    let config = WasiConfig::default().with_network_constraints(localhost_block_constraints());
    let runtime = WasiRuntime::new(config).unwrap();
    let store = runtime.create_store().unwrap();
    let injector = RecordingCredentialInjector::bearer(&["127.0.0.1"]);
    let mut request = EgressHttpRequest {
        url: "http://127.0.0.1/health".to_string(),
        method: "GET".to_string(),
        headers: vec![],
        body: None,
        credential_id: Some("test-cred".to_string()),
    };

    let err = store
        .data()
        .authorize_http_request(
            &mut request,
            &injector,
            "sandbox.egress.read",
            &["test-cred".to_string()],
        )
        .unwrap_err();

    assert!(err.to_string().contains("localhost access denied"));
    assert!(request.headers.is_empty());
}

#[test]
fn wasi_host_state_authorize_tcp_returns_injected_auth_bytes() {
    let constraints = NetworkConstraints {
        host_allow: vec!["db.example.com".to_string()],
        port_allow: vec![5432],
        ip_allow: vec![],
        cidr_deny: vec![],
        deny_localhost: true,
        deny_private_ranges: true,
        deny_tailnet_ranges: true,
        require_sni: false,
        spki_pins: vec![],
        deny_ip_literals: true,
        require_host_canonicalization: true,
        dns_max_ips: 16,
        max_redirects: 5,
        connect_timeout_ms: 10_000,
        total_timeout_ms: 60_000,
        max_response_bytes: 10 * 1024 * 1024,
    };
    let config = WasiConfig::default().with_network_constraints(constraints);
    let runtime = WasiRuntime::new(config).unwrap();
    let store = runtime.create_store().unwrap();
    let injector = RecordingCredentialInjector::bearer(&["db.example.com"]);
    let request = EgressTcpConnectRequest {
        host: "db.example.com".to_string(),
        port: 5432,
        tls: true,
        sni_override: None,
        credential_id: Some("test-cred".to_string()),
    };

    let decision = store
        .data()
        .authorize_tcp_connect(
            &request,
            &injector,
            "sandbox.egress.db",
            &["test-cred".to_string()],
        )
        .unwrap();

    assert!(decision.decision.allowed);
    assert!(decision.decision.credential_injected);
    assert_eq!(decision.tcp_auth.as_deref(), Some(&b"test-auth"[..]));
}

#[test]
fn wasi_host_state_authorize_http_rejects_unauthorized_credential() {
    let config = WasiConfig::default().with_network_constraints(mediated_constraints());
    let runtime = WasiRuntime::new(config).unwrap();
    let store = runtime.create_store().unwrap();
    let injector = RecordingCredentialInjector::unauthorized(&["api.example.com"]);
    let mut request = EgressHttpRequest {
        url: "https://api.example.com/v1/data".to_string(),
        method: "GET".to_string(),
        headers: vec![],
        body: None,
        credential_id: Some("test-cred".to_string()),
    };

    let err = store
        .data()
        .authorize_http_request(
            &mut request,
            &injector,
            "sandbox.egress.read",
            &["test-cred".to_string()],
        )
        .unwrap_err();

    assert!(err.to_string().contains("not authorized"));
    assert!(request.headers.is_empty());
}

// ============================================================================
// 16. Error types display
// ============================================================================

#[test]
fn egress_error_display() {
    let err = EgressError::Denied {
        reason: "host not allowed".to_string(),
        code: DenyReason::HostNotAllowed,
    };
    let msg = format!("{err}");
    assert!(msg.contains("host not allowed"));

    let err = EgressError::InvalidUrl("bad url".to_string());
    assert!(format!("{err}").contains("bad url"));

    let err = EgressError::CanonicalizationFailed("idna error".to_string());
    assert!(format!("{err}").contains("idna error"));
}

#[test]
fn sandbox_error_display() {
    let err = SandboxError::UnsupportedPlatform("wasm32".to_string());
    assert!(format!("{err}").contains("wasm32"));

    let err = SandboxError::Timeout;
    let msg = format!("{err}");
    assert_ne!(msg, "");

    let err = SandboxError::InvalidConfig("bad config".to_string());
    assert!(format!("{err}").contains("bad config"));
}

#[test]
fn wasi_error_display() {
    let err = WasiError::FsAccessDenied {
        path: "/etc/passwd".to_string(),
        reason: "not in allowed paths".to_string(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("/etc/passwd"));

    let err = WasiError::NetworkAccessDenied("blocked".to_string());
    assert!(format!("{err}").contains("blocked"));

    let err = WasiError::Timeout;
    let msg = format!("{err}");
    assert_ne!(msg, "");

    let err = WasiError::ClockAccessDenied;
    let msg = format!("{err}");
    assert_ne!(msg, "");

    let err = WasiError::EntropyAccessDenied;
    let msg = format!("{err}");
    assert_ne!(msg, "");
}

// ============================================================================
// 17. DenyReason exhaustive coverage
// ============================================================================

#[test]
fn deny_reason_all_variants() {
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

    // Just verify all variants can be instantiated and debug-printed
    for reason in &reasons {
        let _ = format!("{reason:?}");
    }
}

// ============================================================================
// 18. Cross-module: EgressGuard + CompiledPolicy integration
// ============================================================================

#[test]
fn compiled_policy_strict_blocks_network_for_guard() {
    let section = strict_sandbox_section();
    let policy = CompiledPolicy::from_manifest(&section, None).unwrap();

    // A strict policy should block direct network
    assert!(policy.block_direct_network);

    // The network gate from this policy should deny all
    let gate = NetworkCapabilityGate::new(None, policy.block_direct_network);
    let err = gate
        .check_http("https://api.example.com", "GET")
        .unwrap_err();
    assert!(matches!(err, WasiError::NetworkAccessDenied(_)));
}

// ============================================================================
// 19. Cross-module: WasiConfig from policy → FsCapabilityGate
// ============================================================================

#[test]
fn wasi_config_from_policy_creates_correct_paths() {
    let section = strict_sandbox_section();
    let state_dir = Some(PathBuf::from("/tmp/connector"));
    let policy = CompiledPolicy::from_manifest(&section, state_dir).unwrap();
    let config = WasiConfig::from_policy(&policy).unwrap();

    // Check that readonly paths from policy are in config
    assert!(
        config
            .readonly_paths
            .iter()
            .any(|p| p == Path::new("/etc/ssl/certs"))
    );

    // Check writable paths include expanded state dir
    assert!(
        config
            .writable_paths
            .iter()
            .any(|p| p == Path::new("/tmp/connector"))
    );
}

// ============================================================================
// 20. PlatformFlags
// ============================================================================

#[test]
fn platform_flags_default_is_empty() {
    let flags = PlatformFlags {
        linux_use_landlock: false,
        linux_use_userns: false,
        macos_entitlements: vec![],
        windows_appcontainer_capabilities: vec![],
        windows_low_integrity: false,
    };
    assert!(flags.is_empty());
}

#[test]
fn platform_flags_non_empty_variants() {
    let flags1 = PlatformFlags {
        linux_use_landlock: true,
        linux_use_userns: false,
        macos_entitlements: vec![],
        windows_appcontainer_capabilities: vec![],
        windows_low_integrity: false,
    };
    assert!(!flags1.is_empty());

    let flags2 = PlatformFlags {
        linux_use_landlock: false,
        linux_use_userns: false,
        macos_entitlements: vec!["entitlement".to_string()],
        windows_appcontainer_capabilities: vec![],
        windows_low_integrity: false,
    };
    assert!(!flags2.is_empty());
}

// ============================================================================
// 21. Invalid URL handling
// ============================================================================

#[test]
fn egress_rejects_relative_url() {
    let guard = EgressGuard::new();
    let constraints = open_constraints();
    let req = http_request("/relative/path");
    let err = guard.evaluate(&req, &constraints).unwrap_err();
    assert!(matches!(err, EgressError::InvalidUrl(_)));
}

#[test]
fn egress_rejects_unknown_scheme_without_port() {
    let guard = EgressGuard::new();
    let constraints = open_constraints();
    // Scheme without a known default port causes InvalidUrl
    let req = http_request("foobar://files.example.com/data");
    let err = guard.evaluate(&req, &constraints).unwrap_err();
    assert!(matches!(err, EgressError::InvalidUrl(_)));
}
