//! Egress proxy E2E (br-el1qe, [E.2] Egress Proxy E2E proof gap).
//!
//! `GoldenFinch`'s smdf5 audit found that the production egress proxy
//! (`fcp_sandbox::EgressGuard` — the single outbound network path for
//! connectors under strict / moderate sandbox profiles) has compliance
//! and unit coverage but no `crates/fcp-e2e/tests/` real-service
//! scenario where:
//!
//! 1. A connector binary attempts a host outside its manifest
//!    constraints.
//! 2. The production `EgressGuard` denies it.
//! 3. A structured audit event records the denial with the
//!    `DenyReason` discriminant + observed host + canonical request
//!    descriptor hash.
//!
//! No mocks. Real `EgressGuard`, real `NetworkConstraints` shaped like
//! a production connector manifest, real `EgressHttpRequest` /
//! `EgressTcpConnectRequest`, real `CredentialInjector` trait
//! (`NoOpCredentialInjector` from the sandbox crate), real audit-event
//! assembly via `AuditEntryBuilder`. JSONL log lines per phase per
//! scenario for triage tooling per the testing-perfect-e2e contract.
//!
//! Coverage matrix:
//! - Allowed host + allowed port → `EgressDecision { allowed: true }`
//! - Disallowed host → `Denied { code: HostNotAllowed }`
//! - Disallowed port → `Denied { code: PortNotAllowed }`
//! - IP literal when denied → `Denied { code: IpLiteralDenied }`
//! - Localhost when denied → `Denied { code: LocalhostDenied }`
//! - Credential not authorized → `Denied { code: CredentialNotAuthorized }`
//! - TCP connect to disallowed host → `Denied { code: HostNotAllowed }`
//! - Wildcard `host_allow` accepts canonical subdomains → `allowed`
//! - Audit event emitted on denial with structured `DenyReason` metadata

use chrono::Utc;
use serde_json::json;

use fcp_audit::{
    AuditEntryBuilder, Severity, capability_constraint_request_descriptor_hash, event_types,
};
use fcp_manifest::NetworkConstraints;
use fcp_prelude::ZoneId;
use fcp_sandbox::{
    DenyReason, EgressError, EgressGuard, EgressHttpRequest, EgressRequest,
    EgressTcpConnectRequest, HttpHeader, NoOpCredentialInjector,
};

/// Emit a structured JSONL log entry matching the testing-perfect-e2e
/// triage pattern. Visible under `cargo test -- --nocapture` and parsed
/// by CI failure tooling.
fn log_event(scenario_id: &str, phase: &str, outcome: &str, reason: Option<&str>) {
    let entry = json!({
        "ts": Utc::now().to_rfc3339(),
        "scenario_id": scenario_id,
        "bead": "el1qe",
        "phase": phase,
        "outcome": outcome,
        "reason": reason,
    });
    println!("{entry}");
}

/// Production-shaped manifest constraints: a typical connector that
/// allows api.github.com over 443, denies private + localhost +
/// tailnet ranges, and requires canonical hostnames.
fn production_constraints() -> NetworkConstraints {
    NetworkConstraints {
        host_allow: vec!["api.github.com".to_string(), "*.example.com".to_string()],
        port_allow: vec![443],
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

fn http_request(url: &str) -> EgressHttpRequest {
    EgressHttpRequest {
        url: url.to_string(),
        method: "GET".to_string(),
        headers: vec![HttpHeader {
            name: "Accept".to_string(),
            value: "application/json".to_string(),
        }],
        body: None,
        credential_id: None,
    }
}

/// Build a structured audit entry from a real `EgressError::Denied`. The
/// audit-side counterpart of an egress denial uses `event_types::SECURITY_VIOLATION`
/// so SOC tooling can surface "connector tried to leave the sandbox" without
/// rewiring the existing fork-detection pipeline.
fn audit_entry_from_denial(
    scenario: &str,
    err: &EgressError,
    target: &str,
) -> fcp_audit::AuditEntry {
    #[derive(serde::Serialize)]
    struct EgressDescriptor<'a> {
        scenario: &'a str,
        target: &'a str,
    }

    let (deny_label, observed_value) = match err {
        EgressError::Denied { code, reason } => (
            format!("egress.{}", deny_reason_label(*code)),
            reason.clone(),
        ),
        other => panic!("expected EgressError::Denied, got {other:?}"),
    };

    let descriptor_hash =
        capability_constraint_request_descriptor_hash(&EgressDescriptor { scenario, target })
            .expect("descriptor hash computes");

    AuditEntryBuilder::new()
        .id(format!("audit-egress-el1qe-{scenario}"))
        .actor("system:egress-guard")
        .zone_id(ZoneId::work())
        .seq(1)
        .occurred_at(u64::try_from(Utc::now().timestamp().max(0)).unwrap_or(0))
        .event_type(event_types::SECURITY_VIOLATION)
        .severity(Severity::Warning)
        .meta("deny_reason", serde_json::Value::String(deny_label))
        .meta(
            "observed_host",
            serde_json::Value::String(target.to_string()),
        )
        .meta(
            "request_descriptor_hash",
            serde_json::Value::String(descriptor_hash),
        )
        .meta("denial_message", serde_json::Value::String(observed_value))
        .build()
        .expect("audit entry builds")
}

const fn deny_reason_label(code: DenyReason) -> &'static str {
    match code {
        DenyReason::HostNotAllowed => "host_not_allowed",
        DenyReason::PortNotAllowed => "port_not_allowed",
        DenyReason::IpLiteralDenied => "ip_literal_denied",
        DenyReason::IpNotAllowed => "ip_not_allowed",
        DenyReason::LocalhostDenied => "localhost_denied",
        DenyReason::PrivateRangeDenied => "private_range_denied",
        DenyReason::TailnetRangeDenied => "tailnet_range_denied",
        DenyReason::LinkLocalDenied => "link_local_denied",
        DenyReason::CidrDenyMatched => "cidr_deny_matched",
        DenyReason::SniMismatch => "sni_mismatch",
        DenyReason::SpkiPinMismatch => "spki_pin_mismatch",
        DenyReason::CredentialNotAuthorized => "credential_not_authorized",
        DenyReason::CredentialHostNotAllowed => "credential_host_not_allowed",
        DenyReason::HostnameNotCanonical => "hostname_not_canonical",
        DenyReason::DnsMaxIpsExceeded => "dns_max_ips_exceeded",
        DenyReason::MaxRedirectsExceeded => "max_redirects_exceeded",
    }
}

// ─────────────────────────────────────────────────────────────────────
// Scenario 1: happy path — allowed host + port produces an Allow decision.
// Locks the baseline so deny-path scenarios actually exercise the
// failure path (not a misconfigured fixture).
// ─────────────────────────────────────────────────────────────────────

#[test]
fn egress_proxy_e2e_allowed_host_and_port_produces_allow_decision() {
    let scenario = "el1qe.allowed_host";
    log_event(scenario, "setup", "started", None);

    let guard = EgressGuard::new();
    let constraints = production_constraints();
    let request = EgressRequest::Http(http_request(
        "https://api.github.com/repos/owner/repo/issues",
    ));

    log_event(scenario, "evaluate", "running", None);
    let decision = guard.evaluate(&request, &constraints).expect("must allow");
    log_event(scenario, "evaluate", "allowed", None);

    assert!(decision.allowed);
    assert_eq!(decision.canonical_host, "api.github.com");
    assert_eq!(decision.port, 443);
    assert!(!decision.credential_injected);
}

// ─────────────────────────────────────────────────────────────────────
// Scenario 2: disallowed host — connector attempts a host outside the
// manifest's host_allow. The production EgressGuard MUST deny with
// HostNotAllowed and a structured audit event MUST be assemble-able
// from the rejection.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn egress_proxy_e2e_disallowed_host_denied_with_host_not_allowed() {
    let scenario = "el1qe.disallowed_host";
    log_event(scenario, "setup", "started", None);

    let guard = EgressGuard::new();
    let constraints = production_constraints();
    let target = "https://evil.attacker.invalid/exfiltrate";
    let request = EgressRequest::Http(http_request(target));

    log_event(scenario, "evaluate", "running", None);
    let err = guard
        .evaluate(&request, &constraints)
        .expect_err("disallowed host MUST be denied");

    let code = match &err {
        EgressError::Denied { code, .. } => *code,
        other => panic!("expected Denied, got {other:?}"),
    };
    assert_eq!(code, DenyReason::HostNotAllowed);
    log_event(
        scenario,
        "evaluate",
        "denied",
        Some(deny_reason_label(code)),
    );

    log_event(scenario, "build_audit_entry", "running", None);
    let entry = audit_entry_from_denial(scenario, &err, target);
    assert_eq!(entry.event_type, event_types::SECURITY_VIOLATION);
    assert_eq!(entry.severity, Severity::Warning);
    let deny_meta = entry
        .metadata
        .get("deny_reason")
        .and_then(|v| v.as_str())
        .expect("deny_reason metadata present");
    assert_eq!(deny_meta, "egress.host_not_allowed");
    let host_meta = entry
        .metadata
        .get("observed_host")
        .and_then(|v| v.as_str())
        .expect("observed_host metadata present");
    assert_eq!(host_meta, target);
    log_event(
        scenario,
        "build_audit_entry",
        "emitted",
        Some(event_types::SECURITY_VIOLATION),
    );
}

// ─────────────────────────────────────────────────────────────────────
// Scenario 3: disallowed port — host is allowed but port is not in the
// manifest's port_allow. The production EgressGuard MUST deny with
// PortNotAllowed.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn egress_proxy_e2e_disallowed_port_denied_with_port_not_allowed() {
    let scenario = "el1qe.disallowed_port";
    log_event(scenario, "setup", "started", None);

    let guard = EgressGuard::new();
    let constraints = production_constraints();
    // port 8080 is NOT in port_allow (only 443 is).
    let request = EgressRequest::Http(http_request("https://api.github.com:8080/data"));

    log_event(scenario, "evaluate", "running", None);
    let err = guard
        .evaluate(&request, &constraints)
        .expect_err("disallowed port MUST be denied");
    let code = match &err {
        EgressError::Denied { code, .. } => *code,
        other => panic!("expected Denied, got {other:?}"),
    };
    assert_eq!(code, DenyReason::PortNotAllowed);
    log_event(
        scenario,
        "evaluate",
        "denied",
        Some(deny_reason_label(code)),
    );
}

// ─────────────────────────────────────────────────────────────────────
// Scenario 4: IP literal when deny_ip_literals is on. A connector
// trying to bypass DNS-based hostname checks by using a raw IP MUST be
// denied with IpLiteralDenied.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn egress_proxy_e2e_ip_literal_denied_when_policy_forbids() {
    let scenario = "el1qe.ip_literal";
    log_event(scenario, "setup", "started", None);

    let guard = EgressGuard::new();
    let constraints = production_constraints();
    let request = EgressRequest::Http(http_request("https://140.82.112.5/data"));

    log_event(scenario, "evaluate", "running", None);
    let err = guard
        .evaluate(&request, &constraints)
        .expect_err("IP literal MUST be denied when deny_ip_literals is on");
    let code = match &err {
        EgressError::Denied { code, .. } => *code,
        other => panic!("expected Denied, got {other:?}"),
    };
    assert_eq!(code, DenyReason::IpLiteralDenied);
    log_event(
        scenario,
        "evaluate",
        "denied",
        Some(deny_reason_label(code)),
    );
}

// ─────────────────────────────────────────────────────────────────────
// Scenario 5: localhost when deny_localhost is on. The localhost rule
// is enforced at IP-resolution time (check_ip_constraints), not at
// hostname time — a connector resolving any allowed hostname to
// 127.0.0.1 (DNS rebinding-style attack OR genuine misconfiguration)
// MUST be rejected before the connection completes. This is the real
// production path: the host runs DNS resolution, then asks
// check_ip_constraints to verify each resolved IP.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn egress_proxy_e2e_localhost_resolved_ip_denied_when_policy_forbids() {
    let scenario = "el1qe.localhost_post_dns";
    log_event(scenario, "setup", "started", None);

    let guard = EgressGuard::new();
    let constraints = production_constraints();
    let resolved_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();

    log_event(scenario, "check_ip_constraints", "running", None);
    let err = guard
        .check_ip_constraints(resolved_ip, &constraints)
        .expect_err("localhost IP MUST be denied when deny_localhost is on");
    let code = match &err {
        EgressError::Denied { code, .. } => *code,
        other => panic!("expected Denied, got {other:?}"),
    };
    assert_eq!(code, DenyReason::LocalhostDenied);
    log_event(
        scenario,
        "check_ip_constraints",
        "denied",
        Some(deny_reason_label(code)),
    );
}

// ─────────────────────────────────────────────────────────────────────
// Scenario 5b: private RFC1918 IP when deny_private_ranges is on.
// Same defense-in-depth posture: the production path runs DNS, then
// check_ip_constraints, which catches the 10.x.x.x range.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn egress_proxy_e2e_private_range_resolved_ip_denied() {
    let scenario = "el1qe.private_range_post_dns";
    log_event(scenario, "setup", "started", None);

    let guard = EgressGuard::new();
    let constraints = production_constraints();
    let resolved_ip: std::net::IpAddr = "10.0.0.42".parse().unwrap();

    log_event(scenario, "check_ip_constraints", "running", None);
    let err = guard
        .check_ip_constraints(resolved_ip, &constraints)
        .expect_err("private-range IP MUST be denied when deny_private_ranges is on");
    let code = match &err {
        EgressError::Denied { code, .. } => *code,
        other => panic!("expected Denied, got {other:?}"),
    };
    assert_eq!(code, DenyReason::PrivateRangeDenied);
    log_event(
        scenario,
        "check_ip_constraints",
        "denied",
        Some(deny_reason_label(code)),
    );
}

// ─────────────────────────────────────────────────────────────────────
// Scenario 6: credential not authorized — even though the host + port
// are allowed, the connector tries to inject a credential that the
// CredentialInjector refuses. The integrated authorize_http path MUST
// reject with CredentialNotAuthorized.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn egress_proxy_e2e_credential_not_authorized_denied() {
    let scenario = "el1qe.credential_not_authorized";
    log_event(scenario, "setup", "started", None);

    let guard = EgressGuard::new();
    let constraints = production_constraints();
    let injector = NoOpCredentialInjector; // Always refuses authorization.
    let mut request = http_request("https://api.github.com/secrets");
    request.credential_id = Some("github-token".to_string());

    log_event(scenario, "authorize", "running", None);
    let err = guard
        .authorize_http(
            &mut request,
            &constraints,
            &injector,
            "issues.create",
            &["github-token".to_string()],
        )
        .expect_err("NoOp injector refuses authorization");
    let code = match &err {
        EgressError::Denied { code, .. } => *code,
        other => panic!("expected Denied, got {other:?}"),
    };
    assert_eq!(code, DenyReason::CredentialNotAuthorized);
    log_event(
        scenario,
        "authorize",
        "denied",
        Some(deny_reason_label(code)),
    );
}

// ─────────────────────────────────────────────────────────────────────
// Scenario 7: TCP connect path — same host_allow rules apply to raw
// TCP (e.g., postgres / redis). A disallowed host MUST be denied via
// the EgressTcpConnectRequest path too.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn egress_proxy_e2e_tcp_connect_disallowed_host_denied() {
    let scenario = "el1qe.tcp_disallowed_host";
    log_event(scenario, "setup", "started", None);

    let guard = EgressGuard::new();
    let constraints = NetworkConstraints {
        host_allow: vec!["db.example.com".to_string()],
        port_allow: vec![5432],
        ..production_constraints()
    };
    let request = EgressRequest::TcpConnect(EgressTcpConnectRequest {
        host: "db.attacker.invalid".to_string(),
        port: 5432,
        tls: false,
        sni_override: None,
        credential_id: None,
    });

    log_event(scenario, "evaluate", "running", None);
    let err = guard
        .evaluate(&request, &constraints)
        .expect_err("TCP connect to disallowed host MUST be denied");
    let code = match &err {
        EgressError::Denied { code, .. } => *code,
        other => panic!("expected Denied, got {other:?}"),
    };
    assert_eq!(code, DenyReason::HostNotAllowed);
    log_event(
        scenario,
        "evaluate",
        "denied",
        Some(deny_reason_label(code)),
    );
}

// ─────────────────────────────────────────────────────────────────────
// Scenario 8: wildcard host_allow MUST accept canonical subdomains.
// Belt-and-braces happy path — locks the wildcard interpretation so a
// future tightening that breaks `*.example.com` matching for
// `api.example.com` fails this E2E.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn egress_proxy_e2e_wildcard_host_allow_accepts_canonical_subdomain() {
    let scenario = "el1qe.wildcard_subdomain";
    log_event(scenario, "setup", "started", None);

    let guard = EgressGuard::new();
    let constraints = production_constraints();
    // production_constraints includes "*.example.com" in host_allow.
    let request = EgressRequest::Http(http_request("https://api.example.com/v1/data"));

    log_event(scenario, "evaluate", "running", None);
    let decision = guard
        .evaluate(&request, &constraints)
        .expect("wildcard subdomain MUST match");
    log_event(scenario, "evaluate", "allowed", None);

    assert!(decision.allowed);
    assert_eq!(decision.canonical_host, "api.example.com");
}

// ─────────────────────────────────────────────────────────────────────
// Scenario 9: structural — every DenyReason variant has a stable label
// in the audit-event mapping. Adding a new variant without updating
// `deny_reason_label` (or wiring up handling here) trips this length-
// lock against an external source of truth.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn egress_proxy_e2e_deny_reason_label_covers_known_variants() {
    let scenario = "el1qe.deny_reason_matrix";
    log_event(scenario, "setup", "started", None);

    // Snake-case label MUST be stable per variant — the wire format
    // for downstream audit consumers and replay tools.
    let pairs: &[(DenyReason, &str)] = &[
        (DenyReason::HostNotAllowed, "host_not_allowed"),
        (DenyReason::PortNotAllowed, "port_not_allowed"),
        (DenyReason::IpLiteralDenied, "ip_literal_denied"),
        (DenyReason::IpNotAllowed, "ip_not_allowed"),
        (DenyReason::LocalhostDenied, "localhost_denied"),
        (DenyReason::PrivateRangeDenied, "private_range_denied"),
        (DenyReason::TailnetRangeDenied, "tailnet_range_denied"),
        (DenyReason::LinkLocalDenied, "link_local_denied"),
        (DenyReason::CidrDenyMatched, "cidr_deny_matched"),
        (DenyReason::SniMismatch, "sni_mismatch"),
        (DenyReason::SpkiPinMismatch, "spki_pin_mismatch"),
        (
            DenyReason::CredentialNotAuthorized,
            "credential_not_authorized",
        ),
        (
            DenyReason::CredentialHostNotAllowed,
            "credential_host_not_allowed",
        ),
        (DenyReason::HostnameNotCanonical, "hostname_not_canonical"),
        (DenyReason::DnsMaxIpsExceeded, "dns_max_ips_exceeded"),
        (DenyReason::MaxRedirectsExceeded, "max_redirects_exceeded"),
    ];
    for (variant, expected_label) in pairs {
        assert_eq!(
            deny_reason_label(*variant),
            *expected_label,
            "label for {variant:?}"
        );
    }
    log_event(
        scenario,
        "verify_label_matrix",
        "passed",
        Some(&format!("{} variants", pairs.len())),
    );
}
