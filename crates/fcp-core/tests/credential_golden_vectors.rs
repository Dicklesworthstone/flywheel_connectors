//! Credential Golden Vectors and Validation Tests (NORMATIVE).
//!
//! This module implements comprehensive tests for the FCP credential system
//! from `FCP_Specification_V3.md` §5.6 (Network Guard and Secret Use).
//!
//! # Test Categories
//!
//! 1. **Golden Vectors**: CBOR test fixtures for cross-implementation verification
//! 2. **Credential Validation**: `CredentialObject` field validation
//! 3. **Capability Gating**: `credential_allow` enforcement in `CapabilityConstraints`
//! 4. **Host Binding**: `host_allow` pattern matching and IP literal detection
//! 5. **Zeroize Discipline**: Secret material safety verification

use std::fs;
use std::path::PathBuf;

use fcp_cbor::SchemaId;
use fcp_core::{
    CapabilityConstraints, CredentialApplication, CredentialId, CredentialObject,
    CredentialValidationError, ObjectHeader, Provenance, SecretId, ZoneId,
};
use semver::Version;
use serde::{Deserialize, Serialize};

/// CBOR serialization helper
fn cbor_to_vec<T: Serialize>(value: &T) -> Vec<u8> {
    let mut buffer = Vec::new();
    ciborium::into_writer(value, &mut buffer).expect("CBOR serialization failed");
    buffer
}

/// CBOR deserialization helper
fn cbor_from_slice<T: for<'de> Deserialize<'de>>(data: &[u8]) -> T {
    ciborium::from_reader(data).expect("CBOR deserialization failed")
}

// ─────────────────────────────────────────────────────────────────────────────
// Test Infrastructure
// ─────────────────────────────────────────────────────────────────────────────

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join("credentials")
}

fn test_header() -> ObjectHeader {
    ObjectHeader {
        encryption_kind: Default::default(),
        schema: SchemaId::new("fcp.core", "CredentialObject", Version::new(1, 0, 0)),
        zone_id: ZoneId::work(),
        created_at: 1_700_000_000,
        provenance: Provenance::new(ZoneId::work()),
        refs: vec![],
        foreign_refs: vec![],
        ttl_secs: None,
        placement: None,
    }
}

fn test_credential_id() -> CredentialId {
    CredentialId::parse("11223344-5566-7788-99aa-bbccddeeff00").unwrap()
}

fn test_secret_id() -> SecretId {
    SecretId::parse("aabbccdd-eeff-0011-2233-445566778899").unwrap()
}

fn test_credential() -> CredentialObject {
    CredentialObject {
        header: test_header(),
        credential_id: test_credential_id(),
        label: Some("api-key-prod".into()),
        secret_id: test_secret_id(),
        application: CredentialApplication::HttpAuthorizationBearer,
        host_allow: vec![],
        expires_at: None,
        description: Some("Production API key".into()),
        tags: vec!["prod".into(), "api".into()],
    }
}

/// FCP2-compliant structured log output.
fn log_test_event(test_name: &str, event: &str, details: &serde_json::Value) {
    let log = serde_json::json!({
        "event": event,
        "test": test_name,
        "module": "credential_golden_vectors",
        "details": details
    });
    eprintln!("{}", serde_json::to_string(&log).unwrap());
}

// ─────────────────────────────────────────────────────────────────────────────
// Golden Vector Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn golden_vector_credential_object_valid() {
    let cred = test_credential();
    let cbor = cbor_to_vec(&cred);

    let vector_path = vectors_dir().join("credential_object_valid.cbor");

    if !vector_path.exists() {
        // Generate the vector on first run
        fs::write(&vector_path, &cbor).expect("write vector");
        log_test_event(
            "golden_vector_credential_object_valid",
            "vector_generated",
            &serde_json::json!({"path": vector_path.display().to_string(), "size": cbor.len()}),
        );
    }

    let loaded = fs::read(&vector_path).expect("read vector");
    let decoded: CredentialObject = cbor_from_slice(&loaded);

    assert_eq!(decoded.credential_id, cred.credential_id);
    assert_eq!(decoded.secret_id, cred.secret_id);
    assert_eq!(decoded.application, cred.application);

    log_test_event(
        "golden_vector_credential_object_valid",
        "vector_verified",
        &serde_json::json!({"credential_id": decoded.credential_id.to_string()}),
    );
}

#[test]
fn golden_vector_credential_object_with_host_allow() {
    let mut cred = test_credential();
    cred.host_allow = vec!["api.example.com".into(), "*.github.com".into()];
    cred.expires_at = Some(1_800_000_000);

    let cbor = cbor_to_vec(&cred);
    let vector_path = vectors_dir().join("credential_object_host_bound.cbor");

    if !vector_path.exists() {
        fs::write(&vector_path, &cbor).expect("write vector");
    }

    let loaded = fs::read(&vector_path).expect("read vector");
    let decoded: CredentialObject = cbor_from_slice(&loaded);

    assert_eq!(decoded.host_allow.len(), 2);
    assert!(decoded.is_host_allowed("api.example.com"));
    assert!(decoded.is_host_allowed("foo.github.com"));
    assert!(!decoded.is_host_allowed("evil.com"));
}

#[test]
fn golden_vector_credential_allow_constraints() {
    let cred_id1 = test_credential_id();
    let cred_id2 = CredentialId::parse("deadbeef-cafe-babe-f00d-0123456789ab").unwrap();

    let constraints = CapabilityConstraints {
        resource_allow: vec!["/api/v1/".into()],
        credential_allow: vec![cred_id1, cred_id2],
        ..Default::default()
    };

    let cbor = cbor_to_vec(&constraints);
    let vector_path = vectors_dir().join("credential_allow_constraints.cbor");

    if !vector_path.exists() {
        fs::write(&vector_path, &cbor).expect("write vector");
    }

    let loaded = fs::read(&vector_path).expect("read vector");
    let decoded: CapabilityConstraints = cbor_from_slice(&loaded);

    assert_eq!(decoded.credential_allow.len(), 2);
    assert!(decoded.is_credential_allowed(&cred_id1));
    assert!(decoded.is_credential_allowed(&cred_id2));
}

// ─────────────────────────────────────────────────────────────────────────────
// Capability Gating Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn capability_gating_allow_when_in_list() {
    let cred_id = test_credential_id();
    let constraints = CapabilityConstraints {
        credential_allow: vec![cred_id],
        ..Default::default()
    };

    let result = constraints.validate_credential(&cred_id);
    assert!(result.is_ok());

    log_test_event(
        "capability_gating_allow_when_in_list",
        "credential_allowed",
        &serde_json::json!({
            "credential_id": cred_id.to_string(),
            "outcome": "allow"
        }),
    );
}

#[test]
fn capability_gating_deny_when_not_in_list() {
    let allowed_cred = test_credential_id();
    let denied_cred = CredentialId::new();

    let constraints = CapabilityConstraints {
        credential_allow: vec![allowed_cred],
        ..Default::default()
    };

    let result = constraints.validate_credential(&denied_cred);
    assert!(result.is_err());

    let err = result.unwrap_err();
    match &err {
        CredentialValidationError::NotInCredentialAllow { credential_id } => {
            assert_eq!(*credential_id, denied_cred);
        }
        _ => panic!("Expected NotInCredentialAllow error"),
    }

    // Verify error message is suitable for DecisionReceipt
    let err_msg = err.to_string();
    assert!(err_msg.contains("credential_allow"));
    assert!(err_msg.contains(&denied_cred.to_string()));

    log_test_event(
        "capability_gating_deny_when_not_in_list",
        "credential_denied",
        &serde_json::json!({
            "credential_id": denied_cred.to_string(),
            "reason_code": "not_in_credential_allow",
            "error": err_msg
        }),
    );
}

#[test]
fn capability_gating_deny_host_not_allowed() {
    let mut cred = test_credential();
    cred.host_allow = vec!["api.example.com".into()];

    // Credential is valid but host doesn't match
    let is_allowed = cred.is_host_allowed("evil.com");
    assert!(!is_allowed);

    let err = CredentialValidationError::HostNotAllowed {
        credential_id: cred.credential_id,
        host: "evil.com".into(),
    };

    // Verify error message
    let err_msg = err.to_string();
    assert!(err_msg.contains("evil.com"));
    assert!(err_msg.contains("not in allowed list"));

    log_test_event(
        "capability_gating_deny_host_not_allowed",
        "host_denied",
        &serde_json::json!({
            "credential_id": cred.credential_id.to_string(),
            "requested_host": "evil.com",
            "allowed_hosts": cred.host_allow,
            "reason_code": "host_not_allowed",
            "error": err_msg
        }),
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Host Binding Validation Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn host_binding_canonical_hostnames_accepted() {
    let mut cred = test_credential();
    cred.host_allow = vec![
        "api.example.com".into(),
        "*.github.com".into(),
        "api.stripe.com:443".into(),
    ];

    // Validate no IP literals
    assert!(cred.validate_host_policy(true).is_ok());

    // All hostnames should match
    assert!(cred.is_host_allowed("api.example.com"));
    assert!(cred.is_host_allowed("foo.github.com"));
    assert!(cred.is_host_allowed("api.stripe.com:443"));
}

#[test]
fn host_binding_ip_literal_rejected_when_policy_requires() {
    let mut cred = test_credential();
    cred.host_allow = vec!["192.168.1.1".into()];

    // Should fail with reject_ip_literals=true
    let result = cred.validate_host_policy(true);
    assert!(result.is_err());

    let err = result.unwrap_err();
    match &err {
        CredentialValidationError::HostNotAllowed { host, .. } => {
            assert_eq!(host, "192.168.1.1");
        }
        _ => panic!("Expected HostNotAllowed error"),
    }

    log_test_event(
        "host_binding_ip_literal_rejected",
        "ip_literal_rejected",
        &serde_json::json!({
            "ip_literal": "192.168.1.1",
            "reason": "policy_rejects_ip_literals"
        }),
    );
}

#[test]
fn host_binding_ipv6_literal_rejected() {
    let mut cred = test_credential();
    cred.host_allow = vec!["[::1]:8080".into()];

    let result = cred.validate_host_policy(true);
    assert!(result.is_err());
}

#[test]
fn host_binding_ip_literal_allowed_when_policy_permits() {
    let mut cred = test_credential();
    cred.host_allow = vec!["192.168.1.1".into(), "10.0.0.1:8080".into()];

    // Should pass with reject_ip_literals=false
    assert!(cred.validate_host_policy(false).is_ok());

    // And hosts should match
    assert!(cred.is_host_allowed("192.168.1.1"));
    assert!(cred.is_host_allowed("10.0.0.1:8080"));
}

// ─────────────────────────────────────────────────────────────────────────────
// CredentialApplication Mode Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn credential_application_http_header_modes() {
    let modes = vec![
        CredentialApplication::HttpAuthorizationBearer,
        CredentialApplication::HttpAuthorizationBasic,
        CredentialApplication::HttpHeader {
            name: "X-API-Key".into(),
            prefix: None,
        },
        CredentialApplication::HttpHeader {
            name: "Authorization".into(),
            prefix: Some("Token ".into()),
        },
    ];

    for mode in &modes {
        let json = serde_json::to_string(mode).unwrap();
        let decoded: CredentialApplication = serde_json::from_str(&json).unwrap();
        assert_eq!(*mode, decoded);
    }
}

#[test]
fn credential_application_query_parameter_mode() {
    let mode = CredentialApplication::QueryParameter {
        name: "api_key".into(),
    };

    let json = serde_json::to_string(&mode).unwrap();
    assert!(json.contains("query_parameter"));
    assert!(json.contains("api_key"));

    let decoded: CredentialApplication = serde_json::from_str(&json).unwrap();
    assert_eq!(mode, decoded);
}

#[test]
fn credential_application_tls_modes() {
    let modes = vec![
        CredentialApplication::TlsClientCertificate,
        CredentialApplication::SshKey,
        CredentialApplication::DatabaseConnection,
        CredentialApplication::WebSocketAuth,
    ];

    for mode in &modes {
        let cbor = cbor_to_vec(mode);
        let decoded: CredentialApplication = cbor_from_slice(&cbor);
        assert_eq!(*mode, decoded);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CredentialId Canonicity Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn credential_id_format_is_canonical_uuid() {
    let id = CredentialId::new();
    let s = id.to_string();

    // Must be lowercase (canonical)
    assert_eq!(s, s.to_lowercase());

    // Must be 36 chars with 4 hyphens
    assert_eq!(s.len(), 36);
    assert_eq!(s.chars().filter(|c| *c == '-').count(), 4);
}

#[test]
fn credential_id_deterministic_display() {
    let id = test_credential_id();

    // Display is deterministic
    assert_eq!(id.to_string(), id.to_string());

    // Known value check
    assert_eq!(id.to_string(), "11223344-5566-7788-99aa-bbccddeeff00");
}

#[test]
fn credential_id_case_insensitive_parsing() {
    // Upper, lower, and mixed case should all parse to the same ID
    let upper = CredentialId::parse("11223344-5566-7788-99AA-BBCCDDEEFF00").unwrap();
    let lower = CredentialId::parse("11223344-5566-7788-99aa-bbccddeeff00").unwrap();
    let mixed = CredentialId::parse("11223344-5566-7788-99Aa-BbCcDdEeFf00").unwrap();

    assert_eq!(upper, lower);
    assert_eq!(lower, mixed);

    // Output is always lowercase
    assert_eq!(upper.to_string(), "11223344-5566-7788-99aa-bbccddeeff00");
}

// ─────────────────────────────────────────────────────────────────────────────
// Zeroize Discipline Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn credential_validation_errors_do_not_leak_secrets() {
    let cred_id = CredentialId::new();
    let secret_id = SecretId::new();

    // Check all error variants don't contain secret bytes
    let errors = vec![
        CredentialValidationError::Expired {
            credential_id: cred_id,
        },
        CredentialValidationError::HostNotAllowed {
            credential_id: cred_id,
            host: "evil.com".into(),
        },
        CredentialValidationError::NotInCredentialAllow {
            credential_id: cred_id,
        },
        CredentialValidationError::SecretNotFound { secret_id },
        CredentialValidationError::SecretRevoked { secret_id },
    ];

    for err in &errors {
        let debug = format!("{err:?}");
        let display = err.to_string();

        // Should not contain any hex patterns that look like secrets
        // (Secret bytes would be hex-encoded if leaked)
        assert!(!debug.contains("0x"));
        assert!(!display.contains("0x"));

        // IDs are UUIDs, which is fine
        log_test_event(
            "credential_validation_errors_do_not_leak_secrets",
            "error_checked",
            &serde_json::json!({
                "error_type": format!("{err:?}").split('{').next().unwrap_or("unknown"),
                "safe": true
            }),
        );
    }
}

#[test]
fn credential_object_debug_does_not_leak_secret_id() {
    let cred = test_credential();
    let debug = format!("{cred:?}");

    // Debug output should contain credential_id (safe to log)
    assert!(debug.contains(&cred.credential_id.to_string()));

    // Debug should NOT contain raw bytes patterns
    assert!(!debug.contains("[0x"));
}
