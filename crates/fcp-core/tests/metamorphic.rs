//! Metamorphic relation tests for zone-capability derivations in `fcp-core`.
//!
//! These tests pin algebraic properties of the exported capability, zone, and
//! revocation APIs so future refactors cannot quietly weaken the security model.

use chrono::{TimeZone, Utc};
use fcp_cbor::SchemaId;
use fcp_core::{
    CapabilityConstraints, CapabilityId, CapabilityToken, CapabilityVerifier, FcpError,
    ObjectHeader, ObjectId, OperationId, Provenance, RevocationDecision, RevocationObject,
    RevocationRegistry, RevocationScope, SealValidation, ZoneBound, ZoneId,
};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use semver::Version;

fn fixed_validity_window() -> (chrono::DateTime<Utc>, chrono::DateTime<Utc>) {
    let not_before = Utc
        .with_ymd_and_hms(2000, 1, 1, 0, 0, 0)
        .single()
        .expect("valid fixed test timestamp");
    let expires = Utc
        .with_ymd_and_hms(2100, 1, 1, 0, 0, 0)
        .single()
        .expect("valid fixed expiry timestamp");
    (not_before, expires)
}

fn wildcard_constraints_cbor() -> Vec<u8> {
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("constraint serialization must succeed");
    cbor
}

fn build_test_token(
    signing_key: &Ed25519SigningKey,
    zone_id: &str,
    capability_id: &str,
    operation_id: &str,
) -> CapabilityToken {
    let (not_before, expires) = fixed_validity_window();
    let constraints_cbor = wildcard_constraints_cbor();
    let raw = CapabilityTokenBuilder::new()
        .capability_id(capability_id)
        .zone_id(zone_id)
        .principal("user:metamorphic")
        .operations(&[operation_id])
        .issuer("node:metamorphic")
        .audience(zone_id)
        .token_id(b"metamorphic-token")
        .validity(not_before, expires)
        .try_constraints_cbor(&constraints_cbor)
        .expect("test constraints CBOR should be valid")
        .sign(signing_key)
        .expect("fixed-input token signing must succeed");
    CapabilityToken::from_raw(raw)
}

fn test_header() -> ObjectHeader {
    ObjectHeader {
        encryption_kind: Default::default(),
        schema: SchemaId::new("fcp.core", "RevocationObject", Version::new(1, 0, 0)),
        zone_id: ZoneId::work(),
        created_at: 1_700_000_000,
        provenance: Provenance::new(ZoneId::work()),
        refs: vec![],
        foreign_refs: vec![],
        ttl_secs: None,
        placement: None,
    }
}

fn test_revocation(
    token_id: ObjectId,
    effective_at: u64,
    expires_at: Option<u64>,
    signature_byte: u8,
) -> RevocationObject {
    RevocationObject {
        header: test_header(),
        revoked: vec![token_id],
        scope: RevocationScope::Capability,
        reason: format!("metamorphic-revocation-{signature_byte}"),
        effective_at,
        expires_at,
        signature: [signature_byte; 64],
    }
}

#[test]
#[allow(deprecated)]
fn metamorphic_mr1_capability_verification_stabilizes_under_reverify() {
    let signing_key = Ed25519SigningKey::from_bytes(&[7u8; 32]).expect("fixed key must parse");
    let verifier = CapabilityVerifier::without_instance_binding(
        signing_key.verifying_key().to_bytes(),
        ZoneId::work(),
    );
    let capability = CapabilityId::from_static("cap.metamorphic");
    let operation = OperationId::from_static("op.metamorphic");
    let token = build_test_token(
        &signing_key,
        ZoneId::work().as_str(),
        capability.as_str(),
        operation.as_str(),
    );

    let by_ref_claims = verifier
        .verify_claims(&token, &capability, &operation, &[])
        .expect("reference verification must succeed")
        .to_cbor()
        .expect("claims must serialize deterministically");

    let owned_checked = verifier
        .verify(token, &capability, &operation, &[])
        .expect("owned verification must succeed");
    let first_claims = owned_checked
        .claims()
        .to_cbor()
        .expect("verified claims must serialize deterministically");
    let raw_token = owned_checked
        .raw()
        .to_cbor()
        .expect("verified raw token must serialize");

    let reverified = verifier
        .verify(owned_checked.downgrade(), &capability, &operation, &[])
        .expect("downgraded token must re-verify");

    assert_eq!(first_claims, by_ref_claims);
    assert_eq!(
        reverified
            .claims()
            .to_cbor()
            .expect("re-verified claims must serialize"),
        first_claims
    );
    assert_eq!(
        reverified
            .raw()
            .to_cbor()
            .expect("re-verified raw token must serialize"),
        raw_token
    );
}

#[test]
#[allow(deprecated)]
fn metamorphic_mr2_zone_scoping_is_exact_not_parent_derived() {
    let parent_zone = ZoneId::work();
    let child_zone: ZoneId = "z:work:child".parse().expect("child zone must parse");

    let bound = ZoneBound::bind("payload", child_zone.clone());
    let access = bound.with_zone_check(&parent_zone, |payload| payload.len());
    assert!(matches!(
        access,
        Err(FcpError::ZoneViolation {
            ref source_zone,
            ref target_zone,
            ..
        }) if source_zone == child_zone.as_str() && target_zone == parent_zone.as_str()
    ));

    let signing_key = Ed25519SigningKey::from_bytes(&[9u8; 32]).expect("fixed key must parse");
    let verifier = CapabilityVerifier::without_instance_binding(
        signing_key.verifying_key().to_bytes(),
        parent_zone,
    );
    let capability = CapabilityId::from_static("cap.zone-meta");
    let operation = OperationId::from_static("op.zone-meta");
    let token = build_test_token(
        &signing_key,
        child_zone.as_str(),
        capability.as_str(),
        operation.as_str(),
    );

    let err = verifier
        .verify(token, &capability, &operation, &[])
        .expect_err("parent-like zone names must not imply containment");
    assert!(matches!(err, FcpError::ZoneViolation { .. }));
}

#[test]
fn metamorphic_mr3_capability_token_signing_is_deterministic_for_fixed_inputs() {
    let signing_key = Ed25519SigningKey::from_bytes(&[42u8; 32]).expect("fixed key must parse");
    let capability = CapabilityId::from_static("cap.deterministic");
    let operation = OperationId::from_static("op.deterministic");

    let first = build_test_token(
        &signing_key,
        ZoneId::work().as_str(),
        capability.as_str(),
        operation.as_str(),
    )
    .into_raw()
    .to_cbor()
    .expect("first token must serialize");

    let second = build_test_token(
        &signing_key,
        ZoneId::work().as_str(),
        capability.as_str(),
        operation.as_str(),
    )
    .into_raw()
    .to_cbor()
    .expect("second token must serialize");

    assert_eq!(first, second);
}

#[test]
fn metamorphic_mr4_revocation_remains_one_way_under_dominated_updates() {
    let token_id = ObjectId::from_bytes([0xAB; 32]);
    let now = 1_700_000_500;
    let mut registry = RevocationRegistry::new();

    let permanent = test_revocation(token_id, now - 10, None, 1);
    registry.add_revocation(&permanent);
    registry.update_head(ObjectId::from_bytes([1u8; 32]), 1, now);

    let initial_seal = registry.check_with_seal(&token_id, now);
    assert_eq!(initial_seal.decision, RevocationDecision::Revoked);
    assert!(registry.is_revoked(&token_id));
    assert!(registry.is_revoked_at(&token_id, now));

    let dominated = test_revocation(token_id, now + 3_600, Some(now + 7_200), 2);
    registry.add_revocation(&dominated);
    registry.update_head(ObjectId::from_bytes([2u8; 32]), 2, now + 1);

    let retained = registry
        .get_revocation(&token_id)
        .expect("revocation entry must still exist");
    assert_eq!(retained.effective_at, permanent.effective_at);
    assert_eq!(retained.expires_at, permanent.expires_at);
    assert!(registry.is_revoked(&token_id));
    assert!(registry.is_revoked_at(&token_id, now));

    let refreshed_seal = registry.check_with_seal(&token_id, now + 1);
    assert_eq!(refreshed_seal.decision, RevocationDecision::Revoked);
    assert!(matches!(
        registry.validate_seal(&refreshed_seal, &token_id),
        SealValidation::Valid
    ));
    assert!(matches!(
        registry.validate_seal(&initial_seal, &token_id),
        SealValidation::Stale { .. }
    ));
}
