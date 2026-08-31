//! Negative-path conformance harness.
//!
//! This file covers three concrete gaps in the existing conformance
//! surface (`datagram_golden_vectors`, capability interop, object header
//! round-trips) that together make up the "tamper-rejection" contract:
//!
//! 1. Capability golden tokens must reject any single-byte signature
//!    mutation (Ed25519 is a MUST-REJECT for `InvalidSignature`).
//! 2. Capability golden tokens must reject any single-byte payload
//!    (CWT claims) mutation: signature covers the full `tbs_data`, so
//!    flipping a payload byte invalidates the signature even though
//!    the bytes re-parse as CBOR.
//! 3. `ObjectHeader` with every optional field populated must round-trip
//!    through canonical CBOR byte-identically — the re-encoded bytes
//!    must equal the original canonical bytes, and the decoded header
//!    must re-derive the same `ObjectId` for a given body (no
//!    round-trip drift in the content-addressed surface).
//!
//! Plus one load-bearing bonus: every byte of a session MAC must be
//! rejected when mutated individually (no MAC byte is redundant).
//!
//! Evidence bundle: `fcp-verification-bundle/v1` (see `VerificationEvidence`
//! struct emitted at the end of each scenario).

use fcp_cbor::SchemaId;
use fcp_conformance::{CapabilityTokenGoldenVector, DatagramMacGoldenVector};
use fcp_crypto::cose::{CapabilityTokenBuilder, CoseToken};
use fcp_crypto::ed25519::{Ed25519SigningKey, Ed25519VerifyingKey};
use fcp_prelude::{
    DeviceSelector, ObjectHeader, ObjectIdKey, ObjectPlacementPolicy, Provenance, StoredObject,
    TaintLevel, ZoneId,
};
use fcp_protocol::{
    MeshSessionId, SessionCryptoSuite, SessionDirection, compute_session_mac, verify_session_mac,
};
use semver::Version;
use serde::Serialize;

// ─────────────────────────────────────────────────────────────────────────────
// Evidence emitter (fcp-verification-bundle/v1)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct VerificationEvidence<'a> {
    bundle: &'static str,
    scenario: &'a str,
    outcome: &'static str,
    vectors_exercised: usize,
    mutations_checked: usize,
    all_rejected: bool,
}

fn emit_evidence(evidence: &VerificationEvidence<'_>) {
    let line = serde_json::to_string(evidence).expect("evidence is serializable");
    eprintln!("{line}");
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    hex::decode(hex).unwrap_or_else(|e| panic!("invalid hex: {e}"))
}

// ─────────────────────────────────────────────────────────────────────────────
// Capability token tamper rejection
// ─────────────────────────────────────────────────────────────────────────────

/// Locate the signature region inside a `COSE_Sign1` CBOR array.
///
/// `COSE_Sign1` is a CBOR array `[protected, unprotected, payload, signature]`
/// where `signature` is the last element and is encoded as a 64-byte byte
/// string `0x58 0x40 <64 bytes>`. The marker `0x58 0x40` appearing within
/// the last 66 bytes is unambiguous for Ed25519 golden vectors; we locate
/// it by scanning from the tail.
fn signature_byte_range(token_bytes: &[u8]) -> std::ops::Range<usize> {
    assert!(token_bytes.len() >= 66, "token too short to contain sig");
    let start_marker = token_bytes.len() - 66;
    assert_eq!(token_bytes[start_marker], 0x58, "expected bstr marker 0x58");
    assert_eq!(token_bytes[start_marker + 1], 0x40, "expected length 64");
    (start_marker + 2)..token_bytes.len()
}

/// Rebuild the `CoseToken` from possibly-tampered bytes and run the
/// cryptographic `verify()` step against the golden vector's public key.
///
/// Returns `Ok(())` if the token verifies, `Err(...)` otherwise. This
/// intentionally skips `CapabilityVerifier::verify()` (which also
/// checks timing via `Utc::now()`) because the golden vectors embed
/// fixed `exp` timestamps in 2023 that are long past; the goal here is
/// to isolate signature-level tamper rejection, not real-clock drift.
fn try_verify_token(bytes: &[u8], pubkey_hex: &str) -> Result<(), String> {
    let token = CoseToken::from_cbor(bytes).map_err(|e| format!("from_cbor failed: {e}"))?;
    let pubkey_bytes: [u8; 32] = hex_to_bytes(pubkey_hex)
        .try_into()
        .expect("vector pubkey is 32 bytes");
    let vk = Ed25519VerifyingKey::from_bytes(&pubkey_bytes)
        .map_err(|e| format!("from_bytes failed: {e}"))?;
    token
        .verify(&vk)
        .map(|_| ())
        .map_err(|e| format!("verify failed: {e}"))
}

/// Contract (NORMATIVE): every byte of the Ed25519 signature on a
/// valid capability token is load-bearing. Flipping any single byte in
/// the 64-byte signature region MUST cause `CoseToken::verify()` to
/// fail. Verifies across ALL capability golden vectors.
#[test]
fn capability_golden_signature_single_byte_tamper_is_rejected() {
    let vectors = CapabilityTokenGoldenVector::load_all();
    let mut total_mutations = 0usize;
    let all_rejected = true;

    for v in &vectors {
        let baseline = hex_to_bytes(&v.expected_token_cbor);

        // Baseline: untouched golden token must verify.
        try_verify_token(&baseline, &v.expected_public_key).unwrap_or_else(|e| {
            panic!(
                "golden vector is not self-consistent: {} — {e}",
                v.description
            )
        });

        let sig_range = signature_byte_range(&baseline);
        for sig_byte in sig_range {
            let mut tampered = baseline.clone();
            tampered[sig_byte] ^= 0x01;
            total_mutations += 1;

            let verdict = try_verify_token(&tampered, &v.expected_public_key);
            assert!(
                verdict.is_err(),
                "vector '{}': flipping signature byte at offset {} did \
                 NOT invalidate verification — Ed25519 is supposed to \
                 reject any single-byte mutation",
                v.description,
                sig_byte
            );
        }
    }

    emit_evidence(&VerificationEvidence {
        bundle: "fcp-verification-bundle/v1",
        scenario: "capability_signature_byte_tamper_rejected",
        outcome: "all_mutations_rejected",
        vectors_exercised: vectors.len(),
        mutations_checked: total_mutations,
        all_rejected,
    });
}

/// Contract (NORMATIVE): every byte of the CWT claims payload is
/// covered by the Ed25519 signature. Flipping any single byte inside
/// the payload region MUST invalidate verification.
///
/// This is the counterpart to the signature-tamper test: if the
/// signature only covered a prefix of the payload, an attacker could
/// silently mutate capability claims (operations, zone, expiry) after
/// signing. The test samples byte positions inside the payload region
/// (everything before the signature marker) across all golden vectors.
#[test]
fn capability_golden_payload_byte_tamper_is_rejected() {
    let vectors = CapabilityTokenGoldenVector::load_all();
    let mut total_mutations = 0usize;
    let all_rejected = true;

    for v in &vectors {
        let baseline = hex_to_bytes(&v.expected_token_cbor);
        let sig_range = signature_byte_range(&baseline);
        // Payload/protected/unprotected all live before the signature
        // marker (which starts at sig_range.start - 2 for the 0x58 0x40
        // prefix). Skip the first 2 bytes (CBOR array header + protected
        // header length marker) so mutations land in semantically
        // meaningful bytes — those first two bytes are structural and a
        // flip may just produce an unparseable token, which still
        // "rejects" but isn't the contract we care about here.
        let payload_region_start = 2;
        let payload_region_end = sig_range.start - 2;

        // Sample every 8th byte to keep runtime reasonable on large
        // vectors while still covering >10% of the payload surface.
        for offset in (payload_region_start..payload_region_end).step_by(8) {
            let mut tampered = baseline.clone();
            tampered[offset] ^= 0x01;
            total_mutations += 1;

            let verdict = try_verify_token(&tampered, &v.expected_public_key);
            assert!(
                verdict.is_err(),
                "vector '{}': flipping payload byte at offset {} did NOT \
                 invalidate verification — the signature must cover the \
                 entire COSE_Sign1 tbs_data, including every payload byte",
                v.description,
                offset
            );
        }
    }

    emit_evidence(&VerificationEvidence {
        bundle: "fcp-verification-bundle/v1",
        scenario: "capability_payload_byte_tamper_rejected",
        outcome: "all_sampled_mutations_rejected",
        vectors_exercised: vectors.len(),
        mutations_checked: total_mutations,
        all_rejected,
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// ObjectHeader canonical CBOR round-trip (all optional fields populated)
// ─────────────────────────────────────────────────────────────────────────────

/// Contract (NORMATIVE): an `ObjectHeader` with EVERY optional field
/// populated must round-trip through canonical CBOR byte-identically,
/// and the resulting header must derive the same `ObjectId` for a
/// given body.
///
/// This closes a gap in the conformance surface: existing tests only
/// cover headers with `ttl_secs: None` and `placement: None`. A header
/// whose optional fields round-trip non-canonically would silently
/// change the content-addressed `ObjectId`, breaking replication and
/// checkpoint integrity.
#[test]
fn object_header_canonical_cbor_roundtrip_all_fields_populated() {
    let header = ObjectHeader {
        encryption_kind: Default::default(),
        schema: SchemaId::new("fcp.test", "RoundTrip", Version::new(2, 3, 4)),
        zone_id: ZoneId::work(),
        created_at: 1_700_000_000,
        provenance: Provenance {
            origin_zone: ZoneId::private(),
            chain: Vec::new(),
            taint: TaintLevel::Untainted,
            elevated: false,
            elevation_token: None,
        },
        refs: vec![
            fcp_core::ObjectId::from_unscoped_bytes(b"ref-1"),
            fcp_core::ObjectId::from_unscoped_bytes(b"ref-2"),
        ],
        foreign_refs: vec![fcp_core::ObjectId::from_unscoped_bytes(b"foreign-1")],
        ttl_secs: Some(86_400),
        placement: Some(ObjectPlacementPolicy {
            min_nodes: 3,
            max_node_fraction_bps: 5_000,
            preferred_devices: vec![
                DeviceSelector::Tag("ssd".into()),
                DeviceSelector::Zone(ZoneId::work()),
            ],
            excluded_devices: vec![DeviceSelector::Class("hdd".into())],
            target_coverage_bps: 10_000,
            min_source_diversity: 2,
        }),
    };

    let canonical_1 = fcp_cbor::to_canonical_cbor(&header)
        .expect("header with all optional fields must canonicalize");
    assert!(
        !canonical_1.is_empty(),
        "canonical encoding must not be empty"
    );

    // Decode → re-encode: must be byte-identical.
    let decoded: ObjectHeader = ciborium::de::from_reader(&canonical_1[..])
        .expect("canonical bytes must deserialize back to ObjectHeader");
    let canonical_2 =
        fcp_cbor::to_canonical_cbor(&decoded).expect("round-trip re-encode must succeed");
    assert_eq!(
        canonical_1, canonical_2,
        "canonical CBOR round-trip is not byte-stable: this breaks \
         content-addressed ObjectId derivation across replicas"
    );

    // ObjectId must match before and after round-trip for the same body.
    let body = b"round-trip body";
    let key = ObjectIdKey::from_bytes([7u8; 32]);
    let id_before =
        StoredObject::derive_id(&header, body, &key).expect("derive_id on original header");
    let id_after =
        StoredObject::derive_id(&decoded, body, &key).expect("derive_id on round-tripped header");
    assert_eq!(
        id_before, id_after,
        "ObjectId differs after round-trip — content-address drift detected"
    );

    emit_evidence(&VerificationEvidence {
        bundle: "fcp-verification-bundle/v1",
        scenario: "object_header_roundtrip_all_fields",
        outcome: "byte_identical_and_objectid_stable",
        vectors_exercised: 1,
        mutations_checked: 0,
        all_rejected: true,
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Bonus: session MAC byte-level tamper rejection
// ─────────────────────────────────────────────────────────────────────────────

/// Contract (NORMATIVE): every byte of the 16-byte session MAC is
/// load-bearing. Flipping any single byte MUST cause verification to
/// fail. This extends the existing `datagram_mac_wrong_key_fails` test
/// which only covers a key-level substitution, not byte-level
/// positional integrity.
#[test]
fn datagram_mac_every_byte_is_load_bearing() {
    let vectors = DatagramMacGoldenVector::load_all();
    let mut total_mutations = 0usize;

    for v in &vectors {
        let mac_key: [u8; 32] = hex_to_bytes(&v.mac_key).try_into().unwrap();
        let session_id_bytes: [u8; 16] = hex_to_bytes(&v.session_id).try_into().unwrap();
        let session_id = MeshSessionId(session_id_bytes);
        let frame_bytes = hex_to_bytes(&v.frame_bytes);
        let expected_mac: [u8; 16] = hex_to_bytes(&v.expected_mac).try_into().unwrap();

        let suite = match v.suite.as_str() {
            "Suite1" => SessionCryptoSuite::Suite1,
            "Suite2" => SessionCryptoSuite::Suite2,
            other => panic!("unknown suite: {other}"),
        };
        let direction = match v.direction.as_str() {
            "InitiatorToResponder" => SessionDirection::InitiatorToResponder,
            "ResponderToInitiator" => SessionDirection::ResponderToInitiator,
            other => panic!("unknown direction: {other}"),
        };

        // Baseline: untampered MAC verifies.
        verify_session_mac(
            suite,
            &mac_key,
            &session_id,
            direction,
            v.seq,
            &frame_bytes,
            &expected_mac,
        )
        .unwrap_or_else(|e| panic!("baseline MAC verify failed for '{}': {e}", v.description));

        // Also confirm compute_session_mac agrees (defense in depth: if
        // compute starts diverging from verify, neither tamper nor
        // baseline detection is meaningful).
        let recomputed =
            compute_session_mac(suite, &mac_key, &session_id, direction, v.seq, &frame_bytes)
                .expect("MAC recompute");
        assert_eq!(recomputed, expected_mac, "compute/verify divergence");

        // Flip each byte individually; every flip must fail verification.
        for byte_idx in 0..16 {
            let mut tampered = expected_mac;
            tampered[byte_idx] ^= 0x01;
            total_mutations += 1;

            let verdict = verify_session_mac(
                suite,
                &mac_key,
                &session_id,
                direction,
                v.seq,
                &frame_bytes,
                &tampered,
            );
            assert!(
                verdict.is_err(),
                "vector '{}': MAC byte {} was not load-bearing — \
                 single-byte flip passed verification, which means the \
                 MAC is not positionally integrity-protected",
                v.description,
                byte_idx
            );
        }
    }

    emit_evidence(&VerificationEvidence {
        bundle: "fcp-verification-bundle/v1",
        scenario: "datagram_mac_every_byte_load_bearing",
        outcome: "all_byte_flips_rejected",
        vectors_exercised: vectors.len(),
        mutations_checked: total_mutations,
        all_rejected: true,
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Cross-key replay rejection (freshly-minted tokens, not golden vectors)
// ─────────────────────────────────────────────────────────────────────────────
//
// The golden-vector tests above cover single-byte mutation. The two
// tests in this section cover a different adversarial axis: a token
// that is byte-perfect (no bit-flips) but presented to the wrong
// verifier, or re-signed by a different issuer. A correct CoseToken
// verifier MUST reject both — the first by KID pre-check (defense in
// depth), the second by the signature check (the primary defense).
//
// Both tests use freshly-generated Ed25519 keypairs so they're
// independent of the golden vectors' fixed keys; this also makes them
// more obviously forgery-shaped than the tamper-by-bit-flip style.

/// Construct a minimal signed capability token for use as baseline in
/// the cross-key adversarial tests below.
fn sign_minimal_token(signing_key: &Ed25519SigningKey) -> CoseToken {
    let claims = fcp_auth_schema::AuthClaims {
        schema_version: fcp_auth_schema::claims::CURRENT_SCHEMA_VERSION,
        capability_id: Some("cap:adversarial".into()),
        zone_id: Some("z:work".into()),
        principal_id: Some("alice@example".into()),
        ..fcp_auth_schema::AuthClaims::default()
    };
    CapabilityTokenBuilder::with_claims(&claims)
        .expect("build from AuthClaims")
        .sign(signing_key)
        .expect("sign")
}

/// Contract (NORMATIVE): a capability token that is byte-perfect but
/// presented to a verifier holding a different Ed25519 public key MUST
/// be rejected. The implementation rejects at the KID step — a
/// defense-in-depth check that happens BEFORE signature verification,
/// so we never spend Ed25519 verify cycles on obviously-wrong keys.
///
/// This closes the "wrong-key replay" gap: a token signed by issuer A
/// and handed to a verifier that only trusts issuer B must not verify
/// just because its bytes are internally valid.
#[test]
fn capability_token_cross_key_replay_is_rejected() {
    let issuer = Ed25519SigningKey::generate();
    let innocent_bystander = Ed25519SigningKey::generate();

    // Baseline: the issuer's own verifying key accepts the token.
    let token = sign_minimal_token(&issuer);
    token
        .verify(&issuer.verifying_key())
        .expect("self-verify must succeed");

    // Adversarial: a DIFFERENT verifying key must reject. Two keys
    // generated independently have distinct KIDs with overwhelming
    // probability, so this exercises the KID-mismatch path.
    assert_ne!(
        issuer.verifying_key().key_id().as_bytes(),
        innocent_bystander.verifying_key().key_id().as_bytes(),
        "fresh keys must have distinct KIDs"
    );
    let verdict = token.verify(&innocent_bystander.verifying_key());
    assert!(
        verdict.is_err(),
        "cross-key verification MUST fail — got Ok, which means a verifier \
         would accept a token it has no cryptographic basis to trust"
    );
    let err_debug = format!("{:?}", verdict.unwrap_err());
    assert!(
        err_debug.contains("KeyIdMismatch"),
        "cross-key rejection MUST surface KeyIdMismatch (defense-in-depth \
         pre-signature check), got: {err_debug}"
    );

    emit_evidence(&VerificationEvidence {
        bundle: "fcp-verification-bundle/v1",
        scenario: "capability_token_cross_key_replay_rejected",
        outcome: "kid_mismatch_enforced",
        vectors_exercised: 1,
        mutations_checked: 0,
        all_rejected: true,
    });
}

/// Contract (NORMATIVE): serializing a token to CBOR bytes and
/// deserializing it back must preserve the signature. This pins the
/// wire-format round-trip: a token that stops verifying after a pure
/// serde round-trip would be a silent interop break for any caller
/// that stores or forwards tokens as bytes.
#[test]
fn capability_token_cbor_roundtrip_preserves_signature() {
    let issuer = Ed25519SigningKey::generate();
    let token = sign_minimal_token(&issuer);

    let bytes = token.to_cbor().expect("serialize");
    let parsed = CoseToken::from_cbor(&bytes).expect("deserialize");
    parsed
        .verify(&issuer.verifying_key())
        .expect("round-tripped token MUST still verify");

    // And the inverse: a truncated token must not decode, and if it
    // does, it must not verify. Strip the last byte of the signature.
    let mut truncated = bytes;
    truncated.pop();
    let verdict = CoseToken::from_cbor(&truncated).and_then(|t| t.verify(&issuer.verifying_key()));
    assert!(
        verdict.is_err(),
        "truncated token MUST fail either decode or verify (cannot silently \
         succeed), got Ok"
    );

    emit_evidence(&VerificationEvidence {
        bundle: "fcp-verification-bundle/v1",
        scenario: "capability_token_cbor_roundtrip_preserves_signature",
        outcome: "roundtrip_verified_truncated_rejected",
        vectors_exercised: 1,
        mutations_checked: 1,
        all_rejected: true,
    });
}
