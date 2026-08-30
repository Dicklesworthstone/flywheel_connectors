//! Emergency revocation primitives — quorum-witness aggregation for
//! the operator-invoked kill-switch (m8j0q.8).
//!
//! Per ADR `docs/architecture/adr/m8j0q-emergency-revocation-protocol.md`:
//! the originator of an emergency revocation collects
//! [`PriorityGossipPolicy::EMERGENCY_QUORUM_WITNESSES`] (or majority of
//! online peers, whichever is smaller) signed [`RevocationWitness`]
//! records before considering propagation complete. The quorum makes
//! "compromised peer silently drops priority push" detectable: failed
//! propagation surfaces as `QuorumNotReached` instead of looking like a
//! successful revocation.
//!
//! [`PriorityGossipPolicy::EMERGENCY_QUORUM_WITNESSES`]: super::gossip::PriorityGossipPolicy::EMERGENCY_QUORUM_WITNESSES

use fcp_crypto::{CryptoError, Ed25519Signature, Ed25519VerifyingKey};
use fcp_prelude::{NodeSignature, ObjectId, TailscaleNodeId, ZoneId};
use serde::{Deserialize, Serialize};

/// Domain separator for [`RevocationWitness::witness_signing_bytes`]
/// — distinguishes emergency-revocation witness signatures from any
/// other signature transcript on the wire.
pub const REVOCATION_WITNESS_DOMAIN: &[u8] = b"FCP2-REVOCATION-WITNESS-V1";

/// A witness signature confirming that a peer has applied an
/// emergency revocation. Used by the originator to prove quorum
/// acknowledgement after the fact.
///
/// Wire form is canonical CBOR (round-trip pinned by the inline
/// tests below). The signature is over the byte string returned by
/// [`Self::witness_signing_bytes`], which deliberately excludes the
/// signature itself so a peer can sign-then-attach.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationWitness {
    /// Tailscale node id of the peer that witnessed the revocation.
    pub witnessing_node: TailscaleNodeId,
    /// Zone the revocation applies to.
    pub zone_id: ZoneId,
    /// Revocation head sequence after this revocation was applied.
    pub revocation_head_seq: u64,
    /// BLAKE3 of the sorted concatenation of revoked `ObjectId` bytes.
    /// Two witnesses for the same revocation MUST produce identical
    /// hashes regardless of how the witness happened to assemble its
    /// view of the revoked set.
    pub revoked_ids_hash: [u8; 32],
    /// Wall-clock time the witness applied the revocation (Unix ms).
    pub witnessed_at_unix_ms: u64,
    /// Peer signature over [`Self::witness_signing_bytes`].
    pub signature: Option<NodeSignature>,
}

impl RevocationWitness {
    /// Construct an unsigned witness. Call [`Self::with_signature`]
    /// after producing the signature over [`Self::witness_signing_bytes`].
    #[must_use]
    pub fn new(
        witnessing_node: TailscaleNodeId,
        zone_id: ZoneId,
        revocation_head_seq: u64,
        revoked_ids_hash: [u8; 32],
        witnessed_at_unix_ms: u64,
    ) -> Self {
        Self {
            witnessing_node,
            zone_id,
            revocation_head_seq,
            revoked_ids_hash,
            witnessed_at_unix_ms,
            signature: None,
        }
    }

    /// Attach a peer signature.
    #[must_use]
    pub fn with_signature(mut self, signature: NodeSignature) -> Self {
        self.signature = Some(signature);
        self
    }

    /// Compute [`Self::revoked_ids_hash`] from a slice of revoked IDs.
    /// IDs are sorted before hashing so two witnesses for the same
    /// revocation produce identical hashes regardless of input order.
    #[must_use]
    pub fn compute_revoked_ids_hash(revoked_ids: &[ObjectId]) -> [u8; 32] {
        let mut sorted: Vec<&ObjectId> = revoked_ids.iter().collect();
        sorted.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        let mut hasher = blake3::Hasher::new();
        hasher.update(REVOCATION_WITNESS_DOMAIN);
        for id in sorted {
            hasher.update(id.as_bytes());
        }
        *hasher.finalize().as_bytes()
    }

    /// Transcript bytes signed by the witnessing peer. Includes
    /// every field except `signature` itself — the signature wraps
    /// the transcript, not the envelope around it.
    ///
    /// Layout is little-endian length-prefixed for stable
    /// concatenation regardless of TailscaleNodeId/ZoneId byte length:
    ///
    /// ```text
    /// REVOCATION_WITNESS_DOMAIN
    /// || u32_le(len(witnessing_node))     || witnessing_node bytes
    /// || u32_le(len(zone_id))             || zone_id bytes
    /// || u64_le(revocation_head_seq)
    /// || revoked_ids_hash (32 bytes)
    /// || u64_le(witnessed_at_unix_ms)
    /// ```
    ///
    /// # Panics
    ///
    /// Panics in pathological-only cases where any encoded field
    /// length exceeds `u32::MAX`; saturating-cast prevents this in
    /// practice.
    #[must_use]
    pub fn witness_signing_bytes(&self) -> Vec<u8> {
        let node_bytes = self.witnessing_node.as_str().as_bytes();
        let zone_bytes = self.zone_id.as_bytes();
        let mut bytes = Vec::with_capacity(
            REVOCATION_WITNESS_DOMAIN.len()
                + 4
                + node_bytes.len()
                + 4
                + zone_bytes.len()
                + 8
                + 32
                + 8,
        );
        bytes.extend_from_slice(REVOCATION_WITNESS_DOMAIN);

        bytes.extend_from_slice(
            &u32::try_from(node_bytes.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        bytes.extend_from_slice(node_bytes);

        bytes.extend_from_slice(
            &u32::try_from(zone_bytes.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        bytes.extend_from_slice(zone_bytes);

        bytes.extend_from_slice(&self.revocation_head_seq.to_le_bytes());
        bytes.extend_from_slice(&self.revoked_ids_hash);
        bytes.extend_from_slice(&self.witnessed_at_unix_ms.to_le_bytes());
        bytes
    }

    /// Verify the attached signature against
    /// [`Self::witness_signing_bytes`] using the witness's public key.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::MissingField`] if `signature` is `None`,
    /// or the verifier's error if signature verification fails.
    pub fn verify_signature(&self, verifying_key: &Ed25519VerifyingKey) -> Result<(), CryptoError> {
        let signature = self
            .signature
            .as_ref()
            .ok_or_else(|| CryptoError::MissingField("witness_signature".into()))?;
        let signature = Ed25519Signature::from_bytes(&signature.signature);
        verifying_key.verify(&self.witness_signing_bytes(), &signature)
    }
}

/// Outcome of a quorum-collection attempt — whether enough witnesses
/// were gathered before the deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum QuorumStatus {
    /// At least the target number of witnesses signed — propagation
    /// considered complete.
    Reached {
        /// Witnesses collected.
        witnesses: u32,
        /// Target the originator was waiting for.
        target: u32,
        /// Total elapsed time in ms.
        elapsed_ms: u64,
    },
    /// Deadline elapsed before the witness target was reached.
    NotReached {
        /// Witnesses collected before the deadline.
        witnesses: u32,
        /// Target the originator was waiting for.
        target: u32,
        /// Total elapsed time in ms (== deadline).
        elapsed_ms: u64,
    },
}

impl QuorumStatus {
    /// Whether this outcome counts as successful propagation.
    #[must_use]
    pub const fn is_reached(&self) -> bool {
        matches!(self, Self::Reached { .. })
    }
}

/// Compute the effective quorum target for an emergency revocation:
/// the lesser of [`PriorityGossipPolicy::EMERGENCY_QUORUM_WITNESSES`](super::gossip::PriorityGossipPolicy::EMERGENCY_QUORUM_WITNESSES)
/// and the majority of online peers (rounded up).
///
/// Implements the "majority of online peers, whichever is smaller" rule from
/// the ADR's open-question resolution #2.
#[must_use]
pub const fn effective_quorum_target(online_peers: u32) -> u32 {
    let majority = online_peers.div_ceil(2);
    let nominal = super::gossip::PriorityGossipPolicy::EMERGENCY_QUORUM_WITNESSES as u32;
    if majority < nominal {
        majority
    } else {
        nominal
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_crypto::Ed25519SigningKey;
    use fcp_prelude::NodeId;

    fn signing_key_from_seed(seed: u8) -> Ed25519SigningKey {
        let bytes = [seed; 32];
        Ed25519SigningKey::from_bytes(&bytes).expect("valid signing key")
    }

    fn sample_witness(seq: u64) -> RevocationWitness {
        RevocationWitness::new(
            TailscaleNodeId::new("node-witness"),
            "z:work".parse().expect("valid zone id"),
            seq,
            [0xAA; 32],
            1_700_000_000_000,
        )
    }

    #[test]
    fn witness_signing_bytes_includes_domain_separator() {
        let w = sample_witness(7);
        let bytes = w.witness_signing_bytes();
        assert!(
            bytes.starts_with(REVOCATION_WITNESS_DOMAIN),
            "witness signing bytes missing domain separator prefix"
        );
    }

    #[test]
    fn witness_signing_bytes_is_deterministic() {
        let w = sample_witness(7);
        let a = w.witness_signing_bytes();
        let b = w.witness_signing_bytes();
        assert_eq!(a, b, "witness signing bytes are non-deterministic");
    }

    #[test]
    fn witness_signing_bytes_changes_when_any_field_changes() {
        let base = sample_witness(7);
        let baseline = base.witness_signing_bytes();

        let mut altered_seq = base.clone();
        altered_seq.revocation_head_seq = 8;
        assert_ne!(
            baseline,
            altered_seq.witness_signing_bytes(),
            "head_seq drift"
        );

        let mut altered_hash = base.clone();
        altered_hash.revoked_ids_hash = [0xBB; 32];
        assert_ne!(baseline, altered_hash.witness_signing_bytes(), "hash drift");

        let mut altered_ts = base.clone();
        altered_ts.witnessed_at_unix_ms = 1_700_000_000_001;
        assert_ne!(
            baseline,
            altered_ts.witness_signing_bytes(),
            "timestamp drift"
        );

        let mut altered_zone = base;
        altered_zone.zone_id = "z:public".parse().expect("valid zone id");
        assert_ne!(baseline, altered_zone.witness_signing_bytes(), "zone drift");
    }

    #[test]
    fn witness_signing_bytes_excludes_attached_signature() {
        // The signature field MUST NOT be included in the transcript
        // — otherwise sign-then-attach would invalidate itself.
        let unsigned = sample_witness(7);
        let mut signed = unsigned.clone();
        signed.signature = Some(NodeSignature::new(
            NodeId::new("node-witness"),
            [0u8; 64],
            1_700_000_000,
        ));
        assert_eq!(
            unsigned.witness_signing_bytes(),
            signed.witness_signing_bytes(),
            "signature field leaked into transcript"
        );
    }

    #[test]
    fn revocation_witness_signature_round_trip() {
        // m8j0q.8.b unit test from ADR §"Tests expected to follow".
        let sk = signing_key_from_seed(0x42);
        let pk = sk.verifying_key();
        let witness = sample_witness(7);
        let sig_bytes = sk.sign(&witness.witness_signing_bytes());
        let signed = witness.with_signature(NodeSignature::new(
            NodeId::new("node-witness"),
            sig_bytes.to_bytes(),
            1_700_000_000,
        ));
        signed
            .verify_signature(&pk)
            .expect("witness signature verifies");
    }

    #[test]
    fn revocation_witness_verification_rejects_wrong_key() {
        let sk_a = signing_key_from_seed(0x01);
        let sk_b = signing_key_from_seed(0x02);
        let pk_b = sk_b.verifying_key();
        let witness = sample_witness(7);
        let sig_bytes = sk_a.sign(&witness.witness_signing_bytes());
        let signed = witness.with_signature(NodeSignature::new(
            NodeId::new("node-witness"),
            sig_bytes.to_bytes(),
            1_700_000_000,
        ));
        signed
            .verify_signature(&pk_b)
            .expect_err("witness signed by A must not verify under B");
    }

    #[test]
    fn revocation_witness_verification_rejects_unsigned() {
        let pk = signing_key_from_seed(0x03).verifying_key();
        let witness = sample_witness(7);
        let err = witness
            .verify_signature(&pk)
            .expect_err("unsigned witness must not verify");
        match err {
            CryptoError::MissingField(field) => {
                assert!(field.contains("witness_signature"));
            }
            other => panic!("expected MissingField, got {other:?}"),
        }
    }

    #[test]
    fn witness_round_trips_through_canonical_cbor() {
        let sk = signing_key_from_seed(0x55);
        let witness = sample_witness(7);
        let sig_bytes = sk.sign(&witness.witness_signing_bytes());
        let signed = witness.with_signature(NodeSignature::new(
            NodeId::new("node-witness"),
            sig_bytes.to_bytes(),
            1_700_000_000,
        ));
        let cbor = fcp_cbor::to_canonical_cbor(&signed).expect("encode witness");
        let back: RevocationWitness =
            ciborium::de::from_reader(cbor.as_slice()).expect("decode witness");
        assert_eq!(back, signed);
    }

    #[test]
    fn compute_revoked_ids_hash_is_order_independent() {
        let a = ObjectId::from_bytes([0x01; 32]);
        let b = ObjectId::from_bytes([0x02; 32]);
        let c = ObjectId::from_bytes([0x03; 32]);
        let h1 = RevocationWitness::compute_revoked_ids_hash(&[a, b, c]);
        let h2 = RevocationWitness::compute_revoked_ids_hash(&[c, b, a]);
        let h3 = RevocationWitness::compute_revoked_ids_hash(&[b, a, c]);
        assert_eq!(h1, h2, "hash is not order-independent");
        assert_eq!(h2, h3, "hash is not order-independent");
    }

    #[test]
    fn compute_revoked_ids_hash_changes_when_set_changes() {
        let a = ObjectId::from_bytes([0x01; 32]);
        let b = ObjectId::from_bytes([0x02; 32]);
        let c = ObjectId::from_bytes([0x03; 32]);
        let with_b = RevocationWitness::compute_revoked_ids_hash(&[a, b]);
        let with_c = RevocationWitness::compute_revoked_ids_hash(&[a, c]);
        assert_ne!(with_b, with_c);
    }

    #[test]
    fn compute_revoked_ids_hash_uses_domain_separator() {
        // Pin: hashing is domain-separated so a witness hash cannot
        // collide with any other use of BLAKE3 over the same byte
        // sequence elsewhere in the protocol.
        let a = ObjectId::from_bytes([0x01; 32]);
        let with_domain = RevocationWitness::compute_revoked_ids_hash(&[a]);
        let raw = blake3::hash(a.as_bytes());
        assert_ne!(
            with_domain,
            *raw.as_bytes(),
            "witness hash collides with raw BLAKE3 of the ID — domain separator missing"
        );
    }

    // ── QuorumStatus + effective_quorum_target ─────────────────────────

    #[test]
    fn quorum_status_reached_predicate() {
        let reached = QuorumStatus::Reached {
            witnesses: 3,
            target: 3,
            elapsed_ms: 1234,
        };
        let not_reached = QuorumStatus::NotReached {
            witnesses: 1,
            target: 3,
            elapsed_ms: 5000,
        };
        assert!(reached.is_reached());
        assert!(!not_reached.is_reached());
    }

    #[test]
    fn effective_quorum_target_caps_at_majority_for_small_meshes() {
        // 2-node mesh: majority is 1, nominal is 3 → target is 1.
        assert_eq!(effective_quorum_target(2), 1);
        // 3-node mesh: majority is 2, nominal is 3 → target is 2.
        assert_eq!(effective_quorum_target(3), 2);
        // 4-node mesh: majority is 2, nominal is 3 → target is 2.
        assert_eq!(effective_quorum_target(4), 2);
        // 5-node mesh: majority is 3, nominal is 3 → target is 3.
        assert_eq!(effective_quorum_target(5), 3);
        // 7-node mesh: majority is 4, nominal is 3 → target is 3 (cap).
        assert_eq!(effective_quorum_target(7), 3);
        // 100-node mesh: nominal cap of 3 wins.
        assert_eq!(effective_quorum_target(100), 3);
    }

    #[test]
    fn effective_quorum_target_handles_degenerate_zero_peers() {
        // No peers online → target is 0; the originator's quorum
        // collection trivially reaches it. Whether to reject the
        // emergency revoke before propagation in that case is an
        // operational policy decision (recorded as a follow-up
        // observation in the ADR's "Open questions" tracking).
        assert_eq!(effective_quorum_target(0), 0);
    }
}
