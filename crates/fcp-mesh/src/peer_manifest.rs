//! Owner-authenticated membership for the live mesh invoke directory.
//!
//! A peer may sign an advertisement, but cannot appoint itself (or another
//! peer) as a trust root. This envelope is verified against independently
//! configured owner keys and an explicit mesh identity. It signs the exact
//! payload JSON, not a re-serialization supplied by the receiver.
//!
//! The verified view is also bound to the local node's real signing key.
//! Persist its checkpoint before activating a replacement directory. A
//! checkpoint is a trusted-storage record, not a substitute for verification.

use std::collections::BTreeSet;

use fcp_core::TailscaleNodeId;
use fcp_crypto::ed25519::{Ed25519Signature, Ed25519SigningKey, Ed25519VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::invoke_route::{
    DEFAULT_MESH_FORWARD_MAX_SKEW_MS, MeshPeerConfig, MeshPeerDirectory,
};

/// Signed payload schema, covered by the owner's signature.
pub const MESH_PEER_DIRECTORY_SCHEMA: &str = "fcp.mesh.peer-directory.v1";
/// Maximum payload size accepted before parsing or signature verification.
pub const MAX_MESH_PEER_DIRECTORY_BYTES: usize = 1024 * 1024;
/// Maximum serialized envelope size (including escaped payload JSON).
pub const MAX_SIGNED_MESH_PEER_DIRECTORY_BYTES: usize = 4 * 1024 * 1024;
/// Maximum members in one owner-authorized directory, including this node.
pub const MAX_MESH_DIRECTORY_PEERS: usize = 4096;

const SIGNING_CONTEXT: &[u8] = b"FCP-MESH-PEER-DIRECTORY-V1";

/// Membership document shared unchanged by every host in one mesh.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshPeerDirectoryPayload {
    /// Must equal [`MESH_PEER_DIRECTORY_SCHEMA`].
    pub schema_version: String,
    /// Operator-selected mesh identity, independently pinned by each host.
    pub mesh_id: String,
    /// Strictly increasing membership generation. Zero is not valid.
    pub generation: u64,
    /// Unix milliseconds at issuance.
    pub issued_at_ms: u64,
    /// Exclusive expiration time in Unix milliseconds.
    pub expires_at_ms: u64,
    /// Complete membership, including every host's own node and public key.
    pub peers: Vec<MeshPeerConfig>,
}

/// An owner-signed directory. The embedded key is only a selector, never trust.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedMeshPeerDirectory {
    /// Hex public key; must match an independently configured trusted owner.
    pub signer_public_key_hex: String,
    /// Exact JSON bytes covered by the signature.
    pub payload_json: String,
    /// Domain-separated Ed25519 signature, encoded as 128 hex characters.
    pub signature_hex: String,
}

/// A persisted acceptance record used to reject rollback and equivocation.
///
/// Store atomically on trusted storage. The timestamp is the most recent
/// recorded verification time, not a claim to have observed all wall-clock time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshPeerDirectoryCheckpoint {
    /// Storage record schema (currently 1).
    pub schema_version: u8,
    /// Mesh identity this checkpoint protects.
    pub mesh_id: String,
    /// Local node to which acceptance was bound.
    pub local_node: String,
    /// Highest accepted generation.
    pub generation: u64,
    /// Hash of the exact signed payload, excluding the signature and signer.
    pub payload_hash_hex: String,
    /// Most recent persisted verification time in Unix milliseconds.
    pub last_observed_ms: u64,
}

/// A directory that passed owner, scope, validity, and local-key verification.
#[derive(Debug, Clone)]
pub struct VerifiedMeshPeerDirectory {
    directory: MeshPeerDirectory,
    payload: MeshPeerDirectoryPayload,
    checkpoint: MeshPeerDirectoryCheckpoint,
}

/// Failure to authenticate or safely advance mesh membership.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MeshPeerDirectoryError {
    /// Malformed, oversized, or internally inconsistent document.
    #[error("invalid signed mesh directory: {0}")]
    Invalid(String),
    /// The document was not signed by an independently trusted owner.
    #[error("mesh directory owner is not trusted")]
    UntrustedOwner,
    /// The selected owner's signature did not verify.
    #[error("mesh directory owner signature is invalid")]
    InvalidSignature,
    /// The directory names a different mesh from the locally pinned identity.
    #[error("mesh directory scope does not match the configured mesh")]
    WrongMesh,
    /// The document is expired or issued too far in the future.
    #[error("mesh directory is outside its signed validity window")]
    OutsideValidityWindow,
    /// Local node membership is absent or does not match the actual signing key.
    #[error("mesh directory does not authorize this node's signing key")]
    LocalIdentityMismatch,
    /// Persistent state belongs to another mesh or node, or is malformed.
    #[error("mesh directory checkpoint is invalid or belongs to another identity")]
    InvalidCheckpoint,
    /// The incoming generation is older than the accepted generation.
    #[error("mesh directory generation {incoming} precedes accepted generation {accepted}")]
    Rollback {
        /// Incoming generation.
        incoming: u64,
        /// Previously accepted generation.
        accepted: u64,
    },
    /// The owner signed different payloads with the same generation.
    #[error("mesh directory generation was reused for a different payload")]
    Equivocation,
    /// The clock is older than the most recently persisted observation.
    #[error("mesh directory verification clock precedes its persisted observation")]
    ClockRollback,
}

impl SignedMeshPeerDirectory {
    /// Sign a structurally valid membership document with an owner key.
    ///
    /// # Errors
    /// Returns an error for invalid membership, serialization, or size limits.
    pub fn sign(
        owner: &Ed25519SigningKey,
        payload: &MeshPeerDirectoryPayload,
    ) -> Result<Self, MeshPeerDirectoryError> {
        validate_payload(payload)?;
        let payload_json = serde_json::to_string(payload)
            .map_err(|_| invalid("payload cannot be serialized"))?;
        if payload_json.len() > MAX_MESH_PEER_DIRECTORY_BYTES {
            return Err(invalid("payload exceeds byte limit"));
        }
        let signature_hex = owner
            .sign_with_context(SIGNING_CONTEXT, payload_json.as_bytes())
            .to_hex();
        Ok(Self {
            signer_public_key_hex: hex::encode(owner.verifying_key().to_bytes()),
            payload_json,
            signature_hex,
        })
    }

    /// Decode a size-bounded envelope. This does not authenticate membership.
    ///
    /// # Errors
    /// Returns an error for oversized input or invalid JSON/envelope fields.
    pub fn from_json(json: &str) -> Result<Self, MeshPeerDirectoryError> {
        if json.len() > MAX_SIGNED_MESH_PEER_DIRECTORY_BYTES {
            return Err(invalid("envelope exceeds byte limit"));
        }
        serde_json::from_str(json).map_err(|_| invalid("malformed envelope JSON"))
    }

    /// Authenticate membership against independent roots and the local identity.
    ///
    /// No key contained in the document can add itself to `trusted_owners`.
    /// The returned checkpoint must pass [`VerifiedMeshPeerDirectory::check_successor`]
    /// and be durably committed before a persistent host activates the directory.
    ///
    /// # Errors
    /// Rejects malformed, untrusted, expired, incorrectly scoped, or locally
    /// misbound documents. Does not mutate any persistent state.
    pub fn verify(
        &self,
        trusted_owners: &[Ed25519VerifyingKey],
        expected_mesh_id: &str,
        local_node: TailscaleNodeId,
        local_key: &Ed25519VerifyingKey,
        now_ms: u64,
    ) -> Result<VerifiedMeshPeerDirectory, MeshPeerDirectoryError> {
        if self.payload_json.len() > MAX_MESH_PEER_DIRECTORY_BYTES {
            return Err(invalid("payload exceeds byte limit"));
        }
        let signer_bytes = decode_hex::<32>(&self.signer_public_key_hex)
            .ok_or_else(|| invalid("malformed signer public key"))?;
        let owner = trusted_owners
            .iter()
            .find(|key| key.to_bytes() == signer_bytes)
            .ok_or(MeshPeerDirectoryError::UntrustedOwner)?;
        let signature_bytes = decode_hex::<64>(&self.signature_hex)
            .ok_or_else(|| invalid("malformed signature"))?;
        owner
            .verify_with_context(
                SIGNING_CONTEXT,
                self.payload_json.as_bytes(),
                &Ed25519Signature::from_bytes(&signature_bytes),
            )
            .map_err(|_| MeshPeerDirectoryError::InvalidSignature)?;
        let payload: MeshPeerDirectoryPayload = serde_json::from_str(&self.payload_json)
            .map_err(|_| invalid("malformed payload JSON"))?;
        validate_payload(&payload)?;
        if payload.mesh_id != expected_mesh_id {
            return Err(MeshPeerDirectoryError::WrongMesh);
        }
        if now_ms >= payload.expires_at_ms
            || payload.issued_at_ms > now_ms.saturating_add(DEFAULT_MESH_FORWARD_MAX_SKEW_MS)
        {
            return Err(MeshPeerDirectoryError::OutsideValidityWindow);
        }
        let local = payload
            .peers
            .iter()
            .find(|peer| peer.node_id == local_node.as_str())
            .ok_or(MeshPeerDirectoryError::LocalIdentityMismatch)?;
        if decode_hex::<32>(&local.public_key_hex) != Some(local_key.to_bytes()) {
            return Err(MeshPeerDirectoryError::LocalIdentityMismatch);
        }
        let directory = MeshPeerDirectory::from_configs(local_node.clone(), &payload.peers)
            .map_err(|_| invalid("invalid member identity, endpoint, or public key"))?;
        let checkpoint = MeshPeerDirectoryCheckpoint {
            schema_version: 1,
            mesh_id: payload.mesh_id.clone(),
            local_node: local_node.as_str().to_owned(),
            generation: payload.generation,
            payload_hash_hex: payload_hash(&self.payload_json),
            last_observed_ms: now_ms,
        };
        Ok(VerifiedMeshPeerDirectory {
            directory,
            payload,
            checkpoint,
        })
    }
}

impl VerifiedMeshPeerDirectory {
    /// Verified peer view, excluding this host as a forwarding target.
    #[must_use]
    pub const fn directory(&self) -> &MeshPeerDirectory {
        &self.directory
    }

    /// The complete authenticated payload, including local membership.
    #[must_use]
    pub const fn payload(&self) -> &MeshPeerDirectoryPayload {
        &self.payload
    }

    /// Record to persist before activating this directory.
    #[must_use]
    pub const fn checkpoint(&self) -> &MeshPeerDirectoryCheckpoint {
        &self.checkpoint
    }

    /// Check a trusted previous record without changing it.
    ///
    /// Re-loading the identical generation is permitted. Re-signing an identical
    /// payload with another independently trusted owner is also permitted; changing
    /// any payload byte requires a higher generation, including validity renewal.
    ///
    /// # Errors
    /// Rejects wrong-scope or corrupt records, rollback, generation reuse, and a
    /// clock earlier than the previous persisted verification observation.
    pub fn check_successor(
        &self,
        previous: &MeshPeerDirectoryCheckpoint,
    ) -> Result<(), MeshPeerDirectoryError> {
        let incoming = &self.checkpoint;
        if previous.schema_version != 1
            || previous.mesh_id != incoming.mesh_id
            || previous.local_node != incoming.local_node
            || previous.generation == 0
            || decode_hex::<32>(&previous.payload_hash_hex).is_none()
        {
            return Err(MeshPeerDirectoryError::InvalidCheckpoint);
        }
        if incoming.generation < previous.generation {
            return Err(MeshPeerDirectoryError::Rollback {
                incoming: incoming.generation,
                accepted: previous.generation,
            });
        }
        if incoming.generation == previous.generation
            && incoming.payload_hash_hex != previous.payload_hash_hex
        {
            return Err(MeshPeerDirectoryError::Equivocation);
        }
        if incoming.last_observed_ms < previous.last_observed_ms {
            return Err(MeshPeerDirectoryError::ClockRollback);
        }
        Ok(())
    }
}

fn invalid(message: &str) -> MeshPeerDirectoryError {
    MeshPeerDirectoryError::Invalid(message.to_owned())
}

fn decode_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 {
        return None;
    }
    let mut bytes = [0; N];
    hex::decode_to_slice(value, &mut bytes).ok()?;
    Some(bytes)
}

fn payload_hash(payload: &str) -> String {
    let mut hash = blake3::Hasher::new();
    hash.update(SIGNING_CONTEXT);
    hash.update(payload.as_bytes());
    hash.finalize().to_hex().to_string()
}

fn validate_payload(payload: &MeshPeerDirectoryPayload) -> Result<(), MeshPeerDirectoryError> {
    if payload.schema_version != MESH_PEER_DIRECTORY_SCHEMA {
        return Err(invalid("unsupported payload schema"));
    }
    if payload.mesh_id.is_empty()
        || payload.mesh_id.len() > 128
        || !payload
            .mesh_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    {
        return Err(invalid("mesh_id must be 1..128 identifier bytes"));
    }
    if payload.generation == 0 || payload.expires_at_ms <= payload.issued_at_ms {
        return Err(invalid("generation or validity interval is invalid"));
    }
    if payload.peers.is_empty() || payload.peers.len() > MAX_MESH_DIRECTORY_PEERS {
        return Err(invalid("member count is outside limits"));
    }
    let mut seen = BTreeSet::new();
    for peer in &payload.peers {
        if peer.node_id != peer.node_id.trim() || !seen.insert(peer.node_id.as_str()) {
            return Err(invalid("member identities must be unique and unpadded"));
        }
    }
    // Validate every entry, including the member skipped as the local target.
    let first = TailscaleNodeId::try_new(payload.peers[0].node_id.clone())
        .map_err(|_| invalid("invalid member identity"))?;
    MeshPeerDirectory::from_configs(first, &payload.peers)
        .map_err(|_| invalid("invalid member identity, endpoint, or public key"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 100_000;

    struct Fixture {
        owner: Ed25519SigningKey,
        local: Ed25519SigningKey,
        document: MeshPeerDirectoryPayload,
    }

    impl Fixture {
        fn new() -> Self {
            let owner = Ed25519SigningKey::from_bytes(&[1; 32]).unwrap();
            let local = Ed25519SigningKey::from_bytes(&[2; 32]).unwrap();
            let peer = Ed25519SigningKey::from_bytes(&[3; 32]).unwrap();
            let document = MeshPeerDirectoryPayload {
                schema_version: MESH_PEER_DIRECTORY_SCHEMA.to_owned(),
                mesh_id: "personal-mesh".to_owned(),
                generation: 7,
                issued_at_ms: NOW - 1000,
                expires_at_ms: NOW + 60_000,
                peers: vec![
                    MeshPeerConfig {
                        node_id: "node-a".to_owned(),
                        endpoint: "http://127.0.0.1:8001".to_owned(),
                        public_key_hex: hex::encode(local.verifying_key().to_bytes()),
                    },
                    MeshPeerConfig {
                        node_id: "node-b".to_owned(),
                        endpoint: "https://node-b.example:8443".to_owned(),
                        public_key_hex: hex::encode(peer.verifying_key().to_bytes()),
                    },
                ],
            };
            Self {
                owner,
                local,
                document,
            }
        }

        fn signed(&self) -> SignedMeshPeerDirectory {
            SignedMeshPeerDirectory::sign(&self.owner, &self.document).unwrap()
        }

        fn verify(
            &self,
            signed: &SignedMeshPeerDirectory,
            now: u64,
        ) -> Result<VerifiedMeshPeerDirectory, MeshPeerDirectoryError> {
            signed.verify(
                &[self.owner.verifying_key()],
                "personal-mesh",
                TailscaleNodeId::try_new("node-a").unwrap(),
                &self.local.verifying_key(),
                now,
            )
        }
    }

    #[test]
    fn authenticated_directory_round_trips_and_binds_local_identity() {
        let f = Fixture::new();
        let wire = serde_json::to_string(&f.signed()).unwrap();
        let signed = SignedMeshPeerDirectory::from_json(&wire).unwrap();
        let verified = f.verify(&signed, NOW).unwrap();
        assert_eq!(verified.directory().len(), 1);
        assert_eq!(verified.directory().local_node().as_str(), "node-a");
        assert_eq!(verified.payload().peers.len(), 2);
        assert_eq!(verified.checkpoint().generation, 7);
        let json = serde_json::to_string(verified.checkpoint()).unwrap();
        let previous = serde_json::from_str(&json).unwrap();
        f.verify(&signed, NOW + 1)
            .unwrap()
            .check_successor(&previous)
            .unwrap();
    }

    #[test]
    fn embedded_signer_is_not_a_trust_root() {
        let f = Fixture::new();
        let outsider = Ed25519SigningKey::from_bytes(&[9; 32]).unwrap();
        let signed = SignedMeshPeerDirectory::sign(&outsider, &f.document).unwrap();
        assert_eq!(
            f.verify(&signed, NOW).unwrap_err(),
            MeshPeerDirectoryError::UntrustedOwner
        );
        assert!(
            f.signed()
                .verify(
                    &[],
                    "personal-mesh",
                    TailscaleNodeId::try_new("node-a").unwrap(),
                    &f.local.verifying_key(),
                    NOW,
                )
                .is_err()
        );
    }

    #[test]
    fn tampered_payload_and_wrong_signature_domain_are_rejected() {
        let f = Fixture::new();
        let mut signed = f.signed();
        signed.payload_json.push(' ');
        assert_eq!(
            f.verify(&signed, NOW).unwrap_err(),
            MeshPeerDirectoryError::InvalidSignature
        );
        signed.signature_hex = f
            .owner
            .sign_with_context(b"another-protocol", signed.payload_json.as_bytes())
            .to_hex();
        assert_eq!(
            f.verify(&signed, NOW).unwrap_err(),
            MeshPeerDirectoryError::InvalidSignature
        );
    }

    #[test]
    fn signature_fields_are_bounded_and_checked() {
        let f = Fixture::new();
        for value in ["", "ff", "not-hex"] {
            let mut signed = f.signed();
            signed.signature_hex = value.to_owned();
            assert!(f.verify(&signed, NOW).is_err());
            let mut signed = f.signed();
            signed.signer_public_key_hex = value.to_owned();
            assert!(f.verify(&signed, NOW).is_err());
        }
    }

    #[test]
    fn independently_pinned_mesh_is_required() {
        let mut f = Fixture::new();
        f.document.mesh_id = "another-mesh".to_owned();
        assert_eq!(
            f.verify(&f.signed(), NOW).unwrap_err(),
            MeshPeerDirectoryError::WrongMesh
        );
    }

    #[test]
    fn local_membership_and_actual_signing_key_are_required() {
        let mut f = Fixture::new();
        f.document.peers[0].public_key_hex = f.document.peers[1].public_key_hex.clone();
        assert_eq!(
            f.verify(&f.signed(), NOW).unwrap_err(),
            MeshPeerDirectoryError::LocalIdentityMismatch
        );
        f.document.peers.remove(0);
        assert_eq!(
            f.verify(&f.signed(), NOW).unwrap_err(),
            MeshPeerDirectoryError::LocalIdentityMismatch
        );
    }

    #[test]
    fn duplicate_local_member_cannot_be_hidden_by_directory_self_filtering() {
        let mut f = Fixture::new();
        f.document.peers.push(f.document.peers[0].clone());
        assert!(SignedMeshPeerDirectory::sign(&f.owner, &f.document).is_err());
    }

    #[test]
    fn invalid_schema_membership_and_lifetime_cannot_be_signed() {
        let f = Fixture::new();
        let mut payload = f.document.clone();
        payload.schema_version = "future-schema".to_owned();
        assert!(SignedMeshPeerDirectory::sign(&f.owner, &payload).is_err());
        payload = f.document.clone();
        payload.peers[0].endpoint = "file:///private".to_owned();
        assert!(SignedMeshPeerDirectory::sign(&f.owner, &payload).is_err());
        payload = f.document.clone();
        payload.peers.clear();
        assert!(SignedMeshPeerDirectory::sign(&f.owner, &payload).is_err());
        payload = f.document.clone();
        payload.generation = 0;
        assert!(SignedMeshPeerDirectory::sign(&f.owner, &payload).is_err());
        payload = f.document.clone();
        payload.expires_at_ms = payload.issued_at_ms;
        assert!(SignedMeshPeerDirectory::sign(&f.owner, &payload).is_err());
    }

    #[test]
    fn expiration_is_exclusive_and_future_issuance_is_bounded() {
        let mut f = Fixture::new();
        assert!(f.verify(&f.signed(), f.document.expires_at_ms - 1).is_ok());
        assert_eq!(
            f.verify(&f.signed(), f.document.expires_at_ms).unwrap_err(),
            MeshPeerDirectoryError::OutsideValidityWindow
        );
        f.document.issued_at_ms = NOW + DEFAULT_MESH_FORWARD_MAX_SKEW_MS + 1;
        assert_eq!(
            f.verify(&f.signed(), NOW).unwrap_err(),
            MeshPeerDirectoryError::OutsideValidityWindow
        );
    }

    #[test]
    fn older_generation_and_same_generation_replacement_fail_closed() {
        let mut f = Fixture::new();
        let old = f.verify(&f.signed(), NOW).unwrap().checkpoint().clone();
        f.document.generation -= 1;
        let incoming = f.verify(&f.signed(), NOW + 1).unwrap();
        assert_eq!(
            incoming.check_successor(&old).unwrap_err(),
            MeshPeerDirectoryError::Rollback {
                incoming: 6,
                accepted: 7,
            }
        );
        f.document.generation = 7;
        f.document.expires_at_ms += 1;
        let incoming = f.verify(&f.signed(), NOW + 1).unwrap();
        assert_eq!(
            incoming.check_successor(&old).unwrap_err(),
            MeshPeerDirectoryError::Equivocation
        );
        f.document.generation += 1;
        f.verify(&f.signed(), NOW + 1)
            .unwrap()
            .check_successor(&old)
            .unwrap();
    }

    #[test]
    fn identical_payload_may_rotate_between_independently_trusted_owners() {
        let mut f = Fixture::new();
        let old = f.verify(&f.signed(), NOW).unwrap().checkpoint().clone();
        f.owner = Ed25519SigningKey::from_bytes(&[4; 32]).unwrap();
        f.verify(&f.signed(), NOW + 1)
            .unwrap()
            .check_successor(&old)
            .unwrap();
    }

    #[test]
    fn foreign_corrupt_or_future_checkpoint_is_not_reset() {
        let f = Fixture::new();
        let verified = f.verify(&f.signed(), NOW).unwrap();
        let original = verified.checkpoint();
        for field in ["mesh", "node", "schema", "hash", "generation"] {
            let mut prior = original.clone();
            match field {
                "mesh" => prior.mesh_id = "other".to_owned(),
                "node" => prior.local_node = "other".to_owned(),
                "schema" => prior.schema_version = 2,
                "hash" => prior.payload_hash_hex = "bad".to_owned(),
                _ => prior.generation = 0,
            }
            assert_eq!(
                verified.check_successor(&prior).unwrap_err(),
                MeshPeerDirectoryError::InvalidCheckpoint
            );
        }
        let mut prior = original.clone();
        prior.last_observed_ms += 1;
        assert_eq!(
            verified.check_successor(&prior).unwrap_err(),
            MeshPeerDirectoryError::ClockRollback
        );
    }

    #[test]
    fn envelope_and_payload_limits_are_checked_before_work() {
        assert!(
            SignedMeshPeerDirectory::from_json(
                &" ".repeat(MAX_SIGNED_MESH_PEER_DIRECTORY_BYTES + 1)
            )
            .is_err()
        );
        let f = Fixture::new();
        let mut signed = f.signed();
        signed.payload_json = " ".repeat(MAX_MESH_PEER_DIRECTORY_BYTES + 1);
        assert!(matches!(
            f.verify(&signed, NOW),
            Err(MeshPeerDirectoryError::Invalid(_))
        ));
    }
}
