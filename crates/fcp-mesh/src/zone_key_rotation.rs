//! V3/V4 zone-key rotation cutover helpers for mesh senders and receivers.
//!
//! The sender builds one `ZoneKeyManifest` that can contain HPKE-X25519
//! wraps for V3 peers and X-Wing wraps for V4 peers. Peers that still need
//! HPKE during a V4 cutover are tracked as deferred acknowledgers so the
//! owner can re-send an X-Wing wrap when they advertise a V4 key.

use fcp_core::{
    NodeId, NodeSignature, TailscaleNodeId, WrappedKey, WrappedZoneKeyV4, ZoneId, ZoneKemAlgorithm,
    ZoneKey, ZoneKeyManifest, wrap_zone_key,
};
use fcp_crypto::{CryptoError, Fcp4Aad, X25519PublicKey, XWingKem, XWingPublicKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::gossip::PeerProtocolCapabilities;

/// Sender preference for per-recipient zone-key wrapping during V3/V4 migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreferredKem {
    /// Prefer X-Wing when the recipient has advertised V4 plus an X-Wing key;
    /// otherwise use HPKE-X25519 unless `require_pq_kem` forbids fallback.
    Auto,
    /// Force HPKE-X25519 selection. Rejected when `require_pq_kem` is set.
    HpkeX25519,
    /// Prefer X-Wing and fall back only when `require_pq_kem` is not set.
    XWing,
}

/// Local protocol-version policy used by mesh zone-key senders and receivers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolVersionPolicy {
    /// Preferred KEM for newly issued zone-key wraps.
    pub preferred_kem: PreferredKem,
    /// Refuse any recipient or incoming manifest that would require a
    /// non-post-quantum zone-key wrap.
    pub require_pq_kem: bool,
}

impl ProtocolVersionPolicy {
    /// Policy for the migration period: prefer X-Wing, tolerate V3 peers.
    #[must_use]
    pub const fn migration_default() -> Self {
        Self {
            preferred_kem: PreferredKem::Auto,
            require_pq_kem: false,
        }
    }

    /// Policy after a zone declares V4-only key wrapping.
    #[must_use]
    pub const fn require_xwing() -> Self {
        Self {
            preferred_kem: PreferredKem::XWing,
            require_pq_kem: true,
        }
    }
}

impl Default for ProtocolVersionPolicy {
    fn default() -> Self {
        Self::migration_default()
    }
}

/// Recipient key material and advertised mesh protocol capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneKeyRecipient {
    /// Recipient node ID as carried in zone-key manifests.
    pub node_id: TailscaleNodeId,
    /// V3 HPKE-X25519 public key from the node key attestation.
    pub hpke_public_key: X25519PublicKey,
    /// Optional V4 X-Wing public key from the node key attestation.
    pub xwing_public_key: Option<XWingPublicKey>,
    /// Signed gossip capability advertisement for V3/V4 negotiation.
    pub protocol_capabilities: PeerProtocolCapabilities,
}

impl ZoneKeyRecipient {
    /// Build a recipient descriptor.
    #[must_use]
    pub fn new(
        node_id: TailscaleNodeId,
        hpke_public_key: X25519PublicKey,
        xwing_public_key: Option<XWingPublicKey>,
        protocol_capabilities: PeerProtocolCapabilities,
    ) -> Self {
        Self {
            node_id,
            hpke_public_key,
            xwing_public_key,
            protocol_capabilities,
        }
    }
}

/// Why a peer cannot produce the final V4 cutover acknowledgement yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeferredAckReason {
    /// Peer has not advertised V4 support yet.
    V3OnlyPeer,
    /// Peer advertised V4 support but has no X-Wing public key in its
    /// attested key set.
    MissingXWingPublicKey,
}

/// Per-peer acknowledgement requirement produced by a zone-key cutover.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ZoneKeyRotationAckRequirement {
    /// Peer received a wrap in the preferred V4 KEM and can acknowledge
    /// the cutover immediately.
    Immediate {
        /// Recipient node.
        peer: TailscaleNodeId,
        /// KEM used for this recipient's wrap.
        kem: ZoneKemAlgorithm,
    },
    /// Peer received a fallback HPKE wrap and must acknowledge later once
    /// it publishes V4 capability and X-Wing key material.
    Deferred {
        /// Recipient node.
        peer: TailscaleNodeId,
        /// Reason the peer cannot complete the V4 cutover now.
        reason: DeferredAckReason,
    },
}

/// Aggregate state for a peer-driven zone-key cutover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZoneKeyRotationPhase {
    /// All recipients received X-Wing wraps.
    Complete,
    /// At least one recipient got an HPKE fallback wrap and must
    /// acknowledge after publishing V4 key material.
    DeferredAcknowledgement,
}

/// Built zone-key rotation proposal ready for owner signing and gossip.
#[derive(Debug, Clone)]
pub struct ZoneKeyRotationCutover {
    /// Mixed V3/V4 manifest carrying the new zone key.
    pub manifest: ZoneKeyManifest,
    /// Cutover phase derived from per-peer acknowledgement requirements.
    pub phase: ZoneKeyRotationPhase,
    /// Peer-driven acknowledgement requirements for this manifest.
    pub acknowledgements: Vec<ZoneKeyRotationAckRequirement>,
}

impl ZoneKeyRotationCutover {
    /// Return the peers that need a deferred V4 acknowledgement.
    #[must_use]
    pub fn deferred_ack_peers(&self) -> Vec<TailscaleNodeId> {
        self.acknowledgements
            .iter()
            .filter_map(|ack| match ack {
                ZoneKeyRotationAckRequirement::Immediate { .. } => None,
                ZoneKeyRotationAckRequirement::Deferred { peer, .. } => Some(peer.clone()),
            })
            .collect()
    }
}

/// Zone-key rotation construction or receiver-policy failure.
#[derive(Debug, Error)]
pub enum ZoneKeyRotationError {
    /// Policy requires X-Wing, but this recipient cannot receive it.
    #[error(
        "peer {peer} cannot receive X-Wing zone-key wrap while policy requires PQ KEM: {reason:?}"
    )]
    PostQuantumKemRequired {
        /// Recipient node.
        peer: String,
        /// Missing peer capability or key material.
        reason: DeferredAckReason,
    },
    /// Policy forbids loading a non-PQ wrap from an incoming manifest.
    #[error("peer {peer} received {kem:?} zone-key wrap while policy requires X-Wing")]
    KemTooWeak {
        /// Recipient node.
        peer: String,
        /// KEM used by the incoming manifest.
        kem: ZoneKemAlgorithm,
    },
    /// No zone-key wrap was published for the requested recipient.
    #[error("manifest has no zone-key wrap for peer {peer}")]
    MissingRecipientWrap {
        /// Recipient node.
        peer: String,
    },
    /// HPKE-X25519 wrapping failed.
    #[error("HPKE zone-key wrap failed for peer {peer}: {source}")]
    HpkeWrap {
        /// Recipient node.
        peer: String,
        /// Underlying core zone-key error.
        source: fcp_core::ZoneKeyError,
    },
    /// X-Wing AAD construction or sealing failed.
    #[error("X-Wing zone-key wrap failed for peer {peer}: {source}")]
    XWingWrap {
        /// Recipient node.
        peer: String,
        /// Underlying crypto error.
        source: CryptoError,
    },
    /// Canonical manifest payload serialization failed.
    #[error("zone-key manifest payload serialization failed: {0}")]
    PayloadSerialization(String),
}

/// Build a mixed V3/V4 zone-key manifest for a peer-driven cutover.
///
/// The returned manifest is deliberately not re-signed; callers must run the
/// owner-signing flow after this helper fills in the recipient wraps.
///
/// # Errors
///
/// Returns [`ZoneKeyRotationError`] when policy requires X-Wing but a
/// recipient can only receive HPKE, or when HPKE/X-Wing wrapping fails.
pub fn build_zone_key_rotation_cutover<K>(
    mut manifest: ZoneKeyManifest,
    zone_key: &ZoneKey,
    recipients: &[ZoneKeyRecipient],
    policy: ProtocolVersionPolicy,
    xwing: &K,
) -> Result<ZoneKeyRotationCutover, ZoneKeyRotationError>
where
    K: XWingKem,
{
    manifest.kem = ZoneKemAlgorithm::HpkeX25519;
    let mut acknowledgements = Vec::with_capacity(recipients.len());

    for recipient in recipients {
        match choose_kem(recipient, policy)? {
            ChosenKem::XWing(public_key) => {
                let sealed = seal_zone_key_xwing(
                    xwing,
                    public_key,
                    &manifest.zone_id,
                    manifest.valid_from,
                    recipient,
                    zone_key,
                )?;
                upsert_xwing_wrap(&mut manifest, recipient.node_id.clone(), sealed);
                manifest.kem = ZoneKemAlgorithm::XWing;
                acknowledgements.push(ZoneKeyRotationAckRequirement::Immediate {
                    peer: recipient.node_id.clone(),
                    kem: ZoneKemAlgorithm::XWing,
                });
            }
            ChosenKem::Hpke { deferred_reason } => {
                let wrapped = wrap_zone_key_result(
                    &recipient.hpke_public_key,
                    &manifest.zone_id,
                    &recipient.node_id,
                    manifest.valid_from,
                    zone_key,
                )?;
                upsert_hpke_wrap(&mut manifest, wrapped);
                if let Some(reason) = deferred_reason {
                    acknowledgements.push(ZoneKeyRotationAckRequirement::Deferred {
                        peer: recipient.node_id.clone(),
                        reason,
                    });
                } else {
                    acknowledgements.push(ZoneKeyRotationAckRequirement::Immediate {
                        peer: recipient.node_id.clone(),
                        kem: ZoneKemAlgorithm::HpkeX25519,
                    });
                }
            }
        }
    }

    let phase = if acknowledgements
        .iter()
        .any(|ack| matches!(ack, ZoneKeyRotationAckRequirement::Deferred { .. }))
    {
        ZoneKeyRotationPhase::DeferredAcknowledgement
    } else {
        ZoneKeyRotationPhase::Complete
    };

    Ok(ZoneKeyRotationCutover {
        manifest,
        phase,
        acknowledgements,
    })
}

/// Resolve and enforce the local receiver policy for an incoming zone-key wrap.
///
/// # Errors
///
/// Returns [`ZoneKeyRotationError::MissingRecipientWrap`] when the manifest
/// does not include this peer, and [`ZoneKeyRotationError::KemTooWeak`] when
/// `policy.require_pq_kem` rejects a non-X-Wing wrap.
pub fn enforce_incoming_zone_key_policy(
    manifest: &ZoneKeyManifest,
    recipient: &TailscaleNodeId,
    policy: ProtocolVersionPolicy,
) -> Result<WrappedKey, ZoneKeyRotationError> {
    let wrapped = manifest
        .resolved_wrapped_key_for(recipient)
        .ok_or_else(|| ZoneKeyRotationError::MissingRecipientWrap {
            peer: recipient.as_str().to_string(),
        })?;
    if policy.require_pq_kem && wrapped.kem() != ZoneKemAlgorithm::XWing {
        return Err(ZoneKeyRotationError::KemTooWeak {
            peer: recipient.as_str().to_string(),
            kem: wrapped.kem(),
        });
    }
    Ok(wrapped)
}

/// Canonical payload bytes that the owner signature must cover after cutover.
///
/// The embedded legacy signature is normalized before serialization so
/// signature bytes are not recursively signed. Changing `kem` or any
/// per-recipient `WrappedKey` variant changes these payload bytes.
///
/// # Errors
///
/// Returns [`ZoneKeyRotationError::PayloadSerialization`] if CBOR encoding
/// fails.
pub fn zone_key_manifest_owner_payload(
    manifest: &ZoneKeyManifest,
) -> Result<Vec<u8>, ZoneKeyRotationError> {
    let mut unsigned = manifest.clone();
    unsigned.signature = NodeSignature::new(
        NodeId::new(unsigned.signature.node_id.as_str()),
        [0_u8; 64],
        0,
    );
    let mut bytes = Vec::new();
    ciborium::into_writer(&unsigned, &mut bytes)
        .map_err(|err| ZoneKeyRotationError::PayloadSerialization(err.to_string()))?;
    Ok(bytes)
}

enum ChosenKem<'a> {
    XWing(&'a XWingPublicKey),
    Hpke {
        deferred_reason: Option<DeferredAckReason>,
    },
}

fn choose_kem(
    recipient: &ZoneKeyRecipient,
    policy: ProtocolVersionPolicy,
) -> Result<ChosenKem<'_>, ZoneKeyRotationError> {
    if policy.preferred_kem == PreferredKem::HpkeX25519 {
        if policy.require_pq_kem {
            return Err(post_quantum_required(
                recipient,
                DeferredAckReason::MissingXWingPublicKey,
            ));
        }
        return Ok(ChosenKem::Hpke {
            deferred_reason: None,
        });
    }

    if recipient.protocol_capabilities.supports_v4()
        && let Some(public_key) = recipient.xwing_public_key.as_ref()
    {
        return Ok(ChosenKem::XWing(public_key));
    }

    let reason = if recipient.protocol_capabilities.supports_v4() {
        DeferredAckReason::MissingXWingPublicKey
    } else {
        DeferredAckReason::V3OnlyPeer
    };
    if policy.require_pq_kem {
        return Err(post_quantum_required(recipient, reason));
    }
    Ok(ChosenKem::Hpke {
        deferred_reason: Some(reason),
    })
}

fn post_quantum_required(
    recipient: &ZoneKeyRecipient,
    reason: DeferredAckReason,
) -> ZoneKeyRotationError {
    ZoneKeyRotationError::PostQuantumKemRequired {
        peer: recipient.node_id.as_str().to_string(),
        reason,
    }
}

fn wrap_zone_key_result(
    recipient_pk: &X25519PublicKey,
    zone_id: &ZoneId,
    recipient_node_id: &TailscaleNodeId,
    issued_at: u64,
    zone_key: &ZoneKey,
) -> Result<fcp_core::WrappedZoneKey, ZoneKeyRotationError> {
    wrap_zone_key(
        recipient_pk,
        zone_id,
        recipient_node_id,
        issued_at,
        zone_key,
    )
    .map_err(|source| ZoneKeyRotationError::HpkeWrap {
        peer: recipient_node_id.as_str().to_string(),
        source,
    })
}

fn seal_zone_key_xwing<K>(
    xwing: &K,
    public_key: &XWingPublicKey,
    zone_id: &ZoneId,
    issued_at: u64,
    recipient: &ZoneKeyRecipient,
    zone_key: &ZoneKey,
) -> Result<fcp_crypto::XWingSealedBox, ZoneKeyRotationError>
where
    K: XWingKem,
{
    let aad = Fcp4Aad::for_zone_key(
        zone_id.as_bytes(),
        recipient.node_id.as_str().as_bytes(),
        issued_at,
    )
    .encode()
    .map_err(|source| ZoneKeyRotationError::XWingWrap {
        peer: recipient.node_id.as_str().to_string(),
        source,
    })?;
    xwing
        .seal(public_key, zone_key.as_bytes(), &aad)
        .map_err(|source| ZoneKeyRotationError::XWingWrap {
            peer: recipient.node_id.as_str().to_string(),
            source,
        })
}

fn upsert_hpke_wrap(manifest: &mut ZoneKeyManifest, wrapped: fcp_core::WrappedZoneKey) {
    manifest
        .wrapped_keys
        .retain(|entry| entry.recipient != wrapped.recipient);
    manifest.wrapped_keys.push(wrapped.clone());
    upsert_wrapped_key_v4(
        &mut manifest.wrapped_keys_v4,
        WrappedZoneKeyV4 {
            recipient: wrapped.recipient,
            issued_at: wrapped.issued_at,
            sealed: WrappedKey::from_hpke(wrapped.sealed),
        },
    );
}

fn upsert_xwing_wrap(
    manifest: &mut ZoneKeyManifest,
    recipient: TailscaleNodeId,
    sealed: fcp_crypto::XWingSealedBox,
) {
    upsert_wrapped_key_v4(
        &mut manifest.wrapped_keys_v4,
        WrappedZoneKeyV4 {
            recipient,
            issued_at: manifest.valid_from,
            sealed: WrappedKey::from_xwing(sealed),
        },
    );
}

fn upsert_wrapped_key_v4(entries: &mut Vec<WrappedZoneKeyV4>, entry: WrappedZoneKeyV4) {
    if let Some(existing) = entries
        .iter_mut()
        .find(|existing| existing.recipient == entry.recipient)
    {
        *existing = entry;
    } else {
        entries.push(entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_core::{
        NodeId, ObjectHeader, ObjectIdKeyId, Provenance, ZONE_KEY_LEN, ZoneKeyAlgorithm, ZoneKeyId,
    };
    use fcp_crypto::{
        Ed25519Signature, Ed25519SigningKey, X25519SecretKey, XWingProvider, XWingSecretKey,
    };
    use semver::Version;

    fn test_manifest(zone_id: ZoneId, valid_from: u64) -> ZoneKeyManifest {
        ZoneKeyManifest {
            header: ObjectHeader {
                encryption_kind: Default::default(),
                schema: fcp_cbor::SchemaId::new(
                    "fcp.zone",
                    "ZoneKeyManifest",
                    Version::new(1, 0, 0),
                ),
                zone_id: zone_id.clone(),
                created_at: valid_from,
                provenance: Provenance::new(zone_id.clone()),
                refs: Vec::new(),
                foreign_refs: Vec::new(),
                ttl_secs: None,
                placement: None,
            },
            zone_id,
            zone_key_id: ZoneKeyId::from_bytes([0x44; 8]),
            object_id_key_id: ObjectIdKeyId::from_bytes([0x55; 8]),
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from,
            valid_until: None,
            prev_zone_key_id: Some(ZoneKeyId::from_bytes([0x33; 8])),
            wrapped_keys: Vec::new(),
            wrapped_object_id_keys: Vec::new(),
            rekey_policy: None,
            signature: NodeSignature::new(NodeId::new("zone-owner"), [0_u8; 64], valid_from),
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: Vec::new(),
        }
    }

    fn test_zone_key() -> ZoneKey {
        ZoneKey::from_bytes([0xA5; ZONE_KEY_LEN])
    }

    fn hpke_public_key() -> X25519PublicKey {
        X25519SecretKey::generate().public_key()
    }

    fn v3_recipient(name: &str) -> ZoneKeyRecipient {
        ZoneKeyRecipient::new(
            TailscaleNodeId::new(name),
            hpke_public_key(),
            None,
            PeerProtocolCapabilities::v3_only(),
        )
    }

    fn v4_recipient_with_secret(
        name: &str,
        xwing: &XWingProvider,
    ) -> (ZoneKeyRecipient, XWingSecretKey) {
        let (public_key, secret_key) = xwing.generate().expect("generate xwing key");
        let recipient = ZoneKeyRecipient::new(
            TailscaleNodeId::new(name),
            hpke_public_key(),
            Some(public_key),
            PeerProtocolCapabilities::v3_v4(),
        );
        (recipient, secret_key)
    }

    fn v4_recipient(name: &str, xwing: &XWingProvider) -> ZoneKeyRecipient {
        v4_recipient_with_secret(name, xwing).0
    }

    #[test]
    fn zone_key_rotation_v4_mixed_manifest_deferred_ack_for_late_peer() {
        let xwing = XWingProvider::new();
        let zone_id = ZoneId::work();
        let zone_key = test_zone_key();
        let v3_peer = v3_recipient("peer-v3");
        let (v4_peer, v4_secret_key) = v4_recipient_with_secret("peer-v4", &xwing);
        let cutover = build_zone_key_rotation_cutover(
            test_manifest(zone_id.clone(), 1_700_000_000),
            &zone_key,
            &[v3_peer.clone(), v4_peer.clone()],
            ProtocolVersionPolicy::migration_default(),
            &xwing,
        )
        .expect("mixed cutover");

        assert_eq!(cutover.phase, ZoneKeyRotationPhase::DeferredAcknowledgement);
        assert_eq!(cutover.deferred_ack_peers(), vec![v3_peer.node_id.clone()]);
        assert_eq!(cutover.manifest.kem, ZoneKemAlgorithm::XWing);
        assert_eq!(cutover.manifest.wrapped_keys.len(), 1);
        assert_eq!(cutover.manifest.wrapped_keys[0].recipient, v3_peer.node_id);

        let v3_wrap = cutover
            .manifest
            .wrapped_key_v4_for(&v3_peer.node_id)
            .expect("v3 promoted wrap");
        assert_eq!(v3_wrap.sealed.kem(), ZoneKemAlgorithm::HpkeX25519);
        let v4_wrap = cutover
            .manifest
            .wrapped_key_v4_for(&v4_peer.node_id)
            .expect("v4 xwing wrap");
        assert_eq!(v4_wrap.sealed.kem(), ZoneKemAlgorithm::XWing);
        let aad = Fcp4Aad::for_zone_key(
            zone_id.as_bytes(),
            v4_peer.node_id.as_str().as_bytes(),
            cutover.manifest.valid_from,
        )
        .encode()
        .expect("aad");
        let opened = xwing
            .open(
                &v4_secret_key,
                v4_wrap.sealed.xwing_sealed().expect("xwing sealed box"),
                &aad,
            )
            .expect("open xwing wrap");
        assert_eq!(opened, zone_key.as_bytes());

        let v4_incoming = enforce_incoming_zone_key_policy(
            &cutover.manifest,
            &v4_peer.node_id,
            ProtocolVersionPolicy::require_xwing(),
        )
        .expect("v4 xwing recipient satisfies pq policy");
        assert_eq!(v4_incoming.kem(), ZoneKemAlgorithm::XWing);

        let v3_incoming = enforce_incoming_zone_key_policy(
            &cutover.manifest,
            &v3_peer.node_id,
            ProtocolVersionPolicy::migration_default(),
        )
        .expect("migration policy accepts v3 fallback");
        assert_eq!(v3_incoming.kem(), ZoneKemAlgorithm::HpkeX25519);
    }

    #[test]
    fn zone_key_rotation_v4_require_pq_refuses_v4_recipient_without_xwing_key() {
        let xwing = XWingProvider::new();
        let zone_id = ZoneId::work();
        let recipient = ZoneKeyRecipient::new(
            TailscaleNodeId::new("peer-v4-no-xwing"),
            hpke_public_key(),
            None,
            PeerProtocolCapabilities::v3_v4(),
        );
        let err = build_zone_key_rotation_cutover(
            test_manifest(zone_id, 1_700_000_100),
            &test_zone_key(),
            &[recipient],
            ProtocolVersionPolicy::require_xwing(),
            &xwing,
        )
        .expect_err("require_pq_kem must refuse downgrade");

        assert!(matches!(
            err,
            ZoneKeyRotationError::PostQuantumKemRequired {
                reason: DeferredAckReason::MissingXWingPublicKey,
                ..
            }
        ));
    }

    #[test]
    fn zone_key_rotation_v4_receiver_rejects_hpke_fallback_when_pq_required() {
        let xwing = XWingProvider::new();
        let zone_id = ZoneId::work();
        let recipient = v3_recipient("late-peer");
        let cutover = build_zone_key_rotation_cutover(
            test_manifest(zone_id, 1_700_000_200),
            &test_zone_key(),
            std::slice::from_ref(&recipient),
            ProtocolVersionPolicy::migration_default(),
            &xwing,
        )
        .expect("fallback cutover");

        let err = enforce_incoming_zone_key_policy(
            &cutover.manifest,
            &recipient.node_id,
            ProtocolVersionPolicy::require_xwing(),
        )
        .expect_err("pq-required receiver rejects hpke fallback");
        assert!(matches!(
            err,
            ZoneKeyRotationError::KemTooWeak {
                kem: ZoneKemAlgorithm::HpkeX25519,
                ..
            }
        ));
    }

    #[test]
    fn zone_key_rotation_v4_downgrade_tamper_changes_signed_payload() {
        let xwing = XWingProvider::new();
        let zone_id = ZoneId::work();
        let zone_key = test_zone_key();
        let recipient = v4_recipient("peer-v4", &xwing);
        let mut manifest = build_zone_key_rotation_cutover(
            test_manifest(zone_id.clone(), 1_700_000_300),
            &zone_key,
            std::slice::from_ref(&recipient),
            ProtocolVersionPolicy::require_xwing(),
            &xwing,
        )
        .expect("v4 cutover")
        .manifest;

        let owner_key = Ed25519SigningKey::generate();
        let payload = zone_key_manifest_owner_payload(&manifest).expect("payload");
        let signature = owner_key.sign(&payload);
        manifest.signature = NodeSignature::new(
            NodeId::new("zone-owner"),
            signature.to_bytes(),
            manifest.valid_from,
        );
        let verifying_key = owner_key.verifying_key();
        let signature = Ed25519Signature::from_bytes(&manifest.signature.signature);
        let signed_payload = zone_key_manifest_owner_payload(&manifest).expect("signed payload");
        verifying_key
            .verify(&signed_payload, &signature)
            .expect("original signature verifies");

        let mut tampered = manifest.clone();
        let hpke_wrap = wrap_zone_key(
            &recipient.hpke_public_key,
            &zone_id,
            &recipient.node_id,
            tampered.valid_from,
            &zone_key,
        )
        .expect("hpke tamper wrap");
        tampered.kem = ZoneKemAlgorithm::HpkeX25519;
        tampered.wrapped_keys = vec![hpke_wrap.clone()];
        tampered.wrapped_keys_v4 = vec![hpke_wrap.to_v4()];
        let tampered_payload = zone_key_manifest_owner_payload(&tampered).expect("tampered");

        assert_ne!(signed_payload, tampered_payload);
        assert!(verifying_key.verify(&tampered_payload, &signature).is_err());
    }
}
