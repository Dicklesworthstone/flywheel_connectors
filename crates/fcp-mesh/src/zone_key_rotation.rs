//! V3/V4 zone-key rotation cutover helpers for mesh senders and receivers.
//!
//! The sender builds one `ZoneKeyManifest` that can contain HPKE-X25519
//! wraps for V3 peers and X-Wing wraps for V4 peers. Peers that still need
//! HPKE during a V4 cutover are tracked as deferred acknowledgers so the
//! owner can re-send an X-Wing wrap when they advertise a V4 key.

use std::collections::HashSet;

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
    /// Every recipient received the selected wrap without a deferred V4
    /// acknowledgement (including explicitly requested HPKE-only issuance).
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
    /// Recipient descriptors must name each node exactly once, so conflicting
    /// keys or capability advertisements cannot silently overwrite one another.
    #[error("zone-key rotation lists peer {peer} more than once")]
    DuplicateRecipient {
        /// Duplicate recipient node.
        peer: String,
    },
    /// The manifest contains ambiguous recipient wraps.
    #[error("invalid zone-key rotation manifest: {0}")]
    InvalidManifest(#[from] fcp_core::ZoneKeyError),
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
/// `recipients` is the complete authorized recipient set for this issuance,
/// not a list of incremental updates. Both zone-key wrap lists are rebuilt
/// from that set; removed peers receive no retained zone-key or object-ID-key
/// wrap, and upgrading a peer to X-Wing removes its legacy HPKE wrap. Object-ID
/// key wraps for retained recipients are preserved unchanged: callers must
/// supply valid object-ID wraps when adding recipients or rotating that key.
///
/// The caller supplies the new manifest metadata, including key IDs, validity
/// window, and predecessor. This helper does not generate keys or change that
/// metadata. It clears the inherited signature; callers must run the
/// owner-signing flow after this helper fills in the recipient wraps.
///
/// # Errors
///
/// Returns [`ZoneKeyRotationError`] when policy requires X-Wing but a
/// recipient can only receive HPKE, recipients are duplicated, the template
/// manifest has ambiguous wraps, or HPKE/X-Wing wrapping fails.
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
    manifest.validate_no_recipient_split_view()?;
    let mut recipient_ids = HashSet::with_capacity(recipients.len());
    for recipient in recipients {
        if !recipient_ids.insert(recipient.node_id.clone()) {
            return Err(ZoneKeyRotationError::DuplicateRecipient {
                peer: recipient.node_id.as_str().to_string(),
            });
        }
        // Validate the complete policy before doing any sealing work.
        choose_kem(recipient, policy)?;
    }

    // A membership-change or revocation rotation is a replacement issuance.
    // Upserting into inherited lists would preserve removed peers and leave
    // an HPKE/X-Wing split view when an existing peer upgrades to V4.
    manifest.wrapped_keys.clear();
    manifest.wrapped_keys_v4.clear();
    manifest
        .wrapped_object_id_keys
        .retain(|entry| recipient_ids.contains(&entry.recipient));
    manifest.signature.signature = [0_u8; 64];
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
                append_xwing_wrap(&mut manifest, recipient.node_id.clone(), sealed);
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
                append_hpke_wrap(&mut manifest, wrapped);
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

    manifest.validate_no_recipient_split_view()?;
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
/// does not include this peer, [`ZoneKeyRotationError::KemTooWeak`] when
/// `policy.require_pq_kem` rejects a non-X-Wing wrap, or
/// [`ZoneKeyRotationError::InvalidManifest`] for duplicate or split-view wraps.
/// This policy check does not replace owner-signature or freshness validation.
pub fn enforce_incoming_zone_key_policy(
    manifest: &ZoneKeyManifest,
    recipient: &TailscaleNodeId,
    policy: ProtocolVersionPolicy,
) -> Result<WrappedKey, ZoneKeyRotationError> {
    manifest.validate_no_recipient_split_view()?;
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

fn append_hpke_wrap(manifest: &mut ZoneKeyManifest, wrapped: fcp_core::WrappedZoneKey) {
    manifest.wrapped_keys_v4.push(wrapped.to_v4());
    manifest.wrapped_keys.push(wrapped);
}

fn append_xwing_wrap(
    manifest: &mut ZoneKeyManifest,
    recipient: TailscaleNodeId,
    sealed: fcp_crypto::XWingSealedBox,
) {
    manifest.wrapped_keys_v4.push(WrappedZoneKeyV4 {
        recipient,
        issued_at: manifest.valid_from,
        sealed: WrappedKey::from_xwing(sealed),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_core::{
        NodeId, ObjectHeader, ObjectIdKey, ObjectIdKeyId, Provenance, ZONE_KEY_LEN,
        ZoneKeyAlgorithm, ZoneKeyId, ZoneKeyRing, wrap_object_id_key,
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
        v3_recipient_with_secret(name).0
    }

    fn v3_recipient_with_secret(name: &str) -> (ZoneKeyRecipient, X25519SecretKey) {
        let secret = X25519SecretKey::generate();
        (
            ZoneKeyRecipient::new(
                TailscaleNodeId::new(name),
                secret.public_key(),
                None,
                PeerProtocolCapabilities::v3_only(),
            ),
            secret,
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

    #[test]
    #[allow(clippy::too_many_lines)]
    fn zone_key_rotation_v4_reissues_exact_membership_and_upgrades_existing_peer() {
        let xwing = XWingProvider::new();
        let zone_id = ZoneId::work();
        let (upgrading, upgrading_secret) = v3_recipient_with_secret("upgrading-peer");
        let (retained, retained_secret) = v3_recipient_with_secret("retained-v3-peer");
        let removed_v3 = v3_recipient("removed-v3-peer");
        let removed_v4 = v4_recipient("removed-v4-peer", &xwing);
        let initial_recipients = [
            upgrading.clone(),
            retained.clone(),
            removed_v3.clone(),
            removed_v4.clone(),
        ];
        let object_id_key = ObjectIdKey::from_bytes([0xCC; ZONE_KEY_LEN]);
        let mut initial = test_manifest(zone_id.clone(), 1_700_000_400);
        for recipient in &initial_recipients {
            initial.wrapped_object_id_keys.push(
                wrap_object_id_key(
                    &recipient.hpke_public_key,
                    &zone_id,
                    &recipient.node_id,
                    initial.valid_from,
                    &object_id_key,
                )
                .expect("initial object-ID wrap"),
            );
        }
        let initial = build_zone_key_rotation_cutover(
            initial,
            &test_zone_key(),
            &initial_recipients,
            ProtocolVersionPolicy::migration_default(),
            &xwing,
        )
        .expect("initial mixed issuance")
        .manifest;

        let (upgrading_public, upgrading_xwing_secret) = xwing.generate().expect("new X-Wing key");
        let mut upgraded = upgrading.clone();
        upgraded.xwing_public_key = Some(upgrading_public);
        upgraded.protocol_capabilities = PeerProtocolCapabilities::v3_v4();
        let next_zone_key = ZoneKey::from_bytes([0xB5; ZONE_KEY_LEN]);
        let mut next = initial.clone();
        next.zone_key_id = ZoneKeyId::from_bytes([0x66; 8]);
        next.prev_zone_key_id = Some(initial.zone_key_id);
        next.valid_from += 10;
        next.header.created_at = next.valid_from;
        next.signature.signature = [0xA1; 64];
        let next = build_zone_key_rotation_cutover(
            next,
            &next_zone_key,
            &[upgraded.clone(), retained.clone()],
            ProtocolVersionPolicy::migration_default(),
            &xwing,
        )
        .expect("membership-change rotation")
        .manifest;

        next.validate_no_recipient_split_view()
            .expect("upgraded recipient must have no legacy HPKE split view");
        assert_eq!(next.wrapped_keys.len(), 1);
        assert_eq!(next.wrapped_keys[0].recipient, retained.node_id);
        assert_eq!(next.wrapped_keys_v4.len(), 2);
        assert_eq!(next.wrapped_object_id_keys.len(), 2);
        assert_eq!(next.prev_zone_key_id, Some(initial.zone_key_id));
        assert_eq!(next.object_id_key_id, initial.object_id_key_id);
        assert_eq!(next.signature.signature, [0_u8; 64]);
        for removed in [&removed_v3, &removed_v4] {
            assert!(next.wrapped_key_for(&removed.node_id).is_none());
            assert!(next.wrapped_key_v4_for(&removed.node_id).is_none());
            assert!(next.wrapped_object_id_key_for(&removed.node_id).is_none());
            assert!(matches!(
                enforce_incoming_zone_key_policy(
                    &next,
                    &removed.node_id,
                    ProtocolVersionPolicy::migration_default(),
                ),
                Err(ZoneKeyRotationError::MissingRecipientWrap { .. })
            ));
        }
        let mut upgraded_ring = ZoneKeyRing::new(zone_id.clone());
        upgraded_ring
            .apply_manifest_v4(
                &next,
                &upgraded.node_id,
                &upgrading_secret,
                &upgrading_xwing_secret,
                &xwing,
            )
            .expect("upgraded recipient applies the actual rotation");
        assert_eq!(upgraded_ring.active_zone_key(), Some(&next_zone_key));
        assert_eq!(upgraded_ring.active_object_id_key(), Some(&object_id_key));
        assert_eq!(upgraded_ring.active_zone_key_id, Some(next.zone_key_id));
        let mut retained_ring = ZoneKeyRing::new(zone_id);
        retained_ring
            .apply_manifest(&next, &retained.node_id, &retained_secret)
            .expect("retained V3 recipient still applies the rotation");
        assert_eq!(retained_ring.active_zone_key(), Some(&next_zone_key));
        assert_eq!(retained_ring.active_object_id_key(), Some(&object_id_key));
        assert_eq!(initial.wrapped_keys_v4.len(), 4);
    }

    #[test]
    fn zone_key_rotation_v4_rejects_conflicting_recipient_descriptors() {
        let xwing = XWingProvider::new();
        let recipient = v3_recipient("duplicate-peer");
        let conflicting = v4_recipient("duplicate-peer", &xwing);
        let error = build_zone_key_rotation_cutover(
            test_manifest(ZoneId::work(), 1_700_000_500),
            &test_zone_key(),
            &[recipient, conflicting],
            ProtocolVersionPolicy::migration_default(),
            &xwing,
        )
        .expect_err("the last descriptor must not silently select a different KEM or key");
        assert!(matches!(
            error,
            ZoneKeyRotationError::DuplicateRecipient { .. }
        ));
    }

    #[test]
    fn zone_key_rotation_v4_refuses_split_view_before_receiver_policy_or_reissue() {
        let xwing = XWingProvider::new();
        let recipient = v4_recipient("split-view-peer", &xwing);
        let mut manifest = build_zone_key_rotation_cutover(
            test_manifest(ZoneId::work(), 1_700_000_600),
            &test_zone_key(),
            std::slice::from_ref(&recipient),
            ProtocolVersionPolicy::require_xwing(),
            &xwing,
        )
        .expect("X-Wing issuance")
        .manifest;
        manifest.wrapped_keys.push(
            wrap_zone_key(
                &recipient.hpke_public_key,
                &manifest.zone_id,
                &recipient.node_id,
                manifest.valid_from,
                &ZoneKey::from_bytes([0xFF; ZONE_KEY_LEN]),
            )
            .expect("conflicting legacy wrap"),
        );

        let error = enforce_incoming_zone_key_policy(
            &manifest,
            &recipient.node_id,
            ProtocolVersionPolicy::require_xwing(),
        )
        .expect_err("an X-Wing selection must not hide a conflicting V3 view");
        assert!(matches!(
            error,
            ZoneKeyRotationError::InvalidManifest(
                fcp_core::ZoneKeyError::InconsistentRecipientWraps { .. }
            )
        ));
        assert!(matches!(
            build_zone_key_rotation_cutover(
                manifest,
                &test_zone_key(),
                &[recipient],
                ProtocolVersionPolicy::migration_default(),
                &xwing,
            ),
            Err(ZoneKeyRotationError::InvalidManifest(_))
        ));
    }

    #[test]
    fn zone_key_rotation_v4_receiver_rejects_duplicate_wraps_before_resolution() {
        let xwing = XWingProvider::new();
        let recipient = v3_recipient("duplicate-wrap-peer");
        let mut manifest = build_zone_key_rotation_cutover(
            test_manifest(ZoneId::work(), 1_700_000_700),
            &test_zone_key(),
            std::slice::from_ref(&recipient),
            ProtocolVersionPolicy::migration_default(),
            &xwing,
        )
        .expect("HPKE issuance")
        .manifest;
        manifest
            .wrapped_keys_v4
            .push(manifest.wrapped_keys_v4[0].clone());
        assert!(matches!(
            enforce_incoming_zone_key_policy(
                &manifest,
                &recipient.node_id,
                ProtocolVersionPolicy::migration_default(),
            ),
            Err(ZoneKeyRotationError::InvalidManifest(
                fcp_core::ZoneKeyError::DuplicateRecipientInManifest { .. }
            ))
        ));
    }
}
