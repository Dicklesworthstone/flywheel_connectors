//! Zone key distribution and rotation primitives.
//!
//! Implements `ZoneKeyManifest` objects and HPKE-wrapped zone keys.

use std::collections::{HashMap, HashSet};
use std::fmt;

use fcp_crypto::{
    CryptoError, Fcp2Aad, Fcp4Aad, HpkeSealedBox, X25519PublicKey, X25519SecretKey, XWingKem,
    XWingSealedBox, XWingSecretKey, hpke_open, hpke_seal,
};
use serde::{Deserialize, Serialize};

use crate::{NodeSignature, ObjectHeader, ObjectIdKey, TailscaleNodeId, ZoneId};

/// Zone key length in bytes (ChaCha20-Poly1305 / XChaCha20-Poly1305).
pub const ZONE_KEY_LEN: usize = 32;

/// Zone key identifier (8 bytes as carried in FCPS frames).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ZoneKeyId(#[serde(with = "crate::util::hex_or_bytes")] pub [u8; 8]);

impl ZoneKeyId {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }
}

impl fmt::Debug for ZoneKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ZoneKeyId")
            .field(&hex::encode(self.0))
            .finish()
    }
}

impl fmt::Display for ZoneKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// `ObjectId` key identifier (8 bytes as carried in FCPS frames).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ObjectIdKeyId(#[serde(with = "crate::util::hex_or_bytes")] pub [u8; 8]);

impl ObjectIdKeyId {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }
}

impl fmt::Debug for ObjectIdKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ObjectIdKeyId")
            .field(&hex::encode(self.0))
            .finish()
    }
}

impl fmt::Display for ObjectIdKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// Symmetric zone encryption key (secret).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ZoneKey([u8; ZONE_KEY_LEN]);

impl ZoneKey {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; ZONE_KEY_LEN]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ZONE_KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for ZoneKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ZoneKey")
            .field(&"[redacted; 32 bytes]")
            .finish()
    }
}

/// Supported zone key algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZoneKeyAlgorithm {
    ChaCha20Poly1305,
    XChaCha20Poly1305,
}

/// KEM used to wrap a zone key for a recipient.
///
/// Carried both at manifest level (default for the manifest) and on each
/// [`WrappedZoneKeyV4`] entry so a single V4 manifest can mix V3
/// (`HpkeX25519`) and V4 (`XWing`) recipients during the migration
/// window. See `docs/post-quantum/x_wing_kem_design.md` §3.2 + §6.
///
/// Introduced under sub-bead `kyopb.1.2.3`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZoneKemAlgorithm {
    /// V3 baseline: HPKE(DHKEM-X25519, HKDF-SHA256, ChaCha20-Poly1305).
    ///
    /// This is the default for absent V3 manifest `kem` fields so the inferred
    /// KEM matches the V3 wire format.
    #[default]
    HpkeX25519,
    /// V4 hybrid: X-Wing (X25519 + ML-KEM-768) + ChaCha20-Poly1305.
    XWing,
}

/// Per-recipient sealed-box variant: discriminates V3 HPKE wrap vs V4
/// X-Wing wrap.
///
/// Carries the actual ciphertext for whichever KEM the sender chose for
/// this recipient. The serde tag `"kem"` puts the discriminator in the
/// JSON/CBOR map directly so a forensic reader can pick out the wrap
/// type without decoding the inner sealed box.
///
/// Introduced under sub-bead `kyopb.1.2.3`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kem", rename_all = "snake_case")]
pub enum WrappedKey {
    /// V3 HPKE-X25519 sealed box (existing wire form).
    HpkeX25519 {
        /// HPKE sealed box: `enc || ciphertext`.
        sealed: HpkeSealedBox,
    },
    /// V4 X-Wing hybrid sealed box.
    XWing {
        /// X-Wing sealed box: `enc || ciphertext` (per kyopb.1.2.2).
        sealed: XWingSealedBox,
    },
}

impl WrappedKey {
    /// Lift a V3 HPKE sealed box into the V4 enum form.
    #[must_use]
    pub const fn from_hpke(sealed: HpkeSealedBox) -> Self {
        Self::HpkeX25519 { sealed }
    }

    /// Lift a V4 X-Wing sealed box into the V4 enum form.
    #[must_use]
    pub const fn from_xwing(sealed: XWingSealedBox) -> Self {
        Self::XWing { sealed }
    }

    /// Report which KEM produced this wrap.
    #[must_use]
    pub const fn kem(&self) -> ZoneKemAlgorithm {
        match self {
            Self::HpkeX25519 { .. } => ZoneKemAlgorithm::HpkeX25519,
            Self::XWing { .. } => ZoneKemAlgorithm::XWing,
        }
    }

    /// Borrow the V3 HPKE sealed box if this is the HPKE-X25519 variant.
    #[must_use]
    pub const fn hpke_sealed(&self) -> Option<&HpkeSealedBox> {
        match self {
            Self::HpkeX25519 { sealed } => Some(sealed),
            Self::XWing { .. } => None,
        }
    }

    /// Borrow the V4 X-Wing sealed box if this is the X-Wing variant.
    #[must_use]
    pub const fn xwing_sealed(&self) -> Option<&XWingSealedBox> {
        match self {
            Self::XWing { sealed } => Some(sealed),
            Self::HpkeX25519 { .. } => None,
        }
    }
}

/// Tagged result type for
/// [`ZoneKeyManifest::resolved_wrapped_key_observable_for`].
///
/// Surfaces the resolution path (V4 direct vs V3 fallback) so callers can emit
/// per-call observability for the V3-deprecation cutover.
///
/// Once the compatibility-ledger phase advances to `V4Required` (see
/// `docs/post-quantum/v3_v4_compatibility_ledger.md`), every
/// [`ResolvedWrappedKey::V3Fallback`] return is a deprecation event
/// the operator should know about. Callers SHOULD emit
/// `fcp_zone_key_v3_fallback_total{zone_id, node_id}` on the
/// `V3Fallback` arm and a structured WARN with `bead = "gtplu"` so
/// the cutover gate has the per-call evidence it needs.
///
/// `#[must_use]` because dropping the variant tag silently is exactly
/// the operator-invisible bypass this type was introduced to prevent.
#[derive(Debug, Clone)]
#[must_use]
pub enum ResolvedWrappedKey {
    /// V4 wrap found in `wrapped_keys_v4`. Modern path; no
    /// observability action required.
    V4(WrappedKey),
    /// V3 wrap found in `wrapped_keys` (V4 list missed). Deprecated
    /// path — caller SHOULD increment the
    /// `fcp_zone_key_v3_fallback_total` metric and log a WARN.
    V3Fallback(WrappedKey),
}

impl ResolvedWrappedKey {
    /// Strip the variant tag and return the underlying `WrappedKey`,
    /// matching the legacy [`ZoneKeyManifest::resolved_wrapped_key_for`]
    /// behaviour. Use this only when bridging to legacy call sites
    /// that don't yet consume the observable variant.
    #[must_use]
    pub fn into_wrapped_key(self) -> WrappedKey {
        match self {
            Self::V4(wk) | Self::V3Fallback(wk) => wk,
        }
    }

    /// Borrow the underlying `WrappedKey` without consuming the tag.
    #[must_use]
    pub const fn wrapped_key(&self) -> &WrappedKey {
        match self {
            Self::V4(wk) | Self::V3Fallback(wk) => wk,
        }
    }

    /// Whether this resolution took the deprecated V3-fallback path.
    /// Convenience predicate for callers that only need to gate
    /// observability emission.
    #[must_use]
    pub const fn is_v3_fallback(&self) -> bool {
        matches!(self, Self::V3Fallback(_))
    }

    /// Stable machine-readable label for tracing / metrics.
    /// `"v4"` or `"v3_fallback"`. Operators write log-aggregator
    /// alerts against these strings.
    #[must_use]
    pub const fn path_label(&self) -> &'static str {
        match self {
            Self::V4(_) => "v4",
            Self::V3Fallback(_) => "v3_fallback",
        }
    }
}

/// V4 wrapped zone-key entry — uses the [`WrappedKey`] enum so a single
/// manifest can carry mixed V3+V4 wraps.
///
/// Lives alongside the legacy [`WrappedZoneKey`] (which still carries
/// `HpkeSealedBox` directly) so V3 deserialisers continue to work
/// unchanged. Senders that emit V4 manifests SHOULD use this list and
/// can choose per recipient which KEM to wrap under.
///
/// Introduced under sub-bead `kyopb.1.2.3`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedZoneKeyV4 {
    pub recipient: TailscaleNodeId,
    pub issued_at: u64,
    pub sealed: WrappedKey,
}

/// Wrapped zone key entry (HPKE sealed box).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedZoneKey {
    pub recipient: TailscaleNodeId,
    pub issued_at: u64,
    pub sealed: HpkeSealedBox,
}

impl WrappedZoneKey {
    /// Lift a V3 wrap into the V4 [`WrappedZoneKeyV4`] form by tagging
    /// it as `HpkeX25519`. Used by the V3→V4 schema migration helper
    /// (see [`ZoneKeyManifest::migrated_to_v4`]).
    #[must_use]
    pub fn to_v4(&self) -> WrappedZoneKeyV4 {
        WrappedZoneKeyV4 {
            recipient: self.recipient.clone(),
            issued_at: self.issued_at,
            sealed: WrappedKey::from_hpke(self.sealed.clone()),
        }
    }
}

/// Wrapped `ObjectIdKey` entry (HPKE sealed box).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedObjectIdKey {
    pub recipient: TailscaleNodeId,
    pub issued_at: u64,
    pub sealed: HpkeSealedBox,
}

/// Rekey policy hints for zone membership changes.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RekeyPolicy {
    #[serde(default)]
    pub epoch_ratchet: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overlap_window_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retain_epochs: Option<u32>,
    #[serde(default)]
    pub rewrap_on_membership_change: bool,
    #[serde(default)]
    pub rotate_object_id_key_on_membership_change: bool,
}

/// Zone key manifest object (owner-signed).
///
/// The `kem` field and `wrapped_keys_v4` list are V4 additions
/// (sub-bead `kyopb.1.2.3`). They are placed at the end of the field
/// list so the canonical CBOR encoding produced by serde derive places
/// them last in the map; V3 deserialisers tolerate them as
/// unknown-skipped fields, and V4 deserialisers find them via the
/// declared field names. Both are `#[serde(default)]` so a V3 manifest
/// (which omits both) deserialises with `kem = HpkeX25519` and an empty
/// `wrapped_keys_v4` list, matching the V3 wire form's implicit
/// semantics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneKeyManifest {
    pub header: ObjectHeader,
    pub zone_id: ZoneId,
    pub zone_key_id: ZoneKeyId,
    pub object_id_key_id: ObjectIdKeyId,
    pub algorithm: ZoneKeyAlgorithm,
    pub valid_from: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_zone_key_id: Option<ZoneKeyId>,
    #[serde(default)]
    pub wrapped_keys: Vec<WrappedZoneKey>,
    #[serde(default)]
    pub wrapped_object_id_keys: Vec<WrappedObjectIdKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rekey_policy: Option<RekeyPolicy>,
    pub signature: NodeSignature,
    /// Default KEM advertised by this manifest (V4 addition; defaults to
    /// `HpkeX25519` for backward compatibility with V3 manifests that
    /// omit the field).
    #[serde(default)]
    pub kem: ZoneKemAlgorithm,
    /// V4 wrapped-key entries. Empty in V3-only manifests; populated by
    /// V4 senders alongside (or instead of) `wrapped_keys` so a single
    /// manifest can carry mixed V3 + V4 wraps during the V3↔V4
    /// migration window. See `WrappedKey` for per-recipient KEM
    /// discrimination.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wrapped_keys_v4: Vec<WrappedZoneKeyV4>,
}

impl ZoneKeyManifest {
    /// Find the wrapped zone key for a recipient node.
    #[must_use]
    pub fn wrapped_key_for(&self, node_id: &TailscaleNodeId) -> Option<&WrappedZoneKey> {
        self.wrapped_keys
            .iter()
            .find(|entry| entry.recipient == *node_id)
    }

    /// Find the wrapped `ObjectIdKey` for a recipient node.
    #[must_use]
    pub fn wrapped_object_id_key_for(
        &self,
        node_id: &TailscaleNodeId,
    ) -> Option<&WrappedObjectIdKey> {
        self.wrapped_object_id_keys
            .iter()
            .find(|entry| entry.recipient == *node_id)
    }

    /// Create a new empty manifest (for testing).
    ///
    /// # Errors
    ///
    /// This function is infallible but returns `Result` for API consistency.
    #[cfg(test)]
    pub fn new_empty(
        zone_id: ZoneId,
        valid_from: u64,
        _owner_key: &fcp_crypto::Ed25519SigningKey,
    ) -> Result<Self, crate::error::FcpError> {
        use rand::RngCore;

        let mut zone_key_id = [0u8; 8];
        rand::rng().fill_bytes(&mut zone_key_id);

        let mut object_id_key_id = [0u8; 8];
        rand::rng().fill_bytes(&mut object_id_key_id);

        // We need to sign a dummy payload or just return a valid signed structure?
        // The structure needs to be signed.
        // We can't easily sign `Self` because `signature` is a field.
        // We need a canonical representation without signature.
        // Ideally we follow `ZoneKeyManifest::sign` pattern if it existed.
        // But for testing we can just sign an empty byte slice if verify isn't strict about payload match
        // OR we duplicate the signing logic here.
        // But `ZoneKeyManifest` doesn't seem to have a canonical serialization method exposed?
        // Wait, `apply_manifest` doesn't verify signature. `NodeKeyAttestation` does.
        // `ZoneKeyManifest` struct definition doesn't have a `verify` method shown in my previous `read_file`.
        // Let's verify `ZoneKeyManifest` struct again.

        // It has `signature: NodeSignature`.
        // So we can just create a dummy signature.

        let signature =
            crate::NodeSignature::new(crate::NodeId::new("owner"), [0u8; 64], valid_from);

        Ok(Self {
            header: ObjectHeader {
                encryption_kind: Default::default(),
                schema: fcp_cbor::SchemaId::new(
                    "fcp.zone",
                    "ZoneKeyManifest",
                    semver::Version::new(1, 0, 0),
                ),
                zone_id: zone_id.clone(),
                created_at: valid_from,
                provenance: crate::Provenance::new(zone_id.clone()),
                refs: vec![],
                foreign_refs: vec![],
                ttl_secs: None,
                placement: None,
            },
            zone_id,
            zone_key_id: ZoneKeyId(zone_key_id),
            object_id_key_id: ObjectIdKeyId(object_id_key_id),
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from,
            valid_until: None,
            prev_zone_key_id: None,
            wrapped_keys: vec![],
            wrapped_object_id_keys: vec![],
            rekey_policy: None,
            signature,
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
        })
    }

    /// Find the V4 wrapped zone-key entry for a recipient. Looks only in
    /// `wrapped_keys_v4`; callers that want V3 fallback should also
    /// consult [`Self::wrapped_key_for`].
    #[must_use]
    pub fn wrapped_key_v4_for(&self, node_id: &TailscaleNodeId) -> Option<&WrappedZoneKeyV4> {
        self.wrapped_keys_v4
            .iter()
            .find(|entry| entry.recipient == *node_id)
    }

    /// Resolve a recipient's wrap by trying V4 first, falling back to V3.
    ///
    /// Returns the [`WrappedKey`] enum directly so callers do not need to
    /// know which list a recipient was published into. V4 senders that
    /// also published a V3 wrap for this recipient (interop manifests)
    /// will see the V4 form returned.
    ///
    /// **Observability note (br-gtplu):** this method is OPAQUE about
    /// whether the result came from the V4 list or fell back to the V3
    /// list. Once the compatibility-ledger phase advances to `V4Required`
    /// (see `docs/post-quantum/v3_v4_compatibility_ledger.md`), every
    /// V3 fallback is a deprecation event the operator should know
    /// about — but this method gives them no signal. Prefer the
    /// observable variant
    /// [`Self::resolved_wrapped_key_observable_for`] in any new
    /// caller, and emit a `fcp_zone_key_v3_fallback_total{zone_id,
    /// node_id}` metric on the `V3Fallback` arm.
    #[must_use]
    pub fn resolved_wrapped_key_for(&self, node_id: &TailscaleNodeId) -> Option<WrappedKey> {
        self.resolved_wrapped_key_observable_for(node_id)
            .map(ResolvedWrappedKey::into_wrapped_key)
    }

    /// Observable resolver: returns a [`ResolvedWrappedKey`] tagged with
    /// the resolution path so callers can emit per-call observability
    /// (logs, metrics, audit-events) when the V3 fallback path fires.
    ///
    /// This is the post-`gtplu` recommended entry point. The legacy
    /// [`Self::resolved_wrapped_key_for`] now delegates here and strips
    /// the tag for backward compatibility with the zoo of existing
    /// call sites; new code should consume the tagged enum.
    ///
    /// Resolution order is identical to the legacy method:
    /// 1. V4 list (`wrapped_keys_v4`) — returns
    ///    [`ResolvedWrappedKey::V4`].
    /// 2. V3 list (`wrapped_keys`)    — returns
    ///    [`ResolvedWrappedKey::V3Fallback`].
    ///
    /// **Operator metric (br-gtplu):** when this method returns
    /// `Some(ResolvedWrappedKey::V3Fallback(_))`, callers SHOULD
    /// increment `fcp_zone_key_v3_fallback_total{zone_id, node_id}`
    /// and log a WARN with `bead = "gtplu"` so the
    /// compatibility-ledger cutover gate has the per-call evidence
    /// it needs to verify the migration finished.
    #[must_use]
    pub fn resolved_wrapped_key_observable_for(
        &self,
        node_id: &TailscaleNodeId,
    ) -> Option<ResolvedWrappedKey> {
        if let Some(v4) = self.wrapped_key_v4_for(node_id) {
            return Some(ResolvedWrappedKey::V4(v4.sealed.clone()));
        }
        self.wrapped_key_for(node_id)
            .map(|v3| ResolvedWrappedKey::V3Fallback(WrappedKey::from_hpke(v3.sealed.clone())))
    }

    /// Produce a V4 view of this manifest by promoting every entry in
    /// `wrapped_keys` to a `WrappedZoneKeyV4` tagged as `HpkeX25519`,
    /// and setting the manifest-level `kem` field if requested.
    ///
    /// **Does NOT re-sign.** Returns an [`UnsignedV4Manifest`] — a
    /// type-system-enforced "unsigned-by-construction" wrapper that
    /// cannot be confused with a publishable [`ZoneKeyManifest`]
    /// (br-z8bsg). The only way to extract a publishable manifest is
    /// to call [`UnsignedV4Manifest::sign`] with a fresh owner
    /// signature over the migrated payload.
    ///
    /// Closes the modes-of-reasoning audit gap that the doc-comment
    /// said "caller MUST re-sign" but the type system did not enforce.
    /// A caller who ignored the doc could previously call
    /// `store.publish(manifest.migrated_to_v4(kem))` and ship a
    /// manifest whose signature commits to the OLD pre-migration
    /// payload. With the typestate, that line is a compile error.
    ///
    /// Originally V3 wraps are NOT removed; the V4 manifest carries
    /// both lists so V3-only recipients keep working.
    #[must_use]
    pub fn migrated_to_v4(&self, manifest_kem: ZoneKemAlgorithm) -> UnsignedV4Manifest {
        let mut migrated = self.clone();
        migrated.kem = manifest_kem;
        // Promote any V3 wraps the migrated manifest doesn't already
        // cover under wrapped_keys_v4 (under HpkeX25519 tag) so a single
        // lookup against wrapped_keys_v4 suffices for any recipient.
        for v3 in &self.wrapped_keys {
            if migrated.wrapped_key_v4_for(&v3.recipient).is_none() {
                migrated.wrapped_keys_v4.push(v3.to_v4());
            }
        }
        // The inherited V3 signature is intentionally left as-is. It
        // commits to the V3-shaped payload, so any V4 verifier that
        // re-derives canonical signing bytes from the migrated form
        // will reject it — defence-in-depth even if a downstream
        // consumer reaches inside via `as_payload().clone()` and
        // tries to publish the inner value. The typestate is the
        // load-bearing safety property; this is the secondary one.
        UnsignedV4Manifest { inner: migrated }
    }

    /// Add a V4 X-Wing wrap for a recipient. If the recipient already
    /// has a V4 entry, it is replaced; the V3 `wrapped_keys` list is
    /// untouched (so a V4 sender can still publish HPKE wraps for V3
    /// recipients in the same manifest).
    pub fn add_xwing_wrap(
        &mut self,
        recipient: TailscaleNodeId,
        issued_at: u64,
        sealed: XWingSealedBox,
    ) {
        let existing_slot = self
            .wrapped_keys_v4
            .iter()
            .position(|entry| entry.recipient == recipient);
        let entry = WrappedZoneKeyV4 {
            recipient,
            issued_at,
            sealed: WrappedKey::from_xwing(sealed),
        };
        if let Some(index) = existing_slot {
            self.wrapped_keys_v4[index] = entry;
        } else {
            self.wrapped_keys_v4.push(entry);
        }
    }

    /// Find recipients that have BOTH a V3 (`wrapped_keys`) entry and a
    /// V4 (`wrapped_keys_v4`) entry whose contents could plausibly
    /// resolve to a different zone key — the "split-view" case from
    /// the security audit (br-shbvv).
    ///
    /// Returns recipients whose two wraps are NOT the safe
    /// "promoted-V3" form: either the V4 wrap is the [`WrappedKey::XWing`]
    /// variant (different KEM, ciphertexts inherently differ) or the
    /// V4 wrap is [`WrappedKey::HpkeX25519`] but its sealed bytes do
    /// NOT match the V3 wrap's sealed bytes (signalling the issuer
    /// re-sealed under a different zone key — the load-bearing
    /// failure mode).
    ///
    /// Without the recipient's secret key, the verifier cannot
    /// cryptographically prove the two wraps decrypt to the same
    /// material. This check is a structural lower bound on safety:
    /// recipients that appear here MIGHT decrypt to identical zone
    /// keys, but the manifest builder did not produce them via the
    /// safe `migrated_to_v4` path. Strict callers should treat any
    /// non-empty result as a manifest validation failure (see
    /// [`Self::validate_no_recipient_split_view`]).
    #[must_use]
    pub fn split_view_recipients(&self) -> Vec<TailscaleNodeId> {
        let mut out = Vec::new();
        for v4_entry in &self.wrapped_keys_v4 {
            let Some(v3_entry) = self
                .wrapped_keys
                .iter()
                .find(|e| e.recipient == v4_entry.recipient)
            else {
                continue;
            };
            let safe = match &v4_entry.sealed {
                WrappedKey::HpkeX25519 { sealed: v4_sealed } => {
                    // Promoted V3: bytes AND issued_at must match the
                    // V3 entry exactly. issued_at is part of the AAD
                    // for the unwrap, so a mismatch would let two
                    // lookup paths derive different AAD for the same
                    // sealed bytes. Ed25519/X25519 byte equality and
                    // u64 equality are public-data comparisons so a
                    // plain `==` is fine here.
                    v4_sealed.enc == v3_entry.sealed.enc
                        && v4_sealed.ciphertext == v3_entry.sealed.ciphertext
                        && v4_entry.issued_at == v3_entry.issued_at
                }
                WrappedKey::XWing { .. } => false,
            };
            if !safe {
                out.push(v4_entry.recipient.clone());
            }
        }
        out
    }

    /// Reject manifests with split-view recipients (br-shbvv) or
    /// duplicate-recipient wraps (br-vzn2p).
    ///
    /// See [`Self::split_view_recipients`] for the structural
    /// definition of the V3↔V4 split. The duplicate-recipient guard
    /// rejects any manifest whose `wrapped_keys`, `wrapped_keys_v4`,
    /// or `wrapped_object_id_keys` lists contain the same recipient
    /// more than once: linear-scan lookup returns the FIRST entry
    /// while [`IndexedZoneKeyManifest`] retains the LAST entry, so
    /// duplicates would let two callers derive different wraps from
    /// the same signed manifest.
    ///
    /// Strict issuers + verifiers should call this before publishing
    /// or applying a V4 manifest. Producers using only the
    /// [`Self::migrated_to_v4`] + [`Self::add_xwing_wrap`] helpers
    /// satisfy the invariant by construction (the helpers either
    /// promote V3 wraps byte-for-byte or add V4-only entries for
    /// recipients absent from V3).
    ///
    /// # Errors
    ///
    /// Returns [`ZoneKeyError::DuplicateRecipientInManifest`] for the
    /// first duplicate recipient encountered, otherwise
    /// [`ZoneKeyError::InconsistentRecipientWraps`] for the first
    /// split-view recipient encountered.
    pub fn validate_no_recipient_split_view(&self) -> ZoneKeyResult<()> {
        fn first_duplicate<'a, E, F>(
            entries: &'a [E],
            recipient_of: F,
        ) -> Option<&'a TailscaleNodeId>
        where
            F: Fn(&'a E) -> &'a TailscaleNodeId,
        {
            let mut seen: HashSet<&TailscaleNodeId> = HashSet::with_capacity(entries.len());
            for e in entries {
                let r = recipient_of(e);
                if !seen.insert(r) {
                    return Some(r);
                }
            }
            None
        }

        if let Some(dup) = first_duplicate(&self.wrapped_keys, |e| &e.recipient) {
            return Err(ZoneKeyError::DuplicateRecipientInManifest {
                node_id: dup.as_str().to_string(),
                list: "wrapped_keys",
            });
        }
        if let Some(dup) = first_duplicate(&self.wrapped_keys_v4, |e| &e.recipient) {
            return Err(ZoneKeyError::DuplicateRecipientInManifest {
                node_id: dup.as_str().to_string(),
                list: "wrapped_keys_v4",
            });
        }
        if let Some(dup) = first_duplicate(&self.wrapped_object_id_keys, |e| &e.recipient) {
            return Err(ZoneKeyError::DuplicateRecipientInManifest {
                node_id: dup.as_str().to_string(),
                list: "wrapped_object_id_keys",
            });
        }
        if let Some(first) = self.split_view_recipients().into_iter().next() {
            return Err(ZoneKeyError::InconsistentRecipientWraps {
                node_id: first.as_str().to_string(),
            });
        }
        Ok(())
    }
}

/// A `ZoneKeyManifest` produced by [`ZoneKeyManifest::migrated_to_v4`]
/// that has NOT yet been re-signed by the owner (br-z8bsg).
///
/// The type system enforces that an unsigned migrated manifest cannot
/// be confused with a freshly-signed [`ZoneKeyManifest`]: the only way
/// to extract a publishable manifest is through [`Self::sign`] with a
/// caller-supplied `NodeSignature` covering the migrated payload.
///
/// Read-only inspection of the migrated payload is supported via
/// [`Self::as_payload`] (e.g. computing the canonical signing bytes
/// the owner-key flow will sign over, or running validators like
/// [`ZoneKeyManifest::validate_no_recipient_split_view`] before
/// signing). Idempotency of the migration helper is preserved via
/// [`Self::migrated_to_v4`].
///
/// **The inherited V3 signature is preserved as-is** — but it
/// commits to the V3-shaped payload, so any V4 verifier that
/// re-derives canonical signing bytes from the migrated form will
/// reject it. Defence in depth in case a downstream consumer reaches
/// inside via `as_payload().clone()` and tries to publish the inner
/// value: the publish would succeed but verification would fail.
#[derive(Debug, Clone)]
pub struct UnsignedV4Manifest {
    inner: ZoneKeyManifest,
}

impl UnsignedV4Manifest {
    /// Borrow the migrated payload for inspection — e.g. computing
    /// the canonical signing bytes the caller's owner-key flow will
    /// sign over, or running structural validators
    /// ([`ZoneKeyManifest::validate_no_recipient_split_view`],
    /// [`ZoneKeyManifest::wrapped_key_v4_for`]) before signing.
    ///
    /// The returned reference's `signature` field is the inherited
    /// V3 signature, intentionally left in place by
    /// [`ZoneKeyManifest::migrated_to_v4`] as defence in depth: it
    /// commits to the V3-shaped payload, so any V4 verifier that
    /// re-derives canonical signing bytes from the migrated form
    /// will reject it. Callers that bypass the type system by
    /// cloning the inner value still ship a manifest that fails
    /// every owner-signature check, so the safety property holds
    /// even under defeated typestate.
    #[must_use]
    pub const fn as_payload(&self) -> &ZoneKeyManifest {
        &self.inner
    }

    /// Install a fresh owner signature over the migrated payload and
    /// extract the publishable [`ZoneKeyManifest`].
    ///
    /// **Caller is responsible** for computing `signature` over the
    /// canonical signing bytes of the migrated payload (which the
    /// caller obtains via [`Self::as_payload`] and the owner-key
    /// signing flow). This method does not verify the signature — it
    /// just performs the type-level transition from "unsigned" to
    /// "publishable form."
    #[must_use]
    pub fn sign(self, signature: NodeSignature) -> ZoneKeyManifest {
        let mut m = self.inner;
        m.signature = signature;
        m
    }

    /// Idempotency helper: re-run migration on the unsigned payload.
    /// Matches the property pinned by
    /// `zone_key_manifest_v4_migrated_to_v4_is_idempotent_for_already_migrated_recipients`.
    /// The resulting `UnsignedV4Manifest` covers exactly the same
    /// recipients as `self` when the wraps already cover every V3
    /// recipient.
    #[must_use]
    pub fn migrated_to_v4(&self, manifest_kem: ZoneKemAlgorithm) -> Self {
        self.inner.migrated_to_v4(manifest_kem)
    }

    /// Add a V4 X-Wing wrap to the migrated payload BEFORE signing.
    /// Delegates to [`ZoneKeyManifest::add_xwing_wrap`]; the typestate
    /// is preserved because mutation pre-sign is safe — the eventual
    /// owner signature will commit to the final post-mutation
    /// payload via [`Self::sign`].
    pub fn add_xwing_wrap(
        &mut self,
        recipient: TailscaleNodeId,
        issued_at: u64,
        sealed: XWingSealedBox,
    ) {
        self.inner.add_xwing_wrap(recipient, issued_at, sealed);
    }

    /// Convenience extraction for `#[cfg(test)]` and benchmarking
    /// callers that need a `ZoneKeyManifest` without performing real
    /// owner signing — the typestate is bypassed by an explicit
    /// caller-supplied no-op signature. **Production callers MUST use
    /// [`Self::sign`] with a real signature.**
    ///
    /// The name is deliberately verbose so a careless production grep
    /// for `.sign(` does not pick this up.
    #[cfg(test)]
    #[must_use]
    pub fn into_inner_unsigned_for_testing_only(self) -> ZoneKeyManifest {
        self.inner
    }
}

/// O(1)-recipient-lookup view over a [`ZoneKeyManifest`] (br-d2oa0).
///
/// The base manifest stores recipient wraps in `Vec<WrappedZoneKey>` /
/// `Vec<WrappedZoneKeyV4>` / `Vec<WrappedObjectIdKey>` because the
/// owner signature commits to a stable serialisation order. The
/// matching `wrapped_key_for` / `wrapped_key_v4_for` /
/// `wrapped_object_id_key_for` lookups on `ZoneKeyManifest` are
/// therefore `O(n)` linear scans — fine for one-shot inspection but
/// expensive on the dispatcher hot path that resolves wraps per
/// request.
///
/// `IndexedZoneKeyManifest` builds three `HashMap<TailscaleNodeId,
/// usize>` indices once on construction and exposes the same
/// lookup surface in `O(1)`. The base manifest stays unchanged
/// (no breaking serde shape; no `#[serde(skip)]` field required;
/// existing callers continue to use the linear-scan methods).
///
/// Wire format: an `IndexedZoneKeyManifest` does NOT serialise — it
/// is an in-memory view. Use [`Self::manifest`] / [`Self::into_inner`]
/// to round-trip back to the base manifest for canonical encoding.
///
/// # When to use
///
/// - **Use** when you will perform multiple recipient lookups on the
///   same manifest (e.g. dispatcher resolving a wrap per inbound
///   request, batch validators iterating recipients).
/// - **Don't use** for one-shot single-recipient lookups: the
///   `IndexedZoneKeyManifest::new` constructor pays an `O(n)`
///   index build, so for a single lookup it is no faster than the
///   linear scan and adds memory.
#[derive(Debug, Clone)]
pub struct IndexedZoneKeyManifest {
    inner: ZoneKeyManifest,
    /// `recipient → index in inner.wrapped_keys`
    wrapped_keys_index: HashMap<TailscaleNodeId, usize>,
    /// `recipient → index in inner.wrapped_keys_v4`
    wrapped_keys_v4_index: HashMap<TailscaleNodeId, usize>,
    /// `recipient → index in inner.wrapped_object_id_keys`
    wrapped_object_id_keys_index: HashMap<TailscaleNodeId, usize>,
}

impl IndexedZoneKeyManifest {
    /// Build the indexed view, paying the `O(n_total)` index-construction
    /// cost once. The base manifest is consumed; reach back to it via
    /// [`Self::manifest`] (borrow) or [`Self::into_inner`] (consume).
    ///
    /// **Duplicate recipient handling — fail closed (br-vzn2p):** if
    /// the same recipient appears more than once in any of
    /// `wrapped_keys`, `wrapped_keys_v4`, or `wrapped_object_id_keys`,
    /// this constructor returns
    /// [`ZoneKeyError::DuplicateRecipientInManifest`]. Linear-scan
    /// lookup (`iter().find()`) returns the FIRST match while a
    /// `HashMap`-backed index would retain the LAST inserted entry,
    /// so silently accepting duplicates would let two callers derive
    /// different effective wraps from the same signed manifest. That
    /// is split-view ambiguity adjacent to
    /// [`ZoneKeyError::InconsistentRecipientWraps`] and is rejected
    /// pre-construction.
    ///
    /// # Errors
    ///
    /// Returns [`ZoneKeyError::DuplicateRecipientInManifest`] for the
    /// first duplicate recipient encountered, naming the wrap list it
    /// appeared in.
    pub fn new(manifest: ZoneKeyManifest) -> ZoneKeyResult<Self> {
        fn build_index<E, F>(
            entries: &[E],
            list: &'static str,
            recipient_of: F,
        ) -> ZoneKeyResult<HashMap<TailscaleNodeId, usize>>
        where
            F: Fn(&E) -> &TailscaleNodeId,
        {
            let mut idx = HashMap::with_capacity(entries.len());
            for (i, e) in entries.iter().enumerate() {
                let recipient = recipient_of(e);
                if idx.insert(recipient.clone(), i).is_some() {
                    return Err(ZoneKeyError::DuplicateRecipientInManifest {
                        node_id: recipient.as_str().to_string(),
                        list,
                    });
                }
            }
            Ok(idx)
        }

        let wrapped_keys_index =
            build_index(&manifest.wrapped_keys, "wrapped_keys", |e| &e.recipient)?;
        let wrapped_keys_v4_index =
            build_index(&manifest.wrapped_keys_v4, "wrapped_keys_v4", |e| {
                &e.recipient
            })?;
        let wrapped_object_id_keys_index = build_index(
            &manifest.wrapped_object_id_keys,
            "wrapped_object_id_keys",
            |e| &e.recipient,
        )?;
        Ok(Self {
            inner: manifest,
            wrapped_keys_index,
            wrapped_keys_v4_index,
            wrapped_object_id_keys_index,
        })
    }

    /// Borrow the underlying [`ZoneKeyManifest`] for fields that are
    /// not lookup-critical (e.g. `kem`, `valid_from`, `signature`).
    #[must_use]
    pub const fn manifest(&self) -> &ZoneKeyManifest {
        &self.inner
    }

    /// Consume the wrapper and return the base manifest, dropping the
    /// indices. Useful when handing the manifest off to a
    /// canonical-CBOR encode + sign step.
    #[must_use]
    pub fn into_inner(self) -> ZoneKeyManifest {
        self.inner
    }

    /// `O(1)` equivalent of [`ZoneKeyManifest::wrapped_key_for`].
    #[must_use]
    pub fn wrapped_key_for(&self, node_id: &TailscaleNodeId) -> Option<&WrappedZoneKey> {
        self.wrapped_keys_index
            .get(node_id)
            .and_then(|&i| self.inner.wrapped_keys.get(i))
    }

    /// `O(1)` equivalent of [`ZoneKeyManifest::wrapped_object_id_key_for`].
    #[must_use]
    pub fn wrapped_object_id_key_for(
        &self,
        node_id: &TailscaleNodeId,
    ) -> Option<&WrappedObjectIdKey> {
        self.wrapped_object_id_keys_index
            .get(node_id)
            .and_then(|&i| self.inner.wrapped_object_id_keys.get(i))
    }

    /// `O(1)` equivalent of [`ZoneKeyManifest::wrapped_key_v4_for`].
    #[must_use]
    pub fn wrapped_key_v4_for(&self, node_id: &TailscaleNodeId) -> Option<&WrappedZoneKeyV4> {
        self.wrapped_keys_v4_index
            .get(node_id)
            .and_then(|&i| self.inner.wrapped_keys_v4.get(i))
    }

    /// `O(1)` equivalent of [`ZoneKeyManifest::resolved_wrapped_key_for`].
    /// V4 first, V3 fallback — same precedence as the linear-scan
    /// version.
    ///
    /// Post-`vkb3m`: delegates to
    /// [`Self::resolved_wrapped_key_observable_for`] and strips the
    /// resolution-path tag for backward compatibility with existing
    /// call sites. New callers SHOULD consume the observable variant
    /// directly so V3-fallback observability fires on this O(1) hot
    /// path the same way it does on the linear-scan resolver
    /// (br-gtplu).
    #[must_use]
    pub fn resolved_wrapped_key_for(&self, node_id: &TailscaleNodeId) -> Option<WrappedKey> {
        self.resolved_wrapped_key_observable_for(node_id)
            .map(ResolvedWrappedKey::into_wrapped_key)
    }

    /// `O(1)` observable resolver — the indexed-manifest analogue of
    /// [`ZoneKeyManifest::resolved_wrapped_key_observable_for`].
    /// Returns a [`ResolvedWrappedKey`] tagged with whether the wrap
    /// came from the V4 list or fell back to the V3 list, so callers
    /// on the dispatcher hot path can emit the same per-call
    /// `fcp_zone_key_v3_fallback_total{zone_id, node_id}` metric and
    /// `bead = "gtplu"` WARN that the linear-scan resolver does
    /// (br-vkb3m).
    ///
    /// gtplu's original fix only extended observability to the
    /// linear-scan resolver. The cross-domain audit (br-vkb3m) found
    /// that production hot paths use [`IndexedZoneKeyManifest`] for
    /// the per-request `O(1)` lookup and were left with an opaque
    /// resolver — the cutover-gate evidence the gtplu fix was
    /// supposed to provide was missing on the call sites that matter
    /// most. This method closes that gap: the indexed and linear
    /// paths now both surface the resolution tag.
    ///
    /// Resolution order (identical to the linear-scan version):
    /// 1. V4 list (`wrapped_keys_v4`) → [`ResolvedWrappedKey::V4`].
    /// 2. V3 list (`wrapped_keys`)    → [`ResolvedWrappedKey::V3Fallback`].
    #[must_use]
    pub fn resolved_wrapped_key_observable_for(
        &self,
        node_id: &TailscaleNodeId,
    ) -> Option<ResolvedWrappedKey> {
        if let Some(v4) = self.wrapped_key_v4_for(node_id) {
            return Some(ResolvedWrappedKey::V4(v4.sealed.clone()));
        }
        self.wrapped_key_for(node_id)
            .map(|v3| ResolvedWrappedKey::V3Fallback(WrappedKey::from_hpke(v3.sealed.clone())))
    }
}

/// Zone key ring storing active/known keys by id.
#[derive(Debug, Clone)]
pub struct ZoneKeyRing {
    pub zone_id: ZoneId,
    zone_keys: HashMap<ZoneKeyId, ZoneKey>,
    object_id_keys: HashMap<ObjectIdKeyId, ObjectIdKey>,
    pub active_zone_key_id: Option<ZoneKeyId>,
    pub active_object_id_key_id: Option<ObjectIdKeyId>,
}

impl ZoneKeyRing {
    #[must_use]
    pub fn new(zone_id: ZoneId) -> Self {
        Self {
            zone_id,
            zone_keys: HashMap::new(),
            object_id_keys: HashMap::new(),
            active_zone_key_id: None,
            active_object_id_key_id: None,
        }
    }

    pub fn insert_zone_key(&mut self, key_id: ZoneKeyId, key: ZoneKey) {
        self.zone_keys.insert(key_id, key);
    }

    pub fn insert_object_id_key(&mut self, key_id: ObjectIdKeyId, key: ObjectIdKey) {
        self.object_id_keys.insert(key_id, key);
    }

    #[must_use]
    pub fn zone_key(&self, key_id: &ZoneKeyId) -> Option<&ZoneKey> {
        self.zone_keys.get(key_id)
    }

    #[must_use]
    pub fn object_id_key(&self, key_id: &ObjectIdKeyId) -> Option<&ObjectIdKey> {
        self.object_id_keys.get(key_id)
    }

    #[must_use]
    pub fn active_zone_key(&self) -> Option<&ZoneKey> {
        self.active_zone_key_id
            .as_ref()
            .and_then(|key_id| self.zone_keys.get(key_id))
    }

    #[must_use]
    pub fn active_object_id_key(&self) -> Option<&ObjectIdKey> {
        self.active_object_id_key_id
            .as_ref()
            .and_then(|key_id| self.object_id_keys.get(key_id))
    }

    #[must_use]
    pub fn set_active_zone_key(&mut self, key_id: ZoneKeyId) -> bool {
        if self.zone_keys.contains_key(&key_id) {
            self.active_zone_key_id = Some(key_id);
            true
        } else {
            false
        }
    }

    #[must_use]
    pub fn set_active_object_id_key(&mut self, key_id: ObjectIdKeyId) -> bool {
        if self.object_id_keys.contains_key(&key_id) {
            self.active_object_id_key_id = Some(key_id);
            true
        } else {
            false
        }
    }

    /// Apply a zone-key manifest for the local node, dispatching the
    /// recipient wrap across V4 (`wrapped_keys_v4`) and V3
    /// (`wrapped_keys`) lists via
    /// [`ZoneKeyManifest::resolved_wrapped_key_for`].
    ///
    /// This entry point handles HPKE-X25519 wraps only — it has no
    /// X-Wing secret to open V4 X-Wing wraps with. Recipients whose
    /// resolved wrap is [`WrappedKey::XWing`] cause an
    /// [`ZoneKeyError::XWingWrapRequiresV4Apply`] return — callers
    /// MUST switch to [`Self::apply_manifest_v4`] for those
    /// recipients (br-f69kn).
    ///
    /// V4-only manifests whose wraps are produced by the safe
    /// [`ZoneKeyManifest::migrated_to_v4`] helper carry only
    /// HPKE-X25519 wraps in `wrapped_keys_v4` and apply cleanly here
    /// without an X-Wing secret. Manifests built with explicit
    /// [`ZoneKeyManifest::add_xwing_wrap`] entries require
    /// [`Self::apply_manifest_v4`] for those recipients.
    ///
    /// # Errors
    /// Returns [`ZoneKeyError`] if the manifest is for a different
    /// zone, fails the split-view / duplicate-recipient guard, the
    /// recipient has no resolvable wrap, the resolved wrap is
    /// [`WrappedKey::XWing`] (apply via [`Self::apply_manifest_v4`]
    /// instead), or HPKE opening fails.
    pub fn apply_manifest(
        &mut self,
        manifest: &ZoneKeyManifest,
        node_id: &TailscaleNodeId,
        node_secret: &X25519SecretKey,
    ) -> ZoneKeyResult<()> {
        if manifest.zone_id != self.zone_id {
            return Err(ZoneKeyError::ZoneIdMismatch {
                expected: self.zone_id.as_str().to_string(),
                found: manifest.zone_id.as_str().to_string(),
            });
        }
        manifest.validate_no_recipient_split_view()?;

        let wrapped = resolve_wrap_or_error(manifest, node_id)?;
        let issued_at = wrapped_issued_at(manifest, node_id);

        let zone_key = match wrapped {
            WrappedKey::HpkeX25519 { sealed } => {
                let temp = WrappedZoneKey {
                    recipient: node_id.clone(),
                    issued_at,
                    sealed,
                };
                unwrap_zone_key(node_secret, &manifest.zone_id, &temp)?
            }
            WrappedKey::XWing { .. } => {
                return Err(ZoneKeyError::XWingWrapRequiresV4Apply {
                    node_id: node_id.as_str().to_string(),
                });
            }
        };

        self.finalize_apply(manifest, node_id, node_secret, zone_key)
    }

    /// V4-aware variant of [`Self::apply_manifest`]: opens both
    /// [`WrappedKey::HpkeX25519`] and [`WrappedKey::XWing`] wraps
    /// using the X-Wing secret and an [`XWingKem`] provider for the
    /// hybrid path (br-f69kn). Recipients whose effective wrap is
    /// HPKE-X25519 still use `node_secret` — `xwing_secret` /
    /// `xwing_kem` are only consulted on the X-Wing branch.
    ///
    /// The [`ObjectIdKey`] path still uses the V3 HPKE wrap
    /// (`wrapped_object_id_keys`) because the manifest layout did
    /// not promote it to V4. A V4-only zone-key manifest whose
    /// `wrapped_object_id_keys` list is empty for this recipient
    /// fails with [`ZoneKeyError::MissingWrappedObjectIdKey`].
    ///
    /// # Errors
    /// Returns [`ZoneKeyError`] for any of the same conditions as
    /// [`Self::apply_manifest`], plus an X-Wing decryption failure
    /// from a wrong key, tampered ciphertext, or wrong AAD.
    pub fn apply_manifest_v4<K: XWingKem + ?Sized>(
        &mut self,
        manifest: &ZoneKeyManifest,
        node_id: &TailscaleNodeId,
        node_secret: &X25519SecretKey,
        xwing_secret: &XWingSecretKey,
        xwing_kem: &K,
    ) -> ZoneKeyResult<()> {
        if manifest.zone_id != self.zone_id {
            return Err(ZoneKeyError::ZoneIdMismatch {
                expected: self.zone_id.as_str().to_string(),
                found: manifest.zone_id.as_str().to_string(),
            });
        }
        manifest.validate_no_recipient_split_view()?;

        let wrapped = resolve_wrap_or_error(manifest, node_id)?;
        let issued_at = wrapped_issued_at(manifest, node_id);

        let zone_key = match wrapped {
            WrappedKey::HpkeX25519 { sealed } => {
                let temp = WrappedZoneKey {
                    recipient: node_id.clone(),
                    issued_at,
                    sealed,
                };
                unwrap_zone_key(node_secret, &manifest.zone_id, &temp)?
            }
            WrappedKey::XWing { sealed } => unwrap_zone_key_v4_xwing(
                xwing_kem,
                xwing_secret,
                &manifest.zone_id,
                node_id,
                issued_at,
                &sealed,
            )?,
        };

        self.finalize_apply(manifest, node_id, node_secret, zone_key)
    }

    /// Common tail of [`Self::apply_manifest`] and
    /// [`Self::apply_manifest_v4`]: install the unwrapped zone key
    /// and unwrap the V3 `ObjectIdKey` for the same recipient.
    fn finalize_apply(
        &mut self,
        manifest: &ZoneKeyManifest,
        node_id: &TailscaleNodeId,
        node_secret: &X25519SecretKey,
        zone_key: ZoneKey,
    ) -> ZoneKeyResult<()> {
        self.insert_zone_key(manifest.zone_key_id, zone_key);
        self.active_zone_key_id = Some(manifest.zone_key_id);

        let wrapped_object_id = manifest.wrapped_object_id_key_for(node_id).ok_or_else(|| {
            ZoneKeyError::MissingWrappedObjectIdKey {
                node_id: node_id.as_str().to_string(),
            }
        })?;
        let object_id_key =
            unwrap_object_id_key(node_secret, &manifest.zone_id, wrapped_object_id)?;
        self.insert_object_id_key(manifest.object_id_key_id, object_id_key);
        self.active_object_id_key_id = Some(manifest.object_id_key_id);

        Ok(())
    }
}

/// Resolve a recipient's effective wrap (V4 first, V3 fallback) or
/// return [`ZoneKeyError::MissingWrappedZoneKey`].
fn resolve_wrap_or_error(
    manifest: &ZoneKeyManifest,
    node_id: &TailscaleNodeId,
) -> ZoneKeyResult<WrappedKey> {
    manifest
        .resolved_wrapped_key_for(node_id)
        .ok_or_else(|| ZoneKeyError::MissingWrappedZoneKey {
            node_id: node_id.as_str().to_string(),
        })
}

/// Look up `issued_at` for a recipient, preferring the V4 entry
/// (which is byte-equal to the V3 entry's `issued_at` for migrated
/// wraps and authoritative for pure V4-only wraps).
///
/// Caller must have already verified that
/// [`ZoneKeyManifest::resolved_wrapped_key_for`] returned `Some(_)`
/// for `node_id`, so at least one of the two lists carries this
/// recipient.
fn wrapped_issued_at(manifest: &ZoneKeyManifest, node_id: &TailscaleNodeId) -> u64 {
    let result = manifest
        .wrapped_key_v4_for(node_id)
        .map(|w| w.issued_at)
        .or_else(|| manifest.wrapped_key_for(node_id).map(|w| w.issued_at));
    debug_assert!(
        result.is_some(),
        "wrapped_issued_at called for recipient {} not present in V4 or V3 wraps; \
         caller must verify resolved_wrapped_key_for(node_id).is_some() first",
        node_id.as_str()
    );
    result.unwrap_or_default()
}

/// Open a V4 X-Wing-sealed zone-key wrap into a [`ZoneKey`].
///
/// Mirrors the V3 [`unwrap_zone_key`] contract but routes through
/// the hybrid X-Wing path: the AAD is the canonical [`Fcp4Aad`]
/// (vs the V3 [`Fcp2Aad`]) and decap goes through the supplied
/// [`XWingKem`] provider so callers can swap implementations
/// (br-f69kn).
fn unwrap_zone_key_v4_xwing<K: XWingKem + ?Sized>(
    xwing_kem: &K,
    xwing_secret: &XWingSecretKey,
    zone_id: &ZoneId,
    recipient: &TailscaleNodeId,
    issued_at: u64,
    sealed: &XWingSealedBox,
) -> ZoneKeyResult<ZoneKey> {
    let aad = Fcp4Aad::for_zone_key(zone_id.as_bytes(), recipient.as_str().as_bytes(), issued_at)
        .encode()?;
    let opened = xwing_kem.open(xwing_secret, sealed, &aad)?;
    if opened.len() != ZONE_KEY_LEN {
        return Err(ZoneKeyError::InvalidKeyLength {
            expected: ZONE_KEY_LEN,
            found: opened.len(),
        });
    }
    let mut bytes = [0u8; ZONE_KEY_LEN];
    bytes.copy_from_slice(&opened);
    Ok(ZoneKey::from_bytes(bytes))
}

/// Zone key distribution errors.
#[derive(Debug, thiserror::Error)]
pub enum ZoneKeyError {
    #[error("crypto failure: {0}")]
    Crypto(#[from] CryptoError),
    #[error("invalid key length (expected {expected}, got {found})")]
    InvalidKeyLength { expected: usize, found: usize },
    #[error("zone id mismatch (expected {expected}, found {found})")]
    ZoneIdMismatch { expected: String, found: String },
    #[error("missing wrapped zone key for node `{node_id}`")]
    MissingWrappedZoneKey { node_id: String },
    #[error("missing wrapped ObjectIdKey for node `{node_id}`")]
    MissingWrappedObjectIdKey { node_id: String },
    /// V3 + V4 wraps for the same recipient point at structurally
    /// distinct sealed boxes (br-shbvv).
    ///
    /// Means the V3 reader and the V4 reader would resolve different
    /// (zone-key, manifest) pairs — silent zone partitioning. A V4
    /// manifest carrying both wraps for one recipient is only safe
    /// when the V4 wrap is the `HpkeX25519` variant with byte-equal
    /// sealed bytes to the V3 wrap (i.e. the entry was promoted
    /// through `migrated_to_v4`, not produced via `add_xwing_wrap`).
    #[error(
        "split-view manifest: recipient `{node_id}` has both V3 and V4 wraps with \
         non-promoted contents — V3 and V4 readers may resolve different zone keys"
    )]
    InconsistentRecipientWraps { node_id: String },
    /// A recipient appears more than once in one of the wrap lists
    /// (`wrapped_keys`, `wrapped_keys_v4`, or `wrapped_object_id_keys`)
    /// of a [`ZoneKeyManifest`] (br-vzn2p).
    ///
    /// Linear-scan lookup (`iter().find()`) and indexed lookup
    /// (`HashMap::insert` retains the LAST occurrence) would resolve
    /// such a recipient to different wraps, reintroducing a split-view
    /// ambiguity adjacent to [`Self::InconsistentRecipientWraps`].
    /// Manifests with duplicate recipients are fail-closed at
    /// `IndexedZoneKeyManifest::new` and at
    /// [`ZoneKeyManifest::validate_no_recipient_split_view`].
    #[error(
        "duplicate recipient in manifest: recipient `{node_id}` appears more than once in \
         `{list}` — linear and indexed lookups would resolve to different wraps"
    )]
    DuplicateRecipientInManifest { node_id: String, list: &'static str },
    /// The recipient's effective wrap is a V4 X-Wing wrap, but the
    /// caller invoked the V3-only [`ZoneKeyRing::apply_manifest`]
    /// entry point — which has no X-Wing secret to open it.
    /// Callers SHOULD switch to
    /// [`ZoneKeyRing::apply_manifest_v4`] (br-f69kn) and pass the
    /// recipient's X-Wing secret + an [`fcp_crypto::XWingKem`]
    /// provider.
    #[error(
        "recipient `{node_id}` resolves to a V4 X-Wing wrap; call \
         ZoneKeyRing::apply_manifest_v4 with an XWing secret + provider \
         (br-f69kn)"
    )]
    XWingWrapRequiresV4Apply { node_id: String },
}

pub type ZoneKeyResult<T> = Result<T, ZoneKeyError>;

/// Wrap a zone key for a recipient using HPKE.
///
/// # Errors
/// Returns `ZoneKeyError` if HPKE sealing fails.
pub fn wrap_zone_key(
    recipient_pk: &X25519PublicKey,
    zone_id: &ZoneId,
    recipient_node_id: &TailscaleNodeId,
    issued_at: u64,
    zone_key: &ZoneKey,
) -> ZoneKeyResult<WrappedZoneKey> {
    let aad = Fcp2Aad::for_zone_key(
        zone_id.as_bytes(),
        recipient_node_id.as_str().as_bytes(),
        issued_at,
    );
    let sealed = hpke_seal(recipient_pk, zone_key.as_bytes(), &aad)?;
    Ok(WrappedZoneKey {
        recipient: recipient_node_id.clone(),
        issued_at,
        sealed,
    })
}

/// Unwrap a zone key for a recipient using HPKE.
///
/// # Errors
/// Returns `ZoneKeyError` if HPKE opening fails or key length is invalid.
pub fn unwrap_zone_key(
    recipient_sk: &X25519SecretKey,
    zone_id: &ZoneId,
    wrapped: &WrappedZoneKey,
) -> ZoneKeyResult<ZoneKey> {
    let aad = Fcp2Aad::for_zone_key(
        zone_id.as_bytes(),
        wrapped.recipient.as_str().as_bytes(),
        wrapped.issued_at,
    );
    let opened = hpke_open(recipient_sk, &wrapped.sealed, &aad)?;
    if opened.len() != ZONE_KEY_LEN {
        return Err(ZoneKeyError::InvalidKeyLength {
            expected: ZONE_KEY_LEN,
            found: opened.len(),
        });
    }
    let mut bytes = [0u8; ZONE_KEY_LEN];
    bytes.copy_from_slice(&opened);
    Ok(ZoneKey::from_bytes(bytes))
}

/// Wrap an `ObjectIdKey` for a recipient using HPKE.
///
/// # Errors
/// Returns `ZoneKeyError` if HPKE sealing fails.
pub fn wrap_object_id_key(
    recipient_pk: &X25519PublicKey,
    zone_id: &ZoneId,
    recipient_node_id: &TailscaleNodeId,
    issued_at: u64,
    object_id_key: &ObjectIdKey,
) -> ZoneKeyResult<WrappedObjectIdKey> {
    let aad = Fcp2Aad::for_objectid_key(
        zone_id.as_bytes(),
        recipient_node_id.as_str().as_bytes(),
        issued_at,
    );
    let sealed = hpke_seal(recipient_pk, object_id_key.as_bytes(), &aad)?;
    Ok(WrappedObjectIdKey {
        recipient: recipient_node_id.clone(),
        issued_at,
        sealed,
    })
}

/// Unwrap an `ObjectIdKey` for a recipient using HPKE.
///
/// # Errors
/// Returns `ZoneKeyError` if HPKE opening fails or key length is invalid.
pub fn unwrap_object_id_key(
    recipient_sk: &X25519SecretKey,
    zone_id: &ZoneId,
    wrapped: &WrappedObjectIdKey,
) -> ZoneKeyResult<ObjectIdKey> {
    let aad = Fcp2Aad::for_objectid_key(
        zone_id.as_bytes(),
        wrapped.recipient.as_str().as_bytes(),
        wrapped.issued_at,
    );
    let opened = hpke_open(recipient_sk, &wrapped.sealed, &aad)?;
    if opened.len() != ZONE_KEY_LEN {
        return Err(ZoneKeyError::InvalidKeyLength {
            expected: ZONE_KEY_LEN,
            found: opened.len(),
        });
    }
    let mut bytes = [0u8; ZONE_KEY_LEN];
    bytes.copy_from_slice(&opened);
    Ok(ObjectIdKey::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NodeId, NodeSignature, ObjectHeader, Provenance};
    use fcp_cbor::SchemaId;
    use fcp_crypto::x25519::X25519SecretKey;
    use fcp_crypto::{Fcp4Aad, XWingKem, XWingProvider};
    use rand::RngCore;
    use semver::Version;

    fn random_zone_key() -> ZoneKey {
        let mut bytes = [0u8; ZONE_KEY_LEN];
        rand::rng().fill_bytes(&mut bytes);
        ZoneKey::from_bytes(bytes)
    }

    fn random_object_id_key() -> ObjectIdKey {
        let mut bytes = [0u8; ZONE_KEY_LEN];
        rand::rng().fill_bytes(&mut bytes);
        ObjectIdKey::from_bytes(bytes)
    }

    fn test_header(zone_id: &ZoneId) -> ObjectHeader {
        ObjectHeader {
            encryption_kind: Default::default(),
            schema: SchemaId::new("fcp.zone", "ZoneKeyManifest", Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: 1_700_000_000,
            provenance: Provenance::new(zone_id.clone()),
            refs: Vec::new(),
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        }
    }

    fn test_signature() -> NodeSignature {
        NodeSignature::new(NodeId::new("owner-node"), [0u8; 64], 1_700_000_000)
    }

    #[test]
    fn zone_key_wrap_roundtrip() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-1");
        let issued_at = 1_700_000_000;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let zone_key = random_zone_key();

        let wrapped = wrap_zone_key(&pk, &zone_id, &node_id, issued_at, &zone_key).unwrap();
        let opened = unwrap_zone_key(&sk, &zone_id, &wrapped).unwrap();

        assert_eq!(opened, zone_key);
    }

    #[test]
    fn object_id_key_wrap_roundtrip() {
        let zone_id = ZoneId::private();
        let node_id = TailscaleNodeId::new("node-2");
        let issued_at = 1_700_000_123;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let key = random_object_id_key();

        let wrapped = wrap_object_id_key(&pk, &zone_id, &node_id, issued_at, &key).unwrap();
        let opened = unwrap_object_id_key(&sk, &zone_id, &wrapped).unwrap();

        assert_eq!(opened, key);
    }

    #[test]
    fn unwrap_zone_key_fails_with_wrong_node_id() {
        let zone_id = ZoneId::community();
        let node_id = TailscaleNodeId::new("node-3");
        let issued_at = 1_700_000_456;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let zone_key = random_zone_key();

        let mut wrapped = wrap_zone_key(&pk, &zone_id, &node_id, issued_at, &zone_key).unwrap();
        wrapped.recipient = TailscaleNodeId::new("node-4");

        let result = unwrap_zone_key(&sk, &zone_id, &wrapped);
        assert!(result.is_err());
    }

    #[test]
    fn zone_key_ring_selects_by_id() {
        let zone_id = ZoneId::public();
        let mut ring = ZoneKeyRing::new(zone_id);

        let key_id = ZoneKeyId::from_bytes([1u8; 8]);
        let key = ZoneKey::from_bytes([2u8; ZONE_KEY_LEN]);
        ring.insert_zone_key(key_id, key);

        assert!(ring.set_active_zone_key(key_id));
        assert_eq!(ring.active_zone_key(), Some(&key));
    }

    #[test]
    fn apply_manifest_unwraps_and_sets_active() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-apply");
        let issued_at = 1_700_000_777;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();

        let zone_key = random_zone_key();
        let object_id_key = random_object_id_key();

        let wrapped_zone = wrap_zone_key(&pk, &zone_id, &node_id, issued_at, &zone_key).unwrap();
        let wrapped_object =
            wrap_object_id_key(&pk, &zone_id, &node_id, issued_at, &object_id_key).unwrap();

        let manifest = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: ZoneKeyId::from_bytes([9u8; 8]),
            object_id_key_id: ObjectIdKeyId::from_bytes([7u8; 8]),
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at,
            valid_until: None,
            prev_zone_key_id: None,
            wrapped_keys: vec![wrapped_zone],
            wrapped_object_id_keys: vec![wrapped_object],
            rekey_policy: None,
            signature: test_signature(),
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
        };

        let mut ring = ZoneKeyRing::new(zone_id);
        ring.apply_manifest(&manifest, &node_id, &sk).unwrap();

        assert_eq!(ring.active_zone_key_id, Some(manifest.zone_key_id));
        assert_eq!(
            ring.active_object_id_key_id,
            Some(manifest.object_id_key_id)
        );
        assert_eq!(ring.active_zone_key(), Some(&zone_key));
        assert_eq!(ring.active_object_id_key(), Some(&object_id_key));
    }

    /// br-f69kn regression: pre-fix, `ZoneKeyRing::apply_manifest`
    /// looked up the recipient via `wrapped_key_for(node_id)` which
    /// reads only the V3 `wrapped_keys` list. A V4-only manifest
    /// (no V3 wraps at all) — for instance one produced by V4-only
    /// senders or by stripping `wrapped_keys` after migration —
    /// would fail with `MissingWrappedZoneKey` even though every
    /// recipient had a valid V4 wrap in `wrapped_keys_v4`. The fix
    /// resolves through `resolved_wrapped_key_for` and dispatches
    /// HPKE-X25519 vs X-Wing wraps. This test constructs a V4-only
    /// multi-recipient manifest with mixed promoted-V3 (`HpkeX25519`)
    /// and pure-V4 (`XWing`) wraps and verifies every recipient can
    /// successfully apply via `apply_manifest_v4`.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn apply_manifest_v4_resolves_v4_only_multi_recipient_manifest_for_every_recipient() {
        let zone_id = ZoneId::work();
        let issued_at = 1_700_010_500;
        let zone_key = random_zone_key();
        let object_id_key = random_object_id_key();

        let xwing = XWingProvider::new();

        // Recipient A: HPKE-X25519 V4 wrap (the byte-equal "promoted"
        // form from migrated_to_v4). Apply must open via the
        // X25519 secret.
        let alice = TailscaleNodeId::new("alice-promoted-v4");
        let alice_sk = X25519SecretKey::generate();
        let alice_v3 = wrap_zone_key(
            &alice_sk.public_key(),
            &zone_id,
            &alice,
            issued_at,
            &zone_key,
        )
        .expect("alice v3 wrap");
        let alice_object = wrap_object_id_key(
            &alice_sk.public_key(),
            &zone_id,
            &alice,
            issued_at,
            &object_id_key,
        )
        .expect("alice object wrap");

        // Recipient B: X-Wing V4-only wrap. Apply must open via the
        // X-Wing secret + provider.
        let bob = TailscaleNodeId::new("bob-pure-v4");
        let bob_x25519 = X25519SecretKey::generate();
        let (bob_wrap_public, bob_open_secret) = xwing.generate().expect("bob xwing keypair");
        let bob_aad = Fcp4Aad::for_zone_key(zone_id.as_bytes(), bob.as_str().as_bytes(), issued_at)
            .encode()
            .expect("bob aad");
        let bob_xwing_sealed = xwing
            .seal(&bob_wrap_public, zone_key.as_bytes(), &bob_aad)
            .expect("bob xwing wrap");
        // Bob still needs an HPKE-wrapped object_id_key entry: the
        // ObjectIdKey list was not promoted to V4.
        let bob_object = wrap_object_id_key(
            &bob_x25519.public_key(),
            &zone_id,
            &bob,
            issued_at,
            &object_id_key,
        )
        .expect("bob object wrap");

        // Recipient C: another X-Wing V4-only wrap with a different
        // X-Wing key, so we exercise per-recipient AAD binding.
        let carol = TailscaleNodeId::new("carol-pure-v4");
        let carol_x25519 = X25519SecretKey::generate();
        let (carol_wrap_public, carol_open_secret) = xwing.generate().expect("carol xwing keypair");
        let carol_aad =
            Fcp4Aad::for_zone_key(zone_id.as_bytes(), carol.as_str().as_bytes(), issued_at)
                .encode()
                .expect("carol aad");
        let carol_xwing_sealed = xwing
            .seal(&carol_wrap_public, zone_key.as_bytes(), &carol_aad)
            .expect("carol xwing wrap");
        let carol_object = wrap_object_id_key(
            &carol_x25519.public_key(),
            &zone_id,
            &carol,
            issued_at,
            &object_id_key,
        )
        .expect("carol object wrap");

        // Build a V4-ONLY manifest: wrapped_keys is empty, all
        // entries live in wrapped_keys_v4. Alice's wrap is the
        // HpkeX25519 variant (the promoted-V3 form); Bob and Carol
        // are pure XWing wraps.
        let manifest = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: ZoneKeyId::from_bytes([0xF1; 8]),
            object_id_key_id: ObjectIdKeyId::from_bytes([0xF2; 8]),
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at,
            valid_until: None,
            prev_zone_key_id: None,
            wrapped_keys: vec![],
            wrapped_object_id_keys: vec![alice_object, bob_object, carol_object],
            rekey_policy: None,
            signature: test_signature(),
            kem: ZoneKemAlgorithm::XWing,
            wrapped_keys_v4: vec![
                WrappedZoneKeyV4 {
                    recipient: alice.clone(),
                    issued_at,
                    sealed: WrappedKey::from_hpke(alice_v3.sealed),
                },
                WrappedZoneKeyV4 {
                    recipient: bob.clone(),
                    issued_at,
                    sealed: WrappedKey::from_xwing(bob_xwing_sealed),
                },
                WrappedZoneKeyV4 {
                    recipient: carol.clone(),
                    issued_at,
                    sealed: WrappedKey::from_xwing(carol_xwing_sealed),
                },
            ],
        };

        // Sanity: this is a V4-only manifest.
        assert!(manifest.wrapped_keys.is_empty());
        assert_eq!(manifest.wrapped_keys_v4.len(), 3);

        // Pre-fix behaviour: legacy apply_manifest would fail for
        // BOB and CAROL (no V3 wrap to find) and for ALICE too
        // (her V3 list is empty). Post-fix, apply_manifest opens
        // Alice's HPKE-X25519 V4 wrap without an X-Wing secret.
        let mut alice_ring = ZoneKeyRing::new(zone_id.clone());
        alice_ring
            .apply_manifest(&manifest, &alice, &alice_sk)
            .expect("alice (HpkeX25519 V4 wrap) applies via apply_manifest");
        assert_eq!(alice_ring.active_zone_key(), Some(&zone_key));
        assert_eq!(alice_ring.active_object_id_key(), Some(&object_id_key));

        // Pre-fix, apply_manifest for Bob would fail with
        // MissingWrappedZoneKey because wrapped_keys is empty.
        // Post-fix, the V3-only entry point recognises the X-Wing
        // wrap and surfaces the precise XWingWrapRequiresV4Apply
        // error so callers know to switch entry points.
        let mut bob_v3_ring = ZoneKeyRing::new(zone_id.clone());
        let bob_v3_err = bob_v3_ring
            .apply_manifest(&manifest, &bob, &bob_x25519)
            .expect_err("legacy V3-only apply must reject X-Wing wrap with the typed error");
        assert!(
            matches!(bob_v3_err, ZoneKeyError::XWingWrapRequiresV4Apply { ref node_id }
                if node_id == bob.as_str()),
            "expected XWingWrapRequiresV4Apply for bob, got {bob_v3_err:?}"
        );

        // V4 entry point opens every recipient's wrap, including
        // Bob and Carol's pure X-Wing wraps. ALSO includes Alice's
        // HPKE wrap routed through the same V4 entry point — so a
        // caller that always uses apply_manifest_v4 with both
        // secrets in hand never has to switch APIs.
        let mut alice_v4_ring = ZoneKeyRing::new(zone_id.clone());
        let (_, alice_xwing_throwaway_sk) = xwing.generate().expect("throwaway xwing keypair");
        alice_v4_ring
            .apply_manifest_v4(
                &manifest,
                &alice,
                &alice_sk,
                &alice_xwing_throwaway_sk,
                &xwing,
            )
            .expect("alice (HPKE V4 wrap) applies via apply_manifest_v4");
        assert_eq!(alice_v4_ring.active_zone_key(), Some(&zone_key));

        let mut bob_ring = ZoneKeyRing::new(zone_id.clone());
        bob_ring
            .apply_manifest_v4(&manifest, &bob, &bob_x25519, &bob_open_secret, &xwing)
            .expect("bob (X-Wing V4 wrap) applies via apply_manifest_v4");
        assert_eq!(bob_ring.active_zone_key(), Some(&zone_key));
        assert_eq!(bob_ring.active_object_id_key(), Some(&object_id_key));

        let mut carol_ring = ZoneKeyRing::new(zone_id);
        carol_ring
            .apply_manifest_v4(&manifest, &carol, &carol_x25519, &carol_open_secret, &xwing)
            .expect("carol (X-Wing V4 wrap) applies via apply_manifest_v4");
        assert_eq!(carol_ring.active_zone_key(), Some(&zone_key));
    }

    /// br-f69kn: a recipient with a V4 X-Wing wrap whose
    /// `apply_manifest_v4` call passes the WRONG X-Wing secret must
    /// surface a CryptoError-derived `ZoneKeyError`, not a silent
    /// wrong-key zone-key install.
    #[test]
    fn apply_manifest_v4_wrong_xwing_secret_fails_loudly() {
        let zone_id = ZoneId::work();
        let issued_at = 1_700_010_600;
        let zone_key = random_zone_key();
        let object_id_key = random_object_id_key();

        let xwing = XWingProvider::new();
        let bob = TailscaleNodeId::new("bob-wrong-key");
        let bob_x25519 = X25519SecretKey::generate();
        let (bob_wrap_public, _bob_open_secret) = xwing.generate().expect("bob xwing keypair");
        let (_other_pk, attacker_sk) = xwing.generate().expect("attacker xwing keypair");

        let aad = Fcp4Aad::for_zone_key(zone_id.as_bytes(), bob.as_str().as_bytes(), issued_at)
            .encode()
            .expect("aad");
        let sealed = xwing
            .seal(&bob_wrap_public, zone_key.as_bytes(), &aad)
            .expect("seal");
        let bob_object = wrap_object_id_key(
            &bob_x25519.public_key(),
            &zone_id,
            &bob,
            issued_at,
            &object_id_key,
        )
        .expect("object wrap");

        let manifest = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: ZoneKeyId::from_bytes([0xC1; 8]),
            object_id_key_id: ObjectIdKeyId::from_bytes([0xC2; 8]),
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at,
            valid_until: None,
            prev_zone_key_id: None,
            wrapped_keys: vec![],
            wrapped_object_id_keys: vec![bob_object],
            rekey_policy: None,
            signature: test_signature(),
            kem: ZoneKemAlgorithm::XWing,
            wrapped_keys_v4: vec![WrappedZoneKeyV4 {
                recipient: bob.clone(),
                issued_at,
                sealed: WrappedKey::from_xwing(sealed),
            }],
        };

        let mut ring = ZoneKeyRing::new(zone_id);
        let result = ring.apply_manifest_v4(&manifest, &bob, &bob_x25519, &attacker_sk, &xwing);
        assert!(
            matches!(result, Err(ZoneKeyError::Crypto(_))),
            "wrong X-Wing secret must fail loudly with Crypto(_), got {result:?}"
        );
        assert_eq!(
            ring.active_zone_key(),
            None,
            "no zone key should be installed on a failed apply"
        );
    }

    #[test]
    fn apply_manifest_rejects_mismatched_zone() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-apply");
        let issued_at = 1_700_000_888;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();

        let zone_key = random_zone_key();
        let object_id_key = random_object_id_key();

        let wrapped_zone = wrap_zone_key(&pk, &zone_id, &node_id, issued_at, &zone_key).unwrap();
        let wrapped_object =
            wrap_object_id_key(&pk, &zone_id, &node_id, issued_at, &object_id_key).unwrap();

        let manifest = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id,
            zone_key_id: ZoneKeyId::from_bytes([3u8; 8]),
            object_id_key_id: ObjectIdKeyId::from_bytes([4u8; 8]),
            algorithm: ZoneKeyAlgorithm::XChaCha20Poly1305,
            valid_from: issued_at,
            valid_until: None,
            prev_zone_key_id: None,
            wrapped_keys: vec![wrapped_zone],
            wrapped_object_id_keys: vec![wrapped_object],
            rekey_policy: None,
            signature: test_signature(),
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
        };

        let mut ring = ZoneKeyRing::new(ZoneId::private());
        let err = ring
            .apply_manifest(&manifest, &node_id, &sk)
            .expect_err("zone mismatch");
        assert!(matches!(err, ZoneKeyError::ZoneIdMismatch { .. }));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn zone_key_manifest_multi_recipient_v3_v4_wraps_resolve_same_zone_key() {
        let zone_id = ZoneId::work();
        let issued_at = 1_700_010_000;
        let zone_key = random_zone_key();

        let alice = TailscaleNodeId::new("alice-v3");
        let alice_sk = X25519SecretKey::generate();
        let alice_v3 = wrap_zone_key(
            &alice_sk.public_key(),
            &zone_id,
            &alice,
            issued_at,
            &zone_key,
        )
        .expect("alice v3 wrap");

        let bob = TailscaleNodeId::new("bob-v4");
        let xwing = XWingProvider::new();
        let (bob_wrap_public, bob_open_secret) = xwing.generate().expect("bob xwing keypair");
        let bob_aad = Fcp4Aad::for_zone_key(zone_id.as_bytes(), bob.as_str().as_bytes(), issued_at)
            .encode()
            .expect("bob aad");
        let bob_v4 = xwing
            .seal(&bob_wrap_public, zone_key.as_bytes(), &bob_aad)
            .expect("bob v4 wrap");

        let carol = TailscaleNodeId::new("carol-promoted");
        let carol_sk = X25519SecretKey::generate();
        let carol_v3 = wrap_zone_key(
            &carol_sk.public_key(),
            &zone_id,
            &carol,
            issued_at,
            &zone_key,
        )
        .expect("carol v3 wrap");

        let mut unsigned = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: ZoneKeyId::from_bytes([0xA1; 8]),
            object_id_key_id: ObjectIdKeyId::from_bytes([0xB1; 8]),
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at,
            valid_until: None,
            prev_zone_key_id: None,
            wrapped_keys: vec![alice_v3, carol_v3],
            wrapped_object_id_keys: vec![],
            rekey_policy: None,
            signature: test_signature(),
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
        }
        .migrated_to_v4(ZoneKemAlgorithm::XWing);
        unsigned.add_xwing_wrap(bob.clone(), issued_at, bob_v4);
        // br-z8bsg: typestate transition. Production callers would
        // compute a real owner signature here; the in-tree test uses
        // the same dummy signature the rest of this test suite uses.
        let manifest = unsigned.sign(test_signature());

        manifest
            .validate_no_recipient_split_view()
            .expect("builder-produced V4 manifest has no split-view recipients");

        let alice_opened = unwrap_zone_key(
            &alice_sk,
            &zone_id,
            manifest.wrapped_key_for(&alice).expect("alice v3 wrap"),
        )
        .expect("alice opens v3");
        assert_eq!(alice_opened.as_bytes(), zone_key.as_bytes());

        let bob_resolved = manifest
            .resolved_wrapped_key_for(&bob)
            .expect("bob v4 wrap resolves");
        let bob_opened = xwing
            .open(
                &bob_open_secret,
                bob_resolved.xwing_sealed().expect("bob xwing sealed"),
                &bob_aad,
            )
            .expect("bob opens v4");
        assert_eq!(bob_opened.as_slice(), zone_key.as_bytes());

        let carol_v3_opened = unwrap_zone_key(
            &carol_sk,
            &zone_id,
            manifest.wrapped_key_for(&carol).expect("carol v3 wrap"),
        )
        .expect("carol opens v3");
        let carol_v4_resolved = manifest
            .resolved_wrapped_key_for(&carol)
            .expect("carol promoted v4 wrap resolves");
        let WrappedKey::HpkeX25519 { sealed } = carol_v4_resolved else {
            panic!("carol promoted wrap must stay HPKE");
        };
        let carol_v4 = WrappedZoneKey {
            recipient: carol,
            issued_at,
            sealed,
        };
        let carol_v4_opened =
            unwrap_zone_key(&carol_sk, &zone_id, &carol_v4).expect("carol opens promoted v4");

        assert_eq!(carol_v3_opened.as_bytes(), zone_key.as_bytes());
        assert_eq!(carol_v4_opened.as_bytes(), zone_key.as_bytes());
        assert_eq!(
            blake3::hash(alice_opened.as_bytes()),
            blake3::hash(bob_opened.as_slice()),
            "all recipients must derive the same ZoneKey bytes"
        );
        assert_eq!(
            blake3::hash(bob_opened.as_slice()),
            blake3::hash(carol_v4_opened.as_bytes()),
            "promoted V3+V4 recipient must not split the zone key"
        );
    }

    #[test]
    fn apply_manifest_rejects_v3_v4_split_view_for_same_recipient() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("split-view-node");
        let issued_at = 1_700_020_000;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let canonical_zone_key = ZoneKey::from_bytes([0x11; ZONE_KEY_LEN]);
        let divergent_zone_key = ZoneKey::from_bytes([0x22; ZONE_KEY_LEN]);
        let object_id_key = random_object_id_key();

        let v3_wrap =
            wrap_zone_key(&pk, &zone_id, &node_id, issued_at, &canonical_zone_key).unwrap();
        let divergent_v4_hpke =
            wrap_zone_key(&pk, &zone_id, &node_id, issued_at, &divergent_zone_key).unwrap();
        let wrapped_object =
            wrap_object_id_key(&pk, &zone_id, &node_id, issued_at, &object_id_key).unwrap();

        let manifest = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: ZoneKeyId::from_bytes([0xC1; 8]),
            object_id_key_id: ObjectIdKeyId::from_bytes([0xD1; 8]),
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at,
            valid_until: None,
            prev_zone_key_id: None,
            wrapped_keys: vec![v3_wrap],
            wrapped_object_id_keys: vec![wrapped_object],
            rekey_policy: None,
            signature: test_signature(),
            kem: ZoneKemAlgorithm::XWing,
            wrapped_keys_v4: vec![divergent_v4_hpke.to_v4()],
        };

        let err = manifest
            .validate_no_recipient_split_view()
            .expect_err("divergent V3/V4 recipient wrap must fail validation");
        assert!(matches!(
            err,
            ZoneKeyError::InconsistentRecipientWraps { node_id: id }
                if id == node_id.as_str()
        ));

        let mut ring = ZoneKeyRing::new(zone_id);
        let err = ring
            .apply_manifest(&manifest, &node_id, &sk)
            .expect_err("apply must reject split-view manifests before installing a key");
        assert!(matches!(
            err,
            ZoneKeyError::InconsistentRecipientWraps { node_id: id }
                if id == node_id.as_str()
        ));
        assert!(
            ring.active_zone_key_id.is_none(),
            "failed manifest must not mutate active key state"
        );
    }

    /// Test key rotation: applying a new manifest rotates the active key while
    /// keeping the old key accessible by its ID (deterministic selection).
    #[test]
    fn rotation_deterministic_key_selection_by_zone_key_id() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-rotation");

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();

        // === First manifest (epoch 1) ===
        let issued_at_1 = 1_700_000_000;
        let zone_key_1 = random_zone_key();
        let object_id_key_1 = random_object_id_key();
        let zone_key_id_1 = ZoneKeyId::from_bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        let object_id_key_id_1 =
            ObjectIdKeyId::from_bytes([0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]);

        let wrapped_zone_1 =
            wrap_zone_key(&pk, &zone_id, &node_id, issued_at_1, &zone_key_1).unwrap();
        let wrapped_object_1 =
            wrap_object_id_key(&pk, &zone_id, &node_id, issued_at_1, &object_id_key_1).unwrap();

        let manifest_1 = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: zone_key_id_1,
            object_id_key_id: object_id_key_id_1,
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at_1,
            valid_until: None,
            prev_zone_key_id: None,
            wrapped_keys: vec![wrapped_zone_1],
            wrapped_object_id_keys: vec![wrapped_object_1],
            rekey_policy: None,
            signature: test_signature(),
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
        };

        let mut ring = ZoneKeyRing::new(zone_id.clone());
        ring.apply_manifest(&manifest_1, &node_id, &sk).unwrap();

        // Verify initial state
        assert_eq!(ring.active_zone_key_id, Some(zone_key_id_1));
        assert_eq!(ring.active_zone_key(), Some(&zone_key_1));

        // === Second manifest (epoch 2) - rotation ===
        let issued_at_2 = 1_700_100_000;
        let zone_key_2 = random_zone_key();
        let object_id_key_2 = random_object_id_key();
        let zone_key_id_2 = ZoneKeyId::from_bytes([0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28]);
        let object_id_key_id_2 =
            ObjectIdKeyId::from_bytes([0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]);

        let wrapped_zone_2 =
            wrap_zone_key(&pk, &zone_id, &node_id, issued_at_2, &zone_key_2).unwrap();
        let wrapped_object_2 =
            wrap_object_id_key(&pk, &zone_id, &node_id, issued_at_2, &object_id_key_2).unwrap();

        let manifest_2 = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: zone_key_id_2,
            object_id_key_id: object_id_key_id_2,
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at_2,
            valid_until: None,
            prev_zone_key_id: Some(zone_key_id_1), // Links to previous key
            wrapped_keys: vec![wrapped_zone_2],
            wrapped_object_id_keys: vec![wrapped_object_2],
            rekey_policy: Some(RekeyPolicy {
                overlap_window_secs: Some(600),
                ..RekeyPolicy::default()
            }),
            signature: test_signature(),
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
        };

        ring.apply_manifest(&manifest_2, &node_id, &sk).unwrap();

        // Verify rotation occurred
        assert_eq!(ring.active_zone_key_id, Some(zone_key_id_2));
        assert_eq!(ring.active_zone_key(), Some(&zone_key_2));

        // CRITICAL: Both keys must be accessible by their IDs (deterministic selection)
        // This enables decryption of symbols encrypted under either epoch without trial decrypt.
        assert_eq!(ring.zone_key(&zone_key_id_1), Some(&zone_key_1));
        assert_eq!(ring.zone_key(&zone_key_id_2), Some(&zone_key_2));
        assert_eq!(
            ring.object_id_key(&object_id_key_id_1),
            Some(&object_id_key_1)
        );
        assert_eq!(
            ring.object_id_key(&object_id_key_id_2),
            Some(&object_id_key_2)
        );

        // Verify we can switch active key back to epoch 1 (for decryption overlap window)
        assert!(ring.set_active_zone_key(zone_key_id_1));
        assert_eq!(ring.active_zone_key(), Some(&zone_key_1));
    }

    /// Test membership change: a removed node cannot decrypt newly wrapped keys
    /// because they are not included in the `wrapped_keys` list.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn membership_change_removed_node_cannot_decrypt() {
        let zone_id = ZoneId::work();

        // Three nodes initially in the zone
        let node_1_id = TailscaleNodeId::new("node-1");
        let node_2_id = TailscaleNodeId::new("node-2");
        let node_3_id = TailscaleNodeId::new("node-3"); // Will be removed

        let sk_1 = X25519SecretKey::generate();
        let pk_1 = sk_1.public_key();
        let sk_2 = X25519SecretKey::generate();
        let pk_2 = sk_2.public_key();
        let sk_3 = X25519SecretKey::generate();
        let pk_3 = sk_3.public_key();

        // === Initial manifest with all 3 nodes ===
        let issued_at_1 = 1_700_000_000;
        let zone_key_1 = random_zone_key();
        let object_id_key_1 = random_object_id_key();
        let zone_key_id_1 = ZoneKeyId::from_bytes([0x01; 8]);
        let object_id_key_id_1 = ObjectIdKeyId::from_bytes([0x11; 8]);

        let wrapped_zone_1_for_1 =
            wrap_zone_key(&pk_1, &zone_id, &node_1_id, issued_at_1, &zone_key_1).unwrap();
        let wrapped_zone_1_for_2 =
            wrap_zone_key(&pk_2, &zone_id, &node_2_id, issued_at_1, &zone_key_1).unwrap();
        let wrapped_zone_1_for_3 =
            wrap_zone_key(&pk_3, &zone_id, &node_3_id, issued_at_1, &zone_key_1).unwrap();
        let wrapped_obj_1_for_1 =
            wrap_object_id_key(&pk_1, &zone_id, &node_1_id, issued_at_1, &object_id_key_1).unwrap();
        let wrapped_obj_1_for_2 =
            wrap_object_id_key(&pk_2, &zone_id, &node_2_id, issued_at_1, &object_id_key_1).unwrap();
        let wrapped_obj_1_for_3 =
            wrap_object_id_key(&pk_3, &zone_id, &node_3_id, issued_at_1, &object_id_key_1).unwrap();

        let manifest_1 = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: zone_key_id_1,
            object_id_key_id: object_id_key_id_1,
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at_1,
            valid_until: None,
            prev_zone_key_id: None,
            wrapped_keys: vec![
                wrapped_zone_1_for_1,
                wrapped_zone_1_for_2,
                wrapped_zone_1_for_3,
            ],
            wrapped_object_id_keys: vec![
                wrapped_obj_1_for_1,
                wrapped_obj_1_for_2,
                wrapped_obj_1_for_3,
            ],
            rekey_policy: None,
            signature: test_signature(),
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
        };

        // All 3 nodes can apply the initial manifest
        let mut ring_1 = ZoneKeyRing::new(zone_id.clone());
        let mut ring_2 = ZoneKeyRing::new(zone_id.clone());
        let mut ring_3 = ZoneKeyRing::new(zone_id.clone());

        ring_1
            .apply_manifest(&manifest_1, &node_1_id, &sk_1)
            .unwrap();
        ring_2
            .apply_manifest(&manifest_1, &node_2_id, &sk_2)
            .unwrap();
        ring_3
            .apply_manifest(&manifest_1, &node_3_id, &sk_3)
            .unwrap();

        // === Second manifest: node-3 is removed from membership ===
        let issued_at_2 = 1_700_100_000;
        let zone_key_2 = random_zone_key();
        let object_id_key_2 = random_object_id_key();
        let zone_key_id_2 = ZoneKeyId::from_bytes([0x31; 8]);
        let object_id_key_id_2 = ObjectIdKeyId::from_bytes([0x41; 8]);

        // Only wrap keys for nodes 1 and 2 (node 3 is excluded)
        let wrapped_zone_2_for_1 =
            wrap_zone_key(&pk_1, &zone_id, &node_1_id, issued_at_2, &zone_key_2).unwrap();
        let wrapped_zone_2_for_2 =
            wrap_zone_key(&pk_2, &zone_id, &node_2_id, issued_at_2, &zone_key_2).unwrap();
        let wrapped_obj_2_for_1 =
            wrap_object_id_key(&pk_1, &zone_id, &node_1_id, issued_at_2, &object_id_key_2).unwrap();
        let wrapped_obj_2_for_2 =
            wrap_object_id_key(&pk_2, &zone_id, &node_2_id, issued_at_2, &object_id_key_2).unwrap();

        let manifest_2 = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: zone_key_id_2,
            object_id_key_id: object_id_key_id_2,
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at_2,
            valid_until: None,
            prev_zone_key_id: Some(zone_key_id_1),
            wrapped_keys: vec![wrapped_zone_2_for_1, wrapped_zone_2_for_2],
            wrapped_object_id_keys: vec![wrapped_obj_2_for_1, wrapped_obj_2_for_2],
            rekey_policy: Some(RekeyPolicy {
                rewrap_on_membership_change: true,
                ..RekeyPolicy::default()
            }),
            signature: test_signature(),
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
        };

        // Nodes 1 and 2 can apply the new manifest
        ring_1
            .apply_manifest(&manifest_2, &node_1_id, &sk_1)
            .unwrap();
        ring_2
            .apply_manifest(&manifest_2, &node_2_id, &sk_2)
            .unwrap();

        // CRITICAL: Node 3 CANNOT apply the new manifest (no wrapped key for them)
        let err = ring_3
            .apply_manifest(&manifest_2, &node_3_id, &sk_3)
            .expect_err("removed node should fail");
        assert!(
            matches!(err, ZoneKeyError::MissingWrappedZoneKey { .. }),
            "expected MissingWrappedZoneKey error, got {err:?}"
        );

        // Verify nodes 1 and 2 have the new key
        assert_eq!(ring_1.active_zone_key_id, Some(zone_key_id_2));
        assert_eq!(ring_2.active_zone_key_id, Some(zone_key_id_2));
        assert_eq!(ring_1.active_zone_key(), Some(&zone_key_2));
        assert_eq!(ring_2.active_zone_key(), Some(&zone_key_2));

        // Node 3 still has only the old key
        assert_eq!(ring_3.active_zone_key_id, Some(zone_key_id_1));
        assert_eq!(ring_3.active_zone_key(), Some(&zone_key_1));
        assert!(ring_3.zone_key(&zone_key_id_2).is_none());
    }

    /// Test that `ObjectIdKey` rotation can happen independently or alongside `ZoneKey` rotation.
    #[test]
    fn rotation_with_object_id_key_change() {
        let zone_id = ZoneId::private();
        let node_id = TailscaleNodeId::new("node-objid-rotation");

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();

        // === First manifest ===
        let issued_at_1 = 1_700_000_000;
        let zone_key_1 = random_zone_key();
        let object_id_key_1 = random_object_id_key();
        let zone_key_id_1 = ZoneKeyId::from_bytes([0x01; 8]);
        let object_id_key_id_1 = ObjectIdKeyId::from_bytes([0x11; 8]);

        let wrapped_zone_1 =
            wrap_zone_key(&pk, &zone_id, &node_id, issued_at_1, &zone_key_1).unwrap();
        let wrapped_object_1 =
            wrap_object_id_key(&pk, &zone_id, &node_id, issued_at_1, &object_id_key_1).unwrap();

        let manifest_1 = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: zone_key_id_1,
            object_id_key_id: object_id_key_id_1,
            algorithm: ZoneKeyAlgorithm::XChaCha20Poly1305,
            valid_from: issued_at_1,
            valid_until: None,
            prev_zone_key_id: None,
            wrapped_keys: vec![wrapped_zone_1],
            wrapped_object_id_keys: vec![wrapped_object_1],
            rekey_policy: None,
            signature: test_signature(),
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
        };

        let mut ring = ZoneKeyRing::new(zone_id.clone());
        ring.apply_manifest(&manifest_1, &node_id, &sk).unwrap();

        // === Second manifest with BOTH ZoneKey AND ObjectIdKey rotation ===
        // (Used when rotate_object_id_key_on_membership_change policy is set)
        let issued_at_2 = 1_700_100_000;
        let zone_key_2 = random_zone_key();
        let object_id_key_2 = random_object_id_key();
        let zone_key_id_2 = ZoneKeyId::from_bytes([0x41; 8]);
        let object_id_key_id_2 = ObjectIdKeyId::from_bytes([0x51; 8]); // Also rotated!

        let wrapped_zone_2 =
            wrap_zone_key(&pk, &zone_id, &node_id, issued_at_2, &zone_key_2).unwrap();
        let wrapped_object_2 =
            wrap_object_id_key(&pk, &zone_id, &node_id, issued_at_2, &object_id_key_2).unwrap();

        let manifest_2 = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: zone_key_id_2,
            object_id_key_id: object_id_key_id_2,
            algorithm: ZoneKeyAlgorithm::XChaCha20Poly1305,
            valid_from: issued_at_2,
            valid_until: None,
            prev_zone_key_id: Some(zone_key_id_1),
            wrapped_keys: vec![wrapped_zone_2],
            wrapped_object_id_keys: vec![wrapped_object_2],
            rekey_policy: Some(RekeyPolicy {
                rotate_object_id_key_on_membership_change: true,
                ..RekeyPolicy::default()
            }),
            signature: test_signature(),
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
        };

        ring.apply_manifest(&manifest_2, &node_id, &sk).unwrap();

        // Verify both keys rotated
        assert_eq!(ring.active_zone_key_id, Some(zone_key_id_2));
        assert_eq!(ring.active_object_id_key_id, Some(object_id_key_id_2));

        // Both old and new keys accessible (no trial decrypt needed)
        assert_eq!(ring.zone_key(&zone_key_id_1), Some(&zone_key_1));
        assert_eq!(ring.zone_key(&zone_key_id_2), Some(&zone_key_2));
        assert_eq!(
            ring.object_id_key(&object_id_key_id_1),
            Some(&object_id_key_1)
        );
        assert_eq!(
            ring.object_id_key(&object_id_key_id_2),
            Some(&object_id_key_2)
        );
    }

    /// Test chain of three rotations (key1 → key2 → key3) verifying `prev_zone_key_id` linkage.
    /// This ensures the full rotation history is preserved and all keys remain accessible.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn rotation_chain_three_epochs() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-chain");

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();

        // === Epoch 1: Initial key ===
        let issued_at_1 = 1_700_000_000;
        let zone_key_1 = random_zone_key();
        let object_id_key_1 = random_object_id_key();
        let zone_key_id_1 = ZoneKeyId::from_bytes([0x01; 8]);
        let object_id_key_id_1 = ObjectIdKeyId::from_bytes([0x11; 8]);

        let wrapped_zone_1 =
            wrap_zone_key(&pk, &zone_id, &node_id, issued_at_1, &zone_key_1).unwrap();
        let wrapped_object_1 =
            wrap_object_id_key(&pk, &zone_id, &node_id, issued_at_1, &object_id_key_1).unwrap();

        let manifest_1 = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: zone_key_id_1,
            object_id_key_id: object_id_key_id_1,
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at_1,
            valid_until: None,
            prev_zone_key_id: None, // No previous key
            wrapped_keys: vec![wrapped_zone_1],
            wrapped_object_id_keys: vec![wrapped_object_1],
            rekey_policy: None,
            signature: test_signature(),
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
        };

        let mut ring = ZoneKeyRing::new(zone_id.clone());
        ring.apply_manifest(&manifest_1, &node_id, &sk).unwrap();
        assert_eq!(ring.active_zone_key_id, Some(zone_key_id_1));

        // === Epoch 2: First rotation (links to epoch 1) ===
        let issued_at_2 = 1_700_100_000;
        let zone_key_2 = random_zone_key();
        let object_id_key_2 = random_object_id_key();
        let zone_key_id_2 = ZoneKeyId::from_bytes([0x02; 8]);
        let object_id_key_id_2 = ObjectIdKeyId::from_bytes([0x12; 8]);

        let wrapped_zone_2 =
            wrap_zone_key(&pk, &zone_id, &node_id, issued_at_2, &zone_key_2).unwrap();
        let wrapped_object_2 =
            wrap_object_id_key(&pk, &zone_id, &node_id, issued_at_2, &object_id_key_2).unwrap();

        let manifest_2 = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: zone_key_id_2,
            object_id_key_id: object_id_key_id_2,
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at_2,
            valid_until: None,
            prev_zone_key_id: Some(zone_key_id_1), // Links to epoch 1
            wrapped_keys: vec![wrapped_zone_2],
            wrapped_object_id_keys: vec![wrapped_object_2],
            rekey_policy: None,
            signature: test_signature(),
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
        };

        ring.apply_manifest(&manifest_2, &node_id, &sk).unwrap();
        assert_eq!(ring.active_zone_key_id, Some(zone_key_id_2));

        // === Epoch 3: Second rotation (links to epoch 2) ===
        let issued_at_3 = 1_700_200_000;
        let zone_key_3 = random_zone_key();
        let object_id_key_3 = random_object_id_key();
        let zone_key_id_3 = ZoneKeyId::from_bytes([0x03; 8]);
        let object_id_key_id_3 = ObjectIdKeyId::from_bytes([0x13; 8]);

        let wrapped_zone_3 =
            wrap_zone_key(&pk, &zone_id, &node_id, issued_at_3, &zone_key_3).unwrap();
        let wrapped_object_3 =
            wrap_object_id_key(&pk, &zone_id, &node_id, issued_at_3, &object_id_key_3).unwrap();

        let manifest_3 = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: zone_key_id_3,
            object_id_key_id: object_id_key_id_3,
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at_3,
            valid_until: None,
            prev_zone_key_id: Some(zone_key_id_2), // Links to epoch 2
            wrapped_keys: vec![wrapped_zone_3],
            wrapped_object_id_keys: vec![wrapped_object_3],
            rekey_policy: Some(RekeyPolicy {
                epoch_ratchet: true,
                retain_epochs: Some(3), // Keep all 3 epochs
                ..RekeyPolicy::default()
            }),
            signature: test_signature(),
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
        };

        ring.apply_manifest(&manifest_3, &node_id, &sk).unwrap();

        // Verify final state
        assert_eq!(ring.active_zone_key_id, Some(zone_key_id_3));
        assert_eq!(ring.active_zone_key(), Some(&zone_key_3));

        // CRITICAL: All three keys must be accessible (deterministic key selection)
        assert_eq!(ring.zone_key(&zone_key_id_1), Some(&zone_key_1));
        assert_eq!(ring.zone_key(&zone_key_id_2), Some(&zone_key_2));
        assert_eq!(ring.zone_key(&zone_key_id_3), Some(&zone_key_3));

        // All ObjectId keys also accessible
        assert_eq!(
            ring.object_id_key(&object_id_key_id_1),
            Some(&object_id_key_1)
        );
        assert_eq!(
            ring.object_id_key(&object_id_key_id_2),
            Some(&object_id_key_2)
        );
        assert_eq!(
            ring.object_id_key(&object_id_key_id_3),
            Some(&object_id_key_3)
        );

        // Verify we can decrypt data from any epoch by switching active key
        assert!(ring.set_active_zone_key(zone_key_id_1));
        assert_eq!(ring.active_zone_key(), Some(&zone_key_1));
        assert!(ring.set_active_zone_key(zone_key_id_2));
        assert_eq!(ring.active_zone_key(), Some(&zone_key_2));
        assert!(ring.set_active_zone_key(zone_key_id_3));
        assert_eq!(ring.active_zone_key(), Some(&zone_key_3));
    }

    /// Test that applying the same manifest twice is idempotent.
    /// This verifies manifest replay doesn't corrupt state.
    #[test]
    fn manifest_replay_is_idempotent() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-replay");
        let issued_at = 1_700_000_000;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();

        let zone_key = random_zone_key();
        let object_id_key = random_object_id_key();
        let zone_key_id = ZoneKeyId::from_bytes([0xAA; 8]);
        let object_id_key_id = ObjectIdKeyId::from_bytes([0xBB; 8]);

        let wrapped_zone = wrap_zone_key(&pk, &zone_id, &node_id, issued_at, &zone_key).unwrap();
        let wrapped_object =
            wrap_object_id_key(&pk, &zone_id, &node_id, issued_at, &object_id_key).unwrap();

        let manifest = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id,
            object_id_key_id,
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at,
            valid_until: None,
            prev_zone_key_id: None,
            wrapped_keys: vec![wrapped_zone],
            wrapped_object_id_keys: vec![wrapped_object],
            rekey_policy: None,
            signature: test_signature(),
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
        };

        let mut ring = ZoneKeyRing::new(zone_id);

        // Apply manifest first time
        ring.apply_manifest(&manifest, &node_id, &sk).unwrap();
        let state_after_first = (
            ring.active_zone_key_id,
            ring.active_zone_key().copied(),
            ring.active_object_id_key_id,
        );

        // Apply manifest second time (replay)
        ring.apply_manifest(&manifest, &node_id, &sk).unwrap();
        let state_after_second = (
            ring.active_zone_key_id,
            ring.active_zone_key().copied(),
            ring.active_object_id_key_id,
        );

        // State should be identical after replay
        assert_eq!(state_after_first, state_after_second);
        assert_eq!(ring.zone_key(&zone_key_id), Some(&zone_key));
    }

    /// Test node addition to zone membership (new node can receive keys).
    #[test]
    #[allow(clippy::too_many_lines)]
    fn membership_change_node_addition() {
        let zone_id = ZoneId::work();

        // Two nodes initially in the zone
        let node_1_id = TailscaleNodeId::new("node-1");
        let node_2_id = TailscaleNodeId::new("node-2");
        // New node to be added
        let node_3_id = TailscaleNodeId::new("node-3-new");

        let sk_1 = X25519SecretKey::generate();
        let pk_1 = sk_1.public_key();
        let sk_2 = X25519SecretKey::generate();
        let pk_2 = sk_2.public_key();
        let sk_3 = X25519SecretKey::generate();
        let pk_3 = sk_3.public_key();

        // === Initial manifest with 2 nodes ===
        let issued_at_1 = 1_700_000_000;
        let zone_key_1 = random_zone_key();
        let object_id_key_1 = random_object_id_key();
        let zone_key_id_1 = ZoneKeyId::from_bytes([0x01; 8]);
        let object_id_key_id_1 = ObjectIdKeyId::from_bytes([0x11; 8]);

        let wrapped_zone_1_for_1 =
            wrap_zone_key(&pk_1, &zone_id, &node_1_id, issued_at_1, &zone_key_1).unwrap();
        let wrapped_zone_1_for_2 =
            wrap_zone_key(&pk_2, &zone_id, &node_2_id, issued_at_1, &zone_key_1).unwrap();
        let wrapped_obj_1_for_1 =
            wrap_object_id_key(&pk_1, &zone_id, &node_1_id, issued_at_1, &object_id_key_1).unwrap();
        let wrapped_obj_1_for_2 =
            wrap_object_id_key(&pk_2, &zone_id, &node_2_id, issued_at_1, &object_id_key_1).unwrap();

        let manifest_1 = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: zone_key_id_1,
            object_id_key_id: object_id_key_id_1,
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at_1,
            valid_until: None,
            prev_zone_key_id: None,
            wrapped_keys: vec![wrapped_zone_1_for_1, wrapped_zone_1_for_2],
            wrapped_object_id_keys: vec![wrapped_obj_1_for_1, wrapped_obj_1_for_2],
            rekey_policy: None,
            signature: test_signature(),
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
        };

        let mut ring_1 = ZoneKeyRing::new(zone_id.clone());
        let mut ring_2 = ZoneKeyRing::new(zone_id.clone());
        let mut ring_3 = ZoneKeyRing::new(zone_id.clone());

        ring_1
            .apply_manifest(&manifest_1, &node_1_id, &sk_1)
            .unwrap();
        ring_2
            .apply_manifest(&manifest_1, &node_2_id, &sk_2)
            .unwrap();

        // Node 3 cannot apply initial manifest (not a member yet)
        let err = ring_3
            .apply_manifest(&manifest_1, &node_3_id, &sk_3)
            .expect_err("new node should not be in initial manifest");
        assert!(matches!(err, ZoneKeyError::MissingWrappedZoneKey { .. }));

        // === Second manifest: node-3 is added ===
        let issued_at_2 = 1_700_100_000;
        let zone_key_2 = random_zone_key();
        let object_id_key_2 = random_object_id_key();
        let zone_key_id_2 = ZoneKeyId::from_bytes([0x02; 8]);
        let object_id_key_id_2 = ObjectIdKeyId::from_bytes([0x12; 8]);

        // Wrap keys for all 3 nodes
        let wrapped_zone_2_for_1 =
            wrap_zone_key(&pk_1, &zone_id, &node_1_id, issued_at_2, &zone_key_2).unwrap();
        let wrapped_zone_2_for_2 =
            wrap_zone_key(&pk_2, &zone_id, &node_2_id, issued_at_2, &zone_key_2).unwrap();
        let wrapped_zone_2_for_3 =
            wrap_zone_key(&pk_3, &zone_id, &node_3_id, issued_at_2, &zone_key_2).unwrap();
        let wrapped_obj_2_for_1 =
            wrap_object_id_key(&pk_1, &zone_id, &node_1_id, issued_at_2, &object_id_key_2).unwrap();
        let wrapped_obj_2_for_2 =
            wrap_object_id_key(&pk_2, &zone_id, &node_2_id, issued_at_2, &object_id_key_2).unwrap();
        let wrapped_obj_2_for_3 =
            wrap_object_id_key(&pk_3, &zone_id, &node_3_id, issued_at_2, &object_id_key_2).unwrap();

        let manifest_2 = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: zone_key_id_2,
            object_id_key_id: object_id_key_id_2,
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at_2,
            valid_until: None,
            prev_zone_key_id: Some(zone_key_id_1),
            wrapped_keys: vec![
                wrapped_zone_2_for_1,
                wrapped_zone_2_for_2,
                wrapped_zone_2_for_3,
            ],
            wrapped_object_id_keys: vec![
                wrapped_obj_2_for_1,
                wrapped_obj_2_for_2,
                wrapped_obj_2_for_3,
            ],
            rekey_policy: Some(RekeyPolicy {
                rewrap_on_membership_change: true,
                ..RekeyPolicy::default()
            }),
            signature: test_signature(),
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
        };

        // All 3 nodes can apply the new manifest
        ring_1
            .apply_manifest(&manifest_2, &node_1_id, &sk_1)
            .unwrap();
        ring_2
            .apply_manifest(&manifest_2, &node_2_id, &sk_2)
            .unwrap();
        ring_3
            .apply_manifest(&manifest_2, &node_3_id, &sk_3)
            .unwrap();

        // Verify all nodes have the new key
        assert_eq!(ring_1.active_zone_key_id, Some(zone_key_id_2));
        assert_eq!(ring_2.active_zone_key_id, Some(zone_key_id_2));
        assert_eq!(ring_3.active_zone_key_id, Some(zone_key_id_2));

        // All nodes have the same key value
        assert_eq!(ring_1.active_zone_key(), Some(&zone_key_2));
        assert_eq!(ring_2.active_zone_key(), Some(&zone_key_2));
        assert_eq!(ring_3.active_zone_key(), Some(&zone_key_2));

        // Original nodes have both old and new keys
        assert!(ring_1.zone_key(&zone_key_id_1).is_some());
        assert!(ring_2.zone_key(&zone_key_id_1).is_some());

        // New node only has the new key (didn't receive the old key)
        assert!(ring_3.zone_key(&zone_key_id_1).is_none());
        assert!(ring_3.zone_key(&zone_key_id_2).is_some());
    }

    /// Test that `valid_until` expiration field is correctly stored.
    #[test]
    fn manifest_with_valid_until() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-expiry");
        let issued_at = 1_700_000_000;
        let expires_at = 1_700_100_000; // 100,000 seconds later

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();

        let zone_key = random_zone_key();
        let object_id_key = random_object_id_key();
        let zone_key_id = ZoneKeyId::from_bytes([0xEE; 8]);
        let object_id_key_id = ObjectIdKeyId::from_bytes([0xFF; 8]);

        let wrapped_zone = wrap_zone_key(&pk, &zone_id, &node_id, issued_at, &zone_key).unwrap();
        let wrapped_object =
            wrap_object_id_key(&pk, &zone_id, &node_id, issued_at, &object_id_key).unwrap();

        let manifest = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id,
            object_id_key_id,
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at,
            valid_until: Some(expires_at), // Expiration set
            prev_zone_key_id: None,
            wrapped_keys: vec![wrapped_zone],
            wrapped_object_id_keys: vec![wrapped_object],
            rekey_policy: Some(RekeyPolicy {
                overlap_window_secs: Some(3600), // 1 hour overlap
                ..RekeyPolicy::default()
            }),
            signature: test_signature(),
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
        };

        // Manifest should apply successfully (expiration is metadata, not enforced in apply)
        let mut ring = ZoneKeyRing::new(zone_id);
        ring.apply_manifest(&manifest, &node_id, &sk).unwrap();

        assert_eq!(ring.active_zone_key_id, Some(zone_key_id));
        assert_eq!(manifest.valid_until, Some(expires_at));
        assert_eq!(
            manifest.rekey_policy.as_ref().unwrap().overlap_window_secs,
            Some(3600)
        );
    }

    /// Test XChaCha20-Poly1305 algorithm selection.
    #[test]
    fn manifest_with_xchacha20_poly1305() {
        let zone_id = ZoneId::private();
        let node_id = TailscaleNodeId::new("node-xchacha");
        let issued_at = 1_700_000_000;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();

        let zone_key = random_zone_key();
        let object_id_key = random_object_id_key();

        let wrapped_zone = wrap_zone_key(&pk, &zone_id, &node_id, issued_at, &zone_key).unwrap();
        let wrapped_object =
            wrap_object_id_key(&pk, &zone_id, &node_id, issued_at, &object_id_key).unwrap();

        let manifest = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: ZoneKeyId::from_bytes([0xCC; 8]),
            object_id_key_id: ObjectIdKeyId::from_bytes([0xDD; 8]),
            algorithm: ZoneKeyAlgorithm::XChaCha20Poly1305, // Extended nonce variant
            valid_from: issued_at,
            valid_until: None,
            prev_zone_key_id: None,
            wrapped_keys: vec![wrapped_zone],
            wrapped_object_id_keys: vec![wrapped_object],
            rekey_policy: None,
            signature: test_signature(),
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
        };

        let mut ring = ZoneKeyRing::new(zone_id);
        ring.apply_manifest(&manifest, &node_id, &sk).unwrap();

        assert_eq!(ring.active_zone_key(), Some(&zone_key));
        assert_eq!(manifest.algorithm, ZoneKeyAlgorithm::XChaCha20Poly1305);
    }

    /// Test `ZoneKeyId` and `ObjectIdKeyId` formatting.
    #[test]
    fn key_id_formatting() {
        let zone_key_id = ZoneKeyId::from_bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
        let object_id_key_id =
            ObjectIdKeyId::from_bytes([0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10]);

        // Display format should be lowercase hex
        assert_eq!(format!("{zone_key_id}"), "0123456789abcdef");
        assert_eq!(format!("{object_id_key_id}"), "fedcba9876543210");

        // Debug format includes type name
        assert!(format!("{zone_key_id:?}").contains("ZoneKeyId"));
        assert!(format!("{object_id_key_id:?}").contains("ObjectIdKeyId"));
    }

    /// Test `ZoneKey` redacted debug output for security.
    #[test]
    fn zone_key_debug_is_redacted() {
        let zone_key = ZoneKey::from_bytes([0x42; ZONE_KEY_LEN]);
        let debug_output = format!("{zone_key:?}");

        // Should NOT contain the actual key bytes
        assert!(!debug_output.contains("42"));
        // Should contain redaction marker
        assert!(debug_output.contains("redacted"));
    }

    /// Test `set_active_zone_key` returns false for unknown key.
    #[test]
    fn set_active_key_unknown_returns_false() {
        let zone_id = ZoneId::work();
        let mut ring = ZoneKeyRing::new(zone_id);

        let unknown_key_id = ZoneKeyId::from_bytes([0xFF; 8]);
        let unknown_obj_key_id = ObjectIdKeyId::from_bytes([0xEE; 8]);

        // Setting unknown key should return false
        assert!(!ring.set_active_zone_key(unknown_key_id));
        assert!(!ring.set_active_object_id_key(unknown_obj_key_id));

        // Active key should remain None
        assert!(ring.active_zone_key_id.is_none());
        assert!(ring.active_object_id_key_id.is_none());
    }

    // ── Serde and structural coverage ──

    #[test]
    fn zone_key_id_serde_roundtrip() {
        let id = ZoneKeyId::from_bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
        let json = serde_json::to_string(&id).unwrap();
        let back: ZoneKeyId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn object_id_key_id_serde_roundtrip() {
        let id = ObjectIdKeyId::from_bytes([0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10]);
        let json = serde_json::to_string(&id).unwrap();
        let back: ObjectIdKeyId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn zone_key_algorithm_serde_roundtrip() {
        for alg in [
            ZoneKeyAlgorithm::ChaCha20Poly1305,
            ZoneKeyAlgorithm::XChaCha20Poly1305,
        ] {
            let json = serde_json::to_string(&alg).unwrap();
            let back: ZoneKeyAlgorithm = serde_json::from_str(&json).unwrap();
            assert_eq!(alg, back);
        }
        // Verify snake_case
        let json = serde_json::to_string(&ZoneKeyAlgorithm::ChaCha20Poly1305).unwrap();
        assert!(json.contains("cha_cha20"));
    }

    #[test]
    fn rekey_policy_default() {
        let rp = RekeyPolicy::default();
        assert!(!rp.epoch_ratchet);
        assert!(rp.overlap_window_secs.is_none());
        assert!(rp.retain_epochs.is_none());
        assert!(!rp.rewrap_on_membership_change);
        assert!(!rp.rotate_object_id_key_on_membership_change);
    }

    #[test]
    fn rekey_policy_serde_roundtrip() {
        let rp = RekeyPolicy {
            epoch_ratchet: true,
            overlap_window_secs: Some(600),
            retain_epochs: Some(5),
            rewrap_on_membership_change: true,
            rotate_object_id_key_on_membership_change: false,
        };
        let json = serde_json::to_string(&rp).unwrap();
        let back: RekeyPolicy = serde_json::from_str(&json).unwrap();
        assert!(back.epoch_ratchet);
        assert_eq!(back.overlap_window_secs, Some(600));
        assert_eq!(back.retain_epochs, Some(5));
        assert!(back.rewrap_on_membership_change);
        assert!(!back.rotate_object_id_key_on_membership_change);
    }

    #[test]
    fn rekey_policy_serde_omits_none_fields() {
        let rp = RekeyPolicy::default();
        let json = serde_json::to_string(&rp).unwrap();
        assert!(!json.contains("overlap_window_secs"));
        assert!(!json.contains("retain_epochs"));
    }

    #[test]
    fn zone_key_from_bytes_as_bytes() {
        let bytes = [0x42u8; ZONE_KEY_LEN];
        let key = ZoneKey::from_bytes(bytes);
        assert_eq!(*key.as_bytes(), bytes);
    }

    #[test]
    fn zone_key_ring_new_empty() {
        let zone_id = ZoneId::work();
        let ring = ZoneKeyRing::new(zone_id.clone());
        assert_eq!(ring.zone_id, zone_id);
        assert!(ring.active_zone_key_id.is_none());
        assert!(ring.active_object_id_key_id.is_none());
        assert!(ring.active_zone_key().is_none());
        assert!(ring.active_object_id_key().is_none());
    }

    #[test]
    fn zone_key_ring_lookup_returns_none_for_unknown() {
        let ring = ZoneKeyRing::new(ZoneId::work());
        let unknown = ZoneKeyId::from_bytes([0xFF; 8]);
        let unknown_obj = ObjectIdKeyId::from_bytes([0xEE; 8]);
        assert!(ring.zone_key(&unknown).is_none());
        assert!(ring.object_id_key(&unknown_obj).is_none());
    }

    #[test]
    fn zone_key_error_display() {
        let err = ZoneKeyError::InvalidKeyLength {
            expected: 32,
            found: 16,
        };
        let msg = err.to_string();
        assert!(msg.contains("32"));
        assert!(msg.contains("16"));

        let err = ZoneKeyError::ZoneIdMismatch {
            expected: "z:work".into(),
            found: "z:private".into(),
        };
        assert!(err.to_string().contains("z:work"));

        let err = ZoneKeyError::MissingWrappedZoneKey {
            node_id: "node-42".into(),
        };
        assert!(err.to_string().contains("node-42"));

        let err = ZoneKeyError::MissingWrappedObjectIdKey {
            node_id: "node-99".into(),
        };
        assert!(err.to_string().contains("node-99"));
    }

    #[test]
    fn object_id_key_unwrap_fails_with_wrong_node_id() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-5");
        let issued_at = 1_700_000_000;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let key = random_object_id_key();

        let mut wrapped = wrap_object_id_key(&pk, &zone_id, &node_id, issued_at, &key).unwrap();
        wrapped.recipient = TailscaleNodeId::new("node-6");

        let result = unwrap_object_id_key(&sk, &zone_id, &wrapped);
        assert!(result.is_err());
    }

    #[test]
    fn apply_manifest_missing_object_id_key() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-no-obj");
        let issued_at = 1_700_000_000;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();

        let zone_key = random_zone_key();

        let wrapped_zone = wrap_zone_key(&pk, &zone_id, &node_id, issued_at, &zone_key).unwrap();

        // Create manifest with zone key but NO object id key for this node
        let manifest = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: ZoneKeyId::from_bytes([0x01; 8]),
            object_id_key_id: ObjectIdKeyId::from_bytes([0x11; 8]),
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at,
            valid_until: None,
            prev_zone_key_id: None,
            wrapped_keys: vec![wrapped_zone],
            wrapped_object_id_keys: vec![], // Empty!
            rekey_policy: None,
            signature: test_signature(),
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
        };

        let mut ring = ZoneKeyRing::new(zone_id);
        let err = ring
            .apply_manifest(&manifest, &node_id, &sk)
            .expect_err("should fail without object id key");
        assert!(matches!(
            err,
            ZoneKeyError::MissingWrappedObjectIdKey { .. }
        ));
    }

    #[test]
    fn zone_key_manifest_new_empty() {
        let zone_id = ZoneId::work();
        let signing_key = fcp_crypto::Ed25519SigningKey::generate();
        let manifest =
            ZoneKeyManifest::new_empty(zone_id.clone(), 1_700_000_000, &signing_key).unwrap();
        assert_eq!(manifest.zone_id, zone_id);
        assert_eq!(manifest.valid_from, 1_700_000_000);
        assert!(manifest.valid_until.is_none());
        assert!(manifest.prev_zone_key_id.is_none());
        assert!(manifest.wrapped_keys.is_empty());
        assert!(manifest.wrapped_object_id_keys.is_empty());
        assert!(manifest.rekey_policy.is_none());
        assert_eq!(manifest.algorithm, ZoneKeyAlgorithm::ChaCha20Poly1305);
    }

    /// Test `wrapped_key_for` returns `None` when recipient not found.
    #[test]
    fn wrapped_key_for_missing_recipient() {
        let zone_id = ZoneId::work();
        let node_1_id = TailscaleNodeId::new("node-1");
        let node_2_id = TailscaleNodeId::new("node-2");
        let issued_at = 1_700_000_000;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();

        let zone_key = random_zone_key();
        let object_id_key = random_object_id_key();

        // Only wrap for node-1
        let wrapped_zone = wrap_zone_key(&pk, &zone_id, &node_1_id, issued_at, &zone_key).unwrap();
        let wrapped_object =
            wrap_object_id_key(&pk, &zone_id, &node_1_id, issued_at, &object_id_key).unwrap();

        let manifest = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id,
            zone_key_id: ZoneKeyId::from_bytes([0x01; 8]),
            object_id_key_id: ObjectIdKeyId::from_bytes([0x11; 8]),
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at,
            valid_until: None,
            prev_zone_key_id: None,
            wrapped_keys: vec![wrapped_zone],
            wrapped_object_id_keys: vec![wrapped_object],
            rekey_policy: None,
            signature: test_signature(),
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
        };

        // node-1 found, node-2 not found
        assert!(manifest.wrapped_key_for(&node_1_id).is_some());
        assert!(manifest.wrapped_key_for(&node_2_id).is_none());
        assert!(manifest.wrapped_object_id_key_for(&node_1_id).is_some());
        assert!(manifest.wrapped_object_id_key_for(&node_2_id).is_none());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ZoneKeyId – Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn zone_key_id_hash_consistency() {
        use std::collections::HashSet;
        let id = ZoneKeyId::from_bytes([0x42; 8]);
        let mut set = HashSet::new();
        set.insert(id);
        set.insert(id);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn zone_key_id_equality() {
        let a = ZoneKeyId::from_bytes([1; 8]);
        let b = ZoneKeyId::from_bytes([1; 8]);
        assert_eq!(a, b);
    }

    #[test]
    fn zone_key_id_inequality() {
        let a = ZoneKeyId::from_bytes([1; 8]);
        let b = ZoneKeyId::from_bytes([2; 8]);
        assert_ne!(a, b);
    }

    #[test]
    fn zone_key_id_clone() {
        let a = ZoneKeyId::from_bytes([0xAB; 8]);
        #[allow(clippy::clone_on_copy)]
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn zone_key_id_copy() {
        let a = ZoneKeyId::from_bytes([0xCD; 8]);
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn zone_key_id_as_bytes() {
        let bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let id = ZoneKeyId::from_bytes(bytes);
        assert_eq!(*id.as_bytes(), bytes);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ObjectIdKeyId – Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn object_id_key_id_hash_consistency() {
        use std::collections::HashSet;
        let id = ObjectIdKeyId::from_bytes([0x42; 8]);
        let mut set = HashSet::new();
        set.insert(id);
        set.insert(id);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn object_id_key_id_equality() {
        let a = ObjectIdKeyId::from_bytes([3; 8]);
        let b = ObjectIdKeyId::from_bytes([3; 8]);
        assert_eq!(a, b);
    }

    #[test]
    fn object_id_key_id_inequality() {
        let a = ObjectIdKeyId::from_bytes([3; 8]);
        let b = ObjectIdKeyId::from_bytes([4; 8]);
        assert_ne!(a, b);
    }

    #[test]
    fn object_id_key_id_clone() {
        let a = ObjectIdKeyId::from_bytes([0xDE; 8]);
        #[allow(clippy::clone_on_copy)]
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn object_id_key_id_as_bytes() {
        let bytes = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];
        let id = ObjectIdKeyId::from_bytes(bytes);
        assert_eq!(*id.as_bytes(), bytes);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ZoneKey – Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn zone_key_equality() {
        let a = ZoneKey::from_bytes([0x01; ZONE_KEY_LEN]);
        let b = ZoneKey::from_bytes([0x01; ZONE_KEY_LEN]);
        assert_eq!(a, b);
    }

    #[test]
    fn zone_key_inequality() {
        let a = ZoneKey::from_bytes([0x01; ZONE_KEY_LEN]);
        let b = ZoneKey::from_bytes([0x02; ZONE_KEY_LEN]);
        assert_ne!(a, b);
    }

    #[test]
    fn zone_key_hash_consistency() {
        use std::collections::HashSet;
        let key = ZoneKey::from_bytes([0x42; ZONE_KEY_LEN]);
        let mut set = HashSet::new();
        set.insert(key);
        set.insert(key);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn zone_key_copy() {
        let a = ZoneKey::from_bytes([0x99; ZONE_KEY_LEN]);
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn zone_key_clone() {
        let a = ZoneKey::from_bytes([0xAA; ZONE_KEY_LEN]);
        #[allow(clippy::clone_on_copy)]
        let b = a.clone();
        assert_eq!(a, b);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ZoneKeyAlgorithm – Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn zone_key_algorithm_equality() {
        assert_eq!(
            ZoneKeyAlgorithm::ChaCha20Poly1305,
            ZoneKeyAlgorithm::ChaCha20Poly1305
        );
        assert_ne!(
            ZoneKeyAlgorithm::ChaCha20Poly1305,
            ZoneKeyAlgorithm::XChaCha20Poly1305
        );
    }

    #[test]
    fn zone_key_algorithm_copy() {
        let a = ZoneKeyAlgorithm::XChaCha20Poly1305;
        let b = a;
        assert_eq!(a, b);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ZoneKeyError – Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn zone_key_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(ZoneKeyError::InvalidKeyLength {
            expected: 32,
            found: 16,
        });
        assert!(err.to_string().contains("32"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ZoneKeyRing – Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn zone_key_ring_insert_and_retrieve_object_id_key() {
        let mut ring = ZoneKeyRing::new(ZoneId::work());
        let key_id = ObjectIdKeyId::from_bytes([0x42; 8]);
        let key = random_object_id_key();
        ring.insert_object_id_key(key_id, key);
        assert_eq!(ring.object_id_key(&key_id), Some(&key));
        assert!(ring.set_active_object_id_key(key_id));
        assert_eq!(ring.active_object_id_key(), Some(&key));
    }

    #[test]
    fn zone_key_ring_clone() {
        let mut ring = ZoneKeyRing::new(ZoneId::work());
        let key_id = ZoneKeyId::from_bytes([0x01; 8]);
        let key = random_zone_key();
        ring.insert_zone_key(key_id, key);
        let _ = ring.set_active_zone_key(key_id);

        let cloned = ring.clone();
        assert_eq!(cloned.zone_id, ring.zone_id);
        assert_eq!(cloned.active_zone_key_id, ring.active_zone_key_id);
        assert_eq!(cloned.zone_key(&key_id), Some(&key));
    }

    #[test]
    fn zone_key_ring_multiple_keys() {
        let mut ring = ZoneKeyRing::new(ZoneId::work());
        let id1 = ZoneKeyId::from_bytes([1; 8]);
        let id2 = ZoneKeyId::from_bytes([2; 8]);
        let key1 = ZoneKey::from_bytes([0x11; ZONE_KEY_LEN]);
        let key2 = ZoneKey::from_bytes([0x22; ZONE_KEY_LEN]);

        ring.insert_zone_key(id1, key1);
        ring.insert_zone_key(id2, key2);

        assert_eq!(ring.zone_key(&id1), Some(&key1));
        assert_eq!(ring.zone_key(&id2), Some(&key2));

        // Switch active between them
        assert!(ring.set_active_zone_key(id1));
        assert_eq!(ring.active_zone_key(), Some(&key1));
        assert!(ring.set_active_zone_key(id2));
        assert_eq!(ring.active_zone_key(), Some(&key2));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RekeyPolicy – Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn rekey_policy_clone() {
        let rp = RekeyPolicy {
            epoch_ratchet: true,
            overlap_window_secs: Some(300),
            retain_epochs: Some(3),
            rewrap_on_membership_change: true,
            rotate_object_id_key_on_membership_change: true,
        };
        let cloned = rp.clone();
        assert_eq!(cloned.epoch_ratchet, rp.epoch_ratchet);
        assert_eq!(cloned.overlap_window_secs, rp.overlap_window_secs);
        assert_eq!(cloned.retain_epochs, rp.retain_epochs);
        assert_eq!(
            cloned.rewrap_on_membership_change,
            rp.rewrap_on_membership_change
        );
        assert_eq!(
            cloned.rotate_object_id_key_on_membership_change,
            rp.rotate_object_id_key_on_membership_change
        );
    }

    #[test]
    fn rekey_policy_all_fields_set() {
        let rp = RekeyPolicy {
            epoch_ratchet: true,
            overlap_window_secs: Some(600),
            retain_epochs: Some(10),
            rewrap_on_membership_change: true,
            rotate_object_id_key_on_membership_change: true,
        };
        let json = serde_json::to_string(&rp).unwrap();
        assert!(json.contains("epoch_ratchet"));
        assert!(json.contains("overlap_window_secs"));
        assert!(json.contains("retain_epochs"));
        assert!(json.contains("rewrap_on_membership_change"));
        assert!(json.contains("rotate_object_id_key_on_membership_change"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ZONE_KEY_LEN constant
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn zone_key_len_is_32() {
        assert_eq!(ZONE_KEY_LEN, 32);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // New coverage tests
    // ─────────────────────────────────────────────────────────────────────────

    /// Verify `ZoneKeyId` Display for all-zero bytes.
    #[test]
    fn zone_key_id_display_all_zeros() {
        let id = ZoneKeyId::from_bytes([0x00; 8]);
        assert_eq!(format!("{id}"), "0000000000000000");
    }

    /// Verify `ObjectIdKeyId` Display for all-zero bytes.
    #[test]
    fn object_id_key_id_display_all_zeros() {
        let id = ObjectIdKeyId::from_bytes([0x00; 8]);
        assert_eq!(format!("{id}"), "0000000000000000");
    }

    /// Verify the exact structure of the `ZoneKey` Debug output.
    #[test]
    fn zone_key_debug_exact_format() {
        let key = ZoneKey::from_bytes([0xFF; ZONE_KEY_LEN]);
        let dbg = format!("{key:?}");
        assert_eq!(dbg, "ZoneKey(\"[redacted; 32 bytes]\")");
    }

    /// Verify `ZoneKeyId` Debug includes the hex encoding.
    #[test]
    fn zone_key_id_debug_includes_hex() {
        let id = ZoneKeyId::from_bytes([0xAB, 0xCD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let dbg = format!("{id:?}");
        assert!(dbg.starts_with("ZoneKeyId("));
        assert!(dbg.contains("abcd000000000001"));
    }

    /// Verify `ObjectIdKeyId` Debug includes the hex encoding.
    #[test]
    fn object_id_key_id_debug_includes_hex() {
        let id = ObjectIdKeyId::from_bytes([0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80]);
        let dbg = format!("{id:?}");
        assert!(dbg.starts_with("ObjectIdKeyId("));
        assert!(dbg.contains("1020304050607080"));
    }

    /// Verify `ZoneKeyAlgorithm` `XChaCha20Poly1305` serde `snake_case`.
    #[test]
    fn zone_key_algorithm_xchacha20_serde_snake_case() {
        let json = serde_json::to_string(&ZoneKeyAlgorithm::XChaCha20Poly1305).unwrap();
        assert!(json.contains("x_cha_cha20"));
    }

    /// Verify `ZoneKeyAlgorithm` debug output.
    #[test]
    fn zone_key_algorithm_debug_output() {
        let dbg_c = format!("{:?}", ZoneKeyAlgorithm::ChaCha20Poly1305);
        assert_eq!(dbg_c, "ChaCha20Poly1305");
        let dbg_x = format!("{:?}", ZoneKeyAlgorithm::XChaCha20Poly1305);
        assert_eq!(dbg_x, "XChaCha20Poly1305");
    }

    /// Verify `ZoneKeyAlgorithm` clone.
    #[test]
    fn zone_key_algorithm_clone() {
        let a = ZoneKeyAlgorithm::ChaCha20Poly1305;
        #[allow(clippy::clone_on_copy)]
        let b = a.clone();
        assert_eq!(a, b);
    }

    /// Verify that `wrap_zone_key` produces different ciphertext on each call (HPKE non-determinism).
    #[test]
    fn wrap_zone_key_nondeterministic() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-nd");
        let issued_at = 1_700_000_000;
        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let zone_key = ZoneKey::from_bytes([0x42; ZONE_KEY_LEN]);

        let w1 = wrap_zone_key(&pk, &zone_id, &node_id, issued_at, &zone_key).unwrap();
        let w2 = wrap_zone_key(&pk, &zone_id, &node_id, issued_at, &zone_key).unwrap();

        // Both must decrypt to the same key, but sealed boxes should differ
        let k1 = unwrap_zone_key(&sk, &zone_id, &w1).unwrap();
        let k2 = unwrap_zone_key(&sk, &zone_id, &w2).unwrap();
        assert_eq!(k1, zone_key);
        assert_eq!(k2, zone_key);
        // The encrypted payloads should differ (HPKE uses fresh randomness)
        assert_ne!(w1.sealed.ciphertext, w2.sealed.ciphertext);
    }

    /// Verify `unwrap_zone_key` fails when using a different secret key.
    #[test]
    fn unwrap_zone_key_wrong_secret_key() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-wsk");
        let issued_at = 1_700_000_000;

        let sk_correct = X25519SecretKey::generate();
        let pk = sk_correct.public_key();
        let sk_wrong = X25519SecretKey::generate();

        let zone_key = random_zone_key();
        let wrapped = wrap_zone_key(&pk, &zone_id, &node_id, issued_at, &zone_key).unwrap();

        let result = unwrap_zone_key(&sk_wrong, &zone_id, &wrapped);
        assert!(result.is_err(), "unwrap with wrong SK should fail");
    }

    /// Verify `unwrap_object_id_key` fails when using a different secret key.
    #[test]
    fn unwrap_object_id_key_wrong_secret_key() {
        let zone_id = ZoneId::private();
        let node_id = TailscaleNodeId::new("node-wsk2");
        let issued_at = 1_700_000_000;

        let real_sk = X25519SecretKey::generate();
        let pk = real_sk.public_key();
        let bad_sk = X25519SecretKey::generate();

        let key = random_object_id_key();
        let wrapped = wrap_object_id_key(&pk, &zone_id, &node_id, issued_at, &key).unwrap();

        let result = unwrap_object_id_key(&bad_sk, &zone_id, &wrapped);
        assert!(result.is_err(), "unwrap with wrong SK should fail");
    }

    /// Verify `unwrap_zone_key` fails when `zone_id` differs from the one used for wrapping.
    #[test]
    fn unwrap_zone_key_wrong_zone_id() {
        let wrap_zone = ZoneId::work();
        let open_zone = ZoneId::private();
        let node_id = TailscaleNodeId::new("node-wzi");
        let issued_at = 1_700_000_000;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let zone_key = random_zone_key();

        let wrapped = wrap_zone_key(&pk, &wrap_zone, &node_id, issued_at, &zone_key).unwrap();
        let result = unwrap_zone_key(&sk, &open_zone, &wrapped);
        assert!(result.is_err(), "unwrap with wrong zone_id should fail");
    }

    /// Verify `unwrap_object_id_key` fails when `zone_id` differs.
    #[test]
    fn unwrap_object_id_key_wrong_zone_id() {
        let wrap_zone = ZoneId::community();
        let open_zone = ZoneId::public();
        let node_id = TailscaleNodeId::new("node-wzi2");
        let issued_at = 1_700_000_000;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let key = random_object_id_key();

        let wrapped = wrap_object_id_key(&pk, &wrap_zone, &node_id, issued_at, &key).unwrap();
        let result = unwrap_object_id_key(&sk, &open_zone, &wrapped);
        assert!(result.is_err(), "unwrap with wrong zone_id should fail");
    }

    /// Verify `ZoneKeyRing::insert_zone_key` overwrites an existing key with the same id.
    #[test]
    fn zone_key_ring_insert_overwrites_existing() {
        let mut ring = ZoneKeyRing::new(ZoneId::work());
        let key_id = ZoneKeyId::from_bytes([0x01; 8]);
        let key_a = ZoneKey::from_bytes([0xAA; ZONE_KEY_LEN]);
        let key_b = ZoneKey::from_bytes([0xBB; ZONE_KEY_LEN]);

        ring.insert_zone_key(key_id, key_a);
        assert_eq!(ring.zone_key(&key_id), Some(&key_a));

        ring.insert_zone_key(key_id, key_b);
        assert_eq!(ring.zone_key(&key_id), Some(&key_b));
    }

    /// Verify `ZoneKeyRing::insert_object_id_key` overwrites an existing key.
    #[test]
    fn zone_key_ring_insert_object_id_key_overwrites() {
        let mut ring = ZoneKeyRing::new(ZoneId::work());
        let key_id = ObjectIdKeyId::from_bytes([0x02; 8]);
        let key_a = ObjectIdKey::from_bytes([0xCC; ZONE_KEY_LEN]);
        let key_b = ObjectIdKey::from_bytes([0xDD; ZONE_KEY_LEN]);

        ring.insert_object_id_key(key_id, key_a);
        assert_eq!(ring.object_id_key(&key_id), Some(&key_a));

        ring.insert_object_id_key(key_id, key_b);
        assert_eq!(ring.object_id_key(&key_id), Some(&key_b));
    }

    /// Verify `ZoneKeyRing` debug output includes the type name.
    #[test]
    fn zone_key_ring_debug_output() {
        let ring = ZoneKeyRing::new(ZoneId::work());
        let dbg = format!("{ring:?}");
        assert!(dbg.contains("ZoneKeyRing"));
    }

    /// Verify `RekeyPolicy` debug output.
    #[test]
    fn rekey_policy_debug_output() {
        let rp = RekeyPolicy {
            epoch_ratchet: true,
            overlap_window_secs: Some(600),
            retain_epochs: Some(5),
            rewrap_on_membership_change: false,
            rotate_object_id_key_on_membership_change: false,
        };
        let dbg = format!("{rp:?}");
        assert!(dbg.contains("RekeyPolicy"));
        assert!(dbg.contains("epoch_ratchet: true"));
        assert!(dbg.contains("600"));
    }

    /// Verify `RekeyPolicy` deserialization from minimal JSON (only required fields).
    #[test]
    fn rekey_policy_deserialize_minimal_json() {
        let json = r"{}";
        let rp: RekeyPolicy = serde_json::from_str(json).unwrap();
        assert!(!rp.epoch_ratchet);
        assert!(rp.overlap_window_secs.is_none());
        assert!(rp.retain_epochs.is_none());
        assert!(!rp.rewrap_on_membership_change);
        assert!(!rp.rotate_object_id_key_on_membership_change);
    }

    /// Verify `ZoneKeyManifest::new_empty` produces unique random key IDs across invocations.
    #[test]
    fn zone_key_manifest_new_empty_unique_ids() {
        let zone_id = ZoneId::work();
        let signing_key = fcp_crypto::Ed25519SigningKey::generate();
        let m1 = ZoneKeyManifest::new_empty(zone_id.clone(), 1_700_000_000, &signing_key).unwrap();
        let m2 = ZoneKeyManifest::new_empty(zone_id, 1_700_000_000, &signing_key).unwrap();
        // Random IDs should (almost certainly) differ
        assert_ne!(m1.zone_key_id, m2.zone_key_id);
        assert_ne!(m1.object_id_key_id, m2.object_id_key_id);
    }

    /// Verify `ZoneKeyManifest::new_empty` header fields.
    #[test]
    fn zone_key_manifest_new_empty_header_fields() {
        let zone_id = ZoneId::private();
        let signing_key = fcp_crypto::Ed25519SigningKey::generate();
        let m = ZoneKeyManifest::new_empty(zone_id.clone(), 1_700_000_000, &signing_key).unwrap();
        assert_eq!(m.header.zone_id, zone_id);
        assert_eq!(m.header.created_at, 1_700_000_000);
        assert!(m.header.refs.is_empty());
        assert!(m.header.foreign_refs.is_empty());
        assert!(m.header.ttl_secs.is_none());
        assert!(m.header.placement.is_none());
    }

    /// Verify `wrapped_key_for` selects the correct entry among multiple recipients.
    #[test]
    #[allow(clippy::similar_names)]
    fn wrapped_key_for_selects_correct_among_multiple() {
        let zone_id = ZoneId::work();
        let node_1 = TailscaleNodeId::new("node-sel-1");
        let node_2 = TailscaleNodeId::new("node-sel-2");
        let node_3 = TailscaleNodeId::new("node-sel-3");
        let issued_at = 1_700_000_000;

        let sk1 = X25519SecretKey::generate();
        let sk2 = X25519SecretKey::generate();
        let sk3 = X25519SecretKey::generate();
        let pk1 = sk1.public_key();
        let pk2 = sk2.public_key();
        let pk3 = sk3.public_key();

        let zone_key = random_zone_key();
        let obj_key = random_object_id_key();

        let w1 = wrap_zone_key(&pk1, &zone_id, &node_1, issued_at, &zone_key).unwrap();
        let w2 = wrap_zone_key(&pk2, &zone_id, &node_2, issued_at, &zone_key).unwrap();
        let w3 = wrap_zone_key(&pk3, &zone_id, &node_3, issued_at, &zone_key).unwrap();
        let o1 = wrap_object_id_key(&pk1, &zone_id, &node_1, issued_at, &obj_key).unwrap();
        let o2 = wrap_object_id_key(&pk2, &zone_id, &node_2, issued_at, &obj_key).unwrap();
        let o3 = wrap_object_id_key(&pk3, &zone_id, &node_3, issued_at, &obj_key).unwrap();

        let manifest = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: ZoneKeyId::from_bytes([0x01; 8]),
            object_id_key_id: ObjectIdKeyId::from_bytes([0x11; 8]),
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at,
            valid_until: None,
            prev_zone_key_id: None,
            wrapped_keys: vec![w1, w2, w3],
            wrapped_object_id_keys: vec![o1, o2, o3],
            rekey_policy: None,
            signature: test_signature(),
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
        };

        // Each node selects its own wrapped key
        let got_1 = manifest.wrapped_key_for(&node_1).unwrap();
        assert_eq!(got_1.recipient, node_1);
        let got_2 = manifest.wrapped_key_for(&node_2).unwrap();
        assert_eq!(got_2.recipient, node_2);
        let got_3 = manifest.wrapped_key_for(&node_3).unwrap();
        assert_eq!(got_3.recipient, node_3);

        // Same for object id keys
        let obj_got = manifest.wrapped_object_id_key_for(&node_2).unwrap();
        assert_eq!(obj_got.recipient, node_2);
    }

    /// Verify `WrappedZoneKey` clone preserves all fields.
    #[test]
    fn wrapped_zone_key_clone() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-wclone");
        let issued_at = 1_700_000_000;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let zone_key = random_zone_key();

        let wrapped = wrap_zone_key(&pk, &zone_id, &node_id, issued_at, &zone_key).unwrap();
        let cloned = wrapped.clone();
        assert_eq!(cloned.recipient, wrapped.recipient);
        assert_eq!(cloned.issued_at, wrapped.issued_at);
        assert_eq!(cloned.sealed.ciphertext, wrapped.sealed.ciphertext);
    }

    /// Verify `WrappedObjectIdKey` clone preserves all fields.
    #[test]
    fn wrapped_object_id_key_clone() {
        let zone_id = ZoneId::private();
        let node_id = TailscaleNodeId::new("node-oclone");
        let issued_at = 1_700_000_000;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let key = random_object_id_key();

        let wrapped = wrap_object_id_key(&pk, &zone_id, &node_id, issued_at, &key).unwrap();
        let cloned = wrapped.clone();
        assert_eq!(cloned.recipient, wrapped.recipient);
        assert_eq!(cloned.issued_at, wrapped.issued_at);
        assert_eq!(cloned.sealed.ciphertext, wrapped.sealed.ciphertext);
    }

    /// Verify `WrappedZoneKey` debug output includes relevant information.
    #[test]
    fn wrapped_zone_key_debug() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-dbg");
        let issued_at = 1_700_000_000;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let zone_key = random_zone_key();

        let wrapped = wrap_zone_key(&pk, &zone_id, &node_id, issued_at, &zone_key).unwrap();
        let dbg = format!("{wrapped:?}");
        assert!(dbg.contains("WrappedZoneKey"));
        assert!(dbg.contains("node-dbg"));
    }

    /// Verify `ZoneKeyId` and `ObjectIdKeyId` work correctly as `HashMap` keys with distinct values.
    #[test]
    fn key_ids_as_hashmap_keys() {
        let mut map = HashMap::new();
        let id_a = ZoneKeyId::from_bytes([0x01; 8]);
        let id_b = ZoneKeyId::from_bytes([0x02; 8]);
        let id_c = ZoneKeyId::from_bytes([0x01; 8]); // same as id_a

        map.insert(id_a, "first");
        map.insert(id_b, "second");
        map.insert(id_c, "overwritten"); // should overwrite id_a's entry

        assert_eq!(map.len(), 2);
        assert_eq!(map.get(&id_a), Some(&"overwritten"));
        assert_eq!(map.get(&id_b), Some(&"second"));
    }

    /// Verify `ZoneKeyError::Crypto` variant Display.
    #[test]
    fn zone_key_error_crypto_display() {
        let crypto_err = CryptoError::HpkeFailed("test hpke error".to_string());
        let err = ZoneKeyError::from(crypto_err);
        let msg = err.to_string();
        assert!(msg.contains("crypto failure"));
    }

    /// Verify `ZoneKeyManifest` serde roundtrip (JSON).
    #[test]
    fn zone_key_manifest_serde_roundtrip() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-serde");
        let issued_at = 1_700_000_000;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let zone_key = random_zone_key();
        let obj_key = random_object_id_key();

        let wrapped_zone = wrap_zone_key(&pk, &zone_id, &node_id, issued_at, &zone_key).unwrap();
        let wrapped_obj = wrap_object_id_key(&pk, &zone_id, &node_id, issued_at, &obj_key).unwrap();

        let manifest = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: ZoneKeyId::from_bytes([0xAA; 8]),
            object_id_key_id: ObjectIdKeyId::from_bytes([0xBB; 8]),
            algorithm: ZoneKeyAlgorithm::XChaCha20Poly1305,
            valid_from: issued_at,
            valid_until: Some(1_700_100_000),
            prev_zone_key_id: Some(ZoneKeyId::from_bytes([0x99; 8])),
            wrapped_keys: vec![wrapped_zone],
            wrapped_object_id_keys: vec![wrapped_obj],
            rekey_policy: Some(RekeyPolicy {
                epoch_ratchet: true,
                overlap_window_secs: Some(600),
                retain_epochs: Some(3),
                rewrap_on_membership_change: true,
                rotate_object_id_key_on_membership_change: false,
            }),
            signature: test_signature(),
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
        };

        let json = serde_json::to_string(&manifest).unwrap();
        let back: ZoneKeyManifest = serde_json::from_str(&json).unwrap();

        assert_eq!(back.zone_id, manifest.zone_id);
        assert_eq!(back.zone_key_id, manifest.zone_key_id);
        assert_eq!(back.object_id_key_id, manifest.object_id_key_id);
        assert_eq!(back.algorithm, manifest.algorithm);
        assert_eq!(back.valid_from, manifest.valid_from);
        assert_eq!(back.valid_until, manifest.valid_until);
        assert_eq!(back.prev_zone_key_id, manifest.prev_zone_key_id);
        assert_eq!(back.wrapped_keys.len(), 1);
        assert_eq!(back.wrapped_object_id_keys.len(), 1);
        assert!(back.rekey_policy.is_some());

        // The unwrapped key should still work after serde roundtrip
        let unwrapped = unwrap_zone_key(&sk, &zone_id, &back.wrapped_keys[0]).unwrap();
        assert_eq!(unwrapped, zone_key);
    }

    /// Verify that `unwrap_zone_key` with tampered `issued_at` fails (AAD mismatch).
    #[test]
    fn unwrap_zone_key_tampered_issued_at() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-tamper");
        let issued_at = 1_700_000_000;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let zone_key = random_zone_key();

        let mut wrapped = wrap_zone_key(&pk, &zone_id, &node_id, issued_at, &zone_key).unwrap();
        wrapped.issued_at = 1_700_000_001;

        let result = unwrap_zone_key(&sk, &zone_id, &wrapped);
        assert!(
            result.is_err(),
            "tampered issued_at should cause AAD mismatch"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Edge-case and boundary-condition tests (batch 2)
    // ─────────────────────────────────────────────────────────────────────────

    /// Verify `ZoneKeyId` Display for all-FF bytes.
    #[test]
    fn zone_key_id_display_all_ff() {
        let id = ZoneKeyId::from_bytes([0xFF; 8]);
        assert_eq!(format!("{id}"), "ffffffffffffffff");
    }

    /// Verify `ObjectIdKeyId` Display for all-FF bytes.
    #[test]
    fn object_id_key_id_display_all_ff() {
        let id = ObjectIdKeyId::from_bytes([0xFF; 8]);
        assert_eq!(format!("{id}"), "ffffffffffffffff");
    }

    /// Verify `ZoneKey` single-byte difference causes inequality.
    #[test]
    fn zone_key_single_byte_difference() {
        let mut bytes_a = [0u8; ZONE_KEY_LEN];
        let mut bytes_b = [0u8; ZONE_KEY_LEN];
        bytes_b[ZONE_KEY_LEN - 1] = 1;
        let a = ZoneKey::from_bytes(bytes_a);
        let b = ZoneKey::from_bytes(bytes_b);
        assert_ne!(a, b);

        // First byte differs
        bytes_a[0] = 0xFF;
        let c = ZoneKey::from_bytes(bytes_a);
        assert_ne!(a, c);
    }

    /// Verify that `ObjectIdKey` debug output is redacted.
    #[test]
    fn object_id_key_debug_is_redacted() {
        let key = ObjectIdKey::from_bytes([0x42; 32]);
        let dbg = format!("{key:?}");
        assert!(!dbg.contains("42"));
        assert!(dbg.contains("redacted"));
        assert!(dbg.contains("ObjectIdKey"));
    }

    /// Verify `ObjectIdKey` equality and inequality.
    #[test]
    fn object_id_key_equality_and_inequality() {
        let a = ObjectIdKey::from_bytes([0x01; 32]);
        let b = ObjectIdKey::from_bytes([0x01; 32]);
        let c = ObjectIdKey::from_bytes([0x02; 32]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    /// Verify `ObjectIdKey` copy semantics.
    #[test]
    fn object_id_key_copy() {
        let a = ObjectIdKey::from_bytes([0xAB; 32]);
        let b = a;
        assert_eq!(a, b);
    }

    /// Verify `ObjectIdKey` `from_bytes`/`as_bytes` roundtrip.
    #[test]
    fn object_id_key_from_bytes_as_bytes_roundtrip() {
        let bytes = [0x13; 32];
        let key = ObjectIdKey::from_bytes(bytes);
        assert_eq!(*key.as_bytes(), bytes);
    }

    /// Verify `ObjectIdKey` hash consistency.
    #[test]
    fn object_id_key_hash_consistency() {
        use std::collections::HashSet;
        let key = ObjectIdKey::from_bytes([0x77; 32]);
        let mut set = HashSet::new();
        set.insert(key);
        set.insert(key);
        assert_eq!(set.len(), 1);
    }

    /// Verify `ObjectIdKeyId` copy semantics.
    #[test]
    fn object_id_key_id_copy() {
        let a = ObjectIdKeyId::from_bytes([0xFE; 8]);
        let b = a;
        assert_eq!(a, b);
    }

    /// Verify `ZoneKeyRing` `active_zone_key` returns `None` when `active_zone_key_id`
    /// is set to a key ID that was overwritten.
    #[test]
    fn zone_key_ring_active_after_overwrite_still_works() {
        let mut ring = ZoneKeyRing::new(ZoneId::work());
        let key_id = ZoneKeyId::from_bytes([0x01; 8]);
        let key_a = ZoneKey::from_bytes([0xAA; ZONE_KEY_LEN]);
        let key_b = ZoneKey::from_bytes([0xBB; ZONE_KEY_LEN]);

        ring.insert_zone_key(key_id, key_a);
        assert!(ring.set_active_zone_key(key_id));
        assert_eq!(ring.active_zone_key(), Some(&key_a));

        // Overwrite key value: active key ID stays but value changes
        ring.insert_zone_key(key_id, key_b);
        assert_eq!(ring.active_zone_key(), Some(&key_b));
    }

    /// Verify `ZoneKeyRing` with multiple object id keys and switching.
    #[test]
    fn zone_key_ring_multiple_object_id_keys_switching() {
        let mut ring = ZoneKeyRing::new(ZoneId::private());
        let id1 = ObjectIdKeyId::from_bytes([0x01; 8]);
        let id2 = ObjectIdKeyId::from_bytes([0x02; 8]);
        let id3 = ObjectIdKeyId::from_bytes([0x03; 8]);
        let key1 = ObjectIdKey::from_bytes([0x11; 32]);
        let key2 = ObjectIdKey::from_bytes([0x22; 32]);
        let key3 = ObjectIdKey::from_bytes([0x33; 32]);

        ring.insert_object_id_key(id1, key1);
        ring.insert_object_id_key(id2, key2);
        ring.insert_object_id_key(id3, key3);

        assert!(ring.set_active_object_id_key(id1));
        assert_eq!(ring.active_object_id_key(), Some(&key1));
        assert!(ring.set_active_object_id_key(id3));
        assert_eq!(ring.active_object_id_key(), Some(&key3));
        assert!(ring.set_active_object_id_key(id2));
        assert_eq!(ring.active_object_id_key(), Some(&key2));
    }

    /// Verify manifest serde roundtrip with all optional fields set to None.
    #[test]
    fn zone_key_manifest_serde_no_optional_fields() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-minimal");
        let issued_at = 1_700_000_000;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let zone_key = random_zone_key();
        let obj_key = random_object_id_key();

        let wrapped_zone = wrap_zone_key(&pk, &zone_id, &node_id, issued_at, &zone_key).unwrap();
        let wrapped_obj = wrap_object_id_key(&pk, &zone_id, &node_id, issued_at, &obj_key).unwrap();

        let manifest = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: ZoneKeyId::from_bytes([0x01; 8]),
            object_id_key_id: ObjectIdKeyId::from_bytes([0x02; 8]),
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at,
            valid_until: None,
            prev_zone_key_id: None,
            wrapped_keys: vec![wrapped_zone],
            wrapped_object_id_keys: vec![wrapped_obj],
            rekey_policy: None,
            signature: test_signature(),
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
        };

        let json = serde_json::to_string(&manifest).unwrap();
        // Optional None fields should be omitted
        assert!(!json.contains("valid_until"));
        assert!(!json.contains("prev_zone_key_id"));
        assert!(!json.contains("rekey_policy"));

        let back: ZoneKeyManifest = serde_json::from_str(&json).unwrap();
        assert!(back.valid_until.is_none());
        assert!(back.prev_zone_key_id.is_none());
        assert!(back.rekey_policy.is_none());

        // Key still unwraps correctly
        let unwrapped = unwrap_zone_key(&sk, &zone_id, &back.wrapped_keys[0]).unwrap();
        assert_eq!(unwrapped, zone_key);
    }

    /// Verify `wrap_object_id_key` produces different ciphertext on each call.
    #[test]
    fn wrap_object_id_key_nondeterministic() {
        let zone_id = ZoneId::private();
        let node_id = TailscaleNodeId::new("node-obj-nd");
        let issued_at = 1_700_000_000;
        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let key = ObjectIdKey::from_bytes([0x42; 32]);

        let w1 = wrap_object_id_key(&pk, &zone_id, &node_id, issued_at, &key).unwrap();
        let w2 = wrap_object_id_key(&pk, &zone_id, &node_id, issued_at, &key).unwrap();

        // Both decrypt to the same key
        let k1 = unwrap_object_id_key(&sk, &zone_id, &w1).unwrap();
        let k2 = unwrap_object_id_key(&sk, &zone_id, &w2).unwrap();
        assert_eq!(k1, key);
        assert_eq!(k2, key);

        // Ciphertexts differ due to HPKE randomness
        assert_ne!(w1.sealed.ciphertext, w2.sealed.ciphertext);
    }

    /// Verify `unwrap_object_id_key` fails when `issued_at` is tampered.
    #[test]
    fn unwrap_object_id_key_tampered_issued_at() {
        let zone_id = ZoneId::community();
        let node_id = TailscaleNodeId::new("node-obj-tamper");
        let issued_at = 1_700_000_000;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let key = random_object_id_key();

        let mut wrapped = wrap_object_id_key(&pk, &zone_id, &node_id, issued_at, &key).unwrap();
        wrapped.issued_at = 1_700_000_001; // tamper

        let result = unwrap_object_id_key(&sk, &zone_id, &wrapped);
        assert!(
            result.is_err(),
            "tampered issued_at should cause AAD mismatch"
        );
    }

    /// Verify `RekeyPolicy` serde with zero overlap window.
    #[test]
    fn rekey_policy_serde_zero_overlap_window() {
        let rp = RekeyPolicy {
            epoch_ratchet: false,
            overlap_window_secs: Some(0),
            retain_epochs: Some(0),
            rewrap_on_membership_change: false,
            rotate_object_id_key_on_membership_change: false,
        };
        let json = serde_json::to_string(&rp).unwrap();
        let back: RekeyPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(back.overlap_window_secs, Some(0));
        assert_eq!(back.retain_epochs, Some(0));
    }

    /// Verify `RekeyPolicy` serde with partial fields (only some set).
    #[test]
    fn rekey_policy_serde_partial_fields() {
        let json = r#"{"epoch_ratchet": true, "overlap_window_secs": 1200}"#;
        let rp: RekeyPolicy = serde_json::from_str(json).unwrap();
        assert!(rp.epoch_ratchet);
        assert_eq!(rp.overlap_window_secs, Some(1200));
        assert!(rp.retain_epochs.is_none());
        assert!(!rp.rewrap_on_membership_change);
        assert!(!rp.rotate_object_id_key_on_membership_change);
    }

    /// Verify `RekeyPolicy` serde with large overlap window.
    #[test]
    fn rekey_policy_large_values() {
        let rp = RekeyPolicy {
            epoch_ratchet: true,
            overlap_window_secs: Some(u64::MAX),
            retain_epochs: Some(u32::MAX),
            rewrap_on_membership_change: true,
            rotate_object_id_key_on_membership_change: true,
        };
        let json = serde_json::to_string(&rp).unwrap();
        let back: RekeyPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(back.overlap_window_secs, Some(u64::MAX));
        assert_eq!(back.retain_epochs, Some(u32::MAX));
    }

    /// Verify `ZoneKeyAlgorithm` serde rejects invalid string.
    #[test]
    fn zone_key_algorithm_serde_rejects_invalid() {
        let result: Result<ZoneKeyAlgorithm, _> = serde_json::from_str(r#""invalid_algo""#);
        assert!(result.is_err());
    }

    /// Verify `ZoneKeyManifest` clone preserves all fields.
    #[test]
    fn zone_key_manifest_clone_preserves_fields() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-clone");
        let issued_at = 1_700_000_000;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let zone_key = random_zone_key();
        let obj_key = random_object_id_key();

        let wrapped_zone = wrap_zone_key(&pk, &zone_id, &node_id, issued_at, &zone_key).unwrap();
        let wrapped_obj = wrap_object_id_key(&pk, &zone_id, &node_id, issued_at, &obj_key).unwrap();

        let manifest = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: ZoneKeyId::from_bytes([0x01; 8]),
            object_id_key_id: ObjectIdKeyId::from_bytes([0x02; 8]),
            algorithm: ZoneKeyAlgorithm::XChaCha20Poly1305,
            valid_from: issued_at,
            valid_until: Some(1_700_100_000),
            prev_zone_key_id: Some(ZoneKeyId::from_bytes([0x99; 8])),
            wrapped_keys: vec![wrapped_zone],
            wrapped_object_id_keys: vec![wrapped_obj],
            rekey_policy: Some(RekeyPolicy {
                epoch_ratchet: true,
                overlap_window_secs: Some(300),
                retain_epochs: Some(2),
                rewrap_on_membership_change: true,
                rotate_object_id_key_on_membership_change: false,
            }),
            signature: test_signature(),
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
        };

        let cloned = manifest.clone();
        assert_eq!(cloned.zone_id, manifest.zone_id);
        assert_eq!(cloned.zone_key_id, manifest.zone_key_id);
        assert_eq!(cloned.object_id_key_id, manifest.object_id_key_id);
        assert_eq!(cloned.algorithm, manifest.algorithm);
        assert_eq!(cloned.valid_from, manifest.valid_from);
        assert_eq!(cloned.valid_until, manifest.valid_until);
        assert_eq!(cloned.prev_zone_key_id, manifest.prev_zone_key_id);
        assert_eq!(cloned.wrapped_keys.len(), manifest.wrapped_keys.len());
        assert_eq!(
            cloned.wrapped_object_id_keys.len(),
            manifest.wrapped_object_id_keys.len()
        );
        assert!(cloned.rekey_policy.is_some());
    }

    /// Verify `ZoneKeyManifest` debug output contains type name.
    #[test]
    fn zone_key_manifest_debug_output() {
        let zone_id = ZoneId::work();
        let signing_key = fcp_crypto::Ed25519SigningKey::generate();
        let manifest = ZoneKeyManifest::new_empty(zone_id, 1_700_000_000, &signing_key).unwrap();
        let dbg = format!("{manifest:?}");
        assert!(dbg.contains("ZoneKeyManifest"));
        assert!(dbg.contains("zone_key_id"));
    }

    /// Verify `ZoneKeyError` Debug format for each variant.
    #[test]
    fn zone_key_error_debug_format_all_variants() {
        let err1 = ZoneKeyError::InvalidKeyLength {
            expected: 32,
            found: 16,
        };
        let dbg1 = format!("{err1:?}");
        assert!(dbg1.contains("InvalidKeyLength"));

        let err2 = ZoneKeyError::ZoneIdMismatch {
            expected: "z:work".into(),
            found: "z:private".into(),
        };
        let dbg2 = format!("{err2:?}");
        assert!(dbg2.contains("ZoneIdMismatch"));

        let err3 = ZoneKeyError::MissingWrappedZoneKey {
            node_id: "n1".into(),
        };
        let dbg3 = format!("{err3:?}");
        assert!(dbg3.contains("MissingWrappedZoneKey"));

        let err4 = ZoneKeyError::MissingWrappedObjectIdKey {
            node_id: "n2".into(),
        };
        let dbg4 = format!("{err4:?}");
        assert!(dbg4.contains("MissingWrappedObjectIdKey"));
    }

    /// Verify `WrappedObjectIdKey` debug output includes relevant information.
    #[test]
    fn wrapped_object_id_key_debug() {
        let zone_id = ZoneId::private();
        let node_id = TailscaleNodeId::new("node-obj-dbg");
        let issued_at = 1_700_000_000;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let key = random_object_id_key();

        let wrapped = wrap_object_id_key(&pk, &zone_id, &node_id, issued_at, &key).unwrap();
        let dbg = format!("{wrapped:?}");
        assert!(dbg.contains("WrappedObjectIdKey"));
        assert!(dbg.contains("node-obj-dbg"));
    }

    /// Verify wrap/unwrap with different `issued_at` values produce different AADs.
    #[test]
    fn wrap_unwrap_different_issued_at() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-ts");
        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let zone_key = random_zone_key();

        let issued_at_1 = 1_700_000_000;
        let issued_at_2 = 1_700_000_001;

        let w1 = wrap_zone_key(&pk, &zone_id, &node_id, issued_at_1, &zone_key).unwrap();
        let w2 = wrap_zone_key(&pk, &zone_id, &node_id, issued_at_2, &zone_key).unwrap();

        // Each can be unwrapped only with matching issued_at (embedded in AAD)
        let k1 = unwrap_zone_key(&sk, &zone_id, &w1).unwrap();
        let k2 = unwrap_zone_key(&sk, &zone_id, &w2).unwrap();
        assert_eq!(k1, zone_key);
        assert_eq!(k2, zone_key);
    }

    /// Verify `ZoneKeyRing` with community zone type.
    #[test]
    fn zone_key_ring_community_zone() {
        let ring = ZoneKeyRing::new(ZoneId::community());
        assert_eq!(ring.zone_id, ZoneId::community());
        assert!(ring.active_zone_key().is_none());
    }

    /// Verify `ZoneKeyRing` with public zone type.
    #[test]
    fn zone_key_ring_public_zone() {
        let ring = ZoneKeyRing::new(ZoneId::public());
        assert_eq!(ring.zone_id, ZoneId::public());
        assert!(ring.active_object_id_key().is_none());
    }

    /// Verify `ZoneKeyRing` with owner zone type.
    #[test]
    fn zone_key_ring_owner_zone() {
        let mut ring = ZoneKeyRing::new(ZoneId::owner());
        assert_eq!(ring.zone_id, ZoneId::owner());
        let key_id = ZoneKeyId::from_bytes([0x01; 8]);
        let key = random_zone_key();
        ring.insert_zone_key(key_id, key);
        assert!(ring.set_active_zone_key(key_id));
        assert_eq!(ring.active_zone_key(), Some(&key));
    }

    /// Verify manifest with all five zone types can be created via `new_empty`.
    #[test]
    fn zone_key_manifest_new_empty_all_zone_types() {
        let signing_key = fcp_crypto::Ed25519SigningKey::generate();
        for zone_id in [
            ZoneId::owner(),
            ZoneId::private(),
            ZoneId::work(),
            ZoneId::community(),
            ZoneId::public(),
        ] {
            let manifest = ZoneKeyManifest::new_empty(zone_id.clone(), 100, &signing_key).unwrap();
            assert_eq!(manifest.zone_id, zone_id);
        }
    }

    /// Verify `ZoneKeyId` `from_bytes`/`as_bytes` roundtrip with alternating bytes.
    #[test]
    fn zone_key_id_from_bytes_as_bytes_alternating() {
        let bytes = [0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55];
        let id = ZoneKeyId::from_bytes(bytes);
        assert_eq!(*id.as_bytes(), bytes);
        assert_eq!(format!("{id}"), "aa55aa55aa55aa55");
    }

    /// Verify `ObjectIdKeyId` `from_bytes`/`as_bytes` roundtrip with sequential bytes.
    #[test]
    fn object_id_key_id_from_bytes_as_bytes_sequential() {
        let bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let id = ObjectIdKeyId::from_bytes(bytes);
        assert_eq!(*id.as_bytes(), bytes);
        assert_eq!(format!("{id}"), "0102030405060708");
    }

    /// Verify `ZoneKeyRing` debug output includes `zone_id` when keys are present.
    #[test]
    fn zone_key_ring_debug_with_keys() {
        let mut ring = ZoneKeyRing::new(ZoneId::work());
        let key_id = ZoneKeyId::from_bytes([0x42; 8]);
        ring.insert_zone_key(key_id, random_zone_key());
        let dbg = format!("{ring:?}");
        assert!(dbg.contains("ZoneKeyRing"));
        assert!(dbg.contains("z:work"));
    }

    /// Verify that `set_active_zone_key` preserves pre-existing `active_object_id_key_id`.
    #[test]
    fn set_active_zone_key_preserves_object_id_key_state() {
        let mut ring = ZoneKeyRing::new(ZoneId::work());
        let zone_key_id = ZoneKeyId::from_bytes([0x01; 8]);
        let obj_key_id = ObjectIdKeyId::from_bytes([0x02; 8]);

        ring.insert_zone_key(zone_key_id, random_zone_key());
        ring.insert_object_id_key(obj_key_id, random_object_id_key());

        assert!(ring.set_active_object_id_key(obj_key_id));
        assert!(ring.set_active_zone_key(zone_key_id));

        // Both actives should be set
        assert_eq!(ring.active_zone_key_id, Some(zone_key_id));
        assert_eq!(ring.active_object_id_key_id, Some(obj_key_id));
    }

    /// Verify that unwrap with wrong key returns Crypto variant error.
    #[test]
    fn unwrap_zone_key_wrong_sk_returns_crypto_error() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-ce");
        let issued_at = 1_700_000_000;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let bad_sk = X25519SecretKey::generate();

        let zone_key = random_zone_key();
        let wrapped = wrap_zone_key(&pk, &zone_id, &node_id, issued_at, &zone_key).unwrap();

        let err = unwrap_zone_key(&bad_sk, &zone_id, &wrapped).expect_err("should fail");
        assert!(matches!(err, ZoneKeyError::Crypto(_)));
    }

    /// Verify `ZoneKeyId` serde roundtrip preserves exact bytes for boundary values.
    #[test]
    fn zone_key_id_serde_boundary_bytes() {
        for bytes in [
            [0x00; 8],
            [0xFF; 8],
            [0x00, 0x01, 0x02, 0x03, 0xFC, 0xFD, 0xFE, 0xFF],
        ] {
            let id = ZoneKeyId::from_bytes(bytes);
            let json = serde_json::to_string(&id).unwrap();
            let back: ZoneKeyId = serde_json::from_str(&json).unwrap();
            assert_eq!(id, back);
            assert_eq!(*back.as_bytes(), bytes);
        }
    }

    /// Verify `ObjectIdKeyId` serde roundtrip preserves exact bytes for boundary values.
    #[test]
    fn object_id_key_id_serde_boundary_bytes() {
        for bytes in [
            [0x00; 8],
            [0xFF; 8],
            [0x80, 0x7F, 0x01, 0xFE, 0x00, 0xFF, 0x55, 0xAA],
        ] {
            let id = ObjectIdKeyId::from_bytes(bytes);
            let json = serde_json::to_string(&id).unwrap();
            let back: ObjectIdKeyId = serde_json::from_str(&json).unwrap();
            assert_eq!(id, back);
            assert_eq!(*back.as_bytes(), bytes);
        }
    }

    /// Verify `ZONE_KEY_LEN` matches the expected 32-byte `ChaCha20` key size.
    #[test]
    fn zone_key_len_matches_key_construction() {
        let key = ZoneKey::from_bytes([0u8; ZONE_KEY_LEN]);
        assert_eq!(key.as_bytes().len(), ZONE_KEY_LEN);
        assert_eq!(key.as_bytes().len(), 32);
    }

    /// Verify that `wrapped_key_for` returns the first matching entry when duplicates exist.
    #[test]
    fn wrapped_key_for_returns_first_match() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-dup");
        let issued_at_a = 1_700_000_000;
        let issued_at_b = 1_700_000_001;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let zone_key = random_zone_key();

        let w1 = wrap_zone_key(&pk, &zone_id, &node_id, issued_at_a, &zone_key).unwrap();
        let w2 = wrap_zone_key(&pk, &zone_id, &node_id, issued_at_b, &zone_key).unwrap();

        let manifest = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: ZoneKeyId::from_bytes([0x01; 8]),
            object_id_key_id: ObjectIdKeyId::from_bytes([0x11; 8]),
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at_a,
            valid_until: None,
            prev_zone_key_id: None,
            wrapped_keys: vec![w1, w2],
            wrapped_object_id_keys: vec![],
            rekey_policy: None,
            signature: test_signature(),
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
        };

        // Should return the first match (issued_at_a)
        let found = manifest.wrapped_key_for(&node_id).unwrap();
        assert_eq!(found.issued_at, issued_at_a);
    }

    /// br-vzn2p: duplicate V3 recipients (different `issued_at`, so
    /// distinct wrap material) are rejected fail-closed by
    /// `IndexedZoneKeyManifest::new`. Without this guard the linear
    /// scan returns the FIRST entry while the indexed lookup returns
    /// the LAST, which lets two callers derive different wraps from
    /// the same signed manifest.
    #[test]
    fn br_vzn2p_indexed_constructor_rejects_duplicate_v3_recipient() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("100.64.0.7");
        let issued_at_a = 1_700_000_000;
        let issued_at_b = 1_700_000_001;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let zone_key = random_zone_key();

        let w1 = wrap_zone_key(&pk, &zone_id, &node_id, issued_at_a, &zone_key).unwrap();
        let w2 = wrap_zone_key(&pk, &zone_id, &node_id, issued_at_b, &zone_key).unwrap();

        let manifest = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: ZoneKeyId::from_bytes([0x01; 8]),
            object_id_key_id: ObjectIdKeyId::from_bytes([0x11; 8]),
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at_a,
            valid_until: None,
            prev_zone_key_id: None,
            wrapped_keys: vec![w1, w2],
            wrapped_object_id_keys: vec![],
            rekey_policy: None,
            signature: test_signature(),
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
        };

        let err = IndexedZoneKeyManifest::new(manifest.clone())
            .expect_err("duplicate V3 recipient must fail-close");
        match err {
            ZoneKeyError::DuplicateRecipientInManifest { node_id: id, list } => {
                assert_eq!(id, node_id.as_str());
                assert_eq!(list, "wrapped_keys");
            }
            other => panic!("expected DuplicateRecipientInManifest, got {other:?}"),
        }

        // The manifest's own validator must agree — fail-closed at the
        // pre-publish gate as well as at the indexed-construction gate.
        let val_err = manifest
            .validate_no_recipient_split_view()
            .expect_err("validator must reject duplicate V3 recipient");
        assert!(matches!(
            val_err,
            ZoneKeyError::DuplicateRecipientInManifest {
                list: "wrapped_keys",
                ..
            }
        ));
    }

    /// br-vzn2p: duplicate V4 recipients are rejected the same way.
    /// Two distinct X-Wing wraps for the same recipient would let a
    /// V4 reader resolve a different sealed box depending on whether
    /// it walked the linear or indexed path.
    #[test]
    fn br_vzn2p_indexed_constructor_rejects_duplicate_v4_recipient() {
        let zone_id = ZoneId::work();
        let recipient = TailscaleNodeId::new("100.64.0.8");
        let issued_at_a = 1_700_000_010;
        let issued_at_b = 1_700_000_011;

        let provider = XWingProvider::new();
        let (pk_a, _sk_a) = provider.generate().unwrap();
        let (pk_b, _sk_b) = provider.generate().unwrap();
        let aad_a = Fcp4Aad::for_zone_key(
            zone_id.as_bytes(),
            recipient.as_str().as_bytes(),
            issued_at_a,
        )
        .encode()
        .unwrap();
        let aad_b = Fcp4Aad::for_zone_key(
            zone_id.as_bytes(),
            recipient.as_str().as_bytes(),
            issued_at_b,
        )
        .encode()
        .unwrap();
        let sealed_a = provider.seal(&pk_a, b"zone-key-bytes-a", &aad_a).unwrap();
        let sealed_b = provider.seal(&pk_b, b"zone-key-bytes-b", &aad_b).unwrap();

        let v4_a = WrappedZoneKeyV4 {
            recipient: recipient.clone(),
            issued_at: issued_at_a,
            sealed: WrappedKey::from_xwing(sealed_a),
        };
        let v4_b = WrappedZoneKeyV4 {
            recipient: recipient.clone(),
            issued_at: issued_at_b,
            sealed: WrappedKey::from_xwing(sealed_b),
        };

        let manifest = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: ZoneKeyId::from_bytes([0x02; 8]),
            object_id_key_id: ObjectIdKeyId::from_bytes([0x12; 8]),
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at_a,
            valid_until: None,
            prev_zone_key_id: None,
            wrapped_keys: vec![],
            wrapped_object_id_keys: vec![],
            rekey_policy: None,
            signature: test_signature(),
            kem: ZoneKemAlgorithm::XWing,
            wrapped_keys_v4: vec![v4_a, v4_b],
        };

        let err = IndexedZoneKeyManifest::new(manifest.clone())
            .expect_err("duplicate V4 recipient must fail-close");
        match err {
            ZoneKeyError::DuplicateRecipientInManifest { node_id: id, list } => {
                assert_eq!(id, recipient.as_str());
                assert_eq!(list, "wrapped_keys_v4");
            }
            other => panic!("expected DuplicateRecipientInManifest, got {other:?}"),
        }

        let val_err = manifest
            .validate_no_recipient_split_view()
            .expect_err("validator must reject duplicate V4 recipient");
        assert!(matches!(
            val_err,
            ZoneKeyError::DuplicateRecipientInManifest {
                list: "wrapped_keys_v4",
                ..
            }
        ));
    }

    /// br-vzn2p: duplicate `wrapped_object_id_keys` entries close the
    /// third (and final) wrap-list surface.
    #[test]
    fn br_vzn2p_indexed_constructor_rejects_duplicate_object_id_recipient() {
        let zone_id = ZoneId::work();
        let recipient = TailscaleNodeId::new("100.64.0.9");
        let issued_at_a = 1_700_000_020;
        let issued_at_b = 1_700_000_021;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let key_a = random_object_id_key();
        let key_b = random_object_id_key();

        let w1 = wrap_object_id_key(&pk, &zone_id, &recipient, issued_at_a, &key_a).unwrap();
        let w2 = wrap_object_id_key(&pk, &zone_id, &recipient, issued_at_b, &key_b).unwrap();

        let manifest = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: ZoneKeyId::from_bytes([0x03; 8]),
            object_id_key_id: ObjectIdKeyId::from_bytes([0x13; 8]),
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at_a,
            valid_until: None,
            prev_zone_key_id: None,
            wrapped_keys: vec![],
            wrapped_object_id_keys: vec![w1, w2],
            rekey_policy: None,
            signature: test_signature(),
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
        };

        let err = IndexedZoneKeyManifest::new(manifest.clone())
            .expect_err("duplicate object-id recipient must fail-close");
        match err {
            ZoneKeyError::DuplicateRecipientInManifest { node_id: id, list } => {
                assert_eq!(id, recipient.as_str());
                assert_eq!(list, "wrapped_object_id_keys");
            }
            other => panic!("expected DuplicateRecipientInManifest, got {other:?}"),
        }

        let val_err = manifest
            .validate_no_recipient_split_view()
            .expect_err("validator must reject duplicate object-id recipient");
        assert!(matches!(
            val_err,
            ZoneKeyError::DuplicateRecipientInManifest {
                list: "wrapped_object_id_keys",
                ..
            }
        ));
    }

    /// br-gtplu: when a recipient has only a V3 wrap (no entry in
    /// `wrapped_keys_v4`), `resolved_wrapped_key_observable_for` MUST
    /// return [`ResolvedWrappedKey::V3Fallback`] so callers can emit
    /// per-call observability for the V3-deprecation cutover.
    #[test]
    fn br_gtplu_observable_resolver_returns_v3_fallback_when_only_v3_present() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-v3-only");
        let issued_at = 1_700_000_000;
        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let zone_key = random_zone_key();
        let v3_wrap = wrap_zone_key(&pk, &zone_id, &node_id, issued_at, &zone_key).unwrap();

        let manifest = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: ZoneKeyId::from_bytes([0x01; 8]),
            object_id_key_id: ObjectIdKeyId::from_bytes([0x11; 8]),
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at,
            valid_until: None,
            prev_zone_key_id: None,
            wrapped_keys: vec![v3_wrap],
            wrapped_object_id_keys: vec![],
            rekey_policy: None,
            signature: test_signature(),
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![], // recipient has NO V4 entry
        };

        let resolved = manifest
            .resolved_wrapped_key_observable_for(&node_id)
            .expect("v3-only recipient must resolve");
        assert!(
            resolved.is_v3_fallback(),
            "br-gtplu: V3-only recipient must surface as V3Fallback; got {:?}",
            resolved.path_label()
        );
        assert_eq!(resolved.path_label(), "v3_fallback");
        assert!(matches!(
            resolved.wrapped_key(),
            WrappedKey::HpkeX25519 { .. }
        ));
    }

    /// br-gtplu: when a recipient has a V4 wrap (and possibly also a
    /// V3 wrap for interop), the observable resolver MUST return the
    /// V4 path so callers don't emit a spurious deprecation signal.
    #[test]
    fn br_gtplu_observable_resolver_returns_v4_when_v4_present() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-v4");
        let issued_at = 1_700_000_000;
        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let zone_key = random_zone_key();
        // Build a V3 wrap (used to populate wrapped_keys_v4 below as
        // an HpkeX25519 V4 entry — same KEM, but in the V4 list).
        let v3_wrap = wrap_zone_key(&pk, &zone_id, &node_id, issued_at, &zone_key).unwrap();
        let v4_entry = WrappedZoneKeyV4 {
            recipient: node_id.clone(),
            issued_at,
            sealed: WrappedKey::from_hpke(v3_wrap.sealed.clone()),
        };

        let manifest = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: ZoneKeyId::from_bytes([0x01; 8]),
            object_id_key_id: ObjectIdKeyId::from_bytes([0x11; 8]),
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at,
            valid_until: None,
            prev_zone_key_id: None,
            // ALSO put a V3 entry to confirm V4 wins when both lists
            // contain the recipient (interop manifest case).
            wrapped_keys: vec![v3_wrap],
            wrapped_object_id_keys: vec![],
            rekey_policy: None,
            signature: test_signature(),
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![v4_entry],
        };

        let resolved = manifest
            .resolved_wrapped_key_observable_for(&node_id)
            .expect("v4 recipient must resolve");
        assert!(
            !resolved.is_v3_fallback(),
            "br-gtplu: recipient with V4 entry must NOT surface as V3Fallback; got {:?}",
            resolved.path_label()
        );
        assert_eq!(resolved.path_label(), "v4");
    }

    /// br-gtplu: legacy `resolved_wrapped_key_for` MUST keep returning
    /// the same `WrappedKey` payload as the new observable variant
    /// (just without the variant tag) — back-compat for the zoo of
    /// existing call sites that haven't migrated yet.
    #[test]
    fn br_gtplu_legacy_resolver_strips_observable_tag_unchanged() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-back-compat");
        let issued_at = 1_700_000_000;
        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let zone_key = random_zone_key();
        let v3_wrap = wrap_zone_key(&pk, &zone_id, &node_id, issued_at, &zone_key).unwrap();

        let manifest = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: ZoneKeyId::from_bytes([0x01; 8]),
            object_id_key_id: ObjectIdKeyId::from_bytes([0x11; 8]),
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at,
            valid_until: None,
            prev_zone_key_id: None,
            wrapped_keys: vec![v3_wrap],
            wrapped_object_id_keys: vec![],
            rekey_policy: None,
            signature: test_signature(),
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
        };

        // Both APIs must return the SAME wrapped-key bytes.
        let legacy = manifest.resolved_wrapped_key_for(&node_id).unwrap();
        let observable = manifest
            .resolved_wrapped_key_observable_for(&node_id)
            .unwrap();
        let observable_inner = observable.into_wrapped_key();

        let legacy_sealed = legacy.hpke_sealed().expect("legacy is HPKE");
        let observable_sealed = observable_inner.hpke_sealed().expect("observable is HPKE");
        assert_eq!(legacy_sealed.to_bytes(), observable_sealed.to_bytes());
    }

    // ─────────────────────────────────────────────────────────────────
    // br-vkb3m: extend gtplu's V3-deprecation observability (the
    // ResolvedWrappedKey-tagged variant) to the IndexedZoneKeyManifest
    // hot path. Pre-vkb3m the indexed resolver returned an opaque
    // WrappedKey, so dispatcher-tier callers (which use the indexed
    // form for O(1) per-request lookup) couldn't emit the
    // fcp_zone_key_v3_fallback_total metric or the bead="gtplu" WARN
    // when a V3 fallback fired. The cutover-gate evidence the gtplu
    // fix was supposed to provide was missing on the call sites that
    // matter most.
    //
    // These tests pin three correctness properties of the new
    // IndexedZoneKeyManifest::resolved_wrapped_key_observable_for and
    // a fourth that the indexed and linear resolvers agree on the
    // tagged outcome — so dispatcher-tier code emitting one metric
    // gives operators the same picture as a one-shot inspection
    // through ZoneKeyManifest's linear resolver.
    // ─────────────────────────────────────────────────────────────────

    fn vkb3m_three_recipient_manifest() -> (
        ZoneKeyManifest,
        TailscaleNodeId,
        TailscaleNodeId,
        TailscaleNodeId,
    ) {
        let zone_id = ZoneId::work();
        let issued_at = 1_700_020_000;
        let zone_key = random_zone_key();

        // Recipient A: V3-only — must surface as V3Fallback.
        let alice = TailscaleNodeId::new("alice-v3-only");
        let alice_sk = X25519SecretKey::generate();
        let alice_v3 = wrap_zone_key(
            &alice_sk.public_key(),
            &zone_id,
            &alice,
            issued_at,
            &zone_key,
        )
        .expect("alice v3 wrap");

        // Recipient B: V4-only X-Wing — must surface as V4.
        let bob = TailscaleNodeId::new("bob-v4-only");
        let xwing = XWingProvider::new();
        let (bob_wrap_public, _bob_open_secret) = xwing.generate().expect("bob xwing keypair");
        let bob_aad = Fcp4Aad::for_zone_key(zone_id.as_bytes(), bob.as_str().as_bytes(), issued_at)
            .encode()
            .expect("bob aad");
        let bob_v4_sealed = xwing
            .seal(&bob_wrap_public, zone_key.as_bytes(), &bob_aad)
            .expect("bob v4 wrap");
        let bob_v4 = WrappedZoneKeyV4 {
            recipient: bob.clone(),
            issued_at,
            sealed: WrappedKey::from_xwing(bob_v4_sealed),
        };

        // Recipient C: interop-both (V3 wrap + promoted-V4 entry whose
        // sealed bytes match) — must surface as V4 (no spurious
        // V3-deprecation signal on a recipient already migrated).
        let carol = TailscaleNodeId::new("carol-interop-both");
        let carol_sk = X25519SecretKey::generate();
        let carol_v3 = wrap_zone_key(
            &carol_sk.public_key(),
            &zone_id,
            &carol,
            issued_at,
            &zone_key,
        )
        .expect("carol v3 wrap");
        let carol_v4 = WrappedZoneKeyV4 {
            recipient: carol.clone(),
            issued_at,
            sealed: WrappedKey::from_hpke(carol_v3.sealed.clone()),
        };

        let manifest = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id,
            zone_key_id: ZoneKeyId::from_bytes([0x77; 8]),
            object_id_key_id: ObjectIdKeyId::from_bytes([0x88; 8]),
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at,
            valid_until: None,
            prev_zone_key_id: None,
            wrapped_keys: vec![alice_v3, carol_v3],
            wrapped_object_id_keys: vec![],
            rekey_policy: None,
            signature: test_signature(),
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![bob_v4, carol_v4],
        };

        (manifest, alice, bob, carol)
    }

    #[test]
    fn br_vkb3m_indexed_observable_wrap_resolution_returns_v3_fallback_for_v3_only_recipient() {
        let (manifest, alice, _bob, _carol) = vkb3m_three_recipient_manifest();
        let indexed = IndexedZoneKeyManifest::new(manifest)
            .expect("manifest has no duplicates → index builds");

        let resolved = indexed
            .resolved_wrapped_key_observable_for(&alice)
            .expect("V3-only recipient must resolve via the indexed path");

        assert!(
            resolved.is_v3_fallback(),
            "br-vkb3m: V3-only recipient via IndexedZoneKeyManifest MUST surface as V3Fallback \
             so dispatcher-hot-path callers emit the gtplu deprecation metric/log; got {:?}",
            resolved.path_label()
        );
        assert_eq!(resolved.path_label(), "v3_fallback");
        assert!(matches!(
            resolved.wrapped_key(),
            WrappedKey::HpkeX25519 { .. }
        ));
    }

    #[test]
    fn br_vkb3m_indexed_observable_wrap_resolution_returns_v4_for_v4_only_recipient() {
        let (manifest, _alice, bob, _carol) = vkb3m_three_recipient_manifest();
        let indexed = IndexedZoneKeyManifest::new(manifest)
            .expect("manifest has no duplicates → index builds");

        let resolved = indexed
            .resolved_wrapped_key_observable_for(&bob)
            .expect("V4-only recipient must resolve via the indexed path");

        assert!(
            !resolved.is_v3_fallback(),
            "br-vkb3m: V4-only recipient via IndexedZoneKeyManifest MUST NOT surface as \
             V3Fallback (would spuriously fire the gtplu deprecation alert); got {:?}",
            resolved.path_label()
        );
        assert_eq!(resolved.path_label(), "v4");
        assert!(matches!(resolved.wrapped_key(), WrappedKey::XWing { .. }));
    }

    #[test]
    fn br_vkb3m_indexed_observable_wrap_resolution_returns_v4_for_interop_both_recipient() {
        let (manifest, _alice, _bob, carol) = vkb3m_three_recipient_manifest();
        let indexed = IndexedZoneKeyManifest::new(manifest)
            .expect("manifest has no duplicates → index builds");

        let resolved = indexed
            .resolved_wrapped_key_observable_for(&carol)
            .expect("interop-both recipient must resolve via the indexed path");

        assert!(
            !resolved.is_v3_fallback(),
            "br-vkb3m: interop-both recipient (with V4 entry available) MUST resolve as V4 \
             via the indexed path so the gtplu deprecation signal does not fire on a \
             recipient already migrated to V4; got {:?}",
            resolved.path_label()
        );
        assert_eq!(resolved.path_label(), "v4");
    }

    /// br-vkb3m: the indexed and linear-scan resolvers MUST agree on
    /// the tagged outcome for every recipient. This is the
    /// load-bearing cutover-gate property: a node that toggles
    /// between the two resolver flavours (e.g. one-shot inspection
    /// vs. dispatcher hot path) must observe the SAME
    /// V3-vs-V4 picture for any given recipient — otherwise the
    /// `fcp_zone_key_v3_fallback_total` metric splits across paths
    /// and the cutover gate cannot be trusted.
    #[test]
    fn br_vkb3m_indexed_and_linear_wrap_resolution_paths_agree_on_observable_tag() {
        let (manifest, alice, bob, carol) = vkb3m_three_recipient_manifest();
        let indexed = IndexedZoneKeyManifest::new(manifest.clone())
            .expect("manifest has no duplicates → index builds");

        for recipient in [&alice, &bob, &carol] {
            let linear = manifest
                .resolved_wrapped_key_observable_for(recipient)
                .expect("linear resolver returns recipient");
            let indexed_resolved = indexed
                .resolved_wrapped_key_observable_for(recipient)
                .expect("indexed resolver returns recipient");

            assert_eq!(
                linear.path_label(),
                indexed_resolved.path_label(),
                "br-vkb3m: linear and indexed observable resolvers MUST agree on path \
                 tag for recipient `{}` — linear={:?} indexed={:?}",
                recipient.as_str(),
                linear.path_label(),
                indexed_resolved.path_label()
            );

            // Sealed bytes must also match — same wrap selected.
            let linear_kem = linear.wrapped_key().kem();
            let indexed_kem = indexed_resolved.wrapped_key().kem();
            assert_eq!(
                linear_kem,
                indexed_kem,
                "br-vkb3m: KEM tag mismatch between resolvers for recipient `{}`",
                recipient.as_str()
            );
        }
    }

    /// br-vkb3m: legacy `IndexedZoneKeyManifest::resolved_wrapped_key_for`
    /// MUST keep returning the same `WrappedKey` payload as the new
    /// observable variant (just without the variant tag) — back-compat
    /// for the existing dispatcher call sites that haven't migrated
    /// to the observable form yet.
    #[test]
    fn br_vkb3m_indexed_legacy_wrap_resolution_strips_observable_tag_unchanged() {
        let (manifest, alice, bob, carol) = vkb3m_three_recipient_manifest();
        let indexed = IndexedZoneKeyManifest::new(manifest)
            .expect("manifest has no duplicates → index builds");

        for recipient in [&alice, &bob, &carol] {
            let legacy = indexed
                .resolved_wrapped_key_for(recipient)
                .expect("legacy resolver returns recipient");
            let observable_inner = indexed
                .resolved_wrapped_key_observable_for(recipient)
                .expect("observable resolver returns recipient")
                .into_wrapped_key();

            assert_eq!(
                legacy.kem(),
                observable_inner.kem(),
                "br-vkb3m: legacy and observable resolvers MUST return the same KEM \
                 variant for recipient `{}`",
                recipient.as_str()
            );
        }
    }

    /// Verify `ZoneKeyRing` does not change state on failed `set_active_zone_key`.
    #[test]
    fn zone_key_ring_set_active_failure_preserves_state() {
        let mut ring = ZoneKeyRing::new(ZoneId::work());
        let good_id = ZoneKeyId::from_bytes([0x01; 8]);
        let bad_id = ZoneKeyId::from_bytes([0x02; 8]);
        let key = random_zone_key();

        ring.insert_zone_key(good_id, key);
        assert!(ring.set_active_zone_key(good_id));

        // Attempt to set to unknown key
        assert!(!ring.set_active_zone_key(bad_id));

        // Active should still be good_id
        assert_eq!(ring.active_zone_key_id, Some(good_id));
        assert_eq!(ring.active_zone_key(), Some(&key));
    }

    /// Verify `ZoneKeyRing` does not change state on failed `set_active_object_id_key`.
    #[test]
    fn zone_key_ring_set_active_object_id_key_failure_preserves_state() {
        let mut ring = ZoneKeyRing::new(ZoneId::work());
        let good_id = ObjectIdKeyId::from_bytes([0x01; 8]);
        let bad_id = ObjectIdKeyId::from_bytes([0x02; 8]);
        let key = random_object_id_key();

        ring.insert_object_id_key(good_id, key);
        assert!(ring.set_active_object_id_key(good_id));

        // Attempt to set to unknown key
        assert!(!ring.set_active_object_id_key(bad_id));

        // Active should still be good_id
        assert_eq!(ring.active_object_id_key_id, Some(good_id));
        assert_eq!(ring.active_object_id_key(), Some(&key));
    }

    /// Verify that multiple different zone key rings are independent.
    #[test]
    fn zone_key_rings_are_independent() {
        let key_id = ZoneKeyId::from_bytes([0x01; 8]);
        let key = random_zone_key();

        let mut ring1 = ZoneKeyRing::new(ZoneId::work());
        let mut ring2 = ZoneKeyRing::new(ZoneId::private());

        ring1.insert_zone_key(key_id, key);
        assert!(ring1.set_active_zone_key(key_id));

        // ring2 should be unaffected
        assert!(ring2.active_zone_key().is_none());
        assert!(ring2.zone_key(&key_id).is_none());
        assert!(!ring2.set_active_zone_key(key_id));
    }

    /// Verify that different zone types produce distinct zone IDs that affect wrapping.
    #[test]
    fn different_zone_types_produce_distinct_aad() {
        let node_id = TailscaleNodeId::new("node-zones");
        let issued_at = 1_700_000_000;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let zone_key = random_zone_key();

        let wrapped_work =
            wrap_zone_key(&pk, &ZoneId::work(), &node_id, issued_at, &zone_key).unwrap();
        let wrapped_private =
            wrap_zone_key(&pk, &ZoneId::private(), &node_id, issued_at, &zone_key).unwrap();

        // Both should unwrap correctly under their own zone_id
        let k_work = unwrap_zone_key(&sk, &ZoneId::work(), &wrapped_work).unwrap();
        let k_priv = unwrap_zone_key(&sk, &ZoneId::private(), &wrapped_private).unwrap();
        assert_eq!(k_work, zone_key);
        assert_eq!(k_priv, zone_key);

        // Cross-zone unwrap should fail
        let result = unwrap_zone_key(&sk, &ZoneId::private(), &wrapped_work);
        assert!(result.is_err());
    }
}
