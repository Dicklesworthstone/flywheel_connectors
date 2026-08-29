//! FROST threshold signing support for FCP.
//!
//! This module wraps `frost-ed25519` with FCP-native types so higher layers can
//! run distributed key generation (DKG) without depending directly on the
//! upstream crate's internal wire structures.
//!
//! FCP currently uses the default FROST participant numbering model: every DKG
//! run is addressed by contiguous 1-based participant identifiers in the range
//! `1..=max_signers`.

use crate::{CryptoError, CryptoResult, Ed25519Signature, Ed25519VerifyingKey};
use frost_ed25519 as frost;
use rand_core::{CryptoRng, RngCore};
use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

const FROST_SCALAR_SIZE: usize = 32;
const FROST_GROUP_ELEMENT_SIZE: usize = 32;
const FROST_SIGNATURE_SIZE: usize = 64;

/// A serialized FROST signing share owned by a single participant.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct FrostSigningShare {
    #[serde(with = "serde_bytes")]
    bytes: Vec<u8>,
}

impl FrostSigningShare {
    /// Construct a signing share from its serialized scalar bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are not a valid serialized
    /// `frost-ed25519` signing share.
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        validate_exact_len(bytes, FROST_SCALAR_SIZE)?;
        let _ = frost::keys::SigningShare::deserialize(bytes).map_err(frost_error)?;
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// Return the serialized share bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Reconstruct the upstream `frost-ed25519` signing share.
    ///
    /// # Errors
    ///
    /// Returns an error if the stored bytes are no longer valid.
    pub fn to_frost(&self) -> CryptoResult<frost::keys::SigningShare> {
        frost::keys::SigningShare::deserialize(&self.bytes).map_err(frost_error)
    }

    fn from_frost(share: &frost::keys::SigningShare) -> Self {
        Self {
            bytes: share.serialize(),
        }
    }
}

impl std::fmt::Debug for FrostSigningShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FrostSigningShare")
            .field("bytes", &"<redacted>")
            .finish()
    }
}

/// Secret package retained by a participant between DKG round 1 and round 2.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct FrostDkgRound1SecretPackage {
    #[zeroize(skip)]
    participant: u16,
    #[zeroize(skip)]
    min_signers: u16,
    #[zeroize(skip)]
    max_signers: u16,
    #[serde(with = "serde_bytes")]
    bytes: Vec<u8>,
}

impl FrostDkgRound1SecretPackage {
    /// Return the owning participant's 1-based identifier.
    #[must_use]
    pub const fn participant(&self) -> u16 {
        self.participant
    }

    /// Return the threshold required for the DKG run.
    #[must_use]
    pub const fn min_signers(&self) -> u16 {
        self.min_signers
    }

    /// Return the total number of participants in the DKG run.
    #[must_use]
    pub const fn max_signers(&self) -> u16 {
        self.max_signers
    }

    /// Return the serialized upstream package bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn to_frost(&self) -> CryptoResult<frost::keys::dkg::round1::SecretPackage> {
        let package = frost::keys::dkg::round1::SecretPackage::deserialize(&self.bytes)
            .map_err(frost_error)?;
        validate_round1_secret_metadata(self, &package)?;
        Ok(package)
    }

    fn from_frost(
        participant: u16,
        min_signers: u16,
        max_signers: u16,
        package: &frost::keys::dkg::round1::SecretPackage,
    ) -> CryptoResult<Self> {
        Ok(Self {
            participant,
            min_signers,
            max_signers,
            bytes: package.serialize().map_err(frost_error)?,
        })
    }
}

impl std::fmt::Debug for FrostDkgRound1SecretPackage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FrostDkgRound1SecretPackage")
            .field("participant", &self.participant)
            .field("min_signers", &self.min_signers)
            .field("max_signers", &self.max_signers)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

/// Broadcast package emitted by a participant during DKG round 1.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrostDkgRound1Package {
    participant: u16,
    #[serde(with = "serde_bytes")]
    bytes: Vec<u8>,
}

impl FrostDkgRound1Package {
    /// Return the sending participant's 1-based identifier.
    #[must_use]
    pub const fn participant(&self) -> u16 {
        self.participant
    }

    /// Return the serialized upstream package bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn to_frost(&self) -> CryptoResult<frost::keys::dkg::round1::Package> {
        frost::keys::dkg::round1::Package::deserialize(&self.bytes).map_err(frost_error)
    }

    fn from_frost(
        participant: u16,
        package: &frost::keys::dkg::round1::Package,
    ) -> CryptoResult<Self> {
        Ok(Self {
            participant,
            bytes: package.serialize().map_err(frost_error)?,
        })
    }
}

impl std::fmt::Debug for FrostDkgRound1Package {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FrostDkgRound1Package")
            .field("participant", &self.participant)
            .field("byte_len", &self.bytes.len())
            .finish()
    }
}

/// Secret package retained by a participant between DKG round 2 and round 3.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct FrostDkgRound2SecretPackage {
    #[zeroize(skip)]
    participant: u16,
    #[zeroize(skip)]
    min_signers: u16,
    #[zeroize(skip)]
    max_signers: u16,
    #[serde(with = "serde_bytes")]
    bytes: Vec<u8>,
}

impl FrostDkgRound2SecretPackage {
    /// Return the owning participant's 1-based identifier.
    #[must_use]
    pub const fn participant(&self) -> u16 {
        self.participant
    }

    /// Return the threshold required for the DKG run.
    #[must_use]
    pub const fn min_signers(&self) -> u16 {
        self.min_signers
    }

    /// Return the total number of participants in the DKG run.
    #[must_use]
    pub const fn max_signers(&self) -> u16 {
        self.max_signers
    }

    /// Return the serialized upstream package bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn to_frost(&self) -> CryptoResult<frost::keys::dkg::round2::SecretPackage> {
        let package = frost::keys::dkg::round2::SecretPackage::deserialize(&self.bytes)
            .map_err(frost_error)?;
        validate_round2_secret_metadata(self, &package)?;
        Ok(package)
    }

    fn from_frost(
        participant: u16,
        min_signers: u16,
        max_signers: u16,
        package: &frost::keys::dkg::round2::SecretPackage,
    ) -> CryptoResult<Self> {
        Ok(Self {
            participant,
            min_signers,
            max_signers,
            bytes: package.serialize().map_err(frost_error)?,
        })
    }
}

impl std::fmt::Debug for FrostDkgRound2SecretPackage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FrostDkgRound2SecretPackage")
            .field("participant", &self.participant)
            .field("min_signers", &self.min_signers)
            .field("max_signers", &self.max_signers)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

/// Confidential package sent from one participant to another in DKG round 2.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrostDkgRound2Package {
    sender: u16,
    recipient: u16,
    #[serde(with = "serde_bytes")]
    bytes: Vec<u8>,
}

impl FrostDkgRound2Package {
    /// Return the sending participant's 1-based identifier.
    #[must_use]
    pub const fn sender(&self) -> u16 {
        self.sender
    }

    /// Return the receiving participant's 1-based identifier.
    #[must_use]
    pub const fn recipient(&self) -> u16 {
        self.recipient
    }

    /// Return the serialized upstream package bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn to_frost(&self) -> CryptoResult<frost::keys::dkg::round2::Package> {
        frost::keys::dkg::round2::Package::deserialize(&self.bytes).map_err(frost_error)
    }

    fn from_frost(
        sender: u16,
        recipient: u16,
        package: &frost::keys::dkg::round2::Package,
    ) -> CryptoResult<Self> {
        Ok(Self {
            sender,
            recipient,
            bytes: package.serialize().map_err(frost_error)?,
        })
    }
}

impl std::fmt::Debug for FrostDkgRound2Package {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FrostDkgRound2Package")
            .field("sender", &self.sender)
            .field("recipient", &self.recipient)
            .field("byte_len", &self.bytes.len())
            .finish()
    }
}

/// Secret FROST signing nonces retained by a participant between round 1 and
/// round 2 of threshold signing.
///
/// **SECURITY (FROST nonce-reuse rule, RFC 9591 §6.3):** these nonces MUST
/// be used for exactly one `sign` call. Reuse across two different messages
/// lets any observer of both signature shares recover the participant's
/// signing share — catastrophic for threshold security.
///
/// `sign` consumes this value by move to enforce single-use at compile
/// time. `Clone` is intentionally NOT derived: handing two callers a
/// cloned copy would defeat the move-consume guarantee and re-open the
/// nonce-reuse attack. Serialization remains available for opaque
/// logging/debug-avoidant persistence of an already-live value, but
/// deserialization is intentionally blocked so a caller cannot round-trip
/// one nonce package into multiple live copies.
#[derive(PartialEq, Eq, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct FrostSigningNonces {
    #[zeroize(skip)]
    participant: u16,
    #[serde(with = "serde_bytes")]
    bytes: Vec<u8>,
}

impl FrostSigningNonces {
    /// Return the owning participant's 1-based identifier.
    #[must_use]
    pub const fn participant(&self) -> u16 {
        self.participant
    }

    /// Return the serialized upstream nonce bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn to_frost(&self) -> CryptoResult<frost::round1::SigningNonces> {
        frost::round1::SigningNonces::deserialize(&self.bytes).map_err(frost_error)
    }

    fn from_frost(participant: u16, nonces: &frost::round1::SigningNonces) -> CryptoResult<Self> {
        Ok(Self {
            participant,
            bytes: nonces.serialize().map_err(frost_error)?,
        })
    }
}

impl<'de> Deserialize<'de> for FrostSigningNonces {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Err(de::Error::custom(
            "FrostSigningNonces deserialization is disabled to enforce single-use",
        ))
    }
}

impl std::fmt::Debug for FrostSigningNonces {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FrostSigningNonces")
            .field("participant", &self.participant)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

/// Public FROST nonce commitments broadcast during signing round 1.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrostSigningCommitments {
    participant: u16,
    #[serde(with = "serde_bytes")]
    bytes: Vec<u8>,
}

impl FrostSigningCommitments {
    /// Return the sending participant's 1-based identifier.
    #[must_use]
    pub const fn participant(&self) -> u16 {
        self.participant
    }

    /// Return the serialized upstream commitment bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn to_frost(&self) -> CryptoResult<frost::round1::SigningCommitments> {
        frost::round1::SigningCommitments::deserialize(&self.bytes).map_err(frost_error)
    }

    fn from_frost(
        participant: u16,
        commitments: &frost::round1::SigningCommitments,
    ) -> CryptoResult<Self> {
        Ok(Self {
            participant,
            bytes: commitments.serialize().map_err(frost_error)?,
        })
    }
}

impl std::fmt::Debug for FrostSigningCommitments {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FrostSigningCommitments")
            .field("participant", &self.participant)
            .field("byte_len", &self.bytes.len())
            .finish()
    }
}

/// Coordinator-generated signing package distributed to every selected signer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrostSigningPackage {
    signing_commitments: BTreeMap<u16, FrostSigningCommitments>,
    #[serde(with = "serde_bytes")]
    message: Vec<u8>,
    min_signers: u16,
    max_signers: u16,
}

impl FrostSigningPackage {
    /// Return the selected participants' commitments.
    #[must_use]
    pub const fn signing_commitments(&self) -> &BTreeMap<u16, FrostSigningCommitments> {
        &self.signing_commitments
    }

    /// Return the message that will be signed.
    #[must_use]
    pub fn message(&self) -> &[u8] {
        &self.message
    }

    /// Return the threshold required for this signing group.
    #[must_use]
    pub const fn min_signers(&self) -> u16 {
        self.min_signers
    }

    /// Return the total number of participants in the signing group.
    #[must_use]
    pub const fn max_signers(&self) -> u16 {
        self.max_signers
    }

    fn to_frost(&self) -> CryptoResult<frost::SigningPackage> {
        validate_signer_bounds(self.min_signers, self.max_signers)?;
        let commitments = signing_commitments_to_frost(
            self.min_signers,
            self.max_signers,
            &self.signing_commitments,
        )?;
        Ok(frost::SigningPackage::new(commitments, &self.message))
    }
}

/// A participant's FROST signature share produced in signing round 2.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrostSignatureShare {
    participant: u16,
    #[serde(with = "serde_bytes")]
    bytes: Vec<u8>,
}

impl FrostSignatureShare {
    /// Return the sending participant's 1-based identifier.
    #[must_use]
    pub const fn participant(&self) -> u16 {
        self.participant
    }

    /// Return the serialized signature-share bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn to_frost(&self) -> CryptoResult<frost::round2::SignatureShare> {
        frost::round2::SignatureShare::deserialize(&self.bytes).map_err(frost_error)
    }

    fn from_frost(participant: u16, share: &frost::round2::SignatureShare) -> Self {
        Self {
            participant,
            bytes: share.serialize(),
        }
    }
}

impl std::fmt::Debug for FrostSignatureShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FrostSignatureShare")
            .field("participant", &self.participant)
            .field("byte_len", &self.bytes.len())
            .finish()
    }
}

/// Participant-local FROST key material produced after a successful DKG run.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrostKeyPackage {
    participant: u16,
    signing_share: FrostSigningShare,
    verifying_share: Ed25519VerifyingKey,
    group_public_key: Ed25519VerifyingKey,
    min_signers: u16,
    max_signers: u16,
}

impl FrostKeyPackage {
    /// Return the owning participant's 1-based identifier.
    #[must_use]
    pub const fn participant(&self) -> u16 {
        self.participant
    }

    /// Return the participant's secret signing share.
    #[must_use]
    pub const fn signing_share(&self) -> &FrostSigningShare {
        &self.signing_share
    }

    /// Return the participant's public verifying share.
    #[must_use]
    pub const fn verifying_share(&self) -> &Ed25519VerifyingKey {
        &self.verifying_share
    }

    /// Return the aggregate FROST group public key as an Ed25519 verifying key.
    #[must_use]
    pub const fn group_public_key(&self) -> &Ed25519VerifyingKey {
        &self.group_public_key
    }

    /// Return the threshold required to sign.
    #[must_use]
    pub const fn min_signers(&self) -> u16 {
        self.min_signers
    }

    /// Return the total number of participants in the signing group.
    #[must_use]
    pub const fn max_signers(&self) -> u16 {
        self.max_signers
    }

    /// Convert this FCP wrapper back into the upstream `frost-ed25519` key package.
    ///
    /// # Errors
    ///
    /// Returns an error if any wrapped field is not a valid upstream encoding.
    pub fn to_frost(&self) -> CryptoResult<frost::keys::KeyPackage> {
        validate_signer_bounds(self.min_signers, self.max_signers)?;
        validate_participant(self.participant, self.max_signers)?;
        Ok(frost::keys::KeyPackage::new(
            frost_identifier(self.participant)?,
            self.signing_share.to_frost()?,
            frost_verifying_share_from_ed25519(&self.verifying_share)?,
            frost_verifying_key_from_ed25519(&self.group_public_key)?,
            self.min_signers,
        ))
    }

    fn from_frost(key_package: &frost::keys::KeyPackage, max_signers: u16) -> CryptoResult<Self> {
        let lookup = identifier_lookup(max_signers)?;
        Ok(Self {
            participant: identifier_from_lookup(key_package.identifier(), &lookup)?,
            signing_share: FrostSigningShare::from_frost(key_package.signing_share()),
            verifying_share: ed25519_key_from_frost_share(key_package.verifying_share())?,
            group_public_key: ed25519_key_from_frost_verifying_key(key_package.verifying_key())?,
            min_signers: *key_package.min_signers(),
            max_signers,
        })
    }

    /// Validate that this `FrostKeyPackage` is internally consistent.
    ///
    /// Checks that all wrapped fields decode as valid upstream FROST
    /// encodings and that the participant's `verifying_share` equals
    /// `signing_share * G`. This catches mismatched signing/verifying
    /// share pairs introduced by corrupted storage or a malicious
    /// dealer; it does NOT check consistency against the rest of the
    /// group (that requires [`FrostPublicKeyPackage::validate`]).
    ///
    /// # Errors
    ///
    /// Returns an error if any consistency check fails.
    pub fn validate(&self) -> CryptoResult<()> {
        let key_package = self.to_frost()?;
        let derived_verifying: frost::keys::VerifyingShare = (*key_package.signing_share()).into();
        if derived_verifying != *key_package.verifying_share() {
            return Err(CryptoError::FrostFailed(
                "signing share does not match verifying share".to_string(),
            ));
        }
        Ok(())
    }
}

impl std::fmt::Debug for FrostKeyPackage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FrostKeyPackage")
            .field("participant", &self.participant)
            .field("signing_share", &"<redacted>")
            .field("verifying_share", &self.verifying_share)
            .field("group_public_key", &self.group_public_key)
            .field("min_signers", &self.min_signers)
            .field("max_signers", &self.max_signers)
            .finish()
    }
}

/// Group-wide public FROST material produced after a successful DKG run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrostPublicKeyPackage {
    verifying_shares: BTreeMap<u16, Ed25519VerifyingKey>,
    group_public_key: Ed25519VerifyingKey,
    min_signers: u16,
    max_signers: u16,
}

impl FrostPublicKeyPackage {
    /// Return every participant's public verifying share.
    #[must_use]
    pub const fn verifying_shares(&self) -> &BTreeMap<u16, Ed25519VerifyingKey> {
        &self.verifying_shares
    }

    /// Return the aggregate FROST group public key as an Ed25519 verifying key.
    #[must_use]
    pub const fn group_public_key(&self) -> &Ed25519VerifyingKey {
        &self.group_public_key
    }

    /// Return the threshold required to sign.
    #[must_use]
    pub const fn min_signers(&self) -> u16 {
        self.min_signers
    }

    /// Return the total number of participants in the signing group.
    #[must_use]
    pub const fn max_signers(&self) -> u16 {
        self.max_signers
    }

    /// Convert this FCP wrapper back into the upstream `frost-ed25519`
    /// public key package.
    ///
    /// # Errors
    ///
    /// Returns an error if any wrapped field is not a valid upstream encoding.
    pub fn to_frost(&self) -> CryptoResult<frost::keys::PublicKeyPackage> {
        validate_signer_bounds(self.min_signers, self.max_signers)?;
        if self.verifying_shares.len() != usize::from(self.max_signers) {
            return Err(CryptoError::FrostFailed(format!(
                "expected {} verifying shares, got {}",
                self.max_signers,
                self.verifying_shares.len()
            )));
        }

        let mut verifying_shares = BTreeMap::new();
        for (&participant, verifying_share) in &self.verifying_shares {
            validate_participant(participant, self.max_signers)?;
            verifying_shares.insert(
                frost_identifier(participant)?,
                frost_verifying_share_from_ed25519(verifying_share)?,
            );
        }

        Ok(frost::keys::PublicKeyPackage::new(
            verifying_shares,
            frost_verifying_key_from_ed25519(&self.group_public_key)?,
        ))
    }

    fn from_frost(
        public_key_package: &frost::keys::PublicKeyPackage,
        min_signers: u16,
    ) -> CryptoResult<Self> {
        let shares = public_key_package.verifying_shares();
        let max_signers = u16::try_from(shares.len())
            .map_err(|_| CryptoError::FrostFailed("too many signers for u16".to_string()))?;
        let lookup = identifier_lookup(max_signers)?;
        let mut verifying_shares = BTreeMap::new();

        for (identifier, verifying_share) in shares {
            verifying_shares.insert(
                identifier_from_lookup(identifier, &lookup)?,
                ed25519_key_from_frost_share(verifying_share)?,
            );
        }

        Ok(Self {
            verifying_shares,
            group_public_key: ed25519_key_from_frost_verifying_key(
                public_key_package.verifying_key(),
            )?,
            min_signers,
            max_signers,
        })
    }

    /// Validate that this `FrostPublicKeyPackage` is internally consistent.
    ///
    /// Performs basic structural checks (signer bounds, share count,
    /// well-formed encodings) AND a cryptographic aggregate check:
    /// Lagrange-interpolates the group public key from a
    /// `min_signers`-sized subset of the verifying shares and verifies
    /// it matches the stored `group_public_key`. This catches a
    /// malicious or corrupted coordinator that supplies a
    /// `group_public_key` inconsistent with the per-participant shares.
    ///
    /// The check is O(t²) in scalar/group operations where `t =
    /// min_signers`, so it is exposed as an explicit method rather than
    /// enforced on every `from_frost` construction.
    ///
    /// # Errors
    ///
    /// Returns an error if any consistency check fails or if the
    /// Lagrange aggregate of the chosen subset does not equal
    /// `group_public_key`.
    pub fn validate(&self) -> CryptoResult<()> {
        use frost::{Field, Group};
        type FieldT = frost::Ed25519ScalarField;
        type GroupT = frost::Ed25519Group;
        type Scalar = <FieldT as Field>::Scalar;
        type Element = <GroupT as Group>::Element;

        let public_key_package = self.to_frost()?;

        if usize::from(self.min_signers) > self.verifying_shares.len() {
            return Err(CryptoError::FrostFailed(
                "min_signers exceeds available verifying shares".to_string(),
            ));
        }

        let take_count = usize::from(self.min_signers);
        let mut id_scalars: Vec<Scalar> = Vec::with_capacity(take_count);
        let mut id_elements: Vec<Element> = Vec::with_capacity(take_count);
        for (id, vshare) in public_key_package
            .verifying_shares()
            .iter()
            .take(take_count)
        {
            let id_bytes_vec = id.serialize();
            let id_bytes: [u8; 32] = id_bytes_vec.as_slice().try_into().map_err(|_| {
                CryptoError::FrostFailed("frost identifier serialization length".to_string())
            })?;
            let scalar: Scalar = FieldT::deserialize(&id_bytes).map_err(|e| {
                CryptoError::FrostFailed(format!("frost identifier deserialize: {e:?}"))
            })?;

            let v_bytes_vec = vshare.serialize().map_err(frost_error)?;
            let v_bytes: [u8; 32] = v_bytes_vec.as_slice().try_into().map_err(|_| {
                CryptoError::FrostFailed("verifying share serialization length".to_string())
            })?;
            let element: Element = GroupT::deserialize(&v_bytes).map_err(|e| {
                CryptoError::FrostFailed(format!("verifying share deserialize: {e:?}"))
            })?;

            id_scalars.push(scalar);
            id_elements.push(element);
        }

        let mut accum: Element = GroupT::identity();
        for (i, x_i) in id_scalars.iter().copied().enumerate() {
            let mut num = FieldT::one();
            let mut den = FieldT::one();
            for (j, x_j) in id_scalars.iter().copied().enumerate() {
                if i == j {
                    continue;
                }
                num *= x_j;
                den *= x_j - x_i;
            }
            let den_inv = FieldT::invert(&den).map_err(|e| {
                CryptoError::FrostFailed(format!("lagrange denominator inverse: {e:?}"))
            })?;
            let lambda = num * den_inv;
            accum += id_elements[i] * lambda;
        }

        let stored_bytes = self.group_public_key.to_bytes();
        let stored_element: Element = GroupT::deserialize(&stored_bytes).map_err(|e| {
            CryptoError::FrostFailed(format!("group public key deserialize: {e:?}"))
        })?;

        if accum != stored_element {
            return Err(CryptoError::FrostFailed(
                "group public key does not match Lagrange aggregate of verifying shares"
                    .to_string(),
            ));
        }

        Ok(())
    }
}

/// Run DKG round 1 for a single participant using OS randomness.
///
/// # Errors
///
/// Returns an error if the participant identifier or signer bounds are invalid,
/// or if the upstream FROST round fails.
pub fn dkg_part1(
    participant: u16,
    max_signers: u16,
    min_signers: u16,
) -> CryptoResult<(FrostDkgRound1SecretPackage, FrostDkgRound1Package)> {
    let mut rng = rand::rngs::OsRng;
    dkg_part1_with_rng(participant, max_signers, min_signers, &mut rng)
}

/// Run DKG round 1 for a single participant with an explicit RNG.
///
/// # Errors
///
/// Returns an error if the participant identifier or signer bounds are invalid,
/// or if the upstream FROST round fails.
pub fn dkg_part1_with_rng<R>(
    participant: u16,
    max_signers: u16,
    min_signers: u16,
    rng: &mut R,
) -> CryptoResult<(FrostDkgRound1SecretPackage, FrostDkgRound1Package)>
where
    R: CryptoRng + RngCore,
{
    validate_signer_bounds(min_signers, max_signers)?;
    validate_participant(participant, max_signers)?;
    let identifier = frost_identifier(participant)?;
    let (secret_package, public_package) =
        frost::keys::dkg::part1(identifier, max_signers, min_signers, rng).map_err(frost_error)?;
    Ok((
        FrostDkgRound1SecretPackage::from_frost(
            participant,
            min_signers,
            max_signers,
            &secret_package,
        )?,
        FrostDkgRound1Package::from_frost(participant, &public_package)?,
    ))
}

/// Run DKG round 2 for a participant after receiving every other participant's
/// round-1 broadcast package.
///
/// The `round1_packages` map must be keyed by sender identifier and must
/// exclude the current participant.
///
/// # Errors
///
/// Returns an error if the packages are keyed inconsistently, target the wrong
/// participant set, or if the upstream FROST round fails.
pub fn dkg_part2(
    secret_package: &FrostDkgRound1SecretPackage,
    round1_packages: &BTreeMap<u16, FrostDkgRound1Package>,
) -> CryptoResult<(
    FrostDkgRound2SecretPackage,
    BTreeMap<u16, FrostDkgRound2Package>,
)> {
    let frost_secret = secret_package.to_frost()?;
    let frost_round1 = round1_packages_to_frost(
        secret_package.participant,
        secret_package.max_signers,
        round1_packages,
    )?;
    let (round2_secret, round2_packages) =
        frost::keys::dkg::part2(frost_secret, &frost_round1).map_err(frost_error)?;
    let lookup = identifier_lookup(secret_package.max_signers)?;
    let mut wrapped_round2 = BTreeMap::new();

    for (identifier, package) in round2_packages {
        let recipient = identifier_from_lookup(&identifier, &lookup)?;
        wrapped_round2.insert(
            recipient,
            FrostDkgRound2Package::from_frost(secret_package.participant, recipient, &package)?,
        );
    }

    Ok((
        FrostDkgRound2SecretPackage::from_frost(
            secret_package.participant,
            secret_package.min_signers,
            secret_package.max_signers,
            &round2_secret,
        )?,
        wrapped_round2,
    ))
}

/// Run DKG round 3 for a participant after receiving every other participant's
/// round-1 and round-2 packages.
///
/// The `round1_packages` and `round2_packages` maps must both be keyed by
/// sender identifier and must exclude the current participant.
///
/// # Errors
///
/// Returns an error if the packages are keyed inconsistently, target the wrong
/// participant, or if the upstream FROST round fails.
pub fn dkg_part3(
    secret_package: &FrostDkgRound2SecretPackage,
    round1_packages: &BTreeMap<u16, FrostDkgRound1Package>,
    round2_packages: &BTreeMap<u16, FrostDkgRound2Package>,
) -> CryptoResult<(FrostKeyPackage, FrostPublicKeyPackage)> {
    let frost_secret = secret_package.to_frost()?;
    let frost_round1 = round1_packages_to_frost(
        secret_package.participant,
        secret_package.max_signers,
        round1_packages,
    )?;
    let frost_round2 = round2_packages_to_frost(
        secret_package.participant,
        secret_package.max_signers,
        round2_packages,
    )?;
    let (key_package, public_key_package) =
        frost::keys::dkg::part3(&frost_secret, &frost_round1, &frost_round2)
            .map_err(frost_error)?;
    let public_key_package =
        FrostPublicKeyPackage::from_frost(&public_key_package, secret_package.min_signers)?;
    let key_package = FrostKeyPackage::from_frost(&key_package, public_key_package.max_signers)?;

    Ok((key_package, public_key_package))
}

/// Generate one participant's signing nonces and commitments using OS
/// randomness.
///
/// The returned [`FrostSigningNonces`] must be used exactly once. This API
/// consumes the nonce package during [`sign`] to prevent accidental reuse.
///
/// # Errors
///
/// Returns an error if the wrapped signing share is invalid.
pub fn commit(
    key_package: &FrostKeyPackage,
) -> CryptoResult<(FrostSigningNonces, FrostSigningCommitments)> {
    let mut rng = rand::rngs::OsRng;
    commit_with_rng(key_package, &mut rng)
}

/// Generate one participant's signing nonces and commitments with an explicit
/// RNG.
///
/// # Errors
///
/// Returns an error if the wrapped signing share is invalid.
pub fn commit_with_rng<R>(
    key_package: &FrostKeyPackage,
    rng: &mut R,
) -> CryptoResult<(FrostSigningNonces, FrostSigningCommitments)>
where
    R: CryptoRng + RngCore,
{
    let signing_share = key_package.signing_share().to_frost()?;
    let (nonces, commitments) = frost::round1::commit(&signing_share, rng);
    Ok((
        FrostSigningNonces::from_frost(key_package.participant(), &nonces)?,
        FrostSigningCommitments::from_frost(key_package.participant(), &commitments)?,
    ))
}

/// Build the coordinator's signing package from a selected subset of signing
/// commitments.
///
/// The selected commitments must all belong to the same signing group described
/// by `public_key_package`, and there must be at least `min_signers`
/// commitments present. If a participant drops out after round 1, abort the
/// signing session and rebuild this package with a fresh set of commitments.
///
/// # Errors
///
/// Returns an error if the commitment map is inconsistent with the public key
/// package or if fewer than the threshold number of commitments are present.
pub fn signing_package(
    public_key_package: &FrostPublicKeyPackage,
    commitments: &BTreeMap<u16, FrostSigningCommitments>,
    message: &[u8],
) -> CryptoResult<FrostSigningPackage> {
    let _ = signing_commitments_to_frost(
        public_key_package.min_signers(),
        public_key_package.max_signers(),
        commitments,
    )?;

    for participant in commitments.keys() {
        if !public_key_package
            .verifying_shares()
            .contains_key(participant)
        {
            return Err(CryptoError::FrostFailed(format!(
                "participant {participant} is not present in the public key package"
            )));
        }
    }

    Ok(FrostSigningPackage {
        signing_commitments: commitments.clone(),
        message: message.to_vec(),
        min_signers: public_key_package.min_signers(),
        max_signers: public_key_package.max_signers(),
    })
}

/// Produce one participant's signature share for a coordinator-selected signing
/// package.
///
/// This consumes `signer_nonces` so the same nonce pair cannot be accidentally
/// reused for another signing attempt.
///
/// # Errors
///
/// Returns an error if the signing package does not match the signer's expected
/// commitment set, which can indicate coordinator tampering or a commitment
/// mix-up.
#[allow(clippy::needless_pass_by_value)] // nonces MUST be consumed (used exactly once)
pub fn sign(
    signing_package: &FrostSigningPackage,
    signer_nonces: FrostSigningNonces,
    key_package: &FrostKeyPackage,
) -> CryptoResult<FrostSignatureShare> {
    validate_signing_package_matches_key_package(signing_package, key_package)?;
    if signer_nonces.participant() != key_package.participant() {
        return Err(CryptoError::FrostFailed(format!(
            "signing nonces belong to participant {}, expected {}",
            signer_nonces.participant(),
            key_package.participant()
        )));
    }

    let frost_signing_package = signing_package.to_frost()?;
    let frost_signer_nonces = signer_nonces.to_frost()?;
    let frost_key_package = key_package.to_frost()?;
    let share = frost::round2::sign(
        &frost_signing_package,
        &frost_signer_nonces,
        &frost_key_package,
    )
    .map_err(|error| match error {
        frost::Error::IncorrectCommitment => CryptoError::FrostFailed(format!(
            "signing package commitment for participant {} does not match the locally generated nonces; possible coordinator tampering or commitment mix-up",
            key_package.participant()
        )),
        other => frost_error(other),
    })?;

    Ok(FrostSignatureShare::from_frost(
        key_package.participant(),
        &share,
    ))
}

/// Aggregate validated signature shares into a standard Ed25519 signature.
///
/// The resulting signature is byte-for-byte compatible with ordinary Ed25519
/// verification using the group public key.
///
/// # Errors
///
/// Returns an error if a signer dropped out after commitments were selected, if
/// the share map is inconsistent, or if any share fails verification during
/// aggregation.
pub fn aggregate(
    signing_package: &FrostSigningPackage,
    signature_shares: &BTreeMap<u16, FrostSignatureShare>,
    public_key_package: &FrostPublicKeyPackage,
) -> CryptoResult<Ed25519Signature> {
    validate_signing_package_matches_public_keys(signing_package, public_key_package)?;
    let frost_signing_package = signing_package.to_frost()?;
    let frost_signature_shares = signature_shares_to_frost(signing_package, signature_shares)?;
    let frost_public_keys = public_key_package.to_frost()?;
    let signature = frost::aggregate(
        &frost_signing_package,
        &frost_signature_shares,
        &frost_public_keys,
    )
    .map_err(frost_error)?;
    ed25519_signature_from_frost(&signature)
}

fn frost_error(error: impl std::fmt::Display) -> CryptoError {
    CryptoError::FrostFailed(error.to_string())
}

fn validate_signer_bounds(min_signers: u16, max_signers: u16) -> CryptoResult<()> {
    if min_signers == 0 {
        return Err(CryptoError::FrostFailed(
            "min_signers must be at least 1".to_string(),
        ));
    }
    if min_signers > max_signers {
        return Err(CryptoError::FrostFailed(format!(
            "min_signers ({min_signers}) cannot exceed max_signers ({max_signers})"
        )));
    }
    Ok(())
}

fn validate_participant(participant: u16, max_signers: u16) -> CryptoResult<()> {
    if participant == 0 {
        return Err(CryptoError::FrostFailed(
            "participant identifier must be at least 1".to_string(),
        ));
    }
    if participant > max_signers {
        return Err(CryptoError::FrostFailed(format!(
            "participant identifier {participant} exceeds max_signers {max_signers}"
        )));
    }
    Ok(())
}

const fn validate_exact_len(bytes: &[u8], expected: usize) -> CryptoResult<()> {
    if bytes.len() != expected {
        return Err(CryptoError::InvalidKeyLength {
            expected,
            actual: bytes.len(),
        });
    }
    Ok(())
}

fn frost_identifier(participant: u16) -> CryptoResult<frost::Identifier> {
    frost::Identifier::try_from(participant).map_err(frost_error)
}

fn identifier_lookup(max_signers: u16) -> CryptoResult<BTreeMap<Vec<u8>, u16>> {
    let mut lookup = BTreeMap::new();
    for participant in 1..=max_signers {
        lookup.insert(frost_identifier(participant)?.serialize(), participant);
    }
    Ok(lookup)
}

fn identifier_from_lookup(
    identifier: &frost::Identifier,
    lookup: &BTreeMap<Vec<u8>, u16>,
) -> CryptoResult<u16> {
    lookup
        .get(&identifier.serialize())
        .copied()
        .ok_or_else(|| CryptoError::FrostFailed("unknown FROST participant identifier".to_string()))
}

fn ed25519_key_from_frost_verifying_key(
    verifying_key: &frost::VerifyingKey,
) -> CryptoResult<Ed25519VerifyingKey> {
    let bytes = verifying_key.serialize().map_err(frost_error)?;
    validate_exact_len(&bytes, FROST_GROUP_ELEMENT_SIZE)?;
    let mut key_bytes = [0u8; FROST_GROUP_ELEMENT_SIZE];
    key_bytes.copy_from_slice(&bytes);
    Ed25519VerifyingKey::from_bytes(&key_bytes)
}

fn ed25519_key_from_frost_share(
    verifying_share: &frost::keys::VerifyingShare,
) -> CryptoResult<Ed25519VerifyingKey> {
    let bytes = verifying_share.serialize().map_err(frost_error)?;
    validate_exact_len(&bytes, FROST_GROUP_ELEMENT_SIZE)?;
    let mut key_bytes = [0u8; FROST_GROUP_ELEMENT_SIZE];
    key_bytes.copy_from_slice(&bytes);
    Ed25519VerifyingKey::from_bytes(&key_bytes)
}

fn frost_verifying_key_from_ed25519(
    verifying_key: &Ed25519VerifyingKey,
) -> CryptoResult<frost::VerifyingKey> {
    frost::VerifyingKey::deserialize(&verifying_key.to_bytes()).map_err(frost_error)
}

fn frost_verifying_share_from_ed25519(
    verifying_key: &Ed25519VerifyingKey,
) -> CryptoResult<frost::keys::VerifyingShare> {
    frost::keys::VerifyingShare::deserialize(&verifying_key.to_bytes()).map_err(frost_error)
}

fn ed25519_signature_from_frost(signature: &frost::Signature) -> CryptoResult<Ed25519Signature> {
    let bytes = signature.serialize().map_err(frost_error)?;
    validate_exact_len(&bytes, FROST_SIGNATURE_SIZE)?;
    Ed25519Signature::try_from_slice(&bytes)
}

fn round1_packages_to_frost(
    current_participant: u16,
    max_signers: u16,
    round1_packages: &BTreeMap<u16, FrostDkgRound1Package>,
) -> CryptoResult<BTreeMap<frost::Identifier, frost::keys::dkg::round1::Package>> {
    let mut packages = BTreeMap::new();
    for (&sender, package) in round1_packages {
        validate_participant(sender, max_signers)?;
        if sender == current_participant {
            return Err(CryptoError::FrostFailed(format!(
                "round1 package map must not include participant {current_participant}"
            )));
        }
        if package.participant != sender {
            return Err(CryptoError::FrostFailed(format!(
                "round1 package key {sender} does not match package participant {}",
                package.participant
            )));
        }
        packages.insert(frost_identifier(sender)?, package.to_frost()?);
    }
    Ok(packages)
}

fn validate_round1_secret_metadata(
    package: &FrostDkgRound1SecretPackage,
    decoded: &frost::keys::dkg::round1::SecretPackage,
) -> CryptoResult<()> {
    if decoded.identifier().serialize() != frost_identifier(package.participant)?.serialize() {
        return Err(CryptoError::FrostFailed(
            "round1 secret package participant metadata does not match encoded package".to_string(),
        ));
    }
    if decoded.min_signers() != &package.min_signers {
        return Err(CryptoError::FrostFailed(
            "round1 secret package min_signers metadata does not match encoded package".to_string(),
        ));
    }
    if decoded.max_signers() != &package.max_signers {
        return Err(CryptoError::FrostFailed(
            "round1 secret package max_signers metadata does not match encoded package".to_string(),
        ));
    }
    Ok(())
}

fn validate_round2_secret_metadata(
    package: &FrostDkgRound2SecretPackage,
    decoded: &frost::keys::dkg::round2::SecretPackage,
) -> CryptoResult<()> {
    if decoded.identifier().serialize() != frost_identifier(package.participant)?.serialize() {
        return Err(CryptoError::FrostFailed(
            "round2 secret package participant metadata does not match encoded package".to_string(),
        ));
    }
    if decoded.min_signers() != &package.min_signers {
        return Err(CryptoError::FrostFailed(
            "round2 secret package min_signers metadata does not match encoded package".to_string(),
        ));
    }
    if decoded.max_signers() != &package.max_signers {
        return Err(CryptoError::FrostFailed(
            "round2 secret package max_signers metadata does not match encoded package".to_string(),
        ));
    }
    Ok(())
}

fn round2_packages_to_frost(
    current_participant: u16,
    max_signers: u16,
    round2_packages: &BTreeMap<u16, FrostDkgRound2Package>,
) -> CryptoResult<BTreeMap<frost::Identifier, frost::keys::dkg::round2::Package>> {
    let mut packages = BTreeMap::new();
    for (&sender, package) in round2_packages {
        validate_participant(sender, max_signers)?;
        if sender == current_participant {
            return Err(CryptoError::FrostFailed(format!(
                "round2 package map must not include participant {current_participant}"
            )));
        }
        if package.sender != sender {
            return Err(CryptoError::FrostFailed(format!(
                "round2 package key {sender} does not match package sender {}",
                package.sender
            )));
        }
        if package.recipient != current_participant {
            return Err(CryptoError::FrostFailed(format!(
                "round2 package from participant {sender} targets {}, expected {current_participant}",
                package.recipient
            )));
        }
        packages.insert(frost_identifier(sender)?, package.to_frost()?);
    }
    Ok(packages)
}

fn signing_commitments_to_frost(
    min_signers: u16,
    max_signers: u16,
    signing_commitments: &BTreeMap<u16, FrostSigningCommitments>,
) -> CryptoResult<BTreeMap<frost::Identifier, frost::round1::SigningCommitments>> {
    validate_signer_bounds(min_signers, max_signers)?;
    if signing_commitments.len() < usize::from(min_signers) {
        return Err(CryptoError::FrostFailed(format!(
            "received {} signing commitments, but threshold requires at least {}",
            signing_commitments.len(),
            min_signers
        )));
    }
    if signing_commitments.len() > usize::from(max_signers) {
        return Err(CryptoError::FrostFailed(format!(
            "received {} signing commitments, but signing group only has {} participants",
            signing_commitments.len(),
            max_signers
        )));
    }

    let mut commitments = BTreeMap::new();
    for (&participant, commitment) in signing_commitments {
        validate_participant(participant, max_signers)?;
        if commitment.participant != participant {
            return Err(CryptoError::FrostFailed(format!(
                "signing commitment key {participant} does not match package participant {}",
                commitment.participant
            )));
        }
        commitments.insert(frost_identifier(participant)?, commitment.to_frost()?);
    }
    Ok(commitments)
}

fn validate_signing_package_matches_key_package(
    signing_package: &FrostSigningPackage,
    key_package: &FrostKeyPackage,
) -> CryptoResult<()> {
    if signing_package.min_signers() != key_package.min_signers() {
        return Err(CryptoError::FrostFailed(format!(
            "signing package threshold {} does not match key package threshold {}",
            signing_package.min_signers(),
            key_package.min_signers()
        )));
    }
    if signing_package.max_signers() != key_package.max_signers() {
        return Err(CryptoError::FrostFailed(format!(
            "signing package max_signers {} does not match key package max_signers {}",
            signing_package.max_signers(),
            key_package.max_signers()
        )));
    }
    if !signing_package
        .signing_commitments()
        .contains_key(&key_package.participant())
    {
        return Err(CryptoError::FrostFailed(format!(
            "signing package is missing participant {}",
            key_package.participant()
        )));
    }
    Ok(())
}

fn validate_signing_package_matches_public_keys(
    signing_package: &FrostSigningPackage,
    public_key_package: &FrostPublicKeyPackage,
) -> CryptoResult<()> {
    if signing_package.min_signers() != public_key_package.min_signers() {
        return Err(CryptoError::FrostFailed(format!(
            "signing package threshold {} does not match public key package threshold {}",
            signing_package.min_signers(),
            public_key_package.min_signers()
        )));
    }
    if signing_package.max_signers() != public_key_package.max_signers() {
        return Err(CryptoError::FrostFailed(format!(
            "signing package max_signers {} does not match public key package max_signers {}",
            signing_package.max_signers(),
            public_key_package.max_signers()
        )));
    }

    for participant in signing_package.signing_commitments().keys() {
        if !public_key_package
            .verifying_shares()
            .contains_key(participant)
        {
            return Err(CryptoError::FrostFailed(format!(
                "signing package references participant {participant}, which is missing from the public key package"
            )));
        }
    }

    Ok(())
}

fn signature_shares_to_frost(
    signing_package: &FrostSigningPackage,
    signature_shares: &BTreeMap<u16, FrostSignatureShare>,
) -> CryptoResult<BTreeMap<frost::Identifier, frost::round2::SignatureShare>> {
    let missing_participants = signing_package
        .signing_commitments()
        .keys()
        .copied()
        .filter(|participant| !signature_shares.contains_key(participant))
        .collect::<Vec<_>>();
    if !missing_participants.is_empty() {
        return Err(CryptoError::FrostFailed(format!(
            "missing signature shares from participants {missing_participants:?}; abort and retry with fresh commitments",
        )));
    }
    if signature_shares.len() != signing_package.signing_commitments().len() {
        return Err(CryptoError::FrostFailed(
            "signature share set contains participants that were not selected in the signing package"
                .to_string(),
        ));
    }

    let mut shares = BTreeMap::new();
    for (&participant, share) in signature_shares {
        validate_participant(participant, signing_package.max_signers())?;
        if share.participant != participant {
            return Err(CryptoError::FrostFailed(format!(
                "signature share key {participant} does not match share participant {}",
                share.participant
            )));
        }
        if !signing_package
            .signing_commitments()
            .contains_key(&participant)
        {
            return Err(CryptoError::FrostFailed(format!(
                "signature share from participant {participant} was not requested in the signing package"
            )));
        }
        shares.insert(frost_identifier(participant)?, share.to_frost()?);
    }

    Ok(shares)
}

/// Local FROST coordinator that holds all key packages for threshold signing
/// within a single process.
///
/// This is the simplest deployment model: all `k` participants run locally,
/// so signing completes synchronously without network round-trips. For
/// distributed signing across mesh nodes, a network-aware coordinator
/// would orchestrate the commit/sign/aggregate rounds over authenticated
/// sessions.
///
/// Implements [`crate::ed25519::OwnerSigner`] so callers can use it interchangeably with a
/// single [`crate::ed25519::Ed25519SigningKey`].
pub struct FrostLocalCoordinator {
    key_packages: BTreeMap<u16, FrostKeyPackage>,
    public_key_package: FrostPublicKeyPackage,
}

impl FrostLocalCoordinator {
    /// Create a coordinator from DKG output.
    ///
    /// `key_packages` must contain at least `min_signers` entries.
    ///
    /// # Errors
    ///
    /// Returns an error if fewer than `min_signers` key packages are provided.
    pub fn new(
        key_packages: BTreeMap<u16, FrostKeyPackage>,
        public_key_package: FrostPublicKeyPackage,
    ) -> CryptoResult<Self> {
        let min = public_key_package.min_signers() as usize;
        if key_packages.len() < min {
            return Err(CryptoError::FrostFailed(format!(
                "need at least {min} key packages for threshold signing, got {}",
                key_packages.len()
            )));
        }
        Ok(Self {
            key_packages,
            public_key_package,
        })
    }

    /// The group public key (verifies all signatures produced by this coordinator).
    #[must_use]
    pub const fn group_public_key(&self) -> &crate::ed25519::Ed25519VerifyingKey {
        self.public_key_package.group_public_key()
    }

    /// Sign a message using threshold signing with the first `k` available participants.
    ///
    /// Performs the full commit → sign → aggregate flow locally.
    fn threshold_sign(&self, message: &[u8]) -> CryptoResult<crate::ed25519::Ed25519Signature> {
        let k = self.public_key_package.min_signers() as usize;
        let selected: Vec<u16> = self.key_packages.keys().copied().take(k).collect();

        // Round 1: each selected participant commits
        let mut commitment_map = BTreeMap::new();
        let mut nonces_map = BTreeMap::new();
        for &participant in &selected {
            let key_pkg = self.key_packages.get(&participant).ok_or_else(|| {
                CryptoError::FrostFailed(format!(
                    "missing key package for participant {participant}"
                ))
            })?;
            let (nonces, commitments) = commit(key_pkg)?;
            nonces_map.insert(participant, nonces);
            commitment_map.insert(participant, commitments);
        }

        // Build signing package
        let pkg = signing_package(&self.public_key_package, &commitment_map, message)?;

        // Round 2: each selected participant produces a signature share
        let mut shares = BTreeMap::new();
        for &participant in &selected {
            let share = sign(
                &pkg,
                nonces_map.remove(&participant).expect("nonces present"),
                self.key_packages.get(&participant).expect("key present"),
            )?;
            shares.insert(participant, share);
        }

        // Aggregate into a standard Ed25519 signature
        aggregate(&pkg, &shares, &self.public_key_package)
    }
}

impl crate::ed25519::OwnerSigner for FrostLocalCoordinator {
    fn owner_sign(&self, message: &[u8]) -> CryptoResult<crate::ed25519::Ed25519Signature> {
        self.threshold_sign(message)
    }

    fn owner_key_id(&self) -> crate::kid::KeyId {
        self.public_key_package.group_public_key().key_id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

    fn participant_rng(participant: u16) -> ChaCha20Rng {
        let mut seed = [0u8; 32];
        seed[..2].copy_from_slice(&participant.to_le_bytes());
        seed[31] = 0xA5;
        ChaCha20Rng::from_seed(seed)
    }

    fn execute_dkg(
        min_signers: u16,
        max_signers: u16,
    ) -> (
        BTreeMap<u16, FrostKeyPackage>,
        BTreeMap<u16, FrostPublicKeyPackage>,
    ) {
        let mut round1_secrets = BTreeMap::new();
        let mut round1_public = BTreeMap::new();

        for participant in 1..=max_signers {
            let mut rng = participant_rng(participant);
            let (secret, package) =
                dkg_part1_with_rng(participant, max_signers, min_signers, &mut rng).unwrap();
            round1_secrets.insert(participant, secret);
            round1_public.insert(participant, package);
        }

        let mut round2_secrets = BTreeMap::new();
        let mut inbound_round2: BTreeMap<u16, BTreeMap<u16, FrostDkgRound2Package>> = (1
            ..=max_signers)
            .map(|participant| (participant, BTreeMap::new()))
            .collect();

        for participant in 1..=max_signers {
            let received_round1 = round1_public
                .iter()
                .filter(|(sender, _)| **sender != participant)
                .map(|(sender, package)| (*sender, package.clone()))
                .collect::<BTreeMap<_, _>>();
            let (secret, outbound) =
                dkg_part2(round1_secrets.get(&participant).unwrap(), &received_round1).unwrap();
            round2_secrets.insert(participant, secret);

            for (recipient, package) in outbound {
                inbound_round2
                    .get_mut(&recipient)
                    .unwrap()
                    .insert(participant, package);
            }
        }

        let mut key_packages = BTreeMap::new();
        let mut public_packages = BTreeMap::new();

        for participant in 1..=max_signers {
            let received_round1 = round1_public
                .iter()
                .filter(|(sender, _)| **sender != participant)
                .map(|(sender, package)| (*sender, package.clone()))
                .collect::<BTreeMap<_, _>>();
            let received_round2 = inbound_round2.remove(&participant).unwrap();
            let (key_package, public_key_package) = dkg_part3(
                round2_secrets.get(&participant).unwrap(),
                &received_round1,
                &received_round2,
            )
            .unwrap();
            key_packages.insert(participant, key_package);
            public_packages.insert(participant, public_key_package);
        }

        (key_packages, public_packages)
    }

    #[test]
    fn dkg_happy_path_produces_consistent_key_packages() {
        let (key_packages, public_packages) = execute_dkg(2, 3);
        let reference_public = public_packages.get(&1).unwrap();

        assert_eq!(reference_public.min_signers(), 2);
        assert_eq!(reference_public.max_signers(), 3);
        assert_eq!(reference_public.verifying_shares().len(), 3);

        for participant in 1..=3 {
            let key_package = key_packages.get(&participant).unwrap();
            let public_key_package = public_packages.get(&participant).unwrap();

            assert_eq!(public_key_package, reference_public);
            assert_eq!(key_package.participant(), participant);
            assert_eq!(key_package.min_signers(), 2);
            assert_eq!(key_package.max_signers(), 3);
            assert_eq!(
                key_package.group_public_key(),
                reference_public.group_public_key()
            );
            assert_eq!(
                key_package.verifying_share(),
                reference_public
                    .verifying_shares()
                    .get(&participant)
                    .unwrap()
            );

            let restored_key = key_package.to_frost().unwrap();
            let restored_public = public_key_package.to_frost().unwrap();
            let restored_public_key = restored_public.verifying_key().serialize().unwrap();

            assert_eq!(restored_key.min_signers(), &2);
            assert_eq!(restored_public.verifying_shares().len(), 3);
            assert_eq!(
                restored_public_key,
                key_package.group_public_key().to_bytes().to_vec()
            );
        }
    }

    #[test]
    fn dkg_part1_rejects_zero_participant() {
        let mut rng = participant_rng(1);
        let error = dkg_part1_with_rng(0, 3, 2, &mut rng).unwrap_err();
        assert!(matches!(error, CryptoError::FrostFailed(_)));
    }

    #[test]
    fn dkg_part1_rejects_invalid_threshold_bounds() {
        let mut rng = participant_rng(1);
        let error = dkg_part1_with_rng(1, 2, 3, &mut rng).unwrap_err();
        assert!(matches!(error, CryptoError::FrostFailed(_)));
    }

    #[test]
    fn dkg_part2_rejects_mismatched_round1_sender() {
        let mut rng1 = participant_rng(1);
        let mut rng2 = participant_rng(2);
        let (secret1, package1) = dkg_part1_with_rng(1, 2, 2, &mut rng1).unwrap();
        let (_secret2, package2) = dkg_part1_with_rng(2, 2, 2, &mut rng2).unwrap();

        let round1_packages = BTreeMap::from([(2, package1)]);
        let error = dkg_part2(&secret1, &round1_packages).unwrap_err();
        assert!(matches!(error, CryptoError::FrostFailed(_)));
        assert!(
            error
                .to_string()
                .contains("round1 package key 2 does not match package participant 1")
        );

        let _ = package2;
    }

    #[test]
    fn dkg_part3_rejects_round2_self_entry() {
        let mut rng1 = participant_rng(1);
        let mut rng2 = participant_rng(2);
        let (round1_secret_1, round1_package_1) = dkg_part1_with_rng(1, 2, 2, &mut rng1).unwrap();
        let (round1_secret_2, round1_package_2) = dkg_part1_with_rng(2, 2, 2, &mut rng2).unwrap();

        let round1_for_1 = BTreeMap::from([(2, round1_package_2)]);
        let round1_for_2 = BTreeMap::from([(1, round1_package_1)]);

        let (round2_secret_1, outbound_1) = dkg_part2(&round1_secret_1, &round1_for_1).unwrap();
        let (_round2_secret_2, _outbound_2) = dkg_part2(&round1_secret_2, &round1_for_2).unwrap();

        let wrong_round2_for_1 = BTreeMap::from([(1, outbound_1.get(&2).unwrap().clone())]);
        let error = dkg_part3(&round2_secret_1, &round1_for_1, &wrong_round2_for_1).unwrap_err();

        assert!(matches!(error, CryptoError::FrostFailed(_)));
        assert!(
            error
                .to_string()
                .contains("round2 package map must not include participant 1")
        );
    }

    #[test]
    fn signing_happy_path_produces_ed25519_compatible_signature() {
        let message = b"frost signing roundtrip";
        let (key_packages, public_packages) = execute_dkg(2, 3);
        let public_key_package = public_packages.get(&1).unwrap();

        let mut commitment_map = BTreeMap::new();
        let mut nonces = BTreeMap::new();

        for participant in [1u16, 2u16] {
            let mut rng = participant_rng(participant + 100);
            let (signing_nonces, commitments) =
                commit_with_rng(key_packages.get(&participant).unwrap(), &mut rng).unwrap();
            nonces.insert(participant, signing_nonces);
            commitment_map.insert(participant, commitments);
        }

        let signing_package =
            signing_package(public_key_package, &commitment_map, message).unwrap();
        let mut signature_shares = BTreeMap::new();

        for participant in [1u16, 2u16] {
            let share = sign(
                &signing_package,
                nonces.remove(&participant).unwrap(),
                key_packages.get(&participant).unwrap(),
            )
            .unwrap();
            signature_shares.insert(participant, share);
        }

        let signature = aggregate(&signing_package, &signature_shares, public_key_package).unwrap();
        public_key_package
            .group_public_key()
            .verify(message, &signature)
            .unwrap();
    }

    #[test]
    fn signing_package_rejects_below_threshold_commitments() {
        let (key_packages, public_packages) = execute_dkg(2, 3);
        let public_key_package = public_packages.get(&1).unwrap();
        let mut rng = participant_rng(1);
        let (_nonces, commitments) =
            commit_with_rng(key_packages.get(&1).unwrap(), &mut rng).unwrap();
        let commitment_map = BTreeMap::from([(1, commitments)]);

        let error = signing_package(public_key_package, &commitment_map, b"message").unwrap_err();
        assert!(matches!(error, CryptoError::FrostFailed(_)));
        assert!(
            error
                .to_string()
                .contains("received 1 signing commitments, but threshold requires at least 2")
        );
    }

    #[test]
    fn sign_rejects_tampered_self_commitment() {
        let (key_packages, public_packages) = execute_dkg(2, 3);
        let public_key_package = public_packages.get(&1).unwrap();
        let mut rng1 = participant_rng(11);
        let mut rng2 = participant_rng(12);
        let (nonces1, _commitment1) =
            commit_with_rng(key_packages.get(&1).unwrap(), &mut rng1).unwrap();
        let (_nonces2, commitment2) =
            commit_with_rng(key_packages.get(&2).unwrap(), &mut rng2).unwrap();

        let tampered_commitment = FrostSigningCommitments {
            participant: 1,
            bytes: commitment2.bytes.clone(),
        };
        let signing_package = signing_package(
            public_key_package,
            &BTreeMap::from([(1, tampered_commitment), (2, commitment2)]),
            b"tamper-detect",
        )
        .unwrap();

        let error = sign(&signing_package, nonces1, key_packages.get(&1).unwrap()).unwrap_err();
        assert!(matches!(error, CryptoError::FrostFailed(_)));
        assert!(error.to_string().contains("possible coordinator tampering"));
    }

    #[test]
    fn signing_nonces_bincode_roundtrip_is_rejected() {
        let (key_packages, _public_packages) = execute_dkg(2, 3);
        let mut rng = participant_rng(42);
        let (nonces, _commitments) =
            commit_with_rng(key_packages.get(&1).unwrap(), &mut rng).unwrap();
        let encoded = bincode::serialize(&nonces).expect("nonce serialization should succeed");
        let err = bincode::deserialize::<FrostSigningNonces>(&encoded).unwrap_err();
        assert!(
            err.to_string()
                .contains("deserialization is disabled to enforce single-use")
        );
    }

    #[test]
    fn signing_nonces_ciborium_roundtrip_is_rejected() {
        let (key_packages, _public_packages) = execute_dkg(2, 3);
        let mut rng = participant_rng(43);
        let (nonces, _commitments) =
            commit_with_rng(key_packages.get(&1).unwrap(), &mut rng).unwrap();

        let mut encoded = Vec::new();
        ciborium::into_writer(&nonces, &mut encoded).expect("nonce serialization should succeed");

        let err =
            ciborium::de::from_reader::<FrostSigningNonces, _>(encoded.as_slice()).unwrap_err();
        assert!(
            err.to_string()
                .contains("deserialization is disabled to enforce single-use")
        );
    }

    #[test]
    fn aggregate_rejects_missing_signature_share() {
        let message = b"dropout";
        let (key_packages, public_packages) = execute_dkg(2, 3);
        let public_key_package = public_packages.get(&1).unwrap();
        let mut commitment_map = BTreeMap::new();
        let mut nonces = BTreeMap::new();

        for participant in [1u16, 2u16] {
            let mut rng = participant_rng(participant + 200);
            let (signing_nonces, commitments) =
                commit_with_rng(key_packages.get(&participant).unwrap(), &mut rng).unwrap();
            nonces.insert(participant, signing_nonces);
            commitment_map.insert(participant, commitments);
        }

        let signing_package =
            signing_package(public_key_package, &commitment_map, message).unwrap();
        let first_share = sign(
            &signing_package,
            nonces.remove(&1).unwrap(),
            key_packages.get(&1).unwrap(),
        )
        .unwrap();
        let signature_shares = BTreeMap::from([(1, first_share)]);

        let error = aggregate(&signing_package, &signature_shares, public_key_package).unwrap_err();
        assert!(matches!(error, CryptoError::FrostFailed(_)));
        assert!(
            error
                .to_string()
                .contains("missing signature shares from participants [2]")
        );
    }

    #[test]
    fn key_package_validate_accepts_well_formed_dkg_output() {
        let (key_packages, _public_packages) = execute_dkg(2, 3);
        for participant in 1..=3 {
            key_packages
                .get(&participant)
                .unwrap()
                .validate()
                .expect("DKG-produced key package must validate");
        }
    }

    #[test]
    fn key_package_validate_rejects_mismatched_signing_share() {
        let (key_packages, _public_packages) = execute_dkg(2, 3);
        let mut tampered = key_packages.get(&1).unwrap().clone();
        let other_verifying = key_packages.get(&2).unwrap().verifying_share().clone();
        tampered.verifying_share = other_verifying;

        let err = tampered.validate().unwrap_err();
        assert!(matches!(err, CryptoError::FrostFailed(_)));
        assert!(
            err.to_string()
                .contains("signing share does not match verifying share")
        );
    }

    #[test]
    fn public_key_package_validate_accepts_well_formed_dkg_output() {
        let (_key_packages, public_packages) = execute_dkg(2, 3);
        public_packages
            .get(&1)
            .unwrap()
            .validate()
            .expect("DKG-produced public key package must validate");
    }

    #[test]
    fn public_key_package_validate_rejects_mismatched_group_public_key() {
        let (_keys_a, public_a) = execute_dkg(2, 3);
        let (_keys_b, public_b) = execute_dkg(2, 4);
        let mut tampered = public_a.get(&1).unwrap().clone();
        tampered.group_public_key = public_b.get(&1).unwrap().group_public_key().clone();

        let err = tampered.validate().unwrap_err();
        assert!(matches!(err, CryptoError::FrostFailed(_)));
        assert!(
            err.to_string()
                .contains("does not match Lagrange aggregate")
        );
    }

    #[test]
    fn public_key_package_validate_rejects_swapped_verifying_share() {
        let (_keys_a, public_a) = execute_dkg(2, 3);
        let (_keys_b, public_b) = execute_dkg(2, 4);
        let mut tampered = public_a.get(&1).unwrap().clone();
        let other_share = public_b
            .get(&1)
            .unwrap()
            .verifying_shares()
            .get(&1)
            .unwrap()
            .clone();
        tampered.verifying_shares.insert(1, other_share);

        let err = tampered.validate().unwrap_err();
        assert!(matches!(err, CryptoError::FrostFailed(_)));
    }
}
