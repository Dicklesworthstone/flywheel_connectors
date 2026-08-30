//! Lattice-trapdoor capability delegation — policy-layer verifier
//! (br-kyopb.1.3 trait + br-kyopb.1.3.2 production wiring).
//!
//! This module is the **policy-layer abstraction** for the V4 lattice-
//! trapdoor capability scheme. The cryptographic primitives
//! (`TrapGen` / `Delegate` / `SamplePre` / `Verify`) live in
//! [`fcp_crypto_pq`] (br-kyopb.1.3.1 scaffolded them). The Lean 4
//! soundness proof is tracked separately; this module owns the
//! policy/dispatcher verifier contract.
//!
//! ## Why this lives in policy
//!
//! Host-side code (admission gates, audit-event assembly, dispatcher
//! verification pipelines) needs a stable policy abstraction over the
//! cryptographic primitives. The crypto crate owns `TrapGen` / `Delegate` /
//! `SamplePre` / `Verify`; this module composes those primitives with FCP's
//! certificate trust set, zone/period validity, request binding, and
//! operator-facing error taxonomy.
//!
//! ## Status
//!
//! Two trait implementations ship in this module:
//!
//! - [`UnimplementedLatticeDelegationVerifier`] — a no-trust-set
//!   sentinel that returns [`LatticeDelegationError::NotImplemented`]
//!   on every call. Use this on hosts where V4 is not activated.
//! - [`LatticeDelegationVerifierImpl`] — the production verifier wired
//!   to [`fcp_crypto_pq`]. Performs the **full structural check chain**
//!   (unknown-cert / zone-mismatch / operation-principal mismatch /
//!   period-bounds / parent-chain walk / request-binding hash /
//!   preimage-encoding) before invoking the cryptographic verification
//!   equation.
//!
//! ## Composition with the rest of the security chain
//!
//! At verification time, a [`LatticeDelegationVerifier`] runs in the
//! **same canonical pipeline slot** as the V3 capability-token
//! verifier (`EnforcementCheckId::CapabilityVerify`) — they are
//! mutually exclusive per-token (a token is either V3-CWT or
//! V4-lattice, never both, distinguished by an envelope tag). A V4
//! token that passes `verify_sub_token` still flows through the
//! downstream checks (`DeploymentTier`, `RevocationCascade`,
//! `CapabilityConstraints`, etc.) just like a V3 token would.
//!
//! See bead `flywheel_connectors-kyopb.1.3` and the full design at
//! `docs/post-quantum/lattice_trapdoor_delegation.md`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use fcp_core::{OperationId, PrincipalId, ZoneId};
use fcp_crypto_pq as pq;

/// Inclusive Unix-millisecond time window during which a
/// [`DelegationCertificate`] is valid (br-kyopb.1.3 §3.4).
///
/// Verifiers MUST reject sub-tokens whose certificate's window does
/// not contain `now()`. The window is part of the signed delegation
/// transcript so a rogue issuance node cannot extend an expired
/// certificate's validity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationPeriod {
    /// Inclusive start (Unix ms).
    pub start_unix_ms: u64,
    /// Inclusive end (Unix ms).
    pub end_unix_ms: u64,
}

impl DelegationPeriod {
    /// Whether the period contains the supplied wall-clock time.
    #[must_use]
    pub const fn contains(&self, now_unix_ms: u64) -> bool {
        self.start_unix_ms <= now_unix_ms && now_unix_ms <= self.end_unix_ms
    }
}

/// Opaque content-addressed identifier for a [`DelegationCertificate`].
///
/// Computed via BLAKE3 over the certificate's canonical encoding —
/// schema is versioned by the `fcp_crypto_pq` representation profile. Audit consumers index `DelegationReceipts`
/// by this id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DelegationCertificateId(#[serde(with = "fcp_core::util::hex_or_bytes")] pub [u8; 32]);

impl DelegationCertificateId {
    /// Construct from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase-hex rendering.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// Public material of one node in the lattice-trapdoor delegation
/// tree (br-kyopb.1.3 §3.3 layer 1 or layer 2).
///
/// Holds:
///
/// - `cert_id` — content-addressed identifier
/// - `zone_id` — the zone this delegation authorizes for
/// - `period` — the time window this delegation is valid for
/// - `parent_cert_id` — `None` for root, `Some(...)` for layers 1+
/// - `public_key` — verifier-computable `A_zp` material from
///   `fcp_crypto_pq`
///
/// The trapdoor itself (`T_zp`) is held offline by the issuance
/// node and NEVER appears in this struct.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationCertificate {
    /// Content-addressed identifier.
    pub cert_id: DelegationCertificateId,
    /// Zone this certificate authorizes minting for.
    pub zone_id: ZoneId,
    /// Time window the certificate is valid in.
    pub period: DelegationPeriod,
    /// Parent certificate this one was derived from. `None` only for
    /// the root certificate (the master trapdoor's public companion).
    pub parent_cert_id: Option<DelegationCertificateId>,
    /// Verifier-computable public key for this zone/period delegation.
    pub public_key: pq::ZonePeriodPublicKey,
}

/// Layer-3 sub-token (br-kyopb.1.3 §3.3).
///
/// This is what a client carries on each invocation. Wire format is a
/// content-addressed compact envelope; the preimage byte length is derived
/// from the verifier's `fcp_crypto_pq::LatticeParams` profile.
///
/// Holds:
///
/// - `cert_id` — which certificate's trapdoor minted this sub-token
/// - `op_id` + `principal_id` — the operation + principal this token
///   binds to (encoded into the verification matrix `A_op`)
/// - `request_descriptor_hash` — what the short-vector pre-image
///   solves (binds the token to one specific request)
/// - `preimage` — the short vector `s` such that `A_op · s = c mod q`
///
/// All four fields are part of the verification computation; mutating
/// any of them invalidates the token under `verify_sub_token`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatticeSubToken {
    /// Certificate id this sub-token chains to.
    pub cert_id: DelegationCertificateId,
    /// Operation the token authorizes.
    pub op_id: OperationId,
    /// Principal the token is bound to.
    pub principal_id: PrincipalId,
    /// 32-byte request-descriptor hash (BLAKE3-keyed over the
    /// canonical request descriptor — same shape as
    /// `RequestDescriptorHash` in `fcp-evidence`).
    #[serde(with = "fcp_core::util::hex_or_bytes")]
    pub request_descriptor_hash: [u8; 32],
    /// Compact-encoded short-vector pre-image. Encoding length is
    /// `fcp_crypto_pq::LatticeParams::preimage_encoded_bytes()`.
    pub preimage_bytes: Vec<u8>,
}

/// Outcome of [`LatticeDelegationVerifier::verify_sub_token`] on success.
///
/// A separate type from `()` so future audit consumers can
/// carry the reconstructed verification context (matrix dimensions,
/// detected delegation depth, period observed at verify time) without
/// changing the trait return type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LatticeVerificationReceipt {
    /// Certificate id the verifier reconstructed `A_op` from.
    pub cert_id: DelegationCertificateId,
    /// Trust-set digest used when checking
    /// [`LatticeSubToken::request_descriptor_hash`].
    pub trust_set_id: [u8; 32],
    /// Hash of the request-binding tuple accepted by the verifier.
    pub request_descriptor_hash: [u8; 32],
    /// Period the verifier observed at verification time. Useful for
    /// audit consumers that want to log "token was valid at
    /// `verified_at_unix_ms` because `period.contains(verified_at)`."
    pub period: DelegationPeriod,
    /// Wall-clock time at verification (Unix ms).
    pub verified_at_unix_ms: u64,
}

/// Errors returned by [`LatticeDelegationVerifier`] implementations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LatticeDelegationError {
    /// Trait method has no concrete implementation yet. Callers MUST
    /// treat this as "fall back to V3 ML-DSA path" — it is NOT an
    /// operational failure. See module docs.
    #[error("lattice-trapdoor delegation not yet implemented (kyopb.1.3.1-1.3.4 pending)")]
    NotImplemented,
    /// Sub-token references a certificate the verifier does not hold.
    #[error("delegation certificate {cert_id} not in trust set")]
    UnknownCertificate { cert_id: String },
    /// Sub-token's certificate window does not contain `now()`.
    #[error(
        "sub-token outside delegation period: now {now_unix_ms} not in [{start_unix_ms}, {end_unix_ms}]"
    )]
    OutsidePeriod {
        now_unix_ms: u64,
        start_unix_ms: u64,
        end_unix_ms: u64,
    },
    /// Matrix-vector verification failed: `A_op · s ≠ c mod q`.
    #[error("lattice verification equation failed for cert {cert_id}")]
    VerificationEquationFailed { cert_id: String },
    /// Pre-image norm exceeds the short-vector bound. A long
    /// pre-image proves the signer did NOT hold a trapdoor (anyone
    /// can find a long pre-image; only trapdoor-holders find short
    /// ones). Same security property the soundness theorem rests on.
    #[error("pre-image norm exceeds short-vector bound for cert {cert_id}")]
    PreimageTooLong { cert_id: String },
    /// Zone-id mismatch between sub-token's certificate and the
    /// request's zone — the certificate was minted for a different
    /// zone than the token is being used in.
    #[error(
        "zone mismatch: certificate zone {cert_zone} does not match request zone {request_zone}"
    )]
    ZoneMismatch {
        cert_zone: String,
        request_zone: String,
    },
    /// Certificate's parent chain references a cert not in the trust
    /// set — the delegation tree is incomplete relative to the
    /// verifier's view.
    #[error("delegation chain incomplete: missing parent for cert {cert_id}")]
    IncompleteDelegationChain { cert_id: String },
    /// Delegation chain exceeded the verifier's maximum-depth bound.
    /// This is a `DoS` defense — a malicious issuance node could
    /// otherwise produce arbitrarily long chains and exhaust the
    /// verifier's stack/CPU walking them. The bound is set from the
    /// `depth` field of the lattice parameters profile.
    #[error("delegation chain too deep: observed {observed}, max {max}")]
    ChainTooDeep { observed: u8, max: u8 },
    /// Sub-token's `preimage_bytes` length does not match the wire
    /// format expected by the cryptographic verifier (currently 65,536
    /// bytes for the `LatticeParams::V4_REFERENCE` profile). Returned
    /// as a length-mismatch failure rather than a cryptographic
    /// failure, so audit consumers can distinguish wire corruption
    /// from a genuine forgery attempt.
    #[error("preimage bytes length mismatch: cert {cert_id} expected {expected}, got {got}")]
    PreimageEncodingMismatch {
        cert_id: String,
        expected: usize,
        got: usize,
    },
    /// The lattice parameters bound into the verifier do not match the
    /// parameters bound into the certificate. Indicates a configuration
    /// error (different V4 profiles in play) rather than a forgery.
    #[error(
        "lattice parameter mismatch: verifier configured for n={verifier_n}, certificate expects n={cert_n}"
    )]
    ParameterMismatch { verifier_n: u32, cert_n: u32 },
    /// Operation-id mismatch between the presented sub-token and the
    /// dispatcher request. Hashes are logged rather than raw operation
    /// names to keep evidence redaction-safe.
    #[error(
        "operation mismatch: token operation hash {token_operation_hash} does not match request operation hash {request_operation_hash}"
    )]
    OperationMismatch {
        token_operation_hash: String,
        request_operation_hash: String,
    },
    /// Principal-id mismatch between the presented sub-token and the
    /// dispatcher request. Hashes are logged rather than raw principal
    /// identifiers to keep evidence redaction-safe.
    #[error(
        "principal mismatch: token principal hash {token_principal_hash} does not match request principal hash {request_principal_hash}"
    )]
    PrincipalMismatch {
        token_principal_hash: String,
        request_principal_hash: String,
    },
    /// Certificate public key does not match the policy-layer
    /// certificate envelope.
    #[error("certificate public key mismatch for cert {cert_id}: {reason}")]
    CertificatePublicKeyMismatch { cert_id: String, reason: String },
    /// Sub-token request binding does not match the verifier's
    /// zone/period/operation/principal/certificate/trust-set tuple.
    #[error(
        "request binding mismatch for cert {cert_id}: expected request descriptor hash {expected_hash}, got {got_hash}"
    )]
    RequestBindingMismatch {
        cert_id: String,
        expected_hash: String,
        got_hash: String,
    },
}

/// The policy-layer abstraction over lattice-trapdoor capability
/// verification (br-kyopb.1.3).
///
/// Cryptographic primitives live in `fcp-crypto-pq`. The trait is
/// exposed here in fcp-policy because
/// capability-token verification is a policy concern (not a crypto
/// concern) — the crypto layer provides primitives; the policy layer
/// composes them with the rest of the enforcement chain.
///
/// Implementations MUST be `Send + Sync` so a single verifier can
/// serve concurrent dispatcher requests across the host's worker
/// threads.
pub trait LatticeDelegationVerifier: Send + Sync {
    /// Verify a [`LatticeSubToken`] against the verifier's
    /// trust set of [`DelegationCertificate`]s and the supplied
    /// `now_unix_ms` wall-clock time.
    ///
    /// On success, returns a [`LatticeVerificationReceipt`] that
    /// downstream audit consumers can attach to the per-request
    /// audit event.
    ///
    /// # Errors
    ///
    /// Returns the appropriate [`LatticeDelegationError`] variant on
    /// any verification failure. STUB IMPLEMENTATIONS MUST RETURN
    /// `NotImplemented`; CALLERS MUST treat that variant as "fall
    /// back to V3 ML-DSA," NOT as an operational failure.
    fn verify_sub_token(
        &self,
        sub_token: &LatticeSubToken,
        request_zone: &ZoneId,
        request_operation: &OperationId,
        request_principal: &PrincipalId,
        now_unix_ms: u64,
    ) -> Result<LatticeVerificationReceipt, LatticeDelegationError>;

    /// Whether this verifier holds a trust-set entry for the named
    /// certificate id.
    ///
    /// Stub implementations return `false`.
    fn has_certificate(&self, cert_id: &DelegationCertificateId) -> bool;
}

/// Stub implementation that always returns
/// [`LatticeDelegationError::NotImplemented`].
///
/// Hosts that want V4 lattice support MUST configure
/// [`LatticeDelegationVerifierImpl`] with a real trust set. Keep this
/// sentinel for hosts/profiles where V4 is intentionally inactive.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnimplementedLatticeDelegationVerifier;

impl LatticeDelegationVerifier for UnimplementedLatticeDelegationVerifier {
    fn verify_sub_token(
        &self,
        _sub_token: &LatticeSubToken,
        _request_zone: &ZoneId,
        _request_operation: &OperationId,
        _request_principal: &PrincipalId,
        _now_unix_ms: u64,
    ) -> Result<LatticeVerificationReceipt, LatticeDelegationError> {
        Err(LatticeDelegationError::NotImplemented)
    }

    fn has_certificate(&self, _cert_id: &DelegationCertificateId) -> bool {
        false
    }
}

// ── Production Verifier (br-kyopb.1.3.2) ──────────────────────────────────

/// Production verifier that delegates the cryptographic check to
/// [`fcp_crypto_pq::verify`] (br-kyopb.1.3.2 wiring).
///
/// Holds an in-memory trust set of [`DelegationCertificate`]s indexed
/// by [`DelegationCertificateId`] for `O(1)` lookup, plus the lattice
/// parameter profile to use when constructing the cryptographic
/// verification call.
///
/// ## Verification flow
///
/// 1. Look up the leaf certificate by [`LatticeSubToken::cert_id`]
///    → [`LatticeDelegationError::UnknownCertificate`] on miss.
/// 2. Check `request_zone == leaf.zone_id`
///    → [`LatticeDelegationError::ZoneMismatch`].
/// 3. Check `leaf.period.contains(now_unix_ms)`
///    → [`LatticeDelegationError::OutsidePeriod`].
/// 4. Walk the parent chain from leaf to root, asserting each ancestor
///    exists in the trust set AND its period contains `now_unix_ms`,
///    capped at `params.depth` hops to bound `DoS` exposure
///    → [`LatticeDelegationError::IncompleteDelegationChain`] /
///    [`LatticeDelegationError::OutsidePeriod`] /
///    [`LatticeDelegationError::ChainTooDeep`].
/// 5. Validate the preimage byte-length matches the wire format
///    → [`LatticeDelegationError::PreimageEncodingMismatch`].
/// 6. Construct the [`fcp_crypto_pq`] view of the certificate and
///    invoke [`fcp_crypto_pq::verify`]. Map crypto-layer errors to
///    policy-layer error variants (preserving operator-readable
///    `cert_id` hex in each).
///
/// All structural checks run **before** the cryptographic call, so
/// malformed or replayed tokens fail before the expensive verification
/// equation whenever the policy envelope is already inconsistent.
#[derive(Debug, Clone)]
pub struct LatticeDelegationVerifierImpl {
    certificates: HashMap<DelegationCertificateId, DelegationCertificate>,
    params: pq::LatticeParams,
}

impl LatticeDelegationVerifierImpl {
    /// Construct an empty verifier configured for `params`. The trust
    /// set starts empty; populate it via [`Self::add_certificate`] or
    /// [`Self::with_certificates`].
    #[must_use]
    pub fn empty(params: pq::LatticeParams) -> Self {
        Self {
            certificates: HashMap::new(),
            params,
        }
    }

    /// Construct a verifier with a pre-populated trust set.
    ///
    /// Later inserts win over earlier ones if duplicate `cert_id`s
    /// appear (last-write-wins). Production callers should ensure
    /// uniqueness at the manifest layer.
    #[must_use]
    pub fn with_certificates(
        params: pq::LatticeParams,
        certificates: impl IntoIterator<Item = DelegationCertificate>,
    ) -> Self {
        let mut v = Self::empty(params);
        for cert in certificates {
            v.add_certificate(cert);
        }
        v
    }

    /// Insert one certificate into the trust set. Replaces any prior
    /// entry with the same `cert_id`.
    pub fn add_certificate(&mut self, cert: DelegationCertificate) {
        self.certificates.insert(cert.cert_id, cert);
    }

    /// Number of certificates currently in the trust set.
    #[must_use]
    pub fn certificate_count(&self) -> usize {
        self.certificates.len()
    }

    /// The lattice parameters this verifier is configured against.
    #[must_use]
    pub const fn params(&self) -> pq::LatticeParams {
        self.params
    }

    /// Stable digest of the loaded certificate trust set.
    ///
    /// The request-binding hash includes this digest so a sub-token
    /// minted under one verifier trust set cannot be replayed against a
    /// verifier with different certificate material.
    #[must_use]
    pub fn trust_set_id(&self) -> [u8; 32] {
        let mut entries = self
            .certificates
            .values()
            .map(|cert| {
                let crypto_period = Self::period_to_crypto(cert.period);
                let mut entry = Vec::with_capacity(184);
                entry.extend_from_slice(cert.cert_id.as_bytes());
                entry.extend_from_slice(&Self::zone_to_crypto(&cert.zone_id));
                entry.extend_from_slice(&crypto_period.start_secs.to_le_bytes());
                entry.extend_from_slice(&crypto_period.end_secs.to_le_bytes());
                entry.extend_from_slice(&cert.public_key.hash);
                entry.extend_from_slice(&cert.public_key.zone_id);
                entry.extend_from_slice(&cert.public_key.period.start_secs.to_le_bytes());
                entry.extend_from_slice(&cert.public_key.period.end_secs.to_le_bytes());
                if let Some(parent) = cert.parent_cert_id {
                    entry.extend_from_slice(parent.as_bytes());
                } else {
                    entry.extend_from_slice(&[0_u8; 32]);
                }
                entry
            })
            .collect::<Vec<_>>();
        entries.sort();

        let mut h = blake3::Hasher::new();
        h.update(b"fcp-policy/lattice-trust-set-v1|");
        h.update(&self.params.n.to_le_bytes());
        h.update(&self.params.m.to_le_bytes());
        h.update(&self.params.q.to_le_bytes());
        h.update(&self.params.depth.to_le_bytes());
        for entry in entries {
            h.update(&(entry.len() as u64).to_le_bytes());
            h.update(&entry);
        }
        *h.finalize().as_bytes()
    }

    /// Bridge a policy-layer [`DelegationPeriod`] (Unix ms, inclusive
    /// upper bound) into the crypto-layer
    /// [`pq::DelegationPeriod`] (Unix seconds, exclusive upper bound).
    ///
    /// Conversion preserves the inclusive-end semantics: if
    /// `policy.contains(now_unix_ms)` then
    /// `crypto.contains(now_unix_ms / 1000)` (proven by the `+ 1`
    /// after flooring, which lifts the exclusive crypto upper to be
    /// strictly above any flooring of the inclusive policy upper).
    #[must_use]
    pub const fn period_to_crypto(period: DelegationPeriod) -> pq::DelegationPeriod {
        pq::DelegationPeriod {
            start_secs: period.start_unix_ms / 1000,
            end_secs: period.end_unix_ms / 1000 + 1,
        }
    }

    /// Stable per-zone [u8; 32] identifier consumed by
    /// [`pq::operation_hash`] (which only sees opaque bytes). Computed
    /// as BLAKE3 over the zone's canonical string form, domain-
    /// separated by a fixed tag so any future hash-input changes to
    /// `operation_hash` won't collide with this projection.
    #[must_use]
    pub fn zone_to_crypto(zone: &ZoneId) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"fcp-policy/lattice-zone-projection-v0|");
        h.update(zone.as_str().as_bytes());
        *h.finalize().as_bytes()
    }

    /// Compute the policy-layer request binding a sub-token must carry.
    ///
    /// This binds the token to the exact policy tuple the dispatcher is about
    /// to evaluate. The cryptographic `operation_hash` binds zone/period/op
    /// and principal to the preimage equation; this policy hash additionally
    /// binds certificate identity, public-key binding hash, and the verifier's
    /// trust set.
    #[must_use]
    pub fn request_descriptor_hash(
        cert_id: &DelegationCertificateId,
        request_zone: &ZoneId,
        period: DelegationPeriod,
        request_operation: &OperationId,
        request_principal: &PrincipalId,
        public_key_hash: &[u8; 32],
        trust_set_id: &[u8; 32],
    ) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"fcp-policy/lattice-request-binding-v1|");
        h.update(cert_id.as_bytes());
        h.update(&Self::zone_to_crypto(request_zone));
        let crypto_period = Self::period_to_crypto(period);
        h.update(&crypto_period.start_secs.to_le_bytes());
        h.update(&crypto_period.end_secs.to_le_bytes());
        h.update(&(request_operation.as_str().len() as u64).to_le_bytes());
        h.update(request_operation.as_str().as_bytes());
        h.update(&(request_principal.as_str().len() as u64).to_le_bytes());
        h.update(request_principal.as_str().as_bytes());
        h.update(public_key_hash);
        h.update(trust_set_id);
        *h.finalize().as_bytes()
    }

    fn redacted_id_hash(domain: &'static [u8], value: &str) -> String {
        let mut h = blake3::Hasher::new();
        h.update(domain);
        h.update(value.as_bytes());
        hex::encode(h.finalize().as_bytes())
    }

    fn leaf_for_sub_token(
        &self,
        sub_token: &LatticeSubToken,
    ) -> Result<&DelegationCertificate, LatticeDelegationError> {
        self.certificates.get(&sub_token.cert_id).ok_or_else(|| {
            LatticeDelegationError::UnknownCertificate {
                cert_id: sub_token.cert_id.to_hex(),
            }
        })
    }

    fn validate_leaf_request(
        &self,
        leaf: &DelegationCertificate,
        request_zone: &ZoneId,
        now_unix_ms: u64,
    ) -> Result<(), LatticeDelegationError> {
        if &leaf.zone_id != request_zone {
            return Err(LatticeDelegationError::ZoneMismatch {
                cert_zone: leaf.zone_id.as_str().to_string(),
                request_zone: request_zone.as_str().to_string(),
            });
        }
        if leaf.public_key.params != self.params {
            return Err(LatticeDelegationError::ParameterMismatch {
                verifier_n: self.params.n,
                cert_n: leaf.public_key.params.n,
            });
        }
        if leaf.public_key.zone_id != Self::zone_to_crypto(&leaf.zone_id) {
            return Err(LatticeDelegationError::CertificatePublicKeyMismatch {
                cert_id: leaf.cert_id.to_hex(),
                reason: "public key zone projection does not match certificate zone".to_string(),
            });
        }
        if leaf.public_key.period != Self::period_to_crypto(leaf.period) {
            return Err(LatticeDelegationError::CertificatePublicKeyMismatch {
                cert_id: leaf.cert_id.to_hex(),
                reason: "public key period does not match certificate period".to_string(),
            });
        }
        Self::validate_certificate_period(leaf, now_unix_ms)
    }

    const fn validate_certificate_period(
        certificate: &DelegationCertificate,
        now_unix_ms: u64,
    ) -> Result<(), LatticeDelegationError> {
        if certificate.period.contains(now_unix_ms) {
            return Ok(());
        }
        Err(LatticeDelegationError::OutsidePeriod {
            now_unix_ms,
            start_unix_ms: certificate.period.start_unix_ms,
            end_unix_ms: certificate.period.end_unix_ms,
        })
    }

    fn validate_parent_chain(
        &self,
        leaf: &DelegationCertificate,
        now_unix_ms: u64,
    ) -> Result<(), LatticeDelegationError> {
        let mut hops: u8 = 0;
        let mut current = leaf;
        while let Some(parent_id) = &current.parent_cert_id {
            if hops >= self.params.depth {
                return Err(LatticeDelegationError::ChainTooDeep {
                    observed: hops.saturating_add(1),
                    max: self.params.depth,
                });
            }
            hops = hops.saturating_add(1);
            let parent = self.certificates.get(parent_id).ok_or_else(|| {
                LatticeDelegationError::IncompleteDelegationChain {
                    cert_id: current.cert_id.to_hex(),
                }
            })?;
            Self::validate_certificate_period(parent, now_unix_ms)?;
            current = parent;
        }
        Ok(())
    }

    fn validate_sub_token_request_binding(
        &self,
        leaf: &DelegationCertificate,
        sub_token: &LatticeSubToken,
        request_zone: &ZoneId,
        request_operation: &OperationId,
        request_principal: &PrincipalId,
    ) -> Result<[u8; 32], LatticeDelegationError> {
        if &sub_token.op_id != request_operation {
            return Err(LatticeDelegationError::OperationMismatch {
                token_operation_hash: Self::redacted_id_hash(
                    b"fcp-policy/lattice-token-operation-v1|",
                    sub_token.op_id.as_str(),
                ),
                request_operation_hash: Self::redacted_id_hash(
                    b"fcp-policy/lattice-request-operation-v1|",
                    request_operation.as_str(),
                ),
            });
        }
        if &sub_token.principal_id != request_principal {
            return Err(LatticeDelegationError::PrincipalMismatch {
                token_principal_hash: Self::redacted_id_hash(
                    b"fcp-policy/lattice-token-principal-v1|",
                    sub_token.principal_id.as_str(),
                ),
                request_principal_hash: Self::redacted_id_hash(
                    b"fcp-policy/lattice-request-principal-v1|",
                    request_principal.as_str(),
                ),
            });
        }

        let trust_set_id = self.trust_set_id();
        let expected = Self::request_descriptor_hash(
            &leaf.cert_id,
            request_zone,
            leaf.period,
            request_operation,
            request_principal,
            &leaf.public_key.hash,
            &trust_set_id,
        );
        if sub_token.request_descriptor_hash != expected {
            return Err(LatticeDelegationError::RequestBindingMismatch {
                cert_id: leaf.cert_id.to_hex(),
                expected_hash: hex::encode(expected),
                got_hash: hex::encode(sub_token.request_descriptor_hash),
            });
        }
        Ok(expected)
    }

    fn preimage_for_sub_token(
        &self,
        sub_token: &LatticeSubToken,
        leaf: &DelegationCertificate,
    ) -> Result<pq::LatticePreimage, LatticeDelegationError> {
        let expected = self.params.preimage_encoded_bytes().map_err(|_| {
            LatticeDelegationError::ParameterMismatch {
                verifier_n: self.params.n,
                cert_n: self.params.n,
            }
        })?;
        if sub_token.preimage_bytes.len() != expected {
            return Err(LatticeDelegationError::PreimageEncodingMismatch {
                cert_id: leaf.cert_id.to_hex(),
                expected,
                got: sub_token.preimage_bytes.len(),
            });
        }
        pq::LatticePreimage::from_encoded_bytes(self.params, sub_token.preimage_bytes.clone())
            .map_err(|_| LatticeDelegationError::PreimageEncodingMismatch {
                cert_id: leaf.cert_id.to_hex(),
                expected,
                got: sub_token.preimage_bytes.len(),
            })
    }

    fn verify_crypto_preimage(
        &self,
        leaf: &DelegationCertificate,
        sub_token: &LatticeSubToken,
        preimage: &pq::LatticePreimage,
        now_unix_ms: u64,
        request_descriptor_hash: [u8; 32],
    ) -> Result<LatticeVerificationReceipt, LatticeDelegationError> {
        let crypto_period = Self::period_to_crypto(leaf.period);
        let crypto_zone = Self::zone_to_crypto(&leaf.zone_id);
        let h = pq::operation_hash(
            &crypto_zone,
            crypto_period,
            sub_token.op_id.as_str().as_bytes(),
            sub_token.principal_id.as_str().as_bytes(),
        );
        let now_secs = now_unix_ms / 1000;

        pq::verify(&leaf.public_key, h, preimage, now_secs, self.params)
            .map(|()| LatticeVerificationReceipt {
                cert_id: leaf.cert_id,
                trust_set_id: self.trust_set_id(),
                request_descriptor_hash,
                period: leaf.period,
                verified_at_unix_ms: now_unix_ms,
            })
            .map_err(|err| self.map_crypto_error(leaf, &err))
    }

    fn map_crypto_error(
        &self,
        leaf: &DelegationCertificate,
        err: &pq::LatticePqError,
    ) -> LatticeDelegationError {
        match err {
            pq::LatticePqError::NotImplemented { .. }
            | pq::LatticePqError::UnsupportedPrimitiveRoute { .. } => {
                LatticeDelegationError::NotImplemented
            }
            pq::LatticePqError::VerificationEquationFailed => {
                LatticeDelegationError::VerificationEquationFailed {
                    cert_id: leaf.cert_id.to_hex(),
                }
            }
            pq::LatticePqError::PreimageNormTooLarge { .. } => {
                LatticeDelegationError::PreimageTooLong {
                    cert_id: leaf.cert_id.to_hex(),
                }
            }
            pq::LatticePqError::OutsidePeriod {
                now_secs: ns,
                start_secs,
                end_secs,
            } => LatticeDelegationError::OutsidePeriod {
                now_unix_ms: ns.saturating_mul(1000),
                start_unix_ms: start_secs.saturating_mul(1000),
                end_unix_ms: end_secs.saturating_mul(1000),
            },
            pq::LatticePqError::ParameterMismatch { caller, key } => {
                LatticeDelegationError::ParameterMismatch {
                    verifier_n: caller.n,
                    cert_n: key.n,
                }
            }
            pq::LatticePqError::InvalidEncodingLength { expected, got, .. } => {
                LatticeDelegationError::PreimageEncodingMismatch {
                    cert_id: leaf.cert_id.to_hex(),
                    expected: *expected,
                    got: *got,
                }
            }
            // Secret-bearing trapdoor representation failures should never
            // expose material names or rejection reasons through the policy
            // verifier surface. Classify them with the same config/profile
            // bucket as malformed public representation parameters.
            pq::LatticePqError::InvalidTrapdoorSecret { .. }
            | pq::LatticePqError::InvalidParameter { .. }
            | pq::LatticePqError::RepresentationTooLarge { .. } => {
                LatticeDelegationError::ParameterMismatch {
                    verifier_n: self.params.n,
                    cert_n: self.params.n,
                }
            }
            pq::LatticePqError::InvalidPeriod { .. } => {
                LatticeDelegationError::IncompleteDelegationChain {
                    cert_id: leaf.cert_id.to_hex(),
                }
            }
        }
    }
}

impl LatticeDelegationVerifier for LatticeDelegationVerifierImpl {
    fn verify_sub_token(
        &self,
        sub_token: &LatticeSubToken,
        request_zone: &ZoneId,
        request_operation: &OperationId,
        request_principal: &PrincipalId,
        now_unix_ms: u64,
    ) -> Result<LatticeVerificationReceipt, LatticeDelegationError> {
        // Step 1 — leaf lookup.
        let leaf = self.leaf_for_sub_token(sub_token)?;

        // Steps 2-3 — zone agreement, public-key envelope consistency,
        // and leaf-period containment.
        self.validate_leaf_request(leaf, request_zone, now_unix_ms)?;

        // Step 4 — parent-chain walk (depth-bounded).
        self.validate_parent_chain(leaf, now_unix_ms)?;

        // Step 5 — request binding.
        let request_descriptor_hash = self.validate_sub_token_request_binding(
            leaf,
            sub_token,
            request_zone,
            request_operation,
            request_principal,
        )?;

        // Step 6 — preimage encoding length.
        let preimage = self.preimage_for_sub_token(sub_token, leaf)?;

        // Step 7 — bridge into fcp-crypto-pq + invoke verify.
        self.verify_crypto_preimage(
            leaf,
            sub_token,
            &preimage,
            now_unix_ms,
            request_descriptor_hash,
        )
    }

    fn has_certificate(&self, cert_id: &DelegationCertificateId) -> bool {
        self.certificates.contains_key(cert_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert_id(byte: u8) -> DelegationCertificateId {
        DelegationCertificateId::from_bytes([byte; 32])
    }

    fn period(start: u64, end: u64) -> DelegationPeriod {
        DelegationPeriod {
            start_unix_ms: start,
            end_unix_ms: end,
        }
    }

    fn operation() -> OperationId {
        OperationId::new("op.test").unwrap()
    }

    fn principal() -> PrincipalId {
        PrincipalId::new("agent.test").unwrap()
    }

    fn public_key_for(
        byte: u8,
        zone: &ZoneId,
        period: DelegationPeriod,
    ) -> pq::ZonePeriodPublicKey {
        let hash = [byte; 32];
        pq::ZonePeriodPublicKey {
            hash,
            public_matrix: pq::PublicMatrixMaterial::fixture_seed_only(hash),
            zone_id: LatticeDelegationVerifierImpl::zone_to_crypto(zone),
            period: LatticeDelegationVerifierImpl::period_to_crypto(period),
            params: ref_params(),
        }
    }

    fn sub_token(cert_id_byte: u8) -> LatticeSubToken {
        LatticeSubToken {
            cert_id: cert_id(cert_id_byte),
            op_id: operation(),
            principal_id: principal(),
            request_descriptor_hash: [0_u8; 32],
            preimage_bytes: vec![0_u8; 8],
        }
    }

    #[test]
    fn delegation_period_contains_at_boundaries() {
        let p = period(100, 200);
        assert!(p.contains(100), "lower boundary inclusive");
        assert!(p.contains(150), "interior");
        assert!(p.contains(200), "upper boundary inclusive");
        assert!(!p.contains(99), "below lower");
        assert!(!p.contains(201), "above upper");
    }

    #[test]
    fn delegation_certificate_id_round_trips_through_serde() {
        let id = cert_id(0xAB);
        let json = serde_json::to_string(&id).unwrap();
        let back: DelegationCertificateId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn delegation_certificate_id_to_hex_is_lowercase() {
        let id = cert_id(0xAB);
        let hex = id.to_hex();
        assert_eq!(hex, "ab".repeat(32));
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn unimplemented_verifier_returns_not_implemented_for_verify() {
        let verifier = UnimplementedLatticeDelegationVerifier;
        let sub = sub_token(0x01);
        let zone = ZoneId::work();
        let err = verifier
            .verify_sub_token(&sub, &zone, &operation(), &principal(), 1_700_000_000_000)
            .expect_err("stub verifier MUST return NotImplemented");
        assert_eq!(err, LatticeDelegationError::NotImplemented);
    }

    #[test]
    fn unimplemented_verifier_has_no_certificates() {
        let verifier = UnimplementedLatticeDelegationVerifier;
        for byte in 0_u8..16 {
            assert!(
                !verifier.has_certificate(&cert_id(byte)),
                "stub verifier MUST hold zero certificates"
            );
        }
    }

    #[test]
    fn lattice_delegation_error_variants_round_trip_through_display() {
        // Pin the operator-readable Display strings for each variant —
        // operators reading audit logs / error responses depend on
        // these messages staying recognizable.
        let cases = [
            (
                LatticeDelegationError::NotImplemented,
                "not yet implemented",
            ),
            (
                LatticeDelegationError::UnknownCertificate {
                    cert_id: "deadbeef".to_string(),
                },
                "not in trust set",
            ),
            (
                LatticeDelegationError::OutsidePeriod {
                    now_unix_ms: 100,
                    start_unix_ms: 200,
                    end_unix_ms: 300,
                },
                "outside delegation period",
            ),
            (
                LatticeDelegationError::VerificationEquationFailed {
                    cert_id: "deadbeef".to_string(),
                },
                "verification equation failed",
            ),
            (
                LatticeDelegationError::PreimageTooLong {
                    cert_id: "deadbeef".to_string(),
                },
                "norm exceeds",
            ),
            (
                LatticeDelegationError::ZoneMismatch {
                    cert_zone: "z:work".to_string(),
                    request_zone: "z:public".to_string(),
                },
                "zone mismatch",
            ),
            (
                LatticeDelegationError::IncompleteDelegationChain {
                    cert_id: "deadbeef".to_string(),
                },
                "delegation chain incomplete",
            ),
            (
                LatticeDelegationError::OperationMismatch {
                    token_operation_hash: "hash-a".to_string(),
                    request_operation_hash: "hash-b".to_string(),
                },
                "operation mismatch",
            ),
            (
                LatticeDelegationError::PrincipalMismatch {
                    token_principal_hash: "hash-a".to_string(),
                    request_principal_hash: "hash-b".to_string(),
                },
                "principal mismatch",
            ),
            (
                LatticeDelegationError::RequestBindingMismatch {
                    cert_id: "deadbeef".to_string(),
                    expected_hash: "hash-a".to_string(),
                    got_hash: "hash-b".to_string(),
                },
                "request binding mismatch",
            ),
        ];
        for (err, expected_substring) in cases {
            let s = err.to_string();
            assert!(
                s.contains(expected_substring),
                "Display for {err:?} should contain {expected_substring:?}, got {s:?}"
            );
        }
    }

    #[test]
    fn lattice_sub_token_round_trips_through_json() {
        // Wire-format pin: while the concrete bytes layout for
        // `preimage_bytes` is profile-derived, but the JSON envelope
        // shape MUST stay stable so audit consumers can already key off it.
        let sub = sub_token(0x42);
        let json = serde_json::to_string(&sub).unwrap();
        let back = serde_json::from_str::<LatticeSubToken>(&json).unwrap();
        assert_eq!(sub, back);
    }

    #[test]
    fn delegation_certificate_round_trips_through_json() {
        let certificate = DelegationCertificate {
            cert_id: cert_id(0x51),
            zone_id: ZoneId::work(),
            period: period(1_700_000_000_000, 1_700_003_600_000),
            parent_cert_id: Some(cert_id(0x50)),
            public_key: public_key_for(
                0xAB,
                &ZoneId::work(),
                period(1_700_000_000_000, 1_700_003_600_000),
            ),
        };
        let json = serde_json::to_string(&certificate).unwrap();
        let back: DelegationCertificate = serde_json::from_str(&json).unwrap();
        assert_eq!(certificate, back);
        assert!(
            json.contains("\"public_key\"") && json.contains("\"hash\""),
            "public key remains explicit public certificate material"
        );
        assert_eq!(back.public_key.hash, [0xAB; 32]);
    }

    // ── Production verifier tests (br-kyopb.1.3.2) ───────────────────

    fn ref_params() -> pq::LatticeParams {
        pq::LatticeParams::V4_REFERENCE
    }

    fn ref_preimage_bytes() -> usize {
        ref_params()
            .preimage_encoded_bytes()
            .expect("reference profile has bounded preimage encoding")
    }

    fn cert(
        byte: u8,
        zone: ZoneId,
        period: DelegationPeriod,
        parent: Option<u8>,
    ) -> DelegationCertificate {
        let public_key = public_key_for(byte, &zone, period);
        DelegationCertificate {
            cert_id: cert_id(byte),
            zone_id: zone,
            period,
            parent_cert_id: parent.map(cert_id),
            public_key,
        }
    }

    fn sub_for(byte: u8) -> LatticeSubToken {
        LatticeSubToken {
            cert_id: cert_id(byte),
            op_id: operation(),
            principal_id: principal(),
            request_descriptor_hash: [0_u8; 32],
            preimage_bytes: vec![0_u8; ref_preimage_bytes()],
        }
    }

    fn bind_sub(
        verifier: &LatticeDelegationVerifierImpl,
        leaf: &DelegationCertificate,
        mut sub: LatticeSubToken,
    ) -> LatticeSubToken {
        sub.request_descriptor_hash = LatticeDelegationVerifierImpl::request_descriptor_hash(
            &leaf.cert_id,
            &leaf.zone_id,
            leaf.period,
            &sub.op_id,
            &sub.principal_id,
            &leaf.public_key.hash,
            &verifier.trust_set_id(),
        );
        sub
    }

    fn minted_token_fixture(
        params: pq::LatticeParams,
    ) -> (
        LatticeDelegationVerifierImpl,
        DelegationCertificate,
        LatticeSubToken,
        ZoneId,
        OperationId,
        PrincipalId,
        u64,
    ) {
        let zone = ZoneId::work();
        let operation = operation();
        let principal = principal();
        let policy_period = period(1_700_000_000_000, 1_700_003_600_000);
        let crypto_zone = LatticeDelegationVerifierImpl::zone_to_crypto(&zone);
        let crypto_period = LatticeDelegationVerifierImpl::period_to_crypto(policy_period);
        let entropy = pq::TrapGenEntropy::from_fixture_seed(
            b"fcp-policy/lattice-delegation-success-v1",
            [0x42; 32],
        );
        let (master_public, master_trapdoor) =
            pq::trap_gen_with_entropy(params, &entropy).expect("route TrapGen succeeds");
        let (public_key, trapdoor) = pq::delegate(
            &master_public,
            &master_trapdoor,
            crypto_zone,
            crypto_period,
            params,
        )
        .expect("route Delegate succeeds");
        let h = pq::operation_hash(
            &crypto_zone,
            crypto_period,
            operation.as_str().as_bytes(),
            principal.as_str().as_bytes(),
        );
        let preimage =
            pq::sample_pre(&public_key, &trapdoor, h, params).expect("route SamplePre succeeds");
        let leaf = DelegationCertificate {
            cert_id: cert_id(0x73),
            zone_id: zone.clone(),
            period: policy_period,
            parent_cert_id: None,
            public_key,
        };
        let verifier = LatticeDelegationVerifierImpl::with_certificates(params, [leaf.clone()]);
        let mut sub = LatticeSubToken {
            cert_id: leaf.cert_id,
            op_id: operation.clone(),
            principal_id: principal.clone(),
            request_descriptor_hash: [0_u8; 32],
            preimage_bytes: preimage.as_bytes().to_vec(),
        };
        sub = bind_sub(&verifier, &leaf, sub);
        (
            verifier,
            leaf,
            sub,
            zone,
            operation,
            principal,
            policy_period.start_unix_ms,
        )
    }

    #[test]
    fn impl_empty_starts_with_zero_certificates() {
        let v = LatticeDelegationVerifierImpl::empty(ref_params());
        assert_eq!(v.certificate_count(), 0);
        assert!(!v.has_certificate(&cert_id(0xAA)));
        assert_eq!(v.params(), ref_params());
    }

    #[test]
    fn impl_with_certificates_loads_trust_set() {
        let p = period(1_000_000, 2_000_000);
        let v = LatticeDelegationVerifierImpl::with_certificates(
            ref_params(),
            [
                cert(0x10, ZoneId::work(), p, None),
                cert(0x11, ZoneId::work(), p, Some(0x10)),
            ],
        );
        assert_eq!(v.certificate_count(), 2);
        assert!(v.has_certificate(&cert_id(0x10)));
        assert!(v.has_certificate(&cert_id(0x11)));
        assert!(!v.has_certificate(&cert_id(0x99)));
    }

    #[test]
    fn impl_rejects_unknown_certificate() {
        let v = LatticeDelegationVerifierImpl::empty(ref_params());
        let err = v
            .verify_sub_token(
                &sub_for(0xAA),
                &ZoneId::work(),
                &operation(),
                &principal(),
                1_500_000,
            )
            .expect_err("unknown cert MUST be rejected");
        match err {
            LatticeDelegationError::UnknownCertificate { cert_id } => {
                assert_eq!(cert_id, "aa".repeat(32));
            }
            other => assert!(
                matches!(other, LatticeDelegationError::UnknownCertificate { .. }),
                "expected UnknownCertificate, got {other:?}"
            ),
        }
    }

    #[test]
    fn impl_rejects_zone_mismatch() {
        let p = period(1_000_000, 2_000_000);
        let v = LatticeDelegationVerifierImpl::with_certificates(
            ref_params(),
            [cert(0x10, ZoneId::work(), p, None)],
        );
        let sub = sub_for(0x10);
        let err = v
            .verify_sub_token(
                &sub,
                &ZoneId::public(),
                &operation(),
                &principal(),
                1_500_000,
            )
            .expect_err("zone mismatch MUST be rejected");
        match err {
            LatticeDelegationError::ZoneMismatch {
                cert_zone,
                request_zone,
            } => {
                assert_eq!(cert_zone, ZoneId::work().as_str());
                assert_eq!(request_zone, ZoneId::public().as_str());
            }
            other => assert!(
                matches!(other, LatticeDelegationError::ZoneMismatch { .. }),
                "expected ZoneMismatch, got {other:?}"
            ),
        }
    }

    #[test]
    fn impl_rejects_outside_period_below_lower() {
        let p = period(1_000_000, 2_000_000);
        let v = LatticeDelegationVerifierImpl::with_certificates(
            ref_params(),
            [cert(0x10, ZoneId::work(), p, None)],
        );
        let err = v
            .verify_sub_token(
                &sub_for(0x10),
                &ZoneId::work(),
                &operation(),
                &principal(),
                500_000,
            )
            .expect_err("now < period.start MUST be rejected");
        match err {
            LatticeDelegationError::OutsidePeriod {
                now_unix_ms,
                start_unix_ms,
                end_unix_ms,
            } => {
                assert_eq!(now_unix_ms, 500_000);
                assert_eq!(start_unix_ms, 1_000_000);
                assert_eq!(end_unix_ms, 2_000_000);
            }
            other => assert!(
                matches!(other, LatticeDelegationError::OutsidePeriod { .. }),
                "expected OutsidePeriod, got {other:?}"
            ),
        }
    }

    #[test]
    fn impl_rejects_outside_period_above_upper() {
        let p = period(1_000_000, 2_000_000);
        let v = LatticeDelegationVerifierImpl::with_certificates(
            ref_params(),
            [cert(0x10, ZoneId::work(), p, None)],
        );
        let err = v
            .verify_sub_token(
                &sub_for(0x10),
                &ZoneId::work(),
                &operation(),
                &principal(),
                3_000_000,
            )
            .expect_err("now > period.end MUST be rejected");
        assert!(matches!(err, LatticeDelegationError::OutsidePeriod { .. }));
    }

    #[test]
    fn impl_rejects_incomplete_chain_when_parent_missing() {
        let p = period(1_000_000, 2_000_000);
        // Add the leaf, but NOT its parent (0xAA).
        let v = LatticeDelegationVerifierImpl::with_certificates(
            ref_params(),
            [cert(0xBB, ZoneId::work(), p, Some(0xAA))],
        );
        let err = v
            .verify_sub_token(
                &sub_for(0xBB),
                &ZoneId::work(),
                &operation(),
                &principal(),
                1_500_000,
            )
            .expect_err("missing parent MUST be rejected");
        match err {
            LatticeDelegationError::IncompleteDelegationChain { cert_id } => {
                assert_eq!(cert_id, "bb".repeat(32));
            }
            other => assert!(
                matches!(
                    other,
                    LatticeDelegationError::IncompleteDelegationChain { .. }
                ),
                "expected IncompleteDelegationChain, got {other:?}"
            ),
        }
    }

    #[test]
    fn impl_rejects_chain_when_ancestor_period_excludes_now() {
        let leaf_p = period(1_000_000, 2_000_000);
        let parent_p = period(0, 500_000); // Parent has already expired.
        let v = LatticeDelegationVerifierImpl::with_certificates(
            ref_params(),
            [
                cert(0xAA, ZoneId::work(), parent_p, None),
                cert(0xBB, ZoneId::work(), leaf_p, Some(0xAA)),
            ],
        );
        // now is inside the leaf's period but outside the parent's.
        let err = v
            .verify_sub_token(
                &sub_for(0xBB),
                &ZoneId::work(),
                &operation(),
                &principal(),
                1_500_000,
            )
            .expect_err("expired ancestor MUST be rejected");
        match err {
            LatticeDelegationError::OutsidePeriod {
                now_unix_ms,
                start_unix_ms,
                end_unix_ms,
            } => {
                assert_eq!(now_unix_ms, 1_500_000);
                assert_eq!(start_unix_ms, parent_p.start_unix_ms);
                assert_eq!(end_unix_ms, parent_p.end_unix_ms);
            }
            other => assert!(
                matches!(other, LatticeDelegationError::OutsidePeriod { .. }),
                "expected OutsidePeriod (parent), got {other:?}"
            ),
        }
    }

    #[test]
    fn impl_rejects_chain_too_deep() {
        // Build a chain longer than params.depth (4 for V4_REFERENCE).
        // Pattern: 0x01 -> 0x02 -> 0x03 -> 0x04 -> 0x05 -> 0x06 (5 hops).
        let p = period(0, 10_000_000);
        let mut certs = Vec::new();
        certs.push(cert(0x01, ZoneId::work(), p, None));
        for i in 2_u8..=6 {
            certs.push(cert(i, ZoneId::work(), p, Some(i - 1)));
        }
        let v = LatticeDelegationVerifierImpl::with_certificates(ref_params(), certs);
        let err = v
            .verify_sub_token(
                &sub_for(0x06),
                &ZoneId::work(),
                &operation(),
                &principal(),
                5_000_000,
            )
            .expect_err("chain longer than params.depth MUST be rejected");
        match err {
            LatticeDelegationError::ChainTooDeep { observed, max } => {
                assert!(
                    observed > max,
                    "observed {observed} should exceed max {max}"
                );
                assert_eq!(max, ref_params().depth);
            }
            other => assert!(
                matches!(other, LatticeDelegationError::ChainTooDeep { .. }),
                "expected ChainTooDeep, got {other:?}"
            ),
        }
    }

    #[test]
    fn impl_accepts_chain_at_max_depth() {
        // Exactly params.depth = 4 hops. The parent certificates are
        // policy trust-set structure; the leaf certificate carries real
        // verifier-computable public matrix material and a real preimage.
        let p = period(1_700_000_000_000, 1_700_003_600_000);
        let mut certs = Vec::new();
        certs.push(cert(0x01, ZoneId::work(), p, None));
        for i in 2_u8..=4 {
            certs.push(cert(i, ZoneId::work(), p, Some(i - 1)));
        }
        let (_, mut leaf, mut sub, zone, operation, principal, now) =
            minted_token_fixture(ref_params());
        leaf.parent_cert_id = Some(cert_id(0x04));
        certs.push(leaf.clone());
        let v = LatticeDelegationVerifierImpl::with_certificates(ref_params(), certs);
        sub = bind_sub(&v, &leaf, sub);
        let receipt = v
            .verify_sub_token(&sub, &zone, &operation, &principal, now)
            .expect("max-depth chain with real leaf material verifies");
        assert_eq!(receipt.cert_id, leaf.cert_id);
    }

    #[test]
    fn impl_rejects_preimage_encoding_length_mismatch() {
        let p = period(0, 10_000_000);
        let leaf = cert(0x10, ZoneId::work(), p, None);
        let v = LatticeDelegationVerifierImpl::with_certificates(ref_params(), [leaf.clone()]);
        let mut sub = sub_for(0x10);
        sub = bind_sub(&v, &leaf, sub);
        sub.preimage_bytes = vec![0_u8; 32]; // Wrong for V4_REFERENCE.
        let err = v
            .verify_sub_token(&sub, &ZoneId::work(), &operation(), &principal(), 5_000_000)
            .expect_err("wrong-length preimage MUST be rejected");
        match err {
            LatticeDelegationError::PreimageEncodingMismatch {
                cert_id,
                expected,
                got,
            } => {
                assert_eq!(cert_id, "10".repeat(32));
                assert_eq!(expected, ref_preimage_bytes());
                assert_eq!(got, 32);
            }
            other => assert!(
                matches!(
                    other,
                    LatticeDelegationError::PreimageEncodingMismatch { .. }
                ),
                "expected PreimageEncodingMismatch, got {other:?}"
            ),
        }
    }

    #[test]
    fn impl_happy_path_returns_receipt_for_supported_crypto_routes() {
        for params in [
            pq::LatticeParams::SMALL_TEST,
            pq::LatticeParams::V4_REFERENCE,
        ] {
            let (v, leaf, sub, zone, operation, principal, now) = minted_token_fixture(params);
            let receipt = v
                .verify_sub_token(&sub, &zone, &operation, &principal, now)
                .expect("supported lattice route verifies through fcp-policy");

            assert_eq!(receipt.cert_id, leaf.cert_id);
            assert_eq!(receipt.period, leaf.period);
            assert_eq!(receipt.verified_at_unix_ms, now);
            assert_eq!(receipt.trust_set_id, v.trust_set_id());
            assert_eq!(receipt.request_descriptor_hash, sub.request_descriptor_hash);
            assert_ne!(receipt.request_descriptor_hash, [0_u8; 32]);
        }
    }

    #[test]
    fn impl_rejects_operation_mismatch_before_crypto_verify() {
        let (v, _, sub, zone, _, principal, now) =
            minted_token_fixture(pq::LatticeParams::SMALL_TEST);
        let request_operation = OperationId::new("op.other").unwrap();
        let err = v
            .verify_sub_token(&sub, &zone, &request_operation, &principal, now)
            .expect_err("wrong operation must not reuse a lattice receipt");
        assert!(matches!(
            err,
            LatticeDelegationError::OperationMismatch { .. }
        ));
    }

    #[test]
    fn impl_rejects_principal_mismatch_before_crypto_verify() {
        let (v, _, sub, zone, operation, _, now) =
            minted_token_fixture(pq::LatticeParams::SMALL_TEST);
        let request_principal = PrincipalId::new("agent.other").unwrap();
        let err = v
            .verify_sub_token(&sub, &zone, &operation, &request_principal, now)
            .expect_err("wrong principal must not reuse a lattice receipt");
        assert!(matches!(
            err,
            LatticeDelegationError::PrincipalMismatch { .. }
        ));
    }

    #[test]
    fn impl_rejects_receipt_replay_after_trust_set_change() {
        let (_, leaf, sub, zone, operation, principal, now) =
            minted_token_fixture(pq::LatticeParams::SMALL_TEST);
        let mut extra = leaf.clone();
        extra.cert_id = cert_id(0x74);
        let replay_verifier = LatticeDelegationVerifierImpl::with_certificates(
            pq::LatticeParams::SMALL_TEST,
            [leaf, extra],
        );

        let err = replay_verifier
            .verify_sub_token(&sub, &zone, &operation, &principal, now)
            .expect_err("request binding includes the trust-set digest");
        assert!(matches!(
            err,
            LatticeDelegationError::RequestBindingMismatch { .. }
        ));
    }

    #[test]
    fn impl_rejects_certificate_public_key_envelope_mismatch() {
        let (v, mut leaf, mut sub, zone, operation, principal, now) =
            minted_token_fixture(pq::LatticeParams::SMALL_TEST);
        leaf.public_key.zone_id = LatticeDelegationVerifierImpl::zone_to_crypto(&ZoneId::public());
        let verifier = LatticeDelegationVerifierImpl::with_certificates(
            pq::LatticeParams::SMALL_TEST,
            [leaf.clone()],
        );
        sub = bind_sub(&v, &leaf, sub);

        let err = verifier
            .verify_sub_token(&sub, &zone, &operation, &principal, now)
            .expect_err("certificate public key must match the policy zone envelope");
        assert!(matches!(
            err,
            LatticeDelegationError::CertificatePublicKeyMismatch { .. }
        ));
    }

    #[test]
    fn impl_maps_invalid_trapdoor_secret_without_leaking_secret_context() {
        let v = LatticeDelegationVerifierImpl::empty(ref_params());
        let leaf = cert(0x10, ZoneId::work(), period(0, 10_000), None);
        let err = v.map_crypto_error(
            &leaf,
            &pq::LatticePqError::InvalidTrapdoorSecret {
                material: "basis-envelope coefficients",
                reason: "raw secret coefficient storage rejected",
            },
        );

        assert_eq!(
            err,
            LatticeDelegationError::ParameterMismatch {
                verifier_n: ref_params().n,
                cert_n: ref_params().n,
            }
        );
        let rendered = err.to_string();
        assert!(!rendered.contains("basis-envelope"));
        assert!(!rendered.contains("secret"));
        assert!(!rendered.contains("coefficient"));
    }

    #[test]
    fn impl_maps_unsupported_primitive_route_to_fallback() {
        let v = LatticeDelegationVerifierImpl::empty(ref_params());
        let leaf = cert(0x10, ZoneId::work(), period(0, 10_000), None);
        let err = v.map_crypto_error(
            &leaf,
            &pq::LatticePqError::UnsupportedPrimitiveRoute {
                primitive: "TrapGen",
                route_id: "fcp-pq/internal-route",
                profile: "V4_REFERENCE",
                reason: "larger profiles stay fail-closed",
            },
        );

        assert_eq!(err, LatticeDelegationError::NotImplemented);
    }

    #[test]
    fn impl_add_certificate_overwrites_duplicate_cert_id() {
        let p1 = period(0, 1_000_000);
        let p2 = period(2_000_000, 3_000_000);
        let mut v = LatticeDelegationVerifierImpl::empty(ref_params());
        v.add_certificate(cert(0x10, ZoneId::work(), p1, None));
        assert_eq!(v.certificate_count(), 1);
        v.add_certificate(cert(0x10, ZoneId::work(), p2, None));
        assert_eq!(
            v.certificate_count(),
            1,
            "same cert_id replaces, not duplicates"
        );
        // Verify the new period is the one used.
        let err = v
            .verify_sub_token(
                &sub_for(0x10),
                &ZoneId::work(),
                &operation(),
                &principal(),
                500_000,
            )
            .expect_err("now=500k is in p1 but NOT p2 (which won)");
        match err {
            LatticeDelegationError::OutsidePeriod {
                start_unix_ms,
                end_unix_ms,
                ..
            } => {
                assert_eq!(start_unix_ms, p2.start_unix_ms);
                assert_eq!(end_unix_ms, p2.end_unix_ms);
            }
            other => assert!(
                matches!(other, LatticeDelegationError::OutsidePeriod { .. }),
                "expected OutsidePeriod with p2 bounds, got {other:?}"
            ),
        }
    }

    #[test]
    fn period_to_crypto_preserves_inclusive_upper_bound() {
        // Pin the bridge invariant: if policy-layer
        // contains(now_unix_ms) then crypto-layer
        // contains(now_unix_ms / 1000).
        let p = DelegationPeriod {
            start_unix_ms: 1_000_500,
            end_unix_ms: 2_000_999, // Inclusive upper at 2000.999s.
        };
        let crypto = LatticeDelegationVerifierImpl::period_to_crypto(p);
        // policy.contains(2_000_999) is true (inclusive).
        // crypto.contains(2_000) MUST also be true.
        let now_secs = 2_000_999_u64 / 1000; // = 2000
        assert!(
            crypto.contains(now_secs),
            "crypto must include floor(end_unix_ms/1000) when policy includes end_unix_ms"
        );
        // Boundary check: floor(start_unix_ms / 1000) is included.
        assert!(
            crypto.contains(p.start_unix_ms / 1000),
            "crypto must include floor(start_unix_ms/1000)"
        );
    }

    #[test]
    fn zone_to_crypto_is_deterministic_and_zone_separated() {
        let h_work_a = LatticeDelegationVerifierImpl::zone_to_crypto(&ZoneId::work());
        let h_work_b = LatticeDelegationVerifierImpl::zone_to_crypto(&ZoneId::work());
        assert_eq!(h_work_a, h_work_b, "deterministic across calls");
        let h_public = LatticeDelegationVerifierImpl::zone_to_crypto(&ZoneId::public());
        assert_ne!(
            h_work_a, h_public,
            "different zones produce different hashes"
        );
        let h_owner = LatticeDelegationVerifierImpl::zone_to_crypto(&ZoneId::owner());
        assert_ne!(h_owner, h_work_a);
        assert_ne!(h_owner, h_public);
    }
}
