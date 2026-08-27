//! # FCP post-quantum cryptographic primitives — lattice-trapdoor delegation
//!
//! API scaffolding (br-kyopb.1.3.1) for the four lattice-trapdoor primitives
//! that back V4 capability delegation. The full design is documented in
//! `docs/post-quantum/lattice_trapdoor_delegation.md`.
//!
//! ## Status
//!
//! `trap_gen`, `delegate`, `sample_pre`, and `verify` now expose the reviewed
//! `fcp-internal-mp12-chkp-no-ffi-v1` route for profiles that the internal
//! arithmetic path explicitly supports. The current supported arithmetic
//! profiles are `SMALL_TEST` and `V4_REFERENCE`. `SMALL_TEST` uses a compact
//! dense relation for exhaustive checks; `V4_REFERENCE` uses the same public
//! material shape with a bounded sparse-`R` basis route so verifiers can
//! reconstruct the public matrix without trapdoor access.
//! This crate exists to pin the API contract that:
//!
//! - `fcp_policy::lattice_delegation::LatticeDelegationVerifier` (br-kyopb.1.3.2)
//!   will implement against,
//! - the Lean 4 formal proof (br-kyopb.1.3.3) will model, and
//! - the throughput benchmark (br-kyopb.1.3.4) will measure.
//!
//! Unsupported TrapGen/Delegate/SamplePre/Verify profiles return
//! [`LatticePqError::UnsupportedPrimitiveRoute`] instead of silently falling
//! back to deterministic fixture trapdoors. See
//! `docs/post-quantum/v3_v4_compatibility_ledger.md` for the cross-version
//! dispatch rules.
//!
//! ## API surface
//!
//! Four primitives, exactly mirroring §3 of the design doc:
//!
//! | Primitive    | Purpose                                                    |
//! | ------------ | ---------------------------------------------------------- |
//! | [`trap_gen`] | Setup-time: sample the master matrix `A_root` + trapdoor   |
//! | [`delegate`] | Issuance-time: derive `(A_zp, T_zp)` for `(zone, period)`  |
//! | [`sample_pre`]| Mint-time: produce a short preimage `e` such that `A·e≡h`  |
//! | [`verify`]   | Verify-time: check `A·e ≡ h (mod q)` and `‖e‖₂ ≤ B`        |
//!
//! The public-matrix fixture profile remains seed-backed: public matrices are
//! transmitted as 32-byte seeds and expanded under explicit memory bounds.
//! Secret trapdoors now sit behind a versioned representation envelope so the
//! current fixture seed bundles cannot be mistaken for production bases.
//! Sub-token preimages use profile-derived packed coefficient lengths rather
//! than the old fixed 64-byte scaffold.

#![forbid(unsafe_code)]
// nursery/pedantic style lints that newer nightlies fire on this unchanged code.
// Needed here rather than in Cargo.toml because this crate re-enables the groups
// with an inner attribute, which overrides the workspace lint table.
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::duration_suboptimal_units)]
#![allow(clippy::redundant_clone)]
#![allow(clippy::significant_drop_tightening)]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, OnceLock};

use rand::RngCore;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use thiserror::Error;
use zeroize::Zeroize;

// ── Parameters and representation profile ─────────────────────────────────

/// Current lattice representation profile version.
///
/// Version 2 keeps the version-1 public SHAKE seed fixtures stable, but wraps
/// secret trapdoor material in a basis-capable metadata envelope. The envelope
/// can carry fixture seed bundles today and a future reviewed basis envelope
/// without changing public matrix or token wire formats.
pub const LATTICE_REPRESENTATION_VERSION: u16 = 2;

/// Public matrix material representation version.
///
/// Version 1 distinguishes legacy fixture seed-only public keys from
/// verifier-computable route material that carries the public tail block needed
/// to reconstruct `A_zp` without trapdoor access.
pub const PUBLIC_MATRIX_MATERIAL_VERSION: u16 = 1;

/// Public SHAKE fixture compatibility generation.
///
/// This stays at version 1 so previously pinned public matrix fixtures keep
/// their deterministic hashes while the secret representation evolves.
pub const FIXTURE_SHAKE_COMPATIBILITY_VERSION: u16 = 1;

/// Reviewed primitive route selected by
/// `docs/post-quantum/lattice_primitive_route_packet_2026-05-08.md`.
pub const PRIMITIVE_ROUTE_ID: &str = "fcp-internal-mp12-chkp-no-ffi-v1";

/// Route revision for the internal no-FFI TrapGen/Delegate implementation.
pub const PRIMITIVE_ROUTE_REVISION: u16 = 1;

const MATRIX_SEED_BYTES: usize = 32;
const SECRET_SEED_BUNDLE_BYTES: usize = 96;
const TRAP_GEN_ENTROPY_BYTES: usize = 32;
const BASIS_ENVELOPE_MAGIC: &[u8] = b"fcp-pq-basis-v1";
const MAX_PUBLIC_MATRIX_EXPANDED_BYTES: usize = 64 * 1024 * 1024;
const MAX_PREIMAGE_ENCODED_BYTES: usize = 1024 * 1024;
const MAX_TRAPDOOR_SECRET_BYTES: usize = 1024 * 1024;
const V4_SPARSE_R_WEIGHT: u32 = 8;
const V4_ROW_XOF_CHUNK_COEFFS: usize = 1024;
const V4_VERIFY_PARALLEL_ROW_THRESHOLD: usize = 128;
const V4_ABAR_SELECTION_CACHE_ENTRIES: usize = 1;
const V4_COEFFICIENT_BYTES: usize = 4;

/// Lattice security parameters (§3.2 of the design doc).
///
/// These values drive matrix dimensions, coefficient widths, route support
/// shape, and centered-norm enforcement for the reviewed internal route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatticeParams {
    /// Module rank `n`.
    pub n: u32,
    /// Modulus `q`. Stored as `u64` to leave headroom for future profiles.
    pub q: u64,
    /// Number of lattice columns `m`.
    pub m: u32,
    /// Discrete-Gaussian width parameter `σ` (×100, fixed-point — avoids
    /// `f64` in the public API).
    pub sigma_x100: u32,
    /// Maximum delegation depth `L`.
    pub depth: u8,
}

impl LatticeParams {
    /// Small deterministic test profile. This is not a security profile; it is
    /// intentionally tiny so representation and arithmetic tests can exercise
    /// dimension logic without allocating the V4 reference matrix.
    pub const SMALL_TEST: Self = Self {
        n: 8,
        q: 257,
        m: 16,
        sigma_x100: 320,
        depth: 2,
    };

    /// Reference V4 profile: `n=512`, `q=2^32-5`, `m=16384`, `σ≈113`,
    /// `L=4` (~128-bit classical / Cat. 3 PQ security per the design
    /// doc §3.2).
    pub const V4_REFERENCE: Self = Self {
        n: 512,
        q: 4_294_967_291, // 2^32 - 5
        m: 16_384,
        sigma_x100: 11_300, // σ ≈ 113.0
        depth: 4,
    };

    /// Validate basic arithmetic and allocation invariants for this profile.
    ///
    /// This intentionally does not prove cryptographic strength; it enforces
    /// the representation boundary so malformed external profiles cannot drive
    /// divide-by-zero, overflow, or unbounded allocation paths.
    ///
    /// # Errors
    ///
    /// Returns [`LatticePqError::InvalidParameter`] for zero or otherwise
    /// malformed scalar parameters, or [`LatticePqError::RepresentationTooLarge`]
    /// when the profile would exceed the explicit allocation ceilings.
    pub fn validate(self) -> LatticePqResult<()> {
        if self.n == 0 {
            return Err(LatticePqError::InvalidParameter {
                field: "n",
                value: 0,
                reason: "lattice dimension must be non-zero",
            });
        }
        if self.m == 0 {
            return Err(LatticePqError::InvalidParameter {
                field: "m",
                value: 0,
                reason: "lattice width must be non-zero",
            });
        }
        if self.q < 2 {
            return Err(LatticePqError::InvalidParameter {
                field: "q",
                value: self.q,
                reason: "modulus must be at least 2",
            });
        }
        if self.sigma_x100 == 0 {
            return Err(LatticePqError::InvalidParameter {
                field: "sigma_x100",
                value: 0,
                reason: "Gaussian width must be non-zero",
            });
        }
        if self.depth == 0 {
            return Err(LatticePqError::InvalidParameter {
                field: "depth",
                value: 0,
                reason: "delegation depth must be non-zero",
            });
        }
        let _profile = self.representation_profile()?;
        Ok(())
    }

    /// Bytes required to store one coefficient modulo `q`.
    ///
    /// # Errors
    ///
    /// Returns [`LatticePqError::InvalidParameter`] when `q < 2`.
    ///
    /// # Panics
    ///
    /// Panics only on targets where `usize` cannot represent a `u32` bit count.
    pub fn coefficient_bytes(self) -> LatticePqResult<usize> {
        if self.q < 2 {
            return Err(LatticePqError::InvalidParameter {
                field: "q",
                value: self.q,
                reason: "modulus must be at least 2",
            });
        }
        let bits = u64::BITS - (self.q - 1).leading_zeros();
        Ok(usize::try_from(bits.div_ceil(8)).expect("u32 bit count fits in usize"))
    }

    /// Expanded public matrix byte count for `n × m` coefficients.
    ///
    /// # Errors
    ///
    /// Returns [`LatticePqError::InvalidParameter`] when `q < 2`, or
    /// [`LatticePqError::RepresentationTooLarge`] when the expanded matrix would
    /// exceed this crate's allocation ceiling.
    ///
    /// # Panics
    ///
    /// Panics only on targets where `usize` cannot represent a `u32` dimension.
    pub fn public_matrix_expanded_bytes(self) -> LatticePqResult<usize> {
        let coefficient_bytes = self.coefficient_bytes()?;
        checked_profile_product(
            "public_matrix",
            &[
                usize::try_from(self.n).expect("u32 n fits in usize"),
                usize::try_from(self.m).expect("u32 m fits in usize"),
                coefficient_bytes,
            ],
            MAX_PUBLIC_MATRIX_EXPANDED_BYTES,
        )
    }

    /// Packed byte count for a short-vector preimage in `Z_q^m`.
    ///
    /// # Errors
    ///
    /// Returns [`LatticePqError::InvalidParameter`] when `q < 2`, or
    /// [`LatticePqError::RepresentationTooLarge`] when the packed preimage would
    /// exceed this crate's allocation ceiling.
    ///
    /// # Panics
    ///
    /// Panics only on targets where `usize` cannot represent a `u32` dimension.
    pub fn preimage_encoded_bytes(self) -> LatticePqResult<usize> {
        let coefficient_bytes = self.coefficient_bytes()?;
        checked_profile_product(
            "preimage",
            &[
                usize::try_from(self.m).expect("u32 m fits in usize"),
                coefficient_bytes,
            ],
            MAX_PREIMAGE_ENCODED_BYTES,
        )
    }

    /// Fixture seed-bundle bytes for the SHAKE compatibility trapdoor route.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::public_matrix_expanded_bytes`] because
    /// trapdoor storage is valid only for a bounded public-matrix profile.
    pub fn trapdoor_storage_bytes(self) -> LatticePqResult<usize> {
        self.public_matrix_expanded_bytes()?;
        Ok(SECRET_SEED_BUNDLE_BYTES)
    }

    /// Full representation profile implied by these parameters.
    ///
    /// # Errors
    ///
    /// Returns [`LatticePqError::InvalidParameter`] for malformed parameters, or
    /// [`LatticePqError::RepresentationTooLarge`] for profiles that exceed the
    /// explicit matrix/preimage allocation ceilings.
    ///
    /// # Panics
    ///
    /// Panics only on targets where `usize` cannot represent a `u32` dimension.
    pub fn representation_profile(self) -> LatticePqResult<LatticeRepresentationProfile> {
        let coefficient_bytes = self.coefficient_bytes()?;
        let public_matrix_expanded_bytes = checked_profile_product(
            "public_matrix",
            &[
                usize::try_from(self.n).expect("u32 n fits in usize"),
                usize::try_from(self.m).expect("u32 m fits in usize"),
                coefficient_bytes,
            ],
            MAX_PUBLIC_MATRIX_EXPANDED_BYTES,
        )?;
        let preimage_encoded_bytes = checked_profile_product(
            "preimage",
            &[
                usize::try_from(self.m).expect("u32 m fits in usize"),
                coefficient_bytes,
            ],
            MAX_PREIMAGE_ENCODED_BYTES,
        )?;
        Ok(LatticeRepresentationProfile {
            version: LATTICE_REPRESENTATION_VERSION,
            params: self,
            coefficient_bytes,
            public_matrix_seed_bytes: MATRIX_SEED_BYTES,
            public_matrix_expanded_bytes,
            trapdoor_storage_bytes: SECRET_SEED_BUNDLE_BYTES,
            preimage_encoded_bytes,
        })
    }
}

/// Concrete encoding plan for a lattice parameter profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatticeRepresentationProfile {
    /// Representation version.
    pub version: u16,
    /// Parameter profile the representation is bound to.
    pub params: LatticeParams,
    /// Bytes per packed coefficient modulo `q`.
    pub coefficient_bytes: usize,
    /// Serialized public-matrix seed length.
    pub public_matrix_seed_bytes: usize,
    /// Upper-bound checked size for the expanded public matrix.
    pub public_matrix_expanded_bytes: usize,
    /// Fixture seed-bundle bytes for the SHAKE compatibility trapdoor route.
    pub trapdoor_storage_bytes: usize,
    /// Packed preimage byte length.
    pub preimage_encoded_bytes: usize,
}

/// Explicit entropy input for production `TrapGen`.
///
/// Production callers use [`Self::from_os_random`]. Tests and deterministic
/// evidence use [`Self::from_fixture_seed`], which records only a hash of the
/// fixture id so logs can prove which fixture ran without exposing the seed.
#[derive(Clone, Eq)]
pub struct TrapGenEntropy {
    bytes: [u8; TRAP_GEN_ENTROPY_BYTES],
    fixture_id_hash: Option<[u8; 32]>,
}

impl TrapGenEntropy {
    /// Build entropy from the operating system CSPRNG.
    #[must_use]
    pub fn from_os_random() -> Self {
        let mut bytes = [0_u8; TRAP_GEN_ENTROPY_BYTES];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self {
            bytes,
            fixture_id_hash: None,
        }
    }

    /// Build deterministic entropy for named fixtures.
    ///
    /// The fixture id is hashed before storage; the raw id and seed never
    /// appear in trapdoor metadata or debug output.
    #[must_use]
    pub fn from_fixture_seed(fixture_id: &[u8], seed: [u8; TRAP_GEN_ENTROPY_BYTES]) -> Self {
        let mut bytes = [0_u8; TRAP_GEN_ENTROPY_BYTES];
        shake256_fill(
            b"trap-gen-entropy-fixture",
            |shaker| {
                update_len_prefixed(shaker, PRIMITIVE_ROUTE_ID.as_bytes());
                update_len_prefixed(shaker, fixture_id);
                update_len_prefixed(shaker, &seed);
            },
            &mut bytes,
        );
        Self {
            bytes,
            fixture_id_hash: Some(*blake3::hash(fixture_id).as_bytes()),
        }
    }

    /// Hash of the fixture id for deterministic test evidence.
    #[must_use]
    pub const fn fixture_id_hash(&self) -> Option<[u8; 32]> {
        self.fixture_id_hash
    }
}

impl PartialEq for TrapGenEntropy {
    fn eq(&self, other: &Self) -> bool {
        self.fixture_id_hash == other.fixture_id_hash
            && constant_time_bytes_eq(&self.bytes, &other.bytes)
    }
}

impl std::fmt::Debug for TrapGenEntropy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrapGenEntropy")
            .field("fixture_id_hash", &self.fixture_id_hash)
            .field("secret_material", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl Drop for TrapGenEntropy {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// Which trapdoor layer a secret representation belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrapdoorScope {
    /// Root setup-time trapdoor.
    Root,
    /// Child trapdoor derived for a narrower delegation node.
    Child,
}

/// Secret material storage strategy for a trapdoor representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrapdoorMaterialKind {
    /// Deterministic SHAKE seed bundle used only by fixture scaffolding.
    FixtureShakeSeedBundle,
    /// Opaque envelope for a future reviewed MP12/CHKP/GPV basis route.
    BasisEnvelope,
}

/// Redaction-safe bucket for the stored secret size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretStorageLengthBucket {
    /// No secret bytes were present.
    Empty,
    /// Secret storage is at most 128 bytes.
    UpTo128,
    /// Secret storage is at most 4 KiB.
    UpTo4KiB,
    /// Secret storage is at most 64 KiB.
    UpTo64KiB,
    /// Secret storage is at most 1 MiB.
    UpTo1MiB,
    /// Secret storage exceeds the representation ceiling.
    TooLarge,
}

impl SecretStorageLengthBucket {
    #[must_use]
    const fn from_len(len: usize) -> Self {
        match len {
            0 => Self::Empty,
            1..=128 => Self::UpTo128,
            129..=4096 => Self::UpTo4KiB,
            4097..=65_536 => Self::UpTo64KiB,
            65_537..=MAX_TRAPDOOR_SECRET_BYTES => Self::UpTo1MiB,
            _ => Self::TooLarge,
        }
    }
}

/// Redaction-safe relation state for trapdoor/public-key metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrapdoorRelationResult {
    /// Metadata matches the deterministic fixture contract only.
    FixtureOnly,
    /// Metadata and route arithmetic match the reviewed primitive.
    MetadataConsistent,
    /// Metadata does not match the public key, parent key, or parameter profile.
    MetadataMismatch,
    /// A cryptographic relation check is unsupported for this route/profile.
    UnsupportedPrimitive,
}

/// Redaction-safe quality bucket for the represented trapdoor basis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrapdoorNormQualityBucket {
    /// Fixture seed bundle; no basis norm exists.
    FixtureSeed,
    /// Future basis route reports a small reviewed basis.
    Small,
    /// Future basis route is bounded for the configured V4 profile.
    V4Bounded,
    /// Future basis route reports an over-bound basis.
    Oversized,
    /// No quality statement is available yet.
    Unknown,
}

/// Public matrix material route carried by verifier-facing public keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PublicMatrixMaterialKind {
    /// Legacy fixture path where the 32-byte field is only a deterministic
    /// seed placeholder and cannot reconstruct a production `A` matrix.
    FixtureSeedOnly,
    /// Reviewed route material containing the public seed plus the public tail
    /// block needed to reconstruct `A = [A_bar | I - A_bar * R]`.
    RouteTailCoefficients,
}

/// Verifier-computable public matrix material.
///
/// This material is public and serializable. Its custom [`Debug`] keeps logs
/// summarized so evidence artifacts do not accidentally dump expanded matrices.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicMatrixMaterial {
    /// Public matrix material version.
    pub version: u16,
    /// Material route.
    pub kind: PublicMatrixMaterialKind,
    /// Hash of [`PRIMITIVE_ROUTE_ID`] for route-bound public material.
    pub route_id_hash: [u8; 32],
    /// Primitive route revision.
    pub route_revision: u16,
    /// Seed for the public `A_bar` block, or the legacy fixture seed.
    pub public_seed: [u8; 32],
    /// Encoded public tail coefficients for route material.
    #[serde(with = "hex_vec")]
    pub tail_coefficients: Vec<u8>,
}

impl PublicMatrixMaterial {
    /// Construct legacy fixture seed-only public material.
    #[must_use]
    pub const fn fixture_seed_only(seed: [u8; 32]) -> Self {
        Self {
            version: PUBLIC_MATRIX_MATERIAL_VERSION,
            kind: PublicMatrixMaterialKind::FixtureSeedOnly,
            route_id_hash: ZERO_HASH,
            route_revision: FIXTURE_SHAKE_COMPATIBILITY_VERSION,
            public_seed: seed,
            tail_coefficients: Vec::new(),
        }
    }

    /// Public seed or fixture seed carried by this material.
    #[must_use]
    pub const fn seed(&self) -> [u8; 32] {
        self.public_seed
    }

    /// Encoded public tail byte length.
    #[must_use]
    pub fn tail_coefficients_len(&self) -> usize {
        self.tail_coefficients.len()
    }
}

impl std::fmt::Debug for PublicMatrixMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicMatrixMaterial")
            .field("version", &self.version)
            .field("kind", &self.kind)
            .field("route_revision", &self.route_revision)
            .field("public_seed_len", &MATRIX_SEED_BYTES)
            .field("tail_coefficients_len", &self.tail_coefficients.len())
            .finish_non_exhaustive()
    }
}

/// Public, serializable metadata for a secret trapdoor representation.
///
/// This structure is safe for logs and evidence: it contains public hashes,
/// parameter identifiers, and length buckets only. It never carries trapdoor
/// coefficients, seed bytes, or expanded secret matrices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrapdoorRepresentationMetadata {
    /// Representation envelope version.
    pub version: u16,
    /// Root or child layer.
    pub scope: TrapdoorScope,
    /// Stored secret material route.
    pub material_kind: TrapdoorMaterialKind,
    /// Parameter profile bound into the secret.
    pub params: LatticeParams,
    /// Public matrix seed/hash this secret claims to support.
    pub public_matrix_hash: [u8; 32],
    /// Parent public matrix seed/hash for child trapdoors.
    pub parent_public_matrix_hash: Option<[u8; 32]>,
    /// Redaction-safe storage length bucket.
    pub secret_storage_len_bucket: SecretStorageLengthBucket,
}

impl TrapdoorRepresentationMetadata {
    /// Validate that metadata is structurally well-formed.
    ///
    /// # Errors
    ///
    /// Returns [`LatticePqError::InvalidTrapdoorSecret`] when the scope and
    /// parent linkage are inconsistent, or parameter validation fails.
    pub fn validate(self) -> LatticePqResult<()> {
        self.params.validate()?;
        if self.version != LATTICE_REPRESENTATION_VERSION {
            return Err(LatticePqError::InvalidEncodingLength {
                material: "trapdoor_version",
                expected: usize::from(LATTICE_REPRESENTATION_VERSION),
                got: usize::from(self.version),
            });
        }
        match self.material_kind {
            TrapdoorMaterialKind::FixtureShakeSeedBundle => {
                let expected_bucket =
                    SecretStorageLengthBucket::from_len(self.params.trapdoor_storage_bytes()?);
                if self.secret_storage_len_bucket != expected_bucket {
                    return Err(LatticePqError::InvalidTrapdoorSecret {
                        material: "fixture_trapdoor_seed_bundle",
                        reason: "fixture secret length bucket must match parameter profile",
                    });
                }
            }
            TrapdoorMaterialKind::BasisEnvelope
                if matches!(
                    self.secret_storage_len_bucket,
                    SecretStorageLengthBucket::Empty | SecretStorageLengthBucket::TooLarge
                ) =>
            {
                return Err(LatticePqError::InvalidTrapdoorSecret {
                    material: "basis_envelope",
                    reason: "basis envelope length bucket must be non-empty and within limits",
                });
            }
            TrapdoorMaterialKind::BasisEnvelope => {}
        }
        match (self.scope, self.parent_public_matrix_hash) {
            (TrapdoorScope::Root, None) | (TrapdoorScope::Child, Some(_)) => Ok(()),
            (TrapdoorScope::Root, Some(_)) => Err(LatticePqError::InvalidTrapdoorSecret {
                material: "root_trapdoor",
                reason: "root trapdoor metadata must not include a parent hash",
            }),
            (TrapdoorScope::Child, None) => Err(LatticePqError::InvalidTrapdoorSecret {
                material: "child_trapdoor",
                reason: "child trapdoor metadata must include a parent hash",
            }),
        }
    }
}

/// Redaction-safe summary of a trapdoor/public-key relation check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrapdoorRelationSummary {
    /// Metadata checked.
    pub metadata: TrapdoorRepresentationMetadata,
    /// Relation outcome without exposing coefficients or secret bytes.
    pub result: TrapdoorRelationResult,
    /// Norm/quality bucket without exposing basis vectors.
    pub norm_quality_bucket: TrapdoorNormQualityBucket,
}

fn validate_trapdoor_secret(
    material_kind: TrapdoorMaterialKind,
    params: LatticeParams,
    len: usize,
) -> LatticePqResult<SecretStorageLengthBucket> {
    let bucket = SecretStorageLengthBucket::from_len(len);
    if bucket == SecretStorageLengthBucket::TooLarge {
        return Err(LatticePqError::RepresentationTooLarge {
            material: "trapdoor_secret",
            requested: len,
            max: MAX_TRAPDOOR_SECRET_BYTES,
        });
    }
    match material_kind {
        TrapdoorMaterialKind::FixtureShakeSeedBundle => {
            let expected = params.trapdoor_storage_bytes()?;
            if len != expected {
                return Err(LatticePqError::InvalidEncodingLength {
                    material: "fixture_trapdoor_seed_bundle",
                    expected,
                    got: len,
                });
            }
        }
        TrapdoorMaterialKind::BasisEnvelope => {
            if len == 0 {
                return Err(LatticePqError::InvalidTrapdoorSecret {
                    material: "basis_envelope",
                    reason: "basis envelope must not be empty",
                });
            }
        }
    }
    Ok(bucket)
}

fn trapdoor_metadata(
    scope: TrapdoorScope,
    material_kind: TrapdoorMaterialKind,
    params: LatticeParams,
    public_matrix_hash: [u8; 32],
    parent_public_matrix_hash: Option<[u8; 32]>,
    secret_len: usize,
) -> LatticePqResult<TrapdoorRepresentationMetadata> {
    let secret_storage_len_bucket = validate_trapdoor_secret(material_kind, params, secret_len)?;
    let metadata = TrapdoorRepresentationMetadata {
        version: LATTICE_REPRESENTATION_VERSION,
        scope,
        material_kind,
        params,
        public_matrix_hash,
        parent_public_matrix_hash,
        secret_storage_len_bucket,
    };
    metadata.validate()?;
    Ok(metadata)
}

const fn norm_quality_bucket(
    material_kind: TrapdoorMaterialKind,
    secret_storage_len_bucket: SecretStorageLengthBucket,
) -> TrapdoorNormQualityBucket {
    match material_kind {
        TrapdoorMaterialKind::FixtureShakeSeedBundle => TrapdoorNormQualityBucket::FixtureSeed,
        TrapdoorMaterialKind::BasisEnvelope => match secret_storage_len_bucket {
            SecretStorageLengthBucket::Empty | SecretStorageLengthBucket::TooLarge => {
                TrapdoorNormQualityBucket::Oversized
            }
            SecretStorageLengthBucket::UpTo128 | SecretStorageLengthBucket::UpTo4KiB => {
                TrapdoorNormQualityBucket::Small
            }
            SecretStorageLengthBucket::UpTo64KiB | SecretStorageLengthBucket::UpTo1MiB => {
                TrapdoorNormQualityBucket::V4Bounded
            }
        },
    }
}

fn checked_profile_product(
    material: &'static str,
    factors: &[usize],
    max: usize,
) -> LatticePqResult<usize> {
    let mut requested = 1usize;
    for factor in factors {
        requested =
            requested
                .checked_mul(*factor)
                .ok_or(LatticePqError::RepresentationTooLarge {
                    material,
                    requested: usize::MAX,
                    max,
                })?;
    }
    if requested > max {
        return Err(LatticePqError::RepresentationTooLarge {
            material,
            requested,
            max,
        });
    }
    Ok(requested)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RouteDimensions {
    abar_cols: u32,
    gadget_cols: u32,
}

#[derive(Debug, Clone, Copy)]
struct BasisEnvelopeView {
    route_id_hash: [u8; 32],
    route_revision: u16,
    scope: TrapdoorScope,
    params_hash: [u8; 32],
    public_matrix_hash: [u8; 32],
    parent_public_matrix_hash: [u8; 32],
    zone_id_hash: [u8; 32],
    period_id_hash: [u8; 32],
    entropy_id_hash: [u8; 32],
    public_seed: [u8; 32],
    r_seed: [u8; 32],
    relation_digest: [u8; 32],
}

const ZERO_HASH: [u8; 32] = [0_u8; 32];

#[must_use]
pub fn primitive_route_profile_name(params: LatticeParams) -> &'static str {
    if params == LatticeParams::SMALL_TEST {
        "SMALL_TEST"
    } else if params == LatticeParams::V4_REFERENCE {
        "V4_REFERENCE"
    } else {
        "CUSTOM"
    }
}

fn route_id_hash() -> [u8; 32] {
    *blake3::hash(PRIMITIVE_ROUTE_ID.as_bytes()).as_bytes()
}

fn params_hash(params: LatticeParams) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"fcp-pq/params-hash-v1|");
    hasher.update(&params.n.to_le_bytes());
    hasher.update(&params.q.to_le_bytes());
    hasher.update(&params.m.to_le_bytes());
    hasher.update(&params.sigma_x100.to_le_bytes());
    hasher.update(&[params.depth]);
    *hasher.finalize().as_bytes()
}

fn period_hash(period: DelegationPeriod) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"fcp-pq/period-hash-v1|");
    hasher.update(&period.start_secs.to_le_bytes());
    hasher.update(&period.end_secs.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn route_dimensions(
    params: LatticeParams,
    primitive: &'static str,
) -> LatticePqResult<RouteDimensions> {
    params.validate()?;
    if params != LatticeParams::SMALL_TEST && params != LatticeParams::V4_REFERENCE {
        return Err(LatticePqError::UnsupportedPrimitiveRoute {
            primitive,
            route_id: PRIMITIVE_ROUTE_ID,
            profile: primitive_route_profile_name(params),
            reason: "internal route supports only the reviewed SMALL_TEST and V4_REFERENCE profiles",
        });
    }
    if params.m <= params.n {
        return Err(LatticePqError::InvalidParameter {
            field: "m",
            value: u64::from(params.m),
            reason: "internal gadget route requires room for an A_bar block plus gadget columns",
        });
    }
    Ok(RouteDimensions {
        abar_cols: params.m - params.n,
        gadget_cols: params.n,
    })
}

fn encoded_tail_coefficients_len(params: LatticeParams) -> LatticePqResult<usize> {
    let dims = route_dimensions(params, "public_matrix_material")?;
    checked_profile_product(
        "public_matrix_tail",
        &[
            usize::try_from(params.n).expect("u32 n fits in usize"),
            usize::try_from(dims.gadget_cols).expect("u32 gadget columns fit in usize"),
            params.coefficient_bytes()?,
        ],
        MAX_PUBLIC_MATRIX_EXPANDED_BYTES,
    )
}

fn route_r_support(
    params: LatticeParams,
    r_seed: &[u8; 32],
    gadget_col: u32,
    dims: RouteDimensions,
) -> LatticePqResult<Vec<(u32, i64)>> {
    if params == LatticeParams::SMALL_TEST {
        let mut support =
            Vec::with_capacity(usize::try_from(dims.abar_cols).expect("u32 cols fit in usize"));
        for abar_col in 0..dims.abar_cols {
            support.push((abar_col, r_coeff(params, r_seed, abar_col, gadget_col)));
        }
        return Ok(support);
    }

    if params != LatticeParams::V4_REFERENCE {
        return Err(LatticePqError::UnsupportedPrimitiveRoute {
            primitive: "route_r_support",
            route_id: PRIMITIVE_ROUTE_ID,
            profile: primitive_route_profile_name(params),
            reason: "sparse R support is defined only for V4_REFERENCE",
        });
    }
    if dims.abar_cols < V4_SPARSE_R_WEIGHT {
        return Err(LatticePqError::InvalidParameter {
            field: "m",
            value: u64::from(params.m),
            reason: "V4 sparse route requires at least V4_SPARSE_R_WEIGHT A_bar columns",
        });
    }

    let mut shaker = Shake256::default();
    update_len_prefixed(&mut shaker, BASIS_ENVELOPE_MAGIC);
    update_len_prefixed(&mut shaker, PRIMITIVE_ROUTE_ID.as_bytes());
    update_len_prefixed(&mut shaker, b"route-v4-sparse-r-support-v1");
    Update::update(&mut shaker, &PRIMITIVE_ROUTE_REVISION.to_le_bytes());
    Update::update(&mut shaker, &params_hash(params));
    update_len_prefixed(&mut shaker, r_seed);
    Update::update(&mut shaker, &gadget_col.to_le_bytes());
    let mut reader = shaker.finalize_xof();
    let mut support =
        Vec::with_capacity(usize::try_from(V4_SPARSE_R_WEIGHT).expect("weight fits in usize"));
    while support.len() < usize::try_from(V4_SPARSE_R_WEIGHT).expect("weight fits in usize") {
        let mut candidate = [0_u8; 9];
        reader.read(&mut candidate);
        let mut index_bytes = [0_u8; 8];
        index_bytes.copy_from_slice(&candidate[..8]);
        let abar_col = u32::try_from(u64::from_le_bytes(index_bytes) % u64::from(dims.abar_cols))
            .expect("modulo abar_cols fits in u32");
        if support.iter().any(|(seen, _)| *seen == abar_col) {
            continue;
        }
        let sign = if candidate[8] & 1 == 0 { -1 } else { 1 };
        support.push((abar_col, sign));
    }
    Ok(support)
}

fn encode_coeff(params: LatticeParams, coeff: u64, out: &mut Vec<u8>) -> LatticePqResult<()> {
    if coeff >= params.q {
        return Err(LatticePqError::InvalidParameter {
            field: "coefficient",
            value: coeff,
            reason: "coefficient must be reduced modulo q",
        });
    }
    let coefficient_bytes = params.coefficient_bytes()?;
    let bytes = coeff.to_le_bytes();
    out.extend_from_slice(&bytes[..coefficient_bytes]);
    Ok(())
}

fn decode_coeff(params: LatticeParams, bytes: &[u8], index: usize) -> LatticePqResult<u64> {
    let coefficient_bytes = params.coefficient_bytes()?;
    let offset =
        index
            .checked_mul(coefficient_bytes)
            .ok_or(LatticePqError::RepresentationTooLarge {
                material: "coefficient_index",
                requested: usize::MAX,
                max: MAX_PUBLIC_MATRIX_EXPANDED_BYTES,
            })?;
    let end =
        offset
            .checked_add(coefficient_bytes)
            .ok_or(LatticePqError::RepresentationTooLarge {
                material: "coefficient_index",
                requested: usize::MAX,
                max: MAX_PUBLIC_MATRIX_EXPANDED_BYTES,
            })?;
    let slice = bytes
        .get(offset..end)
        .ok_or(LatticePqError::InvalidEncodingLength {
            material: "public_matrix_tail",
            expected: end,
            got: bytes.len(),
        })?;
    let mut coeff_bytes = [0_u8; 8];
    coeff_bytes[..coefficient_bytes].copy_from_slice(slice);
    let coeff = u64::from_le_bytes(coeff_bytes);
    if coeff >= params.q {
        return Err(LatticePqError::InvalidTrapdoorSecret {
            material: "public_matrix_tail",
            reason: "public tail coefficient is not reduced modulo q",
        });
    }
    Ok(coeff)
}

#[cfg(test)]
fn tail_coeff(
    params: LatticeParams,
    public_seed: &[u8; 32],
    r_seed: &[u8; 32],
    row: u32,
    gadget_col: u32,
) -> u64 {
    let dims = route_dimensions(params, "tail_coeff").expect("route dimensions already checked");
    let support =
        route_r_support(params, r_seed, gadget_col, dims).expect("route R support checked");
    let product = tail_product(params, public_seed, &support, row);
    let identity = i128::from(row == gadget_col);
    reduce_i128_mod_q(identity - product, params.q)
}

fn tail_product(
    params: LatticeParams,
    public_seed: &[u8; 32],
    support: &[(u32, i64)],
    row: u32,
) -> i128 {
    let mut product = 0_i128;
    for (abar_col, r) in support {
        let a = public_coeff(params, public_seed, row, *abar_col);
        product += i128::from(a) * i128::from(*r);
    }
    product
}

#[cfg(test)]
fn v4_public_abar_row(
    params: LatticeParams,
    public_seed: &[u8; 32],
    row: u32,
    dims: RouteDimensions,
) -> Vec<u64> {
    debug_assert_eq!(params, LatticeParams::V4_REFERENCE);
    let mut shaker = Shake256::default();
    update_len_prefixed(&mut shaker, SHAKE_DOMAIN_PREFIX);
    update_len_prefixed(&mut shaker, b"route-public-abar-row-v1");
    update_len_prefixed(&mut shaker, PRIMITIVE_ROUTE_ID.as_bytes());
    update_params(&mut shaker, params);
    update_len_prefixed(&mut shaker, public_seed);
    Update::update(&mut shaker, &row.to_le_bytes());
    let mut reader = shaker.finalize_xof();
    let mut coeffs =
        Vec::with_capacity(usize::try_from(dims.abar_cols).expect("u32 cols fit in usize"));
    for _ in 0..dims.abar_cols {
        let mut out = [0_u8; 8];
        reader.read(&mut out);
        coeffs.push(u64::from_le_bytes(out) % params.q);
    }
    coeffs
}

fn v4_public_abar_selected_row(
    params: LatticeParams,
    public_seed: &[u8; 32],
    row: u32,
    selected_cols: &[u32],
) -> Vec<u64> {
    debug_assert_eq!(params, LatticeParams::V4_REFERENCE);
    if selected_cols.is_empty() {
        return Vec::new();
    }
    debug_assert!(selected_cols.windows(2).all(|cols| cols[0] < cols[1]));

    let mut shaker = Shake256::default();
    update_len_prefixed(&mut shaker, SHAKE_DOMAIN_PREFIX);
    update_len_prefixed(&mut shaker, b"route-public-abar-row-v1");
    update_len_prefixed(&mut shaker, PRIMITIVE_ROUTE_ID.as_bytes());
    update_params(&mut shaker, params);
    update_len_prefixed(&mut shaker, public_seed);
    Update::update(&mut shaker, &row.to_le_bytes());
    let mut reader = shaker.finalize_xof();
    let mut coeffs = Vec::with_capacity(selected_cols.len());
    let mut next_selected = 0_usize;
    let max_col = *selected_cols
        .last()
        .expect("selected_cols is known non-empty");
    let mut chunk = [0_u8; V4_ROW_XOF_CHUNK_COEFFS * 8];
    let mut chunk_start = 0_u32;
    while chunk_start <= max_col {
        let remaining_coeffs =
            usize::try_from(max_col - chunk_start + 1).expect("selected column range fits usize");
        let chunk_coeffs = remaining_coeffs.min(V4_ROW_XOF_CHUNK_COEFFS);
        let chunk_bytes = chunk_coeffs * 8;
        reader.read(&mut chunk[..chunk_bytes]);
        let chunk_end =
            chunk_start + u32::try_from(chunk_coeffs).expect("chunk coefficient count fits in u32");
        while next_selected < selected_cols.len() && selected_cols[next_selected] < chunk_end {
            let byte_offset = usize::try_from(selected_cols[next_selected] - chunk_start)
                .expect("selected column offset fits usize")
                * 8;
            let mut out = [0_u8; 8];
            out.copy_from_slice(&chunk[byte_offset..byte_offset + 8]);
            coeffs.push(u64::from_le_bytes(out) % params.q);
            next_selected += 1;
            if next_selected == selected_cols.len() {
                break;
            }
        }
        if next_selected == selected_cols.len() {
            break;
        }
        chunk_start = chunk_end;
    }
    coeffs
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct V4AbarSelectionCacheKey {
    route_id_hash: [u8; 32],
    route_revision: u16,
    params_hash: [u8; 32],
    public_seed: [u8; 32],
    selected_cols_hash: [u8; 32],
    selected_cols_len: usize,
}

struct V4AbarSelectionCacheEntry {
    key: V4AbarSelectionCacheKey,
    coeffs: Arc<[u32]>,
}

static V4_ABAR_SELECTION_CACHE: OnceLock<Mutex<VecDeque<V4AbarSelectionCacheEntry>>> =
    OnceLock::new();

fn selected_cols_hash(selected_cols: &[u32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"fcp-pq/v4-selected-abar-cols-v1|");
    hasher.update(
        &u64::try_from(selected_cols.len())
            .expect("selected cols length fits in u64")
            .to_le_bytes(),
    );
    for col in selected_cols {
        hasher.update(&col.to_le_bytes());
    }
    *hasher.finalize().as_bytes()
}

fn v4_abar_selection_cache_key(
    params: LatticeParams,
    material: &PublicMatrixMaterial,
    selected_cols: &[u32],
) -> V4AbarSelectionCacheKey {
    V4AbarSelectionCacheKey {
        route_id_hash: material.route_id_hash,
        route_revision: material.route_revision,
        params_hash: params_hash(params),
        public_seed: material.public_seed,
        selected_cols_hash: selected_cols_hash(selected_cols),
        selected_cols_len: selected_cols.len(),
    }
}

fn build_v4_selected_abar_coefficients(
    params: LatticeParams,
    public_seed: &[u8; 32],
    selected_cols: &[u32],
) -> Arc<[u32]> {
    debug_assert_eq!(params, LatticeParams::V4_REFERENCE);
    let rows = (0..params.n)
        .into_par_iter()
        .with_min_len(32)
        .map(|row| {
            v4_public_abar_selected_row(params, public_seed, row, selected_cols)
                .into_iter()
                .map(|coeff| u32::try_from(coeff).expect("V4 coefficient fits in u32"))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let mut coeffs = Vec::with_capacity(
        usize::try_from(params.n).expect("u32 n fits in usize") * selected_cols.len(),
    );
    for row in rows {
        coeffs.extend(row);
    }
    coeffs.into()
}

fn v4_selected_abar_coefficients(
    params: LatticeParams,
    material: &PublicMatrixMaterial,
    selected_cols: &[u32],
) -> Arc<[u32]> {
    let key = v4_abar_selection_cache_key(params, material, selected_cols);
    let cache = V4_ABAR_SELECTION_CACHE.get_or_init(|| Mutex::new(VecDeque::new()));
    {
        let entries = cache
            .lock()
            .expect("V4 public material cache mutex must not be poisoned");
        if let Some(entry) = entries.iter().find(|entry| entry.key == key) {
            return Arc::clone(&entry.coeffs);
        }
    }

    let coeffs = build_v4_selected_abar_coefficients(params, &material.public_seed, selected_cols);
    {
        let mut entries = cache
            .lock()
            .expect("V4 public material cache mutex must not be poisoned");
        if let Some(entry) = entries.iter().find(|entry| entry.key == key) {
            return Arc::clone(&entry.coeffs);
        }
        entries.push_front(V4AbarSelectionCacheEntry {
            key,
            coeffs: Arc::clone(&coeffs),
        });
        while entries.len() > V4_ABAR_SELECTION_CACHE_ENTRIES {
            entries.pop_back();
        }
        drop(entries);
    }
    coeffs
}

#[cfg(test)]
fn tail_product_from_row(row_coefficients: &[u64], support: &[(u32, i64)]) -> i128 {
    let mut product = 0_i128;
    for (abar_col, r) in support {
        let a = row_coefficients[usize::try_from(*abar_col).expect("u32 col fits in usize")];
        product += i128::from(a) * i128::from(*r);
    }
    product
}

fn v4_index_r_supports(r_supports: &[Vec<(u32, i64)>]) -> (Vec<u32>, Vec<Vec<(usize, i64)>>) {
    let mut selected_cols: Vec<u32> = r_supports
        .iter()
        .flat_map(|support| support.iter().map(|(abar_col, _)| *abar_col))
        .collect();
    selected_cols.sort_unstable();
    selected_cols.dedup();

    let indexed_supports = r_supports
        .iter()
        .map(|support| {
            support
                .iter()
                .map(|(abar_col, r)| {
                    let index = selected_cols
                        .binary_search(abar_col)
                        .expect("every support column was selected");
                    (index, *r)
                })
                .collect()
        })
        .collect();
    (selected_cols, indexed_supports)
}

fn tail_product_from_selected_row(row_coefficients: &[u64], support: &[(usize, i64)]) -> i128 {
    let mut product = 0_i128;
    for (abar_col, r) in support {
        let a = row_coefficients[*abar_col];
        product += i128::from(a) * i128::from(*r);
    }
    product
}

fn route_preimage_abar_terms(dims: RouteDimensions, coeffs: &[u64]) -> Vec<(u32, u64)> {
    coeffs
        .iter()
        .take(usize::try_from(dims.abar_cols).expect("u32 A_bar cols fit in usize"))
        .enumerate()
        .filter_map(|(col, coeff)| {
            (*coeff != 0).then_some((u32::try_from(col).expect("A_bar col fits in u32"), *coeff))
        })
        .collect()
}

fn route_public_matrix_material(
    params: LatticeParams,
    public_seed: &[u8; 32],
    r_seed: &[u8; 32],
) -> LatticePqResult<PublicMatrixMaterial> {
    let dims = route_dimensions(params, "public_matrix_material")?;
    let r_supports = (0..dims.gadget_cols)
        .map(|gadget_col| route_r_support(params, r_seed, gadget_col, dims))
        .collect::<LatticePqResult<Vec<_>>>()?;
    let mut tail_coefficients = Vec::with_capacity(encoded_tail_coefficients_len(params)?);

    if params == LatticeParams::V4_REFERENCE {
        let (selected_cols, indexed_r_supports) = v4_index_r_supports(&r_supports);
        for row in 0..params.n {
            let row_coefficients =
                v4_public_abar_selected_row(params, public_seed, row, &selected_cols);
            for (gadget_col, support) in indexed_r_supports.iter().enumerate() {
                let product = tail_product_from_selected_row(&row_coefficients, support);
                let gadget_col_u32 = u32::try_from(gadget_col).expect("gadget column fits in u32");
                let tail = reduce_i128_mod_q(i128::from(row == gadget_col_u32) - product, params.q);
                let relation_lhs = reduce_i128_mod_q(product + i128::from(tail), params.q);
                let relation_rhs = u64::from(row == gadget_col_u32);
                if relation_lhs != relation_rhs {
                    return Err(LatticePqError::InvalidTrapdoorSecret {
                        material: "basis_relation",
                        reason: "internal gadget relation did not reduce to the identity gadget",
                    });
                }
                encode_coeff(params, tail, &mut tail_coefficients)?;
            }
        }
    } else {
        for row in 0..params.n {
            for gadget_col in 0..dims.gadget_cols {
                let support = &r_supports[usize::try_from(gadget_col).expect("u32 col fits usize")];
                let product = tail_product(params, public_seed, support, row);
                let tail = reduce_i128_mod_q(i128::from(row == gadget_col) - product, params.q);
                let relation_lhs = reduce_i128_mod_q(product + i128::from(tail), params.q);
                let relation_rhs = u64::from(row == gadget_col);
                if relation_lhs != relation_rhs {
                    return Err(LatticePqError::InvalidTrapdoorSecret {
                        material: "basis_relation",
                        reason: "internal gadget relation did not reduce to the identity gadget",
                    });
                }
                encode_coeff(params, tail, &mut tail_coefficients)?;
            }
        }
    }
    Ok(PublicMatrixMaterial {
        version: PUBLIC_MATRIX_MATERIAL_VERSION,
        kind: PublicMatrixMaterialKind::RouteTailCoefficients,
        route_id_hash: route_id_hash(),
        route_revision: PRIMITIVE_ROUTE_REVISION,
        public_seed: *public_seed,
        tail_coefficients,
    })
}

fn validate_route_public_matrix_material(
    params: LatticeParams,
    material: &PublicMatrixMaterial,
) -> LatticePqResult<()> {
    let expected_len = validate_route_public_matrix_material_header(params, material)?;
    for index in 0..(expected_len / params.coefficient_bytes()?) {
        let _ = decode_coeff(params, &material.tail_coefficients, index)?;
    }
    Ok(())
}

fn validate_route_public_matrix_material_header(
    params: LatticeParams,
    material: &PublicMatrixMaterial,
) -> LatticePqResult<usize> {
    let expected_len = encoded_tail_coefficients_len(params)?;
    if material.version != PUBLIC_MATRIX_MATERIAL_VERSION {
        return Err(LatticePqError::InvalidEncodingLength {
            material: "public_matrix_material_version",
            expected: usize::from(PUBLIC_MATRIX_MATERIAL_VERSION),
            got: usize::from(material.version),
        });
    }
    if material.kind != PublicMatrixMaterialKind::RouteTailCoefficients {
        return Err(LatticePqError::InvalidTrapdoorSecret {
            material: "public_matrix_material",
            reason: "supported route requires public tail coefficients",
        });
    }
    if material.route_id_hash != route_id_hash()
        || material.route_revision != PRIMITIVE_ROUTE_REVISION
    {
        return Err(LatticePqError::InvalidTrapdoorSecret {
            material: "public_matrix_material",
            reason: "public material route id or revision mismatch",
        });
    }
    if material.tail_coefficients.len() != expected_len {
        return Err(LatticePqError::InvalidEncodingLength {
            material: "public_matrix_tail",
            expected: expected_len,
            got: material.tail_coefficients.len(),
        });
    }
    Ok(expected_len)
}

fn public_matrix_digest(
    params: LatticeParams,
    material: &PublicMatrixMaterial,
) -> LatticePqResult<[u8; 32]> {
    let dims = route_dimensions(params, "public_matrix_digest")?;
    validate_route_public_matrix_material(params, material)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"fcp-pq/public-matrix-material-v1|");
    hasher.update(PRIMITIVE_ROUTE_ID.as_bytes());
    hasher.update(&PRIMITIVE_ROUTE_REVISION.to_le_bytes());
    hasher.update(&params_hash(params));
    hasher.update(&material.public_seed);

    if params == LatticeParams::SMALL_TEST {
        for row in 0..params.n {
            for col in 0..dims.abar_cols {
                let coeff = public_coeff(params, &material.public_seed, row, col);
                hasher.update(&coeff.to_le_bytes());
            }
        }
    } else {
        hasher.update(b"seed-derived-abar-v1");
        hasher.update(&dims.abar_cols.to_le_bytes());
    }
    hasher.update(&material.tail_coefficients);
    Ok(*hasher.finalize().as_bytes())
}

fn public_matrix_coeff(
    params: LatticeParams,
    material: &PublicMatrixMaterial,
    row: u32,
    col: u32,
) -> LatticePqResult<u64> {
    let dims = route_dimensions(params, "public_matrix_coeff")?;
    validate_route_public_matrix_material(params, material)?;
    if row >= params.n {
        return Err(LatticePqError::InvalidParameter {
            field: "row",
            value: u64::from(row),
            reason: "row is outside the public matrix",
        });
    }
    if col >= params.m {
        return Err(LatticePqError::InvalidParameter {
            field: "col",
            value: u64::from(col),
            reason: "column is outside the public matrix",
        });
    }
    if col < dims.abar_cols {
        return Ok(public_coeff(params, &material.public_seed, row, col));
    }
    let tail_col = col - dims.abar_cols;
    let index = usize::try_from(row)
        .expect("u32 row fits in usize")
        .checked_mul(usize::try_from(dims.gadget_cols).expect("u32 cols fit in usize"))
        .and_then(|base| {
            base.checked_add(usize::try_from(tail_col).expect("u32 tail col fits in usize"))
        })
        .ok_or(LatticePqError::RepresentationTooLarge {
            material: "public_matrix_tail_index",
            requested: usize::MAX,
            max: MAX_PUBLIC_MATRIX_EXPANDED_BYTES,
        })?;
    decode_coeff(params, &material.tail_coefficients, index)
}

fn read_fixed<const N: usize>(bytes: &[u8], offset: &mut usize) -> Option<[u8; N]> {
    let end = offset.checked_add(N)?;
    let slice = bytes.get(*offset..end)?;
    *offset = end;
    Some(slice.try_into().expect("slice length matches fixed array"))
}

fn read_u16(bytes: &[u8], offset: &mut usize) -> Option<u16> {
    Some(u16::from_le_bytes(read_fixed::<2>(bytes, offset)?))
}

fn read_scope(bytes: &[u8], offset: &mut usize) -> Option<TrapdoorScope> {
    let tag = *bytes.get(*offset)?;
    *offset += 1;
    match tag {
        0 => Some(TrapdoorScope::Root),
        1 => Some(TrapdoorScope::Child),
        _ => None,
    }
}

fn parse_basis_envelope(bytes: &[u8]) -> Option<BasisEnvelopeView> {
    let magic_end = BASIS_ENVELOPE_MAGIC.len();
    if bytes.get(..magic_end)? != BASIS_ENVELOPE_MAGIC {
        return None;
    }
    let mut offset = magic_end;
    let route_id_hash = read_fixed(bytes, &mut offset)?;
    let route_revision = read_u16(bytes, &mut offset)?;
    let scope = read_scope(bytes, &mut offset)?;
    let params_hash = read_fixed(bytes, &mut offset)?;
    let public_matrix_hash = read_fixed(bytes, &mut offset)?;
    let parent_public_matrix_hash = read_fixed(bytes, &mut offset)?;
    let zone_id_hash = read_fixed(bytes, &mut offset)?;
    let period_id_hash = read_fixed(bytes, &mut offset)?;
    let entropy_id_hash = read_fixed(bytes, &mut offset)?;
    let public_seed = read_fixed(bytes, &mut offset)?;
    let r_seed = read_fixed(bytes, &mut offset)?;
    let relation_digest = read_fixed(bytes, &mut offset)?;
    if offset != bytes.len() {
        return None;
    }
    Some(BasisEnvelopeView {
        route_id_hash,
        route_revision,
        scope,
        params_hash,
        public_matrix_hash,
        parent_public_matrix_hash,
        zone_id_hash,
        period_id_hash,
        entropy_id_hash,
        public_seed,
        r_seed,
        relation_digest,
    })
}

fn encode_basis_envelope(view: &BasisEnvelopeView) -> Vec<u8> {
    let mut out = Vec::with_capacity(BASIS_ENVELOPE_MAGIC.len() + 322);
    out.extend_from_slice(BASIS_ENVELOPE_MAGIC);
    out.extend_from_slice(&view.route_id_hash);
    out.extend_from_slice(&view.route_revision.to_le_bytes());
    out.push(match view.scope {
        TrapdoorScope::Root => 0,
        TrapdoorScope::Child => 1,
    });
    out.extend_from_slice(&view.params_hash);
    out.extend_from_slice(&view.public_matrix_hash);
    out.extend_from_slice(&view.parent_public_matrix_hash);
    out.extend_from_slice(&view.zone_id_hash);
    out.extend_from_slice(&view.period_id_hash);
    out.extend_from_slice(&view.entropy_id_hash);
    out.extend_from_slice(&view.public_seed);
    out.extend_from_slice(&view.r_seed);
    out.extend_from_slice(&view.relation_digest);
    out
}

fn public_coeff(params: LatticeParams, seed: &[u8; 32], row: u32, col: u32) -> u64 {
    if params == LatticeParams::V4_REFERENCE {
        let dims = route_dimensions(params, "public_coeff")
            .expect("V4_REFERENCE route dimensions are valid");
        debug_assert!(col < dims.abar_cols);
        let mut shaker = Shake256::default();
        update_len_prefixed(&mut shaker, SHAKE_DOMAIN_PREFIX);
        update_len_prefixed(&mut shaker, b"route-public-abar-row-v1");
        update_len_prefixed(&mut shaker, PRIMITIVE_ROUTE_ID.as_bytes());
        update_params(&mut shaker, params);
        update_len_prefixed(&mut shaker, seed);
        Update::update(&mut shaker, &row.to_le_bytes());
        let mut reader = shaker.finalize_xof();
        let mut out = [0_u8; 8];
        for _ in 0..=col {
            reader.read(&mut out);
        }
        return u64::from_le_bytes(out) % params.q;
    }

    let mut out = [0_u8; 8];
    shake256_fill(
        b"route-public-abar-coeff",
        |shaker| {
            update_len_prefixed(shaker, PRIMITIVE_ROUTE_ID.as_bytes());
            update_params(shaker, params);
            update_len_prefixed(shaker, seed);
            Update::update(shaker, &row.to_le_bytes());
            Update::update(shaker, &col.to_le_bytes());
        },
        &mut out,
    );
    u64::from_le_bytes(out) % params.q
}

fn r_coeff(params: LatticeParams, seed: &[u8; 32], row: u32, col: u32) -> i64 {
    let mut out = [0_u8; 1];
    shake256_fill(
        b"route-small-r-coeff",
        |shaker| {
            update_len_prefixed(shaker, PRIMITIVE_ROUTE_ID.as_bytes());
            update_params(shaker, params);
            update_len_prefixed(shaker, seed);
            Update::update(shaker, &row.to_le_bytes());
            Update::update(shaker, &col.to_le_bytes());
        },
        &mut out,
    );
    i64::from(out[0] % 3) - 1
}

fn reduce_i128_mod_q(value: i128, q: u64) -> u64 {
    let q_i128 = i128::from(q);
    let reduced = value.rem_euclid(q_i128);
    u64::try_from(reduced).expect("positive residue less than q fits in u64")
}

fn reduce_u128_mod_q(value: u128, q: u64) -> u64 {
    u64::try_from(value % u128::from(q)).expect("residue less than q fits in u64")
}

fn decode_v4_tail_coeff_at(
    params: LatticeParams,
    tail_coefficients: &[u8],
    byte_offset: usize,
) -> LatticePqResult<u32> {
    let end = byte_offset.checked_add(V4_COEFFICIENT_BYTES).ok_or(
        LatticePqError::RepresentationTooLarge {
            material: "public_matrix_tail_index",
            requested: usize::MAX,
            max: MAX_PUBLIC_MATRIX_EXPANDED_BYTES,
        },
    )?;
    let slice =
        tail_coefficients
            .get(byte_offset..end)
            .ok_or(LatticePqError::InvalidEncodingLength {
                material: "public_matrix_tail",
                expected: end,
                got: tail_coefficients.len(),
            })?;
    let mut coeff_bytes = [0_u8; V4_COEFFICIENT_BYTES];
    coeff_bytes.copy_from_slice(slice);
    let coeff = u32::from_le_bytes(coeff_bytes);
    if u64::from(coeff) >= params.q {
        return Err(LatticePqError::InvalidTrapdoorSecret {
            material: "public_matrix_tail",
            reason: "public tail coefficient is not reduced modulo q",
        });
    }
    Ok(coeff)
}

fn route_public_hash(
    scope: TrapdoorScope,
    params: LatticeParams,
    public_seed: &[u8; 32],
    parent_public_matrix_hash: [u8; 32],
    zone_id_hash: [u8; 32],
    period_id_hash: [u8; 32],
    relation_digest: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"fcp-pq/route-public-hash-v1|");
    hasher.update(PRIMITIVE_ROUTE_ID.as_bytes());
    hasher.update(&PRIMITIVE_ROUTE_REVISION.to_le_bytes());
    hasher.update(&[match scope {
        TrapdoorScope::Root => 0,
        TrapdoorScope::Child => 1,
    }]);
    hasher.update(&params_hash(params));
    hasher.update(public_seed);
    hasher.update(&parent_public_matrix_hash);
    hasher.update(&zone_id_hash);
    hasher.update(&period_id_hash);
    hasher.update(relation_digest);
    *hasher.finalize().as_bytes()
}

fn derive_root_public_seed(params: LatticeParams, entropy: &TrapGenEntropy) -> [u8; 32] {
    let mut out = [0_u8; 32];
    shake256_fill(
        b"route-root-public-seed",
        |shaker| {
            update_len_prefixed(shaker, PRIMITIVE_ROUTE_ID.as_bytes());
            Update::update(shaker, &PRIMITIVE_ROUTE_REVISION.to_le_bytes());
            update_params(shaker, params);
            update_len_prefixed(shaker, &entropy.bytes);
        },
        &mut out,
    );
    out
}

fn derive_root_r_seed(params: LatticeParams, entropy: &TrapGenEntropy) -> [u8; 32] {
    let mut out = [0_u8; 32];
    shake256_fill(
        b"route-root-r-seed",
        |shaker| {
            update_len_prefixed(shaker, PRIMITIVE_ROUTE_ID.as_bytes());
            Update::update(shaker, &PRIMITIVE_ROUTE_REVISION.to_le_bytes());
            update_params(shaker, params);
            update_len_prefixed(shaker, &entropy.bytes);
        },
        &mut out,
    );
    out
}

fn derive_child_public_seed(
    parent_pub: &MasterPublicKey,
    zone_id: &[u8; 32],
    period: DelegationPeriod,
    params: LatticeParams,
) -> [u8; 32] {
    let mut out = [0_u8; 32];
    shake256_fill(
        b"route-child-public-seed",
        |shaker| {
            update_len_prefixed(shaker, PRIMITIVE_ROUTE_ID.as_bytes());
            Update::update(shaker, &PRIMITIVE_ROUTE_REVISION.to_le_bytes());
            update_len_prefixed(shaker, &parent_pub.hash);
            update_len_prefixed(shaker, zone_id);
            update_period(shaker, period);
            update_params(shaker, params);
            Update::update(shaker, &[params.depth]);
        },
        &mut out,
    );
    out
}

fn derive_child_r_seed(
    parent_r_seed: &[u8; 32],
    child_public_seed: &[u8; 32],
    zone_id: &[u8; 32],
    period: DelegationPeriod,
    params: LatticeParams,
) -> [u8; 32] {
    let mut out = [0_u8; 32];
    shake256_fill(
        b"route-child-r-seed",
        |shaker| {
            update_len_prefixed(shaker, PRIMITIVE_ROUTE_ID.as_bytes());
            Update::update(shaker, &PRIMITIVE_ROUTE_REVISION.to_le_bytes());
            update_len_prefixed(shaker, parent_r_seed);
            update_len_prefixed(shaker, child_public_seed);
            update_len_prefixed(shaker, zone_id);
            update_period(shaker, period);
            update_params(shaker, params);
        },
        &mut out,
    );
    out
}

fn build_root_basis_envelope(
    params: LatticeParams,
    entropy: &TrapGenEntropy,
) -> LatticePqResult<(MasterPublicKey, MasterTrapdoor)> {
    let public_seed = derive_root_public_seed(params, entropy);
    let r_seed = derive_root_r_seed(params, entropy);
    let public_matrix = route_public_matrix_material(params, &public_seed, &r_seed)?;
    let relation_digest = public_matrix_digest(params, &public_matrix)?;
    let public_hash = route_public_hash(
        TrapdoorScope::Root,
        params,
        &public_seed,
        ZERO_HASH,
        ZERO_HASH,
        ZERO_HASH,
        &relation_digest,
    );
    let entropy_id_hash = entropy.fixture_id_hash.unwrap_or(ZERO_HASH);
    let view = BasisEnvelopeView {
        route_id_hash: route_id_hash(),
        route_revision: PRIMITIVE_ROUTE_REVISION,
        scope: TrapdoorScope::Root,
        params_hash: params_hash(params),
        public_matrix_hash: public_hash,
        parent_public_matrix_hash: ZERO_HASH,
        zone_id_hash: ZERO_HASH,
        period_id_hash: ZERO_HASH,
        entropy_id_hash,
        public_seed,
        r_seed,
        relation_digest,
    };
    let envelope = encode_basis_envelope(&view);
    Ok((
        MasterPublicKey {
            hash: public_hash,
            public_matrix,
            params,
        },
        MasterTrapdoor::from_basis_envelope(params, public_hash, envelope)?,
    ))
}

fn basis_relation_matches_root(
    metadata: TrapdoorRepresentationMetadata,
    bytes: &[u8],
    public: &MasterPublicKey,
) -> bool {
    if metadata.material_kind != TrapdoorMaterialKind::BasisEnvelope {
        return false;
    }
    let Some(view) = parse_basis_envelope(bytes) else {
        return false;
    };
    if view.route_id_hash != route_id_hash()
        || view.route_revision != PRIMITIVE_ROUTE_REVISION
        || view.scope != TrapdoorScope::Root
        || view.params_hash != params_hash(metadata.params)
        || view.public_matrix_hash != metadata.public_matrix_hash
        || view.public_matrix_hash != public.hash
        || view.parent_public_matrix_hash != ZERO_HASH
        || view.zone_id_hash != ZERO_HASH
        || view.period_id_hash != ZERO_HASH
    {
        return false;
    }
    let Ok(expected_material) =
        route_public_matrix_material(metadata.params, &view.public_seed, &view.r_seed)
    else {
        return false;
    };
    if expected_material != public.public_matrix {
        return false;
    }
    let Ok(relation_digest) = public_matrix_digest(metadata.params, &public.public_matrix) else {
        return false;
    };
    let expected_public_hash = route_public_hash(
        TrapdoorScope::Root,
        metadata.params,
        &view.public_seed,
        ZERO_HASH,
        ZERO_HASH,
        ZERO_HASH,
        &relation_digest,
    );
    view.relation_digest == relation_digest && expected_public_hash == public.hash
}

fn basis_relation_matches_child(
    metadata: TrapdoorRepresentationMetadata,
    bytes: &[u8],
    child_public: &ZonePeriodPublicKey,
    parent_public: &MasterPublicKey,
) -> bool {
    if metadata.material_kind != TrapdoorMaterialKind::BasisEnvelope {
        return false;
    }
    let Some(view) = parse_basis_envelope(bytes) else {
        return false;
    };
    let zone_id_hash = *blake3::hash(&child_public.zone_id).as_bytes();
    let period_id_hash = period_hash(child_public.period);
    if view.route_id_hash != route_id_hash()
        || view.route_revision != PRIMITIVE_ROUTE_REVISION
        || view.scope != TrapdoorScope::Child
        || view.params_hash != params_hash(metadata.params)
        || view.public_matrix_hash != metadata.public_matrix_hash
        || view.public_matrix_hash != child_public.hash
        || view.parent_public_matrix_hash != parent_public.hash
        || view.zone_id_hash != zone_id_hash
        || view.period_id_hash != period_id_hash
    {
        return false;
    }
    let Ok(expected_material) =
        route_public_matrix_material(metadata.params, &view.public_seed, &view.r_seed)
    else {
        return false;
    };
    if expected_material != child_public.public_matrix {
        return false;
    }
    let Ok(relation_digest) = public_matrix_digest(metadata.params, &child_public.public_matrix)
    else {
        return false;
    };
    let expected_public_hash = route_public_hash(
        TrapdoorScope::Child,
        metadata.params,
        &view.public_seed,
        parent_public.hash,
        zone_id_hash,
        period_id_hash,
        &relation_digest,
    );
    view.relation_digest == relation_digest && expected_public_hash == child_public.hash
}

// ── Wire-format placeholders ──────────────────────────────────────────────

/// Time window `(start, end)` a delegation certificate is valid in,
/// in **monotonic seconds** since FCP epoch (matches
/// `fcp_policy::lattice_delegation::DelegationPeriod`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationPeriod {
    /// Inclusive lower bound.
    pub start_secs: u64,
    /// Exclusive upper bound.
    pub end_secs: u64,
}

impl DelegationPeriod {
    /// `true` if `secs` falls inside `[start, end)`.
    #[must_use]
    pub const fn contains(&self, secs: u64) -> bool {
        secs >= self.start_secs && secs < self.end_secs
    }
}

/// Master public-matrix bundle returned by [`trap_gen`].
///
/// In the production route, `A_root` is an `n×m` matrix over `Z_q` derived
/// from a public seed plus a verifier-facing tail block. The expanded
/// `V4_REFERENCE` matrix is allocation-bounded at 32 MiB, while the serialized
/// public tail is 1 MiB.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MasterPublicKey {
    /// 32-byte public binding hash for the route material.
    pub hash: [u8; 32],
    /// Verifier-computable public matrix material.
    pub public_matrix: PublicMatrixMaterial,
    /// Parameters this key was generated for.
    pub params: LatticeParams,
}

/// Master trapdoor `T_root` held offline by the owner.
///
/// The current representation is a sealed seed bundle bound to
/// [`LATTICE_REPRESENTATION_VERSION`] and [`LatticeParams`]. It is not sent to
/// verifiers and intentionally does not implement `Serialize`: only public
/// matrix seeds and preimages cross the token boundary.
///
/// Serialization boundary:
///
/// ```compile_fail
/// use fcp_crypto_pq::{trap_gen, LatticeParams};
///
/// let (_, trapdoor) = trap_gen(LatticeParams::SMALL_TEST).unwrap();
/// let _json = serde_json::to_string(&trapdoor).unwrap();
/// ```
///
/// **Constant-time equality** (br-1zlht): the trapdoor IS the
/// load-bearing secret of the lattice-trapdoor scheme. Equality via
/// [`subtle::ConstantTimeEq`] not the derived `[u8; N]::eq`.
#[derive(Clone, Eq)]
pub struct MasterTrapdoor {
    metadata: TrapdoorRepresentationMetadata,
    pub(crate) bytes: Vec<u8>,
}

impl MasterTrapdoor {
    /// Build a fixture root trapdoor from encoded seed-bundle bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when parameters are malformed or the fixture secret
    /// length does not match the profile-derived seed-bundle length.
    pub fn from_fixture_seed_bundle(
        params: LatticeParams,
        public_matrix_hash: [u8; 32],
        bytes: Vec<u8>,
    ) -> LatticePqResult<Self> {
        let metadata = trapdoor_metadata(
            TrapdoorScope::Root,
            TrapdoorMaterialKind::FixtureShakeSeedBundle,
            params,
            public_matrix_hash,
            None,
            bytes.len(),
        )?;
        Ok(Self { metadata, bytes })
    }

    /// Build a future basis-capable root trapdoor envelope.
    ///
    /// # Errors
    ///
    /// Returns an error when parameters are malformed or the basis envelope is
    /// empty or exceeds the secret storage ceiling.
    pub fn from_basis_envelope(
        params: LatticeParams,
        public_matrix_hash: [u8; 32],
        bytes: Vec<u8>,
    ) -> LatticePqResult<Self> {
        let metadata = trapdoor_metadata(
            TrapdoorScope::Root,
            TrapdoorMaterialKind::BasisEnvelope,
            params,
            public_matrix_hash,
            None,
            bytes.len(),
        )?;
        Ok(Self { metadata, bytes })
    }

    /// Redaction-safe metadata for this trapdoor.
    #[must_use]
    pub const fn metadata(&self) -> TrapdoorRepresentationMetadata {
        self.metadata
    }

    /// Representation version bound into this trapdoor.
    #[must_use]
    pub const fn representation_version(&self) -> u16 {
        self.metadata.version
    }

    /// Parameter profile bound into this trapdoor.
    #[must_use]
    pub const fn params(&self) -> LatticeParams {
        self.metadata.params
    }

    /// Secret material route for this trapdoor.
    #[must_use]
    pub const fn material_kind(&self) -> TrapdoorMaterialKind {
        self.metadata.material_kind
    }

    /// Redaction-safe secret storage length bucket.
    #[must_use]
    pub const fn secret_storage_len_bucket(&self) -> SecretStorageLengthBucket {
        self.metadata.secret_storage_len_bucket
    }

    /// Encoded secret storage byte length.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.bytes.len()
    }

    /// Redaction-safe relation summary against the public root key.
    #[must_use]
    pub fn relation_summary(&self, public: &MasterPublicKey) -> TrapdoorRelationSummary {
        let metadata = self.metadata;
        let root_public_matrix_hash = public.hash;
        let structurally_matches = metadata.scope == TrapdoorScope::Root
            && metadata.parent_public_matrix_hash.is_none()
            && metadata.params == public.params
            && metadata.public_matrix_hash == root_public_matrix_hash;
        let result = if !structurally_matches {
            TrapdoorRelationResult::MetadataMismatch
        } else if metadata.material_kind == TrapdoorMaterialKind::FixtureShakeSeedBundle {
            TrapdoorRelationResult::FixtureOnly
        } else if basis_relation_matches_root(metadata, &self.bytes, public) {
            TrapdoorRelationResult::MetadataConsistent
        } else {
            TrapdoorRelationResult::MetadataMismatch
        };
        TrapdoorRelationSummary {
            metadata,
            result,
            norm_quality_bucket: norm_quality_bucket(
                metadata.material_kind,
                metadata.secret_storage_len_bucket,
            ),
        }
    }
}

impl PartialEq for MasterTrapdoor {
    fn eq(&self, other: &Self) -> bool {
        self.metadata == other.metadata && constant_time_bytes_eq(&self.bytes, &other.bytes)
    }
}

impl std::fmt::Debug for MasterTrapdoor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasterTrapdoor")
            .field("metadata", &self.metadata)
            .field("encoded_len", &self.bytes.len())
            .field("secret_material", &"<redacted>")
            .finish()
    }
}

impl Drop for MasterTrapdoor {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// Per-`(zone, period)` public matrix `A_zp` returned by [`delegate`].
///
/// As with [`MasterPublicKey`], this carries verifier-computable public
/// material rather than the private basis seed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZonePeriodPublicKey {
    /// 32-byte public binding hash for the route material.
    pub hash: [u8; 32],
    /// Verifier-computable public matrix material.
    pub public_matrix: PublicMatrixMaterial,
    /// Zone identifier this delegation authorizes for. Opaque to this
    /// crate — `fcp_policy` owns the canonical `ZoneId` type.
    pub zone_id: [u8; 32],
    /// Time window this delegation is valid in.
    pub period: DelegationPeriod,
    /// Parameters inherited from the master key.
    pub params: LatticeParams,
}

/// Per-`(zone, period)` trapdoor `T_zp` returned by [`delegate`].
///
/// Held by the issuance node; used to derive sub-tokens via [`sample_pre`].
/// The secret child trapdoor intentionally does not implement `Serialize`.
///
/// ```compile_fail
/// use fcp_crypto_pq::{delegate, trap_gen, DelegationPeriod, LatticeParams};
///
/// let params = LatticeParams::SMALL_TEST;
/// let (master_public, master_trapdoor) = trap_gen(params).unwrap();
/// let period = DelegationPeriod {
///     start_secs: 1,
///     end_secs: 2,
/// };
/// let (_, child_trapdoor) =
///     delegate(&master_public, &master_trapdoor, [0_u8; 32], period, params).unwrap();
/// let _json = serde_json::to_string(&child_trapdoor).unwrap();
/// ```
///
/// **Constant-time equality** (br-1zlht): see [`MasterTrapdoor`].
#[derive(Clone, Eq)]
pub struct ZonePeriodTrapdoor {
    metadata: TrapdoorRepresentationMetadata,
    pub(crate) bytes: Vec<u8>,
}

impl ZonePeriodTrapdoor {
    /// Build a fixture child trapdoor from encoded seed-bundle bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when parameters are malformed, parent linkage is
    /// missing, or the fixture secret length does not match the profile.
    pub fn from_fixture_seed_bundle(
        params: LatticeParams,
        parent_public_matrix_hash: [u8; 32],
        public_matrix_hash: [u8; 32],
        bytes: Vec<u8>,
    ) -> LatticePqResult<Self> {
        let metadata = trapdoor_metadata(
            TrapdoorScope::Child,
            TrapdoorMaterialKind::FixtureShakeSeedBundle,
            params,
            public_matrix_hash,
            Some(parent_public_matrix_hash),
            bytes.len(),
        )?;
        Ok(Self { metadata, bytes })
    }

    /// Build a future basis-capable child trapdoor envelope.
    ///
    /// # Errors
    ///
    /// Returns an error when parameters are malformed or the basis envelope is
    /// empty or exceeds the secret storage ceiling.
    pub fn from_basis_envelope(
        params: LatticeParams,
        parent_public_matrix_hash: [u8; 32],
        public_matrix_hash: [u8; 32],
        bytes: Vec<u8>,
    ) -> LatticePqResult<Self> {
        let metadata = trapdoor_metadata(
            TrapdoorScope::Child,
            TrapdoorMaterialKind::BasisEnvelope,
            params,
            public_matrix_hash,
            Some(parent_public_matrix_hash),
            bytes.len(),
        )?;
        Ok(Self { metadata, bytes })
    }

    /// Redaction-safe metadata for this trapdoor.
    #[must_use]
    pub const fn metadata(&self) -> TrapdoorRepresentationMetadata {
        self.metadata
    }

    /// Representation version bound into this trapdoor.
    #[must_use]
    pub const fn representation_version(&self) -> u16 {
        self.metadata.version
    }

    /// Parameter profile bound into this trapdoor.
    #[must_use]
    pub const fn params(&self) -> LatticeParams {
        self.metadata.params
    }

    /// Secret material route for this trapdoor.
    #[must_use]
    pub const fn material_kind(&self) -> TrapdoorMaterialKind {
        self.metadata.material_kind
    }

    /// Redaction-safe secret storage length bucket.
    #[must_use]
    pub const fn secret_storage_len_bucket(&self) -> SecretStorageLengthBucket {
        self.metadata.secret_storage_len_bucket
    }

    /// Encoded secret storage byte length.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.bytes.len()
    }

    /// Redaction-safe relation summary against the child and parent public keys.
    #[must_use]
    pub fn relation_summary(
        &self,
        child_public: &ZonePeriodPublicKey,
        parent_public: &MasterPublicKey,
    ) -> TrapdoorRelationSummary {
        let metadata = self.metadata;
        let structurally_matches = metadata.scope == TrapdoorScope::Child
            && metadata.parent_public_matrix_hash == Some(parent_public.hash)
            && metadata.params == child_public.params
            && metadata.params == parent_public.params
            && metadata.public_matrix_hash == child_public.hash;
        let result = if !structurally_matches {
            TrapdoorRelationResult::MetadataMismatch
        } else if metadata.material_kind == TrapdoorMaterialKind::FixtureShakeSeedBundle {
            TrapdoorRelationResult::FixtureOnly
        } else if basis_relation_matches_child(metadata, &self.bytes, child_public, parent_public) {
            TrapdoorRelationResult::MetadataConsistent
        } else {
            TrapdoorRelationResult::MetadataMismatch
        };
        TrapdoorRelationSummary {
            metadata,
            result,
            norm_quality_bucket: norm_quality_bucket(
                metadata.material_kind,
                metadata.secret_storage_len_bucket,
            ),
        }
    }
}

impl PartialEq for ZonePeriodTrapdoor {
    fn eq(&self, other: &Self) -> bool {
        self.metadata == other.metadata && constant_time_bytes_eq(&self.bytes, &other.bytes)
    }
}

impl std::fmt::Debug for ZonePeriodTrapdoor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZonePeriodTrapdoor")
            .field("metadata", &self.metadata)
            .field("encoded_len", &self.bytes.len())
            .field("secret_material", &"<redacted>")
            .finish()
    }
}

impl Drop for ZonePeriodTrapdoor {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// Hash of an operation context `H(zone | period | op | principal)`,
/// expanded into the verification equation's right-hand side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationHash(pub [u8; 32]);

/// Short lattice preimage `e` such that `A_zp · e ≡ h (mod q)`.
///
/// Real impl: a vector in `Z_q^m` with `‖e‖₂ ≤ B`. The wire/storage encoding
/// is profile-derived (`m × coefficient_bytes`) and validated by
/// [`LatticePreimage::from_encoded_bytes`].
///
/// **Constant-time equality** (br-1zlht): the preimage is the
/// signature material of the lattice-trapdoor scheme; equality via
/// [`subtle::ConstantTimeEq`].
#[derive(Clone, Eq, Serialize, Deserialize)]
pub struct LatticePreimage {
    /// Opaque preimage bytes.
    #[serde(with = "hex_vec")]
    pub bytes: Vec<u8>,
}

impl LatticePreimage {
    /// Build a preimage from encoded bytes after checking the profile-derived
    /// wire length.
    ///
    /// # Errors
    ///
    /// Returns [`LatticePqError::InvalidParameter`] or
    /// [`LatticePqError::RepresentationTooLarge`] when `params` do not define a
    /// bounded preimage profile, and [`LatticePqError::InvalidEncodingLength`]
    /// when `bytes` has the wrong profile-derived length.
    pub fn from_encoded_bytes(params: LatticeParams, bytes: Vec<u8>) -> LatticePqResult<Self> {
        let expected = params.preimage_encoded_bytes()?;
        if bytes.len() != expected {
            return Err(LatticePqError::InvalidEncodingLength {
                material: "preimage",
                expected,
                got: bytes.len(),
            });
        }
        Ok(Self { bytes })
    }

    /// Deterministic all-zero fixture with the correct profile-derived length.
    ///
    /// # Errors
    ///
    /// Returns [`LatticePqError::InvalidParameter`] or
    /// [`LatticePqError::RepresentationTooLarge`] when `params` do not define a
    /// bounded preimage profile.
    pub fn fixture_zero(params: LatticeParams) -> LatticePqResult<Self> {
        let len = params.preimage_encoded_bytes()?;
        Ok(Self {
            bytes: vec![0_u8; len],
        })
    }

    /// Encoded preimage byte length.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.bytes.len()
    }

    /// Borrow the encoded preimage bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl PartialEq for LatticePreimage {
    fn eq(&self, other: &Self) -> bool {
        constant_time_bytes_eq(&self.bytes, &other.bytes)
    }
}

impl std::fmt::Debug for LatticePreimage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LatticePreimage")
            .field("encoded_len", &self.bytes.len())
            .field("secret_material", &"<redacted>")
            .finish()
    }
}

impl Drop for LatticePreimage {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

fn constant_time_bytes_eq(left: &[u8], right: &[u8]) -> bool {
    use subtle::ConstantTimeEq;

    if left.len() != right.len() {
        return false;
    }
    left.ct_eq(right).into()
}

mod hex_vec {
    use serde::{Deserialize, Deserializer, Serializer};

    /// Hard allocation bound for any hex-encoded byte envelope in this crate.
    /// Exact, parameter-derived lengths are enforced at the use sites; this
    /// cap only prevents unbounded allocation from hostile input.
    const MAX_HEX_CHARS: usize = 2 * super::MAX_PUBLIC_MATRIX_EXPANDED_BYTES;

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        if s.len() > MAX_HEX_CHARS {
            return Err(serde::de::Error::custom(format!(
                "hex byte envelope exceeds {MAX_HEX_CHARS} characters"
            )));
        }
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

// ── Deterministic expansion scaffolding ───────────────────────────────────

const SHAKE_DOMAIN_PREFIX: &[u8] = b"fcp-crypto-pq/lattice-v1";

fn shake256_fill(tag: &[u8], feed: impl FnOnce(&mut Shake256), out: &mut [u8]) {
    let mut shaker = Shake256::default();
    update_len_prefixed(&mut shaker, SHAKE_DOMAIN_PREFIX);
    update_len_prefixed(&mut shaker, tag);
    feed(&mut shaker);
    let mut reader = shaker.finalize_xof();
    reader.read(out);
}

fn update_len_prefixed(shaker: &mut Shake256, bytes: &[u8]) {
    let len = u64::try_from(bytes.len()).expect("SHAKE input length fits in u64");
    Update::update(shaker, &len.to_le_bytes());
    Update::update(shaker, bytes);
}

fn update_period(shaker: &mut Shake256, period: DelegationPeriod) {
    Update::update(shaker, &period.start_secs.to_le_bytes());
    Update::update(shaker, &period.end_secs.to_le_bytes());
}

fn update_params(shaker: &mut Shake256, params: LatticeParams) {
    Update::update(shaker, &params.n.to_le_bytes());
    Update::update(shaker, &params.q.to_le_bytes());
    Update::update(shaker, &params.m.to_le_bytes());
    Update::update(shaker, &params.sigma_x100.to_le_bytes());
    Update::update(shaker, &[params.depth]);
}

fn trap_gen_seed(params: LatticeParams, purpose: &[u8]) -> [u8; 32] {
    let mut out = [0_u8; 32];
    shake256_fill(
        b"trap-gen-seed",
        |shaker| {
            update_params(shaker, params);
            update_len_prefixed(shaker, purpose);
        },
        &mut out,
    );
    out
}

fn zone_period_trapdoor_seed(
    parent_trap: &MasterTrapdoor,
    matrix_seed: &[u8; 32],
    zone_id: &[u8; 32],
    period: DelegationPeriod,
    params: LatticeParams,
) -> LatticePqResult<Vec<u8>> {
    let mut out = vec![0_u8; params.trapdoor_storage_bytes()?];
    shake256_fill(
        b"zone-period-trapdoor-seed-bundle",
        |shaker| {
            update_len_prefixed(shaker, &parent_trap.bytes);
            update_len_prefixed(shaker, matrix_seed);
            update_len_prefixed(shaker, zone_id);
            update_period(shaker, period);
            update_params(shaker, params);
        },
        &mut out,
    );
    Ok(out)
}

fn trap_gen_secret_bundle(params: LatticeParams) -> LatticePqResult<Vec<u8>> {
    let mut out = vec![0_u8; params.trapdoor_storage_bytes()?];
    shake256_fill(
        b"master-trapdoor-seed-bundle",
        |shaker| {
            update_params(shaker, params);
            update_len_prefixed(shaker, b"master-trapdoor");
        },
        &mut out,
    );
    Ok(out)
}

/// Deterministically derive the public matrix seed for a `(zone, period)` child.
///
/// This is only the SHAKE256 public-seed scaffold for the eventual
/// matrix-valued hash. It is **not** CHKP basis-shortening and does not prove
/// possession of a trapdoor.
#[must_use]
pub fn zone_period_matrix_seed(
    parent_pub: &MasterPublicKey,
    zone_id: &[u8; 32],
    period: DelegationPeriod,
    params: LatticeParams,
) -> [u8; 32] {
    let mut out = [0_u8; 32];
    shake256_fill(
        b"zone-period-matrix-seed",
        |shaker| {
            update_len_prefixed(shaker, &parent_pub.hash);
            update_len_prefixed(shaker, zone_id);
            update_period(shaker, period);
            update_params(shaker, params);
        },
        &mut out,
    );
    out
}

/// Expand an operation hash into the verification right-hand side in `Z_q^n`.
///
/// This pins the deterministic SHAKE256 rejection-sampling fixture needed by
/// the future `A · e ≡ h (mod q)` check. It does **not** sample a preimage,
/// validate a norm bound, or establish lattice soundness.
///
/// # Panics
///
/// Panics only on targets where `usize` cannot represent a `u32` lattice
/// dimension.
#[must_use]
pub fn expand_operation_hash_rhs(h: OperationHash, params: LatticeParams) -> Vec<u64> {
    let len = usize::try_from(params.n).expect("u32 lattice dimension fits in usize");
    let modulus = params.q.max(1);
    let modulus_u128 = u128::from(modulus);
    let range = u128::from(u64::MAX) + 1;
    let reject_above = range - (range % modulus_u128);

    let mut out = Vec::with_capacity(len);
    let mut reader_buf = [0_u8; 8];
    let mut shaker = Shake256::default();
    update_len_prefixed(&mut shaker, SHAKE_DOMAIN_PREFIX);
    update_len_prefixed(&mut shaker, b"operation-rhs-vector");
    update_len_prefixed(&mut shaker, &h.0);
    update_params(&mut shaker, params);
    let mut reader = shaker.finalize_xof();

    while out.len() < len {
        reader.read(&mut reader_buf);
        let candidate = u128::from(u64::from_le_bytes(reader_buf));
        if candidate < reject_above {
            let coeff = candidate % modulus_u128;
            out.push(u64::try_from(coeff).expect("coefficient fits in u64"));
        }
    }
    out
}

/// Reconstruct one public matrix coefficient from verifier-facing material.
///
/// This is the public half of the route: it never reads a trapdoor envelope or
/// secret `R` seed. It exists so [`verify`] can evaluate `A_zp * e` from the
/// same public material that crosses the policy/certificate boundary.
///
/// # Errors
///
/// Returns [`LatticePqError::ParameterMismatch`] when `params` do not match the
/// key, [`LatticePqError::UnsupportedPrimitiveRoute`] when the route does not
/// support verifier reconstruction for the profile, and encoding/parameter
/// errors for malformed public material or out-of-range coordinates.
pub fn reconstruct_public_matrix_coefficient(
    key: &ZonePeriodPublicKey,
    row: u32,
    col: u32,
    params: LatticeParams,
) -> LatticePqResult<u64> {
    if params != key.params {
        return Err(LatticePqError::ParameterMismatch {
            caller: params,
            key: key.params,
        });
    }
    public_matrix_coeff(params, &key.public_matrix, row, col)
}

/// Recompute the public matrix material digest from verifier-facing data.
///
/// # Errors
///
/// Returns the same route and encoding errors as
/// [`reconstruct_public_matrix_coefficient`].
pub fn reconstruct_public_matrix_digest(
    key: &ZonePeriodPublicKey,
    params: LatticeParams,
) -> LatticePqResult<[u8; 32]> {
    if params != key.params {
        return Err(LatticePqError::ParameterMismatch {
            caller: params,
            key: key.params,
        });
    }
    public_matrix_digest(params, &key.public_matrix)
}

fn centered_lift(coeff: u64, q: u64) -> i128 {
    if coeff > q / 2 {
        i128::from(coeff) - i128::from(q)
    } else {
        i128::from(coeff)
    }
}

const fn square_u128(value: u128) -> u128 {
    value.saturating_mul(value)
}

fn centered_abs_u128(coeff: u64, q: u64) -> u128 {
    centered_lift(coeff, q).unsigned_abs()
}

fn route_preimage_nonzero_budget(params: LatticeParams) -> LatticePqResult<usize> {
    let _dims = route_dimensions(params, "preimage_norm_bound")?;
    if params == LatticeParams::V4_REFERENCE {
        let rhs_terms = usize::try_from(params.n).expect("u32 n fits in usize");
        let route_terms = rhs_terms
            .checked_mul(usize::try_from(V4_SPARSE_R_WEIGHT).expect("weight fits in usize"))
            .and_then(|terms| terms.checked_add(rhs_terms))
            .expect("V4 route preimage nonzero budget fits in usize");
        Ok(route_terms)
    } else {
        Ok(usize::try_from(params.m).expect("u32 m fits in usize"))
    }
}

/// Hard centered-coefficient norm bound enforced by [`verify`].
///
/// The current route samples `e = [R*x ; x]` for the centered operation RHS
/// `x`. `V4_REFERENCE` uses a sparse `R` with `V4_SPARSE_R_WEIGHT` non-zero
/// entries per RHS coordinate, so the public verifier enforces the same
/// route-level nonzero budget without learning the secret `R` seed. The bound
/// is intentionally a hard fail-closed cap over centered residues, not a
/// structural success check.
///
/// # Errors
///
/// Returns parameter or route errors for malformed or unsupported profiles.
pub fn preimage_norm_bound_squared(params: LatticeParams) -> LatticePqResult<u128> {
    let max_centered = u128::from(params.q / 2);
    let max_centered_squared = square_u128(max_centered);
    let budget = route_preimage_nonzero_budget(params)? as u128;
    Ok(max_centered_squared
        .saturating_mul(budget)
        .saturating_sub(1))
}

fn decode_preimage_coeff(
    params: LatticeParams,
    bytes: &[u8],
    index: usize,
) -> LatticePqResult<u64> {
    let coefficient_bytes = params.coefficient_bytes()?;
    let offset =
        index
            .checked_mul(coefficient_bytes)
            .ok_or(LatticePqError::RepresentationTooLarge {
                material: "preimage_index",
                requested: usize::MAX,
                max: MAX_PREIMAGE_ENCODED_BYTES,
            })?;
    let end =
        offset
            .checked_add(coefficient_bytes)
            .ok_or(LatticePqError::RepresentationTooLarge {
                material: "preimage_index",
                requested: usize::MAX,
                max: MAX_PREIMAGE_ENCODED_BYTES,
            })?;
    let slice = bytes
        .get(offset..end)
        .ok_or(LatticePqError::InvalidEncodingLength {
            material: "preimage",
            expected: params.preimage_encoded_bytes()?,
            got: bytes.len(),
        })?;
    let mut coeff_bytes = [0_u8; 8];
    coeff_bytes[..coefficient_bytes].copy_from_slice(slice);
    let coeff = u64::from_le_bytes(coeff_bytes);
    if coeff >= params.q {
        return Err(LatticePqError::InvalidParameter {
            field: "preimage_coefficient",
            value: coeff,
            reason: "preimage coefficient must be reduced modulo q",
        });
    }
    Ok(coeff)
}

fn preimage_coefficients(
    params: LatticeParams,
    preimage: &LatticePreimage,
) -> LatticePqResult<Vec<u64>> {
    let expected = params.preimage_encoded_bytes()?;
    if preimage.bytes.len() != expected {
        return Err(LatticePqError::InvalidEncodingLength {
            material: "preimage",
            expected,
            got: preimage.bytes.len(),
        });
    }
    let coeff_count = usize::try_from(params.m).expect("u32 m fits in usize");
    (0..coeff_count)
        .map(|index| decode_preimage_coeff(params, &preimage.bytes, index))
        .collect()
}

fn preimage_norm_squared_from_coefficients(params: LatticeParams, coeffs: &[u64]) -> u128 {
    coeffs.iter().fold(0_u128, |acc, coeff| {
        acc.saturating_add(square_u128(centered_abs_u128(*coeff, params.q)))
    })
}

/// Compute the centered `l2` norm squared for an encoded lattice preimage.
///
/// # Errors
///
/// Returns parameter, allocation, length, or coefficient-canonicalization
/// errors if the preimage cannot be decoded for `params`.
pub fn preimage_norm_squared(
    params: LatticeParams,
    preimage: &LatticePreimage,
) -> LatticePqResult<u128> {
    let coeffs = preimage_coefficients(params, preimage)?;
    Ok(preimage_norm_squared_from_coefficients(params, &coeffs))
}

fn constant_time_residue_vec_eq(left: &[u64], right: &[u64]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0_u64;
    for (left_coeff, right_coeff) in left.iter().zip(right.iter()) {
        diff |= left_coeff ^ right_coeff;
    }
    diff == 0
}

fn validated_zone_basis_view(
    key: &ZonePeriodPublicKey,
    trap: &ZonePeriodTrapdoor,
    params: LatticeParams,
) -> LatticePqResult<BasisEnvelopeView> {
    let metadata = trap.metadata();
    if metadata.scope != TrapdoorScope::Child
        || metadata.material_kind != TrapdoorMaterialKind::BasisEnvelope
        || metadata.params != params
        || metadata.public_matrix_hash != key.hash
    {
        return Err(LatticePqError::InvalidTrapdoorSecret {
            material: "zone_period_basis_envelope",
            reason: "trapdoor metadata does not match the zone-period public key",
        });
    }
    let view = parse_basis_envelope(&trap.bytes).ok_or(LatticePqError::InvalidTrapdoorSecret {
        material: "zone_period_basis_envelope",
        reason: "basis envelope could not be decoded",
    })?;
    let zone_id_hash = *blake3::hash(&key.zone_id).as_bytes();
    let period_id_hash = period_hash(key.period);
    if view.route_id_hash != route_id_hash()
        || view.route_revision != PRIMITIVE_ROUTE_REVISION
        || view.scope != TrapdoorScope::Child
        || view.params_hash != params_hash(params)
        || view.public_matrix_hash != key.hash
        || view.zone_id_hash != zone_id_hash
        || view.period_id_hash != period_id_hash
    {
        return Err(LatticePqError::InvalidTrapdoorSecret {
            material: "zone_period_basis_envelope",
            reason: "basis envelope route or public binding metadata mismatch",
        });
    }
    let expected_material = route_public_matrix_material(params, &view.public_seed, &view.r_seed)?;
    if expected_material != key.public_matrix {
        return Err(LatticePqError::InvalidTrapdoorSecret {
            material: "zone_period_basis_envelope",
            reason: "basis envelope R seed does not reproduce the public matrix material",
        });
    }
    let relation_digest = public_matrix_digest(params, &key.public_matrix)?;
    let expected_public_hash = route_public_hash(
        TrapdoorScope::Child,
        params,
        &view.public_seed,
        view.parent_public_matrix_hash,
        zone_id_hash,
        period_id_hash,
        &relation_digest,
    );
    if view.relation_digest != relation_digest || expected_public_hash != key.hash {
        return Err(LatticePqError::InvalidTrapdoorSecret {
            material: "zone_period_basis_envelope",
            reason: "basis envelope relation digest does not match the public key",
        });
    }
    Ok(view)
}

fn route_preimage_coefficients(
    params: LatticeParams,
    r_seed: &[u8; 32],
    rhs: &[u64],
) -> LatticePqResult<Vec<u64>> {
    let dims = route_dimensions(params, "sample_pre")?;
    if rhs.len() != usize::try_from(params.n).expect("u32 n fits in usize") {
        return Err(LatticePqError::InvalidEncodingLength {
            material: "operation_rhs",
            expected: usize::try_from(params.n).expect("u32 n fits in usize"),
            got: rhs.len(),
        });
    }
    let mut centered = vec![0_i128; usize::try_from(params.m).expect("u32 m fits in usize")];
    let abar_cols = usize::try_from(dims.abar_cols).expect("u32 A_bar cols fit in usize");
    for (gadget_col, rhs_coeff) in rhs.iter().enumerate() {
        let x = centered_lift(*rhs_coeff, params.q);
        for (abar_col, r_coeff) in route_r_support(
            params,
            r_seed,
            u32::try_from(gadget_col).expect("gadget col fits in u32"),
            dims,
        )? {
            let index = usize::try_from(abar_col).expect("u32 A_bar col fits in usize");
            centered[index] += i128::from(r_coeff) * x;
        }
        centered[abar_cols + gadget_col] = x;
    }
    Ok(centered
        .into_iter()
        .map(|coeff| reduce_i128_mod_q(coeff, params.q))
        .collect())
}

fn encode_preimage_coefficients(
    params: LatticeParams,
    coeffs: &[u64],
) -> LatticePqResult<LatticePreimage> {
    if coeffs.len() != usize::try_from(params.m).expect("u32 m fits in usize") {
        return Err(LatticePqError::InvalidEncodingLength {
            material: "preimage",
            expected: usize::try_from(params.m).expect("u32 m fits in usize"),
            got: coeffs.len(),
        });
    }
    let mut bytes = Vec::with_capacity(params.preimage_encoded_bytes()?);
    for coeff in coeffs {
        encode_coeff(params, *coeff, &mut bytes)?;
    }
    LatticePreimage::from_encoded_bytes(params, bytes)
}

fn public_matrix_vector_product_v4(
    params: LatticeParams,
    material: &PublicMatrixMaterial,
    coeffs: &[u64],
    dims: RouteDimensions,
) -> LatticePqResult<Vec<u64>> {
    debug_assert_eq!(params, LatticeParams::V4_REFERENCE);
    let _expected_len = validate_route_public_matrix_material_header(params, material)?;
    let abar_terms = route_preimage_abar_terms(dims, coeffs);
    let selected_cols = abar_terms.iter().map(|(col, _)| *col).collect::<Vec<_>>();
    let abar_coefficients = v4_selected_abar_coefficients(params, material, &selected_cols);
    let rows = usize::try_from(params.n).expect("u32 n fits in usize");
    if rows < V4_VERIFY_PARALLEL_ROW_THRESHOLD {
        return public_matrix_vector_product_v4_serial(
            params,
            material,
            coeffs,
            dims,
            &abar_terms,
            &abar_coefficients,
        );
    }
    (0..params.n)
        .into_par_iter()
        .with_min_len(32)
        .map(|row| {
            v4_public_matrix_row_product(
                params,
                material,
                coeffs,
                dims,
                &abar_terms,
                &abar_coefficients,
                row,
            )
        })
        .collect()
}

fn public_matrix_vector_product_v4_serial(
    params: LatticeParams,
    material: &PublicMatrixMaterial,
    coeffs: &[u64],
    dims: RouteDimensions,
    abar_terms: &[(u32, u64)],
    abar_coefficients: &[u32],
) -> LatticePqResult<Vec<u64>> {
    let mut out = Vec::with_capacity(usize::try_from(params.n).expect("u32 n fits in usize"));
    for row in 0..params.n {
        out.push(v4_public_matrix_row_product(
            params,
            material,
            coeffs,
            dims,
            abar_terms,
            abar_coefficients,
            row,
        )?);
    }
    Ok(out)
}

fn v4_public_matrix_row_product(
    params: LatticeParams,
    material: &PublicMatrixMaterial,
    coeffs: &[u64],
    dims: RouteDimensions,
    abar_terms: &[(u32, u64)],
    abar_coefficients: &[u32],
    row: u32,
) -> LatticePqResult<u64> {
    let abar_cols = usize::try_from(dims.abar_cols).expect("u32 A_bar cols fit in usize");
    let gadget_cols = usize::try_from(dims.gadget_cols).expect("u32 gadget cols fit in usize");
    let selected_cols = abar_terms.len();
    let row_usize = usize::try_from(row).expect("u32 row fits in usize");
    let row_start = row_usize * selected_cols;
    let row_tail_start = row_usize
        .checked_mul(gadget_cols)
        .and_then(|base| base.checked_mul(V4_COEFFICIENT_BYTES))
        .ok_or(LatticePqError::RepresentationTooLarge {
            material: "public_matrix_tail_index",
            requested: usize::MAX,
            max: MAX_PUBLIC_MATRIX_EXPANDED_BYTES,
        })?;
    debug_assert_eq!(
        params
            .coefficient_bytes()
            .expect("V4 coefficient width is valid"),
        V4_COEFFICIENT_BYTES
    );

    let mut sum = 0_u128;
    for (selected_index, (_, preimage_coeff)) in abar_terms.iter().enumerate() {
        let matrix_coeff = abar_coefficients[row_start + selected_index];
        sum += u128::from(matrix_coeff) * u128::from(*preimage_coeff);
    }
    for tail_col in 0..gadget_cols {
        let preimage_coeff = coeffs[abar_cols + tail_col];
        let byte_offset = row_tail_start + tail_col * V4_COEFFICIENT_BYTES;
        let matrix_coeff =
            decode_v4_tail_coeff_at(params, &material.tail_coefficients, byte_offset)?;
        if preimage_coeff != 0 {
            sum += u128::from(matrix_coeff) * u128::from(preimage_coeff);
        }
    }
    Ok(reduce_u128_mod_q(sum, params.q))
}

fn public_matrix_vector_product(
    params: LatticeParams,
    material: &PublicMatrixMaterial,
    coeffs: &[u64],
) -> LatticePqResult<Vec<u64>> {
    let dims = route_dimensions(params, "verify")?;
    if coeffs.len() != usize::try_from(params.m).expect("u32 m fits in usize") {
        return Err(LatticePqError::InvalidEncodingLength {
            material: "preimage",
            expected: usize::try_from(params.m).expect("u32 m fits in usize"),
            got: coeffs.len(),
        });
    }
    if params == LatticeParams::V4_REFERENCE {
        return public_matrix_vector_product_v4(params, material, coeffs, dims);
    }
    validate_route_public_matrix_material(params, material)?;
    let abar_cols = usize::try_from(dims.abar_cols).expect("u32 A_bar cols fit in usize");
    let gadget_cols = usize::try_from(dims.gadget_cols).expect("u32 gadget cols fit in usize");
    let mut out = Vec::with_capacity(usize::try_from(params.n).expect("u32 n fits in usize"));
    for row in 0..params.n {
        let mut sum = 0_i128;
        for (col, preimage_coeff) in coeffs.iter().take(abar_cols).enumerate() {
            if *preimage_coeff == 0 {
                continue;
            }
            let matrix_coeff = public_coeff(
                params,
                &material.public_seed,
                row,
                u32::try_from(col).expect("A_bar col fits in u32"),
            );
            sum += i128::from(matrix_coeff) * i128::from(*preimage_coeff);
        }
        for tail_col in 0..gadget_cols {
            let preimage_coeff = coeffs[abar_cols + tail_col];
            if preimage_coeff == 0 {
                continue;
            }
            let tail_index = usize::try_from(row)
                .expect("u32 row fits in usize")
                .checked_mul(gadget_cols)
                .and_then(|base| base.checked_add(tail_col))
                .ok_or(LatticePqError::RepresentationTooLarge {
                    material: "public_matrix_tail_index",
                    requested: usize::MAX,
                    max: MAX_PUBLIC_MATRIX_EXPANDED_BYTES,
                })?;
            let matrix_coeff = decode_coeff(params, &material.tail_coefficients, tail_index)?;
            sum += i128::from(matrix_coeff) * i128::from(preimage_coeff);
        }
        out.push(reduce_i128_mod_q(sum, params.q));
    }
    Ok(out)
}

// ── Errors ────────────────────────────────────────────────────────────────

/// Failure modes for the lattice-trapdoor primitives.
///
/// Supported route primitives use [`LatticePqError::UnsupportedPrimitiveRoute`]
/// when a parameter profile is outside the reviewed internal route instead of
/// returning fixture success. [`LatticePqError::NotImplemented`] is retained
/// for future primitive surfaces that have not landed yet.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LatticePqError {
    /// A primitive surface is not implemented yet.
    #[error("lattice primitive `{primitive}` not implemented (responsible bead: {bead})")]
    NotImplemented {
        /// Name of the primitive that was called.
        primitive: &'static str,
        /// Bead ID expected to land the implementation.
        bead: &'static str,
    },

    /// The reviewed primitive route does not support this profile yet.
    #[error(
        "unsupported lattice primitive route `{route_id}` for `{primitive}` profile `{profile}`: {reason}"
    )]
    UnsupportedPrimitiveRoute {
        /// Primitive that rejected the route/profile pair.
        primitive: &'static str,
        /// Route id selected by the reviewed route packet.
        route_id: &'static str,
        /// Parameter profile name.
        profile: &'static str,
        /// Human-readable rejection reason.
        reason: &'static str,
    },

    /// Parameter profile is malformed before any cryptographic work starts.
    #[error("invalid lattice parameter `{field}`={value}: {reason}")]
    InvalidParameter {
        /// Parameter field name.
        field: &'static str,
        /// Rejected value.
        value: u64,
        /// Human-readable reason.
        reason: &'static str,
    },

    /// Representation implied by the parameters would exceed the crate's
    /// explicit allocation ceiling.
    #[error(
        "lattice representation `{material}` too large: requested {requested} bytes, max {max}"
    )]
    RepresentationTooLarge {
        /// Material being represented.
        material: &'static str,
        /// Requested encoded or expanded byte count.
        requested: usize,
        /// Hard ceiling.
        max: usize,
    },

    /// Encoded material does not match the profile-derived wire length.
    #[error("invalid encoded `{material}` length: expected {expected} bytes, got {got}")]
    InvalidEncodingLength {
        /// Material being decoded.
        material: &'static str,
        /// Expected byte count.
        expected: usize,
        /// Supplied byte count.
        got: usize,
    },

    /// Parameters mismatch between caller and key (e.g. trapdoor was
    /// generated for `n=512` but verification passed `n=1024` params).
    #[error("parameter mismatch: caller passed {caller:?}, key expects {key:?}")]
    ParameterMismatch {
        /// Caller-supplied params.
        caller: LatticeParams,
        /// Params bound into the key being used.
        key: LatticeParams,
    },

    /// Secret trapdoor metadata or storage is malformed.
    #[error("invalid trapdoor secret `{material}`: {reason}")]
    InvalidTrapdoorSecret {
        /// Secret material being decoded.
        material: &'static str,
        /// Human-readable rejection reason.
        reason: &'static str,
    },

    /// `period.start_secs >= period.end_secs`.
    #[error("invalid delegation period: start {start_secs} not < end {end_secs}")]
    InvalidPeriod {
        /// Start bound that failed.
        start_secs: u64,
        /// End bound that failed.
        end_secs: u64,
    },

    /// Operation timestamp falls outside the certificate's valid window.
    #[error("timestamp {now_secs} outside delegation period [{start_secs}, {end_secs})")]
    OutsidePeriod {
        /// Current time the verifier was running at.
        now_secs: u64,
        /// Period lower bound.
        start_secs: u64,
        /// Period upper bound.
        end_secs: u64,
    },

    /// Preimage failed the verification equation `A · e ≡ h (mod q)`.
    #[error("preimage failed verification equation")]
    VerificationEquationFailed,

    /// Preimage norm exceeded the hard bound `B`.
    #[error("preimage norm exceeded bound (got {got_squared}, max squared {max_squared})")]
    PreimageNormTooLarge {
        /// Computed `‖e‖₂²`.
        got_squared: u128,
        /// Hard ceiling `B²`.
        max_squared: u128,
    },
}

/// Convenience alias.
pub type LatticePqResult<T> = Result<T, LatticePqError>;

// ── Primitives ────────────────────────────────────────────────────────────

/// **`TrapGen`** (§3.3 layer 0).
///
/// Implements the reviewed internal route for supported profiles. The route
/// constructs an MP12-style relation `A_root · [R; I] = I (mod q)` and stores
/// the entropy-derived `R` seed in a redacted basis envelope. `SMALL_TEST`
/// uses dense `R` for exhaustive checks; `V4_REFERENCE` uses bounded sparse
/// `R` supports.
///
/// # Errors
///
/// Returns [`LatticePqError::UnsupportedPrimitiveRoute`] for profiles outside
/// the reviewed supported arithmetic set.
pub fn trap_gen(params: LatticeParams) -> LatticePqResult<(MasterPublicKey, MasterTrapdoor)> {
    let entropy = TrapGenEntropy::from_os_random();
    trap_gen_with_entropy(params, &entropy)
}

/// Deterministic `TrapGen` entry point for tests and evidence.
///
/// This is the production route with caller-supplied entropy, not the legacy
/// SHAKE seed-bundle fixture route.
///
/// # Errors
///
/// Returns the same errors as [`trap_gen`].
pub fn trap_gen_with_entropy(
    params: LatticeParams,
    entropy: &TrapGenEntropy,
) -> LatticePqResult<(MasterPublicKey, MasterTrapdoor)> {
    let _dims = route_dimensions(params, "trap_gen")?;
    build_root_basis_envelope(params, entropy)
}

/// Fixture-only SHAKE seed-bundle `TrapGen` compatibility helper.
///
/// This helper exists for representation fixtures, legacy bridge benches, and
/// negative tests. It must not be used as a production trapdoor source.
///
/// # Errors
///
/// Returns parameter validation and encoding errors for malformed profiles.
pub fn trap_gen_fixture(
    params: LatticeParams,
) -> LatticePqResult<(MasterPublicKey, MasterTrapdoor)> {
    params.validate()?;
    let public_hash = trap_gen_seed(params, b"master-public-matrix-seed");
    let trapdoor_bytes = trap_gen_secret_bundle(params)?;
    Ok((
        MasterPublicKey {
            hash: public_hash,
            public_matrix: PublicMatrixMaterial::fixture_seed_only(public_hash),
            params,
        },
        MasterTrapdoor::from_fixture_seed_bundle(params, public_hash, trapdoor_bytes)?,
    ))
}

/// **Delegate** (§3.3 layer 1).
///
/// Implements the reviewed internal route for supported profiles. The child
/// trapdoor is derived from the parent basis envelope under explicit parent,
/// zone, period, route, depth, and parameter domain separation. Fixture parent
/// trapdoors are rejected by this production entry point.
///
/// # Errors
///
/// - [`LatticePqError::ParameterMismatch`] if `params` disagree with the
///   parent's bound parameters.
/// - [`LatticePqError::InvalidPeriod`] if `period.start_secs >=
///   period.end_secs`.
/// - [`LatticePqError::InvalidTrapdoorSecret`] if the parent is a fixture or
///   malformed basis envelope.
/// - [`LatticePqError::UnsupportedPrimitiveRoute`] if `params` is not
///   supported by the reviewed route.
pub fn delegate(
    parent_pub: &MasterPublicKey,
    parent_trap: &MasterTrapdoor,
    zone_id: [u8; 32],
    period: DelegationPeriod,
    params: LatticeParams,
) -> LatticePqResult<(ZonePeriodPublicKey, ZonePeriodTrapdoor)> {
    if params != parent_pub.params {
        return Err(LatticePqError::ParameterMismatch {
            caller: params,
            key: parent_pub.params,
        });
    }
    if params != parent_trap.params() {
        return Err(LatticePqError::ParameterMismatch {
            caller: params,
            key: parent_trap.params(),
        });
    }
    params.validate()?;
    if period.start_secs >= period.end_secs {
        return Err(LatticePqError::InvalidPeriod {
            start_secs: period.start_secs,
            end_secs: period.end_secs,
        });
    }
    let _dims = route_dimensions(params, "delegate")?;
    if parent_trap.material_kind() == TrapdoorMaterialKind::FixtureShakeSeedBundle {
        return Err(LatticePqError::InvalidTrapdoorSecret {
            material: "fixture_parent_trapdoor",
            reason: "production delegate requires a basis envelope parent, not SHAKE fixture material",
        });
    }
    if parent_trap.relation_summary(parent_pub).result != TrapdoorRelationResult::MetadataConsistent
    {
        return Err(LatticePqError::InvalidTrapdoorSecret {
            material: "parent_basis_envelope",
            reason: "parent basis envelope does not validate against the parent public key",
        });
    }
    let parent_view =
        parse_basis_envelope(&parent_trap.bytes).ok_or(LatticePqError::InvalidTrapdoorSecret {
            material: "parent_basis_envelope",
            reason: "parent basis envelope could not be decoded",
        })?;

    let public_seed = derive_child_public_seed(parent_pub, &zone_id, period, params);
    let r_seed = derive_child_r_seed(&parent_view.r_seed, &public_seed, &zone_id, period, params);
    let public_matrix = route_public_matrix_material(params, &public_seed, &r_seed)?;
    let relation_digest = public_matrix_digest(params, &public_matrix)?;
    let zone_id_hash = *blake3::hash(&zone_id).as_bytes();
    let period_id_hash = period_hash(period);
    let public_hash = route_public_hash(
        TrapdoorScope::Child,
        params,
        &public_seed,
        parent_pub.hash,
        zone_id_hash,
        period_id_hash,
        &relation_digest,
    );
    let view = BasisEnvelopeView {
        route_id_hash: route_id_hash(),
        route_revision: PRIMITIVE_ROUTE_REVISION,
        scope: TrapdoorScope::Child,
        params_hash: params_hash(params),
        public_matrix_hash: public_hash,
        parent_public_matrix_hash: parent_pub.hash,
        zone_id_hash,
        period_id_hash,
        entropy_id_hash: parent_view.entropy_id_hash,
        public_seed,
        r_seed,
        relation_digest,
    };
    let envelope = encode_basis_envelope(&view);

    Ok((
        ZonePeriodPublicKey {
            hash: public_hash,
            public_matrix,
            zone_id,
            period,
            params,
        },
        ZonePeriodTrapdoor::from_basis_envelope(params, parent_pub.hash, public_hash, envelope)?,
    ))
}

/// Fixture-only SHAKE seed-bundle delegation compatibility helper.
///
/// This preserves deterministic legacy evidence without allowing fixture
/// trapdoors through the production [`delegate`] path.
///
/// # Errors
///
/// Returns the same parameter and period validation errors as [`delegate`].
pub fn delegate_fixture(
    parent_pub: &MasterPublicKey,
    parent_trap: &MasterTrapdoor,
    zone_id: [u8; 32],
    period: DelegationPeriod,
    params: LatticeParams,
) -> LatticePqResult<(ZonePeriodPublicKey, ZonePeriodTrapdoor)> {
    if params != parent_pub.params {
        return Err(LatticePqError::ParameterMismatch {
            caller: params,
            key: parent_pub.params,
        });
    }
    if params != parent_trap.params() {
        return Err(LatticePqError::ParameterMismatch {
            caller: params,
            key: parent_trap.params(),
        });
    }
    params.validate()?;
    if period.start_secs >= period.end_secs {
        return Err(LatticePqError::InvalidPeriod {
            start_secs: period.start_secs,
            end_secs: period.end_secs,
        });
    }

    let pub_hash = zone_period_matrix_seed(parent_pub, &zone_id, period, params);
    let trap_bytes = zone_period_trapdoor_seed(parent_trap, &pub_hash, &zone_id, period, params);

    Ok((
        ZonePeriodPublicKey {
            hash: pub_hash,
            public_matrix: PublicMatrixMaterial::fixture_seed_only(pub_hash),
            zone_id,
            period,
            params,
        },
        ZonePeriodTrapdoor::from_fixture_seed_bundle(
            params,
            parent_pub.hash,
            pub_hash,
            trap_bytes?,
        )?,
    ))
}

/// **`SamplePre`** (§3.3 layer 2).
///
/// Current reviewed route sampler: given `(A_zp, T_zp, h)`, expand `h` into a
/// centered RHS `x`, parse the child basis envelope's `R` seed, and emit
/// `e = [R*x ; x]`. The verifier independently checks `A_zp * e == h (mod q)`
/// and the hard centered-norm cap from [`preimage_norm_bound_squared`].
///
/// # Errors
///
/// - [`LatticePqError::ParameterMismatch`] if `params` disagree with
///   `key.params` or `trap.params`.
/// - [`LatticePqError::InvalidTrapdoorSecret`] for fixture, malformed, or
///   public-key-mismatched basis envelopes.
/// - [`LatticePqError::UnsupportedPrimitiveRoute`] for unsupported profiles.
/// - [`LatticePqError::PreimageNormTooLarge`] if the sampled witness exceeds
///   the route norm cap.
pub fn sample_pre(
    key: &ZonePeriodPublicKey,
    trap: &ZonePeriodTrapdoor,
    h: OperationHash,
    params: LatticeParams,
) -> LatticePqResult<LatticePreimage> {
    if params != key.params {
        return Err(LatticePqError::ParameterMismatch {
            caller: params,
            key: key.params,
        });
    }
    if params != trap.params() {
        return Err(LatticePqError::ParameterMismatch {
            caller: params,
            key: trap.params(),
        });
    }
    params.validate()?;
    let view = validated_zone_basis_view(key, trap, params)?;
    let rhs = expand_operation_hash_rhs(h, params);
    let coeffs = route_preimage_coefficients(params, &view.r_seed, &rhs)?;
    let norm_squared = preimage_norm_squared_from_coefficients(params, &coeffs);
    let max_squared = preimage_norm_bound_squared(params)?;
    if norm_squared > max_squared {
        return Err(LatticePqError::PreimageNormTooLarge {
            got_squared: norm_squared,
            max_squared,
        });
    }
    encode_preimage_coefficients(params, &coeffs)
}

/// **Verify** (§3.3 verification equation).
///
/// Real impl: check `A_zp · e ≡ h (mod q)` and `‖e‖₂ ≤ B`. Returns `Ok(())`
/// on success, an error variant explaining the failure mode otherwise.
///
/// # Errors
///
/// - [`LatticePqError::ParameterMismatch`] if `params` disagree with
///   `key.params`.
/// - [`LatticePqError::OutsidePeriod`] if `now_secs ∉ key.period`.
/// - [`LatticePqError::InvalidEncodingLength`] or
///   [`LatticePqError::InvalidParameter`] for malformed preimages.
/// - [`LatticePqError::PreimageNormTooLarge`] when the centered norm exceeds
///   the hard cap.
/// - [`LatticePqError::VerificationEquationFailed`] when `A_zp * e` does not
///   match the operation RHS.
pub fn verify(
    key: &ZonePeriodPublicKey,
    h: OperationHash,
    preimage: &LatticePreimage,
    now_secs: u64,
    params: LatticeParams,
) -> LatticePqResult<()> {
    if params != key.params {
        return Err(LatticePqError::ParameterMismatch {
            caller: params,
            key: key.params,
        });
    }
    params.validate()?;
    if !key.period.contains(now_secs) {
        return Err(LatticePqError::OutsidePeriod {
            now_secs,
            start_secs: key.period.start_secs,
            end_secs: key.period.end_secs,
        });
    }
    let coeffs = preimage_coefficients(params, preimage)?;
    let norm_squared = preimage_norm_squared_from_coefficients(params, &coeffs);
    let max_squared = preimage_norm_bound_squared(params)?;
    if norm_squared > max_squared {
        return Err(LatticePqError::PreimageNormTooLarge {
            got_squared: norm_squared,
            max_squared,
        });
    }
    let lhs = public_matrix_vector_product(params, &key.public_matrix, &coeffs)?;
    let rhs = expand_operation_hash_rhs(h, params);
    if constant_time_residue_vec_eq(&lhs, &rhs) {
        Ok(())
    } else {
        Err(LatticePqError::VerificationEquationFailed)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────

/// Compute the canonical operation hash
/// `H(zone | period | op | principal)`.
///
/// Uses a stable BLAKE3 transcript as the operation digest; verification then
/// expands this digest to `Z_q^n` with [`expand_operation_hash_rhs`].
#[must_use]
pub fn operation_hash(
    zone_id: &[u8; 32],
    period: DelegationPeriod,
    op: &[u8],
    principal: &[u8],
) -> OperationHash {
    let mut h = blake3::Hasher::new();
    h.update(b"fcp-pq/operation-hash-v0|");
    h.update(zone_id);
    h.update(&period.start_secs.to_le_bytes());
    h.update(&period.end_secs.to_le_bytes());
    h.update(&(op.len() as u64).to_le_bytes());
    h.update(op);
    h.update(&(principal.len() as u64).to_le_bytes());
    h.update(principal);
    OperationHash(*h.finalize().as_bytes())
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ref_period() -> DelegationPeriod {
        DelegationPeriod {
            start_secs: 1_000,
            end_secs: 2_000,
        }
    }

    fn fixture_entropy() -> TrapGenEntropy {
        TrapGenEntropy::from_fixture_seed(
            b"fixture:small_test:trapgen-delegate-route-v1",
            [0x5A; TRAP_GEN_ENTROPY_BYTES],
        )
    }

    #[test]
    fn v4_reference_params_have_expected_shape() {
        let p = LatticeParams::V4_REFERENCE;
        assert_eq!(p.n, 512);
        assert_eq!(p.q, 4_294_967_291);
        assert_eq!(p.m, 16_384);
        assert_eq!(p.sigma_x100, 11_300);
        assert_eq!(p.depth, 4);
        p.validate().expect("reference profile is valid");
        let profile = p
            .representation_profile()
            .expect("reference profile has bounded representation");
        assert_eq!(profile.version, LATTICE_REPRESENTATION_VERSION);
        assert_eq!(profile.coefficient_bytes, 4);
        assert_eq!(profile.public_matrix_seed_bytes, 32);
        assert_eq!(profile.public_matrix_expanded_bytes, 33_554_432);
        assert_eq!(profile.trapdoor_storage_bytes, 96);
        assert_eq!(profile.preimage_encoded_bytes, 65_536);
    }

    #[test]
    fn small_test_profile_has_tiny_deterministic_representation() {
        let p = LatticeParams::SMALL_TEST;
        p.validate().expect("small profile is valid");
        let profile = p.representation_profile().unwrap();
        assert_eq!(profile.coefficient_bytes, 2);
        assert_eq!(profile.public_matrix_expanded_bytes, 256);
        assert_eq!(profile.preimage_encoded_bytes, 32);
    }

    #[test]
    fn delegation_period_contains_handles_boundaries() {
        let p = ref_period();
        assert!(!p.contains(999), "before start is excluded");
        assert!(p.contains(1_000), "start is inclusive");
        assert!(p.contains(1_500), "interior is included");
        assert!(p.contains(1_999), "just-before-end is included");
        assert!(!p.contains(2_000), "end is exclusive");
        assert!(!p.contains(2_001), "after end is excluded");
    }

    #[test]
    fn trap_gen_fixture_is_deterministic_on_params() {
        let p = LatticeParams::V4_REFERENCE;
        let (pk1, tr1) = trap_gen_fixture(p).expect("fixture trap_gen succeeds");
        let (pk2, tr2) = trap_gen_fixture(p).expect("fixture trap_gen succeeds");
        assert_eq!(pk1, pk2, "same params → same public key");
        assert_eq!(tr1, tr2, "same params → same trapdoor");
        assert_ne!(
            &pk1.hash[..],
            &tr1.bytes[..],
            "public-key hash and trapdoor bytes are tagged differently"
        );
        assert_eq!(tr1.representation_version(), LATTICE_REPRESENTATION_VERSION);
        assert_eq!(tr1.params(), p);
        assert_eq!(tr1.encoded_len(), p.trapdoor_storage_bytes().unwrap());
    }

    #[test]
    fn trap_gen_distinguishes_param_variants() {
        let mut alt = LatticeParams::V4_REFERENCE;
        alt.depth = 3;
        let (pk_ref, _) = trap_gen_fixture(LatticeParams::V4_REFERENCE).unwrap();
        let (pk_alt, _) = trap_gen_fixture(alt).unwrap();
        assert_ne!(pk_ref.hash, pk_alt.hash, "different params → different key");
    }

    #[test]
    fn trap_gen_shake256_seed_fixtures_are_pinned() {
        let (master_pub, master_trap) = trap_gen_fixture(LatticeParams::V4_REFERENCE).unwrap();
        assert_eq!(
            hex::encode(master_pub.hash),
            "7f00d711a9de7cec422265e9cfb180de6c37aa7da3ff0375abf0249199b491ad"
        );
        assert_eq!(master_trap.encoded_len(), 96);
        assert!(
            format!("{master_trap:?}").contains("<redacted>"),
            "secret trapdoor debug output must redact material"
        );
    }

    #[test]
    fn trap_gen_with_entropy_small_test_validates_basis_relation() {
        let p = LatticeParams::SMALL_TEST;
        let entropy = fixture_entropy();
        let (master_pub, master_trap) = trap_gen_with_entropy(p, &entropy).unwrap();
        let (master_pub_again, master_trap_again) =
            trap_gen_with_entropy(p, &fixture_entropy()).unwrap();

        assert_eq!(master_pub, master_pub_again);
        assert_eq!(master_trap, master_trap_again);
        assert_eq!(
            hex::encode(master_pub.hash),
            "6c843a0141f3e4c56905b170e80221693173f70b1456f1d66caa30eda19b2423"
        );
        assert_eq!(
            master_trap.material_kind(),
            TrapdoorMaterialKind::BasisEnvelope
        );
        assert!(master_trap.encoded_len() < MAX_TRAPDOOR_SECRET_BYTES);
        assert_eq!(
            master_trap.relation_summary(&master_pub).result,
            TrapdoorRelationResult::MetadataConsistent
        );
        assert!(entropy.fixture_id_hash().is_some());
        assert!(
            format!("{entropy:?}").contains("<redacted>"),
            "entropy debug output must redact secret bytes"
        );
    }

    #[test]
    fn production_public_matrix_material_reconstructs_small_test_coefficients() {
        let p = LatticeParams::SMALL_TEST;
        let entropy = fixture_entropy();
        let (master_pub, master_trap) = trap_gen_with_entropy(p, &entropy).unwrap();
        let zone = [0xA5; 32];
        let period = ref_period();
        let (child_pub, child_trap) = delegate(&master_pub, &master_trap, zone, period, p).unwrap();
        let child_view = parse_basis_envelope(&child_trap.bytes).unwrap();
        let expected_material =
            route_public_matrix_material(p, &child_view.public_seed, &child_view.r_seed).unwrap();

        assert_eq!(
            child_pub.public_matrix.kind,
            PublicMatrixMaterialKind::RouteTailCoefficients
        );
        assert_eq!(child_pub.public_matrix, expected_material);
        assert_eq!(
            child_pub.public_matrix.tail_coefficients_len(),
            usize::try_from(p.n).unwrap()
                * usize::try_from(p.n).unwrap()
                * p.coefficient_bytes().unwrap()
        );
        assert_eq!(
            reconstruct_public_matrix_digest(&child_pub, p).unwrap(),
            child_view.relation_digest
        );
        assert_eq!(
            reconstruct_public_matrix_coefficient(&child_pub, 0, 0, p).unwrap(),
            public_coeff(p, &child_view.public_seed, 0, 0)
        );
        assert_eq!(
            reconstruct_public_matrix_coefficient(&child_pub, 0, p.m - p.n, p).unwrap(),
            tail_coeff(p, &child_view.public_seed, &child_view.r_seed, 0, 0)
        );
        assert_eq!(
            child_trap.relation_summary(&child_pub, &master_pub).result,
            TrapdoorRelationResult::MetadataConsistent
        );
    }

    #[test]
    fn public_matrix_material_rejects_wrong_binding_and_malformed_tail() {
        let p = LatticeParams::SMALL_TEST;
        let entropy = fixture_entropy();
        let (master_pub, master_trap) = trap_gen_with_entropy(p, &entropy).unwrap();
        let zone = [0xA5; 32];
        let period = ref_period();
        let (child_pub, child_trap) = delegate(&master_pub, &master_trap, zone, period, p).unwrap();

        let mut wrong_hash = child_pub.clone();
        wrong_hash.hash[0] ^= 0x80;
        assert_eq!(
            child_trap.relation_summary(&wrong_hash, &master_pub).result,
            TrapdoorRelationResult::MetadataMismatch
        );

        let mut malformed_tail = child_pub.clone();
        malformed_tail.public_matrix.tail_coefficients.pop();
        let err = reconstruct_public_matrix_digest(&malformed_tail, p).unwrap_err();
        assert!(
            matches!(
                err,
                LatticePqError::InvalidEncodingLength {
                    material: "public_matrix_tail",
                    ..
                }
            ),
            "got {err:?}"
        );
        assert_eq!(
            child_trap
                .relation_summary(&malformed_tail, &master_pub)
                .result,
            TrapdoorRelationResult::MetadataMismatch
        );

        let original_digest = reconstruct_public_matrix_digest(&child_pub, p).unwrap();
        let mut wrong_seed = child_pub.clone();
        wrong_seed.public_matrix.public_seed[0] ^= 0x01;
        assert_ne!(
            reconstruct_public_matrix_digest(&wrong_seed, p).unwrap(),
            original_digest,
            "public seed must affect verifier reconstruction"
        );
        assert_eq!(
            child_trap.relation_summary(&wrong_seed, &master_pub).result,
            TrapdoorRelationResult::MetadataMismatch
        );

        let mut wrong_route = child_pub;
        wrong_route.public_matrix.route_revision += 1;
        let err = reconstruct_public_matrix_digest(&wrong_route, p).unwrap_err();
        assert!(
            matches!(
                err,
                LatticePqError::InvalidTrapdoorSecret {
                    material: "public_matrix_material",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn v4_selected_abar_rows_match_full_rows_for_sparse_supports() {
        let p = LatticeParams::V4_REFERENCE;
        let dims = route_dimensions(p, "selected-row-test").unwrap();
        let entropy = fixture_entropy();
        let public_seed = derive_root_public_seed(p, &entropy);
        let r_seed = derive_root_r_seed(p, &entropy);
        let r_supports = (0..dims.gadget_cols)
            .map(|gadget_col| route_r_support(p, &r_seed, gadget_col, dims))
            .collect::<LatticePqResult<Vec<_>>>()
            .unwrap();
        let (selected_cols, indexed_supports) = v4_index_r_supports(&r_supports);

        assert!(!selected_cols.is_empty());
        assert!(
            selected_cols.len()
                <= usize::try_from(dims.gadget_cols * V4_SPARSE_R_WEIGHT)
                    .expect("support count fits usize"),
            "selected row must stay bounded by sparse R support"
        );

        for row in [0, 1, p.n - 1] {
            let full_row = v4_public_abar_row(p, &public_seed, row, dims);
            let selected_row = v4_public_abar_selected_row(p, &public_seed, row, &selected_cols);
            for (selected_index, abar_col) in selected_cols.iter().enumerate() {
                assert_eq!(
                    selected_row[selected_index],
                    full_row[usize::try_from(*abar_col).expect("u32 column fits usize")],
                    "selected-row stream must preserve the public A_bar coefficient"
                );
            }
            for (support, indexed_support) in r_supports.iter().zip(indexed_supports.iter()) {
                assert_eq!(
                    tail_product_from_selected_row(&selected_row, indexed_support),
                    tail_product_from_row(&full_row, support),
                    "selected-row products must match full-row products"
                );
            }
        }
    }

    #[test]
    fn public_matrix_reconstruction_fail_closes_custom_profiles() {
        let mut p = LatticeParams::V4_REFERENCE;
        p.depth = 3;
        let (master_pub, master_trap) = trap_gen_fixture(p).unwrap();
        let zone = [7u8; 32];
        let period = ref_period();
        let (zone_pub, _) = delegate_fixture(&master_pub, &master_trap, zone, period, p).unwrap();

        assert_eq!(
            zone_pub.public_matrix.kind,
            PublicMatrixMaterialKind::FixtureSeedOnly
        );
        let err = reconstruct_public_matrix_coefficient(&zone_pub, 0, 0, p).unwrap_err();
        assert!(
            matches!(
                err,
                LatticePqError::UnsupportedPrimitiveRoute {
                    primitive: "public_matrix_coeff",
                    profile: "CUSTOM",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn trap_gen_with_entropy_fail_closes_custom_profiles() {
        let mut p = LatticeParams::V4_REFERENCE;
        p.depth = 3;
        let err = trap_gen_with_entropy(p, &fixture_entropy())
            .expect_err("custom TrapGen must stay fail-closed until a reviewed route lands");
        assert!(
            matches!(
                err,
                LatticePqError::UnsupportedPrimitiveRoute {
                    primitive: "trap_gen",
                    route_id: PRIMITIVE_ROUTE_ID,
                    profile: "CUSTOM",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn delegate_fixture_round_trips_through_seed_bundle() {
        let p = LatticeParams::V4_REFERENCE;
        let (master_pub, master_trap) = trap_gen_fixture(p).unwrap();
        let zone = [7u8; 32];
        let period = ref_period();

        let (zp_pub, zp_trap) = delegate_fixture(&master_pub, &master_trap, zone, period, p)
            .expect("fixture delegate succeeds");

        assert_eq!(zp_pub.zone_id, zone);
        assert_eq!(zp_pub.period, period);
        assert_eq!(zp_pub.params, p);
        assert_ne!(
            zp_pub.hash, master_pub.hash,
            "child key hash differs from master"
        );
        assert_ne!(
            &zp_pub.hash[..],
            &zp_trap.bytes[..],
            "child public hash and child trapdoor are tagged differently"
        );
        assert_eq!(zp_trap.params(), p);
        assert_eq!(zp_trap.encoded_len(), p.trapdoor_storage_bytes().unwrap());
    }

    #[test]
    fn delegate_small_test_validates_child_relation_and_domain_separation() {
        let p = LatticeParams::SMALL_TEST;
        let entropy = fixture_entropy();
        let (master_pub, master_trap) = trap_gen_with_entropy(p, &entropy).unwrap();
        let zone = [0xA5; 32];
        let period = ref_period();
        let (child_pub, child_trap) = delegate(&master_pub, &master_trap, zone, period, p).unwrap();

        assert_eq!(
            child_trap.relation_summary(&child_pub, &master_pub).result,
            TrapdoorRelationResult::MetadataConsistent
        );
        assert_eq!(
            child_trap.material_kind(),
            TrapdoorMaterialKind::BasisEnvelope
        );
        assert_ne!(child_pub.hash, master_pub.hash);

        let (different_zone_pub, _) =
            delegate(&master_pub, &master_trap, [0xA6; 32], period, p).unwrap();
        assert_ne!(
            child_pub.hash, different_zone_pub.hash,
            "zone must affect child key"
        );

        let shifted_start = DelegationPeriod {
            start_secs: period.start_secs + 1,
            end_secs: period.end_secs,
        };
        let (different_start_pub, _) =
            delegate(&master_pub, &master_trap, zone, shifted_start, p).unwrap();
        assert_ne!(
            child_pub.hash, different_start_pub.hash,
            "period start must affect child key"
        );

        let shifted_end = DelegationPeriod {
            start_secs: period.start_secs,
            end_secs: period.end_secs + 1,
        };
        let (different_end_pub, _) =
            delegate(&master_pub, &master_trap, zone, shifted_end, p).unwrap();
        assert_ne!(
            child_pub.hash, different_end_pub.hash,
            "period end must affect child key"
        );

        let other_entropy =
            TrapGenEntropy::from_fixture_seed(b"fixture:alternate-parent", [0xB6; 32]);
        let (other_parent_pub, other_parent_trap) =
            trap_gen_with_entropy(p, &other_entropy).unwrap();
        let (different_parent_pub, _) =
            delegate(&other_parent_pub, &other_parent_trap, zone, period, p).unwrap();
        assert_ne!(
            child_pub.hash, different_parent_pub.hash,
            "parent hash must affect child key"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // V4 route acceptance keeps related cases together.
    fn v4_reference_public_matrix_route_reconstructs_and_rejects_malformed_material() {
        let p = LatticeParams::V4_REFERENCE;
        let entropy = fixture_entropy();
        let (master_pub, master_trap) = trap_gen_with_entropy(p, &entropy).unwrap();
        let (master_pub_again, master_trap_again) =
            trap_gen_with_entropy(p, &fixture_entropy()).unwrap();
        assert_eq!(master_pub, master_pub_again);
        assert_eq!(master_trap, master_trap_again);
        assert_eq!(
            master_pub.public_matrix.kind,
            PublicMatrixMaterialKind::RouteTailCoefficients
        );
        assert_eq!(
            master_pub.public_matrix.tail_coefficients_len(),
            usize::try_from(p.n).unwrap()
                * usize::try_from(p.n).unwrap()
                * p.coefficient_bytes().unwrap()
        );
        assert!(
            master_pub.public_matrix.tail_coefficients_len() <= MAX_PREIMAGE_ENCODED_BYTES,
            "V4 public tail must stay within the explicit route artifact budget"
        );
        assert_eq!(
            master_trap.relation_summary(&master_pub).result,
            TrapdoorRelationResult::MetadataConsistent
        );
        assert_eq!(
            master_trap.secret_storage_len_bucket(),
            SecretStorageLengthBucket::UpTo4KiB
        );

        let zone = [0xA5; 32];
        let period = ref_period();
        let (child_pub, child_trap) = delegate(&master_pub, &master_trap, zone, period, p).unwrap();
        let child_view = parse_basis_envelope(&child_trap.bytes).unwrap();
        assert_eq!(
            child_trap.relation_summary(&child_pub, &master_pub).result,
            TrapdoorRelationResult::MetadataConsistent
        );
        assert_eq!(
            reconstruct_public_matrix_digest(&child_pub, p).unwrap(),
            child_view.relation_digest
        );
        assert_eq!(
            reconstruct_public_matrix_coefficient(&child_pub, 0, 0, p).unwrap(),
            public_coeff(p, &child_view.public_seed, 0, 0)
        );
        assert_eq!(
            reconstruct_public_matrix_coefficient(&child_pub, 0, p.m - p.n, p).unwrap(),
            tail_coeff(p, &child_view.public_seed, &child_view.r_seed, 0, 0)
        );
        assert_eq!(
            reconstruct_public_matrix_coefficient(&child_pub, p.n - 1, p.m - 1, p).unwrap(),
            tail_coeff(
                p,
                &child_view.public_seed,
                &child_view.r_seed,
                p.n - 1,
                p.n - 1
            )
        );

        let zone_json = serde_json::to_string(&child_pub).unwrap();
        assert!(!zone_json.contains("r_seed"));
        assert!(!zone_json.contains("trapdoor"));
        let zone_back: ZonePeriodPublicKey = serde_json::from_str(&zone_json).unwrap();
        assert_eq!(zone_back, child_pub);

        let mut wrong_hash = child_pub.clone();
        wrong_hash.hash[0] ^= 0x80;
        assert_eq!(
            child_trap.relation_summary(&wrong_hash, &master_pub).result,
            TrapdoorRelationResult::MetadataMismatch
        );

        let mut malformed_tail = child_pub.clone();
        malformed_tail.public_matrix.tail_coefficients.pop();
        let err = reconstruct_public_matrix_digest(&malformed_tail, p).unwrap_err();
        assert!(
            matches!(
                err,
                LatticePqError::InvalidEncodingLength {
                    material: "public_matrix_tail",
                    ..
                }
            ),
            "got {err:?}"
        );

        let original_digest = reconstruct_public_matrix_digest(&child_pub, p).unwrap();
        let mut wrong_seed = child_pub.clone();
        wrong_seed.public_matrix.public_seed[0] ^= 0x01;
        assert_ne!(
            reconstruct_public_matrix_digest(&wrong_seed, p).unwrap(),
            original_digest
        );
        assert_eq!(
            child_trap.relation_summary(&wrong_seed, &master_pub).result,
            TrapdoorRelationResult::MetadataMismatch
        );

        let mut wrong_route = child_pub.clone();
        wrong_route.public_matrix.route_revision += 1;
        let err = reconstruct_public_matrix_digest(&wrong_route, p).unwrap_err();
        assert!(
            matches!(
                err,
                LatticePqError::InvalidTrapdoorSecret {
                    material: "public_matrix_material",
                    ..
                }
            ),
            "got {err:?}"
        );

        let err =
            reconstruct_public_matrix_coefficient(&child_pub, 0, 0, LatticeParams::SMALL_TEST)
                .unwrap_err();
        assert!(matches!(err, LatticePqError::ParameterMismatch { .. }));
    }

    #[test]
    fn delegate_rejects_fixture_parent_and_malformed_basis() {
        let p = LatticeParams::SMALL_TEST;
        let zone = [0x33; 32];
        let period = ref_period();
        let (fixture_pub, fixture_trap) = trap_gen_fixture(p).unwrap();
        let err = delegate(&fixture_pub, &fixture_trap, zone, period, p).unwrap_err();
        assert!(
            matches!(
                err,
                LatticePqError::InvalidTrapdoorSecret {
                    material: "fixture_parent_trapdoor",
                    ..
                }
            ),
            "got {err:?}"
        );

        let entropy = fixture_entropy();
        let (master_pub, mut master_trap) = trap_gen_with_entropy(p, &entropy).unwrap();
        let last = master_trap.bytes.len() - 1;
        master_trap.bytes[last] ^= 0x01;
        assert_eq!(
            master_trap.relation_summary(&master_pub).result,
            TrapdoorRelationResult::MetadataMismatch
        );
        let err = delegate(&master_pub, &master_trap, zone, period, p).unwrap_err();
        assert!(
            matches!(
                err,
                LatticePqError::InvalidTrapdoorSecret {
                    material: "parent_basis_envelope",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn child_relation_rejects_wrong_zone_and_period_metadata() {
        let p = LatticeParams::SMALL_TEST;
        let entropy = fixture_entropy();
        let (master_pub, master_trap) = trap_gen_with_entropy(p, &entropy).unwrap();
        let zone = [0x44; 32];
        let period = ref_period();
        let (child_pub, child_trap) = delegate(&master_pub, &master_trap, zone, period, p).unwrap();

        let mut wrong_zone_pub = child_pub.clone();
        wrong_zone_pub.zone_id[0] ^= 0xFF;
        assert_eq!(
            child_trap
                .relation_summary(&wrong_zone_pub, &master_pub)
                .result,
            TrapdoorRelationResult::MetadataMismatch
        );

        let mut wrong_period_pub = child_pub;
        wrong_period_pub.period.end_secs += 1;
        assert_eq!(
            child_trap
                .relation_summary(&wrong_period_pub, &master_pub)
                .result,
            TrapdoorRelationResult::MetadataMismatch
        );
    }

    #[test]
    fn trapdoor_metadata_round_trips_without_secret_material() {
        let p = LatticeParams::SMALL_TEST;
        let entropy = fixture_entropy();
        let (master_pub, master_trap) = trap_gen_with_entropy(p, &entropy).unwrap();
        let zone = [7u8; 32];
        let (zone_pub, zone_trap) = delegate(&master_pub, &master_trap, zone, ref_period(), p)
            .expect("production delegate succeeds for SMALL_TEST");

        let master_metadata = master_trap.metadata();
        assert_eq!(master_metadata.version, LATTICE_REPRESENTATION_VERSION);
        assert_eq!(master_metadata.scope, TrapdoorScope::Root);
        assert_eq!(
            master_metadata.material_kind,
            TrapdoorMaterialKind::BasisEnvelope
        );
        assert_eq!(master_metadata.public_matrix_hash, master_pub.hash);
        assert_eq!(master_metadata.parent_public_matrix_hash, None);
        assert_eq!(
            master_metadata.secret_storage_len_bucket,
            SecretStorageLengthBucket::UpTo4KiB
        );

        let json = serde_json::to_string(&master_metadata).unwrap();
        assert!(!json.contains("secret_material"));
        assert!(!json.contains("seed_bundle"));
        assert!(!json.contains("r_seed"));
        let master_back: TrapdoorRepresentationMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(master_back, master_metadata);

        let zone_metadata = zone_trap.metadata();
        assert_eq!(zone_metadata.scope, TrapdoorScope::Child);
        assert_eq!(
            zone_metadata.material_kind,
            TrapdoorMaterialKind::BasisEnvelope
        );
        assert_eq!(
            zone_metadata.parent_public_matrix_hash,
            Some(master_pub.hash)
        );
        assert_eq!(zone_metadata.public_matrix_hash, zone_pub.hash);
        let zone_json = serde_json::to_string(&zone_metadata).unwrap();
        let zone_back: TrapdoorRepresentationMetadata = serde_json::from_str(&zone_json).unwrap();
        assert_eq!(zone_back, zone_metadata);
    }

    #[test]
    fn trapdoor_metadata_validation_rejects_malformed_public_envelopes() {
        let p = LatticeParams::SMALL_TEST;
        let entropy = fixture_entropy();
        let (master_pub, master_trap) = trap_gen_with_entropy(p, &entropy).unwrap();
        let (zone_pub, zone_trap) =
            delegate(&master_pub, &master_trap, [0x22; 32], ref_period(), p).unwrap();
        let (_, fixture_master_trap) = trap_gen_fixture(p).unwrap();

        let mut wrong_version = master_trap.metadata();
        wrong_version.version = LATTICE_REPRESENTATION_VERSION + 1;
        let err = wrong_version.validate().unwrap_err();
        assert!(
            matches!(
                err,
                LatticePqError::InvalidEncodingLength {
                    material: "trapdoor_version",
                    ..
                }
            ),
            "got {err:?}"
        );

        let mut root_with_parent = master_trap.metadata();
        root_with_parent.parent_public_matrix_hash = Some(master_pub.hash);
        let err = root_with_parent.validate().unwrap_err();
        assert!(
            matches!(
                err,
                LatticePqError::InvalidTrapdoorSecret {
                    material: "root_trapdoor",
                    ..
                }
            ),
            "got {err:?}"
        );

        let mut child_without_parent = zone_trap.metadata();
        child_without_parent.parent_public_matrix_hash = None;
        let err = child_without_parent.validate().unwrap_err();
        assert!(
            matches!(
                err,
                LatticePqError::InvalidTrapdoorSecret {
                    material: "child_trapdoor",
                    ..
                }
            ),
            "got {err:?}"
        );

        let mut malformed_profile = zone_trap.metadata();
        malformed_profile.params.q = 1;
        let err = malformed_profile.validate().unwrap_err();
        assert!(
            matches!(
                err,
                LatticePqError::InvalidParameter {
                    field: "q",
                    value: 1,
                    ..
                }
            ),
            "got {err:?}"
        );

        let mut wrong_fixture_bucket = fixture_master_trap.metadata();
        wrong_fixture_bucket.secret_storage_len_bucket = SecretStorageLengthBucket::UpTo4KiB;
        let err = wrong_fixture_bucket.validate().unwrap_err();
        assert!(
            matches!(
                err,
                LatticePqError::InvalidTrapdoorSecret {
                    material: "fixture_trapdoor_seed_bundle",
                    ..
                }
            ),
            "got {err:?}"
        );

        let mut empty_basis_bucket =
            MasterTrapdoor::from_basis_envelope(p, master_pub.hash, vec![0xAA])
                .unwrap()
                .metadata();
        empty_basis_bucket.secret_storage_len_bucket = SecretStorageLengthBucket::Empty;
        let err = empty_basis_bucket.validate().unwrap_err();
        assert!(
            matches!(
                err,
                LatticePqError::InvalidTrapdoorSecret {
                    material: "basis_envelope",
                    ..
                }
            ),
            "got {err:?}"
        );

        let mut bad_tag = serde_json::to_value(master_trap.metadata()).unwrap();
        bad_tag["material_kind"] = serde_json::Value::String("ImaginaryTrapdoorRoute".to_owned());
        assert!(
            serde_json::from_value::<TrapdoorRepresentationMetadata>(bad_tag).is_err(),
            "unknown material route tags must fail deserialization"
        );

        assert_eq!(zone_pub.params, p, "fixture child public key still valid");
    }

    #[test]
    fn trapdoor_relation_summaries_are_redaction_safe() {
        let p = LatticeParams::SMALL_TEST;
        let entropy = fixture_entropy();
        let (master_pub, master_trap) = trap_gen_with_entropy(p, &entropy).unwrap();
        let zone = [11u8; 32];
        let period = ref_period();
        let (zone_pub, zone_trap) = delegate(&master_pub, &master_trap, zone, period, p).unwrap();

        let root_summary = master_trap.relation_summary(&master_pub);
        assert_eq!(
            root_summary.result,
            TrapdoorRelationResult::MetadataConsistent
        );
        assert_eq!(
            root_summary.norm_quality_bucket,
            TrapdoorNormQualityBucket::Small
        );

        let child_summary = zone_trap.relation_summary(&zone_pub, &master_pub);
        assert_eq!(
            child_summary.result,
            TrapdoorRelationResult::MetadataConsistent
        );
        assert_eq!(
            child_summary.norm_quality_bucket,
            TrapdoorNormQualityBucket::Small
        );

        let summary_json = serde_json::to_string(&child_summary).unwrap();
        assert!(!summary_json.contains("secret_material"));
        assert!(!summary_json.contains("coeff"));
        assert!(!summary_json.contains("seed_bundle"));
    }

    #[test]
    fn trapdoor_relation_summaries_detect_public_metadata_mismatch() {
        let p = LatticeParams::SMALL_TEST;
        let entropy = fixture_entropy();
        let (master_pub, master_trap) = trap_gen_with_entropy(p, &entropy).unwrap();
        let (zone_pub, zone_trap) =
            delegate(&master_pub, &master_trap, [0x33; 32], ref_period(), p).unwrap();

        let mut wrong_master_pub = master_pub.clone();
        wrong_master_pub.hash[0] ^= 0xFF;
        assert_eq!(
            master_trap.relation_summary(&wrong_master_pub).result,
            TrapdoorRelationResult::MetadataMismatch
        );

        let mut wrong_child_pub = zone_pub.clone();
        wrong_child_pub.hash[0] ^= 0xFF;
        assert_eq!(
            zone_trap
                .relation_summary(&wrong_child_pub, &master_pub)
                .result,
            TrapdoorRelationResult::MetadataMismatch
        );
        assert_eq!(
            zone_trap
                .relation_summary(&zone_pub, &wrong_master_pub)
                .result,
            TrapdoorRelationResult::MetadataMismatch
        );
    }

    #[test]
    fn basis_envelope_constructors_reject_unvalidated_basis_bytes() {
        let p = LatticeParams::SMALL_TEST;
        let public_hash = [0x44; 32];
        let parent_hash = [0x55; 32];
        let root = MasterTrapdoor::from_basis_envelope(p, public_hash, vec![0xA5; 4096]).unwrap();
        let child =
            ZonePeriodTrapdoor::from_basis_envelope(p, parent_hash, [0x66; 32], vec![0x5A; 8192])
                .unwrap();

        assert_eq!(root.material_kind(), TrapdoorMaterialKind::BasisEnvelope);
        assert_eq!(
            root.secret_storage_len_bucket(),
            SecretStorageLengthBucket::UpTo4KiB
        );
        assert_eq!(
            child.secret_storage_len_bucket(),
            SecretStorageLengthBucket::UpTo64KiB
        );
        assert_eq!(root.encoded_len(), 4096);
        assert_eq!(child.encoded_len(), 8192);

        let public = MasterPublicKey {
            hash: public_hash,
            public_matrix: PublicMatrixMaterial::fixture_seed_only(public_hash),
            params: p,
        };
        let summary = root.relation_summary(&public);
        assert_eq!(summary.result, TrapdoorRelationResult::MetadataMismatch);
        assert_eq!(
            summary.norm_quality_bucket,
            TrapdoorNormQualityBucket::Small
        );
    }

    #[test]
    fn malformed_trapdoor_secrets_are_rejected() {
        let p = LatticeParams::SMALL_TEST;
        let public_hash = [0x44; 32];

        let err =
            MasterTrapdoor::from_fixture_seed_bundle(p, public_hash, vec![0_u8; 95]).unwrap_err();
        assert!(
            matches!(
                err,
                LatticePqError::InvalidEncodingLength {
                    material: "fixture_trapdoor_seed_bundle",
                    expected: 96,
                    got: 95
                }
            ),
            "got {err:?}"
        );

        let err = MasterTrapdoor::from_basis_envelope(p, public_hash, Vec::new()).unwrap_err();
        assert!(
            matches!(
                err,
                LatticePqError::InvalidTrapdoorSecret {
                    material: "basis_envelope",
                    ..
                }
            ),
            "got {err:?}"
        );

        let err = MasterTrapdoor::from_basis_envelope(
            p,
            public_hash,
            vec![0_u8; MAX_TRAPDOOR_SECRET_BYTES + 1],
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                LatticePqError::RepresentationTooLarge {
                    material: "trapdoor_secret",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn zone_period_matrix_seed_is_deterministic_and_domain_separated() {
        let p = LatticeParams::V4_REFERENCE;
        let (master_pub, master_trap) = trap_gen_fixture(p).unwrap();
        let zone = [7u8; 32];
        let period = ref_period();

        let seed = zone_period_matrix_seed(&master_pub, &zone, period, p);
        assert_eq!(
            hex::encode(seed),
            "7fbac36f184f312452bf9a49cb8eca8b80d820079bfbeda16cc253448d23e3ea"
        );

        let (zp_pub, zp_trap) =
            delegate_fixture(&master_pub, &master_trap, zone, period, p).unwrap();
        assert_eq!(zp_pub.hash, seed, "delegate exposes the public seed");
        assert_eq!(zp_trap.encoded_len(), 96);
        assert!(
            format!("{zp_trap:?}").contains("<redacted>"),
            "zone-period trapdoor debug output must redact material"
        );

        let different_zone_seed = zone_period_matrix_seed(&master_pub, &[8u8; 32], period, p);
        assert_ne!(seed, different_zone_seed, "zone id changes the seed");

        let shifted = DelegationPeriod {
            start_secs: period.start_secs + 1,
            end_secs: period.end_secs + 1,
        };
        let different_period_seed = zone_period_matrix_seed(&master_pub, &zone, shifted, p);
        assert_ne!(seed, different_period_seed, "period changes the seed");
    }

    #[test]
    fn delegate_rejects_param_mismatch() {
        let p = LatticeParams::V4_REFERENCE;
        let (master_pub, master_trap) = trap_gen_fixture(p).unwrap();
        let mut wrong = p;
        wrong.n = 256;
        let err = delegate(&master_pub, &master_trap, [0u8; 32], ref_period(), wrong).unwrap_err();
        assert!(
            matches!(err, LatticePqError::ParameterMismatch { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn delegate_rejects_invalid_period() {
        let p = LatticeParams::V4_REFERENCE;
        let (master_pub, master_trap) = trap_gen_fixture(p).unwrap();
        let bad = DelegationPeriod {
            start_secs: 5_000,
            end_secs: 5_000,
        };
        let err = delegate(&master_pub, &master_trap, [0u8; 32], bad, p).unwrap_err();
        assert!(
            matches!(
                err,
                LatticePqError::InvalidPeriod {
                    start_secs: 5_000,
                    end_secs: 5_000,
                }
            ),
            "got {err:?}"
        );
    }

    fn constant_preimage(params: LatticeParams, coeff: u64) -> LatticePreimage {
        let mut bytes = Vec::with_capacity(params.preimage_encoded_bytes().unwrap());
        for _ in 0..params.m {
            encode_coeff(params, coeff, &mut bytes).unwrap();
        }
        LatticePreimage::from_encoded_bytes(params, bytes).unwrap()
    }

    fn v4_full_row_product(material: &PublicMatrixMaterial, coeffs: &[u64], row: u32) -> u64 {
        let p = LatticeParams::V4_REFERENCE;
        let dims = route_dimensions(p, "v4-full-row-product-test").unwrap();
        let abar_cols = usize::try_from(dims.abar_cols).expect("u32 A_bar cols fit in usize");
        let gadget_cols = usize::try_from(dims.gadget_cols).expect("u32 gadget cols fit in usize");
        let row_coefficients = v4_public_abar_row(p, &material.public_seed, row, dims);
        let mut sum = 0_i128;
        for (col, preimage_coeff) in coeffs.iter().take(abar_cols).enumerate() {
            if *preimage_coeff == 0 {
                continue;
            }
            sum += i128::from(row_coefficients[col]) * i128::from(*preimage_coeff);
        }
        for tail_col in 0..gadget_cols {
            let preimage_coeff = coeffs[abar_cols + tail_col];
            if preimage_coeff == 0 {
                continue;
            }
            let tail_index = usize::try_from(row)
                .expect("u32 row fits in usize")
                .checked_mul(gadget_cols)
                .and_then(|base| base.checked_add(tail_col))
                .unwrap();
            let matrix_coeff = decode_coeff(p, &material.tail_coefficients, tail_index).unwrap();
            sum += i128::from(matrix_coeff) * i128::from(preimage_coeff);
        }
        reduce_i128_mod_q(sum, p.q)
    }

    #[test]
    fn full_pipeline_round_trip_samples_and_verifies_small_test() {
        // TrapGen -> Delegate -> operation_hash -> SamplePre -> Verify
        // exercises every production primitive on the tiny deterministic route.
        let p = LatticeParams::SMALL_TEST;
        let entropy = fixture_entropy();
        let (master_pub, master_trap) = trap_gen_with_entropy(p, &entropy).unwrap();
        let zone = [42u8; 32];
        let period = ref_period();
        let (zp_pub, zp_trap) = delegate(&master_pub, &master_trap, zone, period, p).unwrap();
        let h = operation_hash(&zone, period, b"op:read.user.profile", b"principal:alice");

        let preimage = sample_pre(&zp_pub, &zp_trap, h, p).unwrap();
        assert_eq!(preimage.encoded_len(), p.preimage_encoded_bytes().unwrap());
        let norm_squared = preimage_norm_squared(p, &preimage).unwrap();
        let max_squared = preimage_norm_bound_squared(p).unwrap();
        assert!(
            norm_squared <= max_squared,
            "sampled norm {norm_squared} must fit bound {max_squared}"
        );

        let coeffs = preimage_coefficients(p, &preimage).unwrap();
        let lhs = public_matrix_vector_product(p, &zp_pub.public_matrix, &coeffs).unwrap();
        assert_eq!(lhs, expand_operation_hash_rhs(h, p));

        let now = period.start_secs + 100;
        verify(&zp_pub, h, &preimage, now, p).unwrap();
        let json = serde_json::to_string(&preimage).unwrap();
        let back: LatticePreimage = serde_json::from_str(&json).unwrap();
        verify(&zp_pub, h, &back, now, p).unwrap();
    }

    #[test]
    fn hex_envelope_deserialize_rejects_oversized_input() {
        let oversized = "f".repeat(2 * MAX_PUBLIC_MATRIX_EXPANDED_BYTES + 2);
        let json = format!("{{\"bytes\":\"{oversized}\"}}");
        let err = serde_json::from_str::<LatticePreimage>(&json).unwrap_err();
        assert!(err.to_string().contains("exceeds"), "got: {err}");
    }

    #[test]
    fn v4_reference_sample_pre_verify_round_trip() {
        let p = LatticeParams::V4_REFERENCE;
        let entropy = fixture_entropy();
        let (master_pub, master_trap) = trap_gen_with_entropy(p, &entropy).unwrap();
        let zone = [42u8; 32];
        let period = ref_period();
        let (zp_pub, zp_trap) = delegate(&master_pub, &master_trap, zone, period, p).unwrap();
        let h = operation_hash(&zone, period, b"op:v4.read", b"principal:v4-fixture");

        let preimage = sample_pre(&zp_pub, &zp_trap, h, p).unwrap();
        assert_eq!(preimage.encoded_len(), p.preimage_encoded_bytes().unwrap());
        let norm_squared = preimage_norm_squared(p, &preimage).unwrap();
        let max_squared = preimage_norm_bound_squared(p).unwrap();
        assert!(
            norm_squared <= max_squared,
            "V4 sampled norm {norm_squared} must fit bound {max_squared}"
        );
        let coeffs = preimage_coefficients(p, &preimage).unwrap();
        let lhs = public_matrix_vector_product(p, &zp_pub.public_matrix, &coeffs).unwrap();
        assert_eq!(lhs, expand_operation_hash_rhs(h, p));
        let dims = route_dimensions(p, "v4-product-support-test").unwrap();
        let abar_terms = route_preimage_abar_terms(dims, &coeffs);
        let selected_cols = abar_terms.iter().map(|(col, _)| *col).collect::<Vec<_>>();
        let abar_coefficients =
            v4_selected_abar_coefficients(p, &zp_pub.public_matrix, &selected_cols);
        let serial_lhs = public_matrix_vector_product_v4_serial(
            p,
            &zp_pub.public_matrix,
            &coeffs,
            dims,
            &abar_terms,
            &abar_coefficients,
        )
        .unwrap();
        assert_eq!(
            lhs, serial_lhs,
            "bounded parallel verifier product must match the serial V4 product"
        );
        assert!(
            abar_terms.len()
                <= usize::try_from(p.n * V4_SPARSE_R_WEIGHT).expect("support count fits usize"),
            "sampled V4 preimage should stay within the sparse R support budget"
        );
        for row in [0, 1, p.n - 1] {
            assert_eq!(
                lhs[usize::try_from(row).expect("u32 row fits usize")],
                v4_full_row_product(&zp_pub.public_matrix, &coeffs, row),
                "sparse verifier product must match full-row product"
            );
        }
        verify(&zp_pub, h, &preimage, period.start_secs, p).unwrap();
        let wrong_operation =
            operation_hash(&zone, period, b"op:v4.write", b"principal:v4-fixture");
        let err = verify(&zp_pub, wrong_operation, &preimage, period.start_secs, p).unwrap_err();
        assert!(
            matches!(err, LatticePqError::VerificationEquationFailed),
            "public material cache must not reuse a prior operation decision: {err:?}"
        );
    }

    #[test]
    fn v4_reference_verify_rejects_malformed_tail_after_fast_header_validation() {
        let p = LatticeParams::V4_REFERENCE;
        let entropy = fixture_entropy();
        let (master_pub, master_trap) = trap_gen_with_entropy(p, &entropy).unwrap();
        let zone = [42u8; 32];
        let period = ref_period();
        let (mut zp_pub, zp_trap) = delegate(&master_pub, &master_trap, zone, period, p).unwrap();
        let h = operation_hash(&zone, period, b"op:v4.read", b"principal:v4-fixture");
        let preimage = sample_pre(&zp_pub, &zp_trap, h, p).unwrap();

        let coefficient_bytes = p.coefficient_bytes().unwrap();
        let tail_len = zp_pub.public_matrix.tail_coefficients.len();
        let last_coeff_offset = tail_len - coefficient_bytes;
        let invalid = p.q.to_le_bytes();
        zp_pub.public_matrix.tail_coefficients
            [last_coeff_offset..last_coeff_offset + coefficient_bytes]
            .copy_from_slice(&invalid[..coefficient_bytes]);

        let err = verify(&zp_pub, h, &preimage, period.start_secs, p).unwrap_err();
        assert!(
            matches!(
                err,
                LatticePqError::InvalidTrapdoorSecret {
                    material: "public_matrix_tail",
                    ..
                }
            ),
            "V4 fast verifier path must still reject non-canonical tail material: {err:?}"
        );
    }

    #[test]
    fn v4_abar_materialization_cache_key_tracks_profile_seed_and_selection() {
        let p = LatticeParams::V4_REFERENCE;
        let entropy = fixture_entropy();
        let (master_pub, master_trap) = trap_gen_with_entropy(p, &entropy).unwrap();
        let zone = [42u8; 32];
        let period = ref_period();
        let (zp_pub, zp_trap) = delegate(&master_pub, &master_trap, zone, period, p).unwrap();
        let h = operation_hash(&zone, period, b"op:v4.read", b"principal:v4-fixture");
        let preimage = sample_pre(&zp_pub, &zp_trap, h, p).unwrap();
        let coeffs = preimage_coefficients(p, &preimage).unwrap();
        let dims = route_dimensions(p, "v4-cache-key-test").unwrap();
        let abar_terms = route_preimage_abar_terms(dims, &coeffs);
        let selected_cols = abar_terms.iter().map(|(col, _)| *col).collect::<Vec<_>>();
        let key = v4_abar_selection_cache_key(p, &zp_pub.public_matrix, &selected_cols);

        let mut different_material = zp_pub.public_matrix.clone();
        different_material.public_seed[0] ^= 0xA5;
        assert_ne!(
            key,
            v4_abar_selection_cache_key(p, &different_material, &selected_cols),
            "public seed changes must not reuse cached A_bar material"
        );
        let mut different_route = zp_pub.public_matrix.clone();
        different_route.route_id_hash[0] ^= 0x5A;
        assert_ne!(
            key,
            v4_abar_selection_cache_key(p, &different_route, &selected_cols),
            "route id changes must not reuse cached A_bar material"
        );
        let mut different_revision = zp_pub.public_matrix.clone();
        different_revision.route_revision += 1;
        assert_ne!(
            key,
            v4_abar_selection_cache_key(p, &different_revision, &selected_cols),
            "route revision changes must not reuse cached A_bar material"
        );

        let mut different_profile = p;
        different_profile.depth -= 1;
        assert_ne!(
            key,
            v4_abar_selection_cache_key(different_profile, &zp_pub.public_matrix, &selected_cols),
            "profile changes must not reuse cached A_bar material"
        );

        let mut different_selection = selected_cols;
        different_selection.pop();
        assert_ne!(
            key,
            v4_abar_selection_cache_key(p, &zp_pub.public_matrix, &different_selection),
            "selected-column changes must not reuse cached A_bar material"
        );
    }

    #[test]
    fn verify_rejects_forged_malformed_and_over_bound_preimages() {
        let p = LatticeParams::SMALL_TEST;
        let entropy = fixture_entropy();
        let (master_pub, master_trap) = trap_gen_with_entropy(p, &entropy).unwrap();
        let zone = [0x2A; 32];
        let period = ref_period();
        let (zp_pub, zp_trap) = delegate(&master_pub, &master_trap, zone, period, p).unwrap();
        let h = operation_hash(&zone, period, b"op", b"principal");
        let preimage = sample_pre(&zp_pub, &zp_trap, h, p).unwrap();
        let now = period.start_secs;

        let mut forged_coeffs = preimage_coefficients(p, &preimage).unwrap();
        let coeff = forged_coeffs
            .iter_mut()
            .find(|coeff| centered_abs_u128(**coeff, p.q) < u128::from(p.q / 2))
            .expect("sample has at least one coefficient below the centered max");
        *coeff = (*coeff + 1) % p.q;
        let forged = encode_preimage_coefficients(p, &forged_coeffs).unwrap();
        let err = verify(&zp_pub, h, &forged, now, p).unwrap_err();
        assert!(
            matches!(err, LatticePqError::VerificationEquationFailed),
            "got {err:?}"
        );

        let wrong_zone_h = operation_hash(&[0x2B; 32], period, b"op", b"principal");
        let err = verify(&zp_pub, wrong_zone_h, &preimage, now, p).unwrap_err();
        assert!(
            matches!(err, LatticePqError::VerificationEquationFailed),
            "got {err:?}"
        );

        let wrong_period_h = operation_hash(
            &zone,
            DelegationPeriod {
                start_secs: period.start_secs + 1,
                end_secs: period.end_secs + 1,
            },
            b"op",
            b"principal",
        );
        let err = verify(&zp_pub, wrong_period_h, &preimage, now, p).unwrap_err();
        assert!(
            matches!(err, LatticePqError::VerificationEquationFailed),
            "got {err:?}"
        );

        let mut malformed = preimage;
        malformed.bytes.pop();
        let err = verify(&zp_pub, h, &malformed, now, p).unwrap_err();
        assert!(
            matches!(
                err,
                LatticePqError::InvalidEncodingLength {
                    material: "preimage",
                    ..
                }
            ),
            "got {err:?}"
        );

        let too_large = constant_preimage(p, p.q / 2);
        let err = verify(&zp_pub, h, &too_large, now, p).unwrap_err();
        assert!(
            matches!(err, LatticePqError::PreimageNormTooLarge { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn verify_rejects_outside_period_before_arithmetic() {
        let p = LatticeParams::SMALL_TEST;
        let entropy = fixture_entropy();
        let (master_pub, master_trap) = trap_gen_with_entropy(p, &entropy).unwrap();
        let zone = [0u8; 32];
        let period = ref_period();
        let (zp_pub, zp_trap) = delegate(&master_pub, &master_trap, zone, period, p).unwrap();
        let h = operation_hash(&zone, period, b"op", b"princ");
        let preimage = sample_pre(&zp_pub, &zp_trap, h, p).unwrap();

        // 999 is one second before the period opens.
        let err = verify(&zp_pub, h, &preimage, 999, p).unwrap_err();
        assert!(
            matches!(
                err,
                LatticePqError::OutsidePeriod {
                    now_secs: 999,
                    start_secs: 1_000,
                    end_secs: 2_000,
                }
            ),
            "got {err:?}"
        );

        // 2000 is the exclusive upper bound.
        let err = verify(&zp_pub, h, &preimage, 2_000, p).unwrap_err();
        assert!(
            matches!(
                err,
                LatticePqError::OutsidePeriod {
                    now_secs: 2_000,
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn sample_pre_and_verify_reject_param_mismatch_and_unsupported_profiles() {
        let p = LatticeParams::SMALL_TEST;
        let entropy = fixture_entropy();
        let (master_pub, master_trap) = trap_gen_with_entropy(p, &entropy).unwrap();
        let zone = [0u8; 32];
        let (zp_pub, zp_trap) = delegate(&master_pub, &master_trap, zone, ref_period(), p).unwrap();
        let h = operation_hash(&zone, ref_period(), b"op", b"princ");
        let preimage = sample_pre(&zp_pub, &zp_trap, h, p).unwrap();

        let mut wrong = p;
        wrong.q = 7919;
        let err = sample_pre(&zp_pub, &zp_trap, h, wrong).unwrap_err();
        assert!(
            matches!(err, LatticePqError::ParameterMismatch { .. }),
            "got {err:?}"
        );
        let err = verify(&zp_pub, h, &preimage, 1_500, wrong).unwrap_err();
        assert!(
            matches!(err, LatticePqError::ParameterMismatch { .. }),
            "got {err:?}"
        );

        let mut custom = LatticeParams::V4_REFERENCE;
        custom.depth = 3;
        let (fixture_pub, fixture_trap) = trap_gen_fixture(custom).unwrap();
        let (fixture_zone_pub, _) =
            delegate_fixture(&fixture_pub, &fixture_trap, zone, ref_period(), custom).unwrap();
        let fixture_preimage = LatticePreimage::fixture_zero(custom).unwrap();
        let err = verify(
            &fixture_zone_pub,
            h,
            &fixture_preimage,
            ref_period().start_secs,
            custom,
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                LatticePqError::UnsupportedPrimitiveRoute {
                    primitive: "preimage_norm_bound",
                    profile: "CUSTOM",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn operation_hash_is_deterministic_and_input_separated() {
        let zone = [1u8; 32];
        let p = ref_period();
        let h1 = operation_hash(&zone, p, b"op", b"principal");
        let h2 = operation_hash(&zone, p, b"op", b"principal");
        assert_eq!(h1, h2, "deterministic on identical inputs");

        let h_diff_op = operation_hash(&zone, p, b"op2", b"principal");
        assert_ne!(h1, h_diff_op, "different op → different hash");

        let h_diff_pri = operation_hash(&zone, p, b"op", b"principal2");
        assert_ne!(h1, h_diff_pri, "different principal → different hash");

        // Length-prefix domain separation: ("ab","cd") must NOT collide
        // with ("a","bcd") even though concatenation matches.
        let h_a = operation_hash(&zone, p, b"ab", b"cd");
        let h_b = operation_hash(&zone, p, b"a", b"bcd");
        assert_ne!(h_a, h_b, "length-prefix separation prevents splice");
    }

    #[test]
    fn operation_hash_rhs_expands_with_shake256_fixture() {
        let p = LatticeParams::V4_REFERENCE;
        let zone = [42u8; 32];
        let period = ref_period();
        let h = operation_hash(&zone, period, b"op:read.user.profile", b"principal:alice");
        assert_eq!(
            hex::encode(h.0),
            "375af0d88a424be189140204f0521bace77ef127291b14f609635265a7f7569e"
        );

        let rhs = expand_operation_hash_rhs(h, p);
        assert_eq!(
            rhs.len(),
            usize::try_from(p.n).expect("u32 lattice dimension fits in usize")
        );
        assert!(
            rhs.iter().all(|coeff| *coeff < p.q),
            "all coefficients must be reduced modulo q"
        );
        assert_eq!(
            &rhs[..8],
            &[
                988_739_933,
                1_627_499_036,
                20_657_642,
                332_982_869,
                4_070_681_389,
                1_380_482_524,
                3_733_962_268,
                4_263_286_768,
            ]
        );

        let different = expand_operation_hash_rhs(
            operation_hash(&zone, period, b"op:read.user.profile", b"principal:bob"),
            p,
        );
        assert_ne!(&rhs[..16], &different[..16], "principal changes the RHS");
    }

    #[test]
    fn public_key_representations_round_trip_through_json() {
        let params = LatticeParams::SMALL_TEST;
        let (master_pub, master_trap) = trap_gen(params).unwrap();
        let period = ref_period();
        let zone = [9_u8; 32];
        let (zone_pub, _zone_trap) =
            delegate(&master_pub, &master_trap, zone, period, params).unwrap();

        let master_json = serde_json::to_string(&master_pub).unwrap();
        let master_back: MasterPublicKey = serde_json::from_str(&master_json).unwrap();
        assert_eq!(master_back, master_pub);

        let zone_json = serde_json::to_string(&zone_pub).unwrap();
        let zone_back: ZonePeriodPublicKey = serde_json::from_str(&zone_json).unwrap();
        assert_eq!(zone_back, zone_pub);
        assert_eq!(zone_back.hash.len(), MATRIX_SEED_BYTES);
    }

    #[test]
    fn lattice_preimage_round_trips_through_json() {
        let params = LatticeParams::SMALL_TEST;
        let bytes = (0..params.preimage_encoded_bytes().unwrap())
            .map(|i| u8::try_from(i).expect("small profile fixture byte fits in u8"))
            .collect::<Vec<_>>();
        let pre = LatticePreimage::from_encoded_bytes(params, bytes).unwrap();
        let s = serde_json::to_string(&pre).unwrap();
        assert!(s.contains("\"bytes\":\""), "uses bytes field");
        let back: LatticePreimage = serde_json::from_str(&s).unwrap();
        assert_eq!(back, pre);
        assert_eq!(back.encoded_len(), params.preimage_encoded_bytes().unwrap());
        assert!(
            format!("{back:?}").contains("<redacted>"),
            "preimage debug output must redact bytes"
        );
    }

    #[test]
    fn lattice_preimage_rejects_malformed_profile_length() {
        let params = LatticeParams::SMALL_TEST;
        let err = LatticePreimage::from_encoded_bytes(params, vec![0_u8; 31]).unwrap_err();
        assert!(
            matches!(
                err,
                LatticePqError::InvalidEncodingLength {
                    material: "preimage",
                    expected: 32,
                    got: 31
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn invalid_params_reject_before_allocation() {
        let mut params = LatticeParams::SMALL_TEST;
        params.q = 1;
        let err = params.validate().unwrap_err();
        assert!(
            matches!(
                err,
                LatticePqError::InvalidParameter {
                    field: "q",
                    value: 1,
                    ..
                }
            ),
            "got {err:?}"
        );

        params = LatticeParams::SMALL_TEST;
        params.n = 1;
        params.q = 2;
        params.m = 1_048_577;
        let err = params.representation_profile().unwrap_err();
        assert!(
            matches!(
                err,
                LatticePqError::RepresentationTooLarge {
                    material: "preimage",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn not_implemented_error_names_responsible_bead() {
        let err = LatticePqError::NotImplemented {
            primitive: "sample_pre",
            bead: "kyopb.1.3.1.1.4",
        };
        let msg = err.to_string();
        assert!(msg.contains("sample_pre"), "msg: {msg}");
        assert!(msg.contains("kyopb.1.3.1.1.4"), "msg: {msg}");
    }
}
