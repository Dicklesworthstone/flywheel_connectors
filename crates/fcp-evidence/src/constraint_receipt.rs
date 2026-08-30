//! `ConstraintEnforcementReceipt` (m8j0q.A.7).
//!
//! First-class signed mesh evidence that a capability-constraint enforcement
//! decision (Allow OR Deny) was actually performed by the named enforcing
//! node. Distinct from the audit event (the chain LINK) — this is the BYTES
//! that get linked.
//!
//! ## Design contract
//!
//! - **Content-addressed.** The receipt's `receipt_id` is
//!   `blake3(canonical CBOR of the unsigned receipt)`. Two receipts that
//!   carry the same token, zone, request nonce, observation, and freshness
//!   bounds produce the same id deterministically.
//! - **Sealed in one signed atom.** Both observations — "constraints were
//!   evaluated" and "the evaluation produced this outcome" — are bound into
//!   a single Ed25519 signature over `signing_bytes()`. There is no
//!   instruction-level race between "constraints checked" and "operation
//!   dispatched": the receipt seals both into a single witnessable byte
//!   range, mirroring the `RevocationSeal` pattern proven in MOR/C1.1.
//! - **Replayable offline.** [`ConstraintEnforcementReceipt::verify_offline`]
//!   re-verifies the signature and freshness without network or registry
//!   access. Owners can replay any receipt against any trusted-anchor set.
//! - **Not an authorization token.** A receipt is evidence that a check
//!   happened once. A stale receipt MUST NOT be trusted to authorize a
//!   downstream operation; consumers must re-verify token validity, freshness,
//!   revocation state, and replay state at use time.
//! - **Forgery-resistant.** Mutating any signed field — observed outcome,
//!   token id, zone id, request nonce, request-descriptor hash, freshness
//!   bounds, constraints summary, revocation head sequence, or enforcing node
//!   id — invalidates the signature. Verified by proptest.
//! - **CBOR canonical round-trip.** [`ConstraintEnforcementReceipt::to_canonical_cbor`] and
//!   [`ConstraintEnforcementReceipt::from_canonical_cbor`] are byte-for-byte
//!   inverses for any well-formed receipt.
//!
//! See bead `flywheel_connectors-m8j0q.7` for goal and acceptance criteria.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use fcp_cbor::{SerializationError, to_canonical_cbor};
use fcp_core::{ObjectId, RequestId, TailscaleNodeId, ZoneId};
use fcp_crypto::ed25519::{Ed25519Signature, Ed25519SigningKey, Ed25519VerifyingKey};

/// Domain-separation tag for receipt signing.
///
/// Prevents cross-protocol signature reuse — a receipt signature is bound to
/// the `FCP3-CONSTRAINT-RECEIPT-V1` context and cannot be re-used as a
/// signature for any other FCP protocol message that lacks this prefix.
pub const RECEIPT_SIGNING_DOMAIN: &[u8] = b"FCP3-CONSTRAINT-RECEIPT-V1";

/// Domain-separation tag for receipt id derivation.
///
/// Distinguishes the content hash from the signing hash so a `receipt_id`
/// can never be confused with bytes that would verify against the receipt's
/// signature.
pub const RECEIPT_ID_DOMAIN: &[u8] = b"FCP3-CONSTRAINT-RECEIPT-ID-V1";

/// Default upper bound for receipt freshness.
///
/// Constraint receipts are short-lived evidence. A longer downstream cache
/// window must still reject a receipt whose explicit expiry exceeds this
/// envelope unless policy deliberately constructs a different verifier.
pub const DEFAULT_RECEIPT_FRESHNESS_WINDOW_MS: u64 = 60_000;

/// Opaque content hash of the request descriptor that was evaluated.
///
/// Carried in the receipt instead of the descriptor itself so the receipt
/// stays small and so request payloads (which may carry sensitive data)
/// never reach the signed receipt or any audit consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RequestDescriptorHash(#[serde(with = "fcp_core::util::hex_or_bytes")] pub [u8; 32]);

impl RequestDescriptorHash {
    /// Hash a stable byte representation of the request descriptor.
    ///
    /// Callers SHOULD pass the canonical CBOR encoding of the request
    /// descriptor; the hash is BLAKE3-keyed by `FCP3-CONSTRAINT-REQ-DIGEST-V1`
    /// so this hash cannot collide with any other FCP digest scheme.
    #[must_use]
    pub fn from_canonical_bytes(canonical: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"FCP3-CONSTRAINT-REQ-DIGEST-V1");
        hasher.update(canonical);
        Self(*hasher.finalize().as_bytes())
    }

    /// Construct from raw bytes (round-tripping over the wire).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase-hex rendering for log lines.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Display for RequestDescriptorHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Per-request nonce committed into a constraint-enforcement receipt.
///
/// This is a compact binding for the request identity, not secret material.
/// Callers can derive it from `InvokeRequest.id` with
/// [`Self::from_request_id`] or pass an already-generated nonce with
/// [`Self::from_bytes`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ReceiptNonce(#[serde(with = "fcp_core::util::hex_or_bytes")] pub [u8; 16]);

impl ReceiptNonce {
    /// Construct from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Derive a stable 128-bit receipt nonce from a wire request id.
    #[must_use]
    pub fn from_request_id(request_id: &RequestId) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"FCP3-CONSTRAINT-RECEIPT-NONCE-V1");
        hasher.update(request_id.0.as_bytes());
        let digest = hasher.finalize();
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&digest.as_bytes()[..16]);
        Self(bytes)
    }

    /// Borrow the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Lowercase-hex rendering for log lines and replay errors.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Display for ReceiptNonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Content-addressed identifier for a [`ConstraintEnforcementReceipt`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ReceiptId(#[serde(with = "fcp_core::util::hex_or_bytes")] pub [u8; 32]);

impl ReceiptId {
    /// Construct from raw bytes (round-tripping over the wire).
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

impl std::fmt::Display for ReceiptId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// The outcome recorded inside a receipt.
///
/// This mirrors the discriminant of `fcp_policy::ConstraintEvaluation` but is
/// stored in a stable, serialization-pinned form so that downstream audit
/// consumers don't need a runtime dependency on `fcp-policy`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum EvaluationOutcomeRecord {
    /// All constraint checks passed.
    Allow,
    /// One constraint check denied; carries the categorical denial label.
    Deny {
        /// Stable machine label from `ConstraintDenialKind::as_str` (e.g.,
        /// `"object_id_not_in_allowlist"`).
        denial_kind: String,
        /// Narrow observed value that failed (no full payload).
        observed_value: String,
    },
}

impl EvaluationOutcomeRecord {
    /// Whether this outcome allowed the request.
    #[must_use]
    pub const fn is_allow(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Whether this outcome denied the request.
    #[must_use]
    pub const fn is_deny(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }
}

/// Compact summary of which constraint kinds were evaluated.
///
/// Audit consumers use this to verify that the enforcing node actually
/// considered each mandatory constraint type — a receipt that records
/// `evaluated_kinds` missing `time_window` proves the time-window check
/// did not run on this request, which is itself a policy violation if the
/// owner expected one.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ConstraintsEvaluatedSummary {
    /// Stable kind labels (e.g. `"object_id_allowlist"`,
    /// `"host_allowlist"`, `"time_window"`, `"scope_ceiling"`,
    /// `"principal_binding"`, `"resource_uri_allow"`,
    /// `"resource_uri_deny"`, `"credential_allow"`).
    pub evaluated_kinds: Vec<String>,
    /// Number of `resource_allow` patterns the request was checked against.
    pub resource_allow_count: u32,
    /// Number of `resource_deny` patterns the request was checked against.
    pub resource_deny_count: u32,
    /// Whether `max_calls` was set on the constraint set.
    pub max_calls_set: bool,
    /// Whether `max_bytes` was set on the constraint set.
    pub max_bytes_set: bool,
    /// Number of `credential_allow` entries on the constraint set.
    pub credential_allow_count: u32,
}

/// First-class signed mesh evidence of a capability-constraint enforcement.
///
/// See module docs for the design contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstraintEnforcementReceipt {
    /// Content-addressed identifier (BLAKE3-keyed digest of the unsigned
    /// receipt body). Computed by `compute_id` at seal time.
    pub receipt_id: ReceiptId,
    /// Content-addressed id of the capability token that was checked.
    pub token_id: ObjectId,
    /// Zone in which the request was evaluated.
    pub zone_id: ZoneId,
    /// Per-request nonce binding this receipt to one request instance.
    pub request_nonce: ReceiptNonce,
    /// Hash of the request descriptor that was evaluated.
    pub request_descriptor_hash: RequestDescriptorHash,
    /// Compact summary of which constraints were checked.
    pub constraints_evaluated: ConstraintsEvaluatedSummary,
    /// What the evaluation produced (allow / deny + reason).
    pub evaluation_outcome: EvaluationOutcomeRecord,
    /// Wall-clock time the receipt was sealed (Unix milliseconds).
    pub sealed_at_unix_ms: u64,
    /// Wall-clock time after which the receipt is stale (Unix milliseconds).
    pub expires_at_unix_ms: u64,
    /// Revocation registry head sequence observed by the enforcer.
    pub revocation_head_seq_observed: u64,
    /// Identifier of the node that enforced this evaluation.
    pub enforcing_node_id: TailscaleNodeId,
    /// Ed25519 signature over `signing_bytes` using
    /// `enforcing_node_id`'s signing key.
    pub signature: Ed25519Signature,
}

/// Body of an unsigned receipt — the bytes that the signature commits to.
///
/// Splitting `Body` from `ConstraintEnforcementReceipt` makes the signing
/// transcript explicit and unambiguous: the signature commits to the
/// canonical CBOR of `Body` only, never to the full receipt (which would be
/// circular through `signature`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptBody {
    pub token_id: ObjectId,
    pub zone_id: ZoneId,
    pub request_nonce: ReceiptNonce,
    pub request_descriptor_hash: RequestDescriptorHash,
    pub constraints_evaluated: ConstraintsEvaluatedSummary,
    pub evaluation_outcome: EvaluationOutcomeRecord,
    pub sealed_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub revocation_head_seq_observed: u64,
    pub enforcing_node_id: TailscaleNodeId,
}

impl ReceiptBody {
    /// Canonical CBOR encoding of the body. The signature commits to this.
    ///
    /// # Errors
    /// Returns [`SerializationError`] if canonical encoding fails (e.g., the
    /// body exceeds the canonical-object size cap).
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, SerializationError> {
        to_canonical_cbor(self)
    }

    /// Bytes that the Ed25519 signature commits to.
    ///
    /// Includes the [`RECEIPT_SIGNING_DOMAIN`] prefix so that a body signed
    /// here cannot be re-interpreted as a signature on any other FCP
    /// protocol message.
    ///
    /// # Errors
    /// Propagates [`SerializationError`] from [`Self::to_canonical_cbor`].
    pub fn signing_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        let body = self.to_canonical_cbor()?;
        let mut out = Vec::with_capacity(RECEIPT_SIGNING_DOMAIN.len() + body.len());
        out.extend_from_slice(RECEIPT_SIGNING_DOMAIN);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Compute the [`ReceiptId`] for this body.
    ///
    /// Uses `RECEIPT_ID_DOMAIN` so the id is domain-separated from the
    /// signing transcript — a `receipt_id` value is never a valid signing
    /// transcript by construction.
    ///
    /// # Errors
    /// Propagates [`SerializationError`] from [`Self::to_canonical_cbor`].
    pub fn compute_id(&self) -> Result<ReceiptId, SerializationError> {
        let body = self.to_canonical_cbor()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(RECEIPT_ID_DOMAIN);
        hasher.update(&body);
        Ok(ReceiptId(*hasher.finalize().as_bytes()))
    }
}

/// Errors returned by receipt construction or verification.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ReceiptError {
    /// Canonical CBOR serialization failed.
    #[error("canonical CBOR encoding failed: {0}")]
    Encoding(String),
    /// Receipt id does not match the BLAKE3-keyed digest of the body.
    #[error(
        "receipt_id mismatch: receipt advertises {advertised}, recomputed body hashes to {recomputed}"
    )]
    ReceiptIdMismatch {
        advertised: String,
        recomputed: String,
    },
    /// Ed25519 signature does not verify under the supplied verifying key.
    #[error("signature verification failed for enforcing node {enforcing_node_id}")]
    SignatureVerificationFailed { enforcing_node_id: String },
    /// Verifying-key resolver did not return a key for the enforcing node id.
    #[error("no verifying key registered for enforcing node {enforcing_node_id}")]
    UnknownEnforcingNode { enforcing_node_id: String },
    /// The receipt expires before or exactly when it was sealed.
    #[error(
        "invalid receipt freshness window: sealed_at={sealed_at_unix_ms}, expires_at={expires_at_unix_ms}"
    )]
    InvalidFreshnessWindow {
        sealed_at_unix_ms: u64,
        expires_at_unix_ms: u64,
    },
    /// The receipt's explicit freshness window exceeds verifier policy.
    #[error(
        "receipt freshness window {window_millis}ms exceeds verifier maximum {max_window_millis}ms"
    )]
    FreshnessWindowTooLong {
        window_millis: u64,
        max_window_millis: u64,
    },
    /// The receipt is stale at the verification timestamp.
    #[error("receipt expired at {expires_at_unix_ms}, verification time was {now_unix_ms}")]
    ReceiptExpired {
        expires_at_unix_ms: u64,
        now_unix_ms: u64,
    },
    /// System clock is before Unix epoch.
    #[error("system clock is before Unix epoch")]
    SystemClockBeforeUnixEpoch,
    /// Receipt was presented for a different token than the one it sealed.
    #[error("receipt token mismatch: expected {expected}, observed {observed}")]
    TokenIdMismatch { expected: String, observed: String },
    /// Receipt was presented for a different zone than the one it sealed.
    #[error("receipt zone mismatch: expected {expected}, observed {observed}")]
    ZoneIdMismatch { expected: String, observed: String },
    /// Receipt observed an older revocation head than the verifier requires.
    #[error(
        "receipt revocation head is stale: observed {observed}, current verifier floor {current}"
    )]
    RevocationHeadStale { observed: u64, current: u64 },
    /// The verifier already accepted this nonce inside the sliding window.
    #[error("receipt nonce replay detected for nonce {nonce}")]
    ReceiptReplayDetected { nonce: String },
}

impl From<SerializationError> for ReceiptError {
    fn from(value: SerializationError) -> Self {
        Self::Encoding(value.to_string())
    }
}

/// Context a consumer must provide when treating a receipt as live evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptVerificationContext {
    /// Expected capability-token object id for this operation.
    pub token_id: ObjectId,
    /// Expected zone for this operation.
    pub zone_id: ZoneId,
    /// Current revocation-head sequence floor known to the verifier.
    pub current_revocation_head_seq: u64,
    /// Verification wall-clock time in Unix milliseconds.
    pub now_unix_ms: u64,
}

impl ReceiptVerificationContext {
    /// Build a verification context.
    #[must_use]
    pub const fn new(
        token_id: ObjectId,
        zone_id: ZoneId,
        current_revocation_head_seq: u64,
        now_unix_ms: u64,
    ) -> Self {
        Self {
            token_id,
            zone_id,
            current_revocation_head_seq,
            now_unix_ms,
        }
    }
}

/// Stateful verifier that rejects nonce replay inside a sliding window.
#[derive(Debug, Clone)]
pub struct ConstraintReceiptVerifier {
    max_freshness_window_ms: u64,
    seen_nonces: HashMap<ReceiptNonce, u64>,
}

impl Default for ConstraintReceiptVerifier {
    fn default() -> Self {
        Self::new(DEFAULT_RECEIPT_FRESHNESS_WINDOW_MS)
    }
}

impl ConstraintReceiptVerifier {
    /// Construct a verifier with the maximum accepted freshness window.
    #[must_use]
    pub fn new(max_freshness_window_ms: u64) -> Self {
        Self {
            max_freshness_window_ms,
            seen_nonces: HashMap::new(),
        }
    }

    /// Verify signature, receipt bindings, freshness, revocation floor, and nonce uniqueness.
    ///
    /// # Errors
    /// Returns [`ReceiptError`] when any structural, cryptographic, freshness,
    /// binding, revocation, or replay check fails.
    pub fn verify(
        &mut self,
        receipt: &ConstraintEnforcementReceipt,
        verifying_key: &Ed25519VerifyingKey,
        context: &ReceiptVerificationContext,
    ) -> Result<EvaluationOutcomeRecord, ReceiptError> {
        let outcome = receipt.verify_offline_against(verifying_key, context)?;
        let freshness_window = receipt.freshness_window_ms()?;
        if freshness_window > self.max_freshness_window_ms {
            return Err(ReceiptError::FreshnessWindowTooLong {
                window_millis: freshness_window,
                max_window_millis: self.max_freshness_window_ms,
            });
        }

        self.prune_expired(context.now_unix_ms);
        if self.seen_nonces.contains_key(&receipt.request_nonce) {
            return Err(ReceiptError::ReceiptReplayDetected {
                nonce: receipt.request_nonce.to_hex(),
            });
        }
        self.seen_nonces
            .insert(receipt.request_nonce, receipt.expires_at_unix_ms);
        Ok(outcome)
    }

    fn prune_expired(&mut self, now_unix_ms: u64) {
        self.seen_nonces
            .retain(|_, expires_at_unix_ms| *expires_at_unix_ms >= now_unix_ms);
    }
}

impl ConstraintEnforcementReceipt {
    /// Seal a new receipt: compute the content-addressed id, then sign the
    /// body with `signing_key`.
    ///
    /// # Errors
    /// Returns [`ReceiptError::Encoding`] if the body fails canonical CBOR
    /// encoding.
    pub fn seal(body: ReceiptBody, signing_key: &Ed25519SigningKey) -> Result<Self, ReceiptError> {
        let receipt_id = body.compute_id()?;
        let signing_bytes = body.signing_bytes()?;
        let signature = signing_key.sign(&signing_bytes);
        Ok(Self {
            receipt_id,
            token_id: body.token_id,
            zone_id: body.zone_id,
            request_nonce: body.request_nonce,
            request_descriptor_hash: body.request_descriptor_hash,
            constraints_evaluated: body.constraints_evaluated,
            evaluation_outcome: body.evaluation_outcome,
            sealed_at_unix_ms: body.sealed_at_unix_ms,
            expires_at_unix_ms: body.expires_at_unix_ms,
            revocation_head_seq_observed: body.revocation_head_seq_observed,
            enforcing_node_id: body.enforcing_node_id,
            signature,
        })
    }

    /// Reconstruct the body view that the signature commits to.
    #[must_use]
    pub fn body(&self) -> ReceiptBody {
        ReceiptBody {
            token_id: self.token_id,
            zone_id: self.zone_id.clone(),
            request_nonce: self.request_nonce,
            request_descriptor_hash: self.request_descriptor_hash,
            constraints_evaluated: self.constraints_evaluated.clone(),
            evaluation_outcome: self.evaluation_outcome.clone(),
            sealed_at_unix_ms: self.sealed_at_unix_ms,
            expires_at_unix_ms: self.expires_at_unix_ms,
            revocation_head_seq_observed: self.revocation_head_seq_observed,
            enforcing_node_id: self.enforcing_node_id.clone(),
        }
    }

    /// Freshness duration sealed into this receipt.
    ///
    /// # Errors
    /// Returns [`ReceiptError::InvalidFreshnessWindow`] when the expiry is not
    /// strictly after the seal time.
    pub const fn freshness_window_ms(&self) -> Result<u64, ReceiptError> {
        if self.expires_at_unix_ms <= self.sealed_at_unix_ms {
            return Err(ReceiptError::InvalidFreshnessWindow {
                sealed_at_unix_ms: self.sealed_at_unix_ms,
                expires_at_unix_ms: self.expires_at_unix_ms,
            });
        }
        Ok(self.expires_at_unix_ms - self.sealed_at_unix_ms)
    }

    /// Canonical CBOR encoding of the full (signed) receipt.
    ///
    /// # Errors
    /// Returns [`SerializationError`] if canonical encoding fails.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, SerializationError> {
        to_canonical_cbor(self)
    }

    /// Decode a canonical-CBOR receipt.
    ///
    /// # Errors
    /// Returns [`SerializationError`] from `ciborium`.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SerializationError> {
        let value = ciborium::from_reader(bytes).map_err(SerializationError::from)?;
        Ok(value)
    }

    /// Verify the receipt's signature and content-addressed id offline.
    ///
    /// Re-derives the body, recomputes its id, and verifies the signature
    /// against `verifying_key`. No network or registry access is required.
    ///
    /// # Errors
    /// - [`ReceiptError::Encoding`] if the body fails canonical CBOR
    ///   encoding (would indicate tampering or a bug in this crate).
    /// - [`ReceiptError::ReceiptIdMismatch`] if the receipt's
    ///   `receipt_id` does not match the recomputed body hash.
    /// - [`ReceiptError::SignatureVerificationFailed`] if the Ed25519
    ///   signature does not verify under `verifying_key`.
    pub fn verify_offline(
        &self,
        verifying_key: &Ed25519VerifyingKey,
    ) -> Result<EvaluationOutcomeRecord, ReceiptError> {
        self.verify_offline_at(verifying_key, unix_now_ms()?)
    }

    /// Verify the receipt's signature, content-addressed id, and freshness at a caller-supplied time.
    ///
    /// # Errors
    /// - [`ReceiptError::Encoding`] if the body fails canonical CBOR
    ///   encoding (would indicate tampering or a bug in this crate).
    /// - [`ReceiptError::InvalidFreshnessWindow`] if `expires_at_unix_ms` is
    ///   not strictly after `sealed_at_unix_ms`.
    /// - [`ReceiptError::ReceiptExpired`] if `now_unix_ms` is past the
    ///   receipt's explicit expiry.
    /// - [`ReceiptError::ReceiptIdMismatch`] if the receipt's
    ///   `receipt_id` does not match the recomputed body hash.
    /// - [`ReceiptError::SignatureVerificationFailed`] if the Ed25519
    ///   signature does not verify under `verifying_key`.
    pub fn verify_offline_at(
        &self,
        verifying_key: &Ed25519VerifyingKey,
        now_unix_ms: u64,
    ) -> Result<EvaluationOutcomeRecord, ReceiptError> {
        self.freshness_window_ms()?;
        if now_unix_ms > self.expires_at_unix_ms {
            return Err(ReceiptError::ReceiptExpired {
                expires_at_unix_ms: self.expires_at_unix_ms,
                now_unix_ms,
            });
        }
        let body = self.body();
        let recomputed = body.compute_id()?;
        if recomputed != self.receipt_id {
            return Err(ReceiptError::ReceiptIdMismatch {
                advertised: self.receipt_id.to_hex(),
                recomputed: recomputed.to_hex(),
            });
        }
        let signing_bytes = body.signing_bytes()?;
        verifying_key
            .verify(&signing_bytes, &self.signature)
            .map_err(|_| ReceiptError::SignatureVerificationFailed {
                enforcing_node_id: self.enforcing_node_id.as_str().to_string(),
            })?;
        Ok(self.evaluation_outcome.clone())
    }

    /// Verify the receipt against live-token context.
    ///
    /// This is the API consumers should use when a receipt is presented as
    /// evidence for a current operation. It binds verification to the token id,
    /// zone, revocation-head floor, and caller-supplied wall clock.
    ///
    /// # Errors
    /// Returns [`ReceiptError`] for any signature, freshness, binding, or
    /// revocation-floor failure.
    pub fn verify_offline_against(
        &self,
        verifying_key: &Ed25519VerifyingKey,
        context: &ReceiptVerificationContext,
    ) -> Result<EvaluationOutcomeRecord, ReceiptError> {
        let outcome = self.verify_offline_at(verifying_key, context.now_unix_ms)?;
        if self.token_id != context.token_id {
            return Err(ReceiptError::TokenIdMismatch {
                expected: context.token_id.to_string(),
                observed: self.token_id.to_string(),
            });
        }
        if self.zone_id != context.zone_id {
            return Err(ReceiptError::ZoneIdMismatch {
                expected: context.zone_id.to_string(),
                observed: self.zone_id.to_string(),
            });
        }
        if self.revocation_head_seq_observed < context.current_revocation_head_seq {
            return Err(ReceiptError::RevocationHeadStale {
                observed: self.revocation_head_seq_observed,
                current: context.current_revocation_head_seq,
            });
        }
        Ok(outcome)
    }

    /// Verify offline using a key resolver. Useful when the audit consumer
    /// has a registry of trusted node verifying keys keyed by node id.
    ///
    /// # Errors
    /// - [`ReceiptError::UnknownEnforcingNode`] if the resolver returns
    ///   `None` for the receipt's `enforcing_node_id`.
    /// - Any error from [`Self::verify_offline`].
    pub fn verify_offline_with_resolver<F>(
        &self,
        resolve_key: F,
    ) -> Result<EvaluationOutcomeRecord, ReceiptError>
    where
        F: FnOnce(&TailscaleNodeId) -> Option<Ed25519VerifyingKey>,
    {
        let key = resolve_key(&self.enforcing_node_id).ok_or_else(|| {
            ReceiptError::UnknownEnforcingNode {
                enforcing_node_id: self.enforcing_node_id.as_str().to_string(),
            }
        })?;
        self.verify_offline(&key)
    }
}

fn unix_now_ms() -> Result<u64, ReceiptError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ReceiptError::SystemClockBeforeUnixEpoch)?;
    Ok(duration.as_millis().try_into().unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const SEALED_AT_MS: u64 = 4_000_000_000_000;
    const EXPIRES_AT_MS: u64 = SEALED_AT_MS + DEFAULT_RECEIPT_FRESHNESS_WINDOW_MS;
    const VERIFY_AT_MS: u64 = SEALED_AT_MS + 1_000;
    const REVOCATION_HEAD_SEQ: u64 = 10;

    fn signing_key() -> Ed25519SigningKey {
        // Deterministic key for golden-vector tests.
        Ed25519SigningKey::from_bytes(&[7_u8; 32]).expect("valid signing key")
    }

    fn token_a() -> ObjectId {
        ObjectId::from_unscoped_bytes(b"token-a")
    }

    fn token_b() -> ObjectId {
        ObjectId::from_unscoped_bytes(b"token-b")
    }

    fn zone() -> ZoneId {
        ZoneId::work()
    }

    fn nonce_a() -> ReceiptNonce {
        ReceiptNonce::from_bytes([0xA1_u8; 16])
    }

    fn nonce_b() -> ReceiptNonce {
        ReceiptNonce::from_bytes([0xB2_u8; 16])
    }

    fn node() -> TailscaleNodeId {
        TailscaleNodeId::new("enforcer-node-a")
    }

    fn allow_body() -> ReceiptBody {
        ReceiptBody {
            token_id: token_a(),
            zone_id: zone(),
            request_nonce: nonce_a(),
            request_descriptor_hash: RequestDescriptorHash::from_bytes([1_u8; 32]),
            constraints_evaluated: ConstraintsEvaluatedSummary {
                evaluated_kinds: vec!["host_allowlist".to_string(), "scope_ceiling".to_string()],
                resource_allow_count: 1,
                resource_deny_count: 0,
                max_calls_set: true,
                max_bytes_set: false,
                credential_allow_count: 0,
            },
            evaluation_outcome: EvaluationOutcomeRecord::Allow,
            sealed_at_unix_ms: SEALED_AT_MS,
            expires_at_unix_ms: EXPIRES_AT_MS,
            revocation_head_seq_observed: REVOCATION_HEAD_SEQ,
            enforcing_node_id: node(),
        }
    }

    fn deny_body() -> ReceiptBody {
        ReceiptBody {
            token_id: token_a(),
            zone_id: zone(),
            request_nonce: nonce_b(),
            request_descriptor_hash: RequestDescriptorHash::from_bytes([2_u8; 32]),
            constraints_evaluated: ConstraintsEvaluatedSummary {
                evaluated_kinds: vec!["host_allowlist".to_string()],
                resource_allow_count: 0,
                resource_deny_count: 0,
                max_calls_set: false,
                max_bytes_set: false,
                credential_allow_count: 0,
            },
            evaluation_outcome: EvaluationOutcomeRecord::Deny {
                denial_kind: "host_not_in_allowlist".to_string(),
                observed_value: "host=evil.example.com".to_string(),
            },
            sealed_at_unix_ms: SEALED_AT_MS,
            expires_at_unix_ms: EXPIRES_AT_MS,
            revocation_head_seq_observed: REVOCATION_HEAD_SEQ,
            enforcing_node_id: node(),
        }
    }

    fn context() -> ReceiptVerificationContext {
        ReceiptVerificationContext::new(token_a(), zone(), REVOCATION_HEAD_SEQ, VERIFY_AT_MS)
    }

    // ── Sealing + verification happy paths ───────────────────────────────

    #[test]
    fn seal_then_verify_offline_round_trip_allow() {
        let key = signing_key();
        let receipt = ConstraintEnforcementReceipt::seal(allow_body(), &key).unwrap();
        let outcome = receipt
            .verify_offline(&key.verifying_key())
            .expect("verifies");
        assert!(outcome.is_allow());
    }

    #[test]
    fn seal_then_verify_offline_against_context_round_trip_allow() {
        let key = signing_key();
        let receipt = ConstraintEnforcementReceipt::seal(allow_body(), &key).unwrap();
        let outcome = receipt
            .verify_offline_against(&key.verifying_key(), &context())
            .expect("verifies with live context");
        assert!(outcome.is_allow());
    }

    #[test]
    fn seal_then_verify_offline_round_trip_deny() {
        let key = signing_key();
        let receipt = ConstraintEnforcementReceipt::seal(deny_body(), &key).unwrap();
        let outcome = receipt
            .verify_offline(&key.verifying_key())
            .expect("verifies");
        assert!(outcome.is_deny());
    }

    // ── Content-addressing ───────────────────────────────────────────────

    #[test]
    fn receipt_id_is_content_addressed_deterministically() {
        let key = signing_key();
        let r1 = ConstraintEnforcementReceipt::seal(allow_body(), &key).unwrap();
        let r2 = ConstraintEnforcementReceipt::seal(allow_body(), &key).unwrap();
        assert_eq!(r1.receipt_id, r2.receipt_id);
    }

    #[test]
    fn distinct_bodies_produce_distinct_receipt_ids() {
        let key = signing_key();
        let r_allow = ConstraintEnforcementReceipt::seal(allow_body(), &key).unwrap();
        let r_deny = ConstraintEnforcementReceipt::seal(deny_body(), &key).unwrap();
        assert_ne!(r_allow.receipt_id, r_deny.receipt_id);
    }

    #[test]
    fn request_nonce_changes_receipt_id_for_otherwise_identical_requests() {
        let key = signing_key();
        let mut body_a = allow_body();
        let mut body_b = allow_body();
        body_a.request_nonce = nonce_a();
        body_b.request_nonce = nonce_b();
        let r_a = ConstraintEnforcementReceipt::seal(body_a, &key).unwrap();
        let r_b = ConstraintEnforcementReceipt::seal(body_b, &key).unwrap();
        assert_ne!(r_a.receipt_id, r_b.receipt_id);
        assert_ne!(r_a.request_nonce, r_b.request_nonce);
    }

    #[test]
    fn receipt_id_mismatch_after_body_mutation_is_caught_offline() {
        let key = signing_key();
        let mut receipt = ConstraintEnforcementReceipt::seal(allow_body(), &key).unwrap();
        // Tamper with a signed field while leaving receipt_id unchanged.
        receipt.sealed_at_unix_ms = receipt.sealed_at_unix_ms.wrapping_add(1);
        let err = receipt
            .verify_offline(&key.verifying_key())
            .expect_err("receipt_id no longer matches recomputed body");
        assert!(matches!(err, ReceiptError::ReceiptIdMismatch { .. }));
    }

    #[test]
    fn receipt_id_uses_distinct_domain_from_signing_transcript() {
        // The id-domain prefix must not equal the signing-domain prefix, so a
        // receipt_id can never collide with a signing transcript.
        assert_ne!(RECEIPT_ID_DOMAIN, RECEIPT_SIGNING_DOMAIN);
    }

    // ── Freshness + replay resistance ───────────────────────────────────

    #[test]
    fn receipt_replay_with_expired_window_rejected_by_verify_offline() {
        let key = signing_key();
        let mut body = allow_body();
        body.sealed_at_unix_ms = 1_000;
        body.expires_at_unix_ms = 2_000;
        let receipt = ConstraintEnforcementReceipt::seal(body, &key).unwrap();
        let err = receipt
            .verify_offline_at(&key.verifying_key(), 2_001)
            .expect_err("expired receipt must be rejected");
        assert!(matches!(err, ReceiptError::ReceiptExpired { .. }));
    }

    #[test]
    fn receipt_replay_for_token_a_does_not_authorize_token_b_replay() {
        let key = signing_key();
        let receipt = ConstraintEnforcementReceipt::seal(allow_body(), &key).unwrap();
        let mut context = context();
        context.token_id = token_b();
        let err = receipt
            .verify_offline_against(&key.verifying_key(), &context)
            .expect_err("token mismatch must be rejected");
        assert!(matches!(err, ReceiptError::TokenIdMismatch { .. }));
    }

    #[test]
    fn receipt_replay_for_wrong_zone_is_rejected() {
        let key = signing_key();
        let receipt = ConstraintEnforcementReceipt::seal(allow_body(), &key).unwrap();
        let mut context = context();
        context.zone_id = ZoneId::public();
        let err = receipt
            .verify_offline_against(&key.verifying_key(), &context)
            .expect_err("zone mismatch must be rejected");
        assert!(matches!(err, ReceiptError::ZoneIdMismatch { .. }));
    }

    #[test]
    fn receipt_replay_committed_to_old_revocation_seq_flagged_when_seq_advances() {
        let key = signing_key();
        let receipt = ConstraintEnforcementReceipt::seal(allow_body(), &key).unwrap();
        let mut context = context();
        context.current_revocation_head_seq = REVOCATION_HEAD_SEQ + 1;
        let err = receipt
            .verify_offline_against(&key.verifying_key(), &context)
            .expect_err("old revocation sequence must be rejected");
        assert!(matches!(err, ReceiptError::RevocationHeadStale { .. }));
    }

    #[test]
    fn receipt_replay_verifier_rejects_replayed_nonce_inside_sliding_window() {
        let key = signing_key();
        let receipt = ConstraintEnforcementReceipt::seal(allow_body(), &key).unwrap();
        let mut verifier = ConstraintReceiptVerifier::default();
        let outcome = verifier
            .verify(&receipt, &key.verifying_key(), &context())
            .expect("first receipt accepted");
        assert!(outcome.is_allow());

        let err = verifier
            .verify(&receipt, &key.verifying_key(), &context())
            .expect_err("same nonce inside the window is replay");
        assert!(matches!(err, ReceiptError::ReceiptReplayDetected { .. }));
    }

    #[test]
    fn receipt_replay_verifier_rejects_oversized_freshness_window() {
        let key = signing_key();
        let mut body = allow_body();
        body.expires_at_unix_ms = body.sealed_at_unix_ms + DEFAULT_RECEIPT_FRESHNESS_WINDOW_MS + 1;
        let receipt = ConstraintEnforcementReceipt::seal(body, &key).unwrap();
        let mut verifier = ConstraintReceiptVerifier::default();
        let err = verifier
            .verify(&receipt, &key.verifying_key(), &context())
            .expect_err("oversized receipt window must be rejected");
        assert!(matches!(err, ReceiptError::FreshnessWindowTooLong { .. }));
    }

    // ── CBOR canonical round-trip ────────────────────────────────────────

    #[test]
    fn canonical_cbor_round_trip_is_byte_equivalent() {
        let key = signing_key();
        let receipt = ConstraintEnforcementReceipt::seal(allow_body(), &key).unwrap();
        let bytes_a = receipt.to_canonical_cbor().unwrap();
        let bytes_b = receipt.to_canonical_cbor().unwrap();
        assert_eq!(bytes_a, bytes_b, "canonical encoding must be deterministic");
        let decoded = ConstraintEnforcementReceipt::from_canonical_cbor(&bytes_a).unwrap();
        let bytes_c = decoded.to_canonical_cbor().unwrap();
        assert_eq!(bytes_a, bytes_c, "decode + re-encode must reproduce input");
        assert_eq!(receipt, decoded);
    }

    #[test]
    fn canonical_cbor_round_trip_through_decoded_receipt_still_verifies() {
        let key = signing_key();
        let receipt = ConstraintEnforcementReceipt::seal(deny_body(), &key).unwrap();
        let bytes = receipt.to_canonical_cbor().unwrap();
        let decoded = ConstraintEnforcementReceipt::from_canonical_cbor(&bytes).unwrap();
        decoded
            .verify_offline(&key.verifying_key())
            .expect("decoded receipt still verifies");
    }

    // ── Forgery resistance: per-field mutation invalidates signature ─────

    #[test]
    fn forgery_mutating_evaluation_outcome_fails_signature() {
        let key = signing_key();
        let mut receipt = ConstraintEnforcementReceipt::seal(allow_body(), &key).unwrap();
        receipt.evaluation_outcome = EvaluationOutcomeRecord::Deny {
            denial_kind: "fabricated".to_string(),
            observed_value: "fabricated".to_string(),
        };
        // Recompute receipt_id so the receipt-id check passes; the signature
        // should still fail because the body bytes the signature was made over
        // no longer match.
        receipt.receipt_id = receipt.body().compute_id().unwrap();
        let err = receipt
            .verify_offline(&key.verifying_key())
            .expect_err("signature must reject mutated outcome");
        assert!(matches!(
            err,
            ReceiptError::SignatureVerificationFailed { .. }
        ));
    }

    #[test]
    fn forgery_mutating_request_descriptor_hash_fails_signature() {
        let key = signing_key();
        let mut receipt = ConstraintEnforcementReceipt::seal(allow_body(), &key).unwrap();
        receipt.request_descriptor_hash = RequestDescriptorHash::from_bytes([0xFF_u8; 32]);
        receipt.receipt_id = receipt.body().compute_id().unwrap();
        let err = receipt
            .verify_offline(&key.verifying_key())
            .expect_err("signature must reject mutated descriptor hash");
        assert!(matches!(
            err,
            ReceiptError::SignatureVerificationFailed { .. }
        ));
    }

    #[test]
    fn forgery_mutating_token_id_fails_signature() {
        let key = signing_key();
        let mut receipt = ConstraintEnforcementReceipt::seal(allow_body(), &key).unwrap();
        receipt.token_id = token_b();
        receipt.receipt_id = receipt.body().compute_id().unwrap();
        let err = receipt
            .verify_offline_at(&key.verifying_key(), VERIFY_AT_MS)
            .expect_err("signature must reject mutated token id");
        assert!(matches!(
            err,
            ReceiptError::SignatureVerificationFailed { .. }
        ));
    }

    #[test]
    fn forgery_mutating_zone_id_fails_signature() {
        let key = signing_key();
        let mut receipt = ConstraintEnforcementReceipt::seal(allow_body(), &key).unwrap();
        receipt.zone_id = ZoneId::public();
        receipt.receipt_id = receipt.body().compute_id().unwrap();
        let err = receipt
            .verify_offline_at(&key.verifying_key(), VERIFY_AT_MS)
            .expect_err("signature must reject mutated zone id");
        assert!(matches!(
            err,
            ReceiptError::SignatureVerificationFailed { .. }
        ));
    }

    #[test]
    fn forgery_mutating_request_nonce_fails_signature() {
        let key = signing_key();
        let mut receipt = ConstraintEnforcementReceipt::seal(allow_body(), &key).unwrap();
        receipt.request_nonce = nonce_b();
        receipt.receipt_id = receipt.body().compute_id().unwrap();
        let err = receipt
            .verify_offline_at(&key.verifying_key(), VERIFY_AT_MS)
            .expect_err("signature must reject mutated nonce");
        assert!(matches!(
            err,
            ReceiptError::SignatureVerificationFailed { .. }
        ));
    }

    #[test]
    fn forgery_mutating_sealed_at_fails_signature() {
        let key = signing_key();
        let mut receipt = ConstraintEnforcementReceipt::seal(allow_body(), &key).unwrap();
        receipt.sealed_at_unix_ms = receipt.sealed_at_unix_ms.wrapping_add(1);
        receipt.receipt_id = receipt.body().compute_id().unwrap();
        let err = receipt
            .verify_offline(&key.verifying_key())
            .expect_err("signature must reject mutated sealed_at");
        assert!(matches!(
            err,
            ReceiptError::SignatureVerificationFailed { .. }
        ));
    }

    #[test]
    fn forgery_mutating_expires_at_fails_signature() {
        let key = signing_key();
        let mut receipt = ConstraintEnforcementReceipt::seal(allow_body(), &key).unwrap();
        receipt.expires_at_unix_ms = receipt.expires_at_unix_ms.wrapping_add(1);
        receipt.receipt_id = receipt.body().compute_id().unwrap();
        let err = receipt
            .verify_offline_at(&key.verifying_key(), VERIFY_AT_MS)
            .expect_err("signature must reject mutated expiry");
        assert!(matches!(
            err,
            ReceiptError::SignatureVerificationFailed { .. }
        ));
    }

    #[test]
    fn forgery_mutating_revocation_head_seq_fails_signature() {
        let key = signing_key();
        let mut receipt = ConstraintEnforcementReceipt::seal(allow_body(), &key).unwrap();
        receipt.revocation_head_seq_observed = receipt.revocation_head_seq_observed.wrapping_add(1);
        receipt.receipt_id = receipt.body().compute_id().unwrap();
        let err = receipt
            .verify_offline_at(&key.verifying_key(), VERIFY_AT_MS)
            .expect_err("signature must reject mutated revocation sequence");
        assert!(matches!(
            err,
            ReceiptError::SignatureVerificationFailed { .. }
        ));
    }

    #[test]
    fn forgery_mutating_enforcing_node_id_fails_signature() {
        let key = signing_key();
        let mut receipt = ConstraintEnforcementReceipt::seal(allow_body(), &key).unwrap();
        receipt.enforcing_node_id = TailscaleNodeId::new("attacker-node");
        receipt.receipt_id = receipt.body().compute_id().unwrap();
        let err = receipt
            .verify_offline(&key.verifying_key())
            .expect_err("signature must reject mutated enforcing_node_id");
        assert!(matches!(
            err,
            ReceiptError::SignatureVerificationFailed { .. }
        ));
    }

    #[test]
    fn forgery_mutating_constraints_summary_fails_signature() {
        let key = signing_key();
        let mut receipt = ConstraintEnforcementReceipt::seal(allow_body(), &key).unwrap();
        receipt
            .constraints_evaluated
            .evaluated_kinds
            .push("fabricated_kind".to_string());
        receipt.receipt_id = receipt.body().compute_id().unwrap();
        let err = receipt
            .verify_offline(&key.verifying_key())
            .expect_err("signature must reject mutated constraints summary");
        assert!(matches!(
            err,
            ReceiptError::SignatureVerificationFailed { .. }
        ));
    }

    #[test]
    fn forgery_swapping_signature_with_wrong_key_fails() {
        let key = signing_key();
        let other_key = Ed25519SigningKey::from_bytes(&[0xAB_u8; 32]).unwrap();
        let receipt = ConstraintEnforcementReceipt::seal(allow_body(), &key).unwrap();
        let err = receipt
            .verify_offline(&other_key.verifying_key())
            .expect_err("signature must reject under wrong verifying key");
        assert!(matches!(
            err,
            ReceiptError::SignatureVerificationFailed { .. }
        ));
    }

    // ── Resolver path ────────────────────────────────────────────────────

    #[test]
    fn verify_with_resolver_returns_outcome_when_key_known() {
        let key = signing_key();
        let receipt = ConstraintEnforcementReceipt::seal(allow_body(), &key).unwrap();
        let outcome = receipt
            .verify_offline_with_resolver(|node_id| {
                if *node_id == receipt.enforcing_node_id {
                    Some(key.verifying_key())
                } else {
                    None
                }
            })
            .expect("resolver supplies key");
        assert!(outcome.is_allow());
    }

    #[test]
    fn verify_with_resolver_unknown_node_returns_structured_error() {
        let key = signing_key();
        let receipt = ConstraintEnforcementReceipt::seal(allow_body(), &key).unwrap();
        let err = receipt
            .verify_offline_with_resolver(|_| None)
            .expect_err("resolver returns None");
        assert!(
            matches!(
                &err,
                ReceiptError::UnknownEnforcingNode { enforcing_node_id }
                    if enforcing_node_id == receipt.enforcing_node_id.as_str()
            ),
            "unexpected error: {err:?}"
        );
    }

    // ── EvaluationOutcomeRecord accessors ────────────────────────────────

    #[test]
    fn evaluation_outcome_accessors_round_trip() {
        let allow = EvaluationOutcomeRecord::Allow;
        assert!(allow.is_allow());
        assert!(!allow.is_deny());

        let deny = EvaluationOutcomeRecord::Deny {
            denial_kind: "x".to_string(),
            observed_value: "y".to_string(),
        };
        assert!(deny.is_deny());
        assert!(!deny.is_allow());
    }

    // ── RequestDescriptorHash ────────────────────────────────────────────

    #[test]
    fn request_descriptor_hash_keyed_to_distinct_domain() {
        // Same canonical bytes hashed by `from_canonical_bytes` MUST NOT
        // collide with the receipt-id domain or the signing domain.
        let cbor_payload = b"some canonical request descriptor bytes";
        let req_hash = RequestDescriptorHash::from_canonical_bytes(cbor_payload);

        let mut id_hasher = blake3::Hasher::new();
        id_hasher.update(RECEIPT_ID_DOMAIN);
        id_hasher.update(cbor_payload);
        let id_collision_check: [u8; 32] = *id_hasher.finalize().as_bytes();
        assert_ne!(*req_hash.as_bytes(), id_collision_check);

        let mut sig_hasher = blake3::Hasher::new();
        sig_hasher.update(RECEIPT_SIGNING_DOMAIN);
        sig_hasher.update(cbor_payload);
        let sig_collision_check: [u8; 32] = *sig_hasher.finalize().as_bytes();
        assert_ne!(*req_hash.as_bytes(), sig_collision_check);
    }

    #[test]
    fn request_descriptor_hash_round_trips_through_serde_json() {
        let h = RequestDescriptorHash::from_canonical_bytes(b"abc");
        let json = serde_json::to_string(&h).unwrap();
        let back: RequestDescriptorHash = serde_json::from_str(&json).unwrap();
        assert_eq!(h, back);
    }

    // ── Property: forgery resistance over arbitrary post-seal mutations ──

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// For ANY mutation of any signed field on a sealed receipt,
        /// signature verification MUST fail. This is the structural
        /// forgery-resistance guarantee.
        #[test]
        fn proptest_forgery_resistance_under_signed_field_mutation(
            mutation_seed in 0u32..1024,
            xor_byte in 1u8..=255,
            field_pick in 0u8..10,
        ) {
            let key = signing_key();
            let mut receipt = ConstraintEnforcementReceipt::seal(allow_body(), &key).unwrap();

            match field_pick {
                0 => {
                    receipt.token_id = token_b();
                }
                1 => {
                    receipt.zone_id = ZoneId::public();
                }
                2 => {
                    receipt.request_nonce = nonce_b();
                }
                3 => {
                    // Mutate request_descriptor_hash deterministically.
                    let mut bytes = *receipt.request_descriptor_hash.as_bytes();
                    let idx = (mutation_seed as usize) % bytes.len();
                    bytes[idx] ^= xor_byte;
                    receipt.request_descriptor_hash = RequestDescriptorHash::from_bytes(bytes);
                }
                4 => {
                    // Mutate sealed_at.
                    receipt.sealed_at_unix_ms = receipt.sealed_at_unix_ms
                        .wrapping_add(u64::from(mutation_seed) + 1);
                }
                5 => {
                    receipt.expires_at_unix_ms = receipt.expires_at_unix_ms
                        .wrapping_add(u64::from(mutation_seed) + 1);
                }
                6 => {
                    receipt.revocation_head_seq_observed = receipt.revocation_head_seq_observed
                        .wrapping_add(u64::from(mutation_seed) + 1);
                }
                7 => {
                    // Mutate enforcing_node_id.
                    receipt.enforcing_node_id = TailscaleNodeId::new(
                        format!("attacker-{mutation_seed}")
                    );
                }
                8 => {
                    // Mutate evaluation_outcome.
                    receipt.evaluation_outcome = EvaluationOutcomeRecord::Deny {
                        denial_kind: format!("fabricated-{mutation_seed}"),
                        observed_value: "x".to_string(),
                    };
                }
                _ => {
                    // Mutate constraints_evaluated.
                    receipt
                        .constraints_evaluated
                        .evaluated_kinds
                        .push(format!("injected-{mutation_seed}"));
                }
            }

            // Recompute receipt_id so the receipt-id check passes; the
            // signature check is the one that MUST catch the mutation.
            receipt.receipt_id = receipt.body().compute_id().unwrap();

            let result = receipt.verify_offline(&key.verifying_key());
            prop_assert!(
                matches!(
                    result,
                    Err(ReceiptError::SignatureVerificationFailed { .. })
                ),
                "mutation of signed field {field_pick} produced {result:?}; expected SignatureVerificationFailed"
            );
        }
    }
}
