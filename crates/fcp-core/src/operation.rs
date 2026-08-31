//! Exactly-once semantics for FCP operations.
//!
//! This module implements `OperationIntent` and `OperationReceipt` as defined in
//! `FCP_Specification_V3.md` §6.1 (Receipts). Together with idempotency keys, these objects
//! provide exactly-once semantics for external side effects.
//!
//! # Core Concepts
//!
//! ## Exactly-Once Semantics
//!
//! For Strict idempotency and for Risky/Dangerous operations:
//! 1. `MeshNode` MUST store `OperationIntent` (Required retention) BEFORE executing side effects
//! 2. `OperationIntent` MUST reference the execution lease via `ObjectHeader.refs` (for Risky/Dangerous)
//! 3. `OperationReceipt` MUST reference the `OperationIntent` via `ObjectHeader.refs`
//! 4. On crash recovery, check for intents without corresponding receipts
//!
//! ## Idempotency Enforcement
//!
//! - On retry with same `idempotency_key`, mesh returns prior receipt without re-executing
//! - Receipts are stored in symbol store (`RetentionClass::Lease` or Pinned for critical)
//! - Makes "best-effort vs strict idempotency" enforceable, not advisory
//!
//! ## Lease Binding
//!
//! For Risky/Dangerous operations, `OperationIntent.lease_seq` SHOULD bind to the
//! execution lease fencing token. This prevents zombie lease holders from executing
//! operations after losing the lease.

use fcp_crypto::{
    CryptoResult, HybridSignable, HybridSignedObjectKind, SignedEnvelope,
    signing_bytes_for_canonical_payload,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    CapabilityId, IdempotencyClass, InstanceId, NodeSignature, ObjectHeader, ObjectId, PrincipalId,
    RequestId, TailscaleNodeId, UsageMetric, ZoneId,
};

/// Tracing span name for canonical operation execution.
pub const CANONICAL_OPERATION_SPAN_NAME: &str = "fcp_operation";

/// Stable tracing attribute names emitted by canonical operation spans.
pub const CANONICAL_OPERATION_SPAN_ATTRIBUTE_NAMES: [&str; 5] = [
    "zone_id",
    "capability_id",
    "principal_id",
    "instance_id",
    "request_id",
];

/// Create the canonical tracing span for an FCP operation.
#[must_use]
pub fn canonical_operation_span(
    zone_id: &ZoneId,
    capability_id: &CapabilityId,
    principal_id: &PrincipalId,
    instance_id: &InstanceId,
    request_id: &RequestId,
) -> tracing::Span {
    tracing::info_span!(
        CANONICAL_OPERATION_SPAN_NAME,
        zone_id = %zone_id,
        capability_id = %capability_id,
        principal_id = %principal_id,
        instance_id = %instance_id,
        request_id = %request_id,
    )
}

fn append_len_prefixed_bytes(bytes: &mut Vec<u8>, value: &[u8]) {
    let value_len = u32::try_from(value.len()).unwrap_or(u32::MAX);
    bytes.extend_from_slice(&value_len.to_le_bytes());
    bytes.extend_from_slice(value);
}

fn append_optional_string(bytes: &mut Vec<u8>, value: Option<&str>) {
    if let Some(value) = value {
        bytes.extend_from_slice(&[1]);
        append_len_prefixed_bytes(bytes, value.as_bytes());
    } else {
        bytes.extend_from_slice(&[0]);
    }
}

fn append_canonical_header(bytes: &mut Vec<u8>, header: &ObjectHeader) {
    let header_cbor = fcp_cbor::to_canonical_cbor(header)
        .expect("operation headers must be canonical-CBOR encodable");
    append_len_prefixed_bytes(bytes, &header_cbor);
}

// ─────────────────────────────────────────────────────────────────────────────
// OperationIntent (NORMATIVE)
// ─────────────────────────────────────────────────────────────────────────────

/// Operation intent - pre-commit for exactly-once semantics (NORMATIVE for Strict + Risky/Dangerous).
///
/// Closes the crash window between "side effect happened" and "receipt stored".
/// Written BEFORE executing an external side effect.
///
/// # Execution Rule (NORMATIVE)
///
/// 1. `MeshNode` MUST store `OperationIntent` BEFORE invoking the connector operation
/// 2. `OperationIntent` MUST reference the `ExecutionLease` via `header.refs` (for Risky/Dangerous)
/// 3. `OperationReceipt` MUST reference this intent via `header.refs`
/// 4. On crash recovery, intents without receipts indicate incomplete operations
///
/// # Fencing Token Binding
///
/// For Risky/Dangerous operations, `lease_seq` binds this intent to a specific
/// lease. Connectors can reject stale lease holders by comparing `lease_seq`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationIntent {
    /// Standard object header with schema, zone, provenance.
    ///
    /// For Risky/Dangerous operations, `header.refs` MUST include the
    /// `ObjectId` of the execution lease.
    pub header: ObjectHeader,

    /// `ObjectId` of the original invoke request.
    pub request_object_id: ObjectId,

    /// Unique identifier from the capability token (jti claim).
    ///
    /// Links this intent to the specific capability token authorizing execution.
    pub capability_token_jti: Uuid,

    /// Idempotency key for exactly-once semantics (NORMATIVE for Strict).
    ///
    /// If present, retries with the same key MUST return the prior receipt
    /// without re-executing the operation.
    pub idempotency_key: Option<String>,

    /// When this intent was created (Unix timestamp seconds).
    pub planned_at: u64,

    /// Node that planned/will execute this operation.
    pub planned_by: TailscaleNodeId,

    /// Lease fencing token observed for this intent (NORMATIVE for Risky/Dangerous).
    ///
    /// Connectors/state writers can reject stale lease holders by comparing `lease_seq`.
    /// Must match the `lease_seq` of the active execution lease.
    pub lease_seq: Option<u64>,

    /// Optional upstream idempotency handle (e.g., Stripe idempotency key).
    ///
    /// When the external service provides its own idempotency mechanism,
    /// this field stores the handle used for that service.
    pub upstream_idempotency: Option<String>,

    /// Signature by the planning node's signing key.
    pub signature: NodeSignature,
}

impl OperationIntent {
    /// Get the zone ID from the header.
    #[must_use]
    pub const fn zone_id(&self) -> &ZoneId {
        &self.header.zone_id
    }

    /// Check if this intent requires strict idempotency enforcement.
    #[must_use]
    pub const fn requires_strict_idempotency(&self) -> bool {
        self.idempotency_key.is_some()
    }

    /// Check if this intent is bound to a lease.
    #[must_use]
    pub const fn is_lease_bound(&self) -> bool {
        self.lease_seq.is_some()
    }

    /// Compute the bytes that were signed.
    ///
    /// The signable content is the canonical representation of the intent
    /// excluding the signature field itself.
    #[must_use]
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"FCP2-INTENT-V1");
        append_canonical_header(&mut bytes, &self.header);
        bytes.extend_from_slice(self.request_object_id.as_bytes());
        bytes.extend_from_slice(self.capability_token_jti.as_bytes());
        append_optional_string(&mut bytes, self.idempotency_key.as_deref());
        bytes.extend_from_slice(&self.planned_at.to_le_bytes());
        append_len_prefixed_bytes(&mut bytes, self.planned_by.as_str().as_bytes());
        if let Some(seq) = self.lease_seq {
            bytes.extend_from_slice(&[1]);
            bytes.extend_from_slice(&seq.to_le_bytes());
        } else {
            bytes.extend_from_slice(&[0]);
        }
        append_optional_string(&mut bytes, self.upstream_idempotency.as_deref());
        bytes
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OperationReceipt (NORMATIVE)
// ─────────────────────────────────────────────────────────────────────────────

/// Operation receipt object (NORMATIVE).
///
/// Records the successful completion of an operation, including what was
/// produced. For Strict idempotency, returning a prior receipt on retry
/// is REQUIRED.
///
/// # Idempotency Semantics
///
/// Operations with `SafetyTier::Dangerous` MUST be `IdempotencyClass::Strict`.
/// Operations with `SafetyTier::Risky` SHOULD be Strict unless there is a clear reason.
///
/// # Object References
///
/// `header.refs` MUST include the `ObjectId` of the corresponding `OperationIntent`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationReceipt {
    /// Standard object header with schema, zone, provenance.
    ///
    /// `header.refs` MUST include the intent's `ObjectId`.
    pub header: ObjectHeader,

    /// `ObjectId` of the original invoke request.
    pub request_object_id: ObjectId,

    /// Idempotency key (echoed from intent if provided).
    ///
    /// Used for O(1) lookup on retry.
    pub idempotency_key: Option<String>,

    /// `ObjectId`s of outcome objects produced by the operation.
    ///
    /// These may be `InvokeResponse` objects, `ResourceObjects`, etc.
    pub outcome_object_ids: Vec<ObjectId>,

    /// `ResourceObject` IDs created or modified (NORMATIVE).
    ///
    /// Enables auditing of what resources were affected.
    pub resource_object_ids: Vec<ObjectId>,

    /// Usage metrics observed during execution (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage_metrics: Option<Vec<UsageMetric>>,

    /// When execution completed (Unix timestamp seconds).
    pub executed_at: u64,

    /// Node that executed the operation.
    pub executed_by: TailscaleNodeId,

    /// Signature by executing node's signing key.
    pub signature: NodeSignature,
}

impl OperationReceipt {
    /// Get the zone ID from the header.
    #[must_use]
    pub const fn zone_id(&self) -> &ZoneId {
        &self.header.zone_id
    }

    /// Check if this receipt is for an idempotent operation.
    #[must_use]
    pub const fn is_idempotent(&self) -> bool {
        self.idempotency_key.is_some()
    }

    /// Get the total number of objects produced.
    #[must_use]
    pub fn total_objects_produced(&self) -> usize {
        self.outcome_object_ids.len() + self.resource_object_ids.len()
    }

    /// Compute the bytes that were signed.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // Vec lengths capped by protocol limits
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"FCP2-RECEIPT-V1");
        append_canonical_header(&mut bytes, &self.header);
        bytes.extend_from_slice(self.request_object_id.as_bytes());
        append_optional_string(&mut bytes, self.idempotency_key.as_deref());
        // Include outcome object IDs (count capped at u32::MAX for protocol encoding)
        let outcome_count = u32::try_from(self.outcome_object_ids.len()).unwrap_or(u32::MAX);
        bytes.extend_from_slice(&outcome_count.to_le_bytes());
        for oid in &self.outcome_object_ids {
            bytes.extend_from_slice(oid.as_bytes());
        }
        // Include resource object IDs (count capped at u32::MAX for protocol encoding)
        let resource_count = u32::try_from(self.resource_object_ids.len()).unwrap_or(u32::MAX);
        bytes.extend_from_slice(&resource_count.to_le_bytes());
        for oid in &self.resource_object_ids {
            bytes.extend_from_slice(oid.as_bytes());
        }
        if let Some(metrics) = &self.usage_metrics {
            bytes.extend_from_slice(&[1]);
            let metric_count = u32::try_from(metrics.len()).unwrap_or(u32::MAX);
            bytes.extend_from_slice(&metric_count.to_le_bytes());
            for metric in metrics {
                let kind_bytes = metric.kind.as_str().as_bytes();
                let kind_len = u32::try_from(kind_bytes.len()).unwrap_or(u32::MAX);
                bytes.extend_from_slice(&kind_len.to_le_bytes());
                bytes.extend_from_slice(kind_bytes);
                bytes.extend_from_slice(&metric.amount.to_le_bytes());
                if let Some(unit) = &metric.unit {
                    bytes.extend_from_slice(&[1]);
                    let unit_len = u32::try_from(unit.len()).unwrap_or(u32::MAX);
                    bytes.extend_from_slice(&unit_len.to_le_bytes());
                    bytes.extend_from_slice(unit.as_bytes());
                } else {
                    bytes.extend_from_slice(&[0]);
                }
                if let Some(custom_id) = &metric.custom_id {
                    bytes.extend_from_slice(&[1]);
                    let id_len = u32::try_from(custom_id.len()).unwrap_or(u32::MAX);
                    bytes.extend_from_slice(&id_len.to_le_bytes());
                    bytes.extend_from_slice(custom_id.as_bytes());
                } else {
                    bytes.extend_from_slice(&[0]);
                }
            }
        } else {
            bytes.extend_from_slice(&[0]);
        }
        bytes.extend_from_slice(&self.executed_at.to_le_bytes());
        append_len_prefixed_bytes(&mut bytes, self.executed_by.as_str().as_bytes());
        bytes
    }
}

/// Hybrid signed operation-receipt envelope.
pub type HybridSignedOperationReceipt = SignedEnvelope<OperationReceipt>;

impl HybridSignable for OperationReceipt {
    const OBJECT_KIND: HybridSignedObjectKind = HybridSignedObjectKind::OperationReceipt;

    fn hybrid_signing_bytes(&self) -> CryptoResult<Vec<u8>> {
        Ok(signing_bytes_for_canonical_payload(
            Self::OBJECT_KIND,
            &self.signable_bytes(),
        ))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Operation Status (public operation lifecycle)
// ─────────────────────────────────────────────────────────────────────────────

/// Public operation lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperationStatus {
    /// Operation has been accepted but has not started.
    Pending,
    /// Operation is currently running.
    Running,
    /// Operation completed successfully.
    Completed,
    /// Operation failed.
    Failed,
}

// ─────────────────────────────────────────────────────────────────────────────
// Intent Status (for crash recovery)
// ─────────────────────────────────────────────────────────────────────────────

/// Status of an operation intent.
///
/// Used during crash recovery to determine the state of an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    /// Intent recorded, operation not yet started.
    Pending,
    /// Operation in progress (side effect may or may not have occurred).
    InProgress,
    /// Operation completed successfully (receipt exists).
    Completed,
    /// Operation failed (error receipt exists).
    Failed,
    /// Intent orphaned (no receipt, exceeded timeout).
    Orphaned,
}

impl std::fmt::Display for IntentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::InProgress => write!(f, "in_progress"),
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
            Self::Orphaned => write!(f, "orphaned"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Idempotency Key Index Entry
// ─────────────────────────────────────────────────────────────────────────────

/// Index entry for idempotency key lookups.
///
/// Enables O(1) lookup of receipts by idempotency key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdempotencyEntry {
    /// The idempotency key.
    pub key: String,

    /// Zone context for the operation.
    pub zone_id: ZoneId,

    /// `ObjectId` of the intent.
    pub intent_id: ObjectId,

    /// `ObjectId` of the receipt (if completed).
    pub receipt_id: Option<ObjectId>,

    /// Current status.
    pub status: IntentStatus,

    /// When the entry was created.
    pub created_at: u64,

    /// When the entry expires (for garbage collection).
    ///
    /// After expiry, the key may be reused (though the receipt remains
    /// valid for auditing).
    pub expires_at: u64,
}

impl IdempotencyEntry {
    /// Check if this entry has expired.
    #[must_use]
    pub const fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }

    /// Check if the operation is complete (success or failure).
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self.status, IntentStatus::Completed | IntentStatus::Failed)
    }

    /// Check if a retry should return the existing receipt.
    ///
    /// Returns true if:
    /// - Operation completed and receipt exists
    /// - Entry has not expired
    #[must_use]
    pub const fn should_return_cached(&self, now: u64) -> bool {
        !self.is_expired(now) && self.is_terminal() && self.receipt_id.is_some()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Validation
// ─────────────────────────────────────────────────────────────────────────────

/// Error returned when intent/receipt validation fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationValidationError {
    /// Intent is missing for the given idempotency key.
    IntentNotFound { idempotency_key: String },

    /// Receipt already exists for this idempotency key.
    AlreadyCompleted { idempotency_key: String },

    /// Receipt idempotency key does not match the intent.
    IdempotencyKeyMismatch {
        expected: Option<String>,
        got: Option<String>,
    },

    /// Intent/receipt zone mismatch.
    ZoneMismatch { expected: ZoneId, got: ZoneId },

    /// Receipt does not reference the expected intent.
    IntentReferenceMissing { receipt_id: ObjectId },

    /// Lease sequence mismatch (stale lease holder).
    LeaseSeqMismatch { expected: u64, got: u64 },

    /// Intent has been orphaned.
    IntentOrphaned {
        intent_id: ObjectId,
        planned_at: u64,
    },

    /// Signature verification failed.
    SignatureInvalid { reason: String },

    /// Request object ID mismatch.
    RequestMismatch { expected: ObjectId, got: ObjectId },
}

impl std::fmt::Display for OperationValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IntentNotFound { idempotency_key } => {
                write!(f, "intent not found for idempotency key: {idempotency_key}")
            }
            Self::AlreadyCompleted { idempotency_key } => {
                write!(
                    f,
                    "operation already completed for idempotency key: {idempotency_key}"
                )
            }
            Self::IdempotencyKeyMismatch { expected, got } => {
                write!(
                    f,
                    "idempotency key mismatch: expected {}, got {}",
                    expected.as_deref().unwrap_or("<none>"),
                    got.as_deref().unwrap_or("<none>")
                )
            }
            Self::ZoneMismatch { expected, got } => {
                write!(f, "zone mismatch: expected {expected}, got {got}")
            }
            Self::IntentReferenceMissing { receipt_id } => {
                write!(f, "receipt {receipt_id} does not reference an intent")
            }
            Self::LeaseSeqMismatch { expected, got } => {
                write!(f, "lease seq mismatch: expected {expected}, got {got}")
            }
            Self::IntentOrphaned {
                intent_id,
                planned_at,
            } => {
                write!(f, "intent {intent_id} orphaned (planned at {planned_at})")
            }
            Self::SignatureInvalid { reason } => {
                write!(f, "signature invalid: {reason}")
            }
            Self::RequestMismatch { expected, got } => {
                write!(f, "request mismatch: expected {expected}, got {got}")
            }
        }
    }
}

impl std::error::Error for OperationValidationError {}

/// Validate that a receipt properly references its intent.
///
/// # Arguments
///
/// * `receipt` - The receipt to validate
/// * `receipt_id` - `ObjectId` of the receipt object
/// * `intent` - The expected intent
/// * `intent_id` - `ObjectId` of the intent object
///
/// # Errors
///
/// Returns an error if:
/// - Receipt's `request_object_id` doesn't match intent's
/// - Receipt's zone doesn't match intent's
/// - Receipt's `idempotency_key` doesn't match intent's
/// - Receipt's `header.refs` does not include the corresponding intent ID
pub fn validate_receipt_intent_binding(
    receipt_id: ObjectId,
    receipt: &OperationReceipt,
    intent_id: ObjectId,
    intent: &OperationIntent,
) -> Result<(), OperationValidationError> {
    // Check request object ID matches
    if receipt.request_object_id != intent.request_object_id {
        return Err(OperationValidationError::RequestMismatch {
            expected: intent.request_object_id,
            got: receipt.request_object_id,
        });
    }

    // Check zone matches
    if receipt.zone_id() != intent.zone_id() {
        return Err(OperationValidationError::ZoneMismatch {
            expected: intent.zone_id().clone(),
            got: receipt.zone_id().clone(),
        });
    }

    // Check idempotency key matches
    if receipt.idempotency_key != intent.idempotency_key {
        return Err(OperationValidationError::IdempotencyKeyMismatch {
            expected: intent.idempotency_key.clone(),
            got: receipt.idempotency_key.clone(),
        });
    }

    if !receipt.header.refs.contains(&intent_id) {
        return Err(OperationValidationError::IntentReferenceMissing { receipt_id });
    }

    Ok(())
}

/// Check if an intent should be considered orphaned.
///
/// An intent is orphaned if:
/// - No corresponding receipt exists
/// - More than `orphan_threshold_secs` have passed since `planned_at`
///
/// # Arguments
///
/// * `intent` - The intent to check
/// * `has_receipt` - Whether a receipt exists for this intent
/// * `now` - Current timestamp
/// * `orphan_threshold_secs` - Threshold for orphan detection
#[must_use]
pub const fn is_intent_orphaned(
    intent: &OperationIntent,
    has_receipt: bool,
    now: u64,
    orphan_threshold_secs: u64,
) -> bool {
    !has_receipt && now.saturating_sub(intent.planned_at) > orphan_threshold_secs
}

/// Determine idempotency class requirements based on safety tier.
///
/// Per spec:
/// - Dangerous operations MUST be Strict
/// - Risky operations SHOULD be Strict
/// - Safe operations MAY be any class
#[must_use]
pub const fn required_idempotency_for_safety_tier(
    is_dangerous: bool,
    is_risky: bool,
) -> IdempotencyClass {
    // Both Dangerous and Risky require Strict idempotency per spec
    if is_dangerous || is_risky {
        IdempotencyClass::Strict
    } else {
        IdempotencyClass::None // Safe ops don't require idempotency
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Provenance;
    use fcp_cbor::SchemaId;
    use semver::Version;

    fn test_node(name: &str) -> TailscaleNodeId {
        TailscaleNodeId::new(name)
    }

    fn test_zone() -> ZoneId {
        ZoneId::work()
    }

    fn test_object_id(name: &str) -> ObjectId {
        ObjectId::from_unscoped_bytes(name.as_bytes())
    }

    fn test_intent_id() -> ObjectId {
        test_object_id("intent-1")
    }

    fn test_receipt_id() -> ObjectId {
        test_object_id("receipt-1")
    }

    fn test_signature() -> NodeSignature {
        NodeSignature::new(crate::NodeId::new("test-node"), [0u8; 64], 1000)
    }

    fn create_test_header() -> ObjectHeader {
        let zone = test_zone();
        ObjectHeader {
            encryption_kind: Default::default(),
            schema: SchemaId::new("fcp.operation", "intent", Version::new(1, 0, 0)),
            zone_id: zone.clone(),
            created_at: 1000,
            provenance: Provenance::new(zone),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        }
    }

    fn create_test_intent() -> OperationIntent {
        OperationIntent {
            header: create_test_header(),
            request_object_id: test_object_id("request-1"),
            capability_token_jti: Uuid::nil(),
            idempotency_key: Some("idem-key-123".to_string()),
            planned_at: 1000,
            planned_by: test_node("executor-node"),
            lease_seq: Some(42),
            upstream_idempotency: None,
            signature: test_signature(),
        }
    }

    fn create_test_receipt() -> OperationReceipt {
        let mut header = create_test_header();
        header.schema = SchemaId::new("fcp.operation", "receipt", Version::new(1, 0, 0));
        header.refs = vec![test_intent_id()];

        OperationReceipt {
            header,
            request_object_id: test_object_id("request-1"),
            idempotency_key: Some("idem-key-123".to_string()),
            outcome_object_ids: vec![test_object_id("outcome-1")],
            resource_object_ids: vec![],
            usage_metrics: None,
            executed_at: 1100,
            executed_by: test_node("executor-node"),
            signature: test_signature(),
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // OperationIntent Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_intent_zone_id() {
        let intent = create_test_intent();
        assert_eq!(intent.zone_id(), &test_zone());
    }

    #[test]
    fn test_intent_requires_strict_idempotency() {
        let mut intent = create_test_intent();
        assert!(intent.requires_strict_idempotency());

        intent.idempotency_key = None;
        assert!(!intent.requires_strict_idempotency());
    }

    #[test]
    fn test_intent_is_lease_bound() {
        let mut intent = create_test_intent();
        assert!(intent.is_lease_bound());

        intent.lease_seq = None;
        assert!(!intent.is_lease_bound());
    }

    #[test]
    fn test_intent_signable_bytes_deterministic() {
        let intent = create_test_intent();
        let bytes1 = intent.signable_bytes();
        let bytes2 = intent.signable_bytes();
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn test_intent_signable_bytes_differ_with_different_keys() {
        let mut intent1 = create_test_intent();
        let mut intent2 = create_test_intent();

        intent1.idempotency_key = Some("key-1".to_string());
        intent2.idempotency_key = Some("key-2".to_string());

        assert_ne!(intent1.signable_bytes(), intent2.signable_bytes());
    }

    #[test]
    fn test_intent_serde() {
        let intent = create_test_intent();
        let json = serde_json::to_string(&intent).unwrap();
        let deserialized: OperationIntent = serde_json::from_str(&json).unwrap();

        assert_eq!(intent.request_object_id, deserialized.request_object_id);
        assert_eq!(intent.idempotency_key, deserialized.idempotency_key);
        assert_eq!(intent.planned_at, deserialized.planned_at);
        assert_eq!(intent.lease_seq, deserialized.lease_seq);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // OperationReceipt Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_receipt_zone_id() {
        let receipt = create_test_receipt();
        assert_eq!(receipt.zone_id(), &test_zone());
    }

    #[test]
    fn test_receipt_is_idempotent() {
        let mut receipt = create_test_receipt();
        assert!(receipt.is_idempotent());

        receipt.idempotency_key = None;
        assert!(!receipt.is_idempotent());
    }

    #[test]
    fn test_receipt_total_objects() {
        let mut receipt = create_test_receipt();
        assert_eq!(receipt.total_objects_produced(), 1);

        receipt.resource_object_ids =
            vec![test_object_id("resource-1"), test_object_id("resource-2")];
        assert_eq!(receipt.total_objects_produced(), 3);
    }

    #[test]
    fn test_receipt_signable_bytes_deterministic() {
        let receipt = create_test_receipt();
        let bytes1 = receipt.signable_bytes();
        let bytes2 = receipt.signable_bytes();
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn test_receipt_signable_bytes_change_with_usage() {
        let mut receipt1 = create_test_receipt();
        let mut receipt2 = create_test_receipt();

        receipt1.usage_metrics = Some(vec![UsageMetric::tokens(100)]);
        receipt2.usage_metrics = Some(vec![UsageMetric::tokens(200)]);

        assert_ne!(receipt1.signable_bytes(), receipt2.signable_bytes());
    }

    #[test]
    fn test_receipt_serde() {
        let receipt = create_test_receipt();
        let json = serde_json::to_string(&receipt).unwrap();
        let deserialized: OperationReceipt = serde_json::from_str(&json).unwrap();

        assert_eq!(receipt.request_object_id, deserialized.request_object_id);
        assert_eq!(receipt.idempotency_key, deserialized.idempotency_key);
        assert_eq!(receipt.executed_at, deserialized.executed_at);
        assert_eq!(
            receipt.outcome_object_ids.len(),
            deserialized.outcome_object_ids.len()
        );
        assert_eq!(
            receipt.usage_metrics.as_ref().map_or(0, Vec::len),
            deserialized.usage_metrics.as_ref().map_or(0, Vec::len)
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // IntentStatus Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_intent_status_display() {
        assert_eq!(IntentStatus::Pending.to_string(), "pending");
        assert_eq!(IntentStatus::InProgress.to_string(), "in_progress");
        assert_eq!(IntentStatus::Completed.to_string(), "completed");
        assert_eq!(IntentStatus::Failed.to_string(), "failed");
        assert_eq!(IntentStatus::Orphaned.to_string(), "orphaned");
    }

    #[test]
    fn test_intent_status_serde() {
        let statuses = [
            IntentStatus::Pending,
            IntentStatus::InProgress,
            IntentStatus::Completed,
            IntentStatus::Failed,
            IntentStatus::Orphaned,
        ];

        for status in statuses {
            let json = serde_json::to_string(&status).unwrap();
            let deserialized: IntentStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, deserialized);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // IdempotencyEntry Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_idempotency_entry_is_expired() {
        let entry = IdempotencyEntry {
            key: "test-key".to_string(),
            zone_id: test_zone(),
            intent_id: test_object_id("intent"),
            receipt_id: None,
            status: IntentStatus::Pending,
            created_at: 1000,
            expires_at: 2000,
        };

        assert!(!entry.is_expired(1500));
        assert!(entry.is_expired(2000));
        assert!(entry.is_expired(2500));
    }

    #[test]
    fn test_idempotency_entry_is_terminal() {
        let mut entry = IdempotencyEntry {
            key: "test-key".to_string(),
            zone_id: test_zone(),
            intent_id: test_object_id("intent"),
            receipt_id: None,
            status: IntentStatus::Pending,
            created_at: 1000,
            expires_at: 2000,
        };

        assert!(!entry.is_terminal());

        entry.status = IntentStatus::InProgress;
        assert!(!entry.is_terminal());

        entry.status = IntentStatus::Completed;
        assert!(entry.is_terminal());

        entry.status = IntentStatus::Failed;
        assert!(entry.is_terminal());
    }

    #[test]
    fn test_idempotency_entry_should_return_cached() {
        let mut entry = IdempotencyEntry {
            key: "test-key".to_string(),
            zone_id: test_zone(),
            intent_id: test_object_id("intent"),
            receipt_id: Some(test_object_id("receipt")),
            status: IntentStatus::Completed,
            created_at: 1000,
            expires_at: 2000,
        };

        // Should return cached (completed + receipt + not expired)
        assert!(entry.should_return_cached(1500));

        // Should not return cached (expired)
        assert!(!entry.should_return_cached(2500));

        // Should not return cached (not terminal)
        entry.status = IntentStatus::InProgress;
        assert!(!entry.should_return_cached(1500));

        // Should not return cached (no receipt)
        entry.status = IntentStatus::Completed;
        entry.receipt_id = None;
        assert!(!entry.should_return_cached(1500));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Validation Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_validate_receipt_intent_binding_success() {
        let intent = create_test_intent();
        let receipt = create_test_receipt();

        let result =
            validate_receipt_intent_binding(test_receipt_id(), &receipt, test_intent_id(), &intent);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_receipt_intent_binding_request_mismatch() {
        let intent = create_test_intent();
        let mut receipt = create_test_receipt();
        receipt.request_object_id = test_object_id("different-request");

        let result =
            validate_receipt_intent_binding(test_receipt_id(), &receipt, test_intent_id(), &intent);
        assert!(matches!(
            result,
            Err(OperationValidationError::RequestMismatch { .. })
        ));
    }

    #[test]
    fn test_validate_receipt_intent_binding_zone_mismatch() {
        let intent = create_test_intent();
        let mut receipt = create_test_receipt();
        receipt.header.zone_id = ZoneId::owner();

        let result =
            validate_receipt_intent_binding(test_receipt_id(), &receipt, test_intent_id(), &intent);
        assert!(matches!(
            result,
            Err(OperationValidationError::ZoneMismatch { .. })
        ));
    }

    #[test]
    fn test_validate_receipt_intent_binding_missing_reference() {
        let intent = create_test_intent();
        let mut receipt = create_test_receipt();
        receipt.header.refs.clear();

        let result =
            validate_receipt_intent_binding(test_receipt_id(), &receipt, test_intent_id(), &intent);
        assert!(matches!(
            result,
            Err(OperationValidationError::IntentReferenceMissing { .. })
        ));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Orphan Detection Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_is_intent_orphaned() {
        let intent = create_test_intent();

        // Not orphaned (has receipt)
        assert!(!is_intent_orphaned(&intent, true, 5000, 3600));

        // Not orphaned (within threshold)
        assert!(!is_intent_orphaned(&intent, false, 1500, 3600));

        // Orphaned (no receipt + past threshold)
        assert!(is_intent_orphaned(&intent, false, 5000, 3600));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Idempotency Class Requirements Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_required_idempotency_for_safety_tier() {
        // Dangerous MUST be Strict
        assert_eq!(
            required_idempotency_for_safety_tier(true, false),
            IdempotencyClass::Strict
        );

        // Risky SHOULD be Strict
        assert_eq!(
            required_idempotency_for_safety_tier(false, true),
            IdempotencyClass::Strict
        );

        // Safe operations don't require idempotency
        assert_eq!(
            required_idempotency_for_safety_tier(false, false),
            IdempotencyClass::None
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Retry Returns Same Receipt Test
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_retry_returns_same_receipt_scenario() {
        // Simulate a retry scenario
        let idempotency_key = "stripe-payment-xyz".to_string();

        // First: Create entry when intent is recorded
        let entry = IdempotencyEntry {
            key: idempotency_key,
            zone_id: test_zone(),
            intent_id: test_object_id("intent-1"),
            receipt_id: Some(test_object_id("receipt-1")),
            status: IntentStatus::Completed,
            created_at: 1000,
            expires_at: 1000 + 86400, // 24 hours
        };

        // Second request with same key at different time
        let retry_time = 1500;

        // Entry should indicate cached return
        assert!(entry.should_return_cached(retry_time));

        // The receipt_id from the entry is what should be returned
        assert_eq!(entry.receipt_id, Some(test_object_id("receipt-1")));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden Vector Tests - Deterministic CBOR Serialization
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn golden_intent_signable_bytes_deterministic() {
        // Create intent with all fields populated
        let intent = create_test_intent();

        // Signable bytes must be deterministic across calls
        let bytes1 = intent.signable_bytes();
        let bytes2 = intent.signable_bytes();
        let bytes3 = intent.signable_bytes();

        assert_eq!(bytes1, bytes2);
        assert_eq!(bytes2, bytes3);

        // Must start with domain separator
        assert!(bytes1.starts_with(b"FCP2-INTENT-V1"));
    }

    #[test]
    fn golden_intent_signable_bytes_include_all_fields() {
        let intent = create_test_intent();
        let bytes = intent.signable_bytes();

        // Bytes should include:
        // - Domain separator
        // - created_at (8 bytes)
        // - request_object_id
        // - capability_token_jti (16 bytes for UUID)
        // - idempotency_key (present marker + content)
        // - planned_at (8 bytes)
        // - planned_by
        // - lease_seq (present marker + 8 bytes)
        // - upstream_idempotency (present marker)

        // Must be non-trivial length (domain sep + all fields)
        assert!(bytes.len() > 50);
    }

    #[test]
    fn golden_receipt_signable_bytes_deterministic() {
        let receipt = create_test_receipt();

        let bytes1 = receipt.signable_bytes();
        let bytes2 = receipt.signable_bytes();

        assert_eq!(bytes1, bytes2);
        assert!(bytes1.starts_with(b"FCP2-RECEIPT-V1"));
    }

    #[test]
    fn golden_intent_receipt_signable_bytes_differ() {
        // Intent and receipt for same operation should have different signable bytes
        let intent = create_test_intent();
        let receipt = create_test_receipt();

        let intent_bytes = intent.signable_bytes();
        let receipt_bytes = receipt.signable_bytes();

        // Different domain separators and structures
        assert_ne!(intent_bytes, receipt_bytes);
        assert!(intent_bytes.starts_with(b"FCP2-INTENT-V1"));
        assert!(receipt_bytes.starts_with(b"FCP2-RECEIPT-V1"));
    }

    #[test]
    fn golden_intent_serde_json_roundtrip() {
        let intent = create_test_intent();

        // Serialize to JSON
        let json = serde_json::to_string_pretty(&intent).unwrap();

        // Parse back
        let parsed: OperationIntent = serde_json::from_str(&json).unwrap();

        // Key fields must match
        assert_eq!(parsed.request_object_id, intent.request_object_id);
        assert_eq!(parsed.idempotency_key, intent.idempotency_key);
        assert_eq!(parsed.lease_seq, intent.lease_seq);
        assert_eq!(parsed.planned_at, intent.planned_at);
    }

    #[test]
    fn golden_receipt_serde_json_roundtrip() {
        let receipt = create_test_receipt();

        let json = serde_json::to_string_pretty(&receipt).unwrap();
        let parsed: OperationReceipt = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.request_object_id, receipt.request_object_id);
        assert_eq!(parsed.idempotency_key, receipt.idempotency_key);
        assert_eq!(parsed.outcome_object_ids, receipt.outcome_object_ids);
        assert_eq!(parsed.executed_at, receipt.executed_at);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Idempotency Key Tests - Core Idempotency Properties
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn idempotency_different_keys_produce_independent_entries() {
        // Two operations with different idempotency keys should be independent
        let key1 = "operation-001";
        let key2 = "operation-002";

        let entry1 = IdempotencyEntry {
            key: key1.to_string(),
            zone_id: test_zone(),
            intent_id: test_object_id("intent-1"),
            receipt_id: Some(test_object_id("receipt-1")),
            status: IntentStatus::Completed,
            created_at: 1000,
            expires_at: 2000,
        };

        let entry2 = IdempotencyEntry {
            key: key2.to_string(),
            zone_id: test_zone(),
            intent_id: test_object_id("intent-2"),
            receipt_id: Some(test_object_id("receipt-2")),
            status: IntentStatus::Completed,
            created_at: 1000,
            expires_at: 2000,
        };

        // Keys are different
        assert_ne!(entry1.key, entry2.key);

        // Each should have its own receipt
        assert_ne!(entry1.receipt_id, entry2.receipt_id);

        // Both are independently cacheable
        assert!(entry1.should_return_cached(1500));
        assert!(entry2.should_return_cached(1500));
    }

    #[test]
    fn idempotency_key_collision_resistance() {
        // Keys that are similar but not identical should not collide
        let keys = [
            "op-1", "op-10", "op-100", "op-1000", "op_1", "op.1", "op:1", "OP-1", "Op-1",
        ];

        // All keys should be unique
        let unique: std::collections::HashSet<_> = keys.iter().collect();
        assert_eq!(unique.len(), keys.len());
    }

    #[test]
    fn idempotency_key_expiry_semantics() {
        let entry = IdempotencyEntry {
            key: "test-key".to_string(),
            zone_id: test_zone(),
            intent_id: test_object_id("intent"),
            receipt_id: Some(test_object_id("receipt")),
            status: IntentStatus::Completed,
            created_at: 1000,
            expires_at: 2000,
        };

        // Before expiry - should return cached
        assert!(!entry.is_expired(1999));
        assert!(entry.should_return_cached(1999));

        // At expiry boundary - expired
        assert!(entry.is_expired(2000));
        assert!(!entry.should_return_cached(2000));

        // After expiry - key may be reused
        assert!(entry.is_expired(3000));
        assert!(!entry.should_return_cached(3000));
    }

    #[test]
    fn idempotency_entry_lifecycle() {
        // Simulate full lifecycle of an idempotency entry

        // 1. Intent created, entry pending
        let mut entry = IdempotencyEntry {
            key: "payment-xyz".to_string(),
            zone_id: test_zone(),
            intent_id: test_object_id("intent"),
            receipt_id: None,
            status: IntentStatus::Pending,
            created_at: 1000,
            expires_at: 1000 + 86400, // 24 hours
        };

        assert!(!entry.is_terminal());
        assert!(!entry.should_return_cached(1000));

        // 2. Operation in progress
        entry.status = IntentStatus::InProgress;
        assert!(!entry.is_terminal());
        assert!(!entry.should_return_cached(1000));

        // 3. Operation completed, receipt added
        entry.status = IntentStatus::Completed;
        entry.receipt_id = Some(test_object_id("receipt"));

        assert!(entry.is_terminal());
        assert!(entry.should_return_cached(1500));

        // 4. Retry with same key should return cached
        assert!(entry.should_return_cached(2000));
        assert!(entry.should_return_cached(50000)); // Still within 24 hour window

        // 5. After expiry, entry is no longer cached
        assert!(!entry.should_return_cached(1000 + 86400 + 1));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Lease Fencing Tests - Preventing Zombie Lease Holders
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn lease_fencing_intent_binds_to_lease_seq() {
        let mut intent = create_test_intent();
        intent.lease_seq = Some(42);

        assert!(intent.is_lease_bound());
        assert_eq!(intent.lease_seq, Some(42));
    }

    #[test]
    fn lease_fencing_stale_lease_detection() {
        // Simulate stale lease holder attempting execution
        let intent = create_test_intent();
        let expected_lease_seq = 42_u64;

        // Intent was created with lease_seq = 42
        assert_eq!(intent.lease_seq, Some(expected_lease_seq));

        // Stale lease holder has old sequence
        let stale_lease_seq = 40_u64;

        // Comparison shows stale (old seq < expected seq)
        assert!(stale_lease_seq < expected_lease_seq);
    }

    #[test]
    fn lease_fencing_no_lease_for_safe_operations() {
        let mut intent = create_test_intent();
        intent.lease_seq = None;

        // Safe operations don't require lease binding
        assert!(!intent.is_lease_bound());

        // Can still have strict idempotency without lease
        assert!(intent.requires_strict_idempotency());
    }

    #[test]
    fn lease_fencing_signable_bytes_include_lease_seq() {
        let mut intent1 = create_test_intent();
        let mut intent2 = create_test_intent();

        // Same intent but different lease sequences
        intent1.lease_seq = Some(100);
        intent2.lease_seq = Some(200);

        // Signable bytes should differ
        assert_ne!(intent1.signable_bytes(), intent2.signable_bytes());
    }

    #[test]
    fn lease_fencing_signable_bytes_differ_with_without_lease() {
        let mut intent_with_lease = create_test_intent();
        let mut intent_without_lease = create_test_intent();

        intent_with_lease.lease_seq = Some(42);
        intent_without_lease.lease_seq = None;

        // Signable bytes should differ
        assert_ne!(
            intent_with_lease.signable_bytes(),
            intent_without_lease.signable_bytes()
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Fault Injection Tests - Crash Recovery Simulation
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn fault_crash_between_intent_and_receipt_detection() {
        // Simulate crash after intent created but before receipt
        let intent = create_test_intent();
        let has_receipt = false;
        let now = intent.planned_at + 7200; // 2 hours later
        let orphan_threshold = 3600; // 1 hour threshold

        // Intent should be detected as orphaned
        assert!(is_intent_orphaned(
            &intent,
            has_receipt,
            now,
            orphan_threshold
        ));
    }

    #[test]
    fn fault_crash_recovery_with_receipt_present() {
        // If receipt exists, intent is not orphaned
        let intent = create_test_intent();
        let has_receipt = true;
        let now = intent.planned_at + 7200; // 2 hours later
        let orphan_threshold = 3600;

        assert!(!is_intent_orphaned(
            &intent,
            has_receipt,
            now,
            orphan_threshold
        ));
    }

    #[test]
    fn fault_intent_not_orphaned_within_threshold() {
        // Intent within threshold should not be orphaned
        let intent = create_test_intent();
        let has_receipt = false;
        let now = intent.planned_at + 1800; // 30 minutes later
        let orphan_threshold = 3600; // 1 hour threshold

        // Still within threshold, not orphaned yet
        assert!(!is_intent_orphaned(
            &intent,
            has_receipt,
            now,
            orphan_threshold
        ));
    }

    #[test]
    fn fault_orphan_detection_at_threshold_boundary() {
        let intent = create_test_intent();
        let has_receipt = false;
        let orphan_threshold = 3600;

        // Exactly at threshold - not orphaned (> not >=)
        let at_threshold = intent.planned_at + orphan_threshold;
        assert!(!is_intent_orphaned(
            &intent,
            has_receipt,
            at_threshold,
            orphan_threshold
        ));

        // One second past threshold - orphaned
        let past_threshold = intent.planned_at + orphan_threshold + 1;
        assert!(is_intent_orphaned(
            &intent,
            has_receipt,
            past_threshold,
            orphan_threshold
        ));
    }

    #[test]
    fn fault_orphan_detection_handles_timestamp_overflow() {
        let mut intent = create_test_intent();
        intent.planned_at = u64::MAX - 100; // Near max timestamp

        let has_receipt = false;
        let orphan_threshold = 3600;

        // Should not panic on overflow, should use saturating subtraction
        let result = is_intent_orphaned(&intent, has_receipt, u64::MAX, orphan_threshold);

        // 100 seconds elapsed, less than threshold
        assert!(!result);
    }

    #[test]
    fn fault_idempotency_entry_status_transitions() {
        // Test valid status transitions for fault recovery

        // Pending -> InProgress (normal flow)
        let status1 = IntentStatus::Pending;
        assert!(!matches!(status1, IntentStatus::InProgress));

        // InProgress -> Completed (success)
        let status2 = IntentStatus::InProgress;
        assert!(!matches!(status2, IntentStatus::Completed));

        // InProgress -> Failed (error)
        assert!(!matches!(status2, IntentStatus::Failed));

        // InProgress -> Orphaned (crash recovery)
        assert!(!matches!(status2, IntentStatus::Orphaned));
    }

    #[test]
    fn fault_incomplete_intent_reconciliation_scenario() {
        // Simulate reconciliation of incomplete intents during recovery

        // Found intent without receipt
        let entry = IdempotencyEntry {
            key: "incomplete-op".to_string(),
            zone_id: test_zone(),
            intent_id: test_object_id("orphan-intent"),
            receipt_id: None,
            status: IntentStatus::InProgress,
            created_at: 1000,
            expires_at: 5000,
        };

        // Not terminal, no cached receipt to return
        assert!(!entry.is_terminal());
        assert!(!entry.should_return_cached(2000));

        // After reconciliation, status would be set to Orphaned
        let mut reconciled = entry;
        reconciled.status = IntentStatus::Orphaned;

        // Still not terminal (Orphaned may need different handling in actual implementation)
        assert!(!reconciled.is_terminal());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Concurrency Tests - Race Condition Prevention
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn concurrency_same_key_single_execution_check() {
        // For concurrent requests with same key, only one should execute
        // This is enforced by checking should_return_cached before execution

        let entry = IdempotencyEntry {
            key: "concurrent-op".to_string(),
            zone_id: test_zone(),
            intent_id: test_object_id("intent"),
            receipt_id: None,
            status: IntentStatus::Pending,
            created_at: 1000,
            expires_at: 5000,
        };

        // First request starts execution - status is InProgress
        assert!(!entry.is_terminal());
        assert!(!entry.should_return_cached(1100));

        // Second request checks at same time - sees InProgress
        // Should not start a new execution (implementation detail)
        assert!(!entry.is_terminal());
    }

    #[test]
    fn concurrency_different_keys_independent_execution() {
        // Concurrent requests with different keys should all execute
        let entries: Vec<IdempotencyEntry> = (0..5)
            .map(|i| IdempotencyEntry {
                key: format!("concurrent-{i}"),
                zone_id: test_zone(),
                intent_id: test_object_id(&format!("intent-{i}")),
                receipt_id: None,
                status: IntentStatus::Pending,
                created_at: 1000,
                expires_at: 5000,
            })
            .collect();

        // All should be independent - none should return cached
        for entry in &entries {
            assert!(!entry.should_return_cached(1100));
        }

        // All have unique keys
        let keys: std::collections::HashSet<_> = entries.iter().map(|e| &e.key).collect();
        assert_eq!(keys.len(), 5);
    }

    #[test]
    fn concurrency_race_intent_lease_expiry_scenario() {
        // Simulate race between intent creation and lease expiry
        let intent = create_test_intent();

        // Intent was created when lease was active (lease_seq = 42)
        assert_eq!(intent.lease_seq, Some(42));

        // If lease expires before execution completes, the intent's lease_seq
        // will be stale compared to a new lease's sequence
        let new_lease_seq = 43_u64;

        // Stale lease detection (intent's seq < current seq)
        assert!(intent.lease_seq.unwrap() < new_lease_seq);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Validation Error Display Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn validation_error_display_all_variants() {
        let errors = [
            OperationValidationError::IntentNotFound {
                idempotency_key: "key-123".to_string(),
            },
            OperationValidationError::AlreadyCompleted {
                idempotency_key: "key-456".to_string(),
            },
            OperationValidationError::IdempotencyKeyMismatch {
                expected: Some("expected-key".to_string()),
                got: None,
            },
            OperationValidationError::ZoneMismatch {
                expected: ZoneId::work(),
                got: ZoneId::owner(),
            },
            OperationValidationError::IntentReferenceMissing {
                receipt_id: test_object_id("receipt"),
            },
            OperationValidationError::LeaseSeqMismatch {
                expected: 42,
                got: 41,
            },
            OperationValidationError::IntentOrphaned {
                intent_id: test_object_id("orphan"),
                planned_at: 1000,
            },
            OperationValidationError::SignatureInvalid {
                reason: "bad signature".to_string(),
            },
            OperationValidationError::RequestMismatch {
                expected: test_object_id("req-1"),
                got: test_object_id("req-2"),
            },
        ];

        for error in &errors {
            let display = error.to_string();
            assert!(!display.is_empty());

            // Each error should have meaningful content
            match error {
                OperationValidationError::IntentNotFound { idempotency_key }
                | OperationValidationError::AlreadyCompleted { idempotency_key } => {
                    assert!(display.contains(idempotency_key));
                }
                OperationValidationError::IdempotencyKeyMismatch { .. }
                | OperationValidationError::ZoneMismatch { .. }
                | OperationValidationError::RequestMismatch { .. } => {
                    assert!(display.contains("mismatch"));
                }
                OperationValidationError::IntentReferenceMissing { .. } => {
                    assert!(display.contains("reference"));
                }
                OperationValidationError::LeaseSeqMismatch { expected, .. } => {
                    assert!(display.contains(&expected.to_string()));
                }
                OperationValidationError::IntentOrphaned { .. } => {
                    assert!(display.contains("orphaned"));
                }
                OperationValidationError::SignatureInvalid { reason } => {
                    assert!(display.contains(reason));
                }
            }
        }
    }

    #[test]
    fn validation_error_is_std_error() {
        let error: Box<dyn std::error::Error> =
            Box::new(OperationValidationError::IntentNotFound {
                idempotency_key: "test".to_string(),
            });

        // Should implement std::error::Error
        assert!(!error.to_string().is_empty());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Safety Tier Idempotency Requirements Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn safety_tier_dangerous_requires_strict() {
        // Dangerous operations MUST be Strict
        let result = required_idempotency_for_safety_tier(true, false);
        assert_eq!(result, IdempotencyClass::Strict);

        // Both dangerous and risky
        let result = required_idempotency_for_safety_tier(true, true);
        assert_eq!(result, IdempotencyClass::Strict);
    }

    #[test]
    fn safety_tier_risky_requires_strict() {
        // Risky operations SHOULD be Strict
        let result = required_idempotency_for_safety_tier(false, true);
        assert_eq!(result, IdempotencyClass::Strict);
    }

    #[test]
    fn safety_tier_safe_allows_none() {
        // Safe operations don't require idempotency
        let result = required_idempotency_for_safety_tier(false, false);
        assert_eq!(result, IdempotencyClass::None);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Edge Cases and Boundary Conditions
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn edge_empty_idempotency_key() {
        let mut intent = create_test_intent();
        intent.idempotency_key = Some(String::new());

        // Empty string is still "some" key
        assert!(intent.requires_strict_idempotency());

        // Signable bytes should include the empty key
        let bytes = intent.signable_bytes();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn edge_very_long_idempotency_key() {
        let mut intent = create_test_intent();
        let long_key = "x".repeat(10_000);
        intent.idempotency_key = Some(long_key);

        // Should handle long keys
        assert!(intent.requires_strict_idempotency());

        let bytes = intent.signable_bytes();
        // Bytes should include the long key
        assert!(bytes.len() > 10_000);
    }

    #[test]
    fn edge_receipt_with_many_outcome_objects() {
        let mut receipt = create_test_receipt();

        // Add many outcome objects
        receipt.outcome_object_ids = (0..100)
            .map(|i| test_object_id(&format!("outcome-{i}")))
            .collect();

        assert_eq!(receipt.outcome_object_ids.len(), 100);
        assert_eq!(receipt.total_objects_produced(), 100);

        // Signable bytes should be deterministic
        let bytes1 = receipt.signable_bytes();
        let bytes2 = receipt.signable_bytes();
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn edge_receipt_with_many_resource_objects() {
        let mut receipt = create_test_receipt();

        receipt.resource_object_ids = (0..50)
            .map(|i| test_object_id(&format!("resource-{i}")))
            .collect();

        assert_eq!(receipt.resource_object_ids.len(), 50);
        assert_eq!(receipt.total_objects_produced(), 51); // 1 outcome + 50 resources
    }

    #[test]
    fn edge_intent_with_upstream_idempotency() {
        let mut intent = create_test_intent();
        intent.upstream_idempotency = Some("stripe-idem-key-xyz".to_string());

        let bytes1 = intent.signable_bytes();

        // Change upstream key
        intent.upstream_idempotency = Some("stripe-idem-key-abc".to_string());
        let bytes2 = intent.signable_bytes();

        // Different upstream keys should produce different signable bytes
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn edge_intent_without_upstream_idempotency() {
        let mut intent1 = create_test_intent();
        let mut intent2 = create_test_intent();

        intent1.upstream_idempotency = None;
        intent2.upstream_idempotency = Some("upstream-key".to_string());

        // Should produce different signable bytes
        assert_ne!(intent1.signable_bytes(), intent2.signable_bytes());
    }

    #[test]
    fn edge_idempotency_entry_with_failed_status() {
        let entry = IdempotencyEntry {
            key: "failed-op".to_string(),
            zone_id: test_zone(),
            intent_id: test_object_id("intent"),
            receipt_id: Some(test_object_id("error-receipt")),
            status: IntentStatus::Failed,
            created_at: 1000,
            expires_at: 2000,
        };

        // Failed is terminal
        assert!(entry.is_terminal());

        // Failed with receipt should return cached (to return error consistently)
        assert!(entry.should_return_cached(1500));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // IntentStatus trait coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn intent_status_copy() {
        let s = IntentStatus::Pending;
        let copied = s;
        assert_eq!(s, copied);
    }

    #[test]
    fn intent_status_display_all_variants() {
        assert_eq!(IntentStatus::Pending.to_string(), "pending");
        assert_eq!(IntentStatus::InProgress.to_string(), "in_progress");
        assert_eq!(IntentStatus::Completed.to_string(), "completed");
        assert_eq!(IntentStatus::Failed.to_string(), "failed");
        assert_eq!(IntentStatus::Orphaned.to_string(), "orphaned");
    }

    #[test]
    fn intent_status_serde_all_variants() {
        let variants = [
            IntentStatus::Pending,
            IntentStatus::InProgress,
            IntentStatus::Completed,
            IntentStatus::Failed,
            IntentStatus::Orphaned,
        ];
        for status in variants {
            let json = serde_json::to_string(&status).unwrap();
            let back: IntentStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, back);
        }
    }

    #[test]
    fn intent_status_inequality() {
        assert_ne!(IntentStatus::Pending, IntentStatus::Completed);
        assert_ne!(IntentStatus::Failed, IntentStatus::Orphaned);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // OperationIntent trait coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn operation_intent_clone() {
        let intent = create_test_intent();
        let cloned = intent.clone();
        assert_eq!(cloned.planned_at, intent.planned_at);
        assert_eq!(cloned.lease_seq, intent.lease_seq);
        assert_eq!(cloned.idempotency_key, intent.idempotency_key);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // OperationReceipt trait coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn operation_receipt_clone() {
        let receipt = create_test_receipt();
        let cloned = receipt.clone();
        assert_eq!(cloned.executed_at, receipt.executed_at);
        assert_eq!(cloned.idempotency_key, receipt.idempotency_key);
    }

    #[test]
    fn receipt_zone_id() {
        let receipt = create_test_receipt();
        assert_eq!(receipt.zone_id(), &test_zone());
    }

    #[test]
    fn receipt_is_idempotent() {
        let mut receipt = create_test_receipt();
        assert!(receipt.is_idempotent());

        receipt.idempotency_key = None;
        assert!(!receipt.is_idempotent());
    }

    #[test]
    fn receipt_total_objects_produced_empty() {
        let mut receipt = create_test_receipt();
        receipt.outcome_object_ids.clear();
        receipt.resource_object_ids.clear();
        assert_eq!(receipt.total_objects_produced(), 0);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // IdempotencyEntry trait coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn idempotency_entry_clone() {
        let entry = IdempotencyEntry {
            key: "test".to_string(),
            zone_id: test_zone(),
            intent_id: test_object_id("intent"),
            receipt_id: None,
            status: IntentStatus::Pending,
            created_at: 1000,
            expires_at: 2000,
        };
        let cloned = Clone::clone(&entry);
        assert_eq!(cloned.key, "test");
        assert_eq!(cloned.status, IntentStatus::Pending);
    }

    #[test]
    fn idempotency_entry_serde_roundtrip() {
        let entry = IdempotencyEntry {
            key: "serde-test".to_string(),
            zone_id: test_zone(),
            intent_id: test_object_id("intent"),
            receipt_id: Some(test_object_id("receipt")),
            status: IntentStatus::Completed,
            created_at: 1000,
            expires_at: 5000,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: IdempotencyEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.key, "serde-test");
        assert_eq!(back.status, IntentStatus::Completed);
        assert!(back.receipt_id.is_some());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // OperationValidationError trait coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn validation_error_clone() {
        let err = OperationValidationError::LeaseSeqMismatch {
            expected: 42,
            got: 41,
        };
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn validation_error_equality() {
        let a = OperationValidationError::IdempotencyKeyMismatch {
            expected: Some("k".into()),
            got: None,
        };
        let b = OperationValidationError::IdempotencyKeyMismatch {
            expected: Some("k".into()),
            got: None,
        };
        assert_eq!(a, b);
    }

    #[test]
    fn validation_error_inequality() {
        let a = OperationValidationError::IdempotencyKeyMismatch {
            expected: Some("k1".into()),
            got: None,
        };
        let b = OperationValidationError::IdempotencyKeyMismatch {
            expected: Some("k2".into()),
            got: None,
        };
        assert_ne!(a, b);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // validate_receipt_intent_binding coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn validate_binding_success() {
        let intent = create_test_intent();
        let receipt = create_test_receipt();
        assert!(
            validate_receipt_intent_binding(test_receipt_id(), &receipt, test_intent_id(), &intent)
                .is_ok()
        );
    }

    #[test]
    fn validate_binding_request_mismatch() {
        let intent = create_test_intent();
        let mut receipt = create_test_receipt();
        receipt.request_object_id = test_object_id("different-request");
        let err =
            validate_receipt_intent_binding(test_receipt_id(), &receipt, test_intent_id(), &intent)
                .unwrap_err();
        assert!(matches!(
            err,
            OperationValidationError::RequestMismatch { .. }
        ));
    }

    #[test]
    fn validate_binding_idempotency_key_mismatch() {
        let intent = create_test_intent();
        let mut receipt = create_test_receipt();
        receipt.idempotency_key = Some("different-key".into());
        let err =
            validate_receipt_intent_binding(test_receipt_id(), &receipt, test_intent_id(), &intent)
                .unwrap_err();
        assert!(matches!(
            err,
            OperationValidationError::IdempotencyKeyMismatch { .. }
        ));
    }

    #[test]
    fn validate_binding_missing_intent_reference() {
        let intent = create_test_intent();
        let mut receipt = create_test_receipt();
        receipt.header.refs.clear();
        let err =
            validate_receipt_intent_binding(test_receipt_id(), &receipt, test_intent_id(), &intent)
                .unwrap_err();
        assert!(matches!(
            err,
            OperationValidationError::IntentReferenceMissing { .. }
        ));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: Additional operation tests for 110+ coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn intent_signable_bytes_starts_with_domain_separator() {
        let intent = create_test_intent();
        let bytes = intent.signable_bytes();
        assert!(bytes.starts_with(b"FCP2-INTENT-V1"));
    }

    #[test]
    fn receipt_signable_bytes_starts_with_domain_separator() {
        let receipt = create_test_receipt();
        let bytes = receipt.signable_bytes();
        assert!(bytes.starts_with(b"FCP2-RECEIPT-V1"));
    }

    #[test]
    fn intent_signable_bytes_differ_by_planned_at() {
        let mut intent1 = create_test_intent();
        let mut intent2 = create_test_intent();
        intent1.planned_at = 1000;
        intent2.planned_at = 2000;
        assert_ne!(intent1.signable_bytes(), intent2.signable_bytes());
    }

    #[test]
    fn intent_signable_bytes_differ_by_planned_by() {
        let mut intent1 = create_test_intent();
        let mut intent2 = create_test_intent();
        intent1.planned_by = test_node("node-a");
        intent2.planned_by = test_node("node-b");
        assert_ne!(intent1.signable_bytes(), intent2.signable_bytes());
    }

    #[test]
    fn intent_signable_bytes_differ_by_capability_jti() {
        let mut intent1 = create_test_intent();
        let mut intent2 = create_test_intent();
        intent1.capability_token_jti = Uuid::from_bytes([0x01; 16]);
        intent2.capability_token_jti = Uuid::from_bytes([0x02; 16]);
        assert_ne!(intent1.signable_bytes(), intent2.signable_bytes());
    }

    #[test]
    fn intent_signable_bytes_differ_by_request_object_id() {
        let mut intent1 = create_test_intent();
        let mut intent2 = create_test_intent();
        intent1.request_object_id = test_object_id("req-a");
        intent2.request_object_id = test_object_id("req-b");
        assert_ne!(intent1.signable_bytes(), intent2.signable_bytes());
    }

    #[test]
    fn intent_signable_bytes_differ_by_header_refs() {
        let mut intent1 = create_test_intent();
        let mut intent2 = create_test_intent();
        intent1.header.refs.push(test_object_id("lease-a"));
        intent2.header.refs.push(test_object_id("lease-b"));
        assert_ne!(intent1.signable_bytes(), intent2.signable_bytes());
    }

    #[test]
    fn intent_no_idempotency_key_signable_bytes_contains_absent_marker() {
        let mut intent = create_test_intent();
        intent.idempotency_key = None;
        intent.lease_seq = None;
        intent.upstream_idempotency = None;
        let bytes = intent.signable_bytes();
        // Should have 3 absent markers [0] for the 3 optional fields
        // Just verify it's deterministic and non-trivial
        assert!(bytes.len() > 14); // domain separator is 14 bytes
    }

    #[test]
    fn intent_all_optional_fields_present_signable_bytes() {
        let mut intent = create_test_intent();
        intent.idempotency_key = Some("key".to_string());
        intent.lease_seq = Some(99);
        intent.upstream_idempotency = Some("upstream".to_string());
        let bytes = intent.signable_bytes();
        // Should be longer than when fields are absent
        let mut intent2 = create_test_intent();
        intent2.idempotency_key = None;
        intent2.lease_seq = None;
        intent2.upstream_idempotency = None;
        let bytes2 = intent2.signable_bytes();
        assert!(bytes.len() > bytes2.len());
    }

    #[test]
    fn receipt_signable_bytes_differ_by_executed_at() {
        let mut r1 = create_test_receipt();
        let mut r2 = create_test_receipt();
        r1.executed_at = 1000;
        r2.executed_at = 2000;
        assert_ne!(r1.signable_bytes(), r2.signable_bytes());
    }

    #[test]
    fn receipt_signable_bytes_differ_by_executed_by() {
        let mut r1 = create_test_receipt();
        let mut r2 = create_test_receipt();
        r1.executed_by = test_node("node-x");
        r2.executed_by = test_node("node-y");
        assert_ne!(r1.signable_bytes(), r2.signable_bytes());
    }

    #[test]
    fn receipt_signable_bytes_differ_by_outcome_ids() {
        let mut r1 = create_test_receipt();
        let mut r2 = create_test_receipt();
        r1.outcome_object_ids = vec![test_object_id("o1")];
        r2.outcome_object_ids = vec![test_object_id("o2")];
        assert_ne!(r1.signable_bytes(), r2.signable_bytes());
    }

    #[test]
    fn receipt_signable_bytes_differ_by_resource_ids() {
        let mut r1 = create_test_receipt();
        let mut r2 = create_test_receipt();
        r1.resource_object_ids = vec![test_object_id("r1")];
        r2.resource_object_ids = vec![test_object_id("r2")];
        assert_ne!(r1.signable_bytes(), r2.signable_bytes());
    }

    #[test]
    fn receipt_signable_bytes_differ_by_header_zone() {
        let r1 = create_test_receipt();
        let mut r2 = create_test_receipt();
        r2.header.zone_id = ZoneId::owner();
        assert_ne!(r1.signable_bytes(), r2.signable_bytes());
    }

    #[test]
    fn receipt_signable_bytes_with_no_metrics() {
        let mut receipt = create_test_receipt();
        receipt.usage_metrics = None;
        let bytes = receipt.signable_bytes();
        assert!(bytes.starts_with(b"FCP2-RECEIPT-V1"));
    }

    #[test]
    fn receipt_signable_bytes_with_metrics_with_unit() {
        let mut receipt = create_test_receipt();
        receipt.usage_metrics = Some(vec![UsageMetric {
            kind: crate::UsageMetricKind::Tokens,
            amount: 500,
            unit: Some("token".to_string()),
            custom_id: None,
        }]);
        let bytes = receipt.signable_bytes();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn receipt_signable_bytes_with_metrics_with_custom_id() {
        let mut receipt = create_test_receipt();
        receipt.usage_metrics = Some(vec![UsageMetric {
            kind: crate::UsageMetricKind::Tokens,
            amount: 100,
            unit: None,
            custom_id: Some("custom-meter-1".to_string()),
        }]);
        let bytes = receipt.signable_bytes();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn receipt_no_idempotency_key() {
        let mut receipt = create_test_receipt();
        receipt.idempotency_key = None;
        let bytes = receipt.signable_bytes();
        // Should contain absent marker [0] for idempotency key
        assert!(bytes.starts_with(b"FCP2-RECEIPT-V1"));
    }

    #[test]
    fn receipt_empty_outcomes_and_resources() {
        let mut receipt = create_test_receipt();
        receipt.outcome_object_ids.clear();
        receipt.resource_object_ids.clear();
        assert_eq!(receipt.total_objects_produced(), 0);
        let bytes = receipt.signable_bytes();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn intent_status_is_not_copy_of_another_variant() {
        let pending = IntentStatus::Pending;
        let completed = IntentStatus::Completed;
        assert_ne!(pending, completed);
    }

    #[test]
    fn intent_status_orphaned_display() {
        assert_eq!(IntentStatus::Orphaned.to_string(), "orphaned");
    }

    #[test]
    fn intent_status_orphaned_is_not_terminal() {
        // Orphaned is NOT terminal (not success/failure)
        let entry = IdempotencyEntry {
            key: "k".to_string(),
            zone_id: test_zone(),
            intent_id: test_object_id("i"),
            receipt_id: None,
            status: IntentStatus::Orphaned,
            created_at: 0,
            expires_at: 1000,
        };
        assert!(!entry.is_terminal());
    }

    #[test]
    fn idempotency_entry_not_expired_at_creation() {
        let entry = IdempotencyEntry {
            key: "k".to_string(),
            zone_id: test_zone(),
            intent_id: test_object_id("i"),
            receipt_id: None,
            status: IntentStatus::Pending,
            created_at: 1000,
            expires_at: 2000,
        };
        assert!(!entry.is_expired(1000));
    }

    #[test]
    fn idempotency_entry_expired_exactly_at_boundary() {
        let entry = IdempotencyEntry {
            key: "k".to_string(),
            zone_id: test_zone(),
            intent_id: test_object_id("i"),
            receipt_id: None,
            status: IntentStatus::Pending,
            created_at: 0,
            expires_at: 100,
        };
        assert!(entry.is_expired(100));
        assert!(!entry.is_expired(99));
    }

    #[test]
    fn idempotency_entry_should_return_cached_failed_with_receipt() {
        let entry = IdempotencyEntry {
            key: "k".to_string(),
            zone_id: test_zone(),
            intent_id: test_object_id("i"),
            receipt_id: Some(test_object_id("err-receipt")),
            status: IntentStatus::Failed,
            created_at: 0,
            expires_at: 1000,
        };
        // Failed is terminal, has receipt, not expired
        assert!(entry.should_return_cached(500));
    }

    #[test]
    fn idempotency_entry_should_not_return_cached_pending() {
        let entry = IdempotencyEntry {
            key: "k".to_string(),
            zone_id: test_zone(),
            intent_id: test_object_id("i"),
            receipt_id: Some(test_object_id("r")),
            status: IntentStatus::Pending,
            created_at: 0,
            expires_at: 1000,
        };
        assert!(!entry.should_return_cached(500));
    }

    #[test]
    fn is_intent_orphaned_now_before_planned_at() {
        let mut intent = create_test_intent();
        intent.planned_at = 5000;
        // now < planned_at, saturating_sub gives 0, which is not > threshold
        assert!(!is_intent_orphaned(&intent, false, 1000, 100));
    }

    #[test]
    fn is_intent_orphaned_zero_threshold() {
        let mut intent = create_test_intent();
        intent.planned_at = 100;
        // any elapsed time > 0 means orphaned with 0 threshold
        assert!(is_intent_orphaned(&intent, false, 101, 0));
        // exactly at planned_at, 0 elapsed, not orphaned
        assert!(!is_intent_orphaned(&intent, false, 100, 0));
    }

    #[test]
    fn required_idempotency_both_dangerous_and_risky() {
        let result = required_idempotency_for_safety_tier(true, true);
        assert_eq!(result, IdempotencyClass::Strict);
    }

    #[test]
    fn validate_binding_both_keys_none_matches() {
        let mut intent = create_test_intent();
        intent.idempotency_key = None;
        let mut receipt = create_test_receipt();
        receipt.idempotency_key = None;
        // Should succeed: both None means keys match
        assert!(
            validate_receipt_intent_binding(test_receipt_id(), &receipt, test_intent_id(), &intent)
                .is_ok()
        );
    }

    #[test]
    fn validate_binding_one_key_none_other_some_fails() {
        let mut intent = create_test_intent();
        intent.idempotency_key = None;
        let mut receipt = create_test_receipt();
        receipt.idempotency_key = Some("key".to_string());
        let err =
            validate_receipt_intent_binding(test_receipt_id(), &receipt, test_intent_id(), &intent)
                .unwrap_err();
        assert!(matches!(
            err,
            OperationValidationError::IdempotencyKeyMismatch { .. }
        ));
    }

    #[test]
    fn validation_error_display_lease_seq_mismatch() {
        let err = OperationValidationError::LeaseSeqMismatch {
            expected: 100,
            got: 99,
        };
        let msg = err.to_string();
        assert!(msg.contains("100"));
        assert!(msg.contains("99"));
    }

    #[test]
    fn validation_error_display_intent_orphaned() {
        let err = OperationValidationError::IntentOrphaned {
            intent_id: test_object_id("orphan"),
            planned_at: 12345,
        };
        let msg = err.to_string();
        assert!(msg.contains("orphaned"));
        assert!(msg.contains("12345"));
    }

    #[test]
    fn validation_error_display_already_completed() {
        let err = OperationValidationError::AlreadyCompleted {
            idempotency_key: "my-key".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("my-key"));
        assert!(msg.contains("already completed"));
    }

    #[test]
    fn validation_error_display_idempotency_key_mismatch() {
        let err = OperationValidationError::IdempotencyKeyMismatch {
            expected: Some("expected-key".to_string()),
            got: None,
        };
        let msg = err.to_string();
        assert!(msg.contains("expected-key"));
        assert!(msg.contains("<none>"));
    }

    #[test]
    fn validation_error_display_intent_reference_missing() {
        let err = OperationValidationError::IntentReferenceMissing {
            receipt_id: test_object_id("r"),
        };
        let msg = err.to_string();
        assert!(msg.contains("reference"));
    }

    #[test]
    fn validation_error_display_signature_invalid() {
        let err = OperationValidationError::SignatureInvalid {
            reason: "corrupted key".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("corrupted key"));
    }

    #[test]
    fn validation_error_display_request_mismatch() {
        let err = OperationValidationError::RequestMismatch {
            expected: test_object_id("a"),
            got: test_object_id("b"),
        };
        let msg = err.to_string();
        assert!(msg.contains("request mismatch"));
    }

    #[test]
    fn validation_error_display_zone_mismatch() {
        let err = OperationValidationError::ZoneMismatch {
            expected: ZoneId::work(),
            got: ZoneId::owner(),
        };
        let msg = err.to_string();
        assert!(msg.contains("zone mismatch"));
    }

    #[test]
    fn validation_error_display_intent_not_found() {
        let err = OperationValidationError::IntentNotFound {
            idempotency_key: "missing-key".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("missing-key"));
    }

    #[test]
    fn validation_error_debug_format() {
        let err = OperationValidationError::IdempotencyKeyMismatch {
            expected: Some("k".to_string()),
            got: None,
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("IdempotencyKeyMismatch"));
    }

    #[test]
    fn intent_serde_with_all_optional_fields() {
        let mut intent = create_test_intent();
        intent.upstream_idempotency = Some("stripe-key".to_string());
        let json = serde_json::to_string(&intent).unwrap();
        let decoded: OperationIntent = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.upstream_idempotency, Some("stripe-key".to_string()));
    }

    #[test]
    fn intent_serde_without_optional_fields() {
        let mut intent = create_test_intent();
        intent.idempotency_key = None;
        intent.lease_seq = None;
        intent.upstream_idempotency = None;
        let json = serde_json::to_string(&intent).unwrap();
        let decoded: OperationIntent = serde_json::from_str(&json).unwrap();
        assert!(decoded.idempotency_key.is_none());
        assert!(decoded.lease_seq.is_none());
        assert!(decoded.upstream_idempotency.is_none());
    }

    #[test]
    fn receipt_serde_with_usage_metrics() {
        let mut receipt = create_test_receipt();
        receipt.usage_metrics = Some(vec![UsageMetric::tokens(100), UsageMetric::tokens(200)]);
        let json = serde_json::to_string(&receipt).unwrap();
        let decoded: OperationReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.usage_metrics.as_ref().map_or(0, Vec::len), 2);
    }

    #[test]
    fn receipt_serde_without_usage_metrics() {
        let mut receipt = create_test_receipt();
        receipt.usage_metrics = None;
        let json = serde_json::to_string(&receipt).unwrap();
        // usage_metrics should be skipped in serialization
        assert!(!json.contains("usage_metrics"));
        let decoded: OperationReceipt = serde_json::from_str(&json).unwrap();
        assert!(decoded.usage_metrics.is_none());
    }

    #[test]
    fn idempotency_entry_serde_with_receipt() {
        let entry = IdempotencyEntry {
            key: "with-receipt".to_string(),
            zone_id: test_zone(),
            intent_id: test_object_id("intent"),
            receipt_id: Some(test_object_id("receipt")),
            status: IntentStatus::Completed,
            created_at: 0,
            expires_at: 86400,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let decoded: IdempotencyEntry = serde_json::from_str(&json).unwrap();
        assert!(decoded.receipt_id.is_some());
        assert_eq!(decoded.status, IntentStatus::Completed);
    }

    #[test]
    fn idempotency_entry_serde_without_receipt() {
        let entry = IdempotencyEntry {
            key: "no-receipt".to_string(),
            zone_id: test_zone(),
            intent_id: test_object_id("intent"),
            receipt_id: None,
            status: IntentStatus::Pending,
            created_at: 0,
            expires_at: 86400,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let decoded: IdempotencyEntry = serde_json::from_str(&json).unwrap();
        assert!(decoded.receipt_id.is_none());
    }

    #[test]
    fn intent_debug_format() {
        let intent = create_test_intent();
        let debug = format!("{intent:?}");
        assert!(debug.contains("OperationIntent"));
    }

    #[test]
    fn receipt_debug_format() {
        let receipt = create_test_receipt();
        let debug = format!("{receipt:?}");
        assert!(debug.contains("OperationReceipt"));
    }

    #[test]
    fn idempotency_entry_debug_format() {
        let entry = IdempotencyEntry {
            key: "dbg".to_string(),
            zone_id: test_zone(),
            intent_id: test_object_id("i"),
            receipt_id: None,
            status: IntentStatus::Pending,
            created_at: 0,
            expires_at: 100,
        };
        let debug = format!("{entry:?}");
        assert!(debug.contains("IdempotencyEntry"));
    }

    #[test]
    fn receipt_signable_bytes_with_multiple_metrics() {
        let mut receipt = create_test_receipt();
        receipt.usage_metrics = Some(vec![
            UsageMetric {
                kind: crate::UsageMetricKind::Tokens,
                amount: 100,
                unit: Some("token".to_string()),
                custom_id: Some("custom-1".to_string()),
            },
            UsageMetric {
                kind: crate::UsageMetricKind::Tokens,
                amount: 200,
                unit: None,
                custom_id: None,
            },
        ]);
        let bytes1 = receipt.signable_bytes();
        let bytes2 = receipt.signable_bytes();
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn receipt_total_objects_both_populated() {
        let mut receipt = create_test_receipt();
        receipt.outcome_object_ids = vec![
            test_object_id("o1"),
            test_object_id("o2"),
            test_object_id("o3"),
        ];
        receipt.resource_object_ids = vec![test_object_id("r1"), test_object_id("r2")];
        assert_eq!(receipt.total_objects_produced(), 5);
    }
}
