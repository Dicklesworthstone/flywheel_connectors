//! Audit + explainability types for FCP (NORMATIVE).
//!
//! This module implements audit chain primitives and explainability receipts as
//! described in `FCP_Specification_V3.md` §6.3 (Audit Chain).

use fcp_crypto::{
    CryptoResult, HybridSignable, HybridSignedObjectKind, SignedEnvelope, signing_bytes_for_payload,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    ConnectorId, CorrelationId, EpochId, NodeId, NodeSignature, ObjectHeader, ObjectId,
    OperationId, PrincipalId, SignatureSet, ZoneId,
};

/// Required audit event types (NORMATIVE).
pub const EVENT_SECRET_ACCESS: &str = "secret.access";
pub const EVENT_CAPABILITY_INVOKE: &str = "capability.invoke";
pub const EVENT_ELEVATION_GRANTED: &str = "elevation.granted";
pub const EVENT_DECLASSIFICATION_GRANTED: &str = "declassification.granted";
pub const EVENT_ZONE_TRANSITION: &str = "zone.transition";
pub const EVENT_REVOCATION_ISSUED: &str = "revocation.issued";
pub const EVENT_SECURITY_VIOLATION: &str = "security.violation";
pub const EVENT_AUDIT_FORK_DETECTED: &str = "audit.fork_detected";

/// Operator-visible evidence handle for audit, trace, and receipt drill-downs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OperatorEvidence {
    /// Audit event object backing an operator-facing explanation.
    AuditEvent {
        #[serde(with = "operator_evidence_object_id")]
        event_id: ObjectId,
    },
    /// Decision receipt object backing an allow or deny outcome.
    DecisionReceipt {
        #[serde(with = "operator_evidence_object_id")]
        receipt_id: ObjectId,
    },
    /// Operation receipt object backing an invocation result.
    OperationReceipt {
        #[serde(with = "operator_evidence_object_id")]
        receipt_id: ObjectId,
    },
    /// Correlation ID for trace lookup.
    TraceContext { correlation_id: CorrelationId },
    /// Durable object that can be retrieved by content address.
    DurableObject {
        #[serde(with = "operator_evidence_object_id")]
        object_id: ObjectId,
    },
    /// Local artifact path plus digest for offline evidence bundles.
    LocalArtifact { path: String, digest: String },
}

mod operator_evidence_object_id {
    use std::fmt;

    use serde::{
        Deserializer, Serializer,
        de::{Error, SeqAccess, Visitor},
    };

    use crate::ObjectId;

    pub fn serialize<S>(object_id: &ObjectId, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        crate::util::hex_or_bytes::serialize(object_id.as_bytes(), serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<ObjectId, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer
            .deserialize_any(ObjectIdVisitor)
            .map(ObjectId::from_bytes)
    }

    struct ObjectIdVisitor;

    impl<'de> Visitor<'de> for ObjectIdVisitor {
        type Value = [u8; 32];

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a 32-byte ObjectId as bytes or hex text")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: Error,
        {
            Ok(*ObjectId::parse_prefixed(value)
                .map_err(E::custom)?
                .as_bytes())
        }

        fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
        where
            E: Error,
        {
            Self::copy_bytes(value)
        }

        fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E>
        where
            E: Error,
        {
            Self::copy_bytes(&value)
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut bytes = [0_u8; 32];
            for (index, byte) in bytes.iter_mut().enumerate() {
                *byte = seq
                    .next_element()?
                    .ok_or_else(|| Error::invalid_length(index, &self))?;
            }
            if seq.next_element::<u8>()?.is_some() {
                return Err(Error::invalid_length(33, &self));
            }
            Ok(bytes)
        }
    }

    impl ObjectIdVisitor {
        fn copy_bytes<E>(value: &[u8]) -> Result<[u8; 32], E>
        where
            E: Error,
        {
            if value.len() != 32 {
                return Err(E::invalid_length(value.len(), &Self));
            }

            let mut bytes = [0_u8; 32];
            bytes.copy_from_slice(value);
            Ok(bytes)
        }
    }
}

/// Distributed trace context (NORMATIVE when present).
///
/// W3C Trace Context compatible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceContext {
    /// 16-byte trace ID (unique per logical request).
    pub trace_id: [u8; 16],
    /// 8-byte span ID (unique per span).
    pub span_id: [u8; 8],
    /// Trace flags/sampling (W3C trace-flags).
    pub flags: u8,
}

/// Audit event (NORMATIVE).
///
/// Append-only, hash-linked audit chain per zone. Each event links to its
/// predecessor via `prev` and carries a monotonic `seq` for O(1) freshness
/// comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Standard object header with schema, zone, provenance.
    pub header: ObjectHeader,
    /// Correlation ID for request tracing (16 bytes).
    pub correlation_id: CorrelationId,
    /// Optional full trace context (NORMATIVE when present in `InvokeRequest`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_context: Option<TraceContext>,
    /// Event type (e.g., "secret.access", "capability.invoke").
    pub event_type: String,
    /// Actor who triggered the event.
    pub actor: PrincipalId,
    /// Zone where event occurred.
    pub zone_id: ZoneId,
    /// Connector ID (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_id: Option<ConnectorId>,
    /// Operation ID (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<OperationId>,
    /// Capability token JTI (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_token_jti: Option<Uuid>,
    /// Request object ID (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_id: Option<ObjectId>,
    /// Result object ID (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_object_id: Option<ObjectId>,
    /// Previous event in chain (hash link) - enables tamper detection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev: Option<ObjectId>,
    /// Monotonic chain sequence number (NORMATIVE).
    pub seq: u64,
    /// When event occurred (Unix timestamp seconds).
    pub occurred_at: u64,
    /// Signature by the executing node.
    pub signature: NodeSignature,
}

impl AuditEvent {
    /// Get the zone ID this event belongs to.
    #[must_use]
    pub const fn zone_id(&self) -> &ZoneId {
        &self.zone_id
    }

    /// Check if this is a genesis event (seq 0, no prev).
    #[must_use]
    pub const fn is_genesis(&self) -> bool {
        self.seq == 0 && self.prev.is_none()
    }

    /// Check if this event follows another event in the chain.
    ///
    /// # Arguments
    ///
    /// * `other` - The event that should precede this one
    /// * `other_id` - The `ObjectId` of `other` (computed from its content/header)
    ///
    /// # Returns
    ///
    /// `true` if this event's `prev` points to `other_id` and this event's
    /// sequence number is exactly one greater than `other`'s.
    #[must_use]
    pub fn follows(&self, other: &Self, other_id: &ObjectId) -> bool {
        other
            .seq
            .checked_add(1)
            .is_some_and(|next_seq| self.seq == next_seq)
            && self.prev.as_ref() == Some(other_id)
    }
}

/// Hybrid signed audit-event envelope.
pub type HybridSignedAuditEvent = SignedEnvelope<AuditEvent>;

impl HybridSignable for AuditEvent {
    const OBJECT_KIND: HybridSignedObjectKind = HybridSignedObjectKind::AuditEvent;

    fn hybrid_signing_bytes(&self) -> CryptoResult<Vec<u8>> {
        let mut unsigned = self.clone();
        unsigned.signature = normalized_node_signature(&self.signature);
        signing_bytes_for_payload(Self::OBJECT_KIND, &unsigned)
    }
}

/// Audit head checkpoint (NORMATIVE).
///
/// Quorum-signed checkpoint of the audit chain head. Enables fast sync
/// without full chain traversal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditHead {
    /// Object header.
    pub header: ObjectHeader,
    /// Zone this head covers.
    pub zone_id: ZoneId,
    /// Head event `ObjectId` (tip of the chain).
    pub head_event: ObjectId,
    /// Sequence number of `head_event` (NORMATIVE).
    pub head_seq: u64,
    /// Fraction of expected nodes contributing (0.0-1.0).
    pub coverage: f64,
    /// Epoch this head was checkpointed.
    pub epoch_id: EpochId,
    /// Quorum signatures from nodes (Byzantine-resilient).
    pub quorum_signatures: SignatureSet,
}

impl AuditHead {
    /// Get the zone ID this head belongs to.
    #[must_use]
    pub const fn zone_id(&self) -> &ZoneId {
        &self.zone_id
    }
}

/// Default revocation SLA: 300 seconds (5 minutes).
const fn default_revocation_sla() -> u64 {
    300
}

/// Zone checkpoint for fast sync (NORMATIVE).
///
/// Quorum-signed checkpoint of zone state for efficient synchronization.
/// Acts as the single GC root (so reachability GC is well-defined).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneCheckpoint {
    pub header: ObjectHeader,
    pub zone_id: ZoneId,
    // Enforceable heads (NORMATIVE).
    pub rev_head: ObjectId,
    pub rev_seq: u64,
    pub audit_head: ObjectId,
    pub audit_seq: u64,
    // Policy/config heads (NORMATIVE).
    pub zone_definition_head: ObjectId,
    pub zone_policy_head: ObjectId,
    pub active_zone_key_manifest: ObjectId,
    /// Monotonic checkpoint sequence (NORMATIVE; per-zone).
    pub checkpoint_seq: u64,
    pub as_of_epoch: EpochId,
    /// Quorum-signed (Byzantine-resilient under n/f model).
    pub quorum_signatures: SignatureSet,
    /// Maximum allowed age (in seconds) of the revocation frontier before
    /// the zone enters DEGRADED revocation state. Operations with
    /// [`RevocationFreshnessClass::Critical`](crate::RevocationFreshnessClass::Critical)
    /// MUST abort when this SLA is breached.
    /// Default: 300 seconds (5 minutes).
    #[serde(default = "default_revocation_sla")]
    pub revocation_freshness_sla_secs: u64,
}

impl ZoneCheckpoint {
    /// Get the zone ID this checkpoint belongs to.
    #[must_use]
    pub const fn zone_id(&self) -> &ZoneId {
        &self.zone_id
    }
}

/// Hybrid signed zone-checkpoint envelope.
pub type HybridSignedZoneCheckpoint = SignedEnvelope<ZoneCheckpoint>;

impl HybridSignable for ZoneCheckpoint {
    const OBJECT_KIND: HybridSignedObjectKind = HybridSignedObjectKind::ZoneCheckpoint;

    fn hybrid_signing_bytes(&self) -> CryptoResult<Vec<u8>> {
        let mut unsigned = self.clone();
        unsigned.quorum_signatures = SignatureSet::new();
        signing_bytes_for_payload(Self::OBJECT_KIND, &unsigned)
    }
}

/// Decision receipt for explainable allow/deny (NORMATIVE).
///
/// Content-addressed "why allowed/denied" record with stable `reason_code` and
/// evidence object IDs. This is what powers `fcp explain`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionReceipt {
    pub header: ObjectHeader,
    /// The request that was evaluated.
    pub request_object_id: ObjectId,
    /// The decision (Allow or Deny).
    pub decision: Decision,
    /// Stable reason code for programmatic handling.
    pub reason_code: String,
    /// Evidence object IDs that support this decision.
    pub evidence: Vec<ObjectId>,
    /// Optional human-readable explanation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,
    /// Signature by the evaluating node.
    pub signature: NodeSignature,
}

impl DecisionReceipt {
    /// Get the zone ID from the header.
    #[must_use]
    pub const fn zone_id(&self) -> &ZoneId {
        &self.header.zone_id
    }

    /// Returns true if this receipt is an allow decision.
    #[must_use]
    pub const fn is_allow(&self) -> bool {
        matches!(self.decision, Decision::Allow)
    }

    /// Returns true if this receipt is a deny decision.
    #[must_use]
    pub const fn is_deny(&self) -> bool {
        matches!(self.decision, Decision::Deny)
    }
}

fn normalized_node_signature(signature: &NodeSignature) -> NodeSignature {
    NodeSignature::new(NodeId::new(signature.node_id.as_str()), [0_u8; 64], 0)
}

/// Decision outcome (NORMATIVE).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Deny,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NodeId, Provenance, QuorumPolicy, RiskTier, SignatureSet};
    use fcp_cbor::SchemaId;
    use semver::Version;

    // ─────────────────────────────────────────────────────────────────────────
    // Test Helpers
    // ─────────────────────────────────────────────────────────────────────────

    fn test_header(kind: &str) -> ObjectHeader {
        ObjectHeader {
            encryption_kind: Default::default(),
            schema: SchemaId::new("fcp.core", kind, Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 1_700_000_000,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        }
    }

    fn test_signature() -> NodeSignature {
        NodeSignature::new(NodeId::new("node-1"), [0u8; 64], 1_700_000_000)
    }

    fn test_signature_for_node(node_id: &str, sig_byte: u8, timestamp: u64) -> NodeSignature {
        NodeSignature::new(NodeId::new(node_id), [sig_byte; 64], timestamp)
    }

    fn test_actor() -> PrincipalId {
        PrincipalId::new("user:alice").expect("principal id")
    }

    fn test_zone() -> ZoneId {
        ZoneId::work()
    }

    fn test_epoch() -> EpochId {
        EpochId::new("epoch-1")
    }

    fn test_object_id(label: &str) -> ObjectId {
        ObjectId::test_id(label)
    }

    fn create_audit_event(seq: u64, prev: Option<ObjectId>, event_type: &str) -> AuditEvent {
        let seq_byte = u8::try_from(seq).expect("seq fits in u8 for test data");
        AuditEvent {
            header: test_header("AuditEvent"),
            correlation_id: CorrelationId(Uuid::from_bytes([seq_byte; 16])),
            trace_context: None,
            event_type: event_type.to_string(),
            actor: test_actor(),
            zone_id: test_zone(),
            connector_id: None,
            operation: None,
            capability_token_jti: None,
            request_object_id: None,
            result_object_id: None,
            prev,
            seq,
            occurred_at: 1_700_000_000 + seq,
            signature: test_signature(),
        }
    }

    fn create_audit_event_with_trace(
        seq: u64,
        prev: Option<ObjectId>,
        trace_context: Option<TraceContext>,
    ) -> AuditEvent {
        let seq_byte = u8::try_from(seq).expect("seq fits in u8 for test data");
        AuditEvent {
            header: test_header("AuditEvent"),
            correlation_id: CorrelationId(Uuid::from_bytes([seq_byte; 16])),
            trace_context,
            event_type: EVENT_CAPABILITY_INVOKE.to_string(),
            actor: test_actor(),
            zone_id: test_zone(),
            connector_id: None,
            operation: None,
            capability_token_jti: None,
            request_object_id: None,
            result_object_id: None,
            prev,
            seq,
            occurred_at: 1_700_000_000 + seq,
            signature: test_signature(),
        }
    }

    fn create_quorum_signature_set(node_count: u8) -> SignatureSet {
        let mut set = SignatureSet::new();
        for i in 0..node_count {
            set.add(test_signature_for_node(
                &format!("node-{i}"),
                i,
                1_700_000_000,
            ));
        }
        set
    }

    fn create_audit_head(head_event: ObjectId, head_seq: u64, sig_count: u8) -> AuditHead {
        AuditHead {
            header: test_header("AuditHead"),
            zone_id: test_zone(),
            head_event,
            head_seq,
            coverage: 1.0,
            epoch_id: test_epoch(),
            quorum_signatures: create_quorum_signature_set(sig_count),
        }
    }

    fn create_zone_checkpoint(
        rev_head: ObjectId,
        rev_seq: u64,
        audit_head: ObjectId,
        audit_seq: u64,
        checkpoint_seq: u64,
        sig_count: u8,
    ) -> ZoneCheckpoint {
        ZoneCheckpoint {
            header: test_header("ZoneCheckpoint"),
            zone_id: test_zone(),
            rev_head,
            rev_seq,
            audit_head,
            audit_seq,
            zone_definition_head: test_object_id("zone-def-head"),
            zone_policy_head: test_object_id("zone-policy-head"),
            active_zone_key_manifest: test_object_id("active-zkm"),
            checkpoint_seq,
            as_of_epoch: test_epoch(),
            quorum_signatures: create_quorum_signature_set(sig_count),
            revocation_freshness_sla_secs: default_revocation_sla(),
        }
    }

    fn create_decision_receipt(
        request_id: ObjectId,
        decision: Decision,
        reason_code: &str,
        evidence: Vec<ObjectId>,
    ) -> DecisionReceipt {
        DecisionReceipt {
            header: test_header("DecisionReceipt"),
            request_object_id: request_id,
            decision,
            reason_code: reason_code.to_string(),
            evidence,
            explanation: Some("Test explanation".to_string()),
            signature: test_signature(),
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // AuditEvent Chain Tests (Hash Linking, Monotonic Seq)
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn audit_event_follows_prev_and_seq() {
        let prev_id = ObjectId::test_id("audit-event-1");
        let event1 = create_audit_event(1, None, EVENT_CAPABILITY_INVOKE);
        let event2 = AuditEvent {
            prev: Some(prev_id),
            seq: 2,
            ..create_audit_event(2, None, EVENT_CAPABILITY_INVOKE)
        };

        assert!(event2.follows(&event1, &prev_id));
    }

    #[test]
    fn audit_event_follows_rejects_wrong_seq() {
        let prev_id = test_object_id("audit-event-1");
        let event1 = create_audit_event(1, None, EVENT_CAPABILITY_INVOKE);

        // seq gap (should be 2, but is 3)
        let event_wrong_seq = AuditEvent {
            prev: Some(prev_id),
            seq: 3,
            ..create_audit_event(3, None, EVENT_CAPABILITY_INVOKE)
        };
        assert!(!event_wrong_seq.follows(&event1, &prev_id));

        // seq going backwards
        let event_backwards = AuditEvent {
            prev: Some(prev_id),
            seq: 0,
            ..create_audit_event(0, None, EVENT_CAPABILITY_INVOKE)
        };
        assert!(!event_backwards.follows(&event1, &prev_id));
    }

    #[test]
    fn audit_event_follows_rejects_wrong_prev() {
        let event1 = create_audit_event(1, None, EVENT_CAPABILITY_INVOKE);
        let wrong_prev_id = test_object_id("wrong-event-id");
        let correct_prev_id = test_object_id("correct-event-id");

        let event2 = AuditEvent {
            prev: Some(wrong_prev_id),
            seq: 2,
            ..create_audit_event(2, None, EVENT_CAPABILITY_INVOKE)
        };

        // prev points to wrong id
        assert!(!event2.follows(&event1, &correct_prev_id));
    }

    #[test]
    fn audit_event_follows_rejects_missing_prev() {
        let prev_id = test_object_id("audit-event-1");
        let event1 = create_audit_event(1, None, EVENT_CAPABILITY_INVOKE);

        // event2 has no prev link
        let event2 = create_audit_event(2, None, EVENT_CAPABILITY_INVOKE);

        assert!(!event2.follows(&event1, &prev_id));
    }

    #[test]
    fn audit_event_chain_validation() {
        // Build a chain of 5 events
        let mut chain = Vec::new();
        let mut prev_id: Option<ObjectId> = None;

        for seq in 1..=5 {
            let event = create_audit_event(seq, prev_id, EVENT_CAPABILITY_INVOKE);
            prev_id = Some(test_object_id(&format!("event-{seq}")));
            chain.push((event, prev_id));
        }

        // Validate chain integrity
        for i in 1..chain.len() {
            let (prev_event, prev_object_id) = &chain[i - 1];
            let (current_event, _) = &chain[i];

            // Each event should follow its predecessor
            assert!(
                current_event.follows(prev_event, prev_object_id.as_ref().unwrap()),
                "Event {} should follow event {}",
                i + 1,
                i
            );
        }
    }

    #[test]
    fn audit_event_seq_overflow_handling() {
        // Test with seq near u64::MAX - construct events directly to avoid
        // overflow in test helper's occurred_at calculation
        let max_seq = u64::MAX - 1;
        let event1 = AuditEvent {
            header: test_header("AuditEvent"),
            correlation_id: CorrelationId(Uuid::from_bytes([1; 16])),
            trace_context: None,
            event_type: EVENT_CAPABILITY_INVOKE.to_string(),
            actor: test_actor(),
            zone_id: test_zone(),
            connector_id: None,
            operation: None,
            capability_token_jti: None,
            request_object_id: None,
            result_object_id: None,
            prev: None,
            seq: max_seq,
            occurred_at: 1_700_000_000,
            signature: test_signature(),
        };
        let prev_id = test_object_id("max-event");

        let event2 = AuditEvent {
            header: test_header("AuditEvent"),
            correlation_id: CorrelationId(Uuid::from_bytes([2; 16])),
            trace_context: None,
            event_type: EVENT_CAPABILITY_INVOKE.to_string(),
            actor: test_actor(),
            zone_id: test_zone(),
            connector_id: None,
            operation: None,
            capability_token_jti: None,
            request_object_id: None,
            result_object_id: None,
            prev: Some(prev_id),
            seq: u64::MAX,
            occurred_at: 1_700_000_001,
            signature: test_signature(),
        };

        assert!(event2.follows(&event1, &prev_id));

        // But u64::MAX + 1 would overflow - follows() uses checked_add to prevent this
        let prev_id2 = test_object_id("overflow-event");
        let event3 = AuditEvent {
            header: test_header("AuditEvent"),
            correlation_id: CorrelationId(Uuid::from_bytes([3; 16])),
            trace_context: None,
            event_type: EVENT_CAPABILITY_INVOKE.to_string(),
            actor: test_actor(),
            zone_id: test_zone(),
            connector_id: None,
            operation: None,
            capability_token_jti: None,
            request_object_id: None,
            result_object_id: None,
            prev: Some(prev_id2),
            seq: 0, // Would be u64::MAX + 1, wrapped to 0
            occurred_at: 1_700_000_002,
            signature: test_signature(),
        };

        // This should NOT follow event2 because checked_add(1) on u64::MAX is None
        assert!(!event3.follows(&event2, &prev_id2));
    }

    #[test]
    fn audit_event_zone_binding() {
        let event = create_audit_event(1, None, EVENT_CAPABILITY_INVOKE);
        assert_eq!(event.zone_id().as_str(), "z:work");

        // Zone in header should match zone_id field
        assert_eq!(event.header.zone_id.as_str(), event.zone_id.as_str());
    }

    #[test]
    fn audit_event_types_discriminated() {
        let types = [
            EVENT_SECRET_ACCESS,
            EVENT_CAPABILITY_INVOKE,
            EVENT_ELEVATION_GRANTED,
            EVENT_DECLASSIFICATION_GRANTED,
            EVENT_ZONE_TRANSITION,
            EVENT_REVOCATION_ISSUED,
            EVENT_SECURITY_VIOLATION,
            EVENT_AUDIT_FORK_DETECTED,
        ];

        for event_type in types {
            let event = create_audit_event(1, None, event_type);
            assert_eq!(event.event_type, event_type);

            // Verify JSON serialization preserves type
            let json = serde_json::to_string(&event).unwrap();
            assert!(json.contains(event_type));
        }
    }

    #[test]
    fn audit_event_genesis_has_no_prev() {
        let genesis = create_audit_event(0, None, EVENT_CAPABILITY_INVOKE);
        assert!(genesis.prev.is_none());
        assert_eq!(genesis.seq, 0);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // AuditHead Tests (Quorum Signatures)
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn audit_head_quorum_signatures_required() {
        let head_event = test_object_id("audit-event-100");
        let policy = QuorumPolicy::new(test_zone(), 5, 1);

        // 3 signatures - need 4 (n-f = 5-1) for CriticalWrite
        let head_insufficient = create_audit_head(head_event, 100, 3);
        assert!(
            !head_insufficient
                .quorum_signatures
                .satisfies_quorum(&policy, RiskTier::CriticalWrite)
        );

        // 4 signatures - meets quorum
        let head_sufficient = create_audit_head(head_event, 100, 4);
        assert!(
            head_sufficient
                .quorum_signatures
                .satisfies_quorum(&policy, RiskTier::CriticalWrite)
        );
    }

    #[test]
    fn audit_head_rejects_insufficient_signatures() {
        let head_event = test_object_id("audit-event-50");
        let policy = QuorumPolicy::new(test_zone(), 7, 2);

        // Need 5 signatures (7-2) for CriticalWrite
        for sig_count in 0..5 {
            let head = create_audit_head(head_event, 50, sig_count);
            assert!(
                !head
                    .quorum_signatures
                    .satisfies_quorum(&policy, RiskTier::CriticalWrite),
                "Should reject {sig_count} signatures when 5 required"
            );
        }

        // 5 signatures should pass
        let head = create_audit_head(head_event, 50, 5);
        assert!(
            head.quorum_signatures
                .satisfies_quorum(&policy, RiskTier::CriticalWrite)
        );
    }

    #[test]
    fn audit_head_signature_set_canonicalized() {
        let head_event = test_object_id("audit-event-10");
        let head = create_audit_head(head_event, 10, 3);

        // Signatures should be sorted by node_id
        let sigs: Vec<_> = head
            .quorum_signatures
            .iter()
            .map(|s| s.node_id.as_str())
            .collect();
        let mut sorted_sigs = sigs.clone();
        sorted_sigs.sort_unstable();
        assert_eq!(sigs, sorted_sigs);
    }

    #[test]
    fn audit_head_references_chain_tip() {
        let tip_event_id = test_object_id("chain-tip-event");
        let tip_seq = 42;
        let head = create_audit_head(tip_event_id, tip_seq, 3);

        assert_eq!(head.head_event, tip_event_id);
        assert_eq!(head.head_seq, tip_seq);
    }

    #[test]
    fn audit_head_zone_binding() {
        let head = create_audit_head(test_object_id("event"), 1, 3);
        assert_eq!(head.zone_id().as_str(), "z:work");
    }

    #[test]
    fn audit_head_coverage_tracking() {
        let head = create_audit_head(test_object_id("event"), 1, 3);
        assert!((head.coverage - 1.0).abs() < f64::EPSILON);

        // Partial coverage
        let partial_head = AuditHead {
            coverage: 0.6,
            ..create_audit_head(test_object_id("event"), 1, 3)
        };
        assert!((partial_head.coverage - 0.6).abs() < f64::EPSILON);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ZoneCheckpoint Tests (Head Bindings, Monotonic Seq)
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn zone_checkpoint_binds_audit_head() {
        let audit_head_id = test_object_id("audit-head-100");
        let checkpoint = create_zone_checkpoint(
            test_object_id("rev-head"),
            50,
            audit_head_id,
            100,
            1, // checkpoint_seq
            4,
        );

        assert_eq!(checkpoint.audit_head, audit_head_id);
        assert_eq!(checkpoint.audit_seq, 100);
    }

    #[test]
    fn zone_checkpoint_binds_revocation_head() {
        let rev_head_id = test_object_id("rev-head-50");
        let checkpoint =
            create_zone_checkpoint(rev_head_id, 50, test_object_id("audit-head"), 100, 1, 4);

        assert_eq!(checkpoint.rev_head, rev_head_id);
        assert_eq!(checkpoint.rev_seq, 50);
    }

    #[test]
    fn zone_checkpoint_binds_policy_heads() {
        let checkpoint = create_zone_checkpoint(
            test_object_id("rev-head"),
            50,
            test_object_id("audit-head"),
            100,
            1,
            4,
        );

        // Verify all policy heads are bound
        assert_eq!(
            checkpoint.zone_definition_head,
            test_object_id("zone-def-head")
        );
        assert_eq!(
            checkpoint.zone_policy_head,
            test_object_id("zone-policy-head")
        );
        assert_eq!(
            checkpoint.active_zone_key_manifest,
            test_object_id("active-zkm")
        );
    }

    #[test]
    fn zone_checkpoint_seq_is_monotonic() {
        let checkpoint1 = create_zone_checkpoint(
            test_object_id("rev-1"),
            10,
            test_object_id("audit-1"),
            20,
            1, // checkpoint_seq
            4,
        );

        let checkpoint2 = create_zone_checkpoint(
            test_object_id("rev-2"),
            15,
            test_object_id("audit-2"),
            30,
            2, // checkpoint_seq
            4,
        );

        assert!(checkpoint2.checkpoint_seq > checkpoint1.checkpoint_seq);
    }

    #[test]
    fn zone_checkpoint_quorum_signatures_required() {
        let policy = QuorumPolicy::new(test_zone(), 5, 1);

        // Insufficient signatures
        let checkpoint_insufficient = create_zone_checkpoint(
            test_object_id("rev"),
            10,
            test_object_id("audit"),
            20,
            1,
            3, // 3 < 4 required
        );
        assert!(
            !checkpoint_insufficient
                .quorum_signatures
                .satisfies_quorum(&policy, RiskTier::CriticalWrite)
        );

        // Sufficient signatures
        let checkpoint_sufficient = create_zone_checkpoint(
            test_object_id("rev"),
            10,
            test_object_id("audit"),
            20,
            1,
            4, // 4 >= 4 required
        );
        assert!(
            checkpoint_sufficient
                .quorum_signatures
                .satisfies_quorum(&policy, RiskTier::CriticalWrite)
        );
    }

    #[test]
    fn zone_checkpoint_zone_binding() {
        let checkpoint =
            create_zone_checkpoint(test_object_id("rev"), 10, test_object_id("audit"), 20, 1, 4);
        assert_eq!(checkpoint.zone_id().as_str(), "z:work");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // DecisionReceipt Tests (Content-Addressed, Reason Codes, Evidence)
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn decision_receipt_content_addressed() {
        let request_id = test_object_id("invoke-request");
        let evidence = vec![test_object_id("cap-token"), test_object_id("provenance")];

        let receipt1 =
            create_decision_receipt(request_id, Decision::Deny, "FCP-4010", evidence.clone());

        let receipt2 = create_decision_receipt(request_id, Decision::Deny, "FCP-4010", evidence);

        // Same inputs should produce same serialization
        let json1 = serde_json::to_string(&receipt1).unwrap();
        let json2 = serde_json::to_string(&receipt2).unwrap();
        assert_eq!(json1, json2);
    }

    #[test]
    fn decision_receipt_reason_code_stable() {
        let receipt = create_decision_receipt(
            test_object_id("request"),
            Decision::Deny,
            "FCP-4010",
            vec![],
        );

        assert_eq!(receipt.reason_code, "FCP-4010");

        // Verify reason code survives serialization
        let json = serde_json::to_string(&receipt).unwrap();
        let deserialized: DecisionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.reason_code, "FCP-4010");
    }

    #[test]
    fn decision_receipt_evidence_object_ids() {
        let evidence = vec![
            test_object_id("cap-token-jti"),
            test_object_id("request-object"),
            test_object_id("revocation-head"),
        ];

        let receipt = create_decision_receipt(
            test_object_id("request"),
            Decision::Deny,
            "FCP-4030",
            evidence.clone(),
        );

        assert_eq!(receipt.evidence.len(), 3);
        assert_eq!(receipt.evidence, evidence);
    }

    #[test]
    fn decision_receipt_is_allow_deny() {
        let allow_receipt = create_decision_receipt(
            test_object_id("request"),
            Decision::Allow,
            "FCP-0000",
            vec![],
        );

        let deny_receipt = create_decision_receipt(
            test_object_id("request"),
            Decision::Deny,
            "FCP-4010",
            vec![],
        );

        assert!(allow_receipt.is_allow());
        assert!(!allow_receipt.is_deny());
        assert!(!deny_receipt.is_allow());
        assert!(deny_receipt.is_deny());
    }

    #[test]
    fn decision_receipt_zone_from_header() {
        let receipt = create_decision_receipt(
            test_object_id("request"),
            Decision::Allow,
            "FCP-0000",
            vec![],
        );

        assert_eq!(receipt.zone_id().as_str(), "z:work");
    }

    #[test]
    fn decision_serializes_as_lowercase() {
        let allow_json = serde_json::to_string(&Decision::Allow).unwrap();
        let deny_json = serde_json::to_string(&Decision::Deny).unwrap();
        assert_eq!(allow_json, "\"allow\"");
        assert_eq!(deny_json, "\"deny\"");
    }

    #[test]
    fn decision_receipt_with_explanation() {
        let receipt = DecisionReceipt {
            explanation: Some("Capability token expired at 1700000000".to_string()),
            ..create_decision_receipt(
                test_object_id("request"),
                Decision::Deny,
                "FCP-4020",
                vec![test_object_id("expired-cap")],
            )
        };

        assert!(receipt.explanation.is_some());
        assert!(receipt.explanation.unwrap().contains("expired"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Fork Detection Tests
    // ─────────────────────────────────────────────────────────────────────────

    /// Helper: Simulates fork detection by comparing two events at same seq
    fn is_fork_detected(event_a: &AuditEvent, event_b: &AuditEvent) -> bool {
        // Fork if same seq but different content (would have different ObjectIds)
        event_a.seq == event_b.seq && {
            // Compare by correlation_id as proxy for content difference
            event_a.correlation_id.0 != event_b.correlation_id.0
        }
    }

    #[test]
    fn fork_detection_same_seq_different_id() {
        let event_a = create_audit_event(10, None, EVENT_CAPABILITY_INVOKE);

        // Create divergent event at same seq
        let event_b = AuditEvent {
            correlation_id: CorrelationId(Uuid::from_bytes([0xFF; 16])),
            ..create_audit_event(10, None, EVENT_SECRET_ACCESS)
        };

        assert!(is_fork_detected(&event_a, &event_b));
    }

    #[test]
    fn fork_detection_different_seq_no_fork() {
        let event_a = create_audit_event(10, None, EVENT_CAPABILITY_INVOKE);
        let event_b = create_audit_event(11, None, EVENT_SECRET_ACCESS);

        assert!(!is_fork_detected(&event_a, &event_b));
    }

    #[test]
    fn fork_detection_emits_audit_event() {
        // When fork is detected, an audit event of type EVENT_AUDIT_FORK_DETECTED should be emitted
        let fork_event = create_audit_event(100, None, EVENT_AUDIT_FORK_DETECTED);
        assert_eq!(fork_event.event_type, EVENT_AUDIT_FORK_DETECTED);
    }

    /// Simulates checkpoint advancement halting on fork
    fn can_advance_checkpoint(
        current_checkpoint_seq: u64,
        proposed_audit_seq: u64,
        fork_detected: bool,
    ) -> bool {
        // Cannot advance if fork detected
        if fork_detected {
            return false;
        }
        // Normal advancement: proposed seq must be greater than current
        proposed_audit_seq > current_checkpoint_seq
    }

    #[test]
    fn fork_halts_checkpoint_advancement() {
        let current_seq = 50;
        let proposed_seq = 60;

        // Normal case: can advance
        assert!(can_advance_checkpoint(current_seq, proposed_seq, false));

        // Fork detected: cannot advance
        assert!(!can_advance_checkpoint(current_seq, proposed_seq, true));
    }

    #[test]
    fn fork_requires_manual_intervention() {
        // A fork should produce a DecisionReceipt that indicates manual intervention needed
        let fork_receipt = create_decision_receipt(
            test_object_id("fork-detection-request"),
            Decision::Deny,
            "FCP-5010", // Fork detected reason code
            vec![
                test_object_id("conflicting-event-a"),
                test_object_id("conflicting-event-b"),
            ],
        );

        assert!(fork_receipt.is_deny());
        assert_eq!(fork_receipt.evidence.len(), 2);
        assert_eq!(fork_receipt.reason_code, "FCP-5010");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // TraceContext Propagation Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn trace_context_trace_id_preserved() {
        let trace_id = [0xAB; 16];
        let span_id = [0xCD; 8];
        let trace = TraceContext {
            trace_id,
            span_id,
            flags: 0x01,
        };

        let event = create_audit_event_with_trace(1, None, Some(trace));

        let ctx = event.trace_context.as_ref().unwrap();
        assert_eq!(ctx.trace_id, trace_id);
    }

    #[test]
    fn trace_context_span_id_propagated() {
        let trace_id = [0x11; 16];
        let span_id = [0x22; 8];
        let trace = TraceContext {
            trace_id,
            span_id,
            flags: 0x00,
        };

        let event = create_audit_event_with_trace(1, None, Some(trace));

        let ctx = event.trace_context.as_ref().unwrap();
        assert_eq!(ctx.span_id, span_id);
    }

    #[test]
    fn trace_context_optional() {
        let event = create_audit_event_with_trace(1, None, None);
        assert!(event.trace_context.is_none());

        // JSON should omit trace_context when None
        let json = serde_json::to_string(&event).unwrap();
        assert!(!json.contains("trace_context"));
    }

    #[test]
    fn trace_context_flags_preserved() {
        let trace = TraceContext {
            trace_id: [0x00; 16],
            span_id: [0x00; 8],
            flags: 0x01, // Sampled flag
        };

        let event = create_audit_event_with_trace(1, None, Some(trace));
        assert_eq!(event.trace_context.as_ref().unwrap().flags, 0x01);
    }

    #[test]
    fn trace_context_serialization_roundtrip() {
        let trace = TraceContext {
            trace_id: [
                0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
                0xAA, 0xBB,
            ],
            span_id: [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0],
            flags: 0x01,
        };

        let json = serde_json::to_string(&trace).unwrap();
        let deserialized: TraceContext = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.trace_id, trace.trace_id);
        assert_eq!(deserialized.span_id, trace.span_id);
        assert_eq!(deserialized.flags, trace.flags);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // W3C Trace Context Cross-Component Contract (br21t.3.7)
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn trace_context_invoke_to_audit_contract() {
        // Proves: trace_id from InvokeRequest.context flows into AuditEvent.trace_context
        let trace_id = [
            0x0A, 0xF7, 0x65, 0x19, 0x16, 0xCD, 0x43, 0xDD, 0x84, 0x48, 0xEB, 0x21, 0x1C, 0x80,
            0x31, 0x9C,
        ];
        let span_id = [0xB7, 0xAD, 0x6B, 0x71, 0x69, 0x20, 0x33, 0x31];

        let trace = TraceContext {
            trace_id,
            span_id,
            flags: 0x01, // sampled
        };

        // Simulate: InvokeRequest carries trace_id as W3C hex string
        let invoke_trace_id = hex::encode(trace_id); // "0af7651916cd43dd8448eb211c80319c"
        assert_eq!(
            invoke_trace_id.len(),
            32,
            "W3C trace_id must be 32 hex chars"
        );

        // Simulate: AuditEvent records the binary trace context
        let event = create_audit_event_with_trace(42, None, Some(trace));
        let ctx = event.trace_context.as_ref().unwrap();

        // Contract: binary trace_id matches the hex string from InvokeRequest
        assert_eq!(hex::encode(ctx.trace_id), invoke_trace_id);
        assert_eq!(ctx.span_id, span_id);
        assert_eq!(ctx.flags, 0x01);

        // Contract: JSON serialization preserves trace_context
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("trace_context"));
        let roundtrip: AuditEvent = serde_json::from_str(&json).unwrap();
        let rt_ctx = roundtrip.trace_context.as_ref().unwrap();
        assert_eq!(rt_ctx.trace_id, trace_id);
        assert_eq!(rt_ctx.span_id, span_id);
    }

    #[test]
    fn trace_context_child_span_preserves_trace_id() {
        // Contract: child spans share the same trace_id but have different span_ids
        let trace_id = [0xAA; 16];
        let parent_span = [0x11; 8];
        let child_span = [0x22; 8];

        let parent = TraceContext {
            trace_id,
            span_id: parent_span,
            flags: 0x01,
        };
        let child = TraceContext {
            trace_id,
            span_id: child_span,
            flags: 0x01,
        };

        // Same trace_id across spans
        assert_eq!(parent.trace_id, child.trace_id);
        // Different span_ids
        assert_ne!(parent.span_id, child.span_id);

        // Both produce valid audit events linked via prev hash
        let parent_event = create_audit_event_with_trace(1, None, Some(parent));
        let prev_id = test_object_id("parent-link");
        let child_event = create_audit_event_with_trace(2, Some(prev_id), Some(child));

        let p_ctx = parent_event.trace_context.as_ref().unwrap();
        let c_ctx = child_event.trace_context.as_ref().unwrap();
        assert_eq!(p_ctx.trace_id, c_ctx.trace_id, "trace_id must be shared");
        assert_ne!(
            p_ctx.span_id, c_ctx.span_id,
            "span_ids must differ between parent and child"
        );
    }

    #[test]
    fn trace_context_correlation_id_independent() {
        // Contract: correlation_id and trace_context are independent fields
        let trace = TraceContext {
            trace_id: [0xFF; 16],
            span_id: [0xEE; 8],
            flags: 0x01,
        };
        let event = create_audit_event_with_trace(99, None, Some(trace));

        // correlation_id is derived from seq (test fixture), NOT from trace_id
        assert_ne!(
            event.correlation_id.0.as_bytes(),
            &event.trace_context.as_ref().unwrap().trace_id,
            "correlation_id and trace_id should be independent"
        );

        // Both are present in JSON
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("correlation_id"));
        assert!(json.contains("trace_context"));
    }

    #[test]
    fn trace_context_audit_chain_carries_trace_through_linked_events() {
        // Contract: hash-linked audit chain preserves trace context per event
        let trace_id = [0xBB; 16];

        let link1 = test_object_id("chain-link-1");
        let link2 = test_object_id("chain-link-2");

        let event1 = create_audit_event_with_trace(
            1,
            None,
            Some(TraceContext {
                trace_id,
                span_id: [0x01; 8],
                flags: 0x01,
            }),
        );
        let event2 = create_audit_event_with_trace(
            2,
            Some(link1),
            Some(TraceContext {
                trace_id,
                span_id: [0x02; 8],
                flags: 0x01,
            }),
        );
        let event3 = create_audit_event_with_trace(
            3,
            Some(link2),
            Some(TraceContext {
                trace_id,
                span_id: [0x03; 8],
                flags: 0x01,
            }),
        );

        // All events share the same trace_id
        for event in [&event1, &event2, &event3] {
            assert_eq!(
                event.trace_context.as_ref().unwrap().trace_id,
                trace_id,
                "all events in chain should share trace_id"
            );
        }

        // Hash links form a chain
        assert!(event1.prev.is_none());
        assert_eq!(event2.prev, Some(link1));
        assert_eq!(event3.prev, Some(link2));

        // Monotonic seq
        assert!(event1.seq < event2.seq);
        assert!(event2.seq < event3.seq);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden Vector Tests (Deterministic Serialization)
    // ─────────────────────────────────────────────────────────────────────────

    fn audit_event_schema() -> SchemaId {
        SchemaId::new("fcp.core", "AuditEvent", Version::new(1, 0, 0))
    }

    fn audit_head_schema() -> SchemaId {
        SchemaId::new("fcp.core", "AuditHead", Version::new(1, 0, 0))
    }

    fn zone_checkpoint_schema() -> SchemaId {
        SchemaId::new("fcp.core", "ZoneCheckpoint", Version::new(1, 0, 0))
    }

    fn decision_receipt_schema() -> SchemaId {
        SchemaId::new("fcp.core", "DecisionReceipt", Version::new(1, 0, 0))
    }

    #[test]
    fn golden_audit_event_deterministic() {
        let event = create_audit_event(1, None, EVENT_CAPABILITY_INVOKE);

        let schema = audit_event_schema();
        let bytes1 = fcp_cbor::CanonicalSerializer::serialize(&event, &schema).unwrap();
        let bytes2 = fcp_cbor::CanonicalSerializer::serialize(&event, &schema).unwrap();

        assert_eq!(
            bytes1, bytes2,
            "AuditEvent serialization must be deterministic"
        );
    }

    #[test]
    fn golden_audit_head_deterministic() {
        let head = create_audit_head(test_object_id("event-100"), 100, 3);

        let schema = audit_head_schema();
        let bytes1 = fcp_cbor::CanonicalSerializer::serialize(&head, &schema).unwrap();
        let bytes2 = fcp_cbor::CanonicalSerializer::serialize(&head, &schema).unwrap();

        assert_eq!(
            bytes1, bytes2,
            "AuditHead serialization must be deterministic"
        );
    }

    #[test]
    fn golden_zone_checkpoint_deterministic() {
        let checkpoint =
            create_zone_checkpoint(test_object_id("rev"), 10, test_object_id("audit"), 20, 1, 4);

        let schema = zone_checkpoint_schema();
        let bytes1 = fcp_cbor::CanonicalSerializer::serialize(&checkpoint, &schema).unwrap();
        let bytes2 = fcp_cbor::CanonicalSerializer::serialize(&checkpoint, &schema).unwrap();

        assert_eq!(
            bytes1, bytes2,
            "ZoneCheckpoint serialization must be deterministic"
        );
    }

    #[test]
    fn golden_decision_receipt_deterministic() {
        let receipt = create_decision_receipt(
            test_object_id("request"),
            Decision::Deny,
            "FCP-4010",
            vec![test_object_id("cap"), test_object_id("rev")],
        );

        let schema = decision_receipt_schema();
        let bytes1 = fcp_cbor::CanonicalSerializer::serialize(&receipt, &schema).unwrap();
        let bytes2 = fcp_cbor::CanonicalSerializer::serialize(&receipt, &schema).unwrap();

        assert_eq!(
            bytes1, bytes2,
            "DecisionReceipt serialization must be deterministic"
        );
    }

    #[test]
    fn golden_audit_event_roundtrip() {
        let event = create_audit_event(42, Some(test_object_id("prev")), EVENT_SECRET_ACCESS);

        let schema = audit_event_schema();
        let bytes = fcp_cbor::CanonicalSerializer::serialize(&event, &schema).unwrap();
        let decoded: AuditEvent =
            fcp_cbor::CanonicalSerializer::deserialize(&bytes, &schema).unwrap();

        assert_eq!(decoded.seq, event.seq);
        assert_eq!(decoded.event_type, event.event_type);
        assert_eq!(decoded.prev, event.prev);
    }

    #[test]
    fn golden_decision_receipt_roundtrip() {
        let receipt = create_decision_receipt(
            test_object_id("request"),
            Decision::Allow,
            "FCP-0000",
            vec![test_object_id("cap")],
        );

        let schema = decision_receipt_schema();
        let bytes = fcp_cbor::CanonicalSerializer::serialize(&receipt, &schema).unwrap();
        let decoded: DecisionReceipt =
            fcp_cbor::CanonicalSerializer::deserialize(&bytes, &schema).unwrap();

        assert_eq!(decoded.decision, Decision::Allow);
        assert_eq!(decoded.reason_code, "FCP-0000");
        assert_eq!(decoded.evidence.len(), 1);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Event Type Constants Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn event_type_constants_stable() {
        // These are NORMATIVE and must not change
        assert_eq!(EVENT_SECRET_ACCESS, "secret.access");
        assert_eq!(EVENT_CAPABILITY_INVOKE, "capability.invoke");
        assert_eq!(EVENT_ELEVATION_GRANTED, "elevation.granted");
        assert_eq!(EVENT_DECLASSIFICATION_GRANTED, "declassification.granted");
        assert_eq!(EVENT_ZONE_TRANSITION, "zone.transition");
        assert_eq!(EVENT_REVOCATION_ISSUED, "revocation.issued");
        assert_eq!(EVENT_SECURITY_VIOLATION, "security.violation");
        assert_eq!(EVENT_AUDIT_FORK_DETECTED, "audit.fork_detected");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Comprehensive Serialization Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn audit_event_json_serialization() {
        let trace = TraceContext {
            trace_id: [0x11; 16],
            span_id: [0x22; 8],
            flags: 0x01,
        };

        let event = AuditEvent {
            trace_context: Some(trace),
            connector_id: Some(ConnectorId::from_static("fcp.telegram:base:v1")),
            operation: Some(OperationId::from_static("op-123")),
            capability_token_jti: Some(Uuid::from_bytes([0xAA; 16])),
            request_object_id: Some(test_object_id("request")),
            result_object_id: Some(test_object_id("result")),
            ..create_audit_event(5, Some(test_object_id("prev")), EVENT_CAPABILITY_INVOKE)
        };

        let json = serde_json::to_string_pretty(&event).unwrap();

        // Verify key fields are present
        assert!(
            json.contains("event_type") && json.contains("capability.invoke"),
            "event_type not found in JSON: {json}"
        );
        assert!(json.contains("\"seq\""), "seq not found in JSON");
        assert!(json.contains("trace_context"), "trace_context not found");
        assert!(json.contains("connector_id"), "connector_id not found");
        assert!(json.contains("operation"), "operation not found");
        assert!(
            json.contains("capability_token_jti"),
            "capability_token_jti not found"
        );
    }

    #[test]
    fn audit_head_json_serialization() {
        let head = create_audit_head(test_object_id("event"), 100, 3);
        let json = serde_json::to_string_pretty(&head).unwrap();

        assert!(
            json.contains("head_seq"),
            "head_seq not found in JSON: {json}"
        );
        assert!(
            json.contains("quorum_signatures"),
            "quorum_signatures not found"
        );
        assert!(json.contains("coverage"), "coverage not found");
    }

    #[test]
    fn zone_checkpoint_json_serialization() {
        let checkpoint = create_zone_checkpoint(
            test_object_id("rev"),
            50,
            test_object_id("audit"),
            100,
            5,
            4,
        );

        let json = serde_json::to_string_pretty(&checkpoint).unwrap();

        assert!(
            json.contains("rev_seq"),
            "rev_seq not found in JSON: {json}"
        );
        assert!(
            json.contains("audit_seq"),
            "audit_seq not found in JSON: {json}"
        );
        assert!(
            json.contains("checkpoint_seq"),
            "checkpoint_seq not found in JSON: {json}"
        );
        assert!(
            json.contains("zone_definition_head"),
            "zone_definition_head not found"
        );
        assert!(
            json.contains("zone_policy_head"),
            "zone_policy_head not found"
        );
        assert!(
            json.contains("active_zone_key_manifest"),
            "active_zone_key_manifest not found"
        );
    }

    #[test]
    fn decision_receipt_json_serialization() {
        let receipt = create_decision_receipt(
            test_object_id("request"),
            Decision::Deny,
            "FCP-4010",
            vec![test_object_id("evidence-1"), test_object_id("evidence-2")],
        );

        let json = serde_json::to_string_pretty(&receipt).unwrap();

        assert!(
            json.contains("decision") && json.contains("deny"),
            "decision deny not found in JSON: {json}"
        );
        assert!(
            json.contains("reason_code") && json.contains("FCP-4010"),
            "reason_code not found in JSON: {json}"
        );
        assert!(json.contains("evidence"), "evidence not found in JSON");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Edge Cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn audit_event_with_all_optional_fields() {
        let event = AuditEvent {
            header: test_header("AuditEvent"),
            correlation_id: CorrelationId(Uuid::from_bytes([1; 16])),
            trace_context: Some(TraceContext {
                trace_id: [0xFF; 16],
                span_id: [0xEE; 8],
                flags: 0x01,
            }),
            event_type: EVENT_CAPABILITY_INVOKE.to_string(),
            actor: test_actor(),
            zone_id: test_zone(),
            connector_id: Some(ConnectorId::from_static("fcp.test:base:v1")),
            operation: Some(OperationId::from_static("op-test")),
            capability_token_jti: Some(Uuid::from_bytes([0xDD; 16])),
            request_object_id: Some(test_object_id("req")),
            result_object_id: Some(test_object_id("res")),
            prev: Some(test_object_id("prev")),
            seq: 1,
            occurred_at: 1_700_000_000,
            signature: test_signature(),
        };

        // Should serialize/deserialize without error
        let json = serde_json::to_string(&event).unwrap();
        let decoded: AuditEvent = serde_json::from_str(&json).unwrap();

        assert!(decoded.trace_context.is_some());
        assert!(decoded.connector_id.is_some());
        assert!(decoded.operation.is_some());
        assert!(decoded.capability_token_jti.is_some());
        assert!(decoded.request_object_id.is_some());
        assert!(decoded.result_object_id.is_some());
        assert!(decoded.prev.is_some());
    }

    #[test]
    fn audit_event_with_no_optional_fields() {
        let event = AuditEvent {
            header: test_header("AuditEvent"),
            correlation_id: CorrelationId(Uuid::from_bytes([1; 16])),
            trace_context: None,
            event_type: EVENT_SECRET_ACCESS.to_string(),
            actor: test_actor(),
            zone_id: test_zone(),
            connector_id: None,
            operation: None,
            capability_token_jti: None,
            request_object_id: None,
            result_object_id: None,
            prev: None,
            seq: 0,
            occurred_at: 1_700_000_000,
            signature: test_signature(),
        };

        let json = serde_json::to_string(&event).unwrap();

        // Optional fields should be omitted
        assert!(!json.contains("trace_context"));
        assert!(!json.contains("connector_id"));
        assert!(!json.contains("operation"));
        assert!(!json.contains("capability_token_jti"));
        assert!(!json.contains("request_object_id"));
        assert!(!json.contains("result_object_id"));
        assert!(!json.contains("\"prev\""));
    }

    #[test]
    fn decision_receipt_without_explanation() {
        let receipt = DecisionReceipt {
            header: test_header("DecisionReceipt"),
            request_object_id: test_object_id("request"),
            decision: Decision::Allow,
            reason_code: "FCP-0000".to_string(),
            evidence: vec![],
            explanation: None,
            signature: test_signature(),
        };

        let json = serde_json::to_string(&receipt).unwrap();
        assert!(!json.contains("explanation"));
    }

    #[test]
    fn decision_receipt_empty_evidence() {
        let receipt = create_decision_receipt(
            test_object_id("request"),
            Decision::Allow,
            "FCP-0000",
            vec![],
        );

        assert!(receipt.evidence.is_empty());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Logging Requirements Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn audit_event_has_required_log_fields() {
        let event = create_audit_event(42, Some(test_object_id("prev")), EVENT_CAPABILITY_INVOKE);

        // Required fields per spec
        assert!(!event.event_type.is_empty());
        assert!(event.seq > 0 || event.prev.is_none()); // Genesis can have seq=0
        assert!(event.occurred_at > 0);
        assert_eq!(event.correlation_id.0.as_bytes().len(), 16);
    }

    #[test]
    fn decision_receipt_has_required_log_fields() {
        let receipt = create_decision_receipt(
            test_object_id("request"),
            Decision::Deny,
            "FCP-4010",
            vec![test_object_id("cap")],
        );

        // Required fields per spec
        assert!(!receipt.reason_code.is_empty());
        assert!(!receipt.evidence.is_empty() || receipt.is_allow());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Decision trait coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn decision_copy() {
        let d = Decision::Allow;
        let copied = d;
        assert_eq!(d, copied);
    }

    #[test]
    fn decision_inequality() {
        assert_ne!(Decision::Allow, Decision::Deny);
    }

    #[test]
    fn decision_serde_allow() {
        let json = serde_json::to_string(&Decision::Allow).unwrap();
        assert_eq!(json, "\"allow\"");
        let back: Decision = serde_json::from_str(&json).unwrap();
        assert_eq!(back, Decision::Allow);
    }

    #[test]
    fn decision_serde_deny() {
        let json = serde_json::to_string(&Decision::Deny).unwrap();
        assert_eq!(json, "\"deny\"");
        let back: Decision = serde_json::from_str(&json).unwrap();
        assert_eq!(back, Decision::Deny);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // AuditEvent trait coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn audit_event_clone() {
        let event = create_audit_event(1, None, EVENT_SECRET_ACCESS);
        let cloned = Clone::clone(&event);
        assert_eq!(cloned.seq, 1);
        assert_eq!(cloned.event_type, EVENT_SECRET_ACCESS);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // AuditHead trait coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn audit_head_clone() {
        let head = create_audit_head(test_object_id("event-1"), 50, 3);
        let cloned = Clone::clone(&head);
        assert_eq!(cloned.head_seq, 50);
        assert!((cloned.coverage - 1.0_f64).abs() < f64::EPSILON);
    }

    #[test]
    fn audit_head_zone_id_accessor() {
        let head = create_audit_head(test_object_id("event-1"), 50, 3);
        assert_eq!(head.zone_id().as_str(), "z:work");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ZoneCheckpoint trait coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn zone_checkpoint_clone() {
        let cp =
            create_zone_checkpoint(test_object_id("rev"), 10, test_object_id("audit"), 20, 1, 4);
        let cloned = Clone::clone(&cp);
        assert_eq!(cloned.rev_seq, 10);
        assert_eq!(cloned.audit_seq, 20);
        assert_eq!(cloned.checkpoint_seq, 1);
    }

    #[test]
    fn zone_checkpoint_zone_id_accessor() {
        let cp =
            create_zone_checkpoint(test_object_id("rev"), 10, test_object_id("audit"), 20, 1, 4);
        assert_eq!(cp.zone_id().as_str(), "z:work");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // DecisionReceipt trait coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn decision_receipt_clone() {
        let receipt = create_decision_receipt(
            test_object_id("request"),
            Decision::Deny,
            "FCP-4010",
            vec![test_object_id("cap")],
        );
        let cloned = Clone::clone(&receipt);
        assert_eq!(cloned.reason_code, "FCP-4010");
        assert_eq!(cloned.evidence.len(), 1);
    }

    #[test]
    fn decision_receipt_zone_id_accessor() {
        let receipt = create_decision_receipt(
            test_object_id("request"),
            Decision::Allow,
            "FCP-0000",
            vec![],
        );
        assert_eq!(receipt.zone_id().as_str(), "z:work");
    }

    #[test]
    fn decision_receipt_is_allow_true() {
        let receipt = create_decision_receipt(
            test_object_id("request"),
            Decision::Allow,
            "FCP-0000",
            vec![],
        );
        assert!(receipt.is_allow());
        assert!(!receipt.is_deny());
    }

    #[test]
    fn decision_receipt_is_deny_true() {
        let receipt = create_decision_receipt(
            test_object_id("request"),
            Decision::Deny,
            "FCP-4010",
            vec![test_object_id("evidence")],
        );
        assert!(receipt.is_deny());
        assert!(!receipt.is_allow());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // TraceContext trait coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn trace_context_clone() {
        let trace = TraceContext {
            trace_id: [0xAA; 16],
            span_id: [0xBB; 8],
            flags: 0x01,
        };
        let cloned = Clone::clone(&trace);
        assert_eq!(cloned.trace_id, [0xAA; 16]);
        assert_eq!(cloned.span_id, [0xBB; 8]);
        assert_eq!(cloned.flags, 0x01);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // AuditEvent follows boundary cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn audit_event_follows_genesis() {
        // Genesis event (seq=0) cannot follow anything because
        // follows requires prev_seq + 1 == self.seq
        let genesis = create_audit_event(0, None, EVENT_SECRET_ACCESS);
        let prev = create_audit_event(0, None, EVENT_SECRET_ACCESS);
        let prev_id = test_object_id("prev-0");
        // seq 0 following seq 0 requires prev.seq.checked_add(1) = Some(1) != 0
        assert!(!genesis.follows(&prev, &prev_id));
    }

    #[test]
    fn audit_head_coverage_boundary() {
        let head = AuditHead {
            coverage: 0.0,
            ..create_audit_head(test_object_id("event"), 1, 0)
        };
        assert!(head.coverage.abs() < f64::EPSILON);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Additional AuditEvent tests — edge cases and boundaries
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn audit_event_is_genesis_true_for_seq_zero_no_prev() {
        let event = create_audit_event(0, None, EVENT_SECRET_ACCESS);
        assert!(event.is_genesis());
    }

    #[test]
    fn audit_event_is_genesis_false_for_seq_zero_with_prev() {
        let event = AuditEvent {
            prev: Some(test_object_id("some-prev")),
            seq: 0,
            ..create_audit_event(0, None, EVENT_SECRET_ACCESS)
        };
        assert!(!event.is_genesis());
    }

    #[test]
    fn audit_event_is_genesis_false_for_nonzero_seq_no_prev() {
        let event = create_audit_event(1, None, EVENT_SECRET_ACCESS);
        assert!(!event.is_genesis());
    }

    #[test]
    fn audit_event_is_genesis_false_for_nonzero_seq_with_prev() {
        let event = create_audit_event(5, Some(test_object_id("prev")), EVENT_SECRET_ACCESS);
        assert!(!event.is_genesis());
    }

    #[test]
    fn audit_event_follows_self_never_true() {
        let event = create_audit_event(5, Some(test_object_id("prev")), EVENT_CAPABILITY_INVOKE);
        let self_id = test_object_id("self-id");
        // An event cannot follow itself: seq + 1 != seq
        assert!(!event.follows(&event, &self_id));
    }

    #[test]
    fn audit_event_follows_seq_zero_to_one() {
        let prev_id = test_object_id("genesis-id");
        let genesis = create_audit_event(0, None, EVENT_SECRET_ACCESS);
        let event1 = AuditEvent {
            prev: Some(prev_id),
            seq: 1,
            ..create_audit_event(1, None, EVENT_SECRET_ACCESS)
        };
        assert!(event1.follows(&genesis, &prev_id));
    }

    #[test]
    fn audit_event_follows_requires_both_conditions() {
        let prev_id = test_object_id("prev-id");
        let event1 = create_audit_event(5, None, EVENT_CAPABILITY_INVOKE);

        // Correct seq but no prev pointer
        let event_no_prev = AuditEvent {
            prev: None,
            seq: 6,
            ..create_audit_event(6, None, EVENT_CAPABILITY_INVOKE)
        };
        assert!(!event_no_prev.follows(&event1, &prev_id));

        // Correct prev but wrong seq
        let event_wrong_seq = AuditEvent {
            prev: Some(prev_id),
            seq: 7,
            ..create_audit_event(7, None, EVENT_CAPABILITY_INVOKE)
        };
        assert!(!event_wrong_seq.follows(&event1, &prev_id));
    }

    #[test]
    fn audit_event_zone_id_method_returns_ref() {
        let event = create_audit_event(0, None, EVENT_ZONE_TRANSITION);
        let zone_ref = event.zone_id();
        assert_eq!(zone_ref.as_str(), event.zone_id.as_str());
    }

    #[test]
    fn audit_event_correlation_id_16_bytes() {
        let event = create_audit_event(1, None, EVENT_CAPABILITY_INVOKE);
        assert_eq!(event.correlation_id.0.as_bytes().len(), 16);
    }

    #[test]
    fn audit_event_occurred_at_monotonic_in_chain() {
        let event1 = create_audit_event(1, None, EVENT_CAPABILITY_INVOKE);
        let event2 = create_audit_event(2, Some(test_object_id("e1")), EVENT_CAPABILITY_INVOKE);
        assert!(event2.occurred_at >= event1.occurred_at);
    }

    #[test]
    fn audit_event_different_event_types_different_content() {
        let event_a = create_audit_event(1, None, EVENT_SECRET_ACCESS);
        let event_b = create_audit_event(1, None, EVENT_SECURITY_VIOLATION);
        assert_ne!(event_a.event_type, event_b.event_type);
    }

    #[test]
    fn audit_event_json_roundtrip_with_prev() {
        let event = create_audit_event(
            10,
            Some(test_object_id("prev-event")),
            EVENT_REVOCATION_ISSUED,
        );
        let json = serde_json::to_string(&event).unwrap();
        let decoded: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.seq, 10);
        assert_eq!(decoded.event_type, EVENT_REVOCATION_ISSUED);
        assert!(decoded.prev.is_some());
    }

    #[test]
    fn audit_event_cbor_roundtrip() {
        let event = create_audit_event(3, Some(test_object_id("prev")), EVENT_ELEVATION_GRANTED);
        let mut cbor_bytes = Vec::new();
        ciborium::into_writer(&event, &mut cbor_bytes).unwrap();
        let decoded: AuditEvent = ciborium::from_reader(&cbor_bytes[..]).unwrap();
        assert_eq!(decoded.seq, 3);
        assert_eq!(decoded.event_type, EVENT_ELEVATION_GRANTED);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Additional AuditHead tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn audit_head_json_roundtrip() {
        let head = create_audit_head(test_object_id("tip"), 99, 5);
        let json = serde_json::to_string(&head).unwrap();
        let decoded: AuditHead = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.head_seq, 99);
        assert!((decoded.coverage - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn audit_head_cbor_roundtrip() {
        let head = create_audit_head(test_object_id("tip-cbor"), 42, 3);
        let mut cbor_bytes = Vec::new();
        ciborium::into_writer(&head, &mut cbor_bytes).unwrap();
        let decoded: AuditHead = ciborium::from_reader(&cbor_bytes[..]).unwrap();
        assert_eq!(decoded.head_seq, 42);
    }

    #[test]
    fn audit_head_epoch_preserved() {
        let head = create_audit_head(test_object_id("event"), 10, 3);
        assert_eq!(head.epoch_id.as_str(), "epoch-1");
    }

    #[test]
    fn audit_head_zero_seq() {
        let head = create_audit_head(test_object_id("genesis"), 0, 1);
        assert_eq!(head.head_seq, 0);
    }

    #[test]
    fn audit_head_coverage_full_range() {
        for &coverage in &[0.0, 0.25, 0.5, 0.75, 1.0] {
            let head = AuditHead {
                coverage,
                ..create_audit_head(test_object_id("event"), 1, 1)
            };
            assert!((head.coverage - coverage).abs() < f64::EPSILON);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Additional ZoneCheckpoint tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn zone_checkpoint_json_roundtrip() {
        let cp = create_zone_checkpoint(
            test_object_id("rev-rt"),
            15,
            test_object_id("audit-rt"),
            30,
            3,
            4,
        );
        let json = serde_json::to_string(&cp).unwrap();
        let decoded: ZoneCheckpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.rev_seq, 15);
        assert_eq!(decoded.audit_seq, 30);
        assert_eq!(decoded.checkpoint_seq, 3);
    }

    #[test]
    fn zone_checkpoint_cbor_roundtrip() {
        let cp = create_zone_checkpoint(
            test_object_id("rev-cb"),
            20,
            test_object_id("audit-cb"),
            40,
            2,
            3,
        );
        let mut cbor_bytes = Vec::new();
        ciborium::into_writer(&cp, &mut cbor_bytes).unwrap();
        let decoded: ZoneCheckpoint = ciborium::from_reader(&cbor_bytes[..]).unwrap();
        assert_eq!(decoded.rev_seq, 20);
        assert_eq!(decoded.audit_seq, 40);
        assert_eq!(decoded.checkpoint_seq, 2);
    }

    #[test]
    fn zone_checkpoint_epoch_preserved() {
        let cp =
            create_zone_checkpoint(test_object_id("rev"), 10, test_object_id("audit"), 20, 1, 4);
        assert_eq!(cp.as_of_epoch.as_str(), "epoch-1");
    }

    #[test]
    fn zone_checkpoint_zero_seqs() {
        let cp = create_zone_checkpoint(test_object_id("rev"), 0, test_object_id("audit"), 0, 0, 1);
        assert_eq!(cp.rev_seq, 0);
        assert_eq!(cp.audit_seq, 0);
        assert_eq!(cp.checkpoint_seq, 0);
    }

    #[test]
    fn zone_checkpoint_large_seqs() {
        let cp = create_zone_checkpoint(
            test_object_id("rev"),
            u64::MAX,
            test_object_id("audit"),
            u64::MAX,
            u64::MAX,
            1,
        );
        assert_eq!(cp.rev_seq, u64::MAX);
        assert_eq!(cp.audit_seq, u64::MAX);
        assert_eq!(cp.checkpoint_seq, u64::MAX);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Additional DecisionReceipt tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn decision_receipt_cbor_roundtrip() {
        let receipt = create_decision_receipt(
            test_object_id("req-cbor"),
            Decision::Deny,
            "FCP-4010",
            vec![test_object_id("ev1")],
        );
        let mut cbor_bytes = Vec::new();
        ciborium::into_writer(&receipt, &mut cbor_bytes).unwrap();
        let decoded: DecisionReceipt = ciborium::from_reader(&cbor_bytes[..]).unwrap();
        assert_eq!(decoded.reason_code, "FCP-4010");
        assert!(decoded.is_deny());
    }

    #[test]
    fn decision_receipt_many_evidence_objects() {
        let evidence: Vec<ObjectId> = (0..100)
            .map(|i| test_object_id(&format!("ev-{i}")))
            .collect();
        let receipt = create_decision_receipt(
            test_object_id("req-many"),
            Decision::Deny,
            "FCP-5000",
            evidence,
        );
        assert_eq!(receipt.evidence.len(), 100);
    }

    #[test]
    fn decision_receipt_reason_code_various() {
        for code in ["FCP-0000", "FCP-4010", "FCP-4020", "FCP-4030", "FCP-5010"] {
            let receipt =
                create_decision_receipt(test_object_id("req"), Decision::Deny, code, vec![]);
            assert_eq!(receipt.reason_code, code);
        }
    }

    #[test]
    fn decision_receipt_explanation_long_text() {
        let long_text = "x".repeat(10000);
        let receipt = DecisionReceipt {
            explanation: Some(long_text),
            ..create_decision_receipt(test_object_id("req"), Decision::Deny, "FCP-4010", vec![])
        };
        assert_eq!(receipt.explanation.as_ref().unwrap().len(), 10000);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Additional Decision enum tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn decision_debug_format() {
        let allow_debug = format!("{:?}", Decision::Allow);
        let deny_debug = format!("{:?}", Decision::Deny);
        assert_eq!(allow_debug, "Allow");
        assert_eq!(deny_debug, "Deny");
    }

    #[test]
    fn decision_clone_preserves_value() {
        let d = Decision::Deny;
        let cloned = Clone::clone(&d);
        assert_eq!(d, cloned);
    }

    #[test]
    fn decision_cbor_roundtrip() {
        for decision in [Decision::Allow, Decision::Deny] {
            let mut cbor_bytes = Vec::new();
            ciborium::into_writer(&decision, &mut cbor_bytes).unwrap();
            let decoded: Decision = ciborium::from_reader(&cbor_bytes[..]).unwrap();
            assert_eq!(decision, decoded);
        }
    }

    #[test]
    fn decision_deserialization_rejects_invalid() {
        let result = serde_json::from_str::<Decision>("\"invalid\"");
        assert!(result.is_err());
    }

    #[test]
    fn decision_deserialization_rejects_uppercase() {
        let result = serde_json::from_str::<Decision>("\"Allow\"");
        assert!(result.is_err());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Additional TraceContext tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn trace_context_all_zeros() {
        let trace = TraceContext {
            trace_id: [0u8; 16],
            span_id: [0u8; 8],
            flags: 0,
        };
        let json = serde_json::to_string(&trace).unwrap();
        let decoded: TraceContext = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.trace_id, [0u8; 16]);
        assert_eq!(decoded.span_id, [0u8; 8]);
        assert_eq!(decoded.flags, 0);
    }

    #[test]
    fn trace_context_all_max_bytes() {
        let trace = TraceContext {
            trace_id: [0xFF; 16],
            span_id: [0xFF; 8],
            flags: 0xFF,
        };
        let json = serde_json::to_string(&trace).unwrap();
        let decoded: TraceContext = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.trace_id, [0xFF; 16]);
        assert_eq!(decoded.span_id, [0xFF; 8]);
        assert_eq!(decoded.flags, 0xFF);
    }

    #[test]
    fn trace_context_cbor_roundtrip() {
        let trace = TraceContext {
            trace_id: [0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            span_id: [0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0],
            flags: 0x01,
        };
        let mut cbor_bytes = Vec::new();
        ciborium::into_writer(&trace, &mut cbor_bytes).unwrap();
        let decoded: TraceContext = ciborium::from_reader(&cbor_bytes[..]).unwrap();
        assert_eq!(decoded.trace_id, trace.trace_id);
        assert_eq!(decoded.span_id, trace.span_id);
        assert_eq!(decoded.flags, trace.flags);
    }

    #[test]
    fn trace_context_debug_format() {
        let trace = TraceContext {
            trace_id: [0xAB; 16],
            span_id: [0xCD; 8],
            flags: 0x01,
        };
        let debug = format!("{trace:?}");
        assert!(debug.contains("TraceContext"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Fork detection edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn fork_detection_identical_events_no_fork() {
        let event_a = create_audit_event(10, None, EVENT_CAPABILITY_INVOKE);
        // Same correlation_id means same content — not a fork
        assert!(!is_fork_detected(&event_a, &event_a));
    }

    #[test]
    fn can_advance_checkpoint_rejects_same_seq() {
        assert!(!can_advance_checkpoint(50, 50, false));
    }

    #[test]
    fn can_advance_checkpoint_rejects_lower_seq() {
        assert!(!can_advance_checkpoint(50, 30, false));
    }

    #[test]
    fn can_advance_checkpoint_rejects_zero_to_zero() {
        assert!(!can_advance_checkpoint(0, 0, false));
    }

    #[test]
    fn can_advance_checkpoint_allows_zero_to_one() {
        assert!(can_advance_checkpoint(0, 1, false));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Event type constant format tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn event_type_constants_contain_dot() {
        let all_types = [
            EVENT_SECRET_ACCESS,
            EVENT_CAPABILITY_INVOKE,
            EVENT_ELEVATION_GRANTED,
            EVENT_DECLASSIFICATION_GRANTED,
            EVENT_ZONE_TRANSITION,
            EVENT_REVOCATION_ISSUED,
            EVENT_SECURITY_VIOLATION,
            EVENT_AUDIT_FORK_DETECTED,
        ];
        for t in all_types {
            assert!(
                t.contains('.'),
                "Event type '{t}' should contain a dot separator"
            );
        }
    }

    #[test]
    fn event_type_constants_no_uppercase() {
        let all_types = [
            EVENT_SECRET_ACCESS,
            EVENT_CAPABILITY_INVOKE,
            EVENT_ELEVATION_GRANTED,
            EVENT_DECLASSIFICATION_GRANTED,
            EVENT_ZONE_TRANSITION,
            EVENT_REVOCATION_ISSUED,
            EVENT_SECURITY_VIOLATION,
            EVENT_AUDIT_FORK_DETECTED,
        ];
        for t in all_types {
            assert_eq!(t, t.to_lowercase(), "Event type '{t}' should be lowercase");
        }
    }

    #[test]
    fn event_type_constants_are_unique() {
        let all_types = [
            EVENT_SECRET_ACCESS,
            EVENT_CAPABILITY_INVOKE,
            EVENT_ELEVATION_GRANTED,
            EVENT_DECLASSIFICATION_GRANTED,
            EVENT_ZONE_TRANSITION,
            EVENT_REVOCATION_ISSUED,
            EVENT_SECURITY_VIOLATION,
            EVENT_AUDIT_FORK_DETECTED,
        ];
        let mut seen = std::collections::HashSet::new();
        for t in all_types {
            assert!(seen.insert(t), "Duplicate event type: {t}");
        }
        assert_eq!(seen.len(), 8);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Quorum / signature set edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn quorum_signature_set_empty() {
        let set = create_quorum_signature_set(0);
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn quorum_signature_set_single() {
        let set = create_quorum_signature_set(1);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn quorum_signature_set_large() {
        let set = create_quorum_signature_set(20);
        assert_eq!(set.len(), 20);
    }

    #[test]
    fn audit_head_quorum_read_vs_write_thresholds() {
        let policy = QuorumPolicy::new(test_zone(), 5, 1);
        // Read requires fewer signatures than CriticalWrite
        let head_2sigs = create_audit_head(test_object_id("event"), 1, 2);
        // 2 sigs: enough for Read (threshold = ceil(n/2) = 3? or 1?)
        // We just verify CriticalWrite is stricter
        let head_4sigs = create_audit_head(test_object_id("event"), 1, 4);
        assert!(
            head_4sigs
                .quorum_signatures
                .satisfies_quorum(&policy, RiskTier::CriticalWrite)
        );
        // 2 sigs shouldn't satisfy CriticalWrite (n-f = 4 required)
        assert!(
            !head_2sigs
                .quorum_signatures
                .satisfies_quorum(&policy, RiskTier::CriticalWrite)
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Serialization skip_serializing_if coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn audit_event_optional_fields_skipped_independently() {
        // Only connector_id set, rest None
        let event = AuditEvent {
            connector_id: Some(ConnectorId::from_static("fcp.test:base:v1")),
            ..create_audit_event(1, None, EVENT_CAPABILITY_INVOKE)
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("connector_id"));
        assert!(!json.contains("capability_token_jti"));
        assert!(!json.contains("request_object_id"));
        assert!(!json.contains("result_object_id"));
    }

    #[test]
    fn audit_event_only_capability_token_jti_set() {
        let event = AuditEvent {
            capability_token_jti: Some(Uuid::from_bytes([0xCC; 16])),
            ..create_audit_event(1, None, EVENT_CAPABILITY_INVOKE)
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(!json.contains("connector_id"));
        assert!(json.contains("capability_token_jti"));
    }

    #[test]
    fn audit_event_only_operation_set() {
        let event = AuditEvent {
            operation: Some(OperationId::from_static("op-test-only")),
            ..create_audit_event(1, None, EVENT_CAPABILITY_INVOKE)
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("operation"));
        assert!(!json.contains("connector_id"));
    }
}
