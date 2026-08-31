//! Conformance vectors for FCP evidence retrieval and recovery flows.
//!
//! These vectors test the normative evidence model requirements from
//! `FCP_Specification_V3.md` §6 (Durable Object and Evidence Model):
//! 1. Audit chain integrity (hash-linked, monotonic seq)
//! 2. Operation receipt structure and idempotency dedup
//! 3. Decision receipt allow/deny with evidence references
//! 4. Zone checkpoint structure and freshness semantics
//! 5. Receipt signable bytes determinism

#[cfg(test)]
mod tests {
    use fcp_cbor::SchemaId;
    use fcp_prelude::{
        AuditEvent, ConnectorId, CorrelationId, Decision, DecisionReceipt, EpochId, IntentStatus,
        NodeId, NodeSignature, ObjectHeader, ObjectId, OperationId, OperationIntent,
        OperationReceipt, PrincipalId, Provenance, SignatureSet, TailscaleNodeId, TraceContext,
        ZoneCheckpoint, ZoneId,
    };
    use semver::Version;
    use uuid::Uuid;

    fn test_zone() -> ZoneId {
        "z:evidence".parse().unwrap()
    }

    fn test_header() -> ObjectHeader {
        ObjectHeader {
            encryption_kind: Default::default(),
            schema: SchemaId::new("fcp.test", "Evidence", Version::new(0, 1, 0)),
            zone_id: test_zone(),
            created_at: 1_700_000_000,
            provenance: Provenance::new(test_zone()),
            refs: Vec::new(),
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        }
    }

    fn test_signature() -> NodeSignature {
        NodeSignature::new(NodeId::new("test-node-1"), [0xAA; 64], 1_700_000_000)
    }

    fn test_correlation_id() -> CorrelationId {
        CorrelationId::default()
    }

    // ── Audit Chain Integrity ─────────────────────────────────────────

    #[test]
    fn audit_event_genesis_has_no_prev_and_seq_zero() {
        let event = AuditEvent {
            header: test_header(),
            correlation_id: test_correlation_id(),
            trace_context: None,
            event_type: "capability.invoke".into(),
            actor: PrincipalId::new("agent:test").unwrap(),
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

        assert!(event.is_genesis());
        assert_eq!(event.seq, 0);
        assert!(event.prev.is_none());
    }

    #[test]
    fn audit_event_chain_follows_semantics() {
        let genesis_id = ObjectId::from_bytes([0x01; 32]);

        let genesis = AuditEvent {
            header: test_header(),
            correlation_id: test_correlation_id(),
            trace_context: None,
            event_type: "zone.initialize".into(),
            actor: PrincipalId::new("owner:test").unwrap(),
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

        let successor = AuditEvent {
            header: test_header(),
            correlation_id: test_correlation_id(),
            trace_context: None,
            event_type: "capability.invoke".into(),
            actor: PrincipalId::new("agent:test").unwrap(),
            zone_id: test_zone(),
            connector_id: Some(ConnectorId::from_static("fcp.test")),
            operation: Some(OperationId::from_static("test.read")),
            capability_token_jti: Some(Uuid::new_v4()),
            request_object_id: Some(ObjectId::from_bytes([0x02; 32])),
            result_object_id: Some(ObjectId::from_bytes([0x03; 32])),
            prev: Some(genesis_id),
            seq: 1,
            occurred_at: 1_700_000_001,
            signature: test_signature(),
        };

        assert!(!successor.is_genesis());
        assert!(successor.follows(&genesis, &genesis_id));
    }

    #[test]
    fn audit_event_seq_must_be_monotonic() {
        let genesis_id = ObjectId::from_bytes([0x10; 32]);
        let genesis = AuditEvent {
            header: test_header(),
            correlation_id: test_correlation_id(),
            trace_context: None,
            event_type: "zone.initialize".into(),
            actor: PrincipalId::new("owner:test").unwrap(),
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

        // Wrong: seq skips from 0 to 5 (should be 1)
        let bad_successor = AuditEvent {
            seq: 5,
            prev: Some(genesis_id),
            ..genesis.clone()
        };
        assert!(
            !bad_successor.follows(&genesis, &genesis_id),
            "seq gap should not satisfy follows()"
        );
    }

    #[test]
    fn audit_event_serialization_roundtrip() {
        let event = AuditEvent {
            header: test_header(),
            correlation_id: test_correlation_id(),
            trace_context: Some(TraceContext {
                trace_id: [0xAB; 16],
                span_id: [0xCD; 8],
                flags: 0x01,
            }),
            event_type: "secret.access".into(),
            actor: PrincipalId::new("agent:evidence-test").unwrap(),
            zone_id: test_zone(),
            connector_id: Some(ConnectorId::from_static("fcp.gmail")),
            operation: Some(OperationId::from_static("gmail.read")),
            capability_token_jti: Some(Uuid::nil()),
            request_object_id: Some(ObjectId::from_bytes([0xAA; 32])),
            result_object_id: Some(ObjectId::from_bytes([0xBB; 32])),
            prev: Some(ObjectId::from_bytes([0x99; 32])),
            seq: 42,
            occurred_at: 1_700_000_042,
            signature: test_signature(),
        };

        let json = serde_json::to_value(&event).unwrap();
        let rt: AuditEvent = serde_json::from_value(json).unwrap();
        assert_eq!(rt.seq, 42);
        assert_eq!(rt.event_type, "secret.access");
        assert!(rt.trace_context.is_some());
    }

    // ── Operation Receipt ─────────────────────────────────────────────

    #[test]
    fn operation_receipt_idempotency_key_presence() {
        let receipt = OperationReceipt {
            header: {
                let mut h = test_header();
                h.refs = vec![ObjectId::from_bytes([0x11; 32])];
                h
            },
            request_object_id: ObjectId::from_bytes([0x22; 32]),
            idempotency_key: Some("idem-key-001".into()),
            outcome_object_ids: vec![ObjectId::from_bytes([0x33; 32])],
            resource_object_ids: vec![],
            usage_metrics: None,
            executed_at: 1_700_000_010,
            executed_by: TailscaleNodeId::new("node-executor"),
            signature: test_signature(),
        };

        assert!(receipt.is_idempotent());
        assert_eq!(receipt.total_objects_produced(), 1);
    }

    #[test]
    fn operation_receipt_signable_bytes_are_deterministic() {
        let receipt = OperationReceipt {
            header: {
                let mut h = test_header();
                h.refs = vec![ObjectId::from_bytes([0x11; 32])];
                h
            },
            request_object_id: ObjectId::from_bytes([0x22; 32]),
            idempotency_key: Some("determinism-test".into()),
            outcome_object_ids: vec![ObjectId::from_bytes([0x33; 32])],
            resource_object_ids: vec![],
            usage_metrics: None,
            executed_at: 1_700_000_020,
            executed_by: TailscaleNodeId::new("node-executor"),
            signature: test_signature(),
        };

        let bytes_1 = receipt.signable_bytes();
        let bytes_2 = receipt.signable_bytes();
        assert_eq!(bytes_1, bytes_2, "signable_bytes must be deterministic");
        assert!(!bytes_1.is_empty());
        assert!(bytes_1.starts_with(b"FCP2-RECEIPT-V1"));
    }

    #[test]
    fn operation_receipt_serialization_roundtrip() {
        let receipt = OperationReceipt {
            header: test_header(),
            request_object_id: ObjectId::from_bytes([0x44; 32]),
            idempotency_key: None,
            outcome_object_ids: vec![
                ObjectId::from_bytes([0x55; 32]),
                ObjectId::from_bytes([0x66; 32]),
            ],
            resource_object_ids: vec![ObjectId::from_bytes([0x77; 32])],
            usage_metrics: None,
            executed_at: 1_700_000_030,
            executed_by: TailscaleNodeId::new("node-2"),
            signature: test_signature(),
        };

        let json = serde_json::to_value(&receipt).unwrap();
        let rt: OperationReceipt = serde_json::from_value(json).unwrap();
        assert_eq!(rt.outcome_object_ids.len(), 2);
        assert_eq!(rt.total_objects_produced(), 3);
        assert!(!rt.is_idempotent());
    }

    // ── Decision Receipt ──────────────────────────────────────────────

    #[test]
    fn decision_receipt_allow_with_evidence() {
        let receipt = DecisionReceipt {
            header: test_header(),
            request_object_id: ObjectId::from_bytes([0xD1; 32]),
            decision: Decision::Allow,
            reason_code: "capability.valid".into(),
            evidence: vec![
                ObjectId::from_bytes([0xE1; 32]),
                ObjectId::from_bytes([0xE2; 32]),
            ],
            explanation: Some("Capability token valid for requested operation".into()),
            signature: test_signature(),
        };

        assert!(receipt.is_allow());
        assert!(!receipt.is_deny());
        assert_eq!(receipt.evidence.len(), 2);
    }

    #[test]
    fn decision_receipt_deny_with_stable_reason_code() {
        let receipt = DecisionReceipt {
            header: test_header(),
            request_object_id: ObjectId::from_bytes([0xD2; 32]),
            decision: Decision::Deny,
            reason_code: "capability.expired".into(),
            evidence: vec![ObjectId::from_bytes([0xE3; 32])],
            explanation: None,
            signature: test_signature(),
        };

        assert!(receipt.is_deny());
        assert!(!receipt.is_allow());
        assert_eq!(receipt.reason_code, "capability.expired");
    }

    #[test]
    fn decision_receipt_serialization_roundtrip() {
        let receipt = DecisionReceipt {
            header: test_header(),
            request_object_id: ObjectId::from_bytes([0xD3; 32]),
            decision: Decision::Allow,
            reason_code: "zone.access.granted".into(),
            evidence: vec![],
            explanation: Some("Zone policy permits access".into()),
            signature: test_signature(),
        };

        let json = serde_json::to_value(&receipt).unwrap();
        let rt: DecisionReceipt = serde_json::from_value(json).unwrap();
        assert_eq!(rt.reason_code, "zone.access.granted");
        assert!(rt.is_allow());
    }

    // ── Zone Checkpoint ───────────────────────────────────────────────

    #[test]
    fn zone_checkpoint_structure_captures_all_enforceable_heads() {
        let checkpoint = ZoneCheckpoint {
            header: test_header(),
            zone_id: test_zone(),
            rev_head: ObjectId::from_bytes([0xC1; 32]),
            rev_seq: 10,
            audit_head: ObjectId::from_bytes([0xC2; 32]),
            audit_seq: 42,
            zone_definition_head: ObjectId::from_bytes([0xC3; 32]),
            zone_policy_head: ObjectId::from_bytes([0xC4; 32]),
            active_zone_key_manifest: ObjectId::from_bytes([0xC5; 32]),
            checkpoint_seq: 7,
            as_of_epoch: EpochId::new("epoch-100"),
            quorum_signatures: SignatureSet::default(),
            revocation_freshness_sla_secs: 300,
        };

        assert_eq!(checkpoint.zone_id(), &test_zone());
        assert_eq!(checkpoint.checkpoint_seq, 7);
        assert_eq!(checkpoint.rev_seq, 10);
        assert_eq!(checkpoint.audit_seq, 42);
    }

    #[test]
    fn zone_checkpoint_serialization_roundtrip() {
        let checkpoint = ZoneCheckpoint {
            header: test_header(),
            zone_id: test_zone(),
            rev_head: ObjectId::from_bytes([0xD1; 32]),
            rev_seq: 5,
            audit_head: ObjectId::from_bytes([0xD2; 32]),
            audit_seq: 20,
            zone_definition_head: ObjectId::from_bytes([0xD3; 32]),
            zone_policy_head: ObjectId::from_bytes([0xD4; 32]),
            active_zone_key_manifest: ObjectId::from_bytes([0xD5; 32]),
            checkpoint_seq: 3,
            as_of_epoch: EpochId::new("epoch-50"),
            quorum_signatures: SignatureSet::default(),
            revocation_freshness_sla_secs: 300,
        };

        let json = serde_json::to_value(&checkpoint).unwrap();
        let rt: ZoneCheckpoint = serde_json::from_value(json).unwrap();
        assert_eq!(rt.checkpoint_seq, 3);
        assert_eq!(rt.zone_id, test_zone());
        assert_eq!(rt.audit_seq, 20);
    }

    // ── Operation Intent Lifecycle ────────────────────────────────────

    #[test]
    fn operation_intent_serialization_roundtrip() {
        let intent = OperationIntent {
            header: {
                let mut h = test_header();
                h.refs = vec![ObjectId::from_bytes([0xF1; 32])];
                h
            },
            request_object_id: ObjectId::from_bytes([0xF2; 32]),
            capability_token_jti: Uuid::nil(),
            idempotency_key: Some("intent-key-001".into()),
            planned_at: 1_700_000_000,
            planned_by: TailscaleNodeId::new("node-planner"),
            lease_seq: None,
            upstream_idempotency: None,
            signature: test_signature(),
        };

        let json = serde_json::to_value(&intent).unwrap();
        let rt: OperationIntent = serde_json::from_value(json).unwrap();
        assert_eq!(rt.idempotency_key.as_deref(), Some("intent-key-001"));
    }

    #[test]
    fn intent_status_exhaustive() {
        // Per spec §6.1: IntentStatus has exactly 5 states
        let statuses = [
            IntentStatus::Pending,
            IntentStatus::InProgress,
            IntentStatus::Completed,
            IntentStatus::Failed,
            IntentStatus::Orphaned,
        ];
        let mut seen = std::collections::HashSet::new();
        for status in &statuses {
            let json = serde_json::to_value(status).unwrap();
            assert!(seen.insert(json.as_str().unwrap().to_owned()));
        }
        assert_eq!(seen.len(), 5);
    }

    // ── Decision enum ─────────────────────────────────────────────────

    #[test]
    fn decision_enum_serialization_roundtrip() {
        let allow_json = serde_json::to_value(Decision::Allow).unwrap();
        let deny_json = serde_json::to_value(Decision::Deny).unwrap();

        assert_eq!(allow_json.as_str().unwrap(), "allow");
        assert_eq!(deny_json.as_str().unwrap(), "deny");

        let rt_allow: Decision = serde_json::from_value(allow_json).unwrap();
        let rt_deny: Decision = serde_json::from_value(deny_json).unwrap();
        assert_eq!(rt_allow, Decision::Allow);
        assert_eq!(rt_deny, Decision::Deny);
    }
}
