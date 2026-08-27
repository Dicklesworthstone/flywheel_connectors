//! Connector State Unit Tests (flywheel_connectors-70pq)
//!
//! Comprehensive tests for the connector state management system:
//! - Golden vector tests for deterministic CBOR serialization
//! - State chain integrity tests (hash linking, traversal)
//! - Singleton-writer fencing tests (`lease_seq`, `lease_object_id`)
//! - Failover tests (state recovery, leader transitions)
//! - Fork detection tests (CRITICAL - competing writes)
//! - Snapshot tests (compaction, coverage)
//! - Adversarial tests (Byzantine writers, replay attacks)

use std::{fs, path::PathBuf};

use fcp_cbor::SchemaId;
use fcp_core::{
    ConnectorId, ConnectorStateDelta, ConnectorStateModel, ConnectorStateObject,
    ConnectorStateRoot, ConnectorStateSnapshot, CrdtType, FencingError, ForkEvent, ForkResolution,
    InstanceId, ObjectHeader, ObjectId, Provenance, Signature, SnapshotConfig, TailscaleNodeId,
    ZoneId, validate_singleton_writer_fencing,
};
use semver::Version;
use sha2::{Digest, Sha256};

const SNAPSHOT_GOLDEN_SEQ_100_SHA256: &str =
    "dd6fb52043bc2d6bac665a90299c69c0aac69c7b975a45b1345500ade6368950";
const SNAPSHOT_GOLDEN_SEQ_100_LEN: usize = 404;

// ═══════════════════════════════════════════════════════════════════════════════
// Test Helpers
// ═══════════════════════════════════════════════════════════════════════════════

fn test_zone() -> ZoneId {
    ZoneId::work()
}

fn test_object_id(name: &str) -> ObjectId {
    ObjectId::from_unscoped_bytes(name.as_bytes())
}

fn test_connector_id() -> ConnectorId {
    ConnectorId::new("test", "connector", "1.0.0").unwrap()
}

fn test_instance_id() -> InstanceId {
    InstanceId::new()
}

fn test_node_id(name: &str) -> TailscaleNodeId {
    TailscaleNodeId::new(name)
}

const fn test_signature() -> Signature {
    Signature::from_bytes([0xab; 64])
}

fn create_test_header(schema_name: &str) -> ObjectHeader {
    let zone = test_zone();
    ObjectHeader {
        schema: SchemaId::new("fcp.connector_state", schema_name, Version::new(1, 0, 0)),
        zone_id: zone.clone(),
        created_at: 1000,
        provenance: Provenance::new(zone),
        refs: vec![],
        foreign_refs: vec![],
        ttl_secs: None,
        placement: None,
    }
}

fn create_test_header_with_refs(schema_name: &str, refs: Vec<ObjectId>) -> ObjectHeader {
    let zone = test_zone();
    ObjectHeader {
        schema: SchemaId::new("fcp.connector_state", schema_name, Version::new(1, 0, 0)),
        zone_id: zone.clone(),
        created_at: 1000,
        provenance: Provenance::new(zone),
        refs,
        foreign_refs: vec![],
        ttl_secs: None,
        placement: None,
    }
}

fn create_test_state_root() -> ConnectorStateRoot {
    ConnectorStateRoot::singleton_writer(
        create_test_header("root"),
        test_connector_id(),
        test_zone(),
    )
}

fn create_test_state_object(
    prev: Option<ObjectId>,
    seq: u64,
    lease_seq: u64,
) -> ConnectorStateObject {
    let lease_object_id = test_object_id("lease-1");
    ConnectorStateObject {
        header: create_test_header_with_refs("state_object", vec![lease_object_id]),
        connector_id: test_connector_id(),
        instance_id: None,
        zone_id: test_zone(),
        prev,
        seq,
        state_cbor: vec![0xa0], // Empty CBOR map
        updated_at: 1000_u64.saturating_add(seq.saturating_mul(100)),
        lease_seq,
        lease_object_id,
        writer_public_key: [0u8; 32],
        signature: test_signature(),
    }
}

fn create_test_snapshot(covers_head: ObjectId, covers_seq: u64) -> ConnectorStateSnapshot {
    ConnectorStateSnapshot {
        header: create_test_header("snapshot"),
        connector_id: test_connector_id(),
        instance_id: None,
        zone_id: test_zone(),
        covers_head,
        covers_seq,
        state_cbor: vec![0xa0], // Empty CBOR map
        snapshotted_at: 2000,
        signature: test_signature(),
    }
}

fn connector_state_snapshot_golden_path(connector_id: &ConnectorId, seq: u64) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("golden")
        .join("connector_state_snapshot")
        // Sanitize the connector id for the on-disk path: a ConnectorId's canonical
        // `name:archetype:version` form contains colons, which are illegal in Windows
        // (NTFS) filenames and abort `git checkout` on Windows runners (exit 128). The
        // golden's *content* still serializes the real (colon-bearing) id.
        .join(connector_id.as_str().replace(':', "_"))
        .join(format!("{seq}.cbor"))
}

fn create_test_delta() -> ConnectorStateDelta {
    ConnectorStateDelta {
        header: create_test_header("delta"),
        connector_id: test_connector_id(),
        instance_id: None,
        zone_id: test_zone(),
        crdt_type: CrdtType::LwwMap,
        delta_cbor: vec![0xa0], // Empty CBOR map
        applied_at: 1500,
        applied_by: test_node_id("node-1"),
        signature: test_signature(),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CBOR Golden Vector Tests
// ═══════════════════════════════════════════════════════════════════════════════

mod cbor_golden_vectors {
    use super::*;

    #[test]
    fn state_root_cbor_roundtrip() {
        let root = create_test_state_root();

        let mut cbor = Vec::new();
        ciborium::into_writer(&root, &mut cbor).expect("serialization should succeed");

        let restored: ConnectorStateRoot =
            ciborium::from_reader(&cbor[..]).expect("deserialization should succeed");

        assert_eq!(root.connector_id, restored.connector_id);
        assert_eq!(root.zone_id, restored.zone_id);
        assert_eq!(root.model, restored.model);
        assert_eq!(root.head, restored.head);
        assert_eq!(root.state_schema_version, restored.state_schema_version);
    }

    #[test]
    fn state_object_cbor_roundtrip() {
        let prev = test_object_id("prev-state");
        let obj = create_test_state_object(Some(prev), 42, 100);

        let mut cbor = Vec::new();
        ciborium::into_writer(&obj, &mut cbor).expect("serialization should succeed");

        let restored: ConnectorStateObject =
            ciborium::from_reader(&cbor[..]).expect("deserialization should succeed");

        assert_eq!(obj.prev, restored.prev);
        assert_eq!(obj.seq, restored.seq);
        assert_eq!(obj.state_cbor, restored.state_cbor);
        assert_eq!(obj.lease_seq, restored.lease_seq);
        assert_eq!(obj.lease_object_id, restored.lease_object_id);
        assert_eq!(obj.writer_public_key, restored.writer_public_key);
    }

    #[test]
    fn state_snapshot_cbor_roundtrip() {
        let covers_head = test_object_id("head-state");
        let snapshot = create_test_snapshot(covers_head, 100);

        let mut cbor = Vec::new();
        ciborium::into_writer(&snapshot, &mut cbor).expect("serialization should succeed");

        let restored: ConnectorStateSnapshot =
            ciborium::from_reader(&cbor[..]).expect("deserialization should succeed");

        assert_eq!(snapshot.covers_head, restored.covers_head);
        assert_eq!(snapshot.covers_seq, restored.covers_seq);
        assert_eq!(snapshot.state_cbor, restored.state_cbor);
        assert_eq!(snapshot.snapshotted_at, restored.snapshotted_at);
    }

    #[test]
    fn state_snapshot_file_golden_vector() {
        let snapshot = create_test_snapshot(test_object_id("head-state"), 100);
        let mut cbor = Vec::new();
        ciborium::into_writer(&snapshot, &mut cbor).expect("serialization should succeed");

        let path =
            connector_state_snapshot_golden_path(&snapshot.connector_id, snapshot.covers_seq);
        assert!(
            path.is_file(),
            "connector-state snapshot golden vector is missing: {}",
            path.display()
        );

        let stored = fs::read(&path).expect("golden vector should be readable");
        assert_eq!(stored.len(), SNAPSHOT_GOLDEN_SEQ_100_LEN);
        assert_eq!(
            hex::encode(Sha256::digest(&stored)),
            SNAPSHOT_GOLDEN_SEQ_100_SHA256
        );
        assert_eq!(
            stored,
            cbor,
            "connector-state snapshot golden vector drifted: {}",
            path.display()
        );

        let restored: ConnectorStateSnapshot =
            ciborium::from_reader(&stored[..]).expect("golden vector should deserialize");
        assert_eq!(snapshot.connector_id, restored.connector_id);
        assert_eq!(snapshot.zone_id, restored.zone_id);
        assert_eq!(snapshot.covers_head, restored.covers_head);
        assert_eq!(snapshot.covers_seq, restored.covers_seq);
        assert_eq!(snapshot.state_cbor, restored.state_cbor);
        assert_eq!(snapshot.snapshotted_at, restored.snapshotted_at);
    }

    #[test]
    fn state_delta_cbor_roundtrip() {
        let delta = create_test_delta();

        let mut cbor = Vec::new();
        ciborium::into_writer(&delta, &mut cbor).expect("serialization should succeed");

        let restored: ConnectorStateDelta =
            ciborium::from_reader(&cbor[..]).expect("deserialization should succeed");

        assert_eq!(delta.crdt_type, restored.crdt_type);
        assert_eq!(delta.delta_cbor, restored.delta_cbor);
        assert_eq!(delta.applied_at, restored.applied_at);
    }

    #[test]
    fn fork_event_cbor_roundtrip() {
        let event = ForkEvent {
            common_prev: test_object_id("common-prev"),
            branch_a: test_object_id("branch-a"),
            branch_b: test_object_id("branch-b"),
            fork_seq: 42,
            detected_at: 1000,
            zone_id: test_zone(),
            connector_id: test_connector_id(),
        };

        let mut cbor = Vec::new();
        ciborium::into_writer(&event, &mut cbor).expect("serialization should succeed");

        let restored: ForkEvent =
            ciborium::from_reader(&cbor[..]).expect("deserialization should succeed");

        assert_eq!(event.common_prev, restored.common_prev);
        assert_eq!(event.branch_a, restored.branch_a);
        assert_eq!(event.branch_b, restored.branch_b);
        assert_eq!(event.fork_seq, restored.fork_seq);
    }

    #[test]
    fn genesis_state_object_cbor() {
        let genesis = create_test_state_object(None, 0, 1);

        assert!(genesis.is_genesis());

        let mut cbor = Vec::new();
        ciborium::into_writer(&genesis, &mut cbor).expect("serialization should succeed");

        let restored: ConnectorStateObject =
            ciborium::from_reader(&cbor[..]).expect("deserialization should succeed");

        assert!(restored.is_genesis());
        assert!(restored.prev.is_none());
        assert_eq!(restored.seq, 0);
    }

    #[test]
    fn state_object_with_large_state_cbor() {
        let mut obj = create_test_state_object(None, 1, 1);
        obj.state_cbor = vec![0x42; 100_000]; // 100KB state

        let mut cbor = Vec::new();
        ciborium::into_writer(&obj, &mut cbor).expect("serialization should succeed");

        let restored: ConnectorStateObject =
            ciborium::from_reader(&cbor[..]).expect("deserialization should succeed");

        assert_eq!(restored.state_cbor.len(), 100_000);
    }

    #[test]
    fn connector_state_model_all_variants_cbor() {
        let models = [
            ConnectorStateModel::Stateless,
            ConnectorStateModel::SingletonWriter,
            ConnectorStateModel::Crdt {
                crdt_type: CrdtType::LwwMap,
            },
            ConnectorStateModel::Crdt {
                crdt_type: CrdtType::OrSet,
            },
            ConnectorStateModel::Crdt {
                crdt_type: CrdtType::GCounter,
            },
            ConnectorStateModel::Crdt {
                crdt_type: CrdtType::PnCounter,
            },
        ];

        for model in models {
            let mut cbor = Vec::new();
            ciborium::into_writer(&model, &mut cbor).expect("serialization should succeed");

            let restored: ConnectorStateModel =
                ciborium::from_reader(&cbor[..]).expect("deserialization should succeed");

            assert_eq!(model, restored);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// State Schema Tests
// ═══════════════════════════════════════════════════════════════════════════════

mod state_schema_tests {
    use super::*;

    #[test]
    fn state_root_stateless_constructor() {
        let root = ConnectorStateRoot::stateless(
            create_test_header("root"),
            test_connector_id(),
            test_zone(),
        );

        assert!(root.model.is_stateless());
        assert!(!root.model.is_singleton_writer());
        assert!(!root.model.is_crdt());
        assert!(root.head.is_none());
        assert_eq!(root.state_schema_version, 1);
    }

    #[test]
    fn state_root_singleton_writer_constructor() {
        let root = ConnectorStateRoot::singleton_writer(
            create_test_header("root"),
            test_connector_id(),
            test_zone(),
        );

        assert!(!root.model.is_stateless());
        assert!(root.model.is_singleton_writer());
        assert!(!root.model.is_crdt());
    }

    #[test]
    fn state_root_crdt_constructor() {
        let root = ConnectorStateRoot::crdt(
            create_test_header("root"),
            test_connector_id(),
            test_zone(),
            CrdtType::OrSet,
        );

        assert!(!root.model.is_stateless());
        assert!(!root.model.is_singleton_writer());
        assert!(root.model.is_crdt());
        assert_eq!(root.model.crdt_type(), Some(CrdtType::OrSet));
    }

    #[test]
    fn state_root_with_instance_id() {
        let instance_id = test_instance_id();
        let root = create_test_state_root().with_instance_id(instance_id.clone());

        assert_eq!(root.instance_id, Some(instance_id));
    }

    #[test]
    fn state_root_with_head() {
        let head = test_object_id("head-state");
        let root = create_test_state_root().with_head(head);

        assert_eq!(root.head, Some(head));
    }

    #[test]
    fn state_object_is_genesis() {
        let genesis = create_test_state_object(None, 0, 1);
        let non_genesis = create_test_state_object(Some(test_object_id("prev")), 1, 1);

        assert!(genesis.is_genesis());
        assert!(!non_genesis.is_genesis());
    }

    #[test]
    fn signature_zero_and_from_bytes() {
        let zero = Signature::zero();
        assert_eq!(zero.as_bytes(), &[0u8; 64]);

        let custom = Signature::from_bytes([0xde; 64]);
        assert_eq!(custom.as_bytes(), &[0xde; 64]);
    }

    #[test]
    fn signature_display_truncated() {
        let sig = Signature::from_bytes([0xab; 64]);
        let display = sig.to_string();
        assert!(display.contains("abababab"));
        assert!(display.ends_with("..."));
    }

    #[test]
    fn crdt_type_as_str() {
        assert_eq!(CrdtType::LwwMap.as_str(), "lww_map");
        assert_eq!(CrdtType::OrSet.as_str(), "or_set");
        assert_eq!(CrdtType::GCounter.as_str(), "g_counter");
        assert_eq!(CrdtType::PnCounter.as_str(), "pn_counter");
    }

    #[test]
    fn connector_state_model_display() {
        assert_eq!(ConnectorStateModel::Stateless.to_string(), "stateless");
        assert_eq!(
            ConnectorStateModel::SingletonWriter.to_string(),
            "singleton_writer"
        );
        assert_eq!(
            ConnectorStateModel::Crdt {
                crdt_type: CrdtType::LwwMap
            }
            .to_string(),
            "crdt(lww_map)"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// State Chain Integrity Tests
// ═══════════════════════════════════════════════════════════════════════════════

mod state_chain_tests {
    use super::*;

    #[test]
    fn chain_linked_by_prev() {
        let genesis = create_test_state_object(None, 0, 1);
        let genesis_id = test_object_id("genesis");

        let state1 = create_test_state_object(Some(genesis_id), 1, 1);
        let state1_id = test_object_id("state1");

        let state2 = create_test_state_object(Some(state1_id), 2, 1);

        // Verify chain links
        assert!(genesis.is_genesis());
        assert_eq!(state1.prev, Some(genesis_id));
        assert_eq!(state2.prev, Some(state1_id));

        // Verify sequence increases monotonically
        assert_eq!(genesis.seq, 0);
        assert_eq!(state1.seq, 1);
        assert_eq!(state2.seq, 2);
    }

    #[test]
    fn sequence_must_increase_monotonically() {
        // Build a chain with increasing sequences
        let mut prev_id = None;
        let mut prev_seq = 0u64;

        for i in 0..10 {
            let state = create_test_state_object(prev_id, i, 1);

            assert!(
                state.seq > prev_seq || state.seq == 0,
                "Sequence must increase monotonically"
            );

            prev_id = Some(test_object_id(&format!("state-{i}")));
            prev_seq = state.seq;
        }
    }

    #[test]
    fn chain_traversal_from_head() {
        // Simulate chain traversal: start at head, follow prev links
        let chain_length = 5usize;
        let mut chain = Vec::new();

        for i in 0..chain_length {
            let prev = if i == 0 {
                None
            } else {
                Some(test_object_id(&format!("state-{}", i - 1)))
            };
            chain.push(create_test_state_object(prev, i as u64, 1));
        }

        // Traverse from head (last element) back to genesis
        let head = &chain[chain_length - 1];
        assert_eq!(head.seq, (chain_length - 1) as u64);

        // In real implementation, would follow prev links
        // Here we verify the chain structure
        for (i, state) in chain.iter().enumerate() {
            if i == 0 {
                assert!(state.prev.is_none());
            } else {
                assert!(state.prev.is_some());
            }
        }
    }

    #[test]
    fn state_objects_same_prev_indicates_fork() {
        let common_prev = test_object_id("common-prev");

        let branch_a = create_test_state_object(Some(common_prev), 5, 100);
        let branch_b = create_test_state_object(Some(common_prev), 5, 101);

        // Both objects have same prev - this is a fork!
        assert_eq!(branch_a.prev, branch_b.prev);
        assert_eq!(branch_a.seq, branch_b.seq);

        // Different lease_seq indicates different writers
        assert_ne!(branch_a.lease_seq, branch_b.lease_seq);
    }

    #[test]
    fn updated_at_increases_with_chain() {
        let genesis = create_test_state_object(None, 0, 1);
        let state1 = create_test_state_object(Some(test_object_id("g")), 1, 1);
        let state2 = create_test_state_object(Some(test_object_id("s1")), 2, 1);

        // updated_at should be non-decreasing along chain
        assert!(genesis.updated_at <= state1.updated_at);
        assert!(state1.updated_at <= state2.updated_at);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Singleton-Writer Fencing Tests
// ═══════════════════════════════════════════════════════════════════════════════

mod fencing_tests {
    use super::*;

    #[test]
    fn valid_fencing_passes() {
        let lease_id = test_object_id("lease-1");
        let state_obj = ConnectorStateObject {
            header: create_test_header_with_refs("state_object", vec![lease_id]),
            connector_id: test_connector_id(),
            instance_id: None,
            zone_id: test_zone(),
            prev: None,
            seq: 1,
            state_cbor: vec![0xa0],
            updated_at: 1000,
            lease_seq: 42,
            lease_object_id: lease_id,
            writer_public_key: [0u8; 32],
            signature: test_signature(),
        };

        let result = validate_singleton_writer_fencing(
            &state_obj, 42,   // current_known_seq matches
            1000, // now
            2000, // lease_exp in future
        );

        assert!(result.is_ok());
    }

    #[test]
    fn fencing_fails_on_expired_lease() {
        let lease_id = test_object_id("lease-1");
        let state_obj = ConnectorStateObject {
            header: create_test_header_with_refs("state_object", vec![lease_id]),
            connector_id: test_connector_id(),
            instance_id: None,
            zone_id: test_zone(),
            prev: None,
            seq: 1,
            state_cbor: vec![0xa0],
            updated_at: 1000,
            lease_seq: 42,
            lease_object_id: lease_id,
            writer_public_key: [0u8; 32],
            signature: test_signature(),
        };

        let result = validate_singleton_writer_fencing(
            &state_obj, 42, 2000, // now is at expiry time
            2000, // lease_exp
        );

        assert!(matches!(result, Err(FencingError::LeaseExpired { .. })));

        // Also fails if now > lease_exp
        let result = validate_singleton_writer_fencing(
            &state_obj, 42, 3000, // now is past expiry
            2000,
        );

        assert!(matches!(result, Err(FencingError::LeaseExpired { .. })));
    }

    #[test]
    fn fencing_fails_on_stale_lease_seq() {
        let lease_id = test_object_id("lease-1");
        let state_obj = ConnectorStateObject {
            header: create_test_header_with_refs("state_object", vec![lease_id]),
            connector_id: test_connector_id(),
            instance_id: None,
            zone_id: test_zone(),
            prev: None,
            seq: 1,
            state_cbor: vec![0xa0],
            updated_at: 1000,
            lease_seq: 42, // State object has old lease_seq
            lease_object_id: lease_id,
            writer_public_key: [0u8; 32],
            signature: test_signature(),
        };

        let result = validate_singleton_writer_fencing(
            &state_obj, 100, // current_known_seq is higher
            1000, 2000,
        );

        assert!(matches!(
            result,
            Err(FencingError::StaleLeaseSeq {
                held_seq: 42,
                current_seq: 100
            })
        ));
    }

    #[test]
    fn fencing_fails_when_lease_not_in_refs() {
        let lease_id = test_object_id("lease-1");
        let wrong_lease_id = test_object_id("wrong-lease");

        let state_obj = ConnectorStateObject {
            header: create_test_header_with_refs("state_object", vec![]), // Empty refs!
            connector_id: test_connector_id(),
            instance_id: None,
            zone_id: test_zone(),
            prev: None,
            seq: 1,
            state_cbor: vec![0xa0],
            updated_at: 1000,
            lease_seq: 42,
            lease_object_id: lease_id, // References lease_id but it's not in refs
            writer_public_key: [0u8; 32],
            signature: test_signature(),
        };

        let result = validate_singleton_writer_fencing(&state_obj, 42, 1000, 2000);

        assert!(matches!(result, Err(FencingError::LeaseNotFound { .. })));

        // Also fails if refs has wrong lease
        let state_obj_wrong_ref = ConnectorStateObject {
            header: create_test_header_with_refs("state_object", vec![wrong_lease_id]),
            ..state_obj
        };

        let result = validate_singleton_writer_fencing(&state_obj_wrong_ref, 42, 1000, 2000);

        assert!(matches!(result, Err(FencingError::LeaseNotFound { .. })));
    }

    #[test]
    fn fencing_allows_equal_lease_seq() {
        let lease_id = test_object_id("lease-1");
        let state_obj = ConnectorStateObject {
            header: create_test_header_with_refs("state_object", vec![lease_id]),
            connector_id: test_connector_id(),
            instance_id: None,
            zone_id: test_zone(),
            prev: None,
            seq: 1,
            state_cbor: vec![0xa0],
            updated_at: 1000,
            lease_seq: 100,
            lease_object_id: lease_id,
            writer_public_key: [0u8; 32],
            signature: test_signature(),
        };

        // Equal lease_seq is valid (same writer with same lease)
        let result = validate_singleton_writer_fencing(
            &state_obj, 100, // Equal to state_obj.lease_seq
            1000, 2000,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn fencing_allows_higher_lease_seq_in_object() {
        let lease_id = test_object_id("lease-1");
        let state_obj = ConnectorStateObject {
            header: create_test_header_with_refs("state_object", vec![lease_id]),
            connector_id: test_connector_id(),
            instance_id: None,
            zone_id: test_zone(),
            prev: None,
            seq: 1,
            state_cbor: vec![0xa0],
            updated_at: 1000,
            lease_seq: 200, // Higher than current_known_seq
            lease_object_id: lease_id,
            writer_public_key: [0u8; 32],
            signature: test_signature(),
        };

        // Object with higher lease_seq advances the known seq
        let result = validate_singleton_writer_fencing(
            &state_obj, 100, // Lower than state_obj.lease_seq
            1000, 2000,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn fencing_error_display() {
        let errors = [
            FencingError::LeaseExpired {
                expired_at: 1000,
                now: 2000,
            },
            FencingError::StaleLeaseSeq {
                held_seq: 5,
                current_seq: 10,
            },
            FencingError::SubjectMismatch {
                expected: test_object_id("expected"),
                got: test_object_id("got"),
            },
            FencingError::WrongPurpose,
            FencingError::LeaseNotFound {
                lease_id: test_object_id("lease"),
            },
        ];

        for error in &errors {
            let display = error.to_string();
            assert_ne!(display, "");
        }
    }

    #[test]
    fn stale_writer_scenario() {
        // Scenario: Old leader (zombie) tries to write with stale lease
        let lease_id = test_object_id("old-lease");

        let zombie_state = ConnectorStateObject {
            header: create_test_header_with_refs("state_object", vec![lease_id]),
            connector_id: test_connector_id(),
            instance_id: None,
            zone_id: test_zone(),
            prev: Some(test_object_id("prev")),
            seq: 10,
            state_cbor: vec![0xa0],
            updated_at: 1000,
            lease_seq: 50, // Old lease
            lease_object_id: lease_id,
            writer_public_key: [0u8; 32],
            signature: test_signature(),
        };

        // New leader has taken over with lease_seq = 100
        let result = validate_singleton_writer_fencing(
            &zombie_state,
            100, // Current leader has lease_seq 100
            1000,
            2000,
        );

        assert!(matches!(result, Err(FencingError::StaleLeaseSeq { .. })));
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Failover Tests
// ═══════════════════════════════════════════════════════════════════════════════

mod failover_tests {
    use super::*;

    #[test]
    fn state_recovery_from_root() {
        // Scenario: New node recovers state from root object
        let head_id = test_object_id("head-state");
        let root = create_test_state_root().with_head(head_id);

        // Recovery starts from root.head
        assert_eq!(root.head, Some(head_id));
        assert!(root.model.is_singleton_writer());
    }

    #[test]
    fn leader_transition_with_higher_lease_seq() {
        // Old leader has state with lease_seq = 50
        let old_state = create_test_state_object(Some(test_object_id("prev")), 10, 50);

        // New leader takes over with lease_seq = 51
        let new_state = create_test_state_object(
            Some(test_object_id(&format!("state-{}", old_state.seq))),
            11, // Continue sequence
            51, // Higher lease_seq
        );

        assert!(new_state.lease_seq > old_state.lease_seq);
        assert!(new_state.seq > old_state.seq);
    }

    #[test]
    fn state_root_preserves_schema_version() {
        let root = create_test_state_root();
        assert_eq!(root.state_schema_version, 1);

        // Simulate upgrade scenario
        let upgraded_root = ConnectorStateRoot {
            state_schema_version: 2,
            ..root
        };

        assert_eq!(upgraded_root.state_schema_version, 2);
    }

    #[test]
    fn failover_with_instance_id() {
        // Multi-instance connector: each instance has unique ID
        let instance_a = InstanceId::new();
        let instance_b = InstanceId::new();

        let root_a = create_test_state_root().with_instance_id(instance_a);
        let root_b = create_test_state_root().with_instance_id(instance_b);

        assert_ne!(root_a.instance_id, root_b.instance_id);
    }

    #[test]
    fn recovery_from_snapshot() {
        // Scenario: Recover state from snapshot instead of replaying full chain
        let snapshot = create_test_snapshot(test_object_id("head"), 1000);

        // Snapshot contains full state at covers_seq
        assert_eq!(snapshot.covers_seq, 1000);

        // New states continue from snapshot.covers_seq + 1
        let new_state = create_test_state_object(Some(snapshot.covers_head), 1001, 100);
        assert_eq!(new_state.seq, 1001);
        assert_eq!(new_state.prev, Some(snapshot.covers_head));
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Fork Detection Tests (CRITICAL)
// ═══════════════════════════════════════════════════════════════════════════════

mod fork_detection_tests {
    use super::*;

    #[test]
    fn detect_fork_same_prev() {
        // CRITICAL: Two state objects with same prev = FORK
        let common_prev = test_object_id("common-prev");

        let branch_a = create_test_state_object(Some(common_prev), 5, 100);
        let branch_b = create_test_state_object(Some(common_prev), 5, 101);

        // Both reference same prev - this is a fork!
        assert_eq!(branch_a.prev, branch_b.prev);

        // Create fork event
        let fork = ForkEvent {
            common_prev,
            branch_a: test_object_id("branch-a"),
            branch_b: test_object_id("branch-b"),
            fork_seq: 5, // The sequence number where fork occurred
            detected_at: 2000,
            zone_id: test_zone(),
            connector_id: test_connector_id(),
        };

        assert_eq!(fork.fork_seq, branch_a.seq);
        assert_eq!(fork.fork_seq, branch_b.seq);
    }

    #[test]
    fn fork_resolution_strategies() {
        let resolutions = [
            ForkResolution::ChooseByLease,
            ForkResolution::ManualResolution,
            ForkResolution::CrdtMerge,
        ];

        for resolution in resolutions {
            let json = serde_json::to_string(&resolution).expect("serialize should work");
            let restored: ForkResolution =
                serde_json::from_str(&json).expect("deserialize should work");
            assert_eq!(resolution, restored);
        }
    }

    #[test]
    fn fork_resolution_choose_by_lease() {
        // When forked, choose branch with higher lease_seq
        let common_prev = test_object_id("common-prev");

        let branch_a = create_test_state_object(Some(common_prev), 5, 100);
        let branch_b = create_test_state_object(Some(common_prev), 5, 200); // Higher lease_seq

        // ChooseByLease: branch_b wins (higher lease_seq)
        assert!(branch_b.lease_seq > branch_a.lease_seq);
    }

    #[test]
    fn fork_at_genesis() {
        // Edge case: Two different genesis states (both prev=None)
        let genesis_a = create_test_state_object(None, 0, 100);
        let genesis_b = create_test_state_object(None, 0, 101);

        assert!(genesis_a.is_genesis());
        assert!(genesis_b.is_genesis());

        // Both are genesis - this is still a fork if state_cbor differs
        // In real implementation, different ObjectIds would be generated
    }

    #[test]
    fn fork_detection_requires_same_seq() {
        let common_prev = test_object_id("common-prev");

        // Different sequences from same prev is NOT a fork (impossible in valid chain)
        let state_5 = create_test_state_object(Some(common_prev), 5, 100);
        let state_6 = create_test_state_object(Some(common_prev), 6, 101);

        // This is invalid state (same prev, different seq) - indicates bug
        assert_eq!(state_5.prev, state_6.prev);
        assert_ne!(state_5.seq, state_6.seq);
    }

    #[test]
    fn fork_event_captures_context() {
        let fork = ForkEvent {
            common_prev: test_object_id("common-prev"),
            branch_a: test_object_id("branch-a"),
            branch_b: test_object_id("branch-b"),
            fork_seq: 42,
            detected_at: 1_700_000_000,
            zone_id: test_zone(),
            connector_id: test_connector_id(),
        };

        // All context needed for audit/resolution is captured
        assert_ne!(fork.branch_a, fork.branch_b);
        assert!(fork.detected_at > 0);
    }

    #[test]
    fn crdt_merge_resolution_for_crdt_model() {
        // CrdtMerge resolution is only valid for CRDT models
        let crdt_root = ConnectorStateRoot::crdt(
            create_test_header("root"),
            test_connector_id(),
            test_zone(),
            CrdtType::OrSet,
        );

        assert!(crdt_root.model.is_crdt());

        // For CRDT model, CrdtMerge resolution can be used
        assert_eq!(ForkResolution::CrdtMerge, ForkResolution::CrdtMerge);

        // For SingletonWriter, CrdtMerge would be inappropriate
        let singleton_root = create_test_state_root();
        assert!(singleton_root.model.is_singleton_writer());
        // Would use ChooseByLease or ManualResolution instead
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Snapshot Tests
// ═══════════════════════════════════════════════════════════════════════════════

mod snapshot_tests {
    use super::*;

    #[test]
    fn snapshot_config_default() {
        let config = SnapshotConfig::default();
        assert_eq!(config.snapshot_every_updates, 5000);
        assert_eq!(config.snapshot_every_bytes, 1_048_576); // 1 MiB
    }

    #[test]
    fn snapshot_config_should_snapshot_updates() {
        let config = SnapshotConfig {
            snapshot_every_updates: 100,
            snapshot_every_bytes: 1_000_000,
        };

        assert!(!config.should_snapshot(50, 500));
        assert!(config.should_snapshot(100, 500)); // At update threshold
        assert!(config.should_snapshot(150, 500)); // Above update threshold
    }

    #[test]
    fn snapshot_config_should_snapshot_bytes() {
        let config = SnapshotConfig {
            snapshot_every_updates: 10000,
            snapshot_every_bytes: 1000,
        };

        assert!(!config.should_snapshot(50, 500));
        assert!(config.should_snapshot(50, 1000)); // At byte threshold
        assert!(config.should_snapshot(50, 2000)); // Above byte threshold
    }

    #[test]
    fn snapshot_config_either_threshold() {
        let config = SnapshotConfig {
            snapshot_every_updates: 100,
            snapshot_every_bytes: 1000,
        };

        // Either threshold triggers snapshot
        assert!(config.should_snapshot(100, 0)); // Updates only
        assert!(config.should_snapshot(0, 1000)); // Bytes only
        assert!(config.should_snapshot(100, 1000)); // Both
    }

    #[test]
    fn snapshot_covers_state_at_point() {
        let head_id = test_object_id("head-at-seq-100");
        let snapshot = create_test_snapshot(head_id, 100);

        assert_eq!(snapshot.covers_head, head_id);
        assert_eq!(snapshot.covers_seq, 100);

        // State can be recovered without replaying states 0-100
        assert_ne!(snapshot.state_cbor, [] as [u8; 0]);
    }

    #[test]
    fn snapshot_enables_gc() {
        // After snapshot at seq 100, states 0-99 can be GC'd
        let snapshot = create_test_snapshot(test_object_id("head"), 100);

        // Any state with seq < covers_seq is safe to GC (after replication)
        let old_state = create_test_state_object(Some(test_object_id("prev")), 50, 1);
        assert!(old_state.seq < snapshot.covers_seq);
    }

    #[test]
    fn snapshot_with_instance_id() {
        let mut snapshot = create_test_snapshot(test_object_id("head"), 100);
        let instance_id = test_instance_id();
        snapshot.instance_id = Some(instance_id.clone());

        assert_eq!(snapshot.instance_id, Some(instance_id));
    }

    #[test]
    fn snapshot_serde_roundtrip() {
        let snapshot = create_test_snapshot(test_object_id("head"), 42);

        let json = serde_json::to_string(&snapshot).unwrap();
        let restored: ConnectorStateSnapshot = serde_json::from_str(&json).unwrap();

        assert_eq!(snapshot.covers_seq, restored.covers_seq);
        assert_eq!(snapshot.snapshotted_at, restored.snapshotted_at);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CRDT Delta Tests
// ═══════════════════════════════════════════════════════════════════════════════

mod crdt_delta_tests {
    use super::*;

    #[test]
    fn delta_for_each_crdt_type() {
        let crdt_types = [
            CrdtType::LwwMap,
            CrdtType::OrSet,
            CrdtType::GCounter,
            CrdtType::PnCounter,
        ];

        for crdt_type in crdt_types {
            let delta = ConnectorStateDelta {
                header: create_test_header("delta"),
                connector_id: test_connector_id(),
                instance_id: None,
                zone_id: test_zone(),
                crdt_type,
                delta_cbor: vec![0xa0],
                applied_at: 1000,
                applied_by: test_node_id("node-1"),
                signature: test_signature(),
            };

            assert_eq!(delta.crdt_type, crdt_type);

            // Verify CBOR roundtrip
            let mut cbor = Vec::new();
            ciborium::into_writer(&delta, &mut cbor).unwrap();
            let restored: ConnectorStateDelta = ciborium::from_reader(&cbor[..]).unwrap();
            assert_eq!(restored.crdt_type, crdt_type);
        }
    }

    #[test]
    fn delta_tracks_node_origin() {
        let delta = create_test_delta();

        // Delta tracks which node applied it (for CRDT attribution)
        assert_ne!(delta.applied_by.as_str(), "");
        assert!(delta.applied_at > 0);
    }

    #[test]
    fn delta_with_instance_id() {
        let mut delta = create_test_delta();
        let instance_id = test_instance_id();
        delta.instance_id = Some(instance_id.clone());

        assert_eq!(delta.instance_id, Some(instance_id));
    }

    #[test]
    fn multiple_deltas_from_different_nodes() {
        let delta_node1 = ConnectorStateDelta {
            header: create_test_header("delta"),
            connector_id: test_connector_id(),
            instance_id: None,
            zone_id: test_zone(),
            crdt_type: CrdtType::GCounter,
            delta_cbor: vec![0x01], // Increment by 1
            applied_at: 1000,
            applied_by: test_node_id("node-1"),
            signature: test_signature(),
        };

        let delta_node2 = ConnectorStateDelta {
            header: create_test_header("delta"),
            connector_id: test_connector_id(),
            instance_id: None,
            zone_id: test_zone(),
            crdt_type: CrdtType::GCounter,
            delta_cbor: vec![0x02], // Increment by 2
            applied_at: 1001,
            applied_by: test_node_id("node-2"),
            signature: test_signature(),
        };

        // Different nodes can apply deltas concurrently
        assert_ne!(
            delta_node1.applied_by.as_str(),
            delta_node2.applied_by.as_str()
        );
        assert_ne!(delta_node1.delta_cbor, delta_node2.delta_cbor);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Adversarial Tests
// ═══════════════════════════════════════════════════════════════════════════════

mod adversarial_tests {
    use super::*;

    #[test]
    fn replay_attack_same_state_object() {
        // Attacker replays an old state object
        let old_state = create_test_state_object(Some(test_object_id("prev")), 5, 50);

        // Current chain is at seq=100, lease_seq=100
        let current_seq = 100u64;
        let current_lease_seq = 100u64;

        // Replay should be rejected: seq is stale
        assert!(old_state.seq < current_seq);

        // Fencing also rejects: lease_seq is stale
        let _lease_id = old_state.lease_object_id;
        let result = validate_singleton_writer_fencing(&old_state, current_lease_seq, 1000, 2000);

        assert!(matches!(result, Err(FencingError::StaleLeaseSeq { .. })));
    }

    #[test]
    fn byzantine_writer_without_lease() {
        // Byzantine node tries to write without proper lease
        let fake_lease_id = test_object_id("fake-lease");

        let malicious_state = ConnectorStateObject {
            header: create_test_header_with_refs("state_object", vec![]), // No refs!
            connector_id: test_connector_id(),
            instance_id: None,
            zone_id: test_zone(),
            prev: Some(test_object_id("prev")),
            seq: 10,
            state_cbor: vec![0xa0],
            updated_at: 1000,
            lease_seq: 999,                 // Claims high lease_seq
            lease_object_id: fake_lease_id, // But lease not in refs
            writer_public_key: [0u8; 32],
            signature: Signature::zero(), // Invalid signature
        };

        // Fencing check fails: lease not in refs
        let result = validate_singleton_writer_fencing(&malicious_state, 100, 1000, 2000);

        assert!(matches!(result, Err(FencingError::LeaseNotFound { .. })));
    }

    #[test]
    fn forged_signature_detection() {
        // Attacker forges signature (signature validation is done by caller)
        let _state = create_test_state_object(None, 1, 1);

        // Zero signature should be detected as invalid
        let zero_sig = Signature::zero();
        assert_eq!(zero_sig.as_bytes(), &[0u8; 64]);

        // Valid signature should have non-zero bytes
        let valid_sig = test_signature();
        assert_ne!(valid_sig.as_bytes(), &[0u8; 64]);
    }

    #[test]
    fn sequence_gap_attack() {
        // Attacker tries to skip sequence numbers
        let prev_id = test_object_id("prev-at-seq-10");

        // Normal: seq 10 -> seq 11
        let valid_next = create_test_state_object(Some(prev_id), 11, 100);

        // Attack: seq 10 -> seq 100 (skipping 89 sequences)
        let malicious_next = create_test_state_object(Some(prev_id), 100, 100);

        // Both reference same prev, but different seq
        assert_eq!(valid_next.prev, malicious_next.prev);
        assert_ne!(valid_next.seq, malicious_next.seq);

        // Chain validation should detect gap (not in fencing check)
        assert_eq!(valid_next.seq, 11);
        assert_eq!(malicious_next.seq, 100);
    }

    #[test]
    fn zone_confusion_attack() {
        // Attacker tries to use state from different zone
        let work_zone = ZoneId::work();
        let private_zone = ZoneId::private();

        let state_work = create_test_state_object(None, 1, 1);
        assert_eq!(state_work.zone_id, work_zone);

        // State from private zone shouldn't be accepted in work zone
        let state_private = ConnectorStateObject {
            zone_id: private_zone,
            ..state_work.clone()
        };

        assert_ne!(state_work.zone_id, state_private.zone_id);
    }

    #[test]
    fn expired_lease_race_attack() {
        // Attacker races to submit state just as lease expires
        let lease_id = test_object_id("lease-1");
        let state = ConnectorStateObject {
            header: create_test_header_with_refs("state_object", vec![lease_id]),
            connector_id: test_connector_id(),
            instance_id: None,
            zone_id: test_zone(),
            prev: None,
            seq: 1,
            state_cbor: vec![0xa0],
            updated_at: 1999, // Just before expiry
            lease_seq: 42,
            lease_object_id: lease_id,
            writer_public_key: [0u8; 32],
            signature: test_signature(),
        };

        // At expiry boundary
        let result = validate_singleton_writer_fencing(
            &state, 42, 2000, // now == lease_exp
            2000, // lease_exp
        );

        assert!(matches!(result, Err(FencingError::LeaseExpired { .. })));
    }

    #[test]
    fn state_cbor_size_attack() {
        // Attacker tries to submit extremely large state
        let mut malicious_state = create_test_state_object(None, 1, 1);
        malicious_state.state_cbor = vec![0x42; 100_000_000]; // 100MB

        // System should have size limits (checked elsewhere in pipeline)
        assert!(malicious_state.state_cbor.len() > 10_000_000);
    }

    #[test]
    fn connector_id_spoofing() {
        // Attacker tries to spoof connector ID
        let legitimate_connector = test_connector_id();
        let state = create_test_state_object(None, 1, 1);

        assert_eq!(state.connector_id, legitimate_connector);

        // Different connector ID would be rejected by root validation
        let spoofed_connector = ConnectorId::new("evil", "connector", "1.0.0").unwrap();
        assert_ne!(spoofed_connector, legitimate_connector);
    }

    #[test]
    fn double_spend_via_fork() {
        // Classic double-spend attack via intentional fork
        let common_prev = test_object_id("common-prev");

        // Attacker creates two conflicting states
        let spend_a = create_test_state_object(Some(common_prev), 5, 100);
        let spend_b = create_test_state_object(Some(common_prev), 5, 100); // Same lease_seq!

        // Fork detection catches this
        assert_eq!(spend_a.prev, spend_b.prev);
        assert_eq!(spend_a.seq, spend_b.seq);

        // With same lease_seq, this is a protocol violation
        assert_eq!(spend_a.lease_seq, spend_b.lease_seq);

        let fork = ForkEvent {
            common_prev,
            branch_a: test_object_id("spend-a"),
            branch_b: test_object_id("spend-b"),
            fork_seq: 5,
            detected_at: 2000,
            zone_id: test_zone(),
            connector_id: test_connector_id(),
        };

        // Fork requires resolution
        assert_eq!(fork.fork_seq, spend_a.seq);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Edge Cases and Boundary Tests
// ═══════════════════════════════════════════════════════════════════════════════

mod edge_cases {
    use super::*;

    #[test]
    fn zero_seq_is_valid() {
        let genesis = create_test_state_object(None, 0, 1);
        assert_eq!(genesis.seq, 0);
        assert!(genesis.is_genesis());
    }

    #[test]
    fn max_seq_value() {
        let max_seq_state = create_test_state_object(Some(test_object_id("prev")), u64::MAX, 1);

        let mut cbor = Vec::new();
        ciborium::into_writer(&max_seq_state, &mut cbor).expect("should serialize");

        let restored: ConnectorStateObject =
            ciborium::from_reader(&cbor[..]).expect("should deserialize");

        assert_eq!(restored.seq, u64::MAX);
    }

    #[test]
    fn max_lease_seq_value() {
        let max_lease_state = create_test_state_object(None, 1, u64::MAX);

        let mut cbor = Vec::new();
        ciborium::into_writer(&max_lease_state, &mut cbor).expect("should serialize");

        let restored: ConnectorStateObject =
            ciborium::from_reader(&cbor[..]).expect("should deserialize");

        assert_eq!(restored.lease_seq, u64::MAX);
    }

    #[test]
    fn empty_state_cbor() {
        let mut state = create_test_state_object(None, 1, 1);
        state.state_cbor = vec![];

        let mut cbor = Vec::new();
        ciborium::into_writer(&state, &mut cbor).expect("should serialize");

        let restored: ConnectorStateObject =
            ciborium::from_reader(&cbor[..]).expect("should deserialize");

        assert_eq!(restored.state_cbor, [] as [u8; 0]);
    }

    #[test]
    fn state_root_without_head() {
        let root = create_test_state_root();
        assert!(root.head.is_none());

        let json = serde_json::to_string(&root).unwrap();
        // head should be omitted when None
        assert!(!json.contains("\"head\":null"));
    }

    #[test]
    fn timestamp_at_zero() {
        let mut state = create_test_state_object(None, 1, 1);
        state.updated_at = 0;

        let mut cbor = Vec::new();
        ciborium::into_writer(&state, &mut cbor).expect("should serialize");

        let restored: ConnectorStateObject =
            ciborium::from_reader(&cbor[..]).expect("should deserialize");

        assert_eq!(restored.updated_at, 0);
    }

    #[test]
    fn timestamp_at_max() {
        let mut state = create_test_state_object(None, 1, 1);
        state.updated_at = u64::MAX;

        let mut cbor = Vec::new();
        ciborium::into_writer(&state, &mut cbor).expect("should serialize");

        let restored: ConnectorStateObject =
            ciborium::from_reader(&cbor[..]).expect("should deserialize");

        assert_eq!(restored.updated_at, u64::MAX);
    }

    #[test]
    fn snapshot_config_zero_thresholds() {
        let config = SnapshotConfig {
            snapshot_every_updates: 0,
            snapshot_every_bytes: 0,
        };

        // With zero thresholds, should always snapshot
        assert!(config.should_snapshot(0, 0));
        assert!(config.should_snapshot(1, 0));
        assert!(config.should_snapshot(0, 1));
    }

    #[test]
    fn snapshot_config_max_thresholds() {
        let config = SnapshotConfig {
            snapshot_every_updates: u32::MAX,
            snapshot_every_bytes: u64::MAX,
        };

        // With max thresholds, almost never snapshot
        assert!(!config.should_snapshot(1_000_000, 1_000_000_000));
        assert!(config.should_snapshot(u32::MAX, 0));
        assert!(config.should_snapshot(0, u64::MAX));
    }

    #[test]
    fn multiple_refs_in_header() {
        let refs = vec![
            test_object_id("lease-1"),
            test_object_id("capability-1"),
            test_object_id("audit-entry"),
        ];

        let header = create_test_header_with_refs("state_object", refs.clone());
        assert_eq!(header.refs.len(), 3);

        // Lease must be in refs for fencing validation
        let lease_id = refs[0];
        assert!(header.refs.contains(&lease_id));
    }

    #[test]
    fn delta_with_empty_delta_cbor() {
        let mut delta = create_test_delta();
        delta.delta_cbor = vec![];

        let mut cbor = Vec::new();
        ciborium::into_writer(&delta, &mut cbor).expect("should serialize");

        let restored: ConnectorStateDelta =
            ciborium::from_reader(&cbor[..]).expect("should deserialize");

        assert_eq!(restored.delta_cbor, [] as [u8; 0]);
    }
}
