#![no_main]

use std::sync::Arc;

use arbitrary::{Arbitrary, Unstructured};
use bytes::Bytes;
use fcp_async_core::runtime::block_on_sync;
use fcp_cbor::SchemaId;
use fcp_core::{ObjectHeader, ObjectId, Provenance, TailscaleNodeId, ZoneId, ZoneKeyId};
use fcp_crypto::Ed25519SigningKey;
use fcp_mesh::{MeshNode, MeshNodeConfig, SymbolRequestError};
use fcp_protocol::{SymbolAck, SymbolAckReason, SymbolRequest};
use fcp_raptorq::ObjectTransmissionInformation;
use fcp_store::{
    MemoryObjectStore, MemoryObjectStoreConfig, MemorySymbolStore, MemorySymbolStoreConfig,
    ObjectAdmissionPolicy, ObjectSymbolMeta, ObjectTransmissionInfo, QuarantineStore, StoredSymbol,
    SymbolMeta,
};
use fcp_tailscale::NodeId;
use libfuzzer_sys::fuzz_target;
use semver::Version;
use serde::Deserialize;

const TRACKED_OBJECT_ID: [u8; 32] = [0x11; 32];

#[derive(Arbitrary, Debug, Deserialize)]
struct SymbolAckInput {
    now_ms: u64,
    epoch_id: u64,
    request_nonce: u64,
    final_symbol_count: u32,
    use_tracked_object: bool,
    object_id: [u8; 32],
    reason_mode: u8,
}

fn test_node() -> MeshNode {
    let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
    let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
    let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));
    MeshNode::new(
        MeshNodeConfig::new("node-1").with_sender_instance_id(11),
        object_store,
        symbol_store,
        quarantine_store,
    )
}

fn test_zone_id() -> ZoneId {
    ZoneId::work()
}

fn test_object_header() -> ObjectHeader {
    let zone_id = test_zone_id();
    ObjectHeader {
        schema: SchemaId::new("fcp.test", "TestObject", Version::new(1, 0, 0)),
        zone_id: zone_id.clone(),
        created_at: 1_704_067_200,
        provenance: Provenance::new(zone_id),
        refs: vec![],
        foreign_refs: vec![],
        ttl_secs: None,
        placement: None,
    }
}

fn test_request(object_id: ObjectId) -> SymbolRequest {
    SymbolRequest::new(
        test_object_header(),
        object_id,
        test_zone_id(),
        ZoneKeyId::from_bytes([0x22; 8]),
        1,
        2,
        0,
    )
}

fn install_symbol_data(node: &MeshNode, object_id: ObjectId) -> bool {
    let zone_id = test_zone_id();
    let oti = ObjectTransmissionInformation::new(128, 64, 1, 1, 8);
    let meta = ObjectSymbolMeta {
        object_id,
        zone_id: zone_id.clone(),
        oti: ObjectTransmissionInfo::from(oti),
        source_symbols: 2,
        first_symbol_at: 0,
    };

    block_on_sync(async {
        node.symbol_store().put_object_meta(meta).await?;
        for esi in 0..2u32 {
            let symbol = StoredSymbol {
                meta: SymbolMeta {
                    object_id,
                    esi,
                    zone_id: zone_id.clone(),
                    source_node: Some(1),
                    stored_at: 0,
                },
                data: Bytes::from(vec![u8::try_from(esi).unwrap_or(0); 64]),
            };
            node.symbol_store().put_symbol(symbol).await?;
        }
        Ok::<(), fcp_store::SymbolStoreError>(())
    })
    .is_ok()
}

fn seed_active_transfer(
    node: &mut MeshNode,
    object_id: ObjectId,
    peer: &NodeId,
    now_ms: u64,
) -> bool {
    if !install_symbol_data(node, object_id) {
        return false;
    }

    block_on_sync(async {
        node.handle_symbol_request(test_request(object_id), peer, true, now_ms)
            .await
            .map(|_| ())
    })
    .is_ok()
}

fn follow_up_result(
    node: &mut MeshNode,
    object_id: ObjectId,
    now_ms: u64,
) -> Result<(), SymbolRequestError> {
    block_on_sync(async {
        node.handle_symbol_request(
            test_request(object_id),
            &NodeId::new("peer-follow"),
            true,
            now_ms,
        )
        .await
        .map(|_| ())
    })
    .unwrap_or_else(|_| Ok(()))
}

fn target_object_id(use_tracked_object: bool, raw: [u8; 32]) -> ObjectId {
    if use_tracked_object {
        ObjectId::from_bytes(TRACKED_OBJECT_ID)
    } else if raw == TRACKED_OBJECT_ID {
        ObjectId::from_bytes([0xFD; 32])
    } else {
        ObjectId::from_bytes(raw)
    }
}

fn ack_reason(reason_mode: u8) -> SymbolAckReason {
    match reason_mode % 4 {
        0 => SymbolAckReason::Complete,
        1 => SymbolAckReason::Cancelled,
        2 => SymbolAckReason::Duplicate,
        _ => SymbolAckReason::BudgetExceeded,
    }
}

fuzz_target!(|data: &[u8]| {
    let input = if let Ok(seed) = serde_json::from_slice::<SymbolAckInput>(data) {
        seed
    } else {
        let mut unstructured = Unstructured::new(data);
        let Ok(seed) = SymbolAckInput::arbitrary(&mut unstructured) else {
            return;
        };
        seed
    };

    let tracked_object = ObjectId::from_bytes(TRACKED_OBJECT_ID);
    let mut node = test_node();
    let peer = NodeId::new("peer-1");
    let signing_key = match Ed25519SigningKey::from_bytes(&[11u8; 32]) {
        Ok(key) => key,
        Err(_) => return,
    };
    node.register_peer_signing_key(peer.clone(), signing_key.verifying_key());

    if !seed_active_transfer(&mut node, tracked_object, &peer, 0) {
        return;
    }

    let target_object = target_object_id(input.use_tracked_object, input.object_id);
    let mut ack = SymbolAck::new(
        test_object_header(),
        target_object,
        test_zone_id(),
        ZoneKeyId::from_bytes([0x22; 8]),
        input.epoch_id,
        TailscaleNodeId::new("node-1"),
        input.request_nonce,
        ack_reason(input.reason_mode),
        input.final_symbol_count,
    );
    ack.sign(&signing_key);

    let before_acks = node.metrics().symbol_requests.acks_received;
    let result = node.handle_symbol_ack(&peer, &ack, input.now_ms);
    assert!(
        result.is_ok(),
        "valid signature should reach post-verify symbol-ack handling"
    );
    assert_eq!(
        node.metrics().symbol_requests.acks_received,
        before_acks.saturating_add(1)
    );

    let follow = follow_up_result(&mut node, tracked_object, input.now_ms.saturating_add(1));
    if input.use_tracked_object {
        assert!(
            matches!(follow, Err(SymbolRequestError::AlreadyComplete { .. })),
            "known ack should stop later requests for the same object"
        );
    } else {
        assert!(
            !matches!(follow, Err(SymbolRequestError::AlreadyComplete { .. })),
            "unknown ack must not stop later requests for the tracked object"
        );
    }
});
