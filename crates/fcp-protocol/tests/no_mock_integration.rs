//! Integration tests for fcp-protocol: FCPS/FCPC frame encoding, session handshake,
//! symbol encryption, and control-plane objects.
//!
//! Uses real crypto keys for signature/encryption roundtrips without
//! external dependencies.

use fcp_crypto::{AeadKey, Ed25519SigningKey, MlDsa65SigningKey, PqSigningPolicy, X25519SecretKey};
use fcp_prelude::{
    ObjectHeader, ObjectId, Provenance, TailscaleNodeId, ZoneId, ZoneIdHash, ZoneKeyId,
};
use fcp_protocol::{
    ControlPlaneObject, ControlPlaneRetention, FcpcFrame, FcpcFrameFlags, FcpcFrameHeader,
    FcpsFrame, FcpsFrameHeader, FrameFlags, MeshSessionAck, MeshSessionHello, MeshSessionId,
    ReplayWindow, SessionCookie, SessionCryptoSuite, SessionDirection, SessionNonce,
    SignedFcpsFrame, SymbolAck, SymbolAckReason, SymbolContext, SymbolRecord, SymbolRequest,
    TransportLimits, ZoneKeyAlgorithm, verify_hybrid_signed_fcps_frame,
};

// ── helpers ──

fn test_zone_id() -> ZoneId {
    ZoneId::work()
}

const fn test_object_id() -> ObjectId {
    ObjectId::from_bytes([1u8; 32])
}

const fn test_zone_key_id() -> ZoneKeyId {
    ZoneKeyId::from_bytes([0xAA; 8])
}

fn test_zone_id_hash() -> ZoneIdHash {
    ZoneId::work().hash()
}

fn test_node_id(name: &str) -> TailscaleNodeId {
    TailscaleNodeId::new(name)
}

fn test_schema() -> fcp_cbor::SchemaId {
    fcp_cbor::SchemaId::new("fcp.test", "TestObject", semver::Version::new(1, 0, 0))
}

fn test_object_header() -> ObjectHeader {
    ObjectHeader {
        schema: test_schema(),
        zone_id: test_zone_id(),
        created_at: 1000,
        provenance: Provenance::new(ZoneId::work()),
        refs: vec![],
        foreign_refs: vec![],
        ttl_secs: None,
        placement: None,
    }
}

fn test_signing_key() -> Ed25519SigningKey {
    Ed25519SigningKey::generate()
}

fn test_pq_signing_key() -> MlDsa65SigningKey {
    MlDsa65SigningKey::generate().expect("ML-DSA signing key")
}

const fn test_aead_key() -> AeadKey {
    AeadKey::from_bytes([42u8; 32])
}

// ── FrameFlags ──

#[test]
fn frame_flags_default() {
    let flags = FrameFlags::default();
    assert!(flags.contains(FrameFlags::ENCRYPTED));
    assert!(flags.contains(FrameFlags::RAPTORQ));
    assert!(!flags.contains(FrameFlags::COMPRESSED));
}

#[test]
fn frame_flags_combine() {
    let flags = FrameFlags::ENCRYPTED | FrameFlags::COMPRESSED | FrameFlags::REQUIRES_ACK;
    assert!(flags.contains(FrameFlags::ENCRYPTED));
    assert!(flags.contains(FrameFlags::COMPRESSED));
    assert!(flags.contains(FrameFlags::REQUIRES_ACK));
    assert!(!flags.contains(FrameFlags::ERROR));
}

#[test]
fn frame_flags_control_plane() {
    let flags = FrameFlags::CONTROL_PLANE | FrameFlags::ENCRYPTED;
    assert!(flags.contains(FrameFlags::CONTROL_PLANE));
}

// ── FcpsFrameHeader ──

#[test]
fn fcps_header_encode_decode_roundtrip() {
    let header = FcpsFrameHeader {
        version: fcp_protocol::FCPS_VERSION,
        flags: FrameFlags::default(),
        symbol_count: 5,
        total_payload_len: 5120,
        object_id: test_object_id(),
        symbol_size: fcp_protocol::DEFAULT_SYMBOL_SIZE,
        zone_key_id: test_zone_key_id(),
        zone_id_hash: test_zone_id_hash(),
        epoch_id: 42,
        sender_instance_id: 100,
        frame_seq: 1,
    };

    let encoded = header.encode();
    assert_eq!(encoded.len(), fcp_protocol::FCPS_HEADER_LEN);

    let decoded = FcpsFrameHeader::decode(&encoded).expect("decode");
    assert_eq!(decoded, header);
}

#[test]
fn fcps_header_decode_too_short() {
    let result = FcpsFrameHeader::decode(&[0u8; 10]);
    assert!(result.is_err());
}

#[test]
fn fcps_header_decode_bad_magic() {
    let mut bytes = [0u8; fcp_protocol::FCPS_HEADER_LEN];
    bytes[0..4].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
    let result = FcpsFrameHeader::decode(&bytes);
    assert!(result.is_err());
}

// ── SymbolRecord ──

#[test]
fn symbol_record_encode_decode_roundtrip() {
    let record = SymbolRecord {
        esi: 42,
        k: 10,
        data: vec![0xAB; 1024],
        auth_tag: [0xCC; 16],
    };

    let encoded = record.encode();
    let decoded = SymbolRecord::decode(&encoded, 1024).expect("decode");
    assert_eq!(decoded.esi, 42);
    assert_eq!(decoded.k, 10);
    assert_eq!(decoded.data, vec![0xAB; 1024]);
    assert_eq!(decoded.auth_tag, [0xCC; 16]);
}

#[test]
fn symbol_record_wire_size() {
    let record = SymbolRecord {
        esi: 0,
        k: 0,
        data: vec![0u8; 1024],
        auth_tag: [0u8; 16],
    };
    assert_eq!(
        record.wire_size(),
        fcp_protocol::SYMBOL_RECORD_OVERHEAD + 1024
    );
}

// ── FcpsFrame ──

#[test]
fn fcps_frame_encode_decode_roundtrip() {
    let header = FcpsFrameHeader {
        version: fcp_protocol::FCPS_VERSION,
        flags: FrameFlags::default(),
        symbol_count: 2,
        total_payload_len: 0, // will be computed
        object_id: test_object_id(),
        symbol_size: 64,
        zone_key_id: test_zone_key_id(),
        zone_id_hash: test_zone_id_hash(),
        epoch_id: 1,
        sender_instance_id: 1,
        frame_seq: 1,
    };

    let symbols = vec![
        SymbolRecord {
            esi: 0,
            k: 10,
            data: vec![0xAA; 64],
            auth_tag: [0x11; 16],
        },
        SymbolRecord {
            esi: 1,
            k: 10,
            data: vec![0xBB; 64],
            auth_tag: [0x22; 16],
        },
    ];

    let frame = FcpsFrame {
        header: FcpsFrameHeader {
            total_payload_len: symbols
                .iter()
                .map(|s| u32::try_from(s.wire_size()).unwrap())
                .sum(),
            ..header
        },
        symbols,
    };

    let encoded = frame.encode().expect("encode");
    let decoded = FcpsFrame::decode(&encoded, 65535).expect("decode");
    assert_eq!(decoded.symbols.len(), 2);
    assert_eq!(decoded.symbols[0].esi, 0);
    assert_eq!(decoded.symbols[1].esi, 1);
    assert_eq!(decoded.symbols[0].data, vec![0xAA; 64]);
}

// ── SignedFcpsFrame ──

#[test]
fn hybrid_signed_frame_sign_and_verify() {
    let signing_key = test_signing_key();
    let pq_signing_key = test_pq_signing_key();
    let header = FcpsFrameHeader {
        version: fcp_protocol::FCPS_VERSION,
        flags: FrameFlags::default(),
        symbol_count: 1,
        total_payload_len: u32::try_from(fcp_protocol::SYMBOL_RECORD_OVERHEAD + 64).unwrap(),
        object_id: test_object_id(),
        symbol_size: 64,
        zone_key_id: test_zone_key_id(),
        zone_id_hash: test_zone_id_hash(),
        epoch_id: 1,
        sender_instance_id: 1,
        frame_seq: 1,
    };
    let frame = FcpsFrame {
        header,
        symbols: vec![SymbolRecord {
            esi: 0,
            k: 5,
            data: vec![0u8; 64],
            auth_tag: [0u8; 16],
        }],
    };

    let source_id = test_node_id("node-1");
    let signed =
        SignedFcpsFrame::new_hybrid(&frame, source_id, 12345, &signing_key, &pq_signing_key)
            .expect("sign");

    verify_hybrid_signed_fcps_frame(
        &signed,
        &signing_key.verifying_key(),
        pq_signing_key.verifying_key(),
        PqSigningPolicy::BothRequired,
        65535,
    )
    .expect("verify should pass");
}

#[test]
fn hybrid_signed_frame_wrong_key_fails() {
    let signing_key = test_signing_key();
    let wrong_key = test_signing_key();
    let pq_signing_key = test_pq_signing_key();
    let frame = FcpsFrame {
        header: FcpsFrameHeader {
            version: fcp_protocol::FCPS_VERSION,
            flags: FrameFlags::default(),
            symbol_count: 0,
            total_payload_len: 0,
            object_id: test_object_id(),
            symbol_size: 64,
            zone_key_id: test_zone_key_id(),
            zone_id_hash: test_zone_id_hash(),
            epoch_id: 1,
            sender_instance_id: 1,
            frame_seq: 1,
        },
        symbols: vec![],
    };

    let signed = SignedFcpsFrame::new_hybrid(
        &frame,
        test_node_id("n1"),
        100,
        &signing_key,
        &pq_signing_key,
    )
    .expect("sign");
    let result = verify_hybrid_signed_fcps_frame(
        &signed,
        &wrong_key.verifying_key(),
        pq_signing_key.verifying_key(),
        PqSigningPolicy::BothRequired,
        65535,
    );
    assert!(result.is_err());
}

// ── DecodeStatus ──

#[test]
fn decode_status_sign_and_verify() {
    let key = test_signing_key();
    let mut status = fcp_protocol::DecodeStatus {
        header: test_object_header(),
        object_id: test_object_id(),
        zone_id: test_zone_id(),
        zone_key_id: test_zone_key_id(),
        epoch_id: 1,
        recipient_node_id: fcp_core::TailscaleNodeId::new("node-proto"),
        request_nonce: 1,
        received_unique: 10,
        needed: 5,
        complete: true,
        missing_hint: None,
        signature: fcp_crypto::Ed25519Signature::from_bytes(&[0u8; 64]),
    };

    status.sign(&key);
    status
        .verify(&key.verifying_key())
        .expect("verify should pass");
}

#[test]
fn decode_status_validate_hint_bounds() {
    let status = fcp_protocol::DecodeStatus {
        header: test_object_header(),
        object_id: test_object_id(),
        zone_id: test_zone_id(),
        zone_key_id: test_zone_key_id(),
        epoch_id: 1,
        recipient_node_id: fcp_core::TailscaleNodeId::new("node-proto"),
        request_nonce: 2,
        received_unique: 10,
        needed: 5,
        complete: false,
        missing_hint: Some(vec![0, 1, 2]),
        signature: fcp_crypto::Ed25519Signature::from_bytes(&[0u8; 64]),
    };
    status.validate_hint_bounds().expect("valid hints");
}

#[test]
fn decode_status_hint_too_many() {
    let many_hints: Vec<u32> =
        (0..=u32::try_from(fcp_protocol::MAX_MISSING_HINT_ENTRIES).unwrap()).collect();
    let status = fcp_protocol::DecodeStatus {
        header: test_object_header(),
        object_id: test_object_id(),
        zone_id: test_zone_id(),
        zone_key_id: test_zone_key_id(),
        epoch_id: 1,
        recipient_node_id: fcp_core::TailscaleNodeId::new("node-proto"),
        request_nonce: 3,
        received_unique: 10,
        needed: 5,
        complete: false,
        missing_hint: Some(many_hints),
        signature: fcp_crypto::Ed25519Signature::from_bytes(&[0u8; 64]),
    };
    let result = status.validate_hint_bounds();
    assert!(result.is_err());
}

// ── SymbolAck ──

#[test]
fn symbol_ack_sign_and_verify() {
    let key = test_signing_key();
    let mut ack = SymbolAck::new(
        test_object_header(),
        test_object_id(),
        test_zone_id(),
        test_zone_key_id(),
        1,
        fcp_core::TailscaleNodeId::new("node-proto"),
        4,
        SymbolAckReason::Complete,
        42,
    );
    ack.sign(&key);
    ack.verify(&key.verifying_key())
        .expect("verify should pass");
}

#[test]
fn symbol_ack_wrong_key_fails() {
    let key = test_signing_key();
    let wrong = test_signing_key();
    let mut ack = SymbolAck::new(
        test_object_header(),
        test_object_id(),
        test_zone_id(),
        test_zone_key_id(),
        1,
        fcp_core::TailscaleNodeId::new("node-proto"),
        5,
        SymbolAckReason::Cancelled,
        10,
    );
    ack.sign(&key);
    assert!(ack.verify(&wrong.verifying_key()).is_err());
}

#[test]
fn symbol_ack_reason_variants() {
    assert_ne!(SymbolAckReason::Complete, SymbolAckReason::Cancelled);
    assert_ne!(SymbolAckReason::Duplicate, SymbolAckReason::BudgetExceeded);
}

// ── SymbolRequest ──

#[test]
fn symbol_request_sign_and_verify() {
    let key = test_signing_key();
    let mut req = SymbolRequest::new(
        test_object_header(),
        test_object_id(),
        test_zone_id(),
        test_zone_key_id(),
        1,
        100,
        5,
    );
    req.sign(&key);
    req.verify(&key.verifying_key())
        .expect("verify should pass");
}

#[test]
fn symbol_request_with_missing_hint() {
    let req = SymbolRequest::new(
        test_object_header(),
        test_object_id(),
        test_zone_id(),
        test_zone_key_id(),
        1,
        50,
        0,
    )
    .with_missing_hint(vec![0, 5, 10]);

    assert_eq!(req.missing_hint.as_ref().unwrap().len(), 3);
    req.validate_hint_bounds().expect("valid hints");
}

#[test]
fn symbol_request_validate_bounds_authenticated() {
    let req = SymbolRequest::new(
        test_object_header(),
        test_object_id(),
        test_zone_id(),
        test_zone_key_id(),
        1,
        fcp_protocol::DEFAULT_MAX_SYMBOLS_AUTHENTICATED,
        0,
    );
    req.validate_bounds(true).expect("authenticated bounds ok");
}

#[test]
fn symbol_request_validate_bounds_unauthenticated() {
    let req = SymbolRequest::new(
        test_object_header(),
        test_object_id(),
        test_zone_id(),
        test_zone_key_id(),
        1,
        fcp_protocol::DEFAULT_MAX_SYMBOLS_UNAUTHENTICATED,
        0,
    );
    req.validate_bounds(false)
        .expect("unauthenticated bounds ok");
}

#[test]
fn symbol_request_has_proof_of_need() {
    let req = SymbolRequest::new(
        test_object_header(),
        test_object_id(),
        test_zone_id(),
        test_zone_key_id(),
        1,
        50,
        10,
    )
    .with_missing_hint(vec![3, 7, 9]);
    // has_proof_of_need is true when missing_hint is Some
    assert!(req.has_proof_of_need());

    let req_no_proof = SymbolRequest::new(
        test_object_header(),
        test_object_id(),
        test_zone_id(),
        test_zone_key_id(),
        1,
        50,
        0,
    );
    // No missing_hint → no proof of need
    assert!(!req_no_proof.has_proof_of_need());
}

// ── MeshSessionId ──

#[test]
fn mesh_session_id_random() {
    let id1 = MeshSessionId::default();
    let id2 = MeshSessionId::default();
    assert_ne!(id1, id2, "random IDs should differ");
}

#[test]
fn mesh_session_id_bytes() {
    let id = MeshSessionId::new();
    let bytes = id.as_bytes();
    assert_eq!(bytes.len(), fcp_protocol::SESSION_ID_SIZE);
}

// ── SessionNonce ──

#[test]
fn session_nonce_random() {
    let n1 = SessionNonce::new();
    let n2 = SessionNonce::new();
    assert_ne!(n1, n2);
}

// ── SessionCryptoSuite ──

#[test]
fn suite_id_roundtrip() {
    let suite = SessionCryptoSuite::Suite1;
    let id = suite.id();
    let back = SessionCryptoSuite::try_from_id(id).expect("valid id");
    assert_eq!(back, suite);
}

#[test]
fn suite_id_invalid() {
    let result = SessionCryptoSuite::try_from_id(0);
    assert!(result.is_err());
    let result = SessionCryptoSuite::try_from_id(99);
    assert!(result.is_err());
}

#[test]
fn suite_as_str() {
    assert_ne!(SessionCryptoSuite::Suite1.as_str(), "");
    assert_ne!(SessionCryptoSuite::Suite2.as_str(), "");
    assert_ne!(
        SessionCryptoSuite::Suite1.as_str(),
        SessionCryptoSuite::Suite2.as_str()
    );
}

// ── negotiate_suite ──

#[test]
fn negotiate_suite_prefers_responder_order() {
    // Initiator offers [Suite2, Suite1]; responder prefers Suite1 (listed first).
    // Responder-picks semantics (see docs/protocol/session-handshake.md) → Suite1 wins.
    let initiator = &[SessionCryptoSuite::Suite2, SessionCryptoSuite::Suite1];
    let responder = &[SessionCryptoSuite::Suite1, SessionCryptoSuite::Suite2];
    let result = fcp_protocol::negotiate_suite(initiator, responder);
    assert_eq!(result, Some(SessionCryptoSuite::Suite1));
}

#[test]
fn negotiate_suite_no_mutual() {
    let initiator = &[SessionCryptoSuite::Suite1];
    let responder = &[SessionCryptoSuite::Suite2];
    let result = fcp_protocol::negotiate_suite(initiator, responder);
    assert_eq!(result, None);
}

#[test]
fn negotiate_suite_empty() {
    let result = fcp_protocol::negotiate_suite(&[], &[SessionCryptoSuite::Suite1]);
    assert_eq!(result, None);
}

// ── SessionDirection ──

#[test]
fn session_direction_values() {
    let i2r = SessionDirection::InitiatorToResponder;
    let r2i = SessionDirection::ResponderToInitiator;
    assert_ne!(i2r.as_u8(), r2i.as_u8());
}

// ── TransportLimits ──

#[test]
fn transport_limits_default() {
    let limits = TransportLimits::default();
    assert_eq!(
        limits.effective_max(),
        fcp_protocol::DEFAULT_MAX_DATAGRAM_BYTES
    );
}

// ── ReplayWindow ──

#[test]
fn replay_window_sequential() {
    let mut window = ReplayWindow::new(128);
    assert!(window.check_and_update(1));
    assert!(window.check_and_update(2));
    assert!(window.check_and_update(3));
    assert_eq!(window.highest_seq(), 3);
}

#[test]
fn replay_window_rejects_replay() {
    let mut window = ReplayWindow::new(128);
    assert!(window.check_and_update(1));
    assert!(!window.check_and_update(1), "replay should be rejected");
}

#[test]
fn replay_window_allows_reorder_within_window() {
    let mut window = ReplayWindow::new(128);
    assert!(window.check_and_update(5));
    assert!(window.check_and_update(3)); // out of order but within window
    assert!(window.check_and_update(4));
    assert!(!window.check_and_update(3), "already seen");
}

#[test]
fn replay_window_rejects_old_beyond_window() {
    let mut window = ReplayWindow::new(128);
    for i in 1..=200 {
        window.check_and_update(i);
    }
    // Seq 1 is now beyond the window
    assert!(!window.check_and_update(1));
}

// ── MeshSessionHello ──

#[test]
fn hello_sign_and_verify() {
    let signing_key = test_signing_key();
    let eph = X25519SecretKey::generate();
    let mut hello = MeshSessionHello {
        from: test_node_id("initiator"),
        to: test_node_id("responder"),
        eph_pubkey: eph.public_key(),
        nonce: SessionNonce::new(),
        cookie: None,
        timestamp: fcp_protocol::current_timestamp(),
        suites: vec![SessionCryptoSuite::Suite1, SessionCryptoSuite::Suite2],
        transport_limits: None,
        signature: None,
    };

    hello.sign(&signing_key).expect("sign");
    assert!(hello.signature.is_some());

    hello.verify(&signing_key.verifying_key()).expect("verify");
}

#[test]
fn hello_wrong_key_fails() {
    let key = test_signing_key();
    let wrong = test_signing_key();
    let eph = X25519SecretKey::generate();
    let mut hello = MeshSessionHello {
        from: test_node_id("a"),
        to: test_node_id("b"),
        eph_pubkey: eph.public_key(),
        nonce: SessionNonce::new(),
        cookie: None,
        timestamp: fcp_protocol::current_timestamp(),
        suites: vec![SessionCryptoSuite::Suite1],
        transport_limits: None,
        signature: None,
    };

    hello.sign(&key).expect("sign");
    assert!(hello.verify(&wrong.verifying_key()).is_err());
}

// ── MeshSessionAck ──

#[test]
fn ack_sign_and_verify_with_hello() {
    let init_key = test_signing_key();
    let resp_key = test_signing_key();
    let init_eph = X25519SecretKey::generate();
    let resp_eph = X25519SecretKey::generate();

    let mut hello = MeshSessionHello {
        from: test_node_id("init"),
        to: test_node_id("resp"),
        eph_pubkey: init_eph.public_key(),
        nonce: SessionNonce::new(),
        cookie: None,
        timestamp: fcp_protocol::current_timestamp(),
        suites: vec![SessionCryptoSuite::Suite1],
        transport_limits: None,
        signature: None,
    };
    hello.sign(&init_key).expect("sign hello");

    let mut ack = MeshSessionAck {
        from: test_node_id("resp"),
        to: test_node_id("init"),
        eph_pubkey: resp_eph.public_key(),
        nonce: SessionNonce::new(),
        session_id: MeshSessionId::new(),
        suite: SessionCryptoSuite::Suite1,
        timestamp: fcp_protocol::current_timestamp(),
        signature: None,
    };
    ack.sign(&hello, &resp_key).expect("sign ack");
    ack.verify(&hello, &resp_key.verifying_key())
        .expect("verify ack");
}

// ── Session key derivation ──

#[test]
fn derive_session_keys_deterministic() {
    let init_eph = X25519SecretKey::generate();
    let resp_eph = X25519SecretKey::generate();
    let shared = init_eph.diffie_hellman(&resp_eph.public_key()).unwrap();

    let session_id = MeshSessionId::new();
    let init_node = test_node_id("init");
    let resp_node = test_node_id("resp");
    let hello_nonce = SessionNonce::new();
    let ack_nonce = SessionNonce::new();

    let keys1 = fcp_protocol::derive_session_keys(
        &shared,
        SessionCryptoSuite::Suite1,
        &session_id,
        &init_node,
        &resp_node,
        &hello_nonce,
        &ack_nonce,
    )
    .expect("derive");

    let keys2 = fcp_protocol::derive_session_keys(
        &shared,
        SessionCryptoSuite::Suite1,
        &session_id,
        &init_node,
        &resp_node,
        &hello_nonce,
        &ack_nonce,
    )
    .expect("derive");

    assert_eq!(keys1, keys2, "same inputs → same keys");
}

#[test]
fn session_keys_directional() {
    let init_eph = X25519SecretKey::generate();
    let resp_eph = X25519SecretKey::generate();
    let shared = init_eph.diffie_hellman(&resp_eph.public_key()).unwrap();

    let keys = fcp_protocol::derive_session_keys(
        &shared,
        SessionCryptoSuite::Suite1,
        &MeshSessionId::new(),
        &test_node_id("i"),
        &test_node_id("r"),
        &SessionNonce::new(),
        &SessionNonce::new(),
    )
    .expect("derive");

    let i2r_key = keys.mac_key(SessionDirection::InitiatorToResponder);
    let r2i_key = keys.mac_key(SessionDirection::ResponderToInitiator);
    assert_ne!(i2r_key, r2i_key, "directional MAC keys should differ");
}

// ── Session MAC ──

#[test]
fn session_mac_roundtrip_suite1() {
    let session_id = MeshSessionId::new();
    let mac_key = [0x42u8; 32];
    let frame_bytes = b"test frame data";

    let mac = fcp_protocol::compute_session_mac(
        SessionCryptoSuite::Suite1,
        &mac_key,
        &session_id,
        SessionDirection::InitiatorToResponder,
        1,
        frame_bytes,
    )
    .expect("compute");

    fcp_protocol::verify_session_mac(
        SessionCryptoSuite::Suite1,
        &mac_key,
        &session_id,
        SessionDirection::InitiatorToResponder,
        1,
        frame_bytes,
        &mac,
    )
    .expect("verify");
}

#[test]
fn session_mac_roundtrip_suite2() {
    let session_id = MeshSessionId::new();
    let mac_key = [0x77u8; 32];
    let frame_bytes = b"suite2 frame data";

    let mac = fcp_protocol::compute_session_mac(
        SessionCryptoSuite::Suite2,
        &mac_key,
        &session_id,
        SessionDirection::ResponderToInitiator,
        99,
        frame_bytes,
    )
    .expect("compute");

    fcp_protocol::verify_session_mac(
        SessionCryptoSuite::Suite2,
        &mac_key,
        &session_id,
        SessionDirection::ResponderToInitiator,
        99,
        frame_bytes,
        &mac,
    )
    .expect("verify");
}

#[test]
fn session_mac_wrong_key_fails() {
    let session_id = MeshSessionId::new();
    let mac_key = [0x42u8; 32];
    let wrong_key = [0x99u8; 32];
    let frame_bytes = b"test";

    let mac = fcp_protocol::compute_session_mac(
        SessionCryptoSuite::Suite1,
        &mac_key,
        &session_id,
        SessionDirection::InitiatorToResponder,
        1,
        frame_bytes,
    )
    .expect("compute");

    let result = fcp_protocol::verify_session_mac(
        SessionCryptoSuite::Suite1,
        &wrong_key,
        &session_id,
        SessionDirection::InitiatorToResponder,
        1,
        frame_bytes,
        &mac,
    );
    assert!(result.is_err());
}

// ── Cookie ──

#[test]
fn cookie_compute_and_verify() {
    let cookie_key = [0xBB; 32];
    let eph = X25519SecretKey::generate();
    let hello = MeshSessionHello {
        from: test_node_id("a"),
        to: test_node_id("b"),
        eph_pubkey: eph.public_key(),
        nonce: SessionNonce::new(),
        cookie: None,
        timestamp: fcp_protocol::current_timestamp(),
        suites: vec![SessionCryptoSuite::Suite1],
        transport_limits: None,
        signature: None,
    };

    let cookie = fcp_protocol::compute_cookie(&cookie_key, &hello).expect("compute");
    fcp_protocol::verify_cookie(&cookie_key, &hello, &cookie).expect("verify");
}

#[test]
fn cookie_wrong_key_fails() {
    let key = [0xBB; 32];
    let wrong = [0xCC; 32];
    let eph = X25519SecretKey::generate();
    let hello = MeshSessionHello {
        from: test_node_id("a"),
        to: test_node_id("b"),
        eph_pubkey: eph.public_key(),
        nonce: SessionNonce::new(),
        cookie: None,
        timestamp: fcp_protocol::current_timestamp(),
        suites: vec![SessionCryptoSuite::Suite1],
        transport_limits: None,
        signature: None,
    };

    let cookie = fcp_protocol::compute_cookie(&key, &hello).expect("compute");
    let result = fcp_protocol::verify_cookie(&wrong, &hello, &cookie);
    assert!(result.is_err());
}

#[test]
fn session_cookie_try_from_slice() {
    let bytes = [0xAA; 32];
    let cookie = SessionCookie::try_from_slice(&bytes).expect("valid");
    assert_eq!(cookie.as_bytes(), &bytes);
}

#[test]
fn session_cookie_wrong_length() {
    let result = SessionCookie::try_from_slice(&[0u8; 16]);
    assert!(result.is_err());
}

// ── FcpcFrame ──

#[test]
fn fcpc_frame_seal_and_open() {
    let session_id = MeshSessionId::new();
    let k_ctx = [0x42u8; 32];
    let plaintext = b"hello control plane";

    let frame = FcpcFrame::seal(
        session_id,
        1,
        SessionDirection::InitiatorToResponder,
        FcpcFrameFlags::ENCRYPTED,
        plaintext,
        &k_ctx,
    )
    .expect("seal");

    let decrypted = frame
        .open(SessionDirection::InitiatorToResponder, &k_ctx)
        .expect("open");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn fcpc_frame_wrong_key_fails() {
    let session_id = MeshSessionId::new();
    let k_ctx = [0x42u8; 32];
    let wrong_key = [0x99u8; 32];

    let frame = FcpcFrame::seal(
        session_id,
        1,
        SessionDirection::InitiatorToResponder,
        FcpcFrameFlags::ENCRYPTED,
        b"secret",
        &k_ctx,
    )
    .expect("seal");

    let result = frame.open(SessionDirection::InitiatorToResponder, &wrong_key);
    assert!(result.is_err());
}

#[test]
fn fcpc_frame_encode_decode_roundtrip() {
    let session_id = MeshSessionId::new();
    let k_ctx = [0x42u8; 32];

    let frame = FcpcFrame::seal(
        session_id,
        1,
        SessionDirection::InitiatorToResponder,
        FcpcFrameFlags::ENCRYPTED,
        b"test payload",
        &k_ctx,
    )
    .expect("seal");

    let encoded = frame.encode();
    let decoded = FcpcFrame::decode(&encoded).expect("decode");
    assert_eq!(decoded.header.session_id, session_id);
    assert_eq!(decoded.header.seq, 1);
}

#[test]
fn fcpc_frame_replay_detection() {
    let session_id = MeshSessionId::new();
    let k_ctx = [0x42u8; 32];

    let frame = FcpcFrame::seal(
        session_id,
        5,
        SessionDirection::InitiatorToResponder,
        FcpcFrameFlags::ENCRYPTED,
        b"data",
        &k_ctx,
    )
    .expect("seal");

    let mut window = fcp_protocol::default_replay_window();
    frame.check_replay(&mut window).expect("first check");
    let result = frame.check_replay(&mut window);
    assert!(result.is_err(), "replay should be rejected");
}

#[test]
fn fcpc_header_encode_decode() {
    let header = FcpcFrameHeader {
        version: fcp_protocol::FCPC_VERSION,
        session_id: MeshSessionId::new(),
        seq: 42,
        flags: FcpcFrameFlags::ENCRYPTED,
        len: 1024,
    };

    let encoded = header.encode();
    assert_eq!(encoded.len(), fcp_protocol::FCPC_HEADER_LEN);
    let decoded = FcpcFrameHeader::decode(&encoded).expect("decode");
    assert_eq!(decoded, header);
}

// ── Symbol Envelope (encryption) ──

#[test]
fn symbol_encrypt_decrypt_chacha20() {
    let zone_key = test_aead_key();
    let ctx = SymbolContext {
        object_id: test_object_id(),
        esi: 0,
        k: 10,
        zone_id_hash: test_zone_id_hash(),
        zone_key_id: test_zone_key_id(),
        epoch_id: 1,
        sender_node_id: test_node_id("sender"),
        sender_instance_id: 42,
        frame_seq: 1,
    };

    let plaintext = b"symbol data for testing";
    let (ciphertext, tag) = fcp_protocol::encrypt_symbol(
        &zone_key,
        ZoneKeyAlgorithm::ChaCha20Poly1305,
        &ctx,
        plaintext,
    )
    .expect("encrypt");

    let decrypted = fcp_protocol::decrypt_symbol(
        &zone_key,
        ZoneKeyAlgorithm::ChaCha20Poly1305,
        &ctx,
        &ciphertext,
        &tag,
    )
    .expect("decrypt");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn symbol_encrypt_decrypt_xchacha20() {
    let zone_key = test_aead_key();
    let ctx = SymbolContext {
        object_id: test_object_id(),
        esi: 5,
        k: 20,
        zone_id_hash: test_zone_id_hash(),
        zone_key_id: test_zone_key_id(),
        epoch_id: 99,
        sender_node_id: test_node_id("sender"),
        sender_instance_id: 100,
        frame_seq: 7,
    };

    let plaintext = b"xchacha20 test data";
    let (ciphertext, tag) = fcp_protocol::encrypt_symbol(
        &zone_key,
        ZoneKeyAlgorithm::XChaCha20Poly1305,
        &ctx,
        plaintext,
    )
    .expect("encrypt");

    let decrypted = fcp_protocol::decrypt_symbol(
        &zone_key,
        ZoneKeyAlgorithm::XChaCha20Poly1305,
        &ctx,
        &ciphertext,
        &tag,
    )
    .expect("decrypt");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn symbol_wrong_key_fails() {
    let zone_key = test_aead_key();
    let wrong_key = AeadKey::from_bytes([0x99; 32]);
    let ctx = SymbolContext {
        object_id: test_object_id(),
        esi: 0,
        k: 10,
        zone_id_hash: test_zone_id_hash(),
        zone_key_id: test_zone_key_id(),
        epoch_id: 1,
        sender_node_id: test_node_id("s"),
        sender_instance_id: 1,
        frame_seq: 1,
    };

    let (ciphertext, tag) = fcp_protocol::encrypt_symbol(
        &zone_key,
        ZoneKeyAlgorithm::ChaCha20Poly1305,
        &ctx,
        b"secret",
    )
    .expect("encrypt");

    let result = fcp_protocol::decrypt_symbol(
        &wrong_key,
        ZoneKeyAlgorithm::ChaCha20Poly1305,
        &ctx,
        &ciphertext,
        &tag,
    );
    assert!(result.is_err());
}

#[test]
fn symbol_tampered_ciphertext_fails() {
    let zone_key = test_aead_key();
    let ctx = SymbolContext {
        object_id: test_object_id(),
        esi: 0,
        k: 10,
        zone_id_hash: test_zone_id_hash(),
        zone_key_id: test_zone_key_id(),
        epoch_id: 1,
        sender_node_id: test_node_id("s"),
        sender_instance_id: 1,
        frame_seq: 1,
    };

    let (mut ciphertext, tag) = fcp_protocol::encrypt_symbol(
        &zone_key,
        ZoneKeyAlgorithm::ChaCha20Poly1305,
        &ctx,
        b"original",
    )
    .expect("encrypt");

    // Tamper with ciphertext
    if let Some(byte) = ciphertext.first_mut() {
        *byte ^= 0xFF;
    }

    let result = fcp_protocol::decrypt_symbol(
        &zone_key,
        ZoneKeyAlgorithm::ChaCha20Poly1305,
        &ctx,
        &ciphertext,
        &tag,
    );
    assert!(result.is_err());
}

#[test]
fn symbol_aad_binding() {
    let zone_key = test_aead_key();
    let ctx1 = SymbolContext {
        object_id: test_object_id(),
        esi: 0,
        k: 10,
        zone_id_hash: test_zone_id_hash(),
        zone_key_id: test_zone_key_id(),
        epoch_id: 1,
        sender_node_id: test_node_id("s"),
        sender_instance_id: 1,
        frame_seq: 1,
    };

    let ctx2 = SymbolContext {
        esi: 1, // different ESI
        ..ctx1.clone()
    };

    let (ciphertext, tag) = fcp_protocol::encrypt_symbol(
        &zone_key,
        ZoneKeyAlgorithm::ChaCha20Poly1305,
        &ctx1,
        b"bound data",
    )
    .expect("encrypt");

    // Decrypting with different AAD (different ESI) should fail
    let result = fcp_protocol::decrypt_symbol(
        &zone_key,
        ZoneKeyAlgorithm::ChaCha20Poly1305,
        &ctx2,
        &ciphertext,
        &tag,
    );
    assert!(result.is_err(), "different AAD should reject");
}

#[test]
fn sender_subkey_derivation_unique() {
    let zone_key = test_aead_key();
    let zone_key_id = test_zone_key_id();

    let k1 =
        fcp_protocol::derive_sender_subkey(&zone_key, &zone_key_id, &test_node_id("node-a"), 1);
    let k2 =
        fcp_protocol::derive_sender_subkey(&zone_key, &zone_key_id, &test_node_id("node-b"), 1);
    let k3 =
        fcp_protocol::derive_sender_subkey(&zone_key, &zone_key_id, &test_node_id("node-a"), 2);

    assert_ne!(
        k1.as_bytes(),
        k2.as_bytes(),
        "different node → different key"
    );
    assert_ne!(
        k1.as_bytes(),
        k3.as_bytes(),
        "different instance → different key"
    );
}

#[test]
fn nonce12_deterministic() {
    let n1 = fcp_protocol::derive_nonce12(1, 0);
    let n2 = fcp_protocol::derive_nonce12(1, 0);
    assert_eq!(n1.as_bytes(), n2.as_bytes());

    let n3 = fcp_protocol::derive_nonce12(1, 1);
    assert_ne!(n1.as_bytes(), n3.as_bytes());
}

#[test]
fn nonce24_deterministic() {
    let n1 = fcp_protocol::derive_nonce24(1, 1, 0);
    let n2 = fcp_protocol::derive_nonce24(1, 1, 0);
    assert_eq!(n1.as_bytes(), n2.as_bytes());

    let n3 = fcp_protocol::derive_nonce24(2, 1, 0);
    assert_ne!(n1.as_bytes(), n3.as_bytes());
}

// ── Control-Plane Objects ──

#[test]
fn control_plane_object_new() {
    let header = test_object_header();
    let body = vec![0xAB; 32];
    let obj = ControlPlaneObject::new(header, body.clone());
    assert_eq!(obj.body, body);
}

#[test]
fn control_plane_retention_classification() {
    let audit_schema =
        fcp_cbor::SchemaId::new("fcp.audit", "AuditEvent", semver::Version::new(1, 0, 0));
    assert_eq!(
        fcp_protocol::retention_for_schema(&audit_schema),
        ControlPlaneRetention::Required
    );
    assert!(fcp_protocol::requires_storage(&audit_schema));
}

// ── FcpsDatagram ──

#[test]
fn fcps_datagram_encode_decode() {
    let datagram = fcp_protocol::FcpsDatagram {
        session_id: MeshSessionId::new(),
        seq: 7,
        mac: [0xAA; fcp_protocol::SESSION_MAC_SIZE],
        frame_bytes: vec![0xBB; 100],
    };

    let encoded = datagram.encode();
    let decoded =
        fcp_protocol::FcpsDatagram::decode(&encoded, fcp_protocol::DEFAULT_MAX_DATAGRAM_BYTES)
            .expect("decode");
    assert_eq!(decoded.seq, 7);
    assert_eq!(decoded.frame_bytes, vec![0xBB; 100]);
}

// ── Error display ──

#[test]
fn frame_error_display() {
    let err = fcp_protocol::FrameError::TooShort { len: 10, min: 114 };
    assert_ne!(err.to_string(), "");
}

#[test]
fn session_error_display() {
    let err = fcp_protocol::SessionError::NoMutualSuite;
    assert_ne!(err.to_string(), "");
}

#[test]
fn fcpc_error_display() {
    let err = fcp_protocol::FcpcError::ReplayRejected { seq: 42 };
    assert!(err.to_string().contains("42"));
}

#[test]
fn symbol_envelope_error_display() {
    let err = fcp_protocol::SymbolEnvelopeError::DecryptFailed;
    assert_ne!(err.to_string(), "");
}

// ── build_symbol_aad ──

#[test]
fn symbol_aad_size() {
    let ctx = SymbolContext {
        object_id: test_object_id(),
        esi: 0,
        k: 10,
        zone_id_hash: test_zone_id_hash(),
        zone_key_id: test_zone_key_id(),
        epoch_id: 1,
        sender_node_id: test_node_id("s"),
        sender_instance_id: 1,
        frame_seq: 1,
    };
    let aad = fcp_protocol::build_symbol_aad(&ctx);
    assert_eq!(aad.len(), fcp_protocol::SYMBOL_AAD_SIZE);
}

// ── ZoneKeyAlgorithm ──

#[test]
fn zone_key_algorithm_default() {
    let alg = ZoneKeyAlgorithm::default();
    assert_eq!(alg, ZoneKeyAlgorithm::ChaCha20Poly1305);
}
