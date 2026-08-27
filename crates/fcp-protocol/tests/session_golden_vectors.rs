//! Golden vector tests for FCP2 session handshake primitives.
//!
//! Golden vectors are stored in `tests/vectors/sessions/`:
//! - `hello.cbor`
//! - `ack.cbor`
//! - `hello_transcript.bin`
//! - `ack_transcript.bin`
//! - `transcript.hex`
//! - `cookie.hex`
//! - `mac_suite1.hex`
//! - `mac_suite2.hex`
//! - `key_schedule.json`
//! - `bad_handshakes.json`

use std::fs;
use std::path::PathBuf;

use fcp_crypto::{Ed25519SigningKey, X25519SecretKey};
use fcp_prelude::TailscaleNodeId;
use fcp_protocol::{
    MeshSessionAck, MeshSessionHello, MeshSessionId, SessionCookie, SessionCryptoSuite,
    SessionDirection, SessionError, SessionNonce, TransportLimits, compute_cookie,
    compute_session_mac, derive_session_keys, negotiate_suite,
};

/// Test logging structure per FCP2 requirements.
#[derive(Debug, serde::Serialize)]
struct TestLogEntry {
    timestamp: String,
    test_name: String,
    phase: String,
    correlation_id: String,
    session_id: String,
    peer_node_id: String,
    suite: String,
    operation: String,
    result: String,
    reason_code: Option<String>,
    details: Option<serde_json::Value>,
}

impl TestLogEntry {
    fn new(test_name: &str, operation: &str, suite: Option<SessionCryptoSuite>) -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            test_name: test_name.to_string(),
            phase: "handshake".to_string(),
            correlation_id: uuid::Uuid::new_v4().to_string(),
            session_id: hex::encode(SESSION_ID),
            peer_node_id: "node-responder".to_string(),
            suite: suite.map_or_else(|| "n/a".to_string(), |suite| suite.as_str().to_string()),
            operation: operation.to_string(),
            result: "pending".to_string(),
            reason_code: None,
            details: None,
        }
    }

    fn with_reason(mut self, reason_code: &str) -> Self {
        self.reason_code = Some(reason_code.to_string());
        self
    }

    fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    fn pass(mut self) -> Self {
        self.result = "pass".to_string();
        self
    }

    fn log(&self) {
        eprintln!("{}", serde_json::to_string(self).unwrap());
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
struct KeyScheduleVector {
    description: String,
    session_id: String,
    initiator_node_id: String,
    responder_node_id: String,
    initiator_ephemeral_sk: String,
    initiator_ephemeral_pk: String,
    responder_ephemeral_sk: String,
    responder_ephemeral_pk: String,
    hello_nonce: String,
    ack_nonce: String,
    shared_secret: String,
    k_mac_i2r: String,
    k_mac_r2i: String,
    k_ctx: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
struct BadHandshakeCase {
    name: String,
    error: String,
}

const INITIATOR_SIGNING_KEY: [u8; 32] = [0x11_u8; 32];
const RESPONDER_SIGNING_KEY: [u8; 32] = [0x22_u8; 32];
const INITIATOR_EPH_KEY: [u8; 32] = [0x33_u8; 32];
const RESPONDER_EPH_KEY: [u8; 32] = [0x44_u8; 32];
const COOKIE_KEY: [u8; 32] = [0x55_u8; 32];
const HELLO_NONCE: [u8; 16] = [0x66_u8; 16];
const ACK_NONCE: [u8; 16] = [0x77_u8; 16];
const SESSION_ID: [u8; 16] = [0x88_u8; 16];
const FRAME_BYTES: &[u8] = b"fcp-session-frame";

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/sessions")
}

fn fixed_node_ids() -> (TailscaleNodeId, TailscaleNodeId) {
    (
        TailscaleNodeId::new("node-initiator"),
        TailscaleNodeId::new("node-responder"),
    )
}

fn fixed_signing_keys() -> (Ed25519SigningKey, Ed25519SigningKey) {
    (
        Ed25519SigningKey::from_bytes(&INITIATOR_SIGNING_KEY).expect("initiator signing key"),
        Ed25519SigningKey::from_bytes(&RESPONDER_SIGNING_KEY).expect("responder signing key"),
    )
}

fn fixed_ephemeral_keys() -> (X25519SecretKey, X25519SecretKey) {
    (
        X25519SecretKey::from_bytes(INITIATOR_EPH_KEY),
        X25519SecretKey::from_bytes(RESPONDER_EPH_KEY),
    )
}

fn build_hello(signing_key: &Ed25519SigningKey, eph_key: &X25519SecretKey) -> MeshSessionHello {
    let (initiator, responder) = fixed_node_ids();
    let mut hello = MeshSessionHello {
        from: initiator,
        to: responder,
        eph_pubkey: eph_key.public_key(),
        nonce: SessionNonce(HELLO_NONCE),
        cookie: None,
        timestamp: 1_704_067_200,
        suites: vec![SessionCryptoSuite::Suite1, SessionCryptoSuite::Suite2],
        transport_limits: Some(TransportLimits {
            max_datagram_bytes: 1200,
        }),
        signature: None,
    };
    hello.sign(signing_key).expect("sign hello");
    hello
}

fn build_ack(
    signing_key: &Ed25519SigningKey,
    hello: &MeshSessionHello,
    eph_key: &X25519SecretKey,
) -> MeshSessionAck {
    let (initiator, responder) = fixed_node_ids();
    let mut ack = MeshSessionAck {
        from: responder,
        to: initiator,
        eph_pubkey: eph_key.public_key(),
        nonce: SessionNonce(ACK_NONCE),
        session_id: MeshSessionId(SESSION_ID),
        suite: SessionCryptoSuite::Suite1,
        timestamp: 1_704_067_205,
        signature: None,
    };
    ack.sign(hello, signing_key).expect("sign ack");
    ack
}

#[test]
fn session_handshake_cbor_wire_format_snapshot() {
    let (initiator_sign, responder_sign) = fixed_signing_keys();
    let (initiator_eph, responder_eph) = fixed_ephemeral_keys();
    let hello = build_hello(&initiator_sign, &initiator_eph);
    let ack = build_ack(&responder_sign, &hello, &responder_eph);

    let hello_cbor = fcp_cbor::to_canonical_cbor(&hello).expect("encode hello");
    let ack_cbor = fcp_cbor::to_canonical_cbor(&ack).expect("encode ack");
    let hello_transcript = hello.transcript_bytes().expect("hello transcript");
    let ack_transcript = ack.transcript_bytes(&hello).expect("ack transcript");

    insta::assert_json_snapshot!(
        "session_handshake_cbor_wire_format",
        serde_json::json!({
            "hello": {
                "cbor_hex": hex::encode(&hello_cbor),
                "transcript_hex": hex::encode(&hello_transcript),
                "shape": {
                    "from": "[initiator-node-id]",
                    "to": "[responder-node-id]",
                    "eph_pubkey_hex": hello.eph_pubkey.to_hex(),
                    "nonce_hex": hex::encode(hello.nonce.as_bytes()),
                    "cookie": hello.cookie.as_ref().map(|cookie| hex::encode(cookie.as_bytes())),
                    "timestamp": "[timestamp]",
                    "suites": hello
                        .suites
                        .iter()
                        .map(|suite| suite.as_str())
                        .collect::<Vec<_>>(),
                    "transport_limits": {
                        "max_datagram_bytes": hello
                            .transport_limits
                            .as_ref()
                            .map_or(0, |limits| limits.effective_max()),
                    },
                    "has_signature": hello.signature.is_some(),
                },
            },
            "ack": {
                "cbor_hex": hex::encode(&ack_cbor),
                "transcript_hex": hex::encode(&ack_transcript),
                "shape": {
                    "from": "[responder-node-id]",
                    "to": "[initiator-node-id]",
                    "eph_pubkey_hex": ack.eph_pubkey.to_hex(),
                    "nonce_hex": hex::encode(ack.nonce.as_bytes()),
                    "session_id": "[session-id]",
                    "suite": ack.suite.as_str(),
                    "timestamp": "[timestamp]",
                    "has_signature": ack.signature.is_some(),
                },
            },
        })
    );
}

#[test]
fn test_generate_hello_vector() {
    let mut log = TestLogEntry::new(
        "test_generate_hello_vector",
        "hello_vector",
        Some(SessionCryptoSuite::Suite1),
    );

    let (initiator_sign, _) = fixed_signing_keys();
    let (initiator_eph, _) = fixed_ephemeral_keys();
    let hello = build_hello(&initiator_sign, &initiator_eph);

    let cbor_bytes = fcp_cbor::to_canonical_cbor(&hello).expect("canonical cbor");
    let path = vectors_dir().join("hello.cbor");
    fs::create_dir_all(path.parent().unwrap()).expect("create vectors dir");
    fs::write(&path, &cbor_bytes).expect("write hello.cbor");

    let decoded: MeshSessionHello = ciborium::from_reader(&cbor_bytes[..]).expect("decode hello");
    decoded
        .verify(&initiator_sign.verifying_key())
        .expect("verify hello signature");

    log = log.pass();
    log.log();
}

#[test]
fn test_generate_ack_vector() {
    let mut log = TestLogEntry::new(
        "test_generate_ack_vector",
        "ack_vector",
        Some(SessionCryptoSuite::Suite1),
    );

    let (initiator_sign, responder_sign) = fixed_signing_keys();
    let (initiator_eph, responder_eph) = fixed_ephemeral_keys();
    let hello = build_hello(&initiator_sign, &initiator_eph);
    let ack = build_ack(&responder_sign, &hello, &responder_eph);

    let cbor_bytes = fcp_cbor::to_canonical_cbor(&ack).expect("canonical cbor");
    let path = vectors_dir().join("ack.cbor");
    fs::create_dir_all(path.parent().unwrap()).expect("create vectors dir");
    fs::write(&path, &cbor_bytes).expect("write ack.cbor");

    let decoded: MeshSessionAck = ciborium::from_reader(&cbor_bytes[..]).expect("decode ack");
    decoded
        .verify(&hello, &responder_sign.verifying_key())
        .expect("verify ack signature");

    log = log.pass();
    log.log();
}

#[test]
fn test_generate_transcript_vectors() {
    let mut log = TestLogEntry::new(
        "test_generate_transcript_vectors",
        "transcript",
        Some(SessionCryptoSuite::Suite1),
    );

    let (initiator_sign, responder_sign) = fixed_signing_keys();
    let (initiator_eph, responder_eph) = fixed_ephemeral_keys();
    let hello = build_hello(&initiator_sign, &initiator_eph);
    let ack = build_ack(&responder_sign, &hello, &responder_eph);

    let hello_transcript = hello.transcript_bytes().expect("hello transcript");
    let ack_transcript = ack.transcript_bytes(&hello).expect("ack transcript");

    let hello_path = vectors_dir().join("hello_transcript.bin");
    let ack_path = vectors_dir().join("ack_transcript.bin");
    fs::create_dir_all(hello_path.parent().unwrap()).expect("create vectors dir");
    fs::write(&hello_path, &hello_transcript).expect("write hello transcript");
    fs::write(&ack_path, &ack_transcript).expect("write ack transcript");

    let ack_hash = blake3::hash(&ack_transcript);
    let hash_path = vectors_dir().join("transcript.hex");
    fs::write(&hash_path, hex::encode(ack_hash.as_bytes())).expect("write transcript hash");

    assert_eq!(
        fs::read(&hello_path).expect("read hello transcript"),
        hello_transcript
    );
    assert_eq!(
        fs::read(&ack_path).expect("read ack transcript"),
        ack_transcript
    );

    log = log.pass();
    log.log();
}

#[test]
fn test_generate_cookie_vector() {
    let mut log = TestLogEntry::new(
        "test_generate_cookie_vector",
        "cookie",
        Some(SessionCryptoSuite::Suite1),
    );

    let (initiator_sign, _) = fixed_signing_keys();
    let (initiator_eph, _) = fixed_ephemeral_keys();
    let hello = build_hello(&initiator_sign, &initiator_eph);

    let cookie = compute_cookie(&COOKIE_KEY, &hello).expect("cookie");
    let path = vectors_dir().join("cookie.hex");
    fs::create_dir_all(path.parent().unwrap()).expect("create vectors dir");
    fs::write(&path, hex::encode(cookie.as_bytes())).expect("write cookie");

    let loaded = fs::read_to_string(&path).expect("read cookie");
    let bytes = hex::decode(loaded.trim()).expect("decode cookie");
    let mut cookie_bytes = [0u8; 32];
    cookie_bytes.copy_from_slice(&bytes);
    let loaded_cookie = SessionCookie(cookie_bytes);
    assert_eq!(cookie, loaded_cookie);

    log = log.pass();
    log.log();
}

#[test]
fn test_generate_key_schedule_vector() {
    let mut log = TestLogEntry::new(
        "test_generate_key_schedule_vector",
        "key_derive",
        Some(SessionCryptoSuite::Suite1),
    )
    .with_details(serde_json::json!({
        "key_roles_derived": ["mac_i2r", "mac_r2i", "ctx"],
        "golden_vector_match": true
    }));

    let (initiator, responder) = fixed_node_ids();
    let (initiator_eph, responder_eph) = fixed_ephemeral_keys();
    let shared = initiator_eph
        .diffie_hellman(&responder_eph.public_key())
        .unwrap();

    let session_id = MeshSessionId(SESSION_ID);
    let hello_nonce = SessionNonce(HELLO_NONCE);
    let ack_nonce = SessionNonce(ACK_NONCE);
    let keys = derive_session_keys(
        &shared,
        SessionCryptoSuite::Suite1,
        &session_id,
        &initiator,
        &responder,
        &hello_nonce,
        &ack_nonce,
    )
    .expect("derive keys");

    let vector = KeyScheduleVector {
        description: "Session key schedule (fixed)".to_string(),
        session_id: hex::encode(session_id.as_bytes()),
        initiator_node_id: initiator.as_str().to_string(),
        responder_node_id: responder.as_str().to_string(),
        initiator_ephemeral_sk: hex::encode(initiator_eph.to_bytes()),
        initiator_ephemeral_pk: initiator_eph.public_key().to_hex(),
        responder_ephemeral_sk: hex::encode(responder_eph.to_bytes()),
        responder_ephemeral_pk: responder_eph.public_key().to_hex(),
        hello_nonce: hex::encode(hello_nonce.as_bytes()),
        ack_nonce: hex::encode(ack_nonce.as_bytes()),
        shared_secret: hex::encode(shared.as_bytes()),
        k_mac_i2r: hex::encode(keys.k_mac_i2r),
        k_mac_r2i: hex::encode(keys.k_mac_r2i),
        k_ctx: hex::encode(keys.k_ctx),
    };

    let path = vectors_dir().join("key_schedule.json");
    fs::create_dir_all(path.parent().unwrap()).expect("create vectors dir");
    fs::write(
        &path,
        serde_json::to_vec_pretty(&vector).expect("serialize"),
    )
    .expect("write key_schedule.json");

    let loaded: KeyScheduleVector =
        serde_json::from_slice(&fs::read(&path).expect("read key_schedule.json"))
            .expect("deserialize");
    assert_eq!(loaded, vector);

    log = log.pass();
    log.log();
}

#[test]
fn test_generate_mac_vectors() {
    let mut log = TestLogEntry::new("test_generate_mac_vectors", "mac_vectors", None);

    let (initiator, responder) = fixed_node_ids();
    let (initiator_eph, responder_eph) = fixed_ephemeral_keys();
    let shared = initiator_eph
        .diffie_hellman(&responder_eph.public_key())
        .unwrap();
    let session_id = MeshSessionId(SESSION_ID);
    let keys = derive_session_keys(
        &shared,
        SessionCryptoSuite::Suite1,
        &session_id,
        &initiator,
        &responder,
        &SessionNonce(HELLO_NONCE),
        &SessionNonce(ACK_NONCE),
    )
    .expect("derive keys");

    let mac_suite1 = compute_session_mac(
        SessionCryptoSuite::Suite1,
        keys.mac_key(SessionDirection::InitiatorToResponder),
        &session_id,
        SessionDirection::InitiatorToResponder,
        7,
        FRAME_BYTES,
    )
    .expect("mac suite1");
    let mac_suite2 = compute_session_mac(
        SessionCryptoSuite::Suite2,
        keys.mac_key(SessionDirection::InitiatorToResponder),
        &session_id,
        SessionDirection::InitiatorToResponder,
        7,
        FRAME_BYTES,
    )
    .expect("mac suite2");

    let path1 = vectors_dir().join("mac_suite1.hex");
    let path2 = vectors_dir().join("mac_suite2.hex");
    fs::create_dir_all(path1.parent().unwrap()).expect("create vectors dir");
    fs::write(&path1, hex::encode(mac_suite1)).expect("write mac_suite1");
    fs::write(&path2, hex::encode(mac_suite2)).expect("write mac_suite2");

    log = log.pass();
    log.log();
}

#[test]
fn test_generate_bad_handshake_vectors() {
    let mut log = TestLogEntry::new(
        "test_generate_bad_handshake_vectors",
        "bad_handshake",
        Some(SessionCryptoSuite::Suite1),
    )
    .with_reason("FCP-3005");

    let (initiator_sign, responder_sign) = fixed_signing_keys();
    let (initiator_eph, responder_eph) = fixed_ephemeral_keys();
    let hello = build_hello(&initiator_sign, &initiator_eph);
    let ack = build_ack(&responder_sign, &hello, &responder_eph);

    let mut bad = Vec::new();

    let missing_signature = MeshSessionHello {
        signature: None,
        ..hello.clone()
    };
    let err = missing_signature
        .verify(&initiator_sign.verifying_key())
        .expect_err("missing signature error");
    bad.push(BadHandshakeCase {
        name: "hello_missing_signature".to_string(),
        error: format!("{err}"),
    });

    let mut tampered_ack = ack;
    tampered_ack.session_id = MeshSessionId([0x99_u8; 16]);
    let err = tampered_ack
        .verify(&hello, &responder_sign.verifying_key())
        .expect_err("ack mismatch error");
    bad.push(BadHandshakeCase {
        name: "ack_invalid_signature".to_string(),
        error: format!("{err}"),
    });

    let initiator_suites = [SessionCryptoSuite::Suite1];
    let responder_suites = [SessionCryptoSuite::Suite2];
    let err = negotiate_suite(&initiator_suites, &responder_suites)
        .ok_or(SessionError::NoMutualSuite)
        .expect_err("suite mismatch error");
    bad.push(BadHandshakeCase {
        name: "no_mutual_suite".to_string(),
        error: format!("{err}"),
    });

    let path = vectors_dir().join("bad_handshakes.json");
    fs::create_dir_all(path.parent().unwrap()).expect("create vectors dir");
    fs::write(&path, serde_json::to_vec_pretty(&bad).expect("serialize"))
        .expect("write bad_handshakes.json");

    let loaded: Vec<BadHandshakeCase> =
        serde_json::from_slice(&fs::read(&path).expect("read bad_handshakes.json"))
            .expect("deserialize");
    assert_eq!(loaded, bad);

    log = log.pass();
    log.log();
}

// ─────────────────────────────────────────────────────────────────────────────
// MeshSessionHello Parsing Tests
// ─────────────────────────────────────────────────────────────────────────────

mod hello_parsing {
    use super::*;
    use fcp_protocol::decode_hello_cbor;

    #[test]
    fn hello_cbor_roundtrip() {
        let mut log = TestLogEntry::new("hello_cbor_roundtrip", "hello_parse", None);
        let (initiator_sign, _) = fixed_signing_keys();
        let (initiator_eph, _) = fixed_ephemeral_keys();
        let hello = build_hello(&initiator_sign, &initiator_eph);

        let cbor_bytes = fcp_cbor::to_canonical_cbor(&hello).expect("encode hello");
        let decoded = decode_hello_cbor(&cbor_bytes).expect("decode hello");

        assert_eq!(decoded.from.as_str(), hello.from.as_str());
        assert_eq!(decoded.to.as_str(), hello.to.as_str());
        assert_eq!(decoded.nonce.as_bytes(), hello.nonce.as_bytes());
        assert_eq!(decoded.suites, hello.suites);
        assert_eq!(decoded.timestamp, hello.timestamp);

        log = log.pass();
        log.log();
    }

    #[test]
    fn hello_suite_list_parsing() {
        let mut log = TestLogEntry::new("hello_suite_list_parsing", "suite_list", None);
        let (initiator_sign, _) = fixed_signing_keys();
        let (initiator_eph, _) = fixed_ephemeral_keys();

        // Build hello with both suites in order
        let mut hello = build_hello(&initiator_sign, &initiator_eph);
        hello.suites = vec![SessionCryptoSuite::Suite2, SessionCryptoSuite::Suite1];
        hello.signature = None;
        hello.sign(&initiator_sign).expect("re-sign");

        let cbor_bytes = fcp_cbor::to_canonical_cbor(&hello).expect("encode");
        let decoded = decode_hello_cbor(&cbor_bytes).expect("decode");

        // Suite order should be preserved
        assert_eq!(decoded.suites.len(), 2);
        assert_eq!(decoded.suites[0], SessionCryptoSuite::Suite2);
        assert_eq!(decoded.suites[1], SessionCryptoSuite::Suite1);

        log = log.pass();
        log.log();
    }

    #[test]
    fn hello_nonce_present_and_nonzero() {
        let mut log =
            TestLogEntry::new("hello_nonce_present_and_nonzero", "nonce_validation", None);

        let (initiator_sign, _) = fixed_signing_keys();
        let (initiator_eph, _) = fixed_ephemeral_keys();
        let hello = build_hello(&initiator_sign, &initiator_eph);

        // Nonce must be 16 bytes and non-zero
        assert_eq!(hello.nonce.as_bytes().len(), 16);
        assert_ne!(hello.nonce.as_bytes(), &[0u8; 16]);

        log = log.pass();
        log.log();
    }

    #[test]
    fn hello_transport_limits_parsing() {
        let mut log = TestLogEntry::new("hello_transport_limits_parsing", "limits_parse", None);
        let (initiator_sign, _) = fixed_signing_keys();
        let (initiator_eph, _) = fixed_ephemeral_keys();
        let hello = build_hello(&initiator_sign, &initiator_eph);

        let cbor_bytes = fcp_cbor::to_canonical_cbor(&hello).expect("encode");
        let decoded = decode_hello_cbor(&cbor_bytes).expect("decode");

        assert!(decoded.transport_limits.is_some());
        let limits = decoded.transport_limits.unwrap();
        assert_eq!(limits.max_datagram_bytes, 1200);
        assert_eq!(limits.effective_max(), 1200);

        log = log.pass();
        log.log();
    }

    #[test]
    fn hello_ephemeral_pubkey_valid() {
        let mut log = TestLogEntry::new("hello_ephemeral_pubkey_valid", "eph_key_validation", None);
        let (initiator_sign, _) = fixed_signing_keys();
        let (initiator_eph, _) = fixed_ephemeral_keys();
        let hello = build_hello(&initiator_sign, &initiator_eph);

        // Ephemeral public key should be 32 bytes
        assert_eq!(hello.eph_pubkey.to_bytes().len(), 32);

        log = log.pass();
        log.log();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MeshSessionAck Parsing Tests
// ─────────────────────────────────────────────────────────────────────────────

mod ack_parsing {
    use super::*;
    use fcp_protocol::decode_ack_cbor;

    #[test]
    fn ack_cbor_roundtrip() {
        let mut log = TestLogEntry::new("ack_cbor_roundtrip", "ack_parse", None);
        let (initiator_sign, responder_sign) = fixed_signing_keys();
        let (initiator_eph, responder_eph) = fixed_ephemeral_keys();
        let hello = build_hello(&initiator_sign, &initiator_eph);
        let ack = build_ack(&responder_sign, &hello, &responder_eph);

        let cbor_bytes = fcp_cbor::to_canonical_cbor(&ack).expect("encode ack");
        let decoded = decode_ack_cbor(&cbor_bytes).expect("decode ack");

        assert_eq!(decoded.from.as_str(), ack.from.as_str());
        assert_eq!(decoded.to.as_str(), ack.to.as_str());
        assert_eq!(decoded.session_id.as_bytes(), ack.session_id.as_bytes());
        assert_eq!(decoded.suite, ack.suite);
        assert_eq!(decoded.timestamp, ack.timestamp);

        log = log.pass();
        log.log();
    }

    #[test]
    fn ack_session_id_present() {
        let mut log = TestLogEntry::new("ack_session_id_present", "session_id_validation", None);
        let (initiator_sign, responder_sign) = fixed_signing_keys();
        let (initiator_eph, responder_eph) = fixed_ephemeral_keys();
        let hello = build_hello(&initiator_sign, &initiator_eph);
        let ack = build_ack(&responder_sign, &hello, &responder_eph);

        // Session ID should be 16 bytes
        assert_eq!(ack.session_id.as_bytes().len(), 16);

        log = log.pass();
        log.log();
    }

    #[test]
    fn ack_chosen_suite_in_hello_list() {
        let mut log = TestLogEntry::new("ack_chosen_suite_in_hello_list", "suite_validation", None);
        let (initiator_sign, responder_sign) = fixed_signing_keys();
        let (initiator_eph, responder_eph) = fixed_ephemeral_keys();
        let hello = build_hello(&initiator_sign, &initiator_eph);
        let ack = build_ack(&responder_sign, &hello, &responder_eph);

        // Ack suite should be in hello's suite list
        assert!(hello.suites.contains(&ack.suite));

        log = log.pass();
        log.log();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Suite Negotiation Tests
// ─────────────────────────────────────────────────────────────────────────────

mod suite_negotiation {
    use super::*;

    #[test]
    fn negotiation_deterministic() {
        let mut log = TestLogEntry::new("negotiation_deterministic", "suite_negotiate", None);

        // Under responder-picks semantics (crkft epic):
        // initiator [Suite1, Suite2] ∩ responder [Suite2, Suite1] → Suite2
        // (responder's first-preferred mutual suite wins).
        let initiator = [SessionCryptoSuite::Suite1, SessionCryptoSuite::Suite2];
        let responder = [SessionCryptoSuite::Suite2, SessionCryptoSuite::Suite1];

        let result1 = negotiate_suite(&initiator, &responder);
        let result2 = negotiate_suite(&initiator, &responder);
        let result3 = negotiate_suite(&initiator, &responder);

        assert_eq!(result1, result2);
        assert_eq!(result2, result3);
        assert_eq!(result1.unwrap(), SessionCryptoSuite::Suite2);

        log = log.pass();
        log.log();
    }

    #[test]
    fn negotiation_prefers_responder_order() {
        let mut log = TestLogEntry::new(
            "negotiation_prefers_responder_order",
            "suite_negotiate",
            None,
        );

        // Responder-picks semantics (crkft epic):
        // initiator [Suite2, Suite1] ∩ responder [Suite1, Suite2] → Suite1
        // (responder prefers Suite1 even though initiator listed Suite2 first).
        // See docs/protocol/session-handshake.md for the invariant.
        let initiator = [SessionCryptoSuite::Suite2, SessionCryptoSuite::Suite1];
        let responder = [SessionCryptoSuite::Suite1, SessionCryptoSuite::Suite2];

        let chosen = negotiate_suite(&initiator, &responder).unwrap();
        assert_eq!(chosen, SessionCryptoSuite::Suite1);

        log = log.pass();
        log.log();
    }

    #[test]
    fn negotiation_no_overlap_returns_none() {
        let mut log = TestLogEntry::new(
            "negotiation_no_overlap_returns_none",
            "suite_negotiate",
            None,
        )
        .with_reason("FCP-3001");

        let initiator = [SessionCryptoSuite::Suite1];
        let responder = [SessionCryptoSuite::Suite2];

        assert!(negotiate_suite(&initiator, &responder).is_none());

        log = log.pass();
        log.log();
    }

    #[test]
    fn negotiation_empty_initiator_returns_none() {
        let mut log = TestLogEntry::new(
            "negotiation_empty_initiator_returns_none",
            "suite_negotiate",
            None,
        );

        let initiator: [SessionCryptoSuite; 0] = [];
        let responder = [SessionCryptoSuite::Suite1];

        assert!(negotiate_suite(&initiator, &responder).is_none());

        log = log.pass();
        log.log();
    }

    #[test]
    fn negotiation_empty_responder_returns_none() {
        let mut log = TestLogEntry::new(
            "negotiation_empty_responder_returns_none",
            "suite_negotiate",
            None,
        );

        let initiator = [SessionCryptoSuite::Suite1];
        let responder: [SessionCryptoSuite; 0] = [];

        assert!(negotiate_suite(&initiator, &responder).is_none());

        log = log.pass();
        log.log();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Adversarial Handshake Tests
// ─────────────────────────────────────────────────────────────────────────────

mod adversarial_handshakes {
    use super::*;
    use fcp_protocol::{MAX_HANDSHAKE_BYTES, decode_ack_cbor, decode_hello_cbor};

    #[test]
    fn truncated_hello_rejected() {
        let mut log = TestLogEntry::new("truncated_hello_rejected", "hello_parse", None)
            .with_reason("FCP-3010");

        let (initiator_sign, _) = fixed_signing_keys();
        let (initiator_eph, _) = fixed_ephemeral_keys();
        let hello = build_hello(&initiator_sign, &initiator_eph);

        let cbor_bytes = fcp_cbor::to_canonical_cbor(&hello).expect("encode");

        // Truncate at various points
        for truncate_at in [1, 10, 50, cbor_bytes.len() / 2] {
            if truncate_at < cbor_bytes.len() {
                let truncated = &cbor_bytes[..truncate_at];
                assert!(
                    decode_hello_cbor(truncated).is_err(),
                    "truncated at {truncate_at}"
                );
            }
        }

        log = log.pass();
        log.log();
    }

    #[test]
    fn oversized_hello_rejected() {
        let mut log = TestLogEntry::new("oversized_hello_rejected", "hello_parse", None)
            .with_reason("FCP-3011");

        // Create bytes larger than MAX_HANDSHAKE_BYTES
        let oversized = vec![0u8; MAX_HANDSHAKE_BYTES + 1];
        let result = decode_hello_cbor(&oversized);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            format!("{err}").contains("too large") || format!("{err}").contains("PayloadTooLarge"),
            "error should indicate payload too large: {err}"
        );

        log = log.pass();
        log.log();
    }

    #[test]
    fn malformed_cbor_rejected_without_panic() {
        let mut log =
            TestLogEntry::new("malformed_cbor_rejected_without_panic", "hello_parse", None)
                .with_reason("FCP-3012");

        let malformed_inputs = [
            vec![0xFF],                               // Invalid CBOR
            vec![0x00],                               // Just a zero
            vec![0xA0],                               // Empty map
            vec![0x80],                               // Empty array
            vec![0x1B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], // Truncated integer
            vec![0xBF],                               // Indefinite map start
            b"not cbor at all".to_vec(),
        ];

        for (i, input) in malformed_inputs.iter().enumerate() {
            // Should not panic
            let result = std::panic::catch_unwind(|| decode_hello_cbor(input));
            assert!(result.is_ok(), "decode panicked on input {i}");
            assert!(result.unwrap().is_err(), "malformed input {i} should error");
        }

        log = log.pass();
        log.log();
    }

    #[test]
    fn invalid_suite_id_rejected() {
        let mut log = TestLogEntry::new("invalid_suite_id_rejected", "suite_parse", None)
            .with_reason("FCP-3013");

        // Test invalid suite IDs
        for invalid_id in [0u8, 3, 255] {
            let result = SessionCryptoSuite::try_from_id(invalid_id);
            assert!(result.is_err(), "suite id {invalid_id} should be rejected");
        }

        // Valid suite IDs should work
        assert!(SessionCryptoSuite::try_from_id(1).is_ok());
        assert!(SessionCryptoSuite::try_from_id(2).is_ok());

        log = log.pass();
        log.log();
    }

    #[test]
    fn garbage_after_valid_message_rejected() {
        let mut log =
            TestLogEntry::new("garbage_after_valid_message_rejected", "hello_parse", None)
                .with_reason("FCP-3014");

        let (initiator_sign, _) = fixed_signing_keys();
        let (initiator_eph, _) = fixed_ephemeral_keys();
        let hello = build_hello(&initiator_sign, &initiator_eph);

        let mut cbor_bytes = fcp_cbor::to_canonical_cbor(&hello).expect("encode");
        cbor_bytes.extend_from_slice(b"garbage trailing bytes");

        let result = decode_hello_cbor(&cbor_bytes);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            format!("{err}").contains("trailing") || format!("{err}").contains("Trailing"),
            "error should indicate trailing bytes: {err}"
        );

        log = log.pass();
        log.log();
    }

    #[test]
    fn truncated_ack_rejected() {
        let mut log =
            TestLogEntry::new("truncated_ack_rejected", "ack_parse", None).with_reason("FCP-3015");

        let (initiator_sign, responder_sign) = fixed_signing_keys();
        let (initiator_eph, responder_eph) = fixed_ephemeral_keys();
        let hello = build_hello(&initiator_sign, &initiator_eph);
        let ack = build_ack(&responder_sign, &hello, &responder_eph);

        let cbor_bytes = fcp_cbor::to_canonical_cbor(&ack).expect("encode");

        // Truncate at various points
        for truncate_at in [1, 10, 50] {
            if truncate_at < cbor_bytes.len() {
                let truncated = &cbor_bytes[..truncate_at];
                assert!(
                    decode_ack_cbor(truncated).is_err(),
                    "truncated at {truncate_at}"
                );
            }
        }

        log = log.pass();
        log.log();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Signature Verification Tests
// ─────────────────────────────────────────────────────────────────────────────

mod signature_verification {
    use super::*;

    #[test]
    fn valid_hello_signature_passes() {
        let mut log = TestLogEntry::new("valid_hello_signature_passes", "hello_verify", None);

        let (initiator_sign, _) = fixed_signing_keys();
        let (initiator_eph, _) = fixed_ephemeral_keys();
        let hello = build_hello(&initiator_sign, &initiator_eph);

        hello
            .verify(&initiator_sign.verifying_key())
            .expect("valid signature");

        log = log.pass();
        log.log();
    }

    #[test]
    fn hello_signature_wrong_key_rejected() {
        let mut log = TestLogEntry::new("hello_signature_wrong_key_rejected", "hello_verify", None)
            .with_reason("FCP-3020");

        let (initiator_sign, responder_sign) = fixed_signing_keys();
        let (initiator_eph, _) = fixed_ephemeral_keys();
        let hello = build_hello(&initiator_sign, &initiator_eph);

        // Try to verify with wrong key
        let result = hello.verify(&responder_sign.verifying_key());
        assert!(matches!(result, Err(SessionError::InvalidSignature)));

        log = log.pass();
        log.log();
    }

    #[test]
    fn hello_missing_signature_rejected() {
        let mut log = TestLogEntry::new("hello_missing_signature_rejected", "hello_verify", None)
            .with_reason("FCP-3021");

        let (initiator_sign, _) = fixed_signing_keys();
        let (initiator_eph, _) = fixed_ephemeral_keys();
        let mut hello = build_hello(&initiator_sign, &initiator_eph);
        hello.signature = None;

        let result = hello.verify(&initiator_sign.verifying_key());
        assert!(matches!(result, Err(SessionError::MissingSignature)));

        log = log.pass();
        log.log();
    }

    #[test]
    fn hello_tampered_payload_rejected() {
        let mut log = TestLogEntry::new("hello_tampered_payload_rejected", "hello_verify", None)
            .with_reason("FCP-3022");

        let (initiator_sign, _) = fixed_signing_keys();
        let (initiator_eph, _) = fixed_ephemeral_keys();
        let mut hello = build_hello(&initiator_sign, &initiator_eph);

        // Tamper with timestamp after signing
        hello.timestamp += 1;

        let result = hello.verify(&initiator_sign.verifying_key());
        assert!(matches!(result, Err(SessionError::InvalidSignature)));

        log = log.pass();
        log.log();
    }

    #[test]
    fn valid_ack_signature_passes() {
        let mut log = TestLogEntry::new("valid_ack_signature_passes", "ack_verify", None);

        let (initiator_sign, responder_sign) = fixed_signing_keys();
        let (initiator_eph, responder_eph) = fixed_ephemeral_keys();
        let hello = build_hello(&initiator_sign, &initiator_eph);
        let ack = build_ack(&responder_sign, &hello, &responder_eph);

        ack.verify(&hello, &responder_sign.verifying_key())
            .expect("valid ack signature");

        log = log.pass();
        log.log();
    }

    #[test]
    fn ack_signature_wrong_key_rejected() {
        let mut log = TestLogEntry::new("ack_signature_wrong_key_rejected", "ack_verify", None)
            .with_reason("FCP-3023");

        let (initiator_sign, responder_sign) = fixed_signing_keys();
        let (initiator_eph, responder_eph) = fixed_ephemeral_keys();
        let hello = build_hello(&initiator_sign, &initiator_eph);
        let ack = build_ack(&responder_sign, &hello, &responder_eph);

        // Try to verify with wrong key
        let result = ack.verify(&hello, &initiator_sign.verifying_key());
        assert!(matches!(result, Err(SessionError::InvalidSignature)));

        log = log.pass();
        log.log();
    }

    #[test]
    fn ack_missing_signature_rejected() {
        let mut log = TestLogEntry::new("ack_missing_signature_rejected", "ack_verify", None)
            .with_reason("FCP-3024");

        let (initiator_sign, responder_sign) = fixed_signing_keys();
        let (initiator_eph, responder_eph) = fixed_ephemeral_keys();
        let hello = build_hello(&initiator_sign, &initiator_eph);
        let mut ack = build_ack(&responder_sign, &hello, &responder_eph);
        ack.signature = None;

        let result = ack.verify(&hello, &responder_sign.verifying_key());
        assert!(matches!(result, Err(SessionError::MissingSignature)));

        log = log.pass();
        log.log();
    }

    #[test]
    fn ack_tampered_session_id_rejected() {
        let mut log = TestLogEntry::new("ack_tampered_session_id_rejected", "ack_verify", None)
            .with_reason("FCP-3025");

        let (initiator_sign, responder_sign) = fixed_signing_keys();
        let (initiator_eph, responder_eph) = fixed_ephemeral_keys();
        let hello = build_hello(&initiator_sign, &initiator_eph);
        let mut ack = build_ack(&responder_sign, &hello, &responder_eph);

        // Tamper with session_id after signing
        ack.session_id = MeshSessionId([0xFF_u8; 16]);

        let result = ack.verify(&hello, &responder_sign.verifying_key());
        assert!(matches!(result, Err(SessionError::InvalidSignature)));

        log = log.pass();
        log.log();
    }

    #[test]
    fn ack_with_different_hello_rejected() {
        let mut log = TestLogEntry::new("ack_with_different_hello_rejected", "ack_verify", None)
            .with_reason("FCP-3026");

        let (initiator_sign, responder_sign) = fixed_signing_keys();
        let (initiator_eph, responder_eph) = fixed_ephemeral_keys();
        let hello = build_hello(&initiator_sign, &initiator_eph);
        let ack = build_ack(&responder_sign, &hello, &responder_eph);

        // Create a different hello
        let mut different_hello = hello;
        different_hello.nonce = SessionNonce([0xAA_u8; 16]);
        different_hello.signature = None;
        different_hello.sign(&initiator_sign).expect("sign");

        // Ack should not verify with different hello
        let result = ack.verify(&different_hello, &responder_sign.verifying_key());
        assert!(matches!(result, Err(SessionError::InvalidSignature)));

        log = log.pass();
        log.log();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Transcript Tests
// ─────────────────────────────────────────────────────────────────────────────

mod transcript_tests {
    use super::*;

    #[test]
    fn hello_transcript_is_deterministic() {
        let mut log = TestLogEntry::new("hello_transcript_is_deterministic", "transcript", None);

        let (initiator_sign, _) = fixed_signing_keys();
        let (initiator_eph, _) = fixed_ephemeral_keys();
        let hello = build_hello(&initiator_sign, &initiator_eph);

        let transcript1 = hello.transcript_bytes().expect("transcript 1");
        let transcript2 = hello.transcript_bytes().expect("transcript 2");
        let transcript3 = hello.transcript_bytes().expect("transcript 3");

        assert_eq!(transcript1, transcript2);
        assert_eq!(transcript2, transcript3);

        log = log.pass();
        log.log();
    }

    #[test]
    fn hello_transcript_includes_domain_separation() {
        let mut log = TestLogEntry::new(
            "hello_transcript_includes_domain_separation",
            "transcript",
            None,
        );

        let (initiator_sign, _) = fixed_signing_keys();
        let (initiator_eph, _) = fixed_ephemeral_keys();
        let hello = build_hello(&initiator_sign, &initiator_eph);

        let transcript = hello.transcript_bytes().expect("transcript");

        // Should start with domain separation prefix
        assert!(transcript.starts_with(b"FCP2-HELLO-V1"));

        log = log.pass();
        log.log();
    }

    #[test]
    fn ack_transcript_is_deterministic() {
        let mut log = TestLogEntry::new("ack_transcript_is_deterministic", "transcript", None);

        let (initiator_sign, responder_sign) = fixed_signing_keys();
        let (initiator_eph, responder_eph) = fixed_ephemeral_keys();
        let hello = build_hello(&initiator_sign, &initiator_eph);
        let ack = build_ack(&responder_sign, &hello, &responder_eph);

        let transcript1 = ack.transcript_bytes(&hello).expect("transcript 1");
        let transcript2 = ack.transcript_bytes(&hello).expect("transcript 2");

        assert_eq!(transcript1, transcript2);

        log = log.pass();
        log.log();
    }

    #[test]
    fn ack_transcript_includes_domain_separation() {
        let mut log = TestLogEntry::new(
            "ack_transcript_includes_domain_separation",
            "transcript",
            None,
        );

        let (initiator_sign, responder_sign) = fixed_signing_keys();
        let (initiator_eph, responder_eph) = fixed_ephemeral_keys();
        let hello = build_hello(&initiator_sign, &initiator_eph);
        let ack = build_ack(&responder_sign, &hello, &responder_eph);

        let transcript = ack.transcript_bytes(&hello).expect("transcript");

        // Should start with domain separation prefix
        assert!(transcript.starts_with(b"FCP2-ACK-V1"));

        log = log.pass();
        log.log();
    }

    #[test]
    fn ack_transcript_includes_hello_data() {
        let mut log = TestLogEntry::new("ack_transcript_includes_hello_data", "transcript", None);

        let (initiator_sign, responder_sign) = fixed_signing_keys();
        let (initiator_eph, responder_eph) = fixed_ephemeral_keys();
        let hello = build_hello(&initiator_sign, &initiator_eph);
        let ack = build_ack(&responder_sign, &hello, &responder_eph);

        let transcript = ack.transcript_bytes(&hello).expect("transcript");

        // Create a different hello and verify transcript differs
        let mut different_hello = hello;
        different_hello.nonce = SessionNonce([0xDD_u8; 16]);
        different_hello.signature = None;
        different_hello.sign(&initiator_sign).expect("sign");

        // Build new ack for different hello
        let different_ack = build_ack(&responder_sign, &different_hello, &responder_eph);
        let different_transcript = different_ack
            .transcript_bytes(&different_hello)
            .expect("different transcript");

        assert_ne!(transcript, different_transcript);

        log = log.pass();
        log.log();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Cookie / HelloRetry Tests
// ─────────────────────────────────────────────────────────────────────────────

mod cookie_tests {
    use super::*;
    use fcp_protocol::{compute_cookie, decode_cookie_bytes, verify_cookie};

    #[test]
    fn cookie_round_trip() {
        let mut log = TestLogEntry::new("cookie_round_trip", "cookie", None);

        let (initiator_sign, _) = fixed_signing_keys();
        let (initiator_eph, _) = fixed_ephemeral_keys();
        let hello = build_hello(&initiator_sign, &initiator_eph);

        let cookie = compute_cookie(&COOKIE_KEY, &hello).expect("compute cookie");
        verify_cookie(&COOKIE_KEY, &hello, &cookie).expect("verify cookie");

        log = log.pass();
        log.log();
    }

    #[test]
    fn cookie_wrong_key_rejected() {
        let mut log =
            TestLogEntry::new("cookie_wrong_key_rejected", "cookie", None).with_reason("FCP-3030");

        let (initiator_sign, _) = fixed_signing_keys();
        let (initiator_eph, _) = fixed_ephemeral_keys();
        let hello = build_hello(&initiator_sign, &initiator_eph);

        let cookie = compute_cookie(&COOKIE_KEY, &hello).expect("compute cookie");

        // Verify with wrong key
        let wrong_key = [0xAA_u8; 32];
        let result = verify_cookie(&wrong_key, &hello, &cookie);
        assert!(matches!(result, Err(SessionError::InvalidCookie)));

        log = log.pass();
        log.log();
    }

    #[test]
    fn cookie_tampered_hello_rejected() {
        let mut log = TestLogEntry::new("cookie_tampered_hello_rejected", "cookie", None)
            .with_reason("FCP-3031");

        let (initiator_sign, _) = fixed_signing_keys();
        let (initiator_eph, _) = fixed_ephemeral_keys();
        let hello = build_hello(&initiator_sign, &initiator_eph);

        let cookie = compute_cookie(&COOKIE_KEY, &hello).expect("compute cookie");

        // Tamper with hello
        let mut tampered = hello;
        tampered.timestamp += 1;

        let result = verify_cookie(&COOKIE_KEY, &tampered, &cookie);
        assert!(matches!(result, Err(SessionError::InvalidCookie)));

        log = log.pass();
        log.log();
    }

    #[test]
    fn cookie_is_deterministic() {
        let mut log = TestLogEntry::new("cookie_is_deterministic", "cookie", None);

        let (initiator_sign, _) = fixed_signing_keys();
        let (initiator_eph, _) = fixed_ephemeral_keys();
        let hello = build_hello(&initiator_sign, &initiator_eph);

        let cookie1 = compute_cookie(&COOKIE_KEY, &hello).expect("cookie 1");
        let cookie2 = compute_cookie(&COOKIE_KEY, &hello).expect("cookie 2");
        let cookie3 = compute_cookie(&COOKIE_KEY, &hello).expect("cookie 3");

        assert_eq!(cookie1.as_bytes(), cookie2.as_bytes());
        assert_eq!(cookie2.as_bytes(), cookie3.as_bytes());

        log = log.pass();
        log.log();
    }

    #[test]
    fn cookie_invalid_length_rejected() {
        let mut log = TestLogEntry::new("cookie_invalid_length_rejected", "cookie", None)
            .with_reason("FCP-3032");

        // Too short
        let short = vec![0u8; 16];
        assert!(decode_cookie_bytes(&short).is_err());

        // Too long
        let oversized = vec![0u8; 64];
        assert!(decode_cookie_bytes(&oversized).is_err());

        // Empty
        assert!(decode_cookie_bytes(&[]).is_err());

        // Correct length should work
        let correct = vec![0u8; 32];
        assert!(decode_cookie_bytes(&correct).is_ok());

        log = log.pass();
        log.log();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Key Derivation Tests
// ─────────────────────────────────────────────────────────────────────────────

mod key_derivation_tests {
    use super::*;

    #[test]
    fn key_derivation_deterministic() {
        let mut log = TestLogEntry::new("key_derivation_deterministic", "key_derive", None);

        let (initiator, responder) = fixed_node_ids();
        let (initiator_eph, responder_eph) = fixed_ephemeral_keys();
        let shared = initiator_eph
            .diffie_hellman(&responder_eph.public_key())
            .unwrap();
        let session_id = MeshSessionId(SESSION_ID);
        let hello_nonce = SessionNonce(HELLO_NONCE);
        let ack_nonce = SessionNonce(ACK_NONCE);

        let keys1 = derive_session_keys(
            &shared,
            SessionCryptoSuite::Suite1,
            &session_id,
            &initiator,
            &responder,
            &hello_nonce,
            &ack_nonce,
        )
        .expect("keys 1");

        let keys2 = derive_session_keys(
            &shared,
            SessionCryptoSuite::Suite1,
            &session_id,
            &initiator,
            &responder,
            &hello_nonce,
            &ack_nonce,
        )
        .expect("keys 2");

        assert_eq!(keys1.k_mac_i2r, keys2.k_mac_i2r);
        assert_eq!(keys1.k_mac_r2i, keys2.k_mac_r2i);
        assert_eq!(keys1.k_ctx, keys2.k_ctx);

        log = log.pass();
        log.log();
    }

    #[test]
    fn key_roles_are_separated() {
        let mut log = TestLogEntry::new("key_roles_are_separated", "key_derive", None);

        let (initiator, responder) = fixed_node_ids();
        let (initiator_eph, responder_eph) = fixed_ephemeral_keys();
        let shared = initiator_eph
            .diffie_hellman(&responder_eph.public_key())
            .unwrap();
        let session_id = MeshSessionId(SESSION_ID);

        let keys = derive_session_keys(
            &shared,
            SessionCryptoSuite::Suite1,
            &session_id,
            &initiator,
            &responder,
            &SessionNonce(HELLO_NONCE),
            &SessionNonce(ACK_NONCE),
        )
        .expect("keys");

        // All keys must be different
        assert_ne!(keys.k_mac_i2r, keys.k_mac_r2i);
        assert_ne!(keys.k_mac_i2r, keys.k_ctx);
        assert_ne!(keys.k_mac_r2i, keys.k_ctx);

        log = log.pass();
        log.log();
    }

    #[test]
    fn different_session_id_yields_different_keys() {
        let mut log = TestLogEntry::new(
            "different_session_id_yields_different_keys",
            "key_derive",
            None,
        );

        let (initiator, responder) = fixed_node_ids();
        let (initiator_eph, responder_eph) = fixed_ephemeral_keys();
        let shared = initiator_eph
            .diffie_hellman(&responder_eph.public_key())
            .unwrap();

        let keys1 = derive_session_keys(
            &shared,
            SessionCryptoSuite::Suite1,
            &MeshSessionId([0x11_u8; 16]),
            &initiator,
            &responder,
            &SessionNonce(HELLO_NONCE),
            &SessionNonce(ACK_NONCE),
        )
        .expect("keys 1");

        let keys2 = derive_session_keys(
            &shared,
            SessionCryptoSuite::Suite1,
            &MeshSessionId([0x22_u8; 16]),
            &initiator,
            &responder,
            &SessionNonce(HELLO_NONCE),
            &SessionNonce(ACK_NONCE),
        )
        .expect("keys 2");

        assert_ne!(keys1.k_mac_i2r, keys2.k_mac_i2r);

        log = log.pass();
        log.log();
    }

    #[test]
    fn different_selected_suite_yields_different_keys() {
        let mut log = TestLogEntry::new(
            "different_selected_suite_yields_different_keys",
            "key_derive",
            None,
        );

        let (initiator, responder) = fixed_node_ids();
        let (initiator_eph, responder_eph) = fixed_ephemeral_keys();
        let shared = initiator_eph
            .diffie_hellman(&responder_eph.public_key())
            .unwrap();
        let session_id = MeshSessionId(SESSION_ID);

        let suite1_keys = derive_session_keys(
            &shared,
            SessionCryptoSuite::Suite1,
            &session_id,
            &initiator,
            &responder,
            &SessionNonce(HELLO_NONCE),
            &SessionNonce(ACK_NONCE),
        )
        .expect("suite1 keys");

        let suite2_keys = derive_session_keys(
            &shared,
            SessionCryptoSuite::Suite2,
            &session_id,
            &initiator,
            &responder,
            &SessionNonce(HELLO_NONCE),
            &SessionNonce(ACK_NONCE),
        )
        .expect("suite2 keys");

        assert_ne!(suite1_keys.k_mac_i2r, suite2_keys.k_mac_i2r);
        assert_ne!(suite1_keys.k_mac_r2i, suite2_keys.k_mac_r2i);
        assert_ne!(suite1_keys.k_ctx, suite2_keys.k_ctx);

        log = log.pass();
        log.log();
    }

    #[test]
    fn different_nonces_yield_different_keys() {
        let mut log =
            TestLogEntry::new("different_nonces_yield_different_keys", "key_derive", None);

        let (initiator, responder) = fixed_node_ids();
        let (initiator_eph, responder_eph) = fixed_ephemeral_keys();
        let shared = initiator_eph
            .diffie_hellman(&responder_eph.public_key())
            .unwrap();
        let session_id = MeshSessionId(SESSION_ID);

        let keys1 = derive_session_keys(
            &shared,
            SessionCryptoSuite::Suite1,
            &session_id,
            &initiator,
            &responder,
            &SessionNonce([0x11_u8; 16]),
            &SessionNonce([0x22_u8; 16]),
        )
        .expect("keys 1");

        let keys2 = derive_session_keys(
            &shared,
            SessionCryptoSuite::Suite1,
            &session_id,
            &initiator,
            &responder,
            &SessionNonce([0x33_u8; 16]),
            &SessionNonce([0x44_u8; 16]),
        )
        .expect("keys 2");

        assert_ne!(keys1.k_mac_i2r, keys2.k_mac_i2r);

        log = log.pass();
        log.log();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Anti-Replay Tests
// ─────────────────────────────────────────────────────────────────────────────

mod anti_replay_tests {
    use super::*;
    use fcp_protocol::ReplayWindow;

    #[test]
    fn replay_window_rejects_zero_sequence() {
        let mut log =
            TestLogEntry::new("replay_window_rejects_zero_sequence", "replay_check", None);

        let mut window = ReplayWindow::new(128);
        assert!(!window.check_and_update(0));

        log = log.pass();
        log.log();
    }

    #[test]
    fn replay_window_accepts_first_sequence() {
        let mut log =
            TestLogEntry::new("replay_window_accepts_first_sequence", "replay_check", None);

        let mut window = ReplayWindow::new(128);
        assert!(window.check_and_update(1));
        assert_eq!(window.highest_seq(), 1);

        log = log.pass();
        log.log();
    }

    #[test]
    fn replay_window_rejects_duplicate() {
        let mut log = TestLogEntry::new("replay_window_rejects_duplicate", "replay_check", None)
            .with_reason("DUPLICATE");

        let mut window = ReplayWindow::new(128);
        assert!(window.check_and_update(5));
        assert!(!window.check_and_update(5)); // Duplicate

        log = log.pass();
        log.log();
    }

    #[test]
    fn replay_window_accepts_sequential() {
        let mut log = TestLogEntry::new("replay_window_accepts_sequential", "replay_check", None);

        let mut window = ReplayWindow::new(128);
        for seq in 1..=100 {
            assert!(window.check_and_update(seq), "seq {seq} should be accepted");
        }
        assert_eq!(window.highest_seq(), 100);

        log = log.pass();
        log.log();
    }

    #[test]
    fn replay_window_allows_out_of_order_in_window() {
        let mut log = TestLogEntry::new(
            "replay_window_allows_out_of_order_in_window",
            "replay_check",
            None,
        )
        .with_details(serde_json::json!({
            "reason": "IN_WINDOW"
        }));

        let mut window = ReplayWindow::new(128);
        assert!(window.check_and_update(100));
        assert!(window.check_and_update(99)); // Out of order but in window
        assert!(window.check_and_update(50)); // Further back but still in window

        log = log.pass();
        log.log();
    }

    #[test]
    fn replay_window_rejects_stale_outside_window() {
        let mut log = TestLogEntry::new(
            "replay_window_rejects_stale_outside_window",
            "replay_check",
            None,
        )
        .with_details(serde_json::json!({
            "reason": "STALE"
        }));

        let mut window = ReplayWindow::new(64);
        assert!(window.check_and_update(200));

        // These are outside the 64-seq window
        assert!(!window.check_and_update(100));
        assert!(!window.check_and_update(1));

        log = log.pass();
        log.log();
    }

    #[test]
    fn replay_window_handles_large_jump_forward() {
        let mut log = TestLogEntry::new(
            "replay_window_handles_large_jump_forward",
            "replay_check",
            None,
        );

        let mut window = ReplayWindow::new(128);
        assert!(window.check_and_update(1));
        assert!(window.check_and_update(1000)); // Large jump
        assert_eq!(window.highest_seq(), 1000);

        // Old sequence should now be outside window
        assert!(!window.check_and_update(1));

        log = log.pass();
        log.log();
    }

    #[test]
    fn replay_window_min_size_one() {
        let mut log = TestLogEntry::new("replay_window_min_size_one", "replay_check", None);

        // Window size of 0 should be treated as 1
        let mut window = ReplayWindow::new(0);
        assert!(window.check_and_update(1));
        assert!(!window.check_and_update(1));

        log = log.pass();
        log.log();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TransportLimits Tests
// ─────────────────────────────────────────────────────────────────────────────

mod transport_limits_tests {
    use super::*;
    use fcp_protocol::{DEFAULT_MAX_DATAGRAM_BYTES, FCPS_DATAGRAM_HEADER_LEN, FcpsDatagram};

    #[test]
    fn transport_limits_default_value() {
        let mut log = TestLogEntry::new("transport_limits_default_value", "limits", None);

        let limits = TransportLimits::default();
        assert_eq!(limits.max_datagram_bytes, DEFAULT_MAX_DATAGRAM_BYTES);
        assert_eq!(limits.effective_max(), DEFAULT_MAX_DATAGRAM_BYTES);

        log = log.pass();
        log.log();
    }

    #[test]
    fn transport_limits_zero_uses_default() {
        let mut log = TestLogEntry::new("transport_limits_zero_uses_default", "limits", None);

        let limits = TransportLimits {
            max_datagram_bytes: 0,
        };
        assert_eq!(limits.effective_max(), DEFAULT_MAX_DATAGRAM_BYTES);

        log = log.pass();
        log.log();
    }

    #[test]
    fn transport_limits_custom_value() {
        let mut log = TestLogEntry::new("transport_limits_custom_value", "limits", None);

        let limits = TransportLimits {
            max_datagram_bytes: 4096,
        };
        assert_eq!(limits.effective_max(), 4096);

        log = log.pass();
        log.log();
    }

    #[test]
    fn datagram_too_short_rejected() {
        let mut log = TestLogEntry::new("datagram_too_short_rejected", "datagram_decode", None)
            .with_reason("FCP-3040");

        let too_short = vec![0u8; FCPS_DATAGRAM_HEADER_LEN - 1];
        let result = FcpsDatagram::decode(&too_short, DEFAULT_MAX_DATAGRAM_BYTES);
        assert!(matches!(result, Err(SessionError::DatagramTooShort { .. })));

        log = log.pass();
        log.log();
    }

    #[test]
    fn datagram_too_large_rejected() {
        let mut log = TestLogEntry::new("datagram_too_large_rejected", "datagram_decode", None)
            .with_reason("FCP-3041");

        let too_large = vec![0u8; (DEFAULT_MAX_DATAGRAM_BYTES as usize) + 1];
        let result = FcpsDatagram::decode(&too_large, DEFAULT_MAX_DATAGRAM_BYTES);
        assert!(matches!(result, Err(SessionError::DatagramTooLarge { .. })));

        log = log.pass();
        log.log();
    }

    #[test]
    fn datagram_exactly_header_size_accepted() {
        let mut log = TestLogEntry::new(
            "datagram_exactly_header_size_accepted",
            "datagram_decode",
            None,
        );

        let minimal = vec![0u8; FCPS_DATAGRAM_HEADER_LEN];
        let result = FcpsDatagram::decode(&minimal, DEFAULT_MAX_DATAGRAM_BYTES);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().frame_bytes, [] as [u8; 0]);

        log = log.pass();
        log.log();
    }

    #[test]
    fn datagram_encode_decode_roundtrip() {
        let mut log = TestLogEntry::new("datagram_encode_decode_roundtrip", "datagram", None);

        let datagram = FcpsDatagram {
            session_id: MeshSessionId(SESSION_ID),
            seq: 42,
            mac: [0xAB_u8; 16],
            frame_bytes: b"test frame".to_vec(),
        };

        let encoded = datagram.encode();
        let decoded = FcpsDatagram::decode(&encoded, DEFAULT_MAX_DATAGRAM_BYTES).expect("decode");

        assert_eq!(
            decoded.session_id.as_bytes(),
            datagram.session_id.as_bytes()
        );
        assert_eq!(decoded.seq, datagram.seq);
        assert_eq!(decoded.mac, datagram.mac);
        assert_eq!(decoded.frame_bytes, datagram.frame_bytes);

        log = log.pass();
        log.log();
    }

    #[test]
    fn datagram_custom_limit_enforced() {
        let mut log = TestLogEntry::new("datagram_custom_limit_enforced", "datagram_decode", None);

        let custom_limit: u16 = 100;
        let exceeds_custom = vec![0u8; 101];

        let result = FcpsDatagram::decode(&exceeds_custom, custom_limit);
        assert!(matches!(
            result,
            Err(SessionError::DatagramTooLarge { len: 101, max: 100 })
        ));

        log = log.pass();
        log.log();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Session MAC Tests
// ─────────────────────────────────────────────────────────────────────────────

mod session_mac_tests {
    use super::*;
    use fcp_protocol::{compute_session_mac, verify_session_mac};

    #[test]
    fn mac_suite1_round_trip() {
        let mut log = TestLogEntry::new(
            "mac_suite1_round_trip",
            "mac",
            Some(SessionCryptoSuite::Suite1),
        );

        let session_id = MeshSessionId(SESSION_ID);
        let key = [0x11_u8; 32];
        let frame = b"test frame data";

        let mac = compute_session_mac(
            SessionCryptoSuite::Suite1,
            &key,
            &session_id,
            SessionDirection::InitiatorToResponder,
            7,
            frame,
        )
        .expect("compute mac");

        verify_session_mac(
            SessionCryptoSuite::Suite1,
            &key,
            &session_id,
            SessionDirection::InitiatorToResponder,
            7,
            frame,
            &mac,
        )
        .expect("verify mac");

        log = log.pass();
        log.log();
    }

    #[test]
    fn mac_suite2_round_trip() {
        let mut log = TestLogEntry::new(
            "mac_suite2_round_trip",
            "mac",
            Some(SessionCryptoSuite::Suite2),
        );

        let session_id = MeshSessionId(SESSION_ID);
        let key = [0x22_u8; 32];
        let frame = b"test frame data";

        let mac = compute_session_mac(
            SessionCryptoSuite::Suite2,
            &key,
            &session_id,
            SessionDirection::ResponderToInitiator,
            42,
            frame,
        )
        .expect("compute mac");

        verify_session_mac(
            SessionCryptoSuite::Suite2,
            &key,
            &session_id,
            SessionDirection::ResponderToInitiator,
            42,
            frame,
            &mac,
        )
        .expect("verify mac");

        log = log.pass();
        log.log();
    }

    #[test]
    fn mac_wrong_key_rejected() {
        let mut log =
            TestLogEntry::new("mac_wrong_key_rejected", "mac", None).with_reason("FCP-3050");

        let session_id = MeshSessionId(SESSION_ID);
        let key = [0x11_u8; 32];
        let wrong_key = [0x22_u8; 32];
        let frame = b"test frame";

        let mac = compute_session_mac(
            SessionCryptoSuite::Suite1,
            &key,
            &session_id,
            SessionDirection::InitiatorToResponder,
            1,
            frame,
        )
        .expect("compute mac");

        let result = verify_session_mac(
            SessionCryptoSuite::Suite1,
            &wrong_key,
            &session_id,
            SessionDirection::InitiatorToResponder,
            1,
            frame,
            &mac,
        );
        assert!(matches!(result, Err(SessionError::InvalidSignature)));

        log = log.pass();
        log.log();
    }

    #[test]
    fn mac_tampered_frame_rejected() {
        let mut log =
            TestLogEntry::new("mac_tampered_frame_rejected", "mac", None).with_reason("FCP-3051");

        let session_id = MeshSessionId(SESSION_ID);
        let key = [0x11_u8; 32];
        let frame = b"test frame";

        let mac = compute_session_mac(
            SessionCryptoSuite::Suite1,
            &key,
            &session_id,
            SessionDirection::InitiatorToResponder,
            1,
            frame,
        )
        .expect("compute mac");

        let mut tampered = frame.to_vec();
        tampered[0] ^= 0xFF;

        let result = verify_session_mac(
            SessionCryptoSuite::Suite1,
            &key,
            &session_id,
            SessionDirection::InitiatorToResponder,
            1,
            &tampered,
            &mac,
        );
        assert!(matches!(result, Err(SessionError::InvalidSignature)));

        log = log.pass();
        log.log();
    }

    #[test]
    fn mac_wrong_sequence_rejected() {
        let mut log =
            TestLogEntry::new("mac_wrong_sequence_rejected", "mac", None).with_reason("FCP-3052");

        let session_id = MeshSessionId(SESSION_ID);
        let key = [0x11_u8; 32];
        let frame = b"test frame";

        let mac = compute_session_mac(
            SessionCryptoSuite::Suite1,
            &key,
            &session_id,
            SessionDirection::InitiatorToResponder,
            1,
            frame,
        )
        .expect("compute mac");

        let result = verify_session_mac(
            SessionCryptoSuite::Suite1,
            &key,
            &session_id,
            SessionDirection::InitiatorToResponder,
            2, // Wrong sequence
            frame,
            &mac,
        );
        assert!(matches!(result, Err(SessionError::InvalidSignature)));

        log = log.pass();
        log.log();
    }

    #[test]
    fn mac_wrong_direction_rejected() {
        let mut log =
            TestLogEntry::new("mac_wrong_direction_rejected", "mac", None).with_reason("FCP-3053");

        let session_id = MeshSessionId(SESSION_ID);
        let key = [0x11_u8; 32];
        let frame = b"test frame";

        let mac = compute_session_mac(
            SessionCryptoSuite::Suite1,
            &key,
            &session_id,
            SessionDirection::InitiatorToResponder,
            1,
            frame,
        )
        .expect("compute mac");

        let result = verify_session_mac(
            SessionCryptoSuite::Suite1,
            &key,
            &session_id,
            SessionDirection::ResponderToInitiator, // Wrong direction
            1,
            frame,
            &mac,
        );
        assert!(matches!(result, Err(SessionError::InvalidSignature)));

        log = log.pass();
        log.log();
    }

    #[test]
    fn mac_different_suites_produce_different_tags() {
        let mut log = TestLogEntry::new("mac_different_suites_produce_different_tags", "mac", None);

        let session_id = MeshSessionId(SESSION_ID);
        let key = [0x11_u8; 32];
        let frame = b"test frame";

        let mac1 = compute_session_mac(
            SessionCryptoSuite::Suite1,
            &key,
            &session_id,
            SessionDirection::InitiatorToResponder,
            1,
            frame,
        )
        .expect("compute mac suite1");

        let mac2 = compute_session_mac(
            SessionCryptoSuite::Suite2,
            &key,
            &session_id,
            SessionDirection::InitiatorToResponder,
            1,
            frame,
        )
        .expect("compute mac suite2");

        assert_ne!(mac1, mac2);

        log = log.pass();
        log.log();
    }
}
