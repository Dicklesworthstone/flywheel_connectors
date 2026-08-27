//! Golden vector tests for FCPS datagram envelope encoding, decoding, and MAC.

use fcp_conformance::vectors::datagram::{
    DatagramErrorVector, DatagramGoldenVector, DatagramMacGoldenVector,
};
use fcp_protocol::{
    FcpsDatagram, MeshSessionId, SessionCryptoSuite, SessionDirection, SessionError,
    compute_session_mac, verify_session_mac,
};

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    if hex.is_empty() {
        return Vec::new();
    }
    hex::decode(hex).unwrap_or_else(|e| panic!("invalid hex '{hex}': {e}"))
}

// ─────────────────────────────────────────────────────────────────────────────
// Encoding / Decoding Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn datagram_encode_matches_golden_vectors() {
    for v in DatagramGoldenVector::load_all() {
        let session_id_bytes: [u8; 16] = hex_to_bytes(&v.session_id).try_into().unwrap();
        let mac_bytes: [u8; 16] = hex_to_bytes(&v.mac).try_into().unwrap();
        let frame_bytes = hex_to_bytes(&v.frame_bytes);

        let datagram = FcpsDatagram {
            session_id: MeshSessionId(session_id_bytes),
            seq: v.seq,
            mac: mac_bytes,
            frame_bytes,
        };

        let encoded = datagram.encode();
        assert_eq!(
            hex::encode(&encoded),
            v.expected_encoded,
            "encode mismatch for: {}",
            v.description
        );
    }
}

#[test]
fn datagram_decode_matches_golden_vectors() {
    for v in DatagramGoldenVector::load_all() {
        let encoded = hex_to_bytes(&v.expected_encoded);
        let decoded = FcpsDatagram::decode(&encoded, 1200)
            .unwrap_or_else(|e| panic!("decode failed for '{}': {e}", v.description));

        assert_eq!(
            hex::encode(decoded.session_id.as_bytes()),
            v.session_id,
            "session_id mismatch for: {}",
            v.description
        );
        assert_eq!(decoded.seq, v.seq, "seq mismatch for: {}", v.description);
        assert_eq!(
            hex::encode(decoded.mac),
            v.mac,
            "mac mismatch for: {}",
            v.description
        );
        assert_eq!(
            hex::encode(&decoded.frame_bytes),
            v.frame_bytes,
            "frame_bytes mismatch for: {}",
            v.description
        );
    }
}

#[test]
fn datagram_roundtrip_preserves_bytes() {
    for v in DatagramGoldenVector::load_all() {
        let encoded = hex_to_bytes(&v.expected_encoded);
        let decoded = FcpsDatagram::decode(&encoded, 65535).unwrap();
        let re_encoded = decoded.encode();

        assert_eq!(
            encoded, re_encoded,
            "roundtrip byte mismatch for: {}",
            v.description
        );
    }
}

#[test]
fn datagram_header_is_exactly_40_bytes() {
    // Verify the header size constant matches the wire format
    assert_eq!(fcp_protocol::FCPS_DATAGRAM_HEADER_LEN, 40);

    // An empty-frame datagram encodes to exactly 40 bytes
    let v = DatagramGoldenVector::vector_1_minimal_empty_frame();
    let encoded = hex_to_bytes(&v.expected_encoded);
    assert_eq!(encoded.len(), 40, "empty-frame datagram must be 40 bytes");
}

// ─────────────────────────────────────────────────────────────────────────────
// MAC Computation Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn datagram_mac_matches_golden_vectors() {
    for v in DatagramMacGoldenVector::load_all() {
        let mac_key: [u8; 32] = hex_to_bytes(&v.mac_key).try_into().unwrap();
        let session_id_bytes: [u8; 16] = hex_to_bytes(&v.session_id).try_into().unwrap();
        let session_id = MeshSessionId(session_id_bytes);
        let frame_bytes = hex_to_bytes(&v.frame_bytes);

        let suite = match v.suite.as_str() {
            "Suite1" => SessionCryptoSuite::Suite1,
            "Suite2" => SessionCryptoSuite::Suite2,
            other => panic!("unknown suite: {other}"),
        };

        let direction = match v.direction.as_str() {
            "InitiatorToResponder" => SessionDirection::InitiatorToResponder,
            "ResponderToInitiator" => SessionDirection::ResponderToInitiator,
            other => panic!("unknown direction: {other}"),
        };

        let computed =
            compute_session_mac(suite, &mac_key, &session_id, direction, v.seq, &frame_bytes)
                .unwrap_or_else(|e| panic!("MAC compute failed for '{}': {e}", v.description));

        assert_eq!(
            hex::encode(computed),
            v.expected_mac,
            "MAC mismatch for: {}",
            v.description
        );
    }
}

#[test]
fn datagram_mac_verify_roundtrip() {
    for v in DatagramMacGoldenVector::load_all() {
        let mac_key: [u8; 32] = hex_to_bytes(&v.mac_key).try_into().unwrap();
        let session_id_bytes: [u8; 16] = hex_to_bytes(&v.session_id).try_into().unwrap();
        let session_id = MeshSessionId(session_id_bytes);
        let frame_bytes = hex_to_bytes(&v.frame_bytes);
        let expected_mac: [u8; 16] = hex_to_bytes(&v.expected_mac).try_into().unwrap();

        let suite = match v.suite.as_str() {
            "Suite1" => SessionCryptoSuite::Suite1,
            "Suite2" => SessionCryptoSuite::Suite2,
            other => panic!("unknown suite: {other}"),
        };
        let direction = match v.direction.as_str() {
            "InitiatorToResponder" => SessionDirection::InitiatorToResponder,
            "ResponderToInitiator" => SessionDirection::ResponderToInitiator,
            other => panic!("unknown direction: {other}"),
        };

        // Verify the expected MAC passes verification
        verify_session_mac(
            suite,
            &mac_key,
            &session_id,
            direction,
            v.seq,
            &frame_bytes,
            &expected_mac,
        )
        .unwrap_or_else(|e| panic!("MAC verify failed for '{}': {e}", v.description));
    }
}

#[test]
fn datagram_mac_direction_binding() {
    // Same inputs with different direction must produce different MACs
    let vectors = DatagramMacGoldenVector::load_all();

    // Compare Suite1 i2r (index 0) vs r2i (index 1) - same key/session/seq/frame
    assert_ne!(
        vectors[0].expected_mac, vectors[1].expected_mac,
        "Suite1 MAC must differ between InitiatorToResponder and ResponderToInitiator"
    );

    // Compare Suite2 i2r (index 2) with same direction but different seq
    assert_ne!(
        vectors[2].expected_mac, vectors[3].expected_mac,
        "MAC must differ for different sequence numbers"
    );
}

#[test]
fn datagram_mac_wrong_key_fails() {
    let v = &DatagramMacGoldenVector::load_all()[0];

    let wrong_key = [0x02u8; 32]; // Different from the vector's key
    let session_id_bytes: [u8; 16] = hex_to_bytes(&v.session_id).try_into().unwrap();
    let session_id = MeshSessionId(session_id_bytes);
    let frame_bytes = hex_to_bytes(&v.frame_bytes);
    let expected_mac: [u8; 16] = hex_to_bytes(&v.expected_mac).try_into().unwrap();

    let result = verify_session_mac(
        SessionCryptoSuite::Suite1,
        &wrong_key,
        &session_id,
        SessionDirection::InitiatorToResponder,
        v.seq,
        &frame_bytes,
        &expected_mac,
    );

    assert!(result.is_err(), "wrong key must fail MAC verification");
}

// ─────────────────────────────────────────────────────────────────────────────
// Error Case Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn datagram_decode_errors_match_vectors() {
    for v in DatagramErrorVector::load_all() {
        let input = hex_to_bytes(&v.input_bytes);
        let result = FcpsDatagram::decode(&input, v.max_datagram_bytes);

        match v.expected_error.as_str() {
            "TooShort" => {
                assert!(
                    matches!(result, Err(SessionError::DatagramTooShort { .. })),
                    "expected TooShort for '{}', got: {result:?}",
                    v.description
                );
            }
            "TooLarge" => {
                assert!(
                    matches!(result, Err(SessionError::DatagramTooLarge { .. })),
                    "expected TooLarge for '{}', got: {result:?}",
                    v.description
                );
            }
            other => panic!("unknown expected_error: {other}"),
        }
    }
}

#[test]
fn datagram_exactly_header_accepted() {
    // 40 bytes (exactly the header) must decode successfully with empty frame
    let input = vec![0u8; 40];
    let decoded = FcpsDatagram::decode(&input, 1200).expect("header-only datagram must decode");
    assert_eq!(decoded.frame_bytes, [] as [u8; 0]);
}
