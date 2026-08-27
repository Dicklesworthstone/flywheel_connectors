//! Cross-module integration tests for `fcp-raptorq`.
//!
//! Tests exercise real encode/decode/chunk/envelope pipelines
//! without mocks, verifying that all modules compose correctly.

use std::time::Duration;

use fcp_prelude::{ObjectId, ZoneId, ZoneKey, ZoneKeyAlgorithm, ZoneKeyId};
use fcp_raptorq::{
    ChunkError, ChunkedObjectManifest, DecodeAdmissionController, DecodeError, EncodeError,
    EncodingDecision, ObjectTransmissionInformation, RaptorQConfig, RaptorQDecoder, RaptorQEncoder,
    RaptorQPathProfile, RaptorQPreset, RawChunk, SymbolEnvelope,
};
use fcp_tailscale::NodeId;

// ============================================================================
// Helpers
// ============================================================================

const fn default_config() -> RaptorQConfig {
    RaptorQConfig {
        symbol_size: 1024,
        repair_ratio_bps: 500,
        max_object_size: 64 * 1024 * 1024,
        decode_timeout: Duration::from_secs(30),
        max_chunk_threshold: 256 * 1024,
        chunk_size: 64 * 1024,
    }
}

const fn small_config() -> RaptorQConfig {
    RaptorQConfig {
        symbol_size: 64,
        repair_ratio_bps: 1000, // 10% repair
        max_object_size: 4096,
        decode_timeout: Duration::from_secs(5),
        max_chunk_threshold: 512,
        chunk_size: 256,
    }
}

fn deterministic_payload(size: usize) -> Vec<u8> {
    (0..size)
        .map(|i| u8::try_from(i % 256).expect("fits u8"))
        .collect()
}

const fn test_zone_key() -> ZoneKey {
    ZoneKey::from_bytes([0xAA; 32])
}

const fn test_zone_key_id() -> ZoneKeyId {
    ZoneKeyId::from_bytes([0xBB; 8])
}

fn test_zone_id() -> ZoneId {
    "z:work".parse().unwrap()
}

fn test_node_id() -> NodeId {
    NodeId::new("node-integration-test")
}

const fn test_object_id() -> ObjectId {
    ObjectId::from_bytes([0xCC; 32])
}

// ============================================================================
// 1. Encode → Decode roundtrip (core pipeline)
// ============================================================================

#[test]
fn encode_decode_roundtrip_small_payload() {
    let config = default_config();
    let payload = deterministic_payload(2048);

    let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
    let symbols = encoder.encode_all();
    let oti = encoder.transmission_info();

    let mut decoder = RaptorQDecoder::new(oti, &config);
    let mut result = None;
    for (esi, data) in symbols {
        if let Some(decoded) = decoder.add_symbol(esi, data).unwrap() {
            result = Some(decoded);
            break;
        }
    }

    assert_eq!(result.unwrap(), payload);
}

#[test]
fn encode_decode_roundtrip_exact_symbol_size() {
    let config = default_config();
    // Payload exactly one symbol
    let payload = deterministic_payload(1024);

    let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
    assert_eq!(encoder.source_symbols(), 1);

    let symbols = encoder.encode_all();
    let oti = encoder.transmission_info();

    let mut decoder = RaptorQDecoder::new(oti, &config);
    let mut result = None;
    for (esi, data) in symbols {
        if let Some(decoded) = decoder.add_symbol(esi, data).unwrap() {
            result = Some(decoded);
            break;
        }
    }
    assert_eq!(result.unwrap(), payload);
}

#[test]
fn encode_decode_roundtrip_multi_symbol() {
    let config = small_config();
    let payload = deterministic_payload(500);

    let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
    assert!(encoder.source_symbols() > 1);

    let symbols = encoder.encode_all();
    let oti = encoder.transmission_info();

    let mut decoder = RaptorQDecoder::new(oti, &config);
    let mut result = None;
    for (esi, data) in symbols {
        if let Some(decoded) = decoder.add_symbol(esi, data).unwrap() {
            result = Some(decoded);
            break;
        }
    }
    assert_eq!(result.unwrap(), payload);
}

#[test]
fn source_only_symbols_sufficient_for_decode() {
    let config = default_config();
    let payload = deterministic_payload(4096);

    let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
    let source_symbols = encoder.encode_source();
    let oti = encoder.transmission_info();

    let mut decoder = RaptorQDecoder::new(oti, &config);
    let mut result = None;
    for (esi, data) in source_symbols {
        if let Some(decoded) = decoder.add_symbol(esi, data).unwrap() {
            result = Some(decoded);
            break;
        }
    }
    assert_eq!(result.unwrap(), payload);
}

// ============================================================================
// 2. Encoder properties
// ============================================================================

#[test]
fn encoder_empty_payload_rejected() {
    let config = default_config();
    let result = RaptorQEncoder::new(&[], &config);
    assert!(result.is_err());
}

#[test]
fn encoder_oversized_payload_rejected() {
    let config = small_config(); // max 4096
    let big = vec![0u8; 5000];
    let result = RaptorQEncoder::new(&big, &config);
    assert!(result.is_err());
}

#[test]
fn encoder_total_symbols_includes_repair() {
    let config = default_config();
    let payload = deterministic_payload(4096);
    let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
    // total = source + repair
    assert_eq!(
        encoder.total_symbols(),
        encoder.source_symbols() + encoder.repair_symbols()
    );
    // With enough source symbols, repair should be > 0
    assert!(encoder.total_symbols() >= encoder.source_symbols());
}

#[test]
fn encoder_oti_matches_payload() {
    let config = default_config();
    let payload = deterministic_payload(3000);
    let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
    let oti = encoder.transmission_info();
    assert_eq!(oti.transfer_length(), payload.len() as u64);
    assert_eq!(oti.symbol_size(), config.symbol_size);
}

#[test]
fn encoder_payload_len_accessor() {
    let config = default_config();
    let payload = deterministic_payload(7777);
    let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
    assert_eq!(encoder.payload_len(), 7777);
}

// ============================================================================
// 3. Decoder state tracking
// ============================================================================

#[test]
fn decoder_tracks_received_count() {
    let config = default_config();
    let payload = deterministic_payload(2048);
    let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
    let symbols = encoder.encode_all();
    let oti = encoder.transmission_info();

    let mut decoder = RaptorQDecoder::new(oti, &config);
    assert_eq!(decoder.received_count(), 0);

    // Feed just one symbol
    let (esi, data) = symbols[0].clone();
    let _ = decoder.add_symbol(esi, data);
    assert_eq!(decoder.received_count(), 1);
}

#[test]
fn decoder_skips_duplicate_esi() {
    let config = default_config();
    let payload = deterministic_payload(2048);
    let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
    let symbols = encoder.encode_all();
    let oti = encoder.transmission_info();

    let mut decoder = RaptorQDecoder::new(oti, &config);
    let (esi, data) = symbols[0].clone();
    let _ = decoder.add_symbol(esi, data.clone());
    let _ = decoder.add_symbol(esi, data);
    assert_eq!(decoder.received_count(), 1);
}

#[test]
fn decoder_expected_k_matches_encoder() {
    let config = default_config();
    let payload = deterministic_payload(4096);
    let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
    let oti = encoder.transmission_info();

    let decoder = RaptorQDecoder::new(oti, &config);
    assert_eq!(decoder.expected_k(), encoder.source_symbols());
}

#[test]
fn decoder_likely_complete_tracks_received() {
    let config = default_config();
    // Use a large enough payload so K is large and needed() > K is meaningful
    let payload = deterministic_payload(32768);
    let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
    let symbols = encoder.encode_all();
    let oti = encoder.transmission_info();

    let mut decoder = RaptorQDecoder::new(oti, &config);
    assert!(!decoder.likely_complete());

    let needed = decoder.needed();
    assert!(needed > 0);

    // Feed enough symbols to reach needed threshold
    for (esi, data) in &symbols {
        let _ = decoder.add_symbol(*esi, data.clone());
        if decoder.received_count() >= needed {
            break;
        }
    }
    assert!(decoder.likely_complete());
}

#[test]
fn decoder_timing_functions() {
    let config = default_config();
    let oti = ObjectTransmissionInformation::new(1024, 1024, 1, 1, 1);
    let decoder = RaptorQDecoder::new(oti, &config);

    assert!(!decoder.is_timed_out());
    assert!(decoder.elapsed() < Duration::from_secs(1));
    assert!(decoder.time_remaining() > Duration::from_secs(20));
}

// ============================================================================
// 4. Chunking pipeline
// ============================================================================

#[test]
fn chunk_roundtrip() {
    let payload = deterministic_payload(1000);
    let chunk_size = 300;
    let (manifest, chunks) = ChunkedObjectManifest::from_payload(&payload, chunk_size);

    assert_eq!(manifest.chunk_count(), 4); // ceil(1000/300)
    assert!(manifest.verify_hash(&payload));

    let reconstructed = manifest.reconstruct(&chunks).unwrap();
    assert_eq!(reconstructed, payload);
}

#[test]
fn chunk_single_chunk_roundtrip() {
    let payload = deterministic_payload(100);
    let (manifest, chunks) = ChunkedObjectManifest::from_payload(&payload, 500);

    assert_eq!(manifest.chunk_count(), 1);
    let reconstructed = manifest.reconstruct(&chunks).unwrap();
    assert_eq!(reconstructed, payload);
}

#[test]
fn chunk_exact_boundary() {
    let payload = deterministic_payload(600);
    let (manifest, chunks) = ChunkedObjectManifest::from_payload(&payload, 200);

    assert_eq!(manifest.chunk_count(), 3);
    let reconstructed = manifest.reconstruct(&chunks).unwrap();
    assert_eq!(reconstructed, payload);
}

#[test]
fn chunk_size_at_returns_correct_values() {
    let payload = deterministic_payload(500);
    let chunk_size = 200;
    let (manifest, _chunks) = ChunkedObjectManifest::from_payload(&payload, chunk_size);

    assert_eq!(manifest.chunk_size_at(0).unwrap(), 200);
    assert_eq!(manifest.chunk_size_at(1).unwrap(), 200);
    assert_eq!(manifest.chunk_size_at(2).unwrap(), 100); // remainder
}

#[test]
fn chunk_size_at_invalid_index() {
    let payload = deterministic_payload(500);
    let (manifest, _) = ChunkedObjectManifest::from_payload(&payload, 200);
    let err = manifest.chunk_size_at(10).unwrap_err();
    assert!(matches!(err, ChunkError::InvalidChunkIndex { .. }));
}

#[test]
fn chunk_reconstruct_unchecked() {
    let payload = deterministic_payload(800);
    let (manifest, chunks) = ChunkedObjectManifest::from_payload(&payload, 300);

    let reconstructed = manifest.reconstruct_unchecked(&chunks).unwrap();
    assert_eq!(reconstructed, payload);
}

#[test]
fn chunk_missing_chunks_error() {
    let payload = deterministic_payload(600);
    let (manifest, chunks) = ChunkedObjectManifest::from_payload(&payload, 200);

    // Remove one chunk
    let partial = &chunks[..2];
    let err = manifest.reconstruct(partial).unwrap_err();
    assert!(matches!(err, ChunkError::MissingChunks { .. }));
}

#[test]
fn raw_chunk_content_id_deterministic() {
    let data = vec![1, 2, 3, 4, 5];
    let chunk1 = RawChunk::new(data.clone());
    let chunk2 = RawChunk::new(data);
    assert_eq!(chunk1.content_id(), chunk2.content_id());
}

#[test]
fn raw_chunk_different_data_different_id() {
    let chunk1 = RawChunk::new(vec![1, 2, 3]);
    let chunk2 = RawChunk::new(vec![4, 5, 6]);
    assert_ne!(chunk1.content_id(), chunk2.content_id());
}

// ============================================================================
// 5. EncodingDecision strategy selection
// ============================================================================

#[test]
fn encoding_decision_direct_for_small_payload() {
    let config = default_config();
    let payload = deterministic_payload(1024);
    let decision = EncodingDecision::for_payload(&payload, &config).unwrap();
    assert!(decision.is_direct());
    assert!(!decision.is_chunked());
}

#[test]
fn encoding_decision_chunked_for_large_payload() {
    let config = small_config(); // chunk_threshold = 512
    let payload = deterministic_payload(1000);
    let decision = EncodingDecision::for_payload(&payload, &config).unwrap();
    assert!(decision.is_chunked());
    assert!(!decision.is_direct());
}

#[test]
fn encoding_decision_handles_empty() {
    let config = default_config();
    // Empty payload may succeed as Direct with 0 symbols
    let decision = EncodingDecision::for_payload(&[], &config);
    if let Ok(d) = decision {
        assert!(d.is_direct());
    }
}

// ============================================================================
// 6. Config calculations
// ============================================================================

#[test]
fn config_repair_symbols_proportional() {
    let config = RaptorQConfig {
        repair_ratio_bps: 1000, // 10%
        ..default_config()
    };
    let repair = config.repair_symbols(100);
    assert_eq!(repair, 10);
}

#[test]
fn config_source_symbols_calculation() {
    let config = default_config(); // symbol_size = 1024
    let k = config.source_symbols(4096);
    assert_eq!(k, 4); // 4096 / 1024
}

#[test]
fn config_total_symbols_includes_repair() {
    let config = default_config();
    let payload_len = 4096;
    let total = config.total_symbols(payload_len);
    let source = config.source_symbols(payload_len);
    assert!(total >= source);
    assert_eq!(total, source + config.repair_symbols(source));
}

#[test]
fn config_requires_chunking_below_threshold() {
    let config = default_config(); // threshold = 256KB
    assert!(!config.requires_chunking(1000));
}

#[test]
fn config_requires_chunking_above_threshold() {
    let config = small_config(); // threshold = 512
    assert!(config.requires_chunking(1000));
}

#[test]
fn config_chunk_count_calculation() {
    let config = small_config(); // chunk_size = 256
    assert_eq!(config.chunk_count(500), 2); // ceil(500/256)
    assert_eq!(config.chunk_count(256), 1);
    assert_eq!(config.chunk_count(257), 2);
}

#[test]
fn config_default_values() {
    let config = RaptorQConfig::default();
    assert_eq!(config.symbol_size, 1024);
    assert_eq!(config.repair_ratio_bps, 500);
    assert_eq!(config.max_object_size, 64 * 1024 * 1024);
    assert_eq!(config.decode_timeout, Duration::from_secs(30));
}

// ============================================================================
// 7. Preset profiles
// ============================================================================

#[test]
fn preset_lan_profile() {
    let preset = RaptorQPreset::lan();
    assert!(matches!(preset.profile, RaptorQPathProfile::Lan));
}

#[test]
fn preset_derp_profile() {
    let preset = RaptorQPreset::derp();
    assert!(matches!(preset.profile, RaptorQPathProfile::Derp));
}

#[test]
fn preset_for_profile_roundtrip() {
    let preset = RaptorQPreset::for_profile(RaptorQPathProfile::Lan);
    assert!(matches!(preset.profile, RaptorQPathProfile::Lan));

    let preset = RaptorQPreset::for_profile(RaptorQPathProfile::Derp);
    assert!(matches!(preset.profile, RaptorQPathProfile::Derp));
}

#[test]
fn config_from_preset_lan() {
    let preset = RaptorQPreset::lan();
    let config = RaptorQConfig::from_preset(preset);
    assert!(config.is_some());
    let config = config.unwrap();
    assert!(config.symbol_size > 0);
}

#[test]
fn config_from_preset_derp() {
    let preset = RaptorQPreset::derp();
    let config = RaptorQConfig::from_preset(preset);
    assert!(config.is_some());
}

// ============================================================================
// 8. OTI construction and accessors
// ============================================================================

#[test]
fn oti_construction_and_accessors() {
    let oti = ObjectTransmissionInformation::new(8192, 1024, 1, 1, 4);
    assert_eq!(oti.transfer_length(), 8192);
    assert_eq!(oti.symbol_size(), 1024);
    assert_eq!(oti.source_blocks(), 1);
    assert_eq!(oti.sub_blocks(), 1);
    assert_eq!(oti.symbol_alignment(), 4);
}

#[test]
fn oti_copy_semantics() {
    let oti = ObjectTransmissionInformation::new(1024, 512, 1, 1, 1);
    let oti2 = oti;
    assert_eq!(oti, oti2);
}

#[test]
fn oti_from_encoder_is_consistent() {
    let config = default_config();
    let payload = deterministic_payload(5000);
    let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
    let oti = encoder.transmission_info();

    assert_eq!(oti.transfer_length(), 5000);
    assert_eq!(oti.symbol_size(), config.symbol_size);
    assert_eq!(oti.source_blocks(), 1); // FCP always 1
}

// ============================================================================
// 9. SymbolEnvelope encrypt/decrypt roundtrip
// ============================================================================

#[test]
fn envelope_encrypt_decrypt_chacha20() {
    let zone_key = test_zone_key();
    let zone_key_id = test_zone_key_id();
    let plaintext = b"hello raptorq integration";

    let envelope = SymbolEnvelope::encrypt(
        test_object_id(),
        0,
        10,
        plaintext,
        test_zone_id(),
        zone_key_id,
        1000,
        test_node_id(),
        0xDEAD_BEEF,
        1,
        &zone_key,
        ZoneKeyAlgorithm::ChaCha20Poly1305,
    )
    .unwrap();

    let decrypted = envelope
        .decrypt(&zone_key, ZoneKeyAlgorithm::ChaCha20Poly1305, zone_key_id)
        .unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn envelope_encrypt_decrypt_xchacha20() {
    let zone_key = test_zone_key();
    let zone_key_id = test_zone_key_id();
    let plaintext = b"xchacha20 test data";

    let envelope = SymbolEnvelope::encrypt(
        test_object_id(),
        5,
        20,
        plaintext,
        test_zone_id(),
        zone_key_id,
        2000,
        test_node_id(),
        0xCAFE_BABE,
        42,
        &zone_key,
        ZoneKeyAlgorithm::XChaCha20Poly1305,
    )
    .unwrap();

    let decrypted = envelope
        .decrypt(&zone_key, ZoneKeyAlgorithm::XChaCha20Poly1305, zone_key_id)
        .unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn envelope_wrong_key_fails() {
    let zone_key = test_zone_key();
    let wrong_key = ZoneKey::from_bytes([0xFF; 32]);
    let zone_key_id = test_zone_key_id();

    let envelope = SymbolEnvelope::encrypt(
        test_object_id(),
        0,
        10,
        b"secret",
        test_zone_id(),
        zone_key_id,
        1,
        test_node_id(),
        1,
        1,
        &zone_key,
        ZoneKeyAlgorithm::ChaCha20Poly1305,
    )
    .unwrap();

    let err = envelope
        .decrypt(&wrong_key, ZoneKeyAlgorithm::ChaCha20Poly1305, zone_key_id)
        .unwrap_err();
    assert!(format!("{err}").contains("decryption failed"));
}

#[test]
fn envelope_wrong_zone_key_id_fails() {
    let zone_key = test_zone_key();
    let zone_key_id = test_zone_key_id();
    let wrong_id = ZoneKeyId::from_bytes([0xFF; 8]);

    let envelope = SymbolEnvelope::encrypt(
        test_object_id(),
        0,
        10,
        b"data",
        test_zone_id(),
        zone_key_id,
        1,
        test_node_id(),
        1,
        1,
        &zone_key,
        ZoneKeyAlgorithm::ChaCha20Poly1305,
    )
    .unwrap();

    let err = envelope
        .decrypt(&zone_key, ZoneKeyAlgorithm::ChaCha20Poly1305, wrong_id)
        .unwrap_err();
    assert!(format!("{err}").contains("mismatch"));
}

#[test]
fn envelope_empty_plaintext() {
    let zone_key = test_zone_key();
    let zone_key_id = test_zone_key_id();

    let envelope = SymbolEnvelope::encrypt(
        test_object_id(),
        0,
        1,
        &[],
        test_zone_id(),
        zone_key_id,
        1,
        test_node_id(),
        1,
        1,
        &zone_key,
        ZoneKeyAlgorithm::ChaCha20Poly1305,
    )
    .unwrap();

    let decrypted = envelope
        .decrypt(&zone_key, ZoneKeyAlgorithm::ChaCha20Poly1305, zone_key_id)
        .unwrap();
    assert_eq!(decrypted, [] as [u8; 0]);
}

#[test]
fn envelope_serde_roundtrip() {
    let zone_key = test_zone_key();
    let zone_key_id = test_zone_key_id();

    let envelope = SymbolEnvelope::encrypt(
        test_object_id(),
        3,
        10,
        b"serde test",
        test_zone_id(),
        zone_key_id,
        500,
        test_node_id(),
        0x1234,
        7,
        &zone_key,
        ZoneKeyAlgorithm::ChaCha20Poly1305,
    )
    .unwrap();

    let json = serde_json::to_string(&envelope).unwrap();
    let deserialized: SymbolEnvelope = serde_json::from_str(&json).unwrap();

    let decrypted = deserialized
        .decrypt(&zone_key, ZoneKeyAlgorithm::ChaCha20Poly1305, zone_key_id)
        .unwrap();
    assert_eq!(decrypted, b"serde test");
}

// ============================================================================
// 10. Cross-module: encode → envelope → decode
// ============================================================================

#[test]
fn full_pipeline_encode_encrypt_decrypt_decode() {
    let config = default_config();
    let payload = deterministic_payload(2048);
    let zone_key = test_zone_key();
    let zone_key_id = test_zone_key_id();

    // Encode
    let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
    let source_symbols = encoder.encode_source();
    let oti = encoder.transmission_info();

    // Encrypt each symbol into an envelope
    let envelopes: Vec<SymbolEnvelope> = source_symbols
        .iter()
        .enumerate()
        .map(|(i, (esi, data))| {
            SymbolEnvelope::encrypt(
                test_object_id(),
                *esi,
                u16::try_from(encoder.source_symbols()).unwrap(),
                data,
                test_zone_id(),
                zone_key_id,
                1,
                test_node_id(),
                0xABCD,
                i as u64,
                &zone_key,
                ZoneKeyAlgorithm::ChaCha20Poly1305,
            )
            .unwrap()
        })
        .collect();

    // Decrypt and decode
    let mut decoder = RaptorQDecoder::new(oti, &config);
    let mut result = None;
    for env in &envelopes {
        let plaintext = env
            .decrypt(&zone_key, ZoneKeyAlgorithm::ChaCha20Poly1305, zone_key_id)
            .unwrap();
        if let Some(decoded) = decoder.add_symbol(env.esi, plaintext).unwrap() {
            result = Some(decoded);
            break;
        }
    }

    assert_eq!(result.unwrap(), payload);
}

// ============================================================================
// 11. Cross-module: chunking + encoding
// ============================================================================

#[test]
fn chunking_then_encode_decode_each_chunk() {
    let config = small_config(); // chunk_size = 256
    let payload = deterministic_payload(1000);

    let (manifest, chunks) = ChunkedObjectManifest::from_payload(&payload, config.chunk_size);
    assert!(manifest.chunk_count() > 1);

    // Encode and decode each chunk independently
    let mut decoded_chunks = Vec::new();
    for chunk in &chunks {
        let chunk_data = chunk.len();
        if chunk_data == 0 {
            decoded_chunks.push(RawChunk::new(vec![]));
            continue;
        }

        let mut chunk_config = small_config();
        chunk_config.max_object_size = u32::try_from(chunk_data).unwrap() + 1;

        let encoder = RaptorQEncoder::new(&chunk.bytes, &chunk_config).unwrap();
        let symbols = encoder.encode_all();
        let oti = encoder.transmission_info();

        let mut chunk_decoder = RaptorQDecoder::new(oti, &chunk_config);
        let mut chunk_result = None;
        for (esi, data) in symbols {
            if let Some(d) = chunk_decoder.add_symbol(esi, data).unwrap() {
                chunk_result = Some(d);
                break;
            }
        }
        decoded_chunks.push(RawChunk::new(chunk_result.unwrap()));
    }

    let reconstructed = manifest.reconstruct(&decoded_chunks).unwrap();
    assert_eq!(reconstructed, payload);
}

// ============================================================================
// 12. Admission controller
// ============================================================================

#[test]
fn admission_controller_basic_acquire_release() {
    let config = default_config();
    let controller = DecodeAdmissionController::new(&config);

    assert!(controller.has_capacity());
    assert_eq!(controller.active_count(), 0);

    let permit = controller.try_acquire();
    assert!(permit.is_some());
    assert_eq!(controller.active_count(), 1);

    drop(permit);
    assert_eq!(controller.active_count(), 0);
}

#[test]
fn admission_controller_respects_max_concurrent() {
    let controller =
        DecodeAdmissionController::with_limits(2, 1024 * 1024, Duration::from_secs(30), 1000);

    let _p1 = controller.try_acquire().unwrap();
    let _p2 = controller.try_acquire().unwrap();
    assert_eq!(controller.active_count(), 2);
    assert!(!controller.has_capacity());

    // Third acquire should fail
    assert!(controller.try_acquire().is_none());
}

#[test]
fn admission_controller_acquire_returns_error_when_full() {
    let controller =
        DecodeAdmissionController::with_limits(1, 1024 * 1024, Duration::from_secs(30), 1000);

    let _p1 = controller.acquire().unwrap();
    let result = controller.acquire();
    assert!(result.is_err());
}

#[test]
fn admission_controller_release_on_drop() {
    let controller =
        DecodeAdmissionController::with_limits(1, 1024 * 1024, Duration::from_secs(30), 1000);

    {
        let _permit = controller.acquire().unwrap();
        assert_eq!(controller.active_count(), 1);
    }
    // After drop
    assert_eq!(controller.active_count(), 0);
    assert!(controller.has_capacity());
}

// ============================================================================
// 13. Permit resource tracking
// ============================================================================

#[test]
fn permit_tracks_buffered_symbols() {
    let controller =
        DecodeAdmissionController::with_limits(16, 1024 * 1024, Duration::from_secs(30), 100);

    let mut permit = controller.acquire().unwrap();
    assert_eq!(permit.symbols_buffered(), 0);
    assert_eq!(permit.memory_used(), 0);

    permit.try_buffer_symbol(1024).unwrap();
    assert_eq!(permit.symbols_buffered(), 1);
    assert_eq!(permit.memory_used(), 1024);
}

#[test]
fn permit_rejects_excess_symbols() {
    let controller =
        DecodeAdmissionController::with_limits(16, 1024 * 1024, Duration::from_secs(30), 2);

    let mut permit = controller.acquire().unwrap();
    permit.try_buffer_symbol(100).unwrap();
    permit.try_buffer_symbol(100).unwrap();

    let err = permit.try_buffer_symbol(100).unwrap_err();
    assert!(matches!(err, DecodeError::SymbolBufferExceeded { .. }));
}

#[test]
fn permit_rejects_excess_memory() {
    let controller = DecodeAdmissionController::with_limits(16, 200, Duration::from_secs(30), 1000);

    let mut permit = controller.acquire().unwrap();
    permit.try_buffer_symbol(150).unwrap();

    let err = permit.try_buffer_symbol(100).unwrap_err();
    assert!(matches!(err, DecodeError::MemoryLimitExceeded { .. }));
}

#[test]
fn permit_is_valid_when_fresh() {
    let controller =
        DecodeAdmissionController::with_limits(16, 1024 * 1024, Duration::from_secs(30), 1000);
    let permit = controller.acquire().unwrap();
    assert!(permit.is_valid());
}

#[test]
fn permit_time_tracking() {
    let controller =
        DecodeAdmissionController::with_limits(16, 1024 * 1024, Duration::from_secs(30), 1000);
    let permit = controller.acquire().unwrap();
    assert!(permit.elapsed() < Duration::from_secs(1));
    assert!(permit.time_remaining() > Duration::from_secs(20));
}

// ============================================================================
// 14. MTU-safe symbol sizing
// ============================================================================

#[test]
fn mtu_safe_symbol_size_returns_value() {
    let result = RaptorQConfig::mtu_safe_symbol_size(1200, 1);
    assert!(result.is_some());
    let size = result.unwrap();
    assert!(size > 0);
    assert!(size <= 1200);
}

#[test]
fn mtu_safe_symbol_size_zero_datagram_returns_none() {
    let result = RaptorQConfig::mtu_safe_symbol_size(0, 1);
    assert!(result.is_none());
}

#[test]
fn config_bound_symbol_size() {
    let mut config = default_config();
    let result = config.bound_symbol_size(1200, 1);
    assert!(result.is_some());
    // Symbol size should be adjusted
    assert!(config.symbol_size <= 1200);
}

// ============================================================================
// 15. Error Display messages
// ============================================================================

#[test]
fn encode_error_display() {
    let err = EncodeError::EmptyPayload;
    assert!(format!("{err}").contains("empty"));

    let err = EncodeError::PayloadTooLarge { size: 100, max: 50 };
    let msg = format!("{err}");
    assert!(msg.contains("100"));
    assert!(msg.contains("50"));
}

#[test]
fn decode_error_display() {
    let err = DecodeError::Timeout;
    assert_ne!(format!("{err}"), "");

    let err = DecodeError::InsufficientSymbols {
        received: 3,
        needed: 10,
    };
    let msg = format!("{err}");
    assert!(msg.contains("received"));
    assert!(msg.contains("need"));

    let err = DecodeError::AdmissionDenied {
        reason: "test".into(),
    };
    assert!(format!("{err}").contains("test"));
}

#[test]
fn chunk_error_display() {
    let err = ChunkError::HashMismatch;
    assert_ne!(format!("{err}"), "");

    let err = ChunkError::MissingChunks {
        expected: 5,
        got: 3,
    };
    let msg = format!("{err}");
    assert!(msg.contains("expected"));
    assert!(msg.contains("got"));

    let err = ChunkError::InvalidChunkIndex {
        index: 10,
        count: 5,
    };
    assert!(format!("{err}").contains("10"));
}

// ============================================================================
// 16. Config serde
// ============================================================================

#[test]
fn config_serde_roundtrip() {
    let config = default_config();
    let json = serde_json::to_string(&config).unwrap();
    let deserialized: RaptorQConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.symbol_size, config.symbol_size);
    assert_eq!(deserialized.repair_ratio_bps, config.repair_ratio_bps);
    assert_eq!(deserialized.max_object_size, config.max_object_size);
    assert_eq!(deserialized.decode_timeout, config.decode_timeout);
}

#[test]
fn oti_serde_roundtrip() {
    let oti = ObjectTransmissionInformation::new(4096, 512, 1, 2, 8);
    let json = serde_json::to_string(&oti).unwrap();
    let deserialized: ObjectTransmissionInformation = serde_json::from_str(&json).unwrap();
    assert_eq!(oti, deserialized);
}

// ============================================================================
// 17. Cross-module: EncodingDecision direct roundtrip
// ============================================================================

#[test]
fn encoding_decision_direct_roundtrip() {
    let config = default_config();
    let payload = deterministic_payload(2048);

    let decision = EncodingDecision::for_payload(&payload, &config).unwrap();
    assert!(decision.is_direct());

    if let EncodingDecision::Direct {
        symbols,
        transmission_info,
    } = decision
    {
        let mut decoder = RaptorQDecoder::new(transmission_info, &config);
        let mut result = None;
        for (esi, data) in symbols {
            if let Some(decoded) = decoder.add_symbol(esi, data).unwrap() {
                result = Some(decoded);
                break;
            }
        }
        assert_eq!(result.unwrap(), payload);
    } else {
        panic!("expected Direct");
    }
}

#[test]
fn encoding_decision_chunked_roundtrip() {
    let config = small_config();
    let payload = deterministic_payload(1000);

    let decision = EncodingDecision::for_payload(&payload, &config).unwrap();
    assert!(decision.is_chunked());

    if let EncodingDecision::Chunked { manifest, chunks } = decision {
        let reconstructed = manifest.reconstruct(&chunks).unwrap();
        assert_eq!(reconstructed, payload);
    } else {
        panic!("expected Chunked");
    }
}

// ============================================================================
// 18. Determinism: same payload → same symbols
// ============================================================================

#[test]
fn encoding_is_deterministic() {
    let config = default_config();
    let payload = deterministic_payload(3000);

    let enc1 = RaptorQEncoder::new(&payload, &config).unwrap();
    let enc2 = RaptorQEncoder::new(&payload, &config).unwrap();

    let syms1 = enc1.encode_all();
    let syms2 = enc2.encode_all();

    assert_eq!(syms1.len(), syms2.len());
    for (s1, s2) in syms1.iter().zip(syms2.iter()) {
        assert_eq!(s1.0, s2.0); // ESI match
        assert_eq!(s1.1, s2.1); // data match
    }
}

#[test]
fn chunking_is_deterministic() {
    let payload = deterministic_payload(2000);
    let (m1, c1) = ChunkedObjectManifest::from_payload(&payload, 500);
    let (m2, c2) = ChunkedObjectManifest::from_payload(&payload, 500);

    assert_eq!(m1.chunk_count(), m2.chunk_count());
    for (a, b) in c1.iter().zip(c2.iter()) {
        assert_eq!(a.content_id(), b.content_id());
    }
}

// ============================================================================
// 19. Envelope field verification
// ============================================================================

#[test]
fn envelope_preserves_metadata_after_encrypt() {
    let zone_key = test_zone_key();
    let zone_key_id = test_zone_key_id();
    let object_id = test_object_id();
    let zone_id = test_zone_id();
    let node_id = test_node_id();

    let envelope = SymbolEnvelope::encrypt(
        object_id,
        7,
        15,
        b"metadata test",
        zone_id.clone(),
        zone_key_id,
        999,
        node_id.clone(),
        0x4242,
        55,
        &zone_key,
        ZoneKeyAlgorithm::ChaCha20Poly1305,
    )
    .unwrap();

    assert_eq!(envelope.object_id, object_id);
    assert_eq!(envelope.esi, 7);
    assert_eq!(envelope.k, 15);
    assert_eq!(envelope.zone_id, zone_id);
    assert_eq!(envelope.zone_key_id, zone_key_id);
    assert_eq!(envelope.epoch_id, 999);
    assert_eq!(envelope.source_id, node_id);
    assert_eq!(envelope.sender_instance_id, 0x4242);
    assert_eq!(envelope.frame_seq, 55);
    // Ciphertext should be non-empty
    assert_ne!(envelope.data, [] as [u8; 0]);
    // Auth tag should be non-zero
    assert_ne!(envelope.auth_tag, [0u8; 16]);
}

// ============================================================================
// 20. Decode with insufficient symbols
// ============================================================================

#[test]
fn decoder_with_expected_symbols_constructor() {
    let config = default_config();
    let decoder = RaptorQDecoder::with_expected_symbols(4, 4096, 1024, &config);
    assert_eq!(decoder.expected_k(), 4);
    assert_eq!(decoder.received_count(), 0);
    assert!(!decoder.likely_complete());
}

// ============================================================================
// 21. Admission controller clone + default
// ============================================================================

#[test]
fn admission_controller_clone_shares_state() {
    let controller =
        DecodeAdmissionController::with_limits(4, 1024 * 1024, Duration::from_secs(30), 1000);

    let clone = controller.clone();
    let _p = controller.acquire().unwrap();
    // Clone sees the same active count
    assert_eq!(clone.active_count(), 1);
}

#[test]
fn admission_controller_default() {
    let controller = DecodeAdmissionController::default();
    assert!(controller.has_capacity());
    assert_eq!(controller.active_count(), 0);
}
