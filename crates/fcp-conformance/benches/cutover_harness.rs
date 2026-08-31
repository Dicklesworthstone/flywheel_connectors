//! Unified benchmark harness for FCP3 cutover-critical flows.
//!
//! This harness measures the performance of cross-cutting paths that MUST be
//! preserved through the FCP3 cutover (host-first -> mesh-first). It exercises
//! the protocol, crypto, revocation, gossip, and serialization hot paths in a
//! single repeatable suite.
//!
//! # Baseline document
//!
//! See `docs/FCP3_Pre_Cutover_Baseline.md` for the canonical scenario set and
//! comparison protocol.
//!
//! # Running
//!
//! ```sh
//! cargo bench -p fcp-conformance --bench cutover_harness
//! ```
//!
//! For structured output:
//! ```sh
//! cargo bench -p fcp-conformance --bench cutover_harness -- --output-format bencher
//! ```

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

use fcp_cbor::SchemaId;
use fcp_crypto::{
    AeadKey, ChaCha20Nonce, Ed25519SigningKey, MacKey, blake3_mac, blake3_mac_verify,
    chacha20_decrypt, chacha20_encrypt,
};
use fcp_mesh::gossip::{GossipConfig, GossipMessage, PriorityGossipPolicy, RevocationPushMessage};
use fcp_prelude::{
    ObjectHeader, ObjectId, Provenance, RevocationDecision, RevocationFreshnessClass,
    RevocationObject, RevocationRegistry, RevocationScope, RevocationSlaChecker, ZoneId,
};
use fcp_protocol::{
    FCPC_HEADER_LEN, FCPC_TAG_LEN, FcpcFrame, FcpcFrameFlags, MeshSessionId, SessionDirection,
};
use semver::Version;

// ============================================================================
// Helpers
// ============================================================================

fn test_header() -> ObjectHeader {
    ObjectHeader {
        encryption_kind: Default::default(),
        schema: SchemaId::new("fcp.bench", "CutoverHarness", Version::new(1, 0, 0)),
        zone_id: ZoneId::work(),
        created_at: 1_700_000_000,
        provenance: Provenance::new(ZoneId::work()),
        refs: vec![],
        foreign_refs: vec![],
        ttl_secs: None,
        placement: None,
    }
}

const fn make_object_id(seed: u8) -> ObjectId {
    ObjectId::from_bytes([seed; 32])
}

fn make_id_from_u32(i: u32) -> ObjectId {
    let mut b = [0u8; 32];
    b[..4].copy_from_slice(&i.to_le_bytes());
    ObjectId::from_bytes(b)
}

fn make_revocation(revoked_ids: &[ObjectId]) -> RevocationObject {
    RevocationObject {
        header: test_header(),
        revoked: revoked_ids.to_vec(),
        scope: RevocationScope::Capability,
        reason: "benchmark revocation".into(),
        effective_at: 1_700_000_000,
        expires_at: None,
        signature: [0u8; 64],
    }
}

/// Build a pre-populated registry with `n` revocations for lookup benchmarks.
fn populated_registry(n: u32) -> RevocationRegistry {
    let mut registry = RevocationRegistry::new();
    for i in 0..n {
        registry.add_revocation(&make_revocation(&[make_id_from_u32(i)]));
    }
    registry.update_head(make_object_id(0xFF), u64::from(n), 1_700_000_000);
    registry
}

// ============================================================================
// 1. Revocation Pipeline (S3, C1.x) — cutover must not degrade enforcement
// ============================================================================

fn bench_revocation_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("cutover/revocation_lookup");

    for size in [100, 1_000, 10_000] {
        let registry = populated_registry(size);
        let existing = make_id_from_u32(size / 2);
        let missing = make_id_from_u32(size + 1);

        group.bench_with_input(BenchmarkId::new("hit", size), &size, |b, _| {
            b.iter(|| black_box(registry.is_revoked(&existing)));
        });
        group.bench_with_input(BenchmarkId::new("miss", size), &size, |b, _| {
            b.iter(|| black_box(registry.is_revoked(&missing)));
        });
    }
    group.finish();
}

fn bench_revocation_seal_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("cutover/revocation_seal");
    let registry = populated_registry(1_000);
    let token_id = make_id_from_u32(500);

    group.bench_function("check_with_seal", |b| {
        b.iter(|| black_box(registry.check_with_seal(&token_id, 1_700_000_001)));
    });

    let seal = registry.check_with_seal(&token_id, 1_700_000_001);
    group.bench_function("validate_seal", |b| {
        b.iter(|| black_box(registry.validate_seal(&seal, &token_id)));
    });

    group.finish();
}

fn bench_revocation_sla(c: &mut Criterion) {
    let mut group = c.benchmark_group("cutover/revocation_sla");
    let checker = RevocationSlaChecker::new(1000, 1_700_000_000, 300);

    group.bench_function("check_sla_fresh", |b| {
        b.iter(|| black_box(checker.check_sla(1_700_000_200)));
    });

    group.bench_function("check_sla_breached", |b| {
        b.iter(|| black_box(checker.check_sla(1_700_000_500)));
    });

    group.bench_function("may_proceed_critical", |b| {
        b.iter(|| {
            black_box(checker.may_proceed(1_700_000_500, RevocationFreshnessClass::Critical))
        });
    });

    group.finish();
}

// ============================================================================
// 2. Protocol Framing (I1 data path) — invoke latency-critical
// ============================================================================

fn bench_fcpc_seal_open(c: &mut Criterion) {
    let mut group = c.benchmark_group("cutover/fcpc_roundtrip");
    let session_id = MeshSessionId([0xAA; 16]);
    let k_ctx: [u8; 32] = [0x11; 32];
    let dir = SessionDirection::InitiatorToResponder;

    for payload_size in [256, 1024, 4096] {
        let plaintext = vec![0xBB_u8; payload_size];
        let total_size = FCPC_HEADER_LEN + payload_size + FCPC_TAG_LEN;
        group.throughput(Throughput::Bytes(total_size as u64));

        group.bench_with_input(
            BenchmarkId::new("seal", payload_size),
            &payload_size,
            |b, _| {
                b.iter(|| {
                    black_box(FcpcFrame::seal(
                        session_id,
                        42,
                        dir,
                        FcpcFrameFlags::default(),
                        &plaintext,
                        &k_ctx,
                    ))
                });
            },
        );

        let sealed = FcpcFrame::seal(
            session_id,
            42,
            dir,
            FcpcFrameFlags::default(),
            &plaintext,
            &k_ctx,
        )
        .expect("seal");
        group.bench_with_input(
            BenchmarkId::new("open", payload_size),
            &payload_size,
            |b, _| {
                b.iter(|| black_box(sealed.open(dir, &k_ctx)));
            },
        );
    }
    group.finish();
}

// ============================================================================
// 3. Crypto Hot Paths — underpin every secure operation
// ============================================================================

fn bench_crypto_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("cutover/crypto_sign");
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let message = b"cutover-critical capability token payload";
    let signature = signing_key.sign(message);

    group.bench_function("ed25519_sign", |b| {
        b.iter(|| black_box(signing_key.sign(black_box(message))));
    });

    group.bench_function("ed25519_verify", |b| {
        b.iter(|| black_box(verifying_key.verify(black_box(message), black_box(&signature))));
    });

    group.finish();
}

fn bench_crypto_mac(c: &mut Criterion) {
    let mut group = c.benchmark_group("cutover/crypto_mac");
    let key = MacKey::from_bytes([0x42; 32]);

    for size in [32, 1024] {
        let data = vec![0xCC_u8; size];
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("blake3_mac", size), &size, |b, _| {
            b.iter(|| black_box(blake3_mac(&key, black_box(&data))));
        });

        let mac = blake3_mac(&key, &data);
        group.bench_with_input(BenchmarkId::new("blake3_verify", size), &size, |b, _| {
            b.iter(|| black_box(blake3_mac_verify(&key, black_box(&data), black_box(&mac))));
        });
    }
    group.finish();
}

fn bench_crypto_aead(c: &mut Criterion) {
    let mut group = c.benchmark_group("cutover/crypto_aead");
    let key = AeadKey::from_bytes([0x33; 32]);
    let nonce = ChaCha20Nonce::from_bytes([0x44; 12]);
    let aad: &[u8] = b"cutover-bench-aad";

    for size in [256, 1024, 4096] {
        let plaintext = vec![0xDD_u8; size];
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("encrypt", size), &size, |b, _| {
            b.iter(|| black_box(chacha20_encrypt(&key, &nonce, black_box(&plaintext), aad)));
        });

        let ciphertext = chacha20_encrypt(&key, &nonce, &plaintext, aad).expect("encrypt");
        group.bench_with_input(BenchmarkId::new("decrypt", size), &size, |b, _| {
            b.iter(|| black_box(chacha20_decrypt(&key, &nonce, black_box(&ciphertext), aad)));
        });
    }
    group.finish();
}

// ============================================================================
// 4. Gossip Wire Format (mesh propagation path) — mesh-first critical
// ============================================================================

fn bench_gossip_push_serde(c: &mut Criterion) {
    let mut group = c.benchmark_group("cutover/gossip_push");

    for n_ids in [1, 10, 100] {
        let ids: Vec<ObjectId> = (0..n_ids).map(make_id_from_u32).collect();
        let push = RevocationPushMessage::new(
            fcp_core::TailscaleNodeId::new("node-bench"),
            ZoneId::work(),
            ids,
            42,
            1_700_000_000,
        );
        let msg = GossipMessage::RevocationPush(push);

        let json = serde_json::to_vec(&msg).expect("serialize");

        group.bench_with_input(BenchmarkId::new("serialize", n_ids), &n_ids, |b, _| {
            b.iter(|| black_box(serde_json::to_vec(&msg)));
        });

        group.bench_with_input(BenchmarkId::new("deserialize", n_ids), &n_ids, |b, _| {
            b.iter(|| black_box(serde_json::from_slice::<GossipMessage>(&json)));
        });
    }
    group.finish();
}

fn bench_gossip_config(c: &mut Criterion) {
    let mut group = c.benchmark_group("cutover/gossip_policy");
    let config = GossipConfig::default();

    group.bench_function("direct_push_interval", |b| {
        b.iter(|| black_box(PriorityGossipPolicy::DirectPush.interval_ms(&config)));
    });

    group.bench_function("standard_interval", |b| {
        b.iter(|| black_box(PriorityGossipPolicy::Standard.interval_ms(&config)));
    });

    group.finish();
}

// ============================================================================
// 5. CBOR Schema Roundtrip — serialization underpins all mesh objects
// ============================================================================

fn bench_schema_serde(c: &mut Criterion) {
    let mut group = c.benchmark_group("cutover/schema_serde");

    let simple = SchemaId::new("fcp.core", "Revocation", Version::new(1, 0, 0));
    let long = SchemaId::new(
        "fcp.connectors.google.workspace",
        "DriveFileMetadata",
        Version::new(2, 1, 0),
    );

    group.bench_function("simple_hash", |b| {
        b.iter(|| black_box(simple.hash()));
    });

    group.bench_function("long_hash", |b| {
        b.iter(|| black_box(long.hash()));
    });

    group.bench_function("json_roundtrip", |b| {
        b.iter(|| {
            let bytes = serde_json::to_vec(&simple).expect("ser");
            let _rt: SchemaId = serde_json::from_slice(&bytes).expect("de");
            black_box(());
        });
    });

    group.finish();
}

// ============================================================================
// 6. Cross-Cutting: Full Enforcement Path
//    check revocation -> seal -> create push -> serialize push
//    This is the critical path latency for revocation enforcement + propagation.
// ============================================================================

fn bench_full_enforcement_path(c: &mut Criterion) {
    let mut group = c.benchmark_group("cutover/full_enforcement");

    let registry = populated_registry(10_000);
    let token_id = make_id_from_u32(5_000);

    group.bench_function("check_seal_push_serialize", |b| {
        b.iter(|| {
            // 1. Check revocation with seal
            let seal = registry.check_with_seal(&token_id, 1_700_000_001);
            assert_eq!(seal.decision, RevocationDecision::Revoked);

            // 2. Validate seal
            let validation = registry.validate_seal(&seal, &token_id);
            assert!(validation.is_valid());

            // 3. Create push message
            let push = RevocationPushMessage::new(
                fcp_core::TailscaleNodeId::new("node-enforcer"),
                ZoneId::work(),
                vec![token_id],
                10_001,
                1_700_000_001,
            );

            // 4. Serialize for wire
            let msg = GossipMessage::RevocationPush(push);
            let wire = serde_json::to_vec(&msg).expect("serialize");
            black_box(wire);
        });
    });

    // Non-revoked fast path: check + seal + proceed
    let clean_token = make_id_from_u32(99_999);
    group.bench_function("clean_check_seal_proceed", |b| {
        b.iter(|| {
            let seal = registry.check_with_seal(&clean_token, 1_700_000_001);
            assert_eq!(seal.decision, RevocationDecision::NotRevoked);
            let validation = registry.validate_seal(&seal, &clean_token);
            assert!(validation.is_valid());
            black_box(seal);
        });
    });

    group.finish();
}

// ============================================================================
// Criterion Groups
// ============================================================================

criterion_group!(
    revocation,
    bench_revocation_lookup,
    bench_revocation_seal_roundtrip,
    bench_revocation_sla,
);

criterion_group!(protocol, bench_fcpc_seal_open,);

criterion_group!(
    crypto,
    bench_crypto_signing,
    bench_crypto_mac,
    bench_crypto_aead,
);

criterion_group!(gossip, bench_gossip_push_serde, bench_gossip_config,);

criterion_group!(serialization, bench_schema_serde,);

criterion_group!(enforcement, bench_full_enforcement_path,);

criterion_main!(
    revocation,
    protocol,
    crypto,
    gossip,
    serialization,
    enforcement
);
