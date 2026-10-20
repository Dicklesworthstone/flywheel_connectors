# Phase Q.G — Threshold HPKE KEM Reusing FROST DKG Substrate

- **Beads**: `flywheel_connectors-angoc.11.6`, `flywheel_connectors-angoc.11.6.1` (Parent: `flywheel_connectors-angoc.11`)
- **EV Score**: `71 / 100` (Rank 5 — **Top-5 Landed & Closed**)
- **Status**: Landed and verified across `fcp-crypto`, `fcp-core`, and `fcp-e2e`.

## Implementation & Proof Artifacts

- **Threshold HPKE KEM**: [`crates/fcp-crypto/src/threshold_hpke.rs`](../../../crates/fcp-crypto/src/threshold_hpke.rs) implements $t$-of-$n$ Shamir/FROST-compatible X25519 key-share generation, partial decapsulation share emission, Lagrange interpolation in the exponent, and ChaCha20-Poly1305 AEAD opening.
- **Object Store Integration**: `ObjectEncryptionKind::ThresholdHpkeQuorum { threshold, epoch }` in [`crates/fcp-core/src/object.rs`](../../../crates/fcp-core/src/object.rs).
- **Unit & Roundtrip Tests**: [`crates/fcp-crypto/tests/threshold_hpke_roundtrip.rs`](../../../crates/fcp-crypto/tests/threshold_hpke_roundtrip.rs) (`5 passed; 0 failed`).
- **Cross-Mesh E2E Proof**: [`crates/fcp-e2e/tests/threshold_hpke_sealed_object_e2e.rs`](../../../crates/fcp-e2e/tests/threshold_hpke_sealed_object_e2e.rs) (`1 passed; 0 failed`).

## Fallback & Rollback Contract

- **Single-Recipient HPKE Fallback**: Zones configured with `ObjectEncryptionKind::ZoneKey` or single-recipient `HpkeSealedBox` (`crates/fcp-crypto/src/hpke_seal.rs`) bypass threshold share aggregation while maintaining full AEAD + domain-separated AAD protection.
