# Post-Quantum Hybrid Hardening Cutover Plan (Ed25519 + ML-DSA-65)

Bead: `flywheel_connectors-angoc.8`
Status: **Steady-State Achieved (`PqSigningPolicy::BothRequired`)**

---

## 1. Overview & Security Invariants

Flywheel Connector Protocol (FCP) V4 enforces hybrid classical + post-quantum authenticity across all signed protocol objects using dual **Ed25519** + **FIPS 204 ML-DSA-65** signatures inside [`SignedEnvelope<T>`](../../crates/fcp-crypto/src/hybrid.rs) and **X-Wing** (`X25519` + `ML-KEM-768`) for post-quantum zone-key encapsulation.

### Covered Object Families (`HybridSignedObjectKind`)
Every signed control-plane and data-plane envelope belongs to one of the seven canonical families in [`crates/fcp-crypto/src/hybrid.rs`](../../crates/fcp-crypto/src/hybrid.rs):
1. `capability_token` (`fcp.hybrid-signing.capability_token.v1`)
2. `audit_event` (`fcp.hybrid-signing.audit_event.v1`)
3. `manifest` (`fcp.hybrid-signing.manifest.v1`)
4. `gossip_frame` (`fcp.hybrid-signing.gossip_frame.v1`)
5. `revocation` (`fcp.hybrid-signing.revocation.v1`)
6. `operation_receipt` (`fcp.hybrid-signing.operation_receipt.v1`)
7. `zone_checkpoint` (`fcp.hybrid-signing.zone_checkpoint.v1`)

All signatures bind to domain context `FCP-HYBRID-SIGNED-ENVELOPE-V1` over deterministic CBOR signing bytes (`signing_bytes_for_payload`).

---

## 2. Three-Stage Migration Cutover (N.4) & TLA+ State Alignment

The cryptographic policy cutover mirrors the formal state machine verified in [`specs/tla/cutover.tla`](../../specs/tla/cutover.tla):

| Stage | Timeline | `PqSigningPolicy` | TLA+ State (`specs/tla/cutover.tla`) | Signer Posture | Verifier Posture |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Pre-Cutover (V3)** | Legacy | `ClassicalOnly` | `V1Only` | Ed25519 only | Requires Ed25519 |
| **N.4.a Shadow / Transitional** | Week 0–2 | `EitherOk` | `V2Shadow` | Dual-signs Ed25519 + ML-DSA-65 where available | Accepts valid signature from either algorithm; emits `PqSignatureMismatch` warning when one signature is absent |
| **N.4.b Dual-Sign Default** | Week 2–6 | `BothRequired` (new objects) / `EitherOk` (legacy replay window) | `V2Default` | `SignedEnvelope::sign` and `HybridSignable::sign_hybrid` emit both Ed25519 and ML-DSA-65 by default | New objects require both signatures |
| **N.4.c Steady-State (Current)** | Week 6+ | `BothRequired` | `V2Permanent` | Both Ed25519 and ML-DSA-65 required on all 7 object families | Both signatures must be present and valid; missing or stripped signatures reject with `MissingPqSignature` / `MissingClassicalSignature` (`reason_code = "DowngradeAttempt"`) |

### Emergency Rollback Gate
Any temporary rollback from `BothRequired` to `EitherOk` (corresponding to `TriggerFallback` / `EmergencyRecoverV1` in `specs/tla/cutover.tla`) must pass through [`downgrade_policy_to_either_ok`](../../crates/fcp-crypto/src/hybrid.rs), which requires a hardware-token-backed [`PqPolicyDowngradeAuthorizer`](../../crates/fcp-crypto/src/hybrid.rs) and emits a non-repudiable [`PqPolicyDowngradeAudit`](../../crates/fcp-crypto/src/hybrid.rs) receipt (`event_type = "pq.policy_downgrade"`).

---

## 3. Synchronized Epoch Key Rotation & Compromise Semantics (N.3)

- **Epoch-Synchronized Rotation:** Device and zone signing keys rotate on the same epoch boundary (`KeyRotationSchedule` in `fcp-core::enrollment`). Every rotation ceremony produces a cross-signed [`OwnerKeyMigrationAttestation`](../../crates/fcp-crypto/src/owner_key.rs) over [`OwnerKeyMigrationTranscript`](../../crates/fcp-crypto/src/owner_key.rs) (`schema = "fcp.owner-key-migration.v1"`, domain `FCP-OWNER-KEY-MIGRATION-V1`) with monotonic `migration_epoch`, `not_before_unix`, and `not_after_unix` bounds.
- **Compromise Invariant:** An owner identity holds both an Ed25519 root key and an ML-DSA-65 root key (`HybridOwnerKeyIds`). Compromise or loss of **either** root key is treated as full owner compromise and requires an immediate epoch rotation and revocation emission.

---

## 4. Wesolowski VDF Owner-Burst Rate Limiting (N.3.bis)

To bound the blast radius of a stolen owner key before revocation propagates, high-privilege owner ceremonies are rate-limited by the pure-Rust Wesolowski Verifiable Delay Function in [`crates/fcp-crypto/src/vdf/wesolowski.rs`](../../crates/fcp-crypto/src/vdf/wesolowski.rs):
- Sequential squaring evaluation in the 512-bit signed quadratic-residue group ($\mathbb{Z}/N\mathbb{Z})^\times / \{\pm 1\}$ with $N = 2^{512} - 569$.
- Compact 128-byte proof (`VdfOutput || VdfProof`) verified in $O(\log T)$ steps via Fiat-Shamir prime derivation (`blake3` + deterministic 64-bit Miller-Rabin) and Shamir simultaneous exponentiation.

---

## 5. Threshold HPKE KEM for Cross-Mesh Sealed Objects (N.6)

Cross-zone and cross-mesh sealed objects use the $t$-of-$n$ Threshold HPKE construction in [`crates/fcp-crypto/src/threshold_hpke.rs`](../../crates/fcp-crypto/src/threshold_hpke.rs) (`ThresholdSealedObject`), ensuring that any $t$ cooperating zone shares can reconstruct the decapsulation secret while fewer than $t$ shares reveal zero information about the encapsulated key.

---

## 6. Conformance & Performance Evidence Gates (N.2 & N.5)

- **7-Kind Hybrid Round-Trip:** [`crates/fcp-crypto/tests/hybrid_signing_roundtrip.rs`](../../crates/fcp-crypto/tests/hybrid_signing_roundtrip.rs) and [`crates/fcp-conformance/tests/hybrid_signing_coverage.rs`](../../crates/fcp-conformance/tests/hybrid_signing_coverage.rs)
- **Downgrade-Attack Rejection:** [`crates/fcp-crypto/tests/downgrade_attack_test.rs`](../../crates/fcp-crypto/tests/downgrade_attack_test.rs) and [`crates/fcp-conformance/tests/pq_downgrade_attack_rejection.rs`](../../crates/fcp-conformance/tests/pq_downgrade_attack_rejection.rs) (1,000 proptest envelopes across all 7 object families)
- **Synchronized Key Rotation E2E:** [`crates/fcp-crypto/tests/hybrid_key_rotation_e2e.rs`](../../crates/fcp-crypto/tests/hybrid_key_rotation_e2e.rs)
- **Threshold HPKE Round-Trip & Below-$t$ Safety:** [`crates/fcp-crypto/tests/threshold_hpke_roundtrip.rs`](../../crates/fcp-crypto/tests/threshold_hpke_roundtrip.rs)
- **Performance Budget (`p99 <= 2.0 ms` across `csd`, `contabo`, `laptop`):** [`docs/perf/pq_signing_overhead_evidence.md`](../perf/pq_signing_overhead_evidence.md) and [`crates/fcp-conformance/tests/pq_perf_budget_held.rs`](../../crates/fcp-conformance/tests/pq_perf_budget_held.rs)
