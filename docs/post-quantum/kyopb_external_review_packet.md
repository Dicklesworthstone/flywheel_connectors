# KYOPB External Lattice-Crypto Review Packet (`flywheel_connectors-kyopb.1.3.1.1.6.3`)

- **Bead:** `flywheel_connectors-kyopb.1.3.1.1.6.3` (child of `flywheel_connectors-kyopb.1.3.1.1.6`)
- **Packet Date:** `2026-10-20`
- **Review Gate Status:** `PACKET_ASSEMBLED_AWAITING_EXTERNAL_REVIEWER` (self-review is explicitly not treated as external review completion)
- **Machine-Readable Packet:** [`artifacts/proofs/kyopb_review_packet/2026-10-20/review_packet.json`](file:///data/projects/flywheel_connectors/artifacts/proofs/kyopb_review_packet/2026-10-20/review_packet.json)
- **Finding Disposition Ledger:** [`artifacts/proofs/kyopb_review_packet/2026-10-20/finding_disposition.json`](file:///data/projects/flywheel_connectors/artifacts/proofs/kyopb_review_packet/2026-10-20/finding_disposition.json)

---

## 1. Design Docs & Route Decision Packet

- [`docs/post-quantum/lattice_trapdoor_delegation.md`](file:///data/projects/flywheel_connectors/docs/post-quantum/lattice_trapdoor_delegation.md) — V4 MP12/CHKP/GPV08 lattice-trapdoor delegation architecture.
- [`docs/post-quantum/lattice_primitive_decision_2026-05-07.md`](file:///data/projects/flywheel_connectors/docs/post-quantum/lattice_primitive_decision_2026-05-07.md) — primitive evaluation and security boundary analysis.
- [`docs/post-quantum/lattice_primitive_route_packet_2026-05-08.md`](file:///data/projects/flywheel_connectors/docs/post-quantum/lattice_primitive_route_packet_2026-05-08.md) — internal no-FFI Rust implementation route decision (rejecting `qfall-tools` / C-FFI in production).
- [`docs/post-quantum/throughput_benchmark.md`](file:///data/projects/flywheel_connectors/docs/post-quantum/throughput_benchmark.md) — current criterion throughput and latency benchmark evidence across `SMALL_TEST` and `V4_REFERENCE`.

---

## 2. Implementation File List & Proof Gauntlet References

### Implementation Files
- [`crates/fcp-crypto-pq/src/lib.rs`](file:///data/projects/flywheel_connectors/crates/fcp-crypto-pq/src/lib.rs)
- [`crates/fcp-crypto-pq/src/lattice.rs`](file:///data/projects/flywheel_connectors/crates/fcp-crypto-pq/src/lattice.rs)
- [`crates/fcp-crypto-pq/benches/lattice_delegation.rs`](file:///data/projects/flywheel_connectors/crates/fcp-crypto-pq/benches/lattice_delegation.rs)
- [`lean/Fcp/Crypto/LatticeDelegation.lean`](file:///data/projects/flywheel_connectors/lean/Fcp/Crypto/LatticeDelegation.lean)
- [`scripts/e2e/lattice_delegation_assurance_gauntlet.sh`](file:///data/projects/flywheel_connectors/scripts/e2e/lattice_delegation_assurance_gauntlet.sh)

### Proof-Gauntlet JSONL Hashes (from `.6.2` & `.6.4`)
- `RUN_ID=kyopb-lockfile-main-sagestork-20260604T0913Z`:
  - `sha256:bbc080478c1c83535936859c2dea5bcc39cc808370d72293cb864f5d17410705` (29/29 JSONL rows pass, `final_redaction_scan` pass, `jsonl_contract_validation` pass)
- `RUN_ID=kyopb-lockfile-main-sagestork-20260604Tcurrentmain-b9c9c0d90`:
  - `sha256:3bbee2a29e55a44f8f0994e602707feb572346b8003de4ada48b5f84e7be6e70`

### Lean Theorem & Assumption IDs
- `lattice_delegation_chain_corruption_rejected`
- `lattice_delegation_sis_assumption_boundary_complete`
- `lattice_trapdoor_capability_unforgeability_reduces_to_sis_assumptions`

---

## 3. Cryptographic & Systems Rationale

1. **Parameter & Representation Rationale:**
   - Profiles: `SMALL_TEST` (deterministic CI/unit test profile) and `V4_REFERENCE` (`n = 512`, `q = 12289`, gadget base `b = 2`, depth-bounded delegation tree).
   - Representation v2 stores seed-backed public material (`A_bar` seed + structured branch extensions) rather than multi-megabyte expanded matrices on the wire.
2. **Public-Matrix / `A_bar` Materialization Cache & Deterministic Parallel Verifier Rationale:**
   - `A_bar` expansion is deterministic from the public seed via domain-separated SHAKE256 and cached by content digest (`[u8; 32]`), eliminating repeated expansion overhead while preserving bit-identical verification results across single-threaded and Rayon parallel verifier lanes.
3. **Request / Operation / Principal / Certificate / Trust-Set Binding & Replay Denial:**
   - Preimage targets bind the canonical CBOR tuple `(zone_id, principal_id, operation_id, certificate_chain_digest, trust_set_digest, request_id, expiry_epoch)`.
   - Replay denial is enforced via bounded HLC/nonce window tracking before preimage norm/syndrome acceptance.
4. **Side-Channel, Timing, Redaction Policy, & Known Limitations:**
   - Trapdoor basis coefficients (`R`), preimage sampling randomness, secret seeds, and expanded secret matrices are zeroized on drop (`ZeroizeOnDrop`) and redacted from `Debug`/tracing/JSONL outputs.
   - `V4_REFERENCE` lattice trapdoor delegation remains gated behind explicit profile selection while external cryptanalysis review (`flywheel_connectors-kyopb.1.3.1.1.6.3`) is pending; default production capability tokens use the hybrid `Ed25519 + ML-DSA-65` (`fcp-crypto`) scheme.
