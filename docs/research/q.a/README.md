# Phase Q.A — STARK Aggregation over `CapabilityInvocationBatch`

- **Bead**: `flywheel_connectors-angoc.11.8` (Parent: `flywheel_connectors-angoc.11`)
- **EV Score**: `54 / 100` (Rank 9 — `2026-Q4 Deferred` per [`docs/architecture/alien_graveyard_q3_2026.md`](../../architecture/alien_graveyard_q3_2026.md))
- **Status**: Deferred to 2026-Q4; fallback active in production.

## Scope & Deferral Rationale

STARK aggregation over `CapabilityInvocationBatch` aims to compress $10^4$ audit-chain capability invocation verifications into a single transparent STARK proof ($\le 50\text{ ms}$ p99 verification). Per the Phase Q.K EV rubric ([`docs/architecture/alien_graveyard_q3_2026.md`](../../architecture/alien_graveyard_q3_2026.md)), `Q.A` scored `54/100` due to prover library selection (`plonky2` vs `winterfell`) and memory footprint tradeoffs, placing it outside the Top-5 Q3 commitment.

## Active Fallback & Rollback Contract

- **Production Fallback**: Per-entry Ed25519 / hybrid ML-DSA-65 signature verification (`crates/fcp-crypto/src/hybrid_sign.rs`) and hash-linked `AuditEntry` chains (`crates/fcp-audit`) verify every capability invocation deterministically without STARK prover overhead.
- **Conformance Gate**: [`crates/fcp-conformance/tests/alien_graveyard_q3_completeness.rs`](../../../crates/fcp-conformance/tests/alien_graveyard_q3_completeness.rs) pins `Q.A` in the deferred schedule.
