# Phase Q.B — Quotient Filter for Revocation-Aware Capability Cache

- **Bead**: `flywheel_connectors-angoc.11.2` (Parent: `flywheel_connectors-angoc.11`)
- **EV Score**: `79 / 100` (Rank 1 — **Top-5 Landed & Closed**)
- **Status**: Landed and verified in `fcp-core`.

## Implementation & Proof Artifacts

- **Implementation**: [`crates/fcp-core/src/quotient_filter.rs`](../../../crates/fcp-core/src/quotient_filter.rs) and `RevocationRegistry` integration in [`crates/fcp-core/src/revocation.rs`](../../../crates/fcp-core/src/revocation.rs).
- **Property & Unit Proof**: [`crates/fcp-core/tests/quotient_revocation_cache_property.rs`](../../../crates/fcp-core/tests/quotient_revocation_cache_property.rs) verifies zero false negatives across insert/lookup/delete sequences and bounded false-positive rate.
- **Conformance Gate**: [`crates/fcp-conformance/tests/alien_graveyard_q3_completeness.rs`](../../../crates/fcp-conformance/tests/alien_graveyard_q3_completeness.rs).

## Fallback & Rollback Contract

- **Exact Store Fallback**: `RevocationRegistry` maintains the authoritative exact `HashSet<ObjectId>` backing store alongside the `QuotientFilter`. Any positive quotient-filter hit or filter capacity/delete fault falls back to the exact `HashSet` lookup, guaranteeing zero false-negative revocations and zero false-positive capability denials.
