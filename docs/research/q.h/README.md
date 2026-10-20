# Phase Q.H — Bayesian-Optimization `KSelector` for RaptorQ

- **Bead**: `flywheel_connectors-angoc.11.5` (Parent: `flywheel_connectors-angoc.11`)
- **EV Score**: `72 / 100` (Rank 4 — **Top-5 Landed & Closed**)
- **Status**: Landed and verified in `fcp-raptorq`.

## Implementation & Proof Artifacts

- **Implementation**: [`crates/fcp-raptorq/src/k_selector.rs`](../../../crates/fcp-raptorq/src/k_selector.rs) implements Thompson-sampling / Bayesian posterior selection over source-block size `K` arms per workload and link loss profile.
- **Unit & Regret Bound Tests**: Inline unit and property tests in `crates/fcp-raptorq/src/k_selector.rs` verify sub-linear cumulative regret and convergence to the optimal `K` arm.
- **Conformance Gate**: [`crates/fcp-conformance/tests/alien_graveyard_q3_completeness.rs`](../../../crates/fcp-conformance/tests/alien_graveyard_q3_completeness.rs).

## Fallback & Rollback Contract

- **Cold-Posterior Fallback**: When observation count is below the warm-up threshold or when deterministic static chunking is requested, `KSelector` falls back to the static manifest/preset `K` parameter.
