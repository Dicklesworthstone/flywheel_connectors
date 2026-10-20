# Phase Q.I — Conformal-Prediction Confidence on `OperationReceipt`

- **Bead**: `flywheel_connectors-angoc.11.4` (Parent: `flywheel_connectors-angoc.11`)
- **EV Score**: `74 / 100` (Rank 3 — **Top-5 Landed & Closed**)
- **Status**: Landed and verified in `fcp-core`.

## Implementation & Proof Artifacts

- **Implementation**: [`crates/fcp-core/src/conformal.rs`](../../../crates/fcp-core/src/conformal.rs) implements split conformal prediction (`ConformalCalibrator`, `ConformalScore`) providing finite-sample marginal coverage guarantees $1 - \alpha - O(1/\sqrt{n})$ on `OperationReceipt` non-conformity scores.
- **Unit & Coverage Tests**: Inline tests in [`crates/fcp-core/src/conformal.rs`](../../../crates/fcp-core/src/conformal.rs) verify quantile calibration, finite-sample coverage bounds, and serialization on `OperationReceipt`.
- **Conformance Gate**: [`crates/fcp-conformance/tests/alien_graveyard_q3_completeness.rs`](../../../crates/fcp-conformance/tests/alien_graveyard_q3_completeness.rs).

## Fallback & Rollback Contract

- **Cold-Start Omission**: When fewer than the minimum calibration observations ($n < 100$) have been recorded for an operation class, `confidence: Option<ConformalScore>` is `None` (`skip_serializing_if = "Option::is_none"`), preserving backwards-compatible receipt consumers.
