# Phase Q.D — Flink-CEP Audit-Chain Anomaly Detection & Reservoir Compactor

- **Bead**: `flywheel_connectors-angoc.11.9` (Parent: `flywheel_connectors-angoc.11`)
- **EV Score**: `49 / 100` (Rank 10 — **Landed & Closed**)
- **Status**: Landed and verified across `fcp-audit` and `fcp-e2e`.

## Implementation & Proof Artifacts

- **CEP NFA Engine**: [`crates/fcp-audit/src/cep.rs`](../../../crates/fcp-audit/src/cep.rs) compiles `EventPattern` specifications into bounded NFAs over HLC-ordered `AuditEvent` streams and emits `AnomalyAlert` (`CEP_ANOMALY_ALERT_SCHEMA_VERSION`).
- **Reservoir Compactor**: [`crates/fcp-audit/src/compaction/reservoir.rs`](../../../crates/fcp-audit/src/compaction/reservoir.rs) implements Algorithm R (`ReservoirCompactor`) with cryptographic BLAKE3 pre-compaction digest preservation and deterministic seeding.
- **Property Tests**: [`crates/fcp-audit/tests/cep_pattern_correctness_property.rs`](../../../crates/fcp-audit/tests/cep_pattern_correctness_property.rs) (`8 passed; 0 failed`) and [`crates/fcp-audit/tests/reservoir_unbiased_property.rs`](../../../crates/fcp-audit/tests/reservoir_unbiased_property.rs) (`7 passed; 0 failed`).
- **Cross-Zone E2E Proof**: [`crates/fcp-e2e/tests/cep_cross_zone_anomaly_detection_e2e.rs`](../../../crates/fcp-e2e/tests/cep_cross_zone_anomaly_detection_e2e.rs) (`2 passed; 0 failed`, verifying $<1\text{ s}$ cross-zone anomaly alerting and unbiased reservoir replay).

## Fallback & Rollback Contract

- **Bounded NFA State**: `CompiledNfa` prunes expired partial matches outside `within_ms` on every step so malformed or high-rate event bursts cannot cause unbounded memory growth.
