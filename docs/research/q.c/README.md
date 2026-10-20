# Phase Q.C — CALM / I-CONFLUENCE Operation Classification & Mesh Dispatch

- **Beads**: `flywheel_connectors-angoc.11.1`, `flywheel_connectors-angoc.11.1.1` (Parent: `flywheel_connectors-angoc.11`)
- **EV Score**: `69 / 100` (Rank 6 — **Landed & Closed**)
- **Status**: Landed and verified across `fcp-core`, `fcp-protocol`, `fcp-manifest`, `fcp-mesh`, `fcp-conformance`, and `fcp-e2e`.

## Implementation & Proof Artifacts

- **Protocol & Manifest Contract**: `CoordinationClass` (`IConfluent`, `RequiresQuorum`, `RequiresFencing`) in [`crates/fcp-core/src/protocol.rs`](../../../crates/fcp-core/src/protocol.rs) and [`crates/fcp-manifest/src/lib.rs`](../../../crates/fcp-manifest/src/lib.rs).
- **Mesh Transport Dispatch**: `MeshInvokeTransport` in [`crates/fcp-mesh/src/dispatch.rs`](../../../crates/fcp-mesh/src/dispatch.rs) routes `IConfluent` operations via single-replica direct dispatch (`quorum_messages = 0`), `RequiresQuorum` via $t$-of-$n$ quorum rounds (`fcp.mesh.quorum.round`), and `RequiresFencing` via HRW lease-holder epoch fencing.
- **Conformance Test**: [`crates/fcp-conformance/tests/i_confluence_operation_classification.rs`](../../../crates/fcp-conformance/tests/i_confluence_operation_classification.rs) (`5 passed; 0 failed`).
- **E2E Throughput Proof**: [`crates/fcp-e2e/tests/i_confluent_dispatch_throughput_e2e.rs`](../../../crates/fcp-e2e/tests/i_confluent_dispatch_throughput_e2e.rs) (`3 passed; 0 failed`, verifying $>3\times$ throughput speedup and zero quorum messages for `IConfluent` workloads).

## Fallback & Rollback Contract

- **Emergency Override**: Setting `FCP_FORCE_QUORUM_ALL=1` forces `MeshInvokeTransport` to upgrade all `IConfluent` operations to `RequiresQuorum` without redeploying connectors or manifests.
- **Conservative Default**: Any operation that does not satisfy `SafetyTier::Safe` + (`IdempotencyClass::Strict` or `IdempotencyClass::None` with read-only side effects) defaults fail-closed to `RequiresQuorum` or `RequiresFencing`.
