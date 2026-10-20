# Phase Q.E — Datalog / Soufflé Policy Backend

- **Bead**: `flywheel_connectors-angoc.11.7` (Parent: `flywheel_connectors-angoc.11`)
- **EV Score**: `58 / 100` (Rank 8 — `2026-Q4 Deferred` per [`docs/architecture/alien_graveyard_q3_2026.md`](../../architecture/alien_graveyard_q3_2026.md))
- **Status**: Deferred to 2026-Q4; procedural policy engine active in production.

## Scope & Deferral Rationale

`Q.E` proposes a Soufflé/Datalog backend for zone and capability policy evaluation with provenance witnesses. Per [`docs/architecture/alien_graveyard_q3_2026.md`](../../architecture/alien_graveyard_q3_2026.md), `Q.E` scored `58/100` and was deferred to 2026-Q4 to avoid external sidecar coupling prior to completing the core mesh and post-quantum cutovers.

## Active Fallback & Rollback Contract

- **Production Fallback**: The deterministic procedural policy and zone-isolation engine in `fcp-core` and `fcp-host` (`ZonePolicyEngine` + `CapabilityToken<BoundVerified>` typestate enforcement) is the authoritative evaluator, with structured audit receipts in `fcp-audit`.
- **Conformance Gate**: [`crates/fcp-conformance/tests/alien_graveyard_q3_completeness.rs`](../../../crates/fcp-conformance/tests/alien_graveyard_q3_completeness.rs).
