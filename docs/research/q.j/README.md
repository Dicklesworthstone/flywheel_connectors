# Phase Q.J — TLA+ Formal Specifications (Capability Lifecycle, FROST DKG, Agent-Mail Ordering)

- **Beads**: `flywheel_connectors-angoc.13.2`, `flywheel_connectors-angoc.13.3`, `flywheel_connectors-angoc.13.5` (Parent: `flywheel_connectors-angoc.13` / `flywheel_connectors-angoc.11`)
- **EV Score**: `78 / 100` (Rank 2 — **Top-5 Landed & Closed**)
- **Status**: Landed and verified in `specs/tla/` and `fcp-conformance`.

## Implementation & Proof Artifacts

- **TLA+ Specifications**:
  - [`specs/tla/cutover.tla`](../../../specs/tla/cutover.tla) & [`specs/tla/cutover.cfg`](../../../specs/tla/cutover.cfg)
  - [`specs/tla/capability_lifecycle.tla`](../../../specs/tla/capability_lifecycle.tla) & [`specs/tla/capability_lifecycle.cfg`](../../../specs/tla/capability_lifecycle.cfg)
  - [`specs/tla/frost_dkg.tla`](../../../specs/tla/frost_dkg.tla) & [`specs/tla/frost_dkg.cfg`](../../../specs/tla/frost_dkg.cfg)
  - [`specs/tla/agent_mail.tla`](../../../specs/tla/agent_mail.tla) & [`specs/tla/agent_mail.cfg`](../../../specs/tla/agent_mail.cfg)
- **Conformance & Trace Alignment Gate**: [`crates/fcp-conformance/tests/tla_spec_completeness.rs`](../../../crates/fcp-conformance/tests/tla_spec_completeness.rs).

## Fallback & Rollback Contract

- **Coverage Matrix Downgrade**: If a future spec revision fails bounded model checking, `docs/formal/readme-proof-obligations.json` and `readme_lean_proven_gate` prevent any unverified `PROVEN` claim in `README.md` while keeping CI merge gates deterministic.
