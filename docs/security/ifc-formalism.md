# IFC Formalism

Status: `PROVEN` evidence surface for Phase C. This document records the
formal and runtime evidence pointers for the Zone Isolation gate (`flywheel_connectors-angoc.2`).

## Evidence Pointers

| Gate | Artifact | Status |
| --- | --- | --- |
| 5-zone cross-zone leak E2E | `crates/fcp-e2e/tests/zone_isolation_full_e2e.rs` (`artifacts/e2e/zone_isolation_full_e2e/2320d4e175d10309b3b39b8e97a36da057b6e021.jsonl`) | `PROVEN` — Implements `z:public`, `z:community`, `z:work`, `z:project:alpha`, and `z:private` policy fixtures; rejects unapproved cross-zone invokes; emits structured zone-check JSONL and 100 rejection audit events. |
| Lean zone-flow proof | `lean/Fcp/Zone/Lattice.lean` (`artifacts/lean/2320d4e175d10309b3b39b8e97a36da057b6e021.txt`) | `PROVEN` — Verified green via `make lean-verify` (`Lean 4.29.1`, 5/5 formal proof files green, 0 `sorry`s). |

The executable harness logs every policy decision with redaction-safe
`request_id`, `src_zone`, `dst_zone`, `capability`, `decision`, `reason_code`,
and monotone `hlc` fields. Rejections use the stable `ZoneReject` audit event
label so downstream proof and doctor surfaces can consume the same evidence.
