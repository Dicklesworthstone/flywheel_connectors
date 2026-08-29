# 2026-08-29 Reality Check

Author: DarkOak (omp, kimi-code/k3; Agent Mail registration #45)
Date: 2026-08-29
Beads: `flywheel_connectors-yk5sd` (epic), `flywheel_connectors-83yae` (this artifact), `flywheel_connectors-ek45v` (Q3 quarterly)
Baseline: README.md, AGENTS.md, docs/quarterly/2026-Q2-claims-vs-reality.md, docs/FCP3_Transition_Scorecard.md, docs/architecture/master_reachability.md, Beads/bv snapshot from 2026-08-29

## Executive Summary

The project remains honestly described by the README's status table — **no
status label required a change this quarter** — but the verification envelope
around it had silently broken, and this pass was spent mostly on restoring it:

1. **CI was red across the board** (0 green in the observable 60-run window):
   every build job failed compiling `libdbus-sys v0.2.7` via `fwc`'s `keyring`
   dependency. Fixed by mirroring `release.yml`'s existing system-dependency
   step into 15 job sites across `ci.yml`, `perf-regression.yml`, and
   `reality-check-cadence.yml`.
2. **Four README-honesty pinning tests were failing on `main`, undetected**,
   because CI never reached the test stage. All four are fixed (README-side)
   and re-verified green via `rch`.
3. **The TLA formal-models gate was theater since 2026-05-13.** The six
   healthy-spec Makefile targets piped TLC through `tee` without `pipefail`,
   masking every exit code; two spec families additionally used dependent
   comma-separated quantifier bounds that TLC v1.7.4 rejects. Both classes
   fixed; all 12 targets verified locally with the CI-pinned jar
   (6 green / 6 expected_red).
4. **The reality-check cadence lapsed**: this is the *August* artifact; **no
   July 2026 artifact exists** — the first missed month since the cadence
   began — and the Q3 quarterly report was produced today, ~2 months behind
   the cadence target. All three cadence-workflow failures (Jun/Jul/Aug 1)
   shared one root cause (the `tru` sibling-path dependency, fixed 2026-08-14
   by `a73dbafd4`); nothing noticed because the failure happened before the
   bead-filing logic and produced no durable signal.
5. **Code substance is real and verified at unprecedented depth** for this
   pass: six parallel evidence scouts, ~80,566 test attributes counted
   uncapped, zero `todo!()`/`unimplemented!()` in production code, zero holes
   in the Lean tree, all 24 ledger rows re-anchored to code.

The single load-bearing strategic gap is unchanged: **Mesh-Native
Architecture remains `STEADY-STATE TARGET (NOT YET OPERATIONAL)`** — all four
cutover gates are `SKIP` (verified today) — and **Zone Isolation remains
`LIMITED`** (`angoc.2` blocked).

## Current Status

| Area | August verdict | Evidence checked | Notes |
|------|----------------|------------------|-------|
| Host-First Control Plane | Still `PROVEN` | Release build via rch (57 min, clean); `fwc` smoke test | `fwc list` without host refuses `missing-host-endpoint`; offline catalog works (158 visible connectors) |
| Truthful Runtime Resolution | Still `PROVEN` | `truth.rs` (6 states), `catalog.rs` (~60 classified commands), pinning tests | Refusal exit code is 8; README table rewritten to the implemented `CliExitCode` taxonomy (was divergent wholesale) |
| Mesh-Native Architecture | Still `STEADY-STATE TARGET (NOT YET OPERATIONAL)` | Scorecard gates all `SKIP` today | Row label suffix restored (pinning test was failing) |
| Zone Isolation | Still `LIMITED` | Lean lattice hole-free; five-zone E2E | Graduation remains `angoc.2` (blocked) |
| PQ Zone Keys | Still `PROVEN` | X-Wing + ML-DSA live in **`fcp-crypto`** (not `fcp-crypto-pq`) | 12 prose sites corrected; ML-DSA NIST KAT still unvendored (`kyopb.1.1.3.1`) |
| Cancellation machinery | Doc overclaim corrected | `cancellation.rs` has owner-bound tracking, no deadlines | Feature filed: `flywheel_connectors-861lx` |
| Formal models | **Fixed this pass** | 12/12 make targets verified locally | Were theater since 2026-05-13 (tee-masking + illegal quantifier bounds) |
| CI | **Fixed this pass** | libdbus-sys root cause; 15 apt steps added | Was 0/60 green |
| Beads tracker | **Recovered this pass** | DB rebuilt from JSONL (3,924+); corruption bug filed | `flywheel_connectors-338gk` (fsqlite incremental-write corruption, deterministic repro) |
| Cadence | **This artifact + Q3 report are the backfill** | Jun/Jul/Aug failures diagnosed (one shared cause) | July 2026 has no artifact; do not backfill retroactively — this note is the record |

## Beads And Triage Snapshot

`bv --robot-triage` on 2026-08-29: 3,604 tracked issues, 3,556 closed
(98.7%), 48 open (23 open / 23 blocked / 2 in_progress at snapshot; live
counts shifted as other agents worked), 45 actionable, graph acyclic.
**Velocity: zero beads closed in the 30 days before this audit** (last
closures ~2026-07-20); git activity was maintenance-only (12 commits/30 d)
with the v0.2.1 release on 2026-08-16.

Top `bv` recommendations remain external-resource-bound: live pq_signing
StatPack artifacts across three machines (`angoc.8.3`), production
multi-machine failover proof (`hr0rr.2.4`), MCP Agent Mail corruption
(`d5yeb`), OpenClaw/Hermes parity (`4kw5f`, `6n7`), Zone Isolation
graduation (`angoc.2`).

**Bead-coverage cross-check (the skill's Rule 3):** every open-bead theme
maps to a known vision gap, but the audit found **15 gaps with no bead
coverage** — CI redness, the 4 red pinning tests, the cancellation-deadline
contradiction, 5 README prose-drift clusters, the missed Jul/Aug/Q3
artifacts, the cadence workflow failure, the perf-gate failure, the broken
TLA negative fixture, the offline-queue production locus, the exit-code
table, the unknown-flag CLI bug, and the `br` schema/corruption. All are now
filed as the `RC-2026-08-29` set (13 beads + 1 fsqlite bug) under epic
`flywheel_connectors-yk5sd`:

| Bead | What |
|------|------|
| `0misf` | CI libdbus-sys fix (P1) — **done this pass** |
| `gwul7` | inventory pinning 160→176 (P1) — **done this pass** |
| `vmq67` | status pinning ×3 (P1) — **done this pass** |
| `tpi6g` | README drift reconciliation ×12 (P2) — **done this pass** |
| `uq6kc` | cancellation doc-fix (P2) — **done this pass** |
| `861lx` | cancellation deadlines feature (P3) — open |
| `prft8` | exit-code contract (P2) — **done this pass** (doc-side; code taxonomy was test-pinned and self-consistent) |
| `ce78o` | unknown-flag misclassification (P2) — **done this pass** (code fix + 2 tests) |
| `q5rkt` | TLA negative fixture (P2) — **done this pass** (root cause was much larger: tee-masking + illegal bounds) |
| `ek45v` | Q3 quarterly report (P1) — **done this pass** |
| `83yae` | August monthly artifact (P2) — **done this pass** |
| `jqx5k` | cadence workflow hardening (P2) — **done this pass** (diagnosis + failure annotation) |
| `yk5sd` | tracker epic (P1) |

## README Status Reconciliation

- `PROVEN` still means repository evidence, not live production deployment.
- `LIMITED` still correct for Zone Isolation.
- `STEADY-STATE TARGET (NOT YET OPERATIONAL)` still correct for Mesh-Native;
  the row's `(NOT YET OPERATIONAL)` suffix had been dropped by a prose edit
  and is restored.
- The audit-status paragraph now references `br-lvz4t` again and links both
  the Q2 and Q3 reports.

## Remaining Gaps

1. Mesh-native operational cutover (unchanged strategic gap; `hr0rr.2.x`).
2. Zone Isolation graduation (`angoc.2`, blocked).
3. External-resource-bound proofs: live multi-machine PQ StatPacks, real
   tailnet benchmark transport evidence (`u1jce`), external lattice crypto
   review (`kyopb.1.3.1.1.6.3`), Windows sandbox hardware (`r4qcg.x`).
4. `manifest_operation_field_coverage_conformance`'s `#[ignore]`d reject
   test (`4kw5f.9` lineage, epic blocked).
5. `RetryLoop` idempotency bug (`kxd3e`, open) — non-idempotent POSTs
   retried after transmission.
6. `br`/fsqlite 0.5.3 incremental-write corruption (`338gk`) — until fixed,
   fleet discipline is <10 mutations per DB generation, then rebuild from
   JSONL.
7. September cadence run (2026-09-01) must be watched: first run after the
   `tru` fix, the libdbus steps, and the failure annotation.

## Verification Notes

This pass used: full README/AGENTS reads; six parallel read-only code-evidence
scouts (crypto, mesh/store, host/fwc, connectors, test-infra, docs);
empirical `rch` builds (`fcp-core` probe check; full `fwc --release` build
including `fcp-host`, `fcp-registry`, `fcp-conformance`, `fcp-testkit`);
empirical `rch` test runs (inventory pinning, status pinning — both initially
red, now green); a live `fwc` smoke test of the freshly built binary; local
TLC runs with the CI-pinned tla2tools v1.7.4 (sha1-verified); CI log
archaeology via `gh api` job logs; and uncapped test-attribute counting. The
`readme_drift_check.sh` script passes (141 paths, 0 missing). No production
source files were modified by this pass except `crates/fwc/src/main.rs`
(error-dispatch fix + two regression tests) and the four TLA spec files; all
other changes are README, workflow, Makefile, and docs.
