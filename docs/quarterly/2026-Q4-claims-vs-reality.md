# Claims vs Reality Quarterly Report — Q4 2026

> Period: Q4 2026 (October–December)
> Prior report: [`2026-Q3-claims-vs-reality.md`](2026-Q3-claims-vs-reality.md) (snapshot 2026-08-29, follow-ups through 2026-08-30)
> Audit date: 2026-10-13
> Supporting artifact: [`docs/reality/2026-10-13-reality-check.md`](../reality/2026-10-13-reality-check.md) (full evidence trails, commit-level archaeology, and 8-bead bridge plan)
> Tracker: `flywheel_connectors-u9arm` (epic), `flywheel_connectors-u9arm.1`..`flywheel_connectors-u9arm.8` (bridge tasks)

## Summary

This Q4 2026 reality-check pass audited all 168 commits landed on `main` since the Q3 snapshot (`5dc06fb71..341704c69`), re-verified all 24 rows of [`docs/architecture/master_reachability.md`](../architecture/master_reachability.md) against [`README.md`](../../README.md) and [`docs/FCP3_Transition_Scorecard.md`](../FCP3_Transition_Scorecard.md), ran empirical compilation and test suites via `rch`, audited GitHub Actions workflow runs, and repaired the local Beads (`br` / `bv`) database.

**Result at 2026-10-13:** All 24 README status labels in the Master Reachability Ledger remain **honestly and accurately labeled** (`22 PROVEN`, `1 LIMITED`, `1 STEADY-STATE TARGET (NOT YET OPERATIONAL)`). However, the audit uncovered a critical **unverified-batch verification envelope failure** between `2026-10-08` and `2026-10-13`:

1. **109 commits (`3dab90d2d..341704c69`) landed on `main` without triggering a single `CI` workflow run** because they were published via the GitHub Git Database REST API (`POST /git/commits` + `PATCH /git/refs/heads/main`) using a GitHub App/Actions token, which suppresses `on: push` workflow events.
2. **75 of those 109 commits landed from a sandboxed environment without `cargo`, `rustfmt`, or `rch`**, introducing two workspace compile/module-resolution blockers (`GAP-1`: `flywheel_connectors-u9arm.1`), 86 unformatted source files and 5 rustdoc/dead-code/deprecated-wasmtime warnings (`GAP-2`: `flywheel_connectors-u9arm.2`), and two staged-but-unwired `fcp-host` modules (`http_batch.rs` and `mesh-admission-handler-migration.yml`, `GAP-5`: `flywheel_connectors-u9arm.5`).
3. **The ASUPERSYNC Tokio exception ledger was zeroed out prematurely** (`a4e49ecab`), causing `scripts/ci/asupersync_tokio_guard.sh` to fail on the documented `fcp-async-core` compatibility bridge and dev-dependency test surfaces (`GAP-3`: `flywheel_connectors-u9arm.3`).
4. **The reality-check cadence workflow failed on 2026-09-01 and 2026-10-01** because `cargo install --git ... beads_rust` omitted the explicit package name in a multi-binary repo, and `crates/br-tools/src/scheduled_reality_check.rs` returns `Vec::new()` whenever `today.day() != 1`, hiding overdue monthly/quarterly passes on days `2..=31` (`GAP-4`: `flywheel_connectors-u9arm.4`).
5. **Local Beads (`br` / `bv`) broke on 2026-10-07** due to a stale schema v4 DB with a corrupted partial index (`idx_issues_assignee`) and a stale `.beads/metadata.json` pointer (`beads_flywheel_connectors_v4.db`). Repaired during this pass (`br doctor migrate-schema recover` + schema v19 rebuild from `.beads/issues.jsonl` + `.beads/metadata.json` fix), restoring `br doctor` and `bv --robot-triage` to green health.

## Feature Status Delta Table

Statuses use the README vocabulary. `PROVEN` means direct proof in this repository, not live production deployment. All 24 rows of [`docs/architecture/master_reachability.md`](../architecture/master_reachability.md) were re-verified against code on 2026-10-13.

| Feature | Prior (Q3) | Current (Q4) | Delta | Evidence checked | Notes |
|---------|-----------|--------------|-------|------------------|-------|
| Host-First Control Plane | `PROVEN` | `PROVEN` | None | `crates/fcp-host/src/{supervisor,enforcement,health,cancellation}.rs`, `crates/fcp-host/src/bin/fcp-host/` | Per-archetype cancellation deadlines (`861lx`: 1s/10s + SIGTERM->SIGKILL escalation + WASI epoch/fuel abort) landed in `804e103c5`..`2bf25caee`; 55 commits extracted `bin/fcp-host/` submodules; `session.rs:193` needs `#[path = "session/tests.rs"]` (`u9arm.1`) and staged `http_batch.rs` needs wiring (`u9arm.5`) |
| Truthful Runtime Resolution | `PROVEN` | `PROVEN` | None | `crates/fwc/src/{truth,catalog,readiness}.rs` | `LiveTruthResolver` wired into `fwc list`/`status`/`doctor` (`1ab39a25d`..`b14cf3c1d`); `resolve_with_policy` (`truth.rs:1757`) needs `self.effective_sources(&policy)` so `mesh_backed_enabled: false` is honored under default `V2MeshNative` policy (`u9arm.6`) |
| Zone Isolation | `LIMITED` | `LIMITED` | None | `crates/fcp-core/src/{zone_keys,pcs,policy}.rs`, `lean/Fcp/Zone/Lattice.lean` | Lean zone-lattice proofs remain hole-free (0 `sorry`/`admit`/`axiom`); all 4 children of `angoc.2` are closed; held at `LIMITED` until fresh (<24h) SHA-pinned `artifacts/lean/` and `artifacts/e2e/zone_isolation_full_e2e/` bundles are archived (`angoc.2`) |
| Capability Tokens (CWT/COSE) | `PROVEN` | `PROVEN` | None | `crates/fcp-crypto/src/cose.rs`, `crates/fcp-auth-schema/` | Verified; standalone SDK session authority and signed call/byte/usage budgets landed in `36270adeb`..`d9d936da3` |
| Capability Token Typestate | `PROVEN` | `PROVEN` | None | `crates/fcp-core/src/capability.rs`, `crates/fcp-core/tests/typestate_compile_fail.rs` | `LEGACY_VERIFY_ALLOWLIST.len() == 0` ratchet intact |
| Post-Quantum Zone Keys | `PROVEN` | `PROVEN` | None | `crates/fcp-crypto/src/{xwing,ml_dsa,owner_key}.rs`, `crates/fcp-core/src/zone_keys.rs` | X-Wing draft-06 + ML-DSA-65 verified; hardware benchmark gate across `csd`/`Contabo`/`laptop` (`angoc.8.3` -> `angoc.8.2` -> `angoc.8`) and NIST KAT vendoring (`kyopb.1.1.3.1`) remain open |
| Tamper-Evident Audit + HLC | `PROVEN` | `PROVEN` | None | `crates/fcp-audit/src/{hlc,otlp_export}.rs`, `crates/fwc/src/bin/fwc-audit-export.rs` | Request-scoped host explainer (`b51f52b22`) and read-only retained invoke-journal snapshot/follow export (`fwc-audit-export`, `89260b3e3`..`341704c69`) landed; `capability_replay.rs` blocked on `KeyId: Hash` (`u9arm.1`) |
| Revocation | `PROVEN` | `PROVEN` | None | `crates/fcp-core/src/revocation.rs`, `crates/fcp-e2e/tests/revocation_cascade_e2e.rs` | Verified |
| Egress Proxy | `PROVEN` | `PROVEN` | None | `crates/fcp-sandbox/src/egress.rs`, `crates/fcp-e2e/tests/egress_proxy_e2e.rs` | Verified |
| Secretless Connectors | `PROVEN` | `PROVEN` | None | `crates/fcp-host/src/secret_fetch.rs`, GitHub/Slack/Gmail E2E | Verified |
| Multi-Method Provider Auth | `PROVEN` | `PROVEN` | None | `crates/fcp-provider-auth/src/lib.rs` | All seven auth methods verified |
| Credential Pooling | `PROVEN` | `PROVEN` | None | `crates/fcp-host/src/credentials.rs`, `crates/fcp-e2e/tests/credential_pool_e2e.rs` | Verified |
| Multi-Host Singleton Writers (HRW) | `PROVEN` | `PROVEN` | None | `crates/fcp-core/src/lease.rs`, `crates/fcp-mesh/src/{authority,coordinator,planner}.rs` | Verified; lease-transfer fence race hardened during peer invoke routing work |
| Threshold Owner Key | `PROVEN` | `PROVEN` | None | `crates/fcp-bootstrap/src/ceremony.rs` | FROST ceremony + rogue-key rejection verified |
| Threshold Secrets (Shamir) | `PROVEN` | `PROVEN` | None | `crates/fcp-core/src/secret.rs`, `crates/fcp-crypto/src/{shamir,threshold_hpke}.rs` | Shamir verified; FROST Ed25519 -> X25519 share derivation and RFC 9180 labeled HKDF schedule for threshold HPKE landed in `6ef180061` and `b6d5798c3` (`angoc.11.6.1` 3/5 deliverables done; doc link + dead-code cleanup tracked in `u9arm.2`) |
| Supply Chain Attestations | `PROVEN` | `PROVEN` | None | `crates/fcp-registry/src/lib.rs`, `crates/fcp-e2e/tests/supply_chain_attestation_e2e.rs` | Verified |
| Offline Access | `PROVEN` | `PROVEN` | None | `crates/fcp-store/src/{offline,repair}.rs`, `crates/fcp-e2e/tests/offline_degradation_e2e.rs` | Verified |
| Mesh-Stored Policy Objects | `PROVEN` | `PROVEN` | None | `crates/fcp-core/src/policy.rs`, `crates/fcp-e2e/tests/policy_object_e2e.rs` | Verified |
| Symbol-First Protocol | `PROVEN` | `PROVEN` | None | `crates/fcp-raptorq/` | Verified |
| Browser Real-CDP Control Plane | `PROVEN` | `PROVEN` | None | `connectors/browser/src/` | Verified |
| Voice-Call Multi-Provider Parity | `PROVEN` | `PROVEN` | None | `crates/fcp-voice-call/`, `connectors/{twilio,telnyx,plivo}/` | Verified |
| Manifest Operations Conformance | `PROVEN` | `PROVEN` | None | `crates/fcp-conformance/tests/manifest_operation_*.rs` | Verified (temporarily blocked from compiling on `HEAD` until `u9arm.1` adds `Hash` to `fcp_crypto::KeyId` so dev-dependency `fwc` compiles) |
| Computation Migration | `PROVEN` | `PROVEN` | None | `crates/fcp-kernel/src/computation_migration.rs` | Verified; umbrella epic `flywheel_connectors-angoc.4` closed in this pass (all 4 child tasks complete) |
| Mesh-Native Architecture | `STEADY-STATE TARGET (NOT YET OPERATIONAL)` | `STEADY-STATE TARGET (NOT YET OPERATIONAL)` | None | `docs/FCP3_Transition_Scorecard.md`, `crates/fcp-mesh/`, `crates/fcp-host/src/bin/fcp-mesh-directory.rs` | Major foundational delivery in Oct 2026: multi-node peer invoke routing (`42c122047`), signed peer directory + HTTPS sync + `fcp-mesh-directory` CLI (`1749cee79`, `53c74a7af`), durable connector-state replica export/adoption/multi-donor pull (`2f9e468d6`..`fea37f0db`); status label held pending `hr0rr.2.5` completion and all four cutover gates turning green |

## Inventory Claims Checked (re-measured 2026-10-13)

| Claim | README at 2026-10-13 | Live measurement | Verdict |
|-------|----------------------|------------------|---------|
| Platform crates under `crates/` | 42 | 42 | Accurate |
| Connector crates under `connectors/` | 177 (176 production + `_adversarial`) | 177 | Accurate |
| Connector manifests | 177 | 177 | Accurate |
| `ConnectorErrorMapping` coverage | **140** (`README.md:2772`) | **142** | **Underclaim (2-crate drift)** — filed as `flywheel_connectors-u9arm.8` |
| Explicit `OperationInfo` structs | 176 | 176 | Accurate |
| `crates/fwc/src/intent.rs` size | **5,969 lines, 250 tests** (`README.md:1076`) / 6,264 lines, 267 tests (`README.md:2958`) | 6,264 lines, 267 `#[test]` functions | **Internal inconsistency at line 1076** — filed as `flywheel_connectors-u9arm.8` |
| Workspace binaries | Lists `fwc`, `fcp-host`, `fcp-testkit`, `fcp-e2e` (`README.md:1126-1134`) | Also includes `fwc-audit-export` and `fcp-mesh-directory` | **Underclaim (2 new binaries omitted)** — filed as `flywheel_connectors-u9arm.8` |
| `todo!()`/`unimplemented!()` in production code | 0 | 0 | Verified clean |

## Overclaims Found

None on the 24 Master Reachability status labels. Importantly, the Q3 prose overclaim around **per-archetype cancellation deadlines** (`flywheel_connectors-861lx`) was **implemented in full during Q3→Q4** (`804e103c5`..`2bf25caee`): `fcp-host` now enforces 1s request-response/webhook/polling/database/file-blob/CLI/browser and 10s streaming/bidirectional/queue-pubsub cancellation grace periods with a 200ms reaper, SIGTERM→SIGKILL subprocess escalation, per-execution WASI fuel/epoch abort, and native RPC cancellation settlement.

One guardrail-config overclaim was introduced on `2026-10-08`:
- **`.config/asupersync/tokio_exception_ledger.json` (`a4e49ecab`)** was set to `dependency_exceptions: []` and `max_count: 0` across all source invariants even though `README.md` (lines 1105, 3634–3652) accurately documents that `fcp-async-core` retains the quarantined Tokio timer compatibility bridge and dev/test crates retain 139 `tokio::` references. Reconciling the JSON ledger with the documented quarantine surface is tracked in `flywheel_connectors-u9arm.3`.

## Underclaims Found

1. **`ConnectorErrorMapping` inventory (`README.md:2772`):** Claims `140` of 177 connector crates implement `ConnectorErrorMapping`; live measurement is `142` (`flywheel_connectors-u9arm.8`).
2. **New operational binaries (`fwc-audit-export` and `fcp-mesh-directory`):** Landed in October 2026 (`53c74a7af`, `341704c69`) with full CLI/test surfaces, not yet listed in the `README.md` Binary Architecture table (`flywheel_connectors-u9arm.8`).
3. **`crates/fwc/src/intent.rs` line/test count at `README.md:1076`:** Still says `5,969 lines, 250 tests` while `README.md:2958` and live code have `6,264 lines, 267 tests` (`flywheel_connectors-u9arm.8`).

## Graduations

No top-level Master Reachability row changed status label in this pass (`22 PROVEN`, `1 LIMITED`, `1 STEADY-STATE TARGET (NOT YET OPERATIONAL)`). However, three major subsystem milestones completed their implementation tracks since Q3:
- **Per-archetype cancellation deadlines (`flywheel_connectors-861lx`):** Closed and verified in `fcp-host` + `fcp-sandbox`.
- **Asupersync `0.5.0` runtime upgrade (`flywheel_connectors-m1g2w`):** All 16 runtime declarations upgraded; `fcp-async-core` passes 472/472 unit tests and Clippy (`-D warnings`).
- **Phase J (`angoc.4`), Phase K (`angoc.5`), and Phase L (`angoc.6`) umbrella epics:** All child tasks completed; parent epics closed in `br` during this pass.

## Still-Honest Limits

- **`Zone Isolation`** stays `LIMITED` (`flywheel_connectors-angoc.2`) pending fresh (<24h) SHA-pinned `artifacts/lean/` and `artifacts/e2e/zone_isolation_full_e2e/` bundles.
- **`Mesh-Native Architecture`** stays `STEADY-STATE TARGET (NOT YET OPERATIONAL)` until `flywheel_connectors-hr0rr.2.5` (`A.5`), `flywheel_connectors-u9arm.5` (staged mesh-admission handler wiring), and `flywheel_connectors-u9arm.6` (`LiveTruthResolver::resolve_with_policy` source filtering) complete and all four transition gates in `docs/FCP3_Transition_Scorecard.md` turn green.
- **Windows sandbox** remains Tier 2 (`flywheel_connectors-r4qcg.2`, `.3`, `.4` open).
- **Post-Quantum hybrid signing cutover (`flywheel_connectors-angoc.8`)** remains gated on multi-host hardware benchmarks (`angoc.8.3` across `csd`/`Contabo`/`laptop`) and NIST FIPS 204 KAT vector vendoring (`kyopb.1.1.3.1`).

## Debiasing Notes

- **GitHub REST API commit publishing bypassed `on: push` CI for 109 consecutive commits.** When commits and ref updates are created via the GitHub Git Database API using an installation/Actions token, GitHub suppresses `on: push` workflow events to prevent infinite workflow loops. Combined with a sandboxed agent environment lacking `cargo`, `rustfmt`, and `rch`, 75 commits landed with unverified code—silently breaking `fwc` compilation (`3931e71b3`), `rustfmt` module resolution (`024b113b8`, `6d07b5d83`), and leaving two extracted `fcp-host` handlers staged in `.github/workflows/*.yml` rather than wired into `fcp-host.rs`.
- **Single-day equality (`today.day() == 1`) in `scheduled_reality_check.rs` creates a 29-day blindspot.** If the 1st-of-month cron fails before executing `scheduled-reality-check` (as happened on 2026-09-01 and 2026-10-01 due to `cargo install --git ... beads_rust` ambiguity), running `scheduled-reality-check` on days `2..=31` returns `missing_checks: []` (`"reality-check cadence is current"`). Fixing `due_checks_for_date` (`flywheel_connectors-u9arm.4`) to check whether the current month's and current quarter's artifacts exist on **any** day of the period makes the cadence check self-healing.

## Actions Taken (this pass)

- **Beads DB & Metadata Repair:** Recovered `.beads/beads.db` from schema v4 index corruption (`idx_issues_assignee`) to `br 0.7.4` schema v19 (3,945 issues in sync with `.beads/issues.jsonl`) and fixed `.beads/metadata.json` (`"database": "beads.db"`). Verified `br doctor` (`sqlite.integrity_check`, `counts.db_vs_jsonl`, `db.write_probe`) and `bv --robot-triage` pass cleanly.
- **Backlog Hygiene:** Closed 5 completed epics/beads (`flywheel_connectors-yk5sd`, `flywheel_connectors-angoc.4`, `flywheel_connectors-angoc.5`, `flywheel_connectors-angoc.6`, `flywheel_connectors-6thf5`).
- **Bridge Plan Filing:** Filed tracker epic `flywheel_connectors-u9arm` (`[RC-2026-10-13]`) and 8 self-contained gap beads (`flywheel_connectors-u9arm.1` through `flywheel_connectors-u9arm.8`) covering every `NO_BEAD` compile, formatting, guardrail, cadence, host-staging, truth-resolver, security-audit, and documentation gap discovered.
- **Cadence Artifacts Published:** Wrote [`docs/reality/2026-10-13-reality-check.md`](../reality/2026-10-13-reality-check.md) and this Q4 report (`docs/quarterly/2026-Q4-claims-vs-reality.md`).

## Ledger Supersession Delta

[`docs/architecture/master_reachability.md`](../architecture/master_reachability.md) remains the authoritative 24-row ledger and is 100% consistent with this Q4 2026 report.

## Next Quarter Focus

1. **Execute Stage 0 (`flywheel_connectors-u9arm.1`) and Stage 1 (`u9arm.2`, `u9arm.3`, `u9arm.4`) immediately** to restore workspace compilation, formatting, rustdoc/clippy cleanliness, `asupersync_tokio_guard.sh`, and self-healing `scheduled-reality-check` cadence enforcement.
2. **Finish `fcp-host.rs` de-staging (`flywheel_connectors-u9arm.5`) and `LiveTruthResolver` policy filtering (`flywheel_connectors-u9arm.6`)** so `flywheel_connectors-hr0rr.2.5` (`A.5`) can close cleanly.
3. **Never land commits without `rch` compilation/test verification or an active CI push trigger.**
