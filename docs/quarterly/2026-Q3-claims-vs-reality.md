# Claims vs Reality Quarterly Report — Q3 2026

> Period: Q3 2026 (July–September)
> Auditor: DarkOak (omp, kimi-code/k3), Agent Mail registration #45
> Prior report: [`2026-Q2-claims-vs-reality.md`](2026-Q2-claims-vs-reality.md) (snapshot 2026-05-03, follow-ups through 2026-05-16)
> Audit date: 2026-08-29
> Supporting artifact: [`docs/reality/2026-08-29-reality-check.md`](../reality/2026-08-29-reality-check.md) (full evidence trails)
> Tracker: `flywheel_connectors-yk5sd` (epic), `flywheel_connectors-ek45v` (this report)

## Summary

DarkOak ran the Q3 pass as a full reality check: complete README (3,872 lines) and AGENTS.md read, six parallel code-evidence scouts across the crypto/mesh/host/connector/test-infra/docs claim clusters, empirical builds and test runs via `rch`, a live CLI smoke test of a freshly built `fwc`, and CI archaeology across 60+ workflow runs.

**Result at 2026-08-29:** zero README status *labels* required changes — all 24 master-reachability rows remain correctly labeled. The quarter's real findings are about the **verification envelope**, not the feature labels:

1. **CI was red across the board** — zero green runs in the observable 60-run window (49 cancelled, 10 failure, 1 action_required). Every build job failed compiling `libdbus-sys v0.2.7` (the `keyring` → `dbus-secret-service` chain in `fwc`). Fixed in this pass (system-dependency steps added to all affected jobs, mirroring the pattern `release.yml` already had).
2. **Four README-honesty pinning tests were failing on `main`, undetected**, because CI could not reach the test stage. All four are fixed in this pass.
3. **The formal-models TLA gate had been theater since 2026-05-13.** The six "healthy-spec" Makefile targets piped TLC through `tee` (no `pipefail` under `/bin/sh`), masking every exit code, while two spec families used dependent comma-separated quantifier bounds that TLC v1.7.4 rejects at semantic analysis. Fixed in this pass; all 12 targets verified locally (6 green / 6 expected_red).
4. **The reality-check cadence itself lapsed**: no July or August monthly artifact, and this Q3 report is ~2 months late relative to the cadence target. The cadence workflow failed 2026-06-01, 2026-07-01, and 2026-08-01 — all three from the same `tru` sibling-path manifest-load failure (fixed 2026-08-14 by `a73dbafd4`).
5. **One safety-relevant prose claim was contradicted by code**: per-archetype cancellation deadlines with supervisor force-terminate were documented but do not exist. Doc-fixed in this pass; the feature is filed as `flywheel_connectors-861lx`.

## Feature Status Delta Table

Statuses use the README vocabulary. `PROVEN` means direct proof in this repository, not live production deployment. All 24 rows re-verified against code on 2026-08-29 (evidence anchors in the reality-check artifact).

| Feature | Prior (Q2) | Current (Q3) | Delta | Evidence checked | Notes |
|---------|-----------|--------------|-------|------------------|-------|
| Host-First Control Plane | `PROVEN` | `PROVEN` | None | `crates/fcp-host/src/{supervisor,enforcement,health}.rs`, invoke-loop conformance, concurrent E2E | `fwc` + `fcp-host` release build verified via rch; CLI smoke test exercised the live refusal path |
| Truthful Runtime Resolution | `PROVEN` | `PROVEN` | None | `crates/fwc/src/{truth,catalog,readiness}.rs`, pinning tests | Six knowledge states and command classification verified; `fwc list` without host refuses with `missing-host-endpoint` (observed) |
| Zone Isolation | `LIMITED` | `LIMITED` | None | `crates/fcp-core/src/{zone_keys,pcs,policy}.rs`, Lean lattice, five-zone E2E | Correctly held LIMITED pending `angoc.2` (blocked); Lean zone-lattice proofs confirmed **hole-free** (zero `sorry`/`admit`/`axiom` in `lean/`) |
| Capability Tokens (CWT/COSE) | `PROVEN` | `PROVEN` | None | `crates/fcp-crypto/src/cose.rs`, `fcp-auth-schema` claims, predicate matrix | Note: the README named a verifier function `reject_unexpected_schema_version` that does not exist; the real API is `AuthClaims::check_schema_version` (prose corrected) |
| Capability Token Typestate | `PROVEN` | `PROVEN` | None | trybuild compile-fail suite, `LEGACY_VERIFY_ALLOWLIST.len() == 0` | Ratchet intact |
| Post-Quantum Zone Keys | `PROVEN` | `PROVEN` | None | `crates/fcp-crypto/src/{xwing,ml_dsa,owner_key}.rs`, `zone_keys.rs` V4, mixed-migration E2E | **Crate attribution was inverted in README** (claimed `fcp-crypto-pq`; actually `fcp-crypto`). Substance verified: X-Wing draft-06 + 3 IETF KAT vectors, ML-DSA-65. ML-DSA NIST KAT vectors still not vendored (`kyopb.1.1.3.1`) — prose now says so |
| Tamper-Evident Audit + HLC | `PROVEN` | `PROVEN` | None | `crates/fcp-audit/src/{hlc,otlp_export}.rs`, OTLP schema + golden fixture | Verified |
| Revocation | `PROVEN` | `PROVEN` | None | `crates/fcp-core/src/revocation.rs`, cascade E2E, timing conformance | Verified |
| Egress Proxy | `PROVEN` | `PROVEN` | None | `crates/fcp-sandbox/src/egress.rs`, E2E | Verified |
| Secretless Connectors | `PROVEN` | `PROVEN` | None | `secret_fetch.rs`, three connector-family E2Es | Row prose had lost the pinned precision phrases ("GitHub/Slack/Gmail", "does not claim every connector has migrated") — restored in this pass |
| Multi-Method Provider Auth | `PROVEN` | `PROVEN` | None | `crates/fcp-provider-auth/src/lib.rs` (6,130 lines, `forbid(unsafe_code)`) | All seven methods verified in code |
| Credential Pooling | `PROVEN` | `PROVEN` | None | `crates/fcp-host/src/credentials.rs` (3,083 lines), pool E2E | All six claimed features present |
| Multi-Host Singleton Writers (HRW) | `PROVEN` | `PROVEN` | None | `crates/fcp-core/src/lease.rs`, mesh authority/coordinator/planner, fencing in `fcp-host` | Verified; fencing enforcement lives in `fcp-host/src/bin/fcp-host.rs` atop the cited machinery |
| Threshold Owner Key | `PROVEN` | `PROVEN` | None | `crates/fcp-bootstrap/src/ceremony.rs` (FROST, rogue-key rejection test) | Verified |
| Threshold Secrets (Shamir) | `PROVEN` | `PROVEN` | None | `crates/fcp-core/src/secret.rs`, `fcp-crypto/src/shamir.rs` | Verified |
| Supply Chain Attestations | `PROVEN` | `PROVEN` | None | `crates/fcp-registry/src/lib.rs`, attestation E2E | Verified |
| Offline Access | `PROVEN` | `PROVEN` | None | `crates/fcp-store/src/{offline,repair}.rs`, offline E2Es | Evidence-cell scope corrected: queued writes / drain-on-restore are proven through the E2E harness pattern, not production `fcp-store` types |
| Mesh-Stored Policy Objects | `PROVEN` | `PROVEN` | None | `crates/fcp-core/src/policy.rs`, policy E2E | Verified |
| Symbol-First Protocol | `PROVEN` | `PROVEN` | None | `crates/fcp-raptorq/` (RFC 6330, chunked objects, dense GF(256) fallback, admission 16) | Verified |
| Browser Real-CDP Control Plane | `PROVEN` | `PROVEN` | None | `connectors/browser/src/` (347 KB client: DirectCdpTargetSessionManager, launcher supervisor, cookie scope) | Verified (monolithic-module layout) |
| Voice-Call Multi-Provider Parity | `PROVEN` | `PROVEN` | None | `crates/fcp-voice-call/`, twilio/telnyx/plivo wiring, 385-line verification script | Verified |
| Manifest Operations Conformance | `PROVEN` | `PROVEN` | None | `manifest_operations_*.rs` scanners, drift ratchet, test-dir ratchet | Caveat recorded: the strict field-coverage *reject* test remains `#[ignore]`d (`4kw5f.9` debt, epic blocked) |
| Computation Migration | `PROVEN` | `PROVEN` | None | `crates/fcp-kernel/src/computation_migration.rs`, reference + unplanned E2E | Verified |
| Mesh-Native Architecture | `STEADY-STATE TARGET (NOT YET OPERATIONAL)` | `STEADY-STATE TARGET (NOT YET OPERATIONAL)` | None | `docs/FCP3_Transition_Scorecard.md` — all four cutover gates confirmed `SKIP` on 2026-08-29 | Status label suffix `(NOT YET OPERATIONAL)` had been dropped from the README row, breaking the pinning test; restored |

## Inventory Claims Checked (re-measured 2026-08-29)

Q2's report instructed future passes to re-measure rather than carry forward. Measured with the repo's own pinning algorithm (`readme_inventory_pinning.rs`) and independent shell replication:

| Claim | README before Q3 pass | Live measurement | Verdict |
|-------|----------------------|------------------|---------|
| Platform crates under `crates/` | 42 | 42 | Accurate |
| Connector crates under `connectors/` | 177 (176 production + `_adversarial`) | 177 | Accurate |
| Connector manifests | 177 | 177 | Accurate |
| `ConnectorErrorMapping` coverage | 156 | 156 | Accurate |
| Full `client.rs`/`connector.rs`/`types.rs` layout | 158 | 158 | Accurate |
| Explicit `OperationInfo` structs | **160** | **176** | **Underclaim — fixed** (every connector except `bluebubbles`) |
| Fuzz targets | "100+" | 182 | Accurate (conservative) |
| Test count | "60,000+" | ~80,566 `#[test]`-family attributes + 79 `proptest!` blocks + doc tests | **Verified** (Q2-era scout estimate of 30–40k was a tool-capping artifact; uncapped count confirms the claim) |
| `todo!()`/`unimplemented!()` in production code | (implicit zero) | 0 in all `crates/*/src` and `connectors/*/src` | Verified clean |

## Overclaims Found

None on status labels. Two prose-level overclaims were found and corrected:

1. **Cancellation deadlines (README Cancellation Propagation).** Claimed `cancellation.rs` gives each token a deadline with supervisor force-terminate, defaults 1 s (request-response) / 10 s (streaming). The 2,841-line file contains no deadline machinery at all. Corrected to describe the real owner-bound tracking + supervisor graceful-shutdown backstop; feature filed as `flywheel_connectors-861lx`.
2. **PQ crate attribution (multiple sections).** README claimed X-Wing KEM and ML-DSA-65 (plus their KATs, length-invariant `Deserialize`, proptest, `ZeroizeOnDrop`) live in `fcp-crypto-pq` and that `fcp-crypto` "remains a pure classical-crypto crate." Reality: the PQ primitives live in `fcp-crypto` (`Cargo.toml:46-49`); `fcp-crypto-pq` carries only lattice-trapdoor delegation and self-labels "API scaffolding (br-kyopb.1.3.1)". Twelve prose sites corrected. Related: "KAT vectors from FIPS 204 are pinned" overstated — only an internal regression KAT is pinned; NIST vector vendoring is `kyopb.1.1.3.1`.

## Underclaims Found

1. **OperationInfo inventory: 176, not 160.** The pinning test `readme_inventory_counts_match_workspace_reality` was failing on `main` as a result (empirically confirmed via `rch`). README corrected; test now passes.
2. **`fwc` intent compiler size.** README said ~5.9k lines / 258 inline tests; measured 6,264 lines / 267 `#[test]` functions. Corrected.
3. **Test-count claim.** "60,000+ tests" was challenged by a tool-capped scout estimate (~30–40k). An uncapped count found ~80,566 test attributes. Claim verified as written.

## Still-Honest Limits

- `Zone Isolation` stays `LIMITED` (`angoc.2`, blocked).
- `Mesh-Native Architecture` stays `STEADY-STATE TARGET (NOT YET OPERATIONAL)`; all four cutover gates are `SKIP` (verified 2026-08-29), and `hr0rr.2.4`/`hr0rr.2.5` remain open/blocked.
- `fcp-crypto-pq` lattice delegation is a deterministic SHAKE-256 fixture route — real modular arithmetic, not MP12/CHKP Gaussian sampling; the SIS hardness reduction is an explicitly unmechanized Lean assumption boundary (`kyopb.1.3.1.1`, ~320 h scope, blocked on external crypto review).
- Windows sandbox remains Tier 2 (`r4qcg.2-4` open).
- The `tlon` and `huggingface` manifests declare `status = "proven"` while `huggingface` still reports a code-level `surface_status` of incubating — README now says exactly that; reconciling the introspection surface is left to the connector-graduation epic (`angoc.16`).

## Debiasing Notes

- **The dominant Q3 failure mode was not label drift but ratchet blindness.** Four pinning tests failed on `main` for days-to-weeks and nobody saw it, because CI had been failing at the compile stage (`libdbus-sys`) since at least mid-August and the local full-suite habit had stalled (zero beads closed in the 30 days before this audit). The ratchets worked; the observation channel was dark.
- **Test theater is real even in this repo.** The TLA healthy-spec targets printed unconditional `green` for three months because `java | tee` masks the exit code without `pipefail`. The broken-spec (negative control) target, which checks the real exit code, was the only one that noticed — and its failure was itself misread as a fixture problem. Two spec families had semantically invalid quantifier bounds the entire time.
- **Prose drift accumulates where no pin exists.** Twelve README prose sites contradicted the code (crate attributions, connector statuses, scope claims, exit-code table). The pinning tests only cover the status table and headline counts; everything else relies on the quarterly pass — which is exactly why the Q3 lapse mattered. Consider extending `readme_drift_check.sh` semantics checks or adding targeted pins for the highest-value claims (the exit-code taxonomy, the PQ crate map).
- **Beads velocity is not vision progress.** 98.7% of beads are closed, but the open set is dominated by external-resource dependencies (live multi-machine proofs, external crypto review, Windows hardware) and 15 NO_BEAD gaps were found by this audit (now filed as the `RC-2026-08-29` set under epic `yk5sd`).
- **Tooling fragility compound:** the beads DB was corrupt (page-level B-tree damage) *and* schema-stale *and* the recovery path exposed a deterministic `br`/fsqlite 0.5.3 incremental-write corruption bug (~14 mutations to first failure), filed as `flywheel_connectors-338gk`. Recovery protocol documented in the reality artifact; JSONL was never corrupted.

## Actions Taken (this pass)

- CI: added `Install Linux build dependencies` (`pkg-config`, `libdbus-1-dev`) to 15 job sites across `ci.yml`, `perf-regression.yml`, `reality-check-cadence.yml`, mirroring the existing `release.yml` pattern. Cadence workflow additionally gained a loud failure annotation so a pre-logic failure cannot pass silently again.
- README: fixed the 4 pinning-test failures (audit-status `br-lvz4t` reference, Secretless precision phrases, Mesh-Native label suffix, OperationInfo 176); corrected the 12 prose drift items (PQ crate map, ML-DSA KAT scope, PKCS#11 locus, tailscale LocalAPI, `ZoneTransportPolicy`/transport loci, OpenRouter consumer list, tlon/huggingface statuses, `_adversarial` scope, offline-access evidence scope, `chaos-results/` locus, intent.rs metrics, retired `serve_mcp` Tokio admission); annotated the 14-stage pipeline table with the implemented check names; rewrote the exit-code table to the implemented, test-pinned `CliExitCode` taxonomy (the refusal is **8**, documented; the previous table's 0–7 diverged wholesale from the code).
- Formal models: fixed dependent comma-separated quantifier bounds in `agent_mail_ordering(.tla, _broken)`, `audit_liveness(.tla, _broken)`; unmasked TLC exit codes in all six healthy Makefile targets (redirect + `cat`, matching the broken-target shape). Verified locally with the CI-pinned jar (v1.7.4, sha1-checked): 6 × green, 6 × `expected_red`.
- `fwc`: fixed the unknown-flag error misclassification (`plan --offline` reported `unknown-command: 'plan'; Did you mean 'plan'?`) — valid command + bad flag now yields `unknown-argument` (exit 2) naming the offending flag, and `did_you_mean` can no longer suggest the typed command. Two regression tests added.
- Beads: recovered the tracker DB from JSONL (3,897 → 3,911 → 3,924+ issues across concurrent agent writes); filed the 13-bead `RC-2026-08-29` bridge set + the fsqlite corruption bug; wired dependencies under epic `yk5sd`.
- Docs: published this report and the August monthly artifact; diagnosed all three cadence failures (single shared cause, already fixed) in `jqx5k`.

## Ledger Supersession Delta

`docs/architecture/master_reachability.md` remains the authoritative 24-row ledger and is consistent with this report. The quarterly `TEMPLATE.md` still carries the older 16-row set and has been updated this quarter to the 24-row set (see repo diff).

## Next Quarter Focus

- Verify CI goes green and **stays** green; treat any future 60-run red window as a P1 by itself.
- Re-run connector inventory measurements rather than carrying forward counts (the `OperationInfo` drift is exactly what this catches).
- Check that the September monthly cadence run (2026-09-01) completes and that the cadence failure annotation works if it does not.
- Watch `flywheel_connectors-338gk` (fsqlite incremental-write corruption); until fixed, fleet discipline is <10 mutations per DB generation then rebuild from JSONL.
- Keep Mesh-Native non-operational wording pinned until ordinary `fwc invoke` uses a real mesh-backed path with E2E evidence (all four cutover gates green).
- Review whether `manifest_operation_field_coverage_conformance`'s `#[ignore]`d reject test can be re-enabled (`4kw5f.9` lineage).
