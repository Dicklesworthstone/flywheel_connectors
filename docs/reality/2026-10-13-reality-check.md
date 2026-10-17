# Flywheel Connectors — Project Reality Check & Bridge Plan (`2026-10-13`)

**Date:** `2026-10-13` (Q4 2026)  
**HEAD Commit Audited:** `341704c69d155efa53d74b2ba52751f421b92477` (`main` / `origin/main` / `origin/master`)  
**Previous Reality Check:** [`docs/reality/2026-08-29-reality-check.md`](../reality/2026-08-29-reality-check.md) (`5dc06fb71`, 168 commits prior)  
**Companion Quarterly Artifact:** [`docs/quarterly/2026-Q4-claims-vs-reality.md`](../quarterly/2026-Q4-claims-vs-reality.md)

---

## Executive Summary

Between `2026-08-29` and `2026-10-13`, `main` advanced by **168 commits** across core platform crates and flagship connectors. Contrary to the August 29 projection that the repository had entered a low-change maintenance window, Q3→Q4 saw major architectural delivery across five fronts:

1. **Per-Archetype Cancellation Deadlines (`flywheel_connectors-861lx`):** Landed in `804e103c5` and hardened in `dec885635`, `9688c4ed4`, `a0ba87a0f`, `5e167cf1e`, `b567398f2`, and `2bf25caee` (1s request-response/webhook/polling/database/file-blob/CLI/browser; 10s streaming/bidirectional/queue-pubsub; 200ms reaper cadence; SIGTERM→SIGKILL escalation; per-execution WASI epoch/fuel abort; native RPC cancellation settlement).
2. **Mesh-Backed Invoke Routing, Membership Distribution, & Durable State Replication (`flywheel_connectors-hr0rr.2` family):** Landed multi-node mesh invoke routing (`42c122047`), owner-signed peer directory manifests and hot-reload (`1749cee79`, `3dab90d2d`), HTTPS membership distribution and `fcp-mesh-directory` CLI (`53c74a7af`, `ed3e1e1a1`, `7a47e45f4`), durable connector-state replica export/adoption/multi-donor pull (`2f9e468d6`..`fea37f0db`), and read-only retained invoke-journal snapshot/follow export via the new `fwc-audit-export` binary (`89260b3e3`, `e7f9165fb`, `9a38b5559`, `341704c69`).
3. **Asupersync `0.5.0` Runtime Upgrade (`flywheel_connectors-m1g2w`):** Landed across all 16 direct runtime declarations (`fe34cc856`, `81cd055d0`, `3ff079bbe`), preserving fallible `RuntimeHandle::try_spawn` admission and fixing `Sleep` first-poll deadline anchoring.
4. **Threshold HPKE Primitives (`flywheel_connectors-angoc.11.6.1` partial):** Landed FROST Ed25519 → X25519 share derivation, RFC 9180 labeled HKDF schedule, and 2-of-3 roundtrip/error-matrix tests in `fcp-crypto` (`6ef180061`, `b6d5798c3`).
5. **Standalone SDK Session Authority & MCP Bridge Hardening:** Landed instance-bound standalone session authority, signed call/byte/usage budgets, prompt retrieval, resource templates, and argument completion in `fcp-sdk` and `connectors/mcp-bridge` (`36270adeb`..`5b13cec47`).

**However, the verification and tracking envelope suffered a severe silent breakdown between `2026-10-07` and `2026-10-13`:**

- **109 commits (`3dab90d2d..341704c69`) landed on `main` after `2026-10-08T19:01:51Z` without triggering a single `CI` workflow run**, because commits were published via GitHub REST API blob/ref updates (`GITHUB_TOKEN` / GitHub App), which suppress GitHub Actions `on: push` triggers.
- **75 of those 109 commits explicitly note in their commit message:** *"Cargo, rustfmt and rch are unavailable here, so compilation and tests remain unverified."*
- **As a result, `HEAD` (`341704c69`) does not compile cleanly across the workspace:**
  1. `crates/fwc` (and `crates/fcp-conformance` integration tests, which dev-depend on `fwc`) **fails to compile** at `crates/fwc/src/capability_replay.rs:81` and `:404` (`error[E0277]: the trait bound KeyId: std::hash::Hash is not satisfied`, introduced in commit `3931e71b3`).
  2. `cargo fmt --all -- --check` **crashes with a fatal module resolution error** (`Error writing files: failed to resolve mod tests: .../crates/fcp-host/src/bin/fcp-host/tests.rs does not exist`) because `crates/fcp-host/src/bin/fcp-host/session.rs:193` (and `crates/fcp-host/src/bin/fcp-mesh-directory/sync/sources.rs:203`) declare bare `mod tests;` inside `#[path = "..."]`-anchored parent modules, and **86 source files** have rustfmt diffs.
  3. Two major host integrations (`crates/fcp-host/src/bin/fcp-host/http_batch.rs` from `f3ed2ade8` and async mesh replay admission in `.github/workflows/mesh-admission-handler-migration.yml` from `069fcaed8`) were **staged on disk as unreferenced modules/workflows** without wiring them into `crates/fcp-host/src/bin/fcp-host.rs`.
  4. **Local Beads (`br` / `bv`) broke on `2026-10-07`:** `.beads/beads.db` remained on `fsqlite` schema v4 with a corrupted partial index (`idx_issues_assignee`) while `br 0.7.4` expected schema v19, and `.beads/metadata.json` pointed to a non-existent `beads_flywheel_connectors_v4.db`. Consequently, **zero beads were closed or updated after `2026-09-12`** despite 100+ October commits. *(Repaired during this reality-check pass: `br doctor migrate-schema recover` + schema-19 rebuild + `.beads/metadata.json` target fix restored 100% green `br doctor` and `bv --robot-triage` health.)*
  5. **Monthly/Quarterly Cadence Automation Failed Twice (`2026-09-01` and `2026-10-01`) and Has a Day-of-Month Blindspot:** `.github/workflows/reality-check-cadence.yml` failed on `cargo install --git ... beads_rust` (`multiple packages with binaries found: beads_rust, beads_rust-fuzz`), and `crates/br-tools/src/scheduled_reality_check.rs` returns `Vec::new()` on any day where `today.day() != 1`, falsely reporting `"reality-check cadence is current"` on days `2..=31` even when the monthly and quarterly artifacts are missing.

---

## Phase 1: The Five Core Reality-Check Questions

### 1. What IS working right now?

- **Workspace scale & structural integrity:**
  - **42 platform crates** under `crates/` and **177 connector crates** under `connectors/` (219 workspace members total, zero duplicate workspace entries).
  - **176 of 177 connectors** follow the full `src/client.rs` + `src/connector.rs` + `src/types.rs` layout (`fcp- webhook-receiver` is the documented structural outlier); **176 of 177** publish explicit `OperationInfo` structs (**772 `OperationInfo` literals** total); **142 of 177** implement `ConnectorErrorMapping`; **137 of 177** have `tests/integration.rs`.
  - `bash scripts/ci/readme_drift_check.sh` **passes 100%** (`153 paths checked, 0 missing; 10 symbols checked, 0 missing`).
  - **40 core/platform library crates** (`fcp-core`, `fcp-async-core`, `fcp-crypto`, `fcp-crypto-pq`, `fcp-cbor`, `fcp-protocol`, `fcp-manifest`, `fcp-sandbox`, `fcp-store`, `fcp-raptorq`, `fcp-tailscale`, `fcp-mesh`, `fcp-host --lib`, `fcp-sdk`, `fcp-streaming`, `fcp-oauth`, `fcp-registry`, `fcp-telemetry`, `fcp-webhook`, `fcp-audit`, `fcp-bootstrap`, `fcp-conformance --lib`, `fcp-testkit`, `fcp-evidence`, `fcp-policy`, `fcp-kernel`, `fcp-ratelimit`, `fcp-chaos`, `fcp-bench`, `fcp-migrate`, `br-tools`, etc.) compile cleanly on `rch` (`hz4` job `j-30063538433163303`).
- **Four `PROVEN` README rows remain backed by code, tests, and formal artifacts:**
  - **Capability Tokens (COSE_Sign1):** `CapabilityToken<UnboundVerified>` vs `CapabilityToken<BoundVerified>` typestate split + `fcp-auth-schema::AuthClaims` + `lean/Fcp/Capability/Typestate.lean` (zero `sorry`/`admit`).
  - **Secretless Connectors:** `SecretFetchHook` + `credential_id` scrubbing + redaction gauntlet across GitHub, Slack, and Gmail E2E suites.
  - **Audit Trail:** BLAKE3 hash-linked `AuditEntry` chains + HLC timestamps + request-scoped host lifecycle explanations (`crates/fcp-audit/src/explain/host.rs`) + read-only journal snapshots and streaming follower (`crates/fcp-host/src/invoke_audit_snapshot.rs`, `crates/fwc/src/bin/fwc-audit-export.rs`) + `lean/Fcp/Audit/HashChain.lean`.
  - **2-Tier Deterministic Limiter:** `VdfChallenge` + `QuotaWindowCounter` + `UsageBudgetSnapshot` + TLA+ specs (`QuotaNoOverrun`, `TokenBucketBoundedDrift`).
- **Eighteen `IMPLEMENTED` rows** have substantive runtime implementations, unit/integration coverage, and recent hardening (including per-archetype cancellation deadlines, `asupersync 0.5.0`, standalone SDK session authority, and multi-node mesh routing/state replication building blocks).
- **Local Beads (`br` 0.7.4 / `bv`) health:** Restored during this session (`3,936` total issues; `3,883` closed = `98.65%`).

### 2. What is NOT working / not yet implemented?

1. **`crates/fwc` (lib, bins, and dependent conformance tests) fails to compile on `HEAD` (`341704c69`):**
   - `crates/fwc/src/capability_replay.rs:81` and `:404` insert/lookup `fcp_crypto::KeyId` in a `std::collections::HashMap<KeyId, Ed25519VerifyingKey>`, but `KeyId` (`crates/fcp-crypto/src/kid.rs:21`) only implements `Clone, Serialize, Deserialize, Default, ConstantTimeEq, PartialEq, Eq, Zeroize, Drop` — **not `std::hash::Hash` or `Ord`**.
2. **`cargo fmt --all -- --check` fails with a module-resolution error and 86 unformatted files:**
   - `crates/fcp-host/src/bin/fcp-host/session.rs:193` has `mod tests;` inside a module loaded via `#[path = "fcp-host/session.rs"]` in `fcp-host.rs:167`. `rustfmt` and `rustc --test` look for `crates/fcp-host/src/bin/fcp-host/tests.rs` instead of `crates/fcp-host/src/bin/fcp-host/session/tests.rs` because `#[path = "session/tests.rs"]` is missing.
   - `crates/fcp-host/src/bin/fcp-mesh-directory/sync/sources.rs:203` has `mod tests;` inside a module loaded via `#[path = "sync/sources.rs"]` in `sync.rs:25`. Without `#[path = "sources/tests.rs"]`, it resolves to `sync/tests.rs` instead of `sync/sources/tests.rs`.
   - 86 files modified across the 75 unverified commits since `2026-10-08` have unformatted lines.
3. **Compiler / Rustdoc warnings that fail `-D warnings` gates:**
   - `crates/fcp-crypto/src/threshold_hpke.rs:81`: ambiguous intra-doc link `[crate::hpke_seal]` (both `mod hpke_seal` and `fn hpke_seal` exist in `fcp_crypto`), failing `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps`.
   - `crates/fcp-crypto/src/threshold_hpke.rs:417` (`fn group_pk_bytes`) and `crates/fcp-crypto/src/threshold_hpke/derive.rs:40` (`pub fn group_x25519_public_key`): dead-code warnings when compiling `fcp-crypto`.
   - `crates/fcp-sandbox/src/wasi.rs:971` (`engine_config.async_support(true)`) and `:1220` (`func.post_return_async(&mut store)`): deprecated `wasmtime 46.0.3` calls failing `#[deny(warnings)]` / Clippy.
   - `connectors/slack/src/connector.rs:1464`: `#[warn(recursion_depth_exceeding_limit)]` during `Send` auto-trait check on `WsTransport::send`.
4. **ASUPERSYNC Tokio Guardrail (`scripts/ci/asupersync_tokio_guard.sh`) fails deterministically:**
   - `.config/asupersync/tokio_exception_ledger.json` specifies `max_count: 0` and `dependency_exceptions: []`, whereas the workspace intentionally retains the quarantined Tokio compatibility bridge in `fcp-async-core` and dev/test surfaces (`139` `tokio::` references across 7 crates: `fcp-async-core`, `fcp-crypto`, `fcp-store`, `fcp-telemetry`, `fcp-e2e`, `fcp-postgresql`).
5. **Two staged `fcp-host` binary integrations are unwired on `main`:**
   - `crates/fcp-host/src/bin/fcp-host/http_batch.rs` and `http_batch_tests.rs` (commit `f3ed2ade8`) are not declared in `crates/fcp-host/src/bin/fcp-host.rs` (`mod http_batch;` is only in the unapplied patch inside `.github/workflows/http-batch-integration.yml`).
   - Async mesh replay admission (`router.accept_inbound_async` + `invoke_jobs::execute` in `.github/workflows/mesh-admission-handler-migration.yml`, commit `069fcaed8`) is not applied to `crates/fcp-host/src/bin/fcp-host.rs` (and its pinned `BASE_BLOB` `27b49f81` is already stale relative to `fcp-host.rs` blob `a4b34764`).
6. **`LiveTruthResolver::resolve_with_policy` violates the A.6 single-host fallback gate:**
   - `crates/fwc/src/truth.rs:1757` uses `policy.source_order()` directly instead of `self.effective_sources(...)`, so under the default `V2MeshNative` policy it attempts `KnowledgeState::MeshBacked` even when `mesh_backed_enabled == false`.
7. **Mesh-Native Architecture (`V2`) and Zone Isolation (`LIMITED`) have not yet graduated to `PROVEN`:**
   - **Mesh-Native (`STEADY-STATE TARGET (NOT YET OPERATIONAL)`):** Massive progress landed on `hr0rr.2` (peer routing, directory manifests, durable state replication, retained journal snapshots), but `fwc`'s default production invoke path (`HostClient::invoke` in `crates/fwc/src/main.rs`) still posts to `/rpc/invoke` on `fcp-host`, and `flywheel_connectors-hr0rr.2.5` (`A.5`) remains `in_progress`.
   - **Zone Isolation (`LIMITED`):** All 4 code/proof children of `flywheel_connectors-angoc.2` (`C.1`–`C.7`) are closed and `lean/Fcp/Zone/Lattice.lean` has zero `sorry`s, but `docs/formal/readme-proof-obligations.json` requires fresh (<24h), SHA-pinned green artifacts at `artifacts/lean/${GITHUB_SHA}.txt` and `artifacts/e2e/zone_isolation_full_e2e/${GITHUB_SHA}.jsonl` before the README status can flip from `LIMITED` to `PROVEN`.

### 3. What is blocking us from our stated vision?

1. **Immediate Verification & Compilation Blockers (Tier 0):**
   - `KeyId: Hash` missing in `fcp-crypto` → blocks compiling `fwc` and `fcp-conformance`.
   - Missing `#[path = "..."]` on `mod tests;` in `fcp-host/session.rs` and `fcp-mesh-directory/sync/sources.rs` + 86 unformatted files → blocks `cargo fmt --check` and binary test targets.
   - GitHub App/token commit publication bypassing `on: push` CI triggers → 109 commits landed without CI feedback.
   - Zero-tolerance `tokio_exception_ledger.json` vs documented `fcp-async-core` compat bridge → fails `asupersync-guardrails` on every CI run.
2. **Architectural Cutover & Proof Evidence Blockers (Tier 1):**
   - Completing `flywheel_connectors-hr0rr.2.5` (`A.5`) and wiring the staged `http_batch.rs` / mesh admission handlers into `fcp-host.rs`.
   - Generating and archiving SHA-pinned `lean-verify-zone-lattice` and `zone-isolation-full-e2e` artifacts to graduate Zone Isolation (`flywheel_connectors-angoc.2`).
   - Hardware benchmark execution on `csd`, `Contabo`, and `laptop` for ML-DSA-65 hybrid signing (`flywheel_connectors-angoc.8.3` → `angoc.8.2` → `angoc.8`) and real Tailscale transport invoke latency (`flywheel_connectors-u1jce`).
   - Completing the remaining 2 deliverables of `flywheel_connectors-angoc.11.6.1` (`threshold_hpke_sealed_object_e2e.rs` and `fcp-store` `ObjectHeader` `encryption_kind="threshold_hpke_quorum"`).

### 4. If we completed all open and in-progress beads right now, would that close the gap completely?

**NO.** Even if all 53 previously non-closed beads were completed today:
- `crates/fwc` would still fail to compile (`KeyId: Hash` regression from `3931e71b3` had **no bead**).
- `cargo fmt --all -- --check` would still crash on `fcp-host/session.rs` `mod tests;` and fail across 86 files (**no bead**).
- `cargo doc --no-deps` and Clippy would still fail on `fcp-crypto::threshold_hpke` and `fcp-sandbox::wasi` warnings (**no bead**).
- `scripts/ci/asupersync_tokio_guard.sh` would still fail on `.config/asupersync/tokio_exception_ledger.json` (**no bead**).
- The staged `http_batch.rs` and `mesh-admission-handler-migration.yml` patches would remain unwired in `fcp-host.rs` (**no bead**).
- `reality-check-cadence.yml` would fail again on `2026-11-01` due to `cargo install --git ... beads_rust` ambiguity, and `scheduled-reality-check` would remain blind on days `2..=31` (**no bead** covering the new root causes).
- `LiveTruthResolver::resolve_with_policy` would still bypass `mesh_backed_enabled` (**no bead**).

### 5. What goals, requirements, or broken functionality have `NO_BEAD` coverage?

| Gap ID | Severity | Surface | Description | Newly Filed Bead |
|--------|----------|---------|-------------|------------------|
| **GAP-1** | **P0 (Blocker)** | `fcp-crypto`, `fwc`, `fcp-host` | `fwc` fails to compile (`KeyId: Hash` missing in `crates/fcp-crypto/src/kid.rs:21` for `crates/fwc/src/capability_replay.rs:81,404`); `cargo fmt` crashes on missing `#[path = "..."]` for `mod tests;` in `crates/fcp-host/src/bin/fcp-host/session.rs:193` and `crates/fcp-host/src/bin/fcp-mesh-directory/sync/sources.rs:203`. | `flywheel_connectors-u9arm.1` |
| **GAP-2** | **P1 (High)** | Workspace formatting, `fcp-crypto`, `fcp-sandbox`, CI | 86 files unformatted from 75 unverified commits; `fcp-crypto::threshold_hpke` ambiguous `[crate::hpke_seal]` rustdoc link (`threshold_hpke.rs:81`) + unused functions (`group_pk_bytes`, `group_x25519_public_key`); `fcp-sandbox::wasi` deprecated `wasmtime 46` methods (`async_support`, `post_return_async`). | `flywheel_connectors-u9arm.2` |
| **GAP-3** | **P1 (High)** | `.config/asupersync/`, `scripts/ci/` | `asupersync_tokio_guard.sh` fails (`missing_dependency_exceptions=7`, `failed_source_invariants=7`) because `tokio_exception_ledger.json` was zeroed out while the documented `fcp-async-core` Tokio compat bridge and dev-dep surfaces remain active. | `flywheel_connectors-u9arm.3` |
| **GAP-4** | **P1 (High)** | `.github/workflows/reality-check-cadence.yml`, `crates/br-tools/` | Cadence workflow failed on `2026-09-01` and `2026-10-01` (`cargo install --git ...` missing `beads_rust` package name), and `scheduled_reality_check.rs` returns `Vec::new()` when `today.day() != 1`, hiding overdue monthly/quarterly passes on days `2..=31`. | `flywheel_connectors-u9arm.4` |
| **GAP-5** | **P1 (High)** | `crates/fcp-host/src/bin/fcp-host.rs`, `.github/workflows/` | Staged-only `http_batch.rs` (`f3ed2ade8`) and `mesh-admission-handler-migration.yml` (`069fcaed8`) are not wired into `crates/fcp-host/src/bin/fcp-host.rs`; `fcp-host.rs` is a 1.4 MiB (16,900-line) monolith that forced workflow-based patch staging and bypassed `on: push` CI. | `flywheel_connectors-u9arm.5` |
| **GAP-6** | **P2 (Medium)** | `crates/fwc/src/truth.rs` | `LiveTruthResolver::resolve_with_policy` (`truth.rs:1748-1833`) iterates `policy.source_order()` directly instead of `self.effective_sources(...)`, ignoring `mesh_backed_enabled: false` under default `V2MeshNative` policy. | `flywheel_connectors-u9arm.6` |
| **GAP-7** | **P2 (Medium)** | `Cargo.lock`, `connectors/slack`, `ci.yml` | `ci.yml` `Security Audit` (`cargo audit`) fails on 11 transitive advisories; `Golden Vectors` fails on `fcp-slack` (`connector.rs:1464`) `recursion_depth_exceeding_limit` during `WsTransport::send` `Send` check under `-D warnings`. | `flywheel_connectors-u9arm.7` |
| **GAP-8** | **P2 (Medium)** | `README.md`, `AGENTS.md` | Minor inventory/doc drift: `ConnectorErrorMapping` count (`140` claimed vs `142` actual), `intent.rs` stats (`5,969 lines, 250 tests` claimed vs `6,264 lines, 267 tests` actual), undocumented new binaries (`fwc-audit-export`, `fcp-mesh-directory`), and `AGENTS.md` `bv --robot-triage` jq paths (`.quick_ref` vs `.triage.quick_ref`). | `flywheel_connectors-u9arm.8` |

---

## Vision Checklist & 24-Row Master Reachability Verification

Cross-checked against [`README.md`](../../README.md), [`docs/architecture/master_reachability.md`](../architecture/master_reachability.md), [`docs/FCP3_Transition_Scorecard.md`](../FCP3_Transition_Scorecard.md), and [`crates/fcp-conformance/tests/master_reachability_ledger.rs`](../../crates/fcp-conformance/tests/master_reachability_ledger.rs):

| # | Feature / Claim | README Status | Actual Reality (`2026-10-13`) | Alignment & Delta Since `2026-08-29` |
|---|-----------------|---------------|-------------------------------|--------------------------------------|
| 1 | **Zone Isolation** | `LIMITED` | Enforced in `fcp-policy` + `fcp-host`; `lean/Fcp/Zone/Lattice.lean` has 0 `sorry`s; all 4 children of `angoc.2` closed. | **Aligned.** Needs fresh (<24h) SHA-pinned `artifacts/lean/` and `artifacts/e2e/zone_isolation_full_e2e/` runs to graduate to `PROVEN` (`angoc.2`). |
| 2 | **Capability Tokens (COSE_Sign1)** | `PROVEN` | Typestate `CapabilityToken<UnboundVerified\|BoundVerified>` + `fcp-auth-schema` + Lean proof. | **Aligned.** |
| 3 | **Secretless Connectors** | `PROVEN` | `SecretFetchHook` + `credential_id` redaction gauntlet across GitHub/Slack/Gmail E2E. | **Aligned.** |
| 4 | **WASI + OS Sandboxing** | `IMPLEMENTED` | Wasmtime 46 + Linux Landlock/seccomp + macOS seatbelt + Windows AppContainer (`r4qcg.2/3/4` open for full Windows parity). | **Aligned.** Note: `a0ba87a0f` added per-execution WASI cancellation abort; `wasi.rs:971,1220` has 2 deprecated wasmtime calls (`GAP-2`). |
| 5 | **Mesh-Native Architecture** | `STEADY-STATE TARGET (NOT YET OPERATIONAL)` | Major progress: peer invoke routing (`42c122047`), signed peer directory + HTTPS sync (`1749cee79`, `53c74a7af`), durable state transfer (`76233ed77`, `fea37f0db`). Default `fwc` invoke remains host-first. | **Aligned.** `hr0rr.2.5` (`A.5`) is the final in-progress cutover child before graduation. |
| 6 | **RaptorQ Erasure Coding** | `IMPLEMENTED` | RFC 6330 codec + symbol store + Thompson-sampling Bayesian `KSelector` (`fcp-raptorq`). | **Aligned.** |
| 7 | **Shamir Secret Sharing (t-of-n)** | `IMPLEMENTED` | GF(256) Shamir + FROST Ed25519 DKG + new threshold-HPKE KEM primitives (`6ef180061`, `b6d5798c3`). | **Aligned.** `angoc.11.6.1` has 2 remaining deliverables (store header + E2E). |
| 8 | **Supply Chain Verification** | `IMPLEMENTED` | TUF + Sigstore + `SupplyChainPolicy` admission in `fcp-host`. | **Aligned.** |
| 9 | **Audit Trail** | `PROVEN` | BLAKE3 hash chain + HLC + Lean proof + new request-scoped host explainer (`b51f52b22`) + read-only journal snapshot/follow (`fwc-audit-export`, `341704c69`). | **Aligned.** Note: `capability_replay.rs` needs `KeyId: Hash` fix (`GAP-1`). |
| 10 | **Rate Limiting** | `IMPLEMENTED` | Token bucket, sliding window, leaky bucket, quota enforcement in `fcp-ratelimit`. | **Aligned.** |
| 11 | **OAuth2 / OIDC** | `IMPLEMENTED` | OAuth2 + PKCE + refresh lifecycle in `fcp-oauth`. | **Aligned.** |
| 12 | **Streaming (SSE + WebSocket)** | `IMPLEMENTED` | SSE/WS with reconnect/backpressure; hardened in `90c8f8464` and `5e6616411` (SSE overflow fail-closed, stop/resume controls). | **Aligned.** |
| 13 | **Webhook Verification** | `IMPLEMENTED` | HMAC-SHA256, Ed25519, Stripe/GitHub/Slack/Linear verifiers + replay cache in `fcp-webhook`. | **Aligned.** |
| 14 | **GraphQL Client** | `IMPLEMENTED` | Typed query/mutation/subscription client + deadline error mapping (`fcp-graphql`). | **Aligned.** |
| 15 | **Google Discovery** | `IMPLEMENTED` | Discovery doc ingestion + schema normalization in `fcp-google-discovery`. | **Aligned.** |
| 16 | **Chaos & Fault Injection** | `IMPLEMENTED` | Deterministic 7-fault harness in `fcp-chaos`. | **Aligned.** |
| 17 | **Protocol Conformance** | `IMPLEMENTED` | `fcp-conformance` vectors, schemas, and reachability tests. | **Temporarily blocked on `HEAD` by `GAP-1`** (`fwc` dev-dependency compile error). |
| 18 | **E2E Test Harness** | `IMPLEMENTED` | `fcp-e2e` subprocess, secretless, zone isolation, and failover suites. | **Aligned.** |
| 19 | **Structured Telemetry** | `IMPLEMENTED` | OpenTelemetry + Prometheus + trace context propagation in `fcp-telemetry`. | **Aligned.** |
| 20 | **CLI (`fwc`)** | `IMPLEMENTED` | 48 top-level subcommands + `LiveTruthResolver` + new `fwc-audit-export` companion binary. | **Temporarily blocked on `HEAD` by `GAP-1`** (`capability_replay.rs` `KeyId: Hash`). |
| 21 | **SDK (`fcp-sdk`)** | `IMPLEMENTED` | Authoring traits, retry loop, schema validation, plus new standalone instance-bound session authority and signed call/byte/usage budgets (`36270adeb`..`d9d936da3`). | **Aligned.** |
| 22 | **2-Tier Deterministic Limiter** | `PROVEN` | `VdfChallenge` + `QuotaWindowCounter` + `UsageBudgetSnapshot` + TLA+ specs. | **Aligned.** |
| 23 | **Keyless / Secretless Ingress** | `IMPLEMENTED` | Webhook tokenless + Tailscale peer identity + bearer passthrough (`fcp-provider-auth`). | **Aligned.** |
| 24 | **177 Connectors** | `IMPLEMENTED` | 177 connector crates; `mcp-bridge`, `airtable`, `discord`, and `gitlab` received substantive session/framing/deadline hardening in Oct 2026. | **Aligned.** (`angoc.16.3` and `angoc.16.5` graduation sweeps in progress). |

---

## Beads Backlog Audit (`2026-10-13`)

### Epics & Beads Closed During This Reality Check
- **`flywheel_connectors-yk5sd`** (`[RC-2026-08-29] Tracker epic: verification-loop restoration from 2026-08-29 reality check`): All 14 child/blocking beads (`0misf`, `83yae`, `861lx`, `ce78o`, `ek45v`, `gwul7`, `jqx5k`, `prft8`, `q5rkt`, `tpi6g`, `uq6kc`, `vmq67`, etc.) were closed. Closed epic.
- **`flywheel_connectors-angoc.4`** (`[Phase J] Computation migration hardening`): All 4 children (`angoc.4.1`, `angoc.4.2`, `angoc.4.3`, etc.) closed. Closed epic.
- **`flywheel_connectors-angoc.5`** (`[Phase K] Quarterly + monthly reality-check cadence`): All 2 children (`angoc.5.1`, `angoc.5.2`) closed. Closed epic.
- **`flywheel_connectors-angoc.6`** (`[Phase L] Operator/agent friction reduction`): All 14 children (`angoc.6.1`..`angoc.6.4.4`) closed. Closed epic.
- **`flywheel_connectors-6thf5`** (`Coverage CI job: linker SIGBUS persists under llvm-cov`): Fixed by commit `1b164e2e0` (`fix(ci): scope Coverage job to platform crates to stop linker SIGBUS [flywheel_connectors-6thf5]`); verified green in CI run `37828851749`. Closed bead.

### Active `in_progress` Beads Status Check
1. **`flywheel_connectors-hr0rr.2.5` (P1, `in_progress`):** `[Mesh-Native][A.5] Wire LiveTruthResolver into fwc list/status/doctor` — Substantive commits landed (`1ab39a25d`, `bb6a1bfaf`, `53a8a83db`, `d3a613152`, `cc17c953c`, `b14cf3c1d`); remains open pending `GAP-1` compile fix, `GAP-6` (`resolve_with_policy` `mesh_backed_enabled` gate), and final 4-gate cutover verification.
2. **`flywheel_connectors-m1g2w` (P1, `in_progress`):** `Upgrade Asupersync to 0.5 and preserve fallible spawn admission` — Code and `fcp-async-core` 472/472 unit tests + clippy landed (`fe34cc856`, `81cd055d0`, `3ff079bbe`); held open only for workspace-wide compile/clippy verification once `GAP-1` and `GAP-2` clear.
3. **`flywheel_connectors-2k0sk` (P2, `in_progress`):** `27 crates silently opt out of [workspace.lints] inheritance` — Stanzas landed in `80b056097`; 6 crates cleared; 21 crates still carry pedantic/nursery clippy debt.
4. **`flywheel_connectors-cudqv` (P2, `in_progress`):** `reality-check-cadence workflow: diagnose Jun/Jul failures; add missed-run alerting` — Superseded/extended by `GAP-4` (`flywheel_connectors-u9arm.4`), which diagnoses the Sep/Oct `beads_rust` multi-binary install failure and the `today.day() != 1` blindspot in `scheduled_reality_check.rs`.
5. **`flywheel_connectors-angoc.11.6.1` (P3, `in_progress`):** `Deferred Rust impl for threshold-HPKE KEM reusing FROST DKG` — 3 of 5 deliverables landed (`threshold_hpke.rs`, `derive.rs`, `threshold_hpke_roundtrip.rs`); remaining 2 deliverables are `crates/fcp-e2e/tests/threshold_hpke_sealed_object_e2e.rs` and `fcp-store` `ObjectHeader` `encryption_kind="threshold_hpke_quorum"`.
6. **`flywheel_connectors-angoc.16.3` (P2, `in_progress`) & `flywheel_connectors-angoc.16.5` (P3, `in_progress`):** Connector graduation batches 2 and 4 — active multi-connector promotion sweeps.

---

## Phase 2 & Phase 4: The Bridge Plan (With Ambition Escalation)

**Tracker Epic:** `flywheel_connectors-u9arm` (`[RC-2026-10-13] Tracker epic: October 2026 & Q4 2026 Reality Check — Unverified-Batch Recovery & Verification-Envelope Hardening`)

### Stage 0 — Immediate Compilation & Module-Tree Restoration (P0, Unblocks Everything)
- **Bead `flywheel_connectors-u9arm.1`:**
  1. Implement `std::hash::Hash` (consistent with `ConstantTimeEq` byte equality over `self.0`) and `Ord`/`PartialOrd` on `fcp_crypto::KeyId` in [`crates/fcp-crypto/src/kid.rs`](../../crates/fcp-crypto/src/kid.rs), with unit tests proving `HashMap<KeyId, _>` and `BTreeMap<KeyId, _>` insertion/lookup determinism.
  2. Add `#[path = "session/tests.rs"]` to `mod tests;` in [`crates/fcp-host/src/bin/fcp-host/session.rs`](../../crates/fcp-host/src/bin/fcp-host/session.rs#L192-L193) and `#[path = "sources/tests.rs"]` to `mod tests;` in [`crates/fcp-host/src/bin/fcp-mesh-directory/sync/sources.rs`](../../crates/fcp-host/src/bin/fcp-mesh-directory/sync/sources.rs#L202-L203).
  3. Verify `rch exec -- cargo test -p fwc --lib` and `rch exec -- cargo test -p fcp-conformance --test readme_inventory_pinning --test master_reachability_ledger --test readme_lean_proven_gate --test readme_proven_artifact_pinning` pass.

### Stage 1 — Verification Envelope, Formatting, & CI Trigger Recovery (P1)
- **Bead `flywheel_connectors-u9arm.2` (Formatting + Lint/Doc Warnings):**
  1. Run `cargo fmt --all` across all 86 unformatted files introduced by the 75 unverified commits.
  2. Disambiguate `[crate::hpke_seal]` in [`crates/fcp-crypto/src/threshold_hpke.rs`](../../crates/fcp-crypto/src/threshold_hpke.rs#L81) to `[`crate::hpke_seal::HPKE_MAX_CIPHERTEXT`]` so `RUSTDOCFLAGS="-D warnings" cargo doc -p fcp-crypto --no-deps` passes.
  3. Wire or `#[cfg(test)]`-scope unused helpers `group_pk_bytes` (`threshold_hpke.rs:417`) and `group_x25519_public_key` (`threshold_hpke/derive.rs:40`) in `fcp-crypto`.
  4. Remove deprecated `wasmtime 46.0.3` calls `engine_config.async_support(true)` (`crates/fcp-sandbox/src/wasi.rs:971`) and `func.post_return_async(&mut store).await` (`crates/fcp-sandbox/src/wasi.rs:1220`).
- **Bead `flywheel_connectors-u9arm.3` (ASUPERSYNC Tokio Exception Ledger Reconciliation):**
  1. Reconcile [`.config/asupersync/tokio_exception_ledger.json`](../../.config/asupersync/tokio_exception_ledger.json) with the documented `fcp-async-core` quarantine contract in `README.md` (lines 1105, 3634–3652), recording bounded, non-expiring-without-replacement dependency and source invariants for the 7 bridge/dev-dep crates (`fcp-async-core`, `fcp-crypto`, `fcp-store`, `fcp-telemetry`, `fcp-e2e`, `fcp-postgresql`) while keeping `max_count: 0` on all 176 other connector and platform crates.
  2. Verify `bash scripts/ci/asupersync_tokio_guard.sh` exits `0` with `passed=true`.
- **Bead `flywheel_connectors-u9arm.4` (Cadence Automation & Continuous Overdue Detection):**
  1. Fix [`.github/workflows/reality-check-cadence.yml`](../../.github/workflows/reality-check-cadence.yml#L79) to pass explicit package name `beads_rust` to `cargo install --git ... beads_rust`.
  2. **Ambition Escalation — Continuous Monotonic Cadence Evaluator:** Upgrade [`crates/br-tools/src/scheduled_reality_check.rs`](../../crates/br-tools/src/scheduled_reality_check.rs) so `check_monthly_cadence_with_existing` and `check_quarterly_cadence_with_existing` evaluate **any day `today >= first_cadence_day_of_period(today)`**, not just `today.day() == 1`. Because `duplicate_suppressed` already checks `existing_beads` and `file_present` checks `docs/reality/{YYYY-MM}-*.md` / `docs/quarterly/{YYYY-QN}-claims-vs-reality.md`, removing the single-day equality gate makes the cadence check **idempotent and self-healing across the entire month/quarter**: if a 1st-of-month cron run fails or is delayed, any subsequent run or `workflow_dispatch` on days `2..=31` detects the missing artifact and files the overdue bead exactly once.

### Stage 2 — Host Monolith De-Staging & Truth-Resolver Contract Hardening (P1/P2)
- **Bead `flywheel_connectors-u9arm.5` (Complete Staged `fcp-host` HTTP Batch & Mesh Admission Wiring):**
  1. Wire `#[path = "fcp-host/http_batch.rs"] mod http_batch;` and the validated HTTP batch handler into [`crates/fcp-host/src/bin/fcp-host.rs`](../../crates/fcp-host/src/bin/fcp-host.rs) (completing `f3ed2ade8`).
  2. Apply the reviewed async mesh replay admission handler migration (`router.accept_inbound_async(&envelope).await` + `invoke_jobs::execute` + `replay_journal` `503 Service Unavailable` mapping from `069fcaed8`) directly into `crates/fcp-host/src/bin/fcp-host.rs`.
  3. **Ambition Escalation — Submodule Decomposition of `bin/fcp-host.rs`:** Extract the HTTP route table and mesh forwarding handlers out of the 1.4 MiB `crates/fcp-host/src/bin/fcp-host.rs` monolith into dedicated submodules under `crates/fcp-host/src/bin/fcp-host/`, eliminating the root cause that forced agents to use `.github/workflows/http-batch-integration.yml` and `.github/workflows/mesh-admission-handler-migration.yml` blob-staging workarounds.
- **Bead `flywheel_connectors-u9arm.6` (`LiveTruthResolver::resolve_with_policy` Single-Host Gate Parity):**
  1. Update `LiveTruthResolver::resolve_with_policy` in [`crates/fwc/src/truth.rs`](../../crates/fwc/src/truth.rs#L1748-L1833) to filter `policy.source_order()` through `self.config.mesh_backed_enabled` (matching `effective_sources`), ensuring that under `TruthPrecedencePolicy::v2_default()` a single-host deployment (`mesh_backed_enabled: false`) never attempts an unconfigured `MeshBacked` query or pollutes `DecisionTrace` with false `Unreachable` attempts.
  2. Add unit and property tests proving trace equivalence between `resolve_sync` and `resolve_with_policy` across `{V1HostFirst, V2MeshNative} × {mesh_backed_enabled: false, true}`.

### Stage 3 — CI Security Audit, Slack `Send` Bound, & Documentation Pinning (P2)
- **Bead `flywheel_connectors-u9arm.7` (`cargo audit` & `fcp-slack` `Send` Recursion Fix):**
  1. Box the large inner future in `connectors/slack/src/connector.rs` (`WsTransport::send` / `handle_invoke`) to eliminate `recursion_depth_exceeding_limit` during `Send` auto-trait synthesis without raising `#![recursion_limit]`.
  2. Triage and upgrade/audit-ignore with documented justification the 11 advisories failing `cargo audit` in `ci.yml`.
- **Bead `flywheel_connectors-u9arm.8` (README & AGENTS.md Inventory Sync):**
  1. Update `README.md` `ConnectorErrorMapping` count (`140` → `142`), `intent.rs` line/test count (`5,969 lines, 250 tests` → `6,264 lines, 267 tests`), and document `fwc-audit-export` and `fcp-mesh-directory`.
  2. Update `AGENTS.md` `bv --robot-triage` jq examples (`.quick_ref` → `.triage.quick_ref`, `.recommendations` → `.triage.recommendations`).
  3. Extend `crates/fcp-conformance/tests/readme_inventory_pinning.rs` to mechanically pin the `ConnectorErrorMapping` count so it can never drift silently again.

