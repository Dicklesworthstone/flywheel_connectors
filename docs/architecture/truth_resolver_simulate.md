# Simulate Semantics in the Truth-Resolver Taxonomy

> Bead: `flywheel_connectors-hr0rr.2.5`
> Companion runbook: `docs/runbooks/fwc_truth_source_classification.md` (see its
> `Simulate` section).
> Resolver pattern reference: commit `cd6bfe99b` (`fwc list` routed through
> `LiveTruthResolver::resolve_with_partials`).

This document defines how `fwc simulate` relates to the A.5 truth-source
taxonomy, what the shipped CLI actually does today, and what the target
contract is once the `simulated` truth-source value is wired. It distinguishes
**shipped** from **planned** behavior in every section.

Line numbers below are from the working tree at the time of writing and drift;
function and type names are the stable citations.

## 1. Position in the Truth Taxonomy

`fwc simulate` is **read-only at the host but policy-relevant**:

- It never executes the connector operation. The host path in
  `invoke_dispatch_host` (`crates/fwc/src/main.rs`) returns from the
  `if command == "simulate"` block immediately after `client.preflight(...)`;
  the `client.invoke(...)` call below that block is unreachable for simulate.
- It is still *live*: the preflight is evaluated "against live host policy and
  current connector state" (the success `message` text in that same block), it
  requires a capability token, and its outcome is written to the audit history
  (see §5). That makes the answer policy-relevant evidence, not a local guess.

The command classification matrix agrees:

- `COMMAND_CLASSIFICATIONS` entry for `"simulate"` in
  `crates/fwc/src/catalog.rs`: `truth_source: CommandTruthSource::LiveHost`,
  `execution_mode: CommandExecutionMode::Simulate`
  ("Simulation or preflight (read-only but may reach connectors)"),
  `host_absent: HostAbsentBehavior::FailFast`,
  `requires_capability_token: true`, `may_need_approval: false`.
- The `SimulateCapability` contract in `crates/fwc/src/catalog.rs`
  (`FullDryRun` / `PreflightOnly` / `Unknown` / `Unsupported`) exists
  precisely because a host-level preflight must not be advertised as
  connector-level dry-run: `allows_simulate_label()` is true only for
  `FullDryRun`, and the type's doc comment states "advertising 'simulate'
  when only 'preflight' is available is dishonest." The simulate payload
  surfaces this per-operation as `operation.supports_simulate`
  (`host_live_boolean_field(operation.supports_simulate)` in
  `invoke_dispatch_host`).

**Target contract (planned):** because simulate answers are produced without
committing side effects, downstream consumers must be able to tell them apart
from live runtime truth. The target is a distinct top-level
`_truth_source: "simulated"` value that is *non-authoritative by
construction*: it says "the host evaluated this plan" and explicitly does not
say "this state exists in the runtime."

## 2. Shipped Behavior (Current Implementation)

Dispatch chain, all in `crates/fwc/src/main.rs`:

1. `Commands::Simulate(InvokeArgs)` (clap variant: "Preflight or dry-run a
   connector operation.") is dispatched as
   `invoke_dispatch("simulate", args, cli.host.as_deref())` in the central
   command match.
2. `invoke_dispatch` resolves host configuration and branches directly:
   host configured → `invoke_dispatch_host`; otherwise
   `invoke_dispatch_without_host`. **It does not route through
   `LiveTruthResolver::resolve_with_partials`** — the hr0rr.2.5 resolver
   retrofit (canonical pattern in `cd6bfe99b`) has not been applied to the
   invoke/simulate path.
3. Host path (`invoke_dispatch_host`, `if command == "simulate"` block):
   - Resolves live auth, host catalog, connector, and operation; prepares and
     schema-validates the payload locally. Invalid payload →
     `invalid-input-payload` error, exit `CliExitCode::Validation`.
   - Runs the live host preflight. Allowed → `status: "ok"`,
     `phase: "preflight"`, `CommandAvailability::LiveRuntime` envelope, exit
     `CliExitCode::Success`. Denied → `status: "denied"`,
     `CommandAvailability::Denied` envelope, exit `CliExitCode::PolicyDenied`.
   - Appends an audit history entry: `history::OpStatus::Simulated` when
     allowed, `history::OpStatus::Denied` when denied, `latency_ms: 0`
     (nothing executed).
   - Stamps the payload with
     `inject_simulated_truth_source_metadata(&mut payload)`, i.e.
     **`_truth_source: "simulated"`** (non-authoritative marker, landed in
     hr0rr.2.5) — plus `schema_version: "fcp.fwc.truth-source.v1"`
     (`inject_truth_source_metadata`, `crates/fwc/src/main.rs`;
     `TRUTH_SOURCE_SCHEMA_VERSION`, `crates/fwc/src/truth.rs`).
4. Offline path (`invoke_dispatch_without_host`): there is **no offline
   artifact mode for simulate**. With a schema-valid payload the command
   refuses to fabricate execution: `error.type: "missing-host-endpoint"`,
   message "`fwc` will not fabricate connector execution", exit
   `CliExitCode::Transport`, stamped `KnowledgeState::Offline`
   (`_truth_source: "offline"`). With an invalid payload it is
   `invalid-input-payload` / `CliExitCode::Validation`, same offline stamp.
   This matches the classification's `HostAbsentBehavior::FailFast`.

Note the asymmetry this creates today: a successful simulate is stamped
`"simulated"` (since hr0rr.2.5), which downstream consumers MUST treat as
non-authoritative. Additional shipped signals that the answer was *simulated*:
`command: "simulate"`, `phase: "preflight"`, and the history entry — plus the
`"simulated"` truth-source marker itself. Previously (pre-hr0rr.2.5) there was
no top-level truth-source marker; hr0rr.2.5 landed it. The runbook's
`Simulate` section (`docs/runbooks/fwc_truth_source_classification.md`)
documents the shipped `_truth_source: "simulated"` contract.

## 3. `_truth_source: "simulated"` and `--require-source`

### Shipped

- `KnowledgeState` (`crates/fwc/src/truth.rs`) has exactly six variants —
  `MeshBacked`, `HostBacked`, `NodeLocal`, `Offline`, `Degraded`,
  `FallbackDerived` — and **no `Simulated` variant**.
  `KnowledgeState::operator_truth_source()` can therefore never emit the
  string `"simulated"`.
- `InvokeArgs` (`crates/fwc/src/main.rs`) has **no `--require-source` and no
  `--offline` flags**, so today an operator cannot attach a source floor to a
  simulate invocation at all. `--require-source` exists only on the read-only
  resolver-routed commands (see the runbook's `--require-source` table).

### Target contract (planned)

When the `simulated` value is introduced:

- `simulated` must satisfy **no live floor**. `RequiredTruthSource::accepts`
  (`crates/fwc/src/truth.rs`) accepts `Mesh` → `MeshBacked` only,
  `MeshOrHost` → `MeshBacked | HostBacked`, `AnyLive` →
  `KnowledgeState::is_live()` (which matches only `MeshBacked |
  HostBacked`). A simulated state must remain outside every one of these
  sets: `fwc simulate ... --require-source mesh-or-host` (or `mesh`, or
  `any-live`) must fail closed with the existing
  `truth-source-unavailable` error shape
  (`truth_source_unavailable_dispatch`, `crates/fwc/src/main.rs`) carrying
  `error.required: "<floor>"` and `error.actual: "simulated"`.
- Rationale: simulate output is a *policy evaluation of a plan*, not runtime
  state. Letting it satisfy a live floor would allow a workflow that demands
  proof of live truth to accept a dry run as that proof — exactly the
  confusion the runbook warns against ("Do not treat a simulated history
  entry as evidence that the operation ran").
- A future opt-in floor (e.g. accepting `simulated` explicitly) would be a
  new `RequiredTruthSource` level; it must never be folded into `any-live`.

## 4. Shipped vs Planned Summary

| Aspect | Shipped (today) | Planned (target contract) |
|--------|-----------------|---------------------------|
| Dispatch | `invoke_dispatch` branches host/offline directly (`crates/fwc/src/main.rs`) | Route through `LiveTruthResolver::resolve_with_partials` per the hr0rr.2.5 pattern (`cd6bfe99b`) |
| Top-level truth tag (host path) | `_truth_source: "host"` | `_truth_source: "simulated"`, non-authoritative by contract |
| Top-level truth tag (no host) | `_truth_source: "offline"` + `missing-host-endpoint` refusal | Unchanged — simulate keeps `FailFast` host-absent behavior |
| `--require-source` on simulate | Flag does not exist on `InvokeArgs` | Flag exists; `simulated` satisfies no `mesh`/`mesh-or-host`/`any-live` floor |
| `KnowledgeState` taxonomy | Six variants, no `Simulated` (`crates/fwc/src/truth.rs`) | Adds a simulated state/tag whose `accepts`/`is_live` semantics keep it non-live |
| Side-effect honesty | `SimulateCapability` + `operation.supports_simulate` (`crates/fwc/src/catalog.rs`) | Unchanged; remains the per-connector dry-run honesty layer |
| Audit trail | `OpStatus::Simulated` / `OpStatus::Denied` history entries (`crates/fwc/src/history.rs`) | Unchanged; history stays the correlation surface |

The honest statement of current state: **the `simulated` top-level truth
surface is not wired yet.** The simulate branch still stamps
`KnowledgeState::HostBacked` (`invoke_dispatch_host`,
`crates/fwc/src/main.rs`), the taxonomy has no simulated variant
(`crates/fwc/src/truth.rs`), and the runbook
(`docs/runbooks/fwc_truth_source_classification.md`, `Simulate` section)
already documents the gap under bead `flywheel_connectors-hr0rr.2.5`.

## 5. Operator Guidance

### When to trust simulate output

Trust a successful (`status: "ok"`) simulate answer for exactly one claim:
*with this payload, this principal, this zone, and this capability token, the
live host's policy engine would allow the operation right now.* It is a real
host preflight — schema validation, policy check, and budget evaluation
against current connector state (`invoke_dispatch_host`,
`crates/fwc/src/main.rs`).

Do **not** trust it as:

- **Proof the operation ran.** No invoke RPC is made; the recorded latency is
  `0` and the history status is `simulated`, not `success`.
- **Proof of runtime or mesh state.** Simulate evaluates a plan; it does not
  read live connector data. For live state, use a read-only command with a
  floor, e.g. `fwc --host <endpoint> status --require-source mesh-or-host
  --json` (runbook, `--require-source` section).
- **A guarantee about the future.** Policy, budget, or connector state can
  change between simulate and invoke; re-check denied paths with
  `fwc status` / `fwc schema` as the payload's own `next_actions` suggest.
- **Connector-level dry-run semantics** unless the operation advertises them:
  check `operation.supports_simulate` in the payload and the
  `SimulateCapability` contract (`crates/fwc/src/catalog.rs`). A
  `PreflightOnly` connector gives you validation + policy, not a side-effect
  model.

### Correlation to audit history entries

- Every allowed simulate (and every allowed `fwc preflight`, which shares the
  convention — `preflight_dispatch`, `crates/fwc/src/main.rs`) appends a
  `HistoryEntry` with `status: "simulated"` (`OpStatus::Simulated`,
  `crates/fwc/src/history.rs`); denied preflights record `status: "denied"`.
- Entries carry `entry_id`, `timestamp`, `connector_id`, `operation_id`,
  optional `zone`, hashed `input_hash` / `output_hash` (never raw payloads),
  `latency_ms: 0`, and the `idempotency_key` when one was supplied — use
  these fields to correlate a simulate decision with a later real invoke of
  the same operation.
- `fwc history --status simulated` filters to these entries (status filter
  parsing: `parse_status`, `crates/fwc/src/history.rs`).
- `fwc undo <entry_id>` on a simulated entry reports "read-only or denied
  operation. Nothing to undo." — the undo path treats `simulated` and
  `denied` as `is_read_only` with `safety_level: "none"` (undo dispatch,
  `crates/fwc/src/main.rs`; covered by the
  `undo_simulated_operation_reports_nothing_to_undo` test).
- Capability-usage analytics (`aggregate_capability_usage`,
  `crates/fwc/src/main.rs`) deliberately **skip** simulated entries and
  report the count as `skipped_simulated`, so dry runs never inflate usage or
  error statistics.

### Recommended safety-sensitive flow (from the runbook)

1. `fwc simulate <connector> <operation> --host <endpoint> --input '{...}'`
   to inspect planned behavior and policy outcome.
2. Prove the live source with a read-only command plus
   `--require-source mesh-or-host --json` before relying on live state.
3. Never cite a `status: "simulated"` history entry as evidence of execution.

## 6. References

- `crates/fwc/src/main.rs` — `Commands::Simulate`, `invoke_dispatch`,
  `invoke_dispatch_host` (`if command == "simulate"` block),
  `invoke_dispatch_without_host`, `preflight_dispatch`, undo dispatch,
  `aggregate_capability_usage`, `inject_truth_source_metadata`,
  `truth_source_unavailable_dispatch`, `InvokeArgs`.
- `crates/fwc/src/truth.rs` — `KnowledgeState`, `RequiredTruthSource`
  (`accepts`, `is_live`), `TRUTH_SOURCE_SCHEMA_VERSION`,
  `LiveTruthResolver::resolve_with_partials`.
- `crates/fwc/src/catalog.rs` — `COMMAND_CLASSIFICATIONS` (`"simulate"`
  entry), `CommandExecutionMode::Simulate`, `SimulateCapability`.
- `crates/fwc/src/history.rs` — `OpStatus::Simulated`, `HistoryEntry`,
  `parse_status`.
- `docs/runbooks/fwc_truth_source_classification.md` — runtime contract,
  `--require-source` floors, `Simulate` section.
- Commit `cd6bfe99b` — canonical hr0rr.2.5 resolver routing pattern
  (`fwc list` through `LiveTruthResolver::resolve_with_partials`).
