# FWC Truth-Source Classification Runbook

> Bead: `flywheel_connectors-hr0rr.2.5`

Use this runbook when an operator or agent needs to know whether a read-only
`fwc` answer came from live mesh state, a host-admin endpoint, node-local
configuration, or offline workspace artifacts.

## Runtime Contract

Read-only `fwc --json` commands that participate in the A.5 truth-source
surface include a top-level `schema_version` and `_truth_source` field. The
shared envelope schema is `fcp.fwc.truth-source.v1` unless the command owns a
more specific payload schema, such as audit-chain status or audit verify.

The current schema files are fail-closed contracts for the ratcheted command
surfaces. They pin truth-source metadata, command identity where the runtime
emits it, typed `truth-source-unavailable` and
`truth-resolver-internal-error` error shapes, and command-specific success
bodies for the proven runtime surfaces. Nested objects can still allow provider
or deployment-specific keys when the runtime intentionally exposes variable
metadata, but unknown top-level success fields are rejected.

| Schema file | Command surface | Success schema version | Notes |
|-------------|-----------------|------------------------|-------|
| `list.schema.json` | `fwc list` | `fcp.fwc.truth-source.v1` | Requires `command: "list"`. |
| `show.schema.json` | `fwc show` | `fcp.fwc.truth-source.v1` | Requires `command: "show"`. |
| `schema.schema.json` | `fwc schema` | `fcp.fwc.truth-source.v1` | Requires `command: "schema"`. |
| `search.schema.json` | `fwc search` | `fcp.fwc.truth-source.v1` | Requires `command: "search"`. |
| `status.schema.json` | `fwc status` | `fcp.fwc.truth-source.v1` | Requires `command: "status"`. |
| `doctor.schema.json` | `fwc doctor` | `fcp.fwc.truth-source.v1` | Requires `command: "doctor"`. |
| `context_current.schema.json` | `fwc context current` | `fcp.fwc.truth-source.v1` | Requires `command: "context"` and `subcommand: "current"`. |
| `history.schema.json` | `fwc history` | `fcp.fwc.truth-source.v1` | Requires `command: "history"`. |
| `audit_chain_status.schema.json` | `fwc audit chain status` | `fcp.fwc.audit_chain_status.v1` | Requires `command: "audit"` and `subcommand: "chain status"` on the success path; `truth-source-unavailable` errors use the shared schema version. |
| `audit_verify.schema.json` | `fwc audit verify` | `fcp.fwc.audit_verify.v1` | Success output is the serialized audit report plus `_truth_source`; `truth-source-unavailable` errors use the shared schema version and carry `command: "audit"` plus `subcommand: "verify"`. |
| `mesh_explain_availability.schema.json` | `fwc mesh explain-availability` | `fcp.fwc.truth-source.v1` | Requires `command: "mesh"` and `subcommand: "explain-availability"`; live placement-policy answers report `_truth_source: "mesh"` and weaker artifact-only answers report the resolver's lower-confidence source. |
| `connector_lease_status.schema.json` | `fwc connector lease status` | `1.0.0` | Requires `command: "connector"` and `subcommand: "lease status"`; live host lease evidence reports `_truth_source: "host"` while offline HRW ladder projections report `_truth_source: "offline"`. |

The operator-facing `_truth_source` tags are:

| Tag | Meaning | Typical commands |
|-----|---------|------------------|
| `mesh` | Mesh-backed distributed truth. This is the intended highest-confidence answer once mesh-native cutover is complete. | Future mesh-backed resolver paths and live placement-policy answers for `fwc mesh explain-availability`. |
| `host` | Live host-admin truth from a reachable `fcp-host` endpoint. | `fwc list`, `show`, `schema`, `search`, `status`, live `doctor`, and live connector lease status paths when a host endpoint is configured. |
| `node-local` | Local CLI configuration rather than host or mesh state. | `fwc context current`, `fwc context list`. |
| `offline` | Workspace manifests, local history, local doctor probes, local audit-chain artifacts, or persisted mesh context. | `fwc list --offline`, `show --offline`, `schema --offline`, `search --offline`, `history`, local `doctor`, `audit chain status`, `audit verify`, offline mesh availability, and offline connector lease projections. |
| `degraded` | Resolver output produced under a degraded internal state. Treat as lower-confidence than live host truth. | Reserved for resolver surfaces. |
| `fallback-derived` | Inferred fallback output rather than direct runtime truth. Treat as advisory. | Reserved for resolver fallback surfaces. |
| `unavailable` | The resolver itself failed and could not provide an authoritative answer. | `truth-resolver-internal-error` JSON surfaces with a redacted cause and correlation id. |

Do not infer liveness from command success alone. A successful command with
`_truth_source: "offline"` is useful for inspection, but it is not proof that
the live connector runtime currently has the same state.

## `--require-source`

Use `--require-source` when a workflow must fail closed instead of silently
accepting weaker truth. Supported levels are:

| Requirement | Accepted `_truth_source` values | Rejected examples |
|-------------|---------------------------------|-------------------|
| `mesh` | `mesh` only | `host`, `node-local`, `offline` |
| `mesh-or-host` | `mesh`, `host` | `node-local`, `offline` |
| `any-live` | `mesh`, `host` | `node-local`, `offline` |

When the actual answer does not satisfy the requested floor, JSON output uses:

```json
{
  "status": "error",
  "command": "search",
  "schema_version": "fcp.fwc.truth-source.v1",
  "_truth_source": "offline",
  "error": {
    "type": "truth-source-unavailable",
    "required": "any-live",
    "actual": "offline",
    "recoverable": true
  }
}
```

For production safety, prefer:

```bash
fwc --host <endpoint> list --require-source mesh-or-host --json
fwc --host <endpoint> status --require-source mesh-or-host --json
fwc --host <endpoint> doctor --require-source mesh-or-host --json
```

Use `--require-source mesh` only after the mesh-backed resolver path is known to
be available. In a host-backed deployment, `--require-source mesh` is expected
to fail with `truth-source-unavailable` and `actual: "host"`.

## Command Notes

| Command | Current truth behavior |
|---------|------------------------|
| `fwc list` | Host-backed with `--host` or configured host context; offline with `--offline`; missing host resolves as an offline/unavailable surface. |
| `fwc show <connector>` | Host-backed with live introspection; offline with workspace manifests; connector-resolution failures are also stamped with the resolved source. |
| `fwc schema <connector> [operation]` | Host-backed with live schemas; offline with manifest schemas; operation-resolution failures are stamped offline when using offline artifacts. |
| `fwc search <query>` | Host-backed with live introspection; offline with workspace manifests; missing-host details include the requested source floor. |
| `fwc status [connector]` | Host-backed with a reachable host; missing-host is stamped offline. |
| `fwc doctor` | Host-backed for live host diagnostics; offline for local checks, probes, and self-tests. |
| `fwc context current/list` | Node-local; this reads the active CLI context and does not prove host or mesh liveness. |
| `fwc history` | Offline; history reads the local CLI history store. |
| `fwc audit chain status` | Offline audit-chain artifact truth with `schema_version: "fcp.fwc.audit_chain_status.v1"`. |
| `fwc audit verify` | Offline audit verification truth with `schema_version: "fcp.fwc.audit_verify.v1"`. |
| `fwc mesh explain-availability` | Mesh-backed when placement-policy state is live; lower-confidence answers explain the fallback source, branch, and evidence handles. |
| `fwc connector lease status` | Host-backed when live lease evidence is available; offline answers are HRW ladder projections from persisted mesh context and do not prove live quorum state. |

Mutation commands and side-effecting audit commands are not covered by this
read-only truth-source contract. Keep mutation routing on its command-specific
host or policy path.

## Downgrade Triage

1. Re-run with JSON output and inspect `_truth_source`, `schema_version`,
   `error.type`, `error.required`, and `error.actual`.
2. If the source is `offline`, decide whether offline artifacts are sufficient
   for the task. They are acceptable for local discovery, not for live runtime
   assertions.
3. If the source is `node-local`, treat the answer as CLI configuration only.
   It does not prove a host is reachable.
4. If a live answer is required, add `--host <endpoint>` or restore the active
   context, then use `--require-source mesh-or-host` or `--require-source
   any-live`.
5. If `--require-source mesh` fails with `actual: "host"`, use
   `fwc mesh explain-availability --json` and the mesh cutover-gates runbook to
   investigate why mesh-backed truth is unavailable.

## Text Output

Default TOON output appends an answer-source footer when a truth-source stamped
response is lower confidence than mesh-backed truth:

```text
(answer source: offline)
```

JSON, JSONL, NDJSON, tabular, template, and extract output remain structured and
do not include the text footer. Use `--json` whenever automation needs to read
`schema_version`, `_truth_source`, `error.required`, or `error.actual`
directly.

## Simulate

`fwc simulate` is not the same thing as a read-only truth-source answer. It
uses the invoke-style dry-run path and history can record entries with
`status: "simulated"`, but that status means no live connector mutation was
performed. Since hr0rr.2.5, simulate output carries the top-level
`_truth_source: "simulated"` JSON marker so downstream consumers can treat it
as non-authoritative; the marker is dispatch-time metadata, not an evidence
class in the resolver ladder (see
docs/architecture/truth_resolver_simulate.md).

For safety-sensitive workflows:

1. Use `fwc simulate` to inspect planned behavior and policy outcomes.
2. Use a read-only command with `--require-source mesh-or-host --json` to prove
   the current runtime source before relying on live state.
3. Do not treat a simulated history entry as evidence that the operation ran.

## Verification

Focused proof lanes for this surface should stay narrow:

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-fwc-truth-source CARGO_INCREMENTAL=0 \
  cargo test -p fwc --bin fwc required_truth_source -- --nocapture

rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-fwc-truth-source CARGO_INCREMENTAL=0 \
  cargo test -p fwc --bin fwc truth_source -- --nocapture

rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-fwc-truth-source CARGO_INCREMENTAL=0 \
  cargo test -p fwc --bin fwc require_any_live -- --nocapture

rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-fwc-truth-source CARGO_INCREMENTAL=0 \
  cargo test -p fwc --bin fwc truth_source_footer -- --nocapture

rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-fwc-truth-source CARGO_INCREMENTAL=0 \
  cargo test -p fwc --test audit_chain_status_shape -- --nocapture

rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-fwc-command-schemas CARGO_INCREMENTAL=0 \
  cargo test -p fcp-conformance --test fwc_command_schemas -- --nocapture
```

Run `git diff --check -- docs/runbooks/fwc_truth_source_classification.md` for
documentation-only updates.

## Redaction

Truth-source logs and examples must not include connector credentials, bearer
tokens, OAuth codes, private keys, provider response bodies, raw host endpoints
from private deployments, or principal private data. Hash sensitive identifiers
with a `_hash` suffix before placing them in artifacts.
