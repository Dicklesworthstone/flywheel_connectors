# Proof Readiness Runbook

> Bead: `flywheel_connectors-qeg89.5`

Use this runbook when Beads or BV points at blocked live-evidence work and the
next useful action is to request, collect, or attach the missing proof artifact.

Proof readiness is a prerequisite check. It says whether the repository already
contains fresh, redaction-safe artifacts for a configured live-proof target. It
does not execute the proof command, does not prove the originating bead, and
does not make a blocked bead safe to close.

## Triage Entry Point

Start with robot-mode Beads/BV output:

```bash
bv --robot-next
bv --robot-triage
br show <bead-id> --json
```

If the recommended bead is a blocked live-evidence lane, run the readiness
report before attempting local fixes:

```bash
fwc proof readiness --json --only-missing
```

For one known target:

```bash
fwc proof readiness --json --target <target-id>
```

The target inventory is `docs/proof/evidence_targets.toml`. The default
`--repo-root .` resolves artifact roots and globs relative to the repository.
Use `--manifest <path>` only for a reviewed alternate target manifest.

## Status Meanings

| Status | Meaning | Agent action |
|--------|---------|--------------|
| `ready` | Every configured artifact, machine class, host role, schema, freshness window, and threshold is satisfied for the selected target. | Use the actual proof lane or handoff command for the originating bead; do not close the bead from readiness alone. |
| `missing-prerequisites` | No usable artifact satisfies the target. The report lists missing globs, machine classes, host roles, fields, thresholds, or freshness. | Generate a proof request bundle and ask the operator or remote lane owner for the exact missing artifact. |
| `partially-ready` | At least one usable artifact exists, but coverage is incomplete. | Request only the missing classes, roles, or threshold evidence; preserve the satisfied artifact paths in the bead comment. |
| `error` | The target manifest or selected target could not be evaluated. | Fix the manifest or target selection first. Do not reinterpret an error as a blocker reason. |

Read the target-level `missing`, `satisfied_artifacts`, `command`,
`redaction_notes`, and `next_actions` fields. A `command.argv_template` is a
template for the external proof run; `fwc proof readiness` only reports it.

## Request Missing Evidence

Generate a redaction-safe request bundle for every non-ready target:

```bash
fwc proof request --json
```

For one target:

```bash
fwc proof request --json --target <target-id>
```

The bundle includes structured JSON plus a Markdown request body. It is designed
for Agent Mail and Beads comments after the agent reviews it. The renderer
rejects raw endpoints, private IP literals, credential-shaped text, and
user-local paths. Keep that boundary intact:

- Use role names, machine classes, stable hashes, and repo-relative artifact
  paths.
- Do not include hostnames, endpoint URLs, credential headers, cookies,
  passwords, tokens, user-home paths, or raw provider payloads.
- Keep command placeholders such as `<redacted host list>` until the operator
  runs the proof in the private environment.

Send only the relevant request section to the operator or lane owner. If using
Agent Mail, keep the thread id equal to the Beads id and do not run Agent Mail
service repair or restart commands.

## After Evidence Arrives

When an operator or remote proof lane provides an artifact:

1. Check that the artifact path is repo-relative and under the target's
   configured artifact root.
2. Confirm the artifact JSON uses the target's `artifact_schema`.
3. Confirm required fields, machine class, host role coverage, threshold fields,
   and freshness window are satisfied.
4. Re-run:

```bash
fwc proof readiness --json --target <target-id>
```

5. Add a Beads comment to the originating blocked bead with the redaction-safe
   artifact path, digest, machine class or host roles, readiness status, and the
   follow-up proof command.

Example comment shape:

```text
proof_readiness:{target:"<target-id>",status:"ready",artifact:"artifacts/<class>/<file>.json",digest:"blake3:<digest>",next:"run accepted proof lane"}
```

If the target is still `missing-prerequisites` or `partially-ready`, keep the
bead blocked and include the remaining `missing` entries. If the target is
`ready`, run the actual proof lane or `fwc proof handoff` flow required by the
originating bead. Readiness evidence is not acceptance evidence.

## Known Initial Targets

The initial configured targets map to these blocked proof lanes:

| Target family | Blocking bead | Evidence required |
|---------------|---------------|-------------------|
| PQ signing StatPack | `flywheel_connectors-angoc.8.3` | Fresh `csd`, `contabo`, and `laptop` machine-class StatPack artifacts for hybrid verify overhead. |
| Mesh cutover gates | `flywheel_connectors-hr0rr.2.1` | Three-host cutover telemetry with redacted host roles and green gate records. |
| Multi-machine failover | `flywheel_connectors-hr0rr.2.4` | Production multi-machine failover gauntlet artifact, not only local replay evidence. |
| BLAKE3 dispatch | `flywheel_connectors-angoc.14.2` | AVX-512 and aarch64 throughput artifacts proving the measured backend. |
| ChaCha20-Poly1305 dispatch | `flywheel_connectors-angoc.14.3` | AVX2 and SSE3 throughput artifacts proving the accelerated backend path. |

## Verification

For documentation-only edits to this runbook:

```bash
git diff --check -- docs/runbooks/proof_readiness.md
```

For changes that affect the proof-readiness CLI or target manifest, use the
focused remote lanes:

```bash
rch exec -- cargo test -p fwc --test proof_readiness_report -- --nocapture
rch exec -- cargo test -p fwc --test proof_request_bundle -- --nocapture
```

Do not count local fallback, readiness output, request bundles, or skipped live
harnesses as proof acceptance. A blocked bead only becomes closable after the
bead's own acceptance proof or handoff records accepted remote proof evidence.
