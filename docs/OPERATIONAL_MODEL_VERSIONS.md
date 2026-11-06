# Operational Model Versions

> This document defines the two operational model versions for FCP, what each
> provides, and which fwc commands require which version. V1 is the legacy
> host-first rollback/evaluation boundary; V2 is the current operational
> truth-precedence default. The truth hierarchy classifies answers as
> mesh-backed > host-backed > node-local > offline under V2 by default, while
> individual commands may still execute through host-backed provisioning until
> mesh-routed execution has production evidence.
>
> This is a cutover-audit reference, not the preferred onboarding story. Use it
> to see which operator workflows still depend on the transitional host-backed
> boundary and which ones already have a mesh-backed destination.

## V1: Host-First (Legacy Rollback / Evaluation Boundary)

V1 is the legacy host-first provisioning boundary. It remains available for
explicit rollback and compatibility testing through
`FCP_TRUTH_PRECEDENCE_DEFAULT=v1`, but it is no longer the default
truth-precedence policy.

### What V1 Provides

| Capability | Status | Evidence |
|------------|--------|----------|
| `fwc -> fcp-host -> connector subprocesses` | Proven | CLI integration tests, host admin API, stdio/JSON-RPC supervision |
| Host-backed runtime answers | Proven | `crates/fwc/src/truth.rs` KnowledgeState taxonomy |
| Node-local truth resolution | Proven | `crates/fwc/src/catalog.rs` runtime mode dispatch |
| Offline artifact mode (explicit) | Proven | `--offline` flag, artifact-backed discovery |
| Single-active-host deployment | Proven | One `fcp-host` instance per node |
| Zone isolation (cryptographic) | Proven | Zone encryption keys, Tailscale ACL enforcement |
| Capability tokens (CWT/COSE) | Proven | CBOR-encoded, COSE-signed, revocation-checked |
| Tamper-evident audit chain | Proven | Hash-linked events, monotonic seq, quorum checkpoints |
| Revocation enforcement | Implemented | First-class revocation objects, O(1) freshness checks |
| Egress proxy with CIDR deny | Implemented | Manifest-aware network guardrails |
| Secretless connector flows | Implemented | `credential_id` host-side injection |
| Supply chain attestations | Implemented | Registry attestation schemas, verification policy |

### What V1 Does NOT Provide

- Automatic multi-node placement or failover
- Mesh-backed answers (answers backed by distributed mesh state)
- Cross-device symbol reconstruction
- Automatic computation migration between devices
- Mesh-native gossip-based state sync as the primary truth source

### V1 Operator Contract

Treat this as the minimum honest contract for the boundary that still exists
today, not as the architecture contributors should optimize around long term.

1. Start `fcp-host` on the node where connectors will run.
2. Use `fwc --host http://<host>:<port>` for all live operations.
3. Trust host-backed answers as authoritative for current runtime state.
4. Use `--offline` explicitly when you want artifact-backed data.
5. Do not assume mesh-native features are available.

### Deployment Admission

Truth precedence does not establish execution authority. A host classified as
`Evaluation` admits only `Safe` operations through its deployment gate. `Risky`,
`Dangerous`, and `Critical` operations return `TIER_REQUIRES_MESH_ACTIVE` with the
underlying reason, such as insufficient healthy peers, an unreachable lease
coordinator, stale revocation evidence, or rejected signal signatures.
`Forbidden` operations are refused in every deployment mode.

`Critical` has no evaluation exemption: an omitted approval declaration,
`ApprovalMode::None`, or an approval token cannot establish a healthy mesh.
Passing deployment admission in `MeshActive` also does not satisfy the separate
policy, approval, quorum, or elevation requirements of an operation.

The current `fcp-host` binary remains in `Evaluation` until live mesh health,
lease-coordinator, and revocation-freshness signals are integrated into its
deployment classifier. Configuring peers or selecting V2 truth precedence does
not promote it. A deployment refusal must be resolved with verified runtime
evidence rather than by relabeling an operation or disabling approval metadata.

---

## V2: Mesh-Native Truth Precedence (Operational Default, Hybrid Execution)

V2 is operational for truth precedence and answer classification. In
`crates/fwc/src/truth.rs`, `TruthPrecedencePolicy::default()` returns
`TruthPrecedencePolicy::v2_default()` unless the explicit
`FCP_TRUTH_PRECEDENCE_DEFAULT=v1` rollback override is set. The V2 source
ordering is `MeshBacked > HostBacked > NodeLocal > Offline`, with fallback
allowed by policy.

This does not mean every command is already mesh-routed. Execution remains
hybrid: commands classify answers under the V2 policy today, but many live
operations still materialize through the host-backed provisioning path until
the scorecard cutover gates are satisfied.

### What V2 Provides Today

| Capability | Current Status | Notes |
|------------|---------------|-------|
| V2 truth precedence default | Operational | `TruthPrecedencePolicy::default()` resolves to `V2MeshNative` unless `FCP_TRUTH_PRECEDENCE_DEFAULT=v1` is set |
| Mesh-backed answers (highest confidence) | Operational when mesh evidence exists | `LiveTruthResolver` classifies mesh-backed answers highest and falls back under policy |
| Host-backed fallback under V2 | Operational | V2 keeps `HostBacked` below `MeshBacked` and above `NodeLocal` / `Offline` |
| Multi-node device mesh (Tailscale peers) | Implemented, cutover-gated | MeshNode, gossip, IBLT, XOR filters exist; production default routing still depends on scorecard gates |
| Symbol-first object distribution | Implemented | RaptorQ codec, object-symbol framing, repair machinery in-tree |
| Automatic computation migration | Designed | Migration state machines exist, not operational default |
| Cross-device secret reconstruction | Implemented | Shamir sharing + FROST threshold signing exist |
| Mesh-native gossip sync | Implemented, cutover-gated | Gossip protocol with consistency checks exists; not yet the only production state source |
| Automatic failover / placement | Designed | ObjectPlacementPolicy and RepairController exist |
| Offline resilience via symbol locality | Designed | Probabilistic availability model, not yet E2E proven |

### V2 Cutover Gates

The transition from V2 truth-precedence default to fully mesh-routed execution
requires completing these gates:

1. Production evidence that mesh-backed answers are correct and consistent.
2. Zone-wide TruthPrecedencePolicy enforcement beyond the current `fwc` policy surface (all operators in a zone see the same answer).
3. Proven multi-node placement and failover for at least one real workload.
4. Mesh-native gossip as the default state sync mechanism (not just available, but default).
5. Operator documentation that teaches V2 as the primary path (this document is part of that rewrite).

The FCP3 Transition Scorecard (`docs/FCP3_Transition_Scorecard.md`) tracks
progress toward these gates. Gate 5 is addressed by the current teaching-surface
rewrite (bead z1nkz.1).

---

## FWC Command Truth-Source Matrix

Every `fwc` command is classified under the V2 truth hierarchy by default
(mesh-backed > host-backed > node-local > offline). The table below is a
cutover map: it shows which commands still depend on host-backed execution,
which ones are already honest offline artifact workflows, and where mesh-backed
execution is expected to replace the transitional path.

| Command | V1 (Host-First) | V2 (Mesh-Native) | Notes |
|---------|-----------------|-------------------|-------|
| **Discovery** | | | |
| `list` | Host-backed or offline | Will add mesh-backed source | Hybrid: `--offline` for artifact mode |
| `search` | Host-backed or offline | Will add mesh-backed source | Hybrid |
| `show` | Host-backed or offline | Will add mesh-backed source | Hybrid |
| `ops` | Host-backed or offline | Will add mesh-backed source | Hybrid |
| `schema` | Host-backed or offline | Will add mesh-backed source | Hybrid |
| `examples` | Host-backed or offline | Will add mesh-backed source | Hybrid |
| `zones` | Host-backed | Will show mesh zone topology | V1 shows host-known zones |
| **Lifecycle** | | | |
| `doctor` | Host-backed | Will add mesh health checks | V1 checks host + connector health |
| `status` | Host-backed | Will add mesh placement status | V1 shows host-supervised state |
| `health` | Host-backed | Will aggregate mesh-wide health | V1 shows node-local health |
| `install` | Host-local install | Will add mesh-coordinated install | V1 installs on current host only |
| `update` | Host-local update | Will add mesh-coordinated rollout | |
| `pin` | Host-local pin | Will pin across mesh | |
| `rollout` | Host-local rollout | Will coordinate across nodes | |
| **Execution** | | | |
| `invoke` | Host-backed (requires `--host`) | Mesh-routed execution | V1 requires live host |
| `simulate` | Host-backed (requires `--host`) | Mesh-routed simulation | V1 requires live host |
| `preflight` | Host-backed | Mesh-aware preflight | |
| `cancel` | Host-backed | Mesh-routed cancellation | |
| **Workflow** | | | |
| `task` | Offline artifact | Unchanged | Local intent compilation |
| `plan` | Offline artifact | Unchanged | Local intent compilation |
| `explain` | Offline artifact | Unchanged | Local intent compilation |
| `do` | Host-backed (materializes via host) | Mesh-routed materialization | Safe by default (simulation mode) |
| **Composition** | | | |
| `pipeline` | Host-backed | Mesh-routed pipeline | |
| `recipe` | Host-backed | Mesh-routed recipe | |
| `map` | Host-backed | Mesh-parallel map | |
| `batch-file` | Host-backed | Mesh-parallel batch | |
| **History** | | | |
| `history` | Offline artifact (local audit trail) | Will merge mesh-wide audit | |
| `replay` | Offline artifact | Unchanged | |
| `compare` | Offline artifact | Unchanged | |
| `undo` | Host-backed (reversal via host) | Mesh-routed reversal | |
| `approvals` | Host-backed | Mesh-coordinated approvals | |
| **Auth** | | | |
| `auth` | Host-local credential management | Mesh-distributed credentials | |
| `config` | Host-local configuration | Mesh-synced configuration | |
| **Export** | | | |
| `export-tools` | Offline artifact | Unchanged | |
| `serve-mcp` | Host-backed MCP server | Mesh-backed MCP server | |
| **Evidence** | | | |
| `supply-chain` | Host-local verification | Mesh-wide attestation | |
| `audit` | Host-local audit trail | Mesh-wide audit aggregation | |
| `manifest` | Offline artifact | Unchanged | |
| `net` | Host-backed | Mesh-wide network view | |
| `trace` | Host-backed | Mesh-wide trace correlation | |
| `policy` | Host-backed | Mesh-synced policy | |
| **Truth** | | | |
| `mesh explain-availability` | Shows V1 truth source classification | Will show mesh placement evidence | Already classifies answers by source |

---

## How to Check Your Current Version

```bash
# The answer classification tells you what version you're operating under.
# V2 truth precedence is the default. If an answer reports "host-backed" or
# "node-local", that answer fell back under V2 policy. If it reports
# "mesh-backed", that answer has the highest-confidence V2 evidence.
fwc --host http://127.0.0.1:8787 mesh explain-availability <connector>
```

---

## References

- [README.md](../README.md) — project overview with truth hierarchy framing
- [FWC_Host_First_Truthfulness_Playbook.md](FWC_Host_First_Truthfulness_Playbook.md) — operator guide (transitional, converging toward mesh-native)
- [FCP3_Transition_Scorecard.md](FCP3_Transition_Scorecard.md) — V2 cutover gate progress
- `crates/fwc/src/truth.rs` — KnowledgeState taxonomy and LiveTruthResolver (mesh-backed resolution)
- `crates/fwc/src/catalog.rs` — command source classification and runtime mode dispatch
