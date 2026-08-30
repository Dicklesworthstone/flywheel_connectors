# Flywheel Connector Protocol (FCP)

<div align="center">
  <img src="fcp_illustration.webp" alt="FCP - Secure connectors for AI agents with zone-based isolation and capability tokens">
</div>

> **Specification note:** [`FCP_Specification_V3.md`](FCP_Specification_V3.md) is the current architectural and conformance target. [`FCP_Specification_V2.md`](FCP_Specification_V2.md) is retained as historical / legacy-interoperability context. When descriptions conflict, trust V3 for intended semantics and the code for current behavior.

A secure connector protocol and Rust platform for AI agent operations across zones, hosts, and personal device meshes. The workspace ships **42 platform crates** under `crates/`, **177 connector crates** under `connectors/` (176 production connectors plus one adversarial conformance test crate, `connectors/_adversarial/`), and a single agent-first CLI (`fwc`) that classifies every answer by truth source and refuses to fabricate runtime state.

---

## TL;DR

### The Problem

AI agents need to act on the real world (read mail, file PRs, send messages, query databases, control hardware), but the prevailing toolchains do this with a shared-memory plugin model, an "API key in a `.env` file" trust model, and a "prompt told the model not to do that" security model. None of those survive a hostile input from Discord, a compromised laptop, or a misconfigured deploy.

### The Solution

FCP is a connector platform where:

- Every connector is a **separately-signed sandboxed binary** with an embedded manifest declaring its capabilities, sandbox limits, and network constraints.
- Every operation is gated by a **capability token** with type-state-enforced binding, so an `UnboundVerified` token does not compile against a function that requires `BoundVerified`.
- Every request is **bound to exactly one zone** (a cryptographic namespace with its own symmetric key); cross-zone access requires explicit policy and proof.
- Every connector's outbound network traffic flows through an **egress proxy** with CIDR deny defaults, SNI enforcement, and **secretless credential injection**, so the connector binary never sees raw API keys.
- Every operation produces a **signed receipt** and is recorded on a **hash-linked audit chain** with monotonic sequence numbers and Hybrid Logical Clock causality, plus an OpenTelemetry OTLP parity exporter.
- Sensitive zones support **post-quantum cryptography** (X-Wing KEM hybrid HPKE + ML-DSA-65 signatures) and **threshold owner keys** (FROST) so no single device holds the complete signing material.

### Truth Hierarchy

`fwc` classifies every answer by its source (**mesh-backed > host-backed > node-local > offline**) rather than collapsing everything into a single fake "live" state.

- **Current operational path (V1, host-first):** `fwc → fcp-host → connector subprocesses over supervised stdio/JSON-RPC`. This is what runs in production today.
- **Target steady state (V2, mesh-native):** personal-device sovereignty, mesh durability, capability-gated execution across your own infrastructure. The mesh infrastructure (gossip, IBLT, XOR filters, symbol-first object distribution, LiveTruthResolver, KnowledgeState taxonomy) is built and tested; the cutover gates are documented in [`docs/FCP3_Transition_Scorecard.md`](docs/FCP3_Transition_Scorecard.md).

### Three Foundational Axioms

| Axiom | Principle |
|-------|-----------|
| **Universal Fungibility** | All durable mesh objects are symbol-addressable: any K' RaptorQ symbols reconstruct the canonical object bytes. Control-plane messages may travel over FCPC streams, but the canonical representation is a content-addressed mesh object. |
| **Authenticated Mesh** | Tailscale is the transport AND the identity layer. Every node has unforgeable WireGuard keys. Zones map to Tailscale ACL tags. |
| **Explicit Authority** | No ambient authority. All capabilities flow from the owner key through cryptographic chains and short-lived, instance-bound capability tokens. |

### Why Use FCP?

Status legend:
- `PROVEN`: backed by direct repository evidence (tests, harnesses, golden vectors).
- `LIMITED`: functional at the stated scope but narrower than the mature target (e.g. threshold-gated rather than adaptive).
- `STEADY-STATE TARGET`: architectural target with built infrastructure but not yet operational by default.

`PROVEN` means repository evidence, not a claim of live production deployment.

| Feature | Status | What It Does | Evidence |
|---------|--------|--------------|----------|
| **Host-First Control Plane** | `PROVEN` | `fwc` + `fcp-host` is the proven provisioning boundary. Operators use this path today while mesh-backed truth converges to steady state. | `crates/fcp-host/src/{supervisor,enforcement,health}.rs`, `crates/fcp-conformance/tests/host_invoke_loop_conformance.rs`, `crates/fcp-e2e/tests/capability_enforcement_concurrent_e2e.rs` |
| **Truthful Runtime Resolution** | `PROVEN` | `fwc` resolves runtime mode explicitly and classifies answers as mesh-backed, host-backed, node-local, or offline instead of fabricating "live". | `crates/fwc/src/{truth,catalog,readiness}.rs`, `crates/fwc/tests/{cual_integration,readme_status_pinning}.rs` |
| **Capability Token Typestate** | `PROVEN` | `CapabilityToken<Unverified → UnboundVerified → BoundVerified → ConstraintsEnforced>` is compiler-enforced across every connector boundary. `LEGACY_VERIFY_ALLOWLIST.len() == 0`; forward-only ratchet enforced by conformance test. | `crates/fcp-conformance/tests/capability_typestate_connector_boundary_dja9u.rs`, `crates/fcp-core/tests/typestate_compile_fail.rs` |
| **Capability Tokens (CWT/COSE)** | `PROVEN` | COSE/CWT signing, canonical CBOR, constraints, instance binding, predicate matrix all covered. | `crates/fcp-crypto/src/cose.rs`, `crates/fcp-core/src/capability.rs`, `crates/fcp-host/tests/capability_token_typestate_runtime.rs` |
| **Post-Quantum Zone Keys** | `PROVEN` | `ZoneKeyManifest V4` schema with hybrid HPKE-X25519 + X-Wing KEM wrap lists, RustCrypto X-Wing (draft-06) + IETF KAT, ML-DSA-65 FIPS 204 signatures with KAT, hybrid verifier, length-invariant `Deserialize`, constant-time `Eq`. | `crates/fcp-crypto-pq/`, `crates/fcp-core/src/zone_keys.rs`, mixed V3/V4 mesh migration harness |
| **Zone Isolation** | `LIMITED` | Core cryptographic namespaces proven; Lean zone-flow lattice proof source pinned; host-side connector RPC requires explicit `allowed_zones` before invoke/introspect/health. | `crates/fcp-core/src/{zone_keys,pcs,policy}.rs`, `lean/Fcp/Zone/Lattice.lean`, `crates/fcp-host/tests/allowed_zones_required.rs`, `crates/fcp-e2e/tests/zone_isolation_full_e2e.rs` |
| **Tamper-Evident Audit + HLC** | `PROVEN` | Hash-linked audit chain with monotonic sequence numbers, quorum-signed checkpoints, Hybrid Logical Clocks, Hierarchical Version Vectors for revocation freshness, and an OTLP parity exporter. | `crates/fcp-audit/src/hlc.rs`, `crates/fcp-mesh/src/revocation/hier_vv.rs`, `crates/fcp-conformance/tests/{hlc_hiervv_conformance,audit_otlp_hlc_contract}.rs` |
| **Revocation** | `PROVEN` | First-class revocation objects, exact-membership lookup (no XOR filter in the revocation path), `RevocationSeal` for check-use atomicity, priority gossip push, zone-wide freshness SLA. | `crates/fcp-core/src/revocation.rs`, `crates/fcp-conformance/tests/revocation_timing.rs`, `crates/fcp-e2e/tests/revocation_cascade_e2e.rs` |
| **Egress Proxy** | `PROVEN` | Connector network access routed through manifest-aware guardrails with CIDR deny defaults and denial audit evidence. | `crates/fcp-sandbox/src/egress.rs`, `crates/fcp-e2e/tests/egress_proxy_e2e.rs` |
| **Secretless Connectors** | `PROVEN` | Egress proxy injects credentials per request through `SecretFetchHook`; connector binaries pass `credential_id` references rather than raw bearer material. PROVEN covers the GitHub, Slack, and Gmail connector families; it does not claim every connector has migrated. | `crates/fcp-crypto/src/secret_fetch.rs`, `crates/fcp-e2e/tests/secretless_{github,slack,gmail}_e2e.rs` |
| **Multi-Method Provider Auth** | `PROVEN` | `fcp-provider-auth` consolidates API key, AWS SigV4 request signing, JWT refresh, OAuth device-code, authorization-code with PKCE, refresh-token, and setup-token; `AuthProfile` flows through the credential pool layer. | `crates/fcp-provider-auth/`, host/fwc profile-admin and OAuth login surfaces |
| **Credential Pooling** | `PROVEN` | Multi-credential per-provider pools with priority, strategy, exhaustion-cooldown, active-lease tracking, LRU, sticky restick, max-use, and a redaction-safe connector-boundary E2E. | `crates/fcp-host/src/credentials.rs`, `crates/fcp-e2e/tests/credential_pool_e2e.rs`, host admin API routes, audit log |
| **Multi-Host Singleton Writers (HRW)** | `PROVEN` | Quorum-signed durable leases gossip across nodes; rendezvous hashing picks the holder deterministically; binary launch/flush/invoke fencing prevents split-writer windows; multi-node failover replay harness lands as closeout. | `crates/fcp-core/src/lease.rs`, `crates/fcp-mesh/src/{authority,coordinator,planner}.rs`, multi-node failover replay harness |
| **Threshold Owner Key** | `PROVEN` | FROST ceremony and signing support exist in `fcp-bootstrap`; not yet the universal operational default. | `crates/fcp-bootstrap/src/ceremony.rs`, `crates/fcp-e2e/tests/threshold_owner_key_e2e.rs` |
| **Threshold Secrets (Shamir)** | `PROVEN` | Shamir secret sharing for device-distributed recovery so raw secret material never lives on one machine. | `crates/fcp-core/src/secret.rs`, `crates/fcp-e2e/tests/threshold_secrets_e2e.rs` |
| **Supply Chain Attestations** | `PROVEN` | Registry-side attestation schemas, TUF/cosign verification adapters, host gate proof. Release-distribution proof remains outside this repo. | `crates/fcp-registry/src/lib.rs`, `crates/fcp-e2e/tests/supply_chain_attestation_e2e.rs` |
| **Offline Access** | `PROVEN` | `ObjectPlacementPolicy` (`fcp-core`), repair controllers (`fcp-store/src/repair.rs`), cache-while-offline (`fcp-store/src/offline.rs`); queued writes and drain-on-restore are proven through the connector-side E2E harness pattern. | `crates/fcp-store/src/offline.rs`, `crates/fcp-e2e/tests/{offline_access,offline_repair}_e2e.rs` |
| **Mesh-Stored Policy Objects** | `PROVEN` | Zone definitions and policy bundles exist as owner-signed objects with mesh gossip, verification, evaluation, and revocation proof. | `crates/fcp-core/src/policy.rs`, `crates/fcp-e2e/tests/mesh_policy_object_e2e.rs` |
| **Symbol-First Protocol** | `PROVEN` | RaptorQ object-symbol framing, reconstruction, repair machinery, multipath aggregation, offline resilience. | `crates/fcp-raptorq/`, `crates/fcp-e2e/tests/symbol_first_protocol_e2e.rs`, golden vectors |
| **Browser Real-CDP Control Plane** | `PROVEN` | Rust-owned CDP control-worker, supervised target/session manager, cookie ownership boundary, native launcher/proxy worker, direct-CDP routing, real-browser operation-matrix closeout — mirrors OpenClaw semantics. | `connectors/browser/`, host browser CDP manager proof |
| **Voice-Call Multi-Provider Parity** | `PROVEN` | Shared `CallAuthToken`, `SessionStore`, replay-cache crate (`fcp-voice-call`); Twilio, Telnyx, Plivo all flow through the same architectural shape with no-live-credential loopback evidence. | `crates/fcp-voice-call/`, `connectors/{twilio,telnyx,plivo}/`, `scripts/e2e/voice_call_multi_provider_verification.sh` |
| **Manifest Operations Conformance** | `PROVEN` | Every connector with declared operations exposes them via typed `[provides.operations.*]` in `manifest.toml`; runtime const drift is caught by a conformance scanner. | `crates/fcp-conformance/tests/manifest_operations_*.rs` |
| **Computation Migration** | `PROVEN` | Migrate-and-resume reference proof: CRIU-format checkpoint handoff, lease transfer, replay, byte-equivalent completion. | `crates/fcp-kernel/src/computation_migration.rs`, `crates/fcp-e2e/tests/computation_migration_reference.rs` |
| **Mesh-Native Architecture** | `STEADY-STATE TARGET (NOT YET OPERATIONAL)` | Gossip, IBLT, XOR filters, masked IBLT anti-entropy, and LiveTruthResolver are built and tested. The production `fwc → fcp-host → connector subprocess` invoke path remains host-first today. Pinned by `crates/fwc/tests/readme_status_pinning.rs`. | `crates/fcp-mesh/`, `crates/fwc/src/truth.rs` |

> **Audit status**: all status labels reconciled as of 2026-08-29 (see the Q3 report for the current reconciliation). The Mesh-Native downgrade rationale is tracked in `br-lvz4t`. See [`docs/quarterly/2026-Q2-claims-vs-reality.md`](docs/quarterly/2026-Q2-claims-vs-reality.md) for the inaugural quarterly debiasing report and [`docs/quarterly/2026-Q3-claims-vs-reality.md`](docs/quarterly/2026-Q3-claims-vs-reality.md) for the current quarter.

---

## Design Philosophy

Five principles drive every architectural decision in FCP.

### 1. Mechanical Enforcement, Not Prompted Compliance

Security is enforced by the type system, the binary boundary, the protocol, or cryptography. Never by a string in a prompt. Telling a model "don't read private email" is trivially bypassed by a hostile message; telling a Rust compiler that `gmail.read` does not exist in the `z:public` zone is not. Examples from the codebase:

- **Capability-token typestate.** `CapabilityToken<UnboundVerified>` and `CapabilityToken<BoundVerified>` are distinct types. An operation executor that requires full instance-binding declares `fn execute(_: CapabilityToken<BoundVerified>, ...)`. An `UnboundVerified` token (produced by the gateway, which does not yet know the connector's real `InstanceId`) does not compile against that signature. Enforced by `trybuild` tests in `crates/fcp-core/tests/typestate_compile_fail.rs`.
- **Connector-boundary ratchet.** `crates/fcp-conformance/tests/capability_typestate_connector_boundary_dja9u.rs` checks `LEGACY_VERIFY_ALLOWLIST.len() == 0`. New connectors must use the typestate path; enforced connectors cannot regress.
- **Sealed `FcpConnector` trait.** Third-party crates cannot accidentally subvert the lifecycle by implementing the trait themselves.

### 2. Default Deny With Explicit Allow

If a capability is not granted, it cannot be invoked. If a zone is not bound, the host refuses to start the subprocess. If `allowed_zones` is empty, connector RPC fails closed before invoke, introspection, or health probes reach connector code. If `cidr_deny` is malformed, the sandbox rejects the manifest at runtime rather than silently degrading. If a webhook signing secret is empty or shorter than the threshold, the webhook layer refuses to verify. At every boundary, absence of explicit configuration is treated as denial, never as a permissive default.

### 3. Truthfulness Over Convenience

`fwc` classifies every answer by its source rather than collapsing runtime state into a fake "live" answer. If the host is unreachable and the operator did not pass `--offline`, `fwc` refuses rather than falling back to stale artifact data silently. Offline answers carry provenance markers and stale-data caveats. Placeholder runtime data, guessed `simulate` support, and local file-edit side channels are bugs, not convenience features.

This is the same reason every operator run produces a replayable evidence bundle (`trace.jsonl`, `summary.json`, `environment.json`, `replay.sh`): debugging starts from artifacts the system actually wrote, not from a story the operator reconstructed afterwards.

### 4. Symbol-First Data Model

Durable data is content-addressed and symbol-distributed. Any K' RaptorQ symbols reconstruct the canonical object bytes. There is no "primary copy"; there is only a placement policy and a repair controller that maintains it. This eliminates retransmit coordination, enables multipath aggregation, and turns offline resilience from "did I cache this file" into "do I have K' of the N symbols this object is encoded into."

### 5. Audit Everything That Has Side Effects

Every operation with external effects produces a signed receipt. Every receipt is appended to a hash-linked audit chain with monotonic sequence numbers and Hybrid Logical Clock attributes. Audit heads are quorum-signed across nodes. Receipts are the primary deduplication primitive: on retry with the same idempotency key, the mesh returns the prior receipt instead of re-executing. The OpenTelemetry OTLP parity exporter re-emits the audit chain as traces/metrics/logs, so external observability systems get the same causal model.

---

## Quick Example

```bash
# Install fwc
cargo build -p fwc --bin fwc --release
cp target/release/fwc ~/.local/bin/

# Start fcp-host in another terminal
./target/release/fcp-host

# Talk to the host (current provisioning path, V1)
fwc --host http://127.0.0.1:8787 list
fwc --host http://127.0.0.1:8787 show github
fwc --host http://127.0.0.1:8787 status github
fwc --host http://127.0.0.1:8787 simulate github issues.create --file payload.json
fwc --host http://127.0.0.1:8787 invoke   github issues.create --file payload.json

# See which truth source backs the answer
fwc --host http://127.0.0.1:8787 mesh explain-availability github

# Offline mode: artifact-backed data without a running host
fwc list --offline
fwc search "send message" --offline
fwc show github --offline
fwc ops github --offline
fwc schema github issues.create --offline

# Compile a natural-language intent into a concrete plan, then materialize it safely
fwc plan "search my Gmail for invoices from last week"
fwc explain
fwc do --approve

# Expose connectors to MCP clients
fwc serve-mcp --host http://127.0.0.1:8787 github slack gmail

# Audit + history
fwc history --connector github --limit 20
fwc audit tail --zone z:work
fwc supply-chain verify github
```

---

## Architecture

### Current Operator Path (V1, Host-First)

This is the provisioning boundary that runs in production today.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          OPERATOR PATH (V1)                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   Operator / AI Agent                                                       │
│       │                                                                     │
│       ▼                                                                     │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │  fwc (CLI)                                                          │  │
│   │  --host http://127.0.0.1:8787                                       │  │
│   │  Classifies answers: host-backed | node-local | offline             │  │
│   └────────────────────────────┬────────────────────────────────────────┘  │
│                                │  HTTP Admin API                            │
│                                ▼                                            │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │  fcp-host (Supervisor)                                              │  │
│   │  1. Verify capability token (COSE)         8. Append audit + HLC    │  │
│   │  2. Check token expiry (CWT nbf/exp)       9. Emit OTLP span        │  │
│   │  3. Check revocation (O(1) freshness)     10. Issue HRW lease       │  │
│   │  4. Enforce zone policy (allowed_zones)   11. Credential pool lease │  │
│   │  5. Check rate limits (token bucket)      12. Receipt for retries   │  │
│   │  6. Connector lifecycle / health           13. Rollout / canary     │  │
│   │  7. Sandbox configuration                  14. Drift detection      │  │
│   └────────────────────────────┬────────────────────────────────────────┘  │
│                                │  stdio / JSON-RPC                          │
│                                ▼                                            │
│   ┌─────────────┐     ┌─────────────┐     ┌─────────────┐                  │
│   │  Connector  │     │  Connector  │     │  Connector  │                  │
│   │   Gmail     │     │   GitHub    │     │   Slack     │                  │
│   │ (sandboxed) │     │ (sandboxed) │     │ (sandboxed) │                  │
│   └──────┬──────┘     └──────┬──────┘     └──────┬──────┘                  │
│          │                   │                   │                          │
│          │ Egress proxy: CIDR deny + SNI + SPKI + credential injection      │
│          ▼                   ▼                   ▼                          │
│     Gmail API          GitHub API           Slack API                       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Target Steady State (V2, Mesh-Native)

This is the intended steady-state architecture: every device is a peer in a personal mesh, with symbol-based data distribution and mesh-backed answers as the highest-confidence truth source. The mesh infrastructure is built and tested; the remaining work is production evidence and cutover gating.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          PERSONAL MESH (V2)                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌──────────┐      ┌──────────┐      ┌──────────┐                         │
│   │ Desktop  │◄────►│  Laptop  │◄────►│  Phone   │  ← Tailscale mesh      │
│   │ MeshNode │      │ MeshNode │      │ MeshNode │                         │
│   └────┬─────┘      └────┬─────┘      └────┬─────┘                         │
│        │                 │                 │                                │
│        ▼                 ▼                 ▼                                │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │              SYMBOL DISTRIBUTION (RaptorQ K-of-N)                   │  │
│   │  Object: gmail-inbox-2026-05      K=100 symbols                     │  │
│   │  Desktop: [1,5,12,23,...]  Laptop: [2,8,15,...]  Phone: [3,9,...]   │  │
│   │  Any 100 symbols → full reconstruction; no symbol is "important"    │  │
│   └─────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │  Gossip + IBLT + XOR-filter set reconciliation                      │  │
│   │  HLC + HierVV for causality and revocation freshness                │  │
│   │  HRW (rendezvous hashing) elects singleton writers                  │  │
│   │  Threshold owner key (FROST) and threshold secrets (Shamir)         │  │
│   │  Post-quantum zone keys (X-Wing KEM + ML-DSA-65, ZoneKeyManifest V4)│  │
│   └─────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Core Concepts

### Terminology

| Term | Definition |
|------|------------|
| **Symbol** | A RaptorQ-encoded fragment; any K' symbols reconstruct the original |
| **Object** | Content-addressed data with `ObjectHeader` (refs, retention, provenance) |
| **Zone** | A cryptographic namespace with its own symmetric encryption key |
| **Epoch** | A logical time unit; no ordering within, ordering between |
| **MeshNode** | A device participating in the FCP mesh |
| **Capability** | An authorized operation with cryptographic proof; `grant_object_ids` enable mechanical verification |
| **Role** | Named bundle of capabilities (`RoleObject`) for simplified policy administration |
| **ResourceObject** | Zone-bound handle for external resources (files, repos, APIs) |
| **Resource Visibility** | ResourceObjects carry public/private classification; the host enforces declassification when writing higher-confidentiality data to lower-confidentiality external resources |
| **Connector** | A sandboxed binary that bridges an external service to FCP |
| **Receipt** | Signed proof of operation execution for idempotency |
| **Revocation** | First-class object that invalidates tokens, keys, or devices |
| **Lease** | HRW-elected, quorum-signed authority to act as singleton writer for a connector instance |
| **HLC / HierVV** | Hybrid Logical Clock / Hierarchical Version Vector for audit causality |

### Cryptographic Key Hierarchy

FCP uses a structured key hierarchy to prevent cross-purpose key reuse. The hybrid classical + post-quantum stack lives in `fcp-crypto` (classical primitives plus the production X-Wing KEM and ML-DSA-65 implementations) and `fcp-crypto-pq` (lattice-trapdoor delegation research surface).

```
Owner Key (Ed25519, threshold via FROST)
    │
    ├── sign NodeKeyAttestation     (binds node_id → signing/encryption/issuance keys)
    ├── sign ZoneKeyManifest V3/V4  (distributes zone symmetric keys via HPKE-X25519
    │                                and X-Wing KEM hybrid wrap)
    ├── sign DeviceEnrollment       (admits new nodes)
    └── sign RevocationObject       (invalidates any of the above)

Per-Node Keys:
    Node Signing Key     (Ed25519)   → signs frames, gossip, receipts, audit heads
    Node Encryption Key  (X25519)    → receives HPKE-sealed zone keys
    Node Issuance Key    (Ed25519)   → mints capability tokens (separately revocable)
    Optional: Node ML-DSA-65 Key     → post-quantum signing (hybrid alongside Ed25519)

Per-Zone Keys:
    Zone Encryption Key (ChaCha20-Poly1305)
        │
        ├── HKDF("FCP3-ZONE-KEY" ‖ zone_id) → zone subkey
        ├── HKDF(zone_key ‖ sender_instance_id) → per-sender subkey (reboot-safe)
        └── Per-symbol nonce: frame_seq ‖ ESI (deterministic, no coordination)

Per-Session Keys (from X25519 ECDH, optional X-Wing KEM hybrid):
    Shared secret → HKDF with both nonces
        ├── k_mac_i2r  (initiator → responder MAC key)
        ├── k_mac_r2i  (responder → initiator MAC key)
        └── k_ctx      (control-plane AEAD key)
```

Five distinct cryptographic roles:

| Key | Algorithm | Purpose |
|-----|-----------|---------|
| **Owner Key** | Ed25519 (FROST-thresholded) | Root trust; signs attestations, manifests, revocations |
| **Node Signing Key** | Ed25519 | Per-device; signs frames, gossip, receipts |
| **Node Encryption Key** | X25519 (+ optional X-Wing KEM) | Per-device; receives sealed zone keys and secret shares |
| **Node Issuance Key** | Ed25519 | Per-device; mints capability tokens (separately revocable) |
| **Zone Encryption Key** | ChaCha20-Poly1305 | Per-zone symmetric key; AEAD for zone data |

Each node has a `NodeKeyAttestation` signed by the owner, binding the Tailscale node ID to all three node key types plus their Key IDs (KIDs) for rotation. Issuance keys are separately revocable so token minting can be disabled without affecting other functions.

### Security Invariants

These invariants are enforced mechanically:

1. **Single-Zone Binding.** A connector instance binds to exactly one zone for its lifetime.
2. **Default Deny** — if a capability is not explicitly granted to a zone, it cannot be invoked. The host now refuses to start a connector subprocess with an empty `allowed_zones` set.
3. **No Cross-Connector Calling** — connectors do not call each other; all composition flows through the host.
4. **Threshold Secret Distribution** — secrets use Shamir's Secret Sharing; never complete on any single device.
5. **Revocation Enforcement** — tokens, keys, and operations check revocation before use. Revocation is wired into all 14 stages of the enforcement pipeline (Gemini Lane 3 closed the gap where freshness was checked but `is_revoked()` was not consulted).
6. **Auditable Everything** — every operation produces a signed receipt and a hash-linked audit event with HLC + HierVV.
7. **Cryptographic Authority Chain** — all authority flows from the owner key through verifiable signature chains.

---

## Zone Architecture

Zones are **cryptographic boundaries**, not labels. Each zone has its own randomly generated symmetric key, distributed to eligible nodes via owner-signed `ZoneKeyManifest` (V3 = HPKE-X25519, V4 = hybrid HPKE-X25519 + X-Wing KEM).

```
z:owner        [Trust: 100]   Direct owner control, most privileged
    │                         Tailscale tag: tag:fcp-owner
    ▼
z:private      [Trust: 80]    Personal data, high sensitivity
    │                         Tailscale tag: tag:fcp-private
    ▼
z:work         [Trust: 60]    Professional context, medium sensitivity
    │                         Tailscale tag: tag:fcp-work
    ▼
z:community    [Trust: 40]    Trusted external (paired users)
    │                         Tailscale tag: tag:fcp-community
    ▼
z:public       [Trust: 20]    Public/anonymous inputs
                              Tailscale tag: tag:fcp-public

INVARIANTS:
  Integrity:        Data flows DOWN freely. UP requires ApprovalToken (elevation).
  Confidentiality:  Data flows UP freely. DOWN requires ApprovalToken (declassification).
```

### Provenance and Taint

Every piece of data carries provenance:

| Field | Purpose |
|-------|---------|
| `origin_zone` | Where data originated |
| `current_zone` | Updated on every zone crossing |
| `integrity_label` | Numeric integrity level (higher = more trusted source) |
| `confidentiality_label` | Numeric confidentiality level (higher = more sensitive) |
| `label_adjustments` | Proof-carrying label changes (elevation/declassification) with `ApprovalToken` references |
| `taint` | Compositional flags (`PUBLIC_INPUT`, `EXTERNAL_INPUT`, `PROMPT_SURFACE`, …) |
| `taint_reductions` | Proof-carrying reductions via `SanitizerReceipt` references |

**Merge rule:** combining data from multiple sources yields `MIN(integrity)` and `MAX(confidentiality)`. Compromised inputs cannot elevate trust; sensitive outputs cannot be inadvertently exposed.

**Taint reduction:** specific taints can be cleared when you have a verifiable `SanitizerReceipt` from a sanitizer capability (URL scanner, malware scanner, schema validator). The receipt is a first-class mesh object.

### Defense-in-Depth

```
Layer 1: Tailscale ACLs       → Network-level isolation
Layer 2: Zone Encryption      → Cryptographic isolation (per-zone symmetric keys)
Layer 3: Policy Objects       → Authority isolation (owner-signed mesh objects)
Layer 4: Capability Signing   → Operation isolation (node-signed COSE/CWT tokens)
Layer 5: Revocation Check     → Continuous validity enforcement (HLC-fresh check)
```

---

## Symbol Layer (RaptorQ)

All durable data in FCP is symbol-addressable. RaptorQ (RFC 6330) generates a stream of fungible symbols where **any K' symbols reconstruct the original**. This eliminates retransmit coordination, enables multipath aggregation, and provides natural offline resilience.

| Property | Benefit |
|----------|---------|
| **Fungibility** | Any K' symbols reconstruct; no coordination needed |
| **Multipath** | Aggregate bandwidth across all network paths |
| **Resumable** | No bookkeeping; just collect more symbols |
| **DoS Resistant** | Attackers cannot target "important" symbols |
| **Offline Resilient** | Partial availability = partial reconstruction |
| **Key Rotation Safe** | `zone_key_id` in each symbol enables seamless rotation |
| **Chunked Objects** | Large payloads split via `ChunkedObjectManifest` for partial retrieval and targeted repair |

### Frame Format (FCPS)

```
┌──────────────────────────────────────────────────────────────────────────┐
│                    FCPS FRAME FORMAT (Symbol-Native)                      │
├──────────────────────────────────────────────────────────────────────────┤
│  Bytes 0-3:     Magic (0x46 0x43 0x50 0x53 = "FCPS")                     │
│  Bytes 4-5:     Version (u16 LE)                                          │
│  Bytes 6-7:     Flags (u16 LE)                                            │
│  Bytes 8-11:    Symbol Count (u32 LE)                                     │
│  Bytes 12-15:   Total Payload Length (u32 LE)                             │
│  Bytes 16-47:   Object ID (32 bytes)                                      │
│  Bytes 48-49:   Symbol Size (u16 LE, default 1024)                        │
│  Bytes 50-57:   Zone Key ID (8 bytes, for rotation)                       │
│  Bytes 58-89:   Zone ID hash (32 bytes, BLAKE3; fixed-size)               │
│  Bytes 90-97:   Epoch ID (u64 LE)                                         │
│  Bytes 98-105:  Sender Instance ID (u64 LE, reboot-safety)                │
│  Bytes 106-113: Frame Seq (u64 LE, per-sender monotonic counter)          │
│  Bytes 114+:    Symbol payloads (encrypted, concatenated)                 │
│                                                                           │
│  Fixed header: 114 bytes                                                  │
│  Integrity: per-symbol AEAD tags + per-frame session MAC                  │
│  Per-symbol nonce: derived as frame_seq || esi_le (deterministic)         │
└──────────────────────────────────────────────────────────────────────────┘
```

### Session Authentication

High-throughput symbol delivery uses per-session authentication, not per-frame signatures:

1. **Handshake:** X25519 ECDH authenticated by attested node signing keys, with per-party nonces for replay protection and crypto-suite negotiation. Optional X-Wing KEM hybrid for post-quantum forward secrecy.
2. **Session keys:** HKDF-derived directional MAC keys (`k_mac_i2r`, `k_mac_r2i`) from ECDH shared secret, bound to the selected suite and both handshake nonces.
3. **Per-sender subkeys:** Each sender derives a unique subkey via HKDF including `sender_instance_id`, eliminating cross-sender and cross-reboot nonce collision.
4. **Per-frame MAC:** HMAC-SHA256 or BLAKE3 (negotiated) with per-sender monotonic `frame_seq` for anti-replay.

**Responder-picks suite negotiation:** the initiator proposes supported suites; the responder selects from its preference list with a `MINIMUM_SUITE` floor. See [`docs/protocol/session-handshake.md`](docs/protocol/session-handshake.md).

**Session rekey triggers:** sessions automatically rekey after configurable thresholds: frames (default 1B), elapsed time (default 24h), or cumulative bytes (default 1 TiB).

### Control Plane Framing (FCPC)

FCPS handles high-throughput symbol delivery. FCPC provides reliable, ordered, backpressured framing for control-plane objects (invoke, response, receipts, approvals, audit events). FCPC uses the session's negotiated `k_ctx` symmetric key for AEAD without per-message Ed25519 signatures.

---

## Mesh Architecture

In the target architecture every device is a MeshNode. Today the proven operator path is host-first; the mesh layer below is built and tested but not yet the operational default.

### MeshNode Components

```
┌──────────────────────────────────────────────────────────────────────────┐
│                                MESHNODE                                  │
├──────────────────────────────────────────────────────────────────────────┤
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  Tailscale Identity                                                │  │
│  │  - Stable node ID (unforgeable WireGuard keys)                     │  │
│  │  - Signing/encryption/issuance keys with owner attestation         │  │
│  │  - ACL tags for zone mapping                                       │  │
│  │  - Optional PostureAttestation (TPM / Secure Enclave)              │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  Symbol Store                                                      │  │
│  │  - Local symbol storage with retention classes                     │  │
│  │  - Quarantine store for unreferenced objects (bounded)             │  │
│  │  - XOR filters + IBLT + masked-IBLT anti-entropy for gossip        │  │
│  │  - Reachability-based garbage collection                           │  │
│  │  - ObjectPlacementPolicy enforcement for availability SLOs         │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  Capability + Revocation Registry                                  │  │
│  │  - Zone keyrings (deterministic key selection by zone_key_id)      │  │
│  │  - Trust anchors (owner key, attested node keys)                   │  │
│  │  - Monotonic seq numbers for O(1) freshness                        │  │
│  │  - ZoneCheckpoint checkpoints for fast sync                        │  │
│  │  - RevocationPushMessage for priority gossip                       │  │
│  │  - HLC + HierVV freshness frontier (angoc.17.3)                    │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  Connector State Manager                                           │  │
│  │  - Externalized connector state as mesh objects                    │  │
│  │  - Single-writer semantics via HRW + quorum-signed leases          │  │
│  │  - Fencing tokens prevent split-writer windows                     │  │
│  │  - Multi-writer CRDT support (LWW-Map, OR-Set, counters)           │  │
│  │  - Safe failover and migration for stateful connectors             │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  Execution Planner                                                 │  │
│  │  - Device profiles (CPU, GPU, memory, battery)                     │  │
│  │  - Connector availability and version requirements                 │  │
│  │  - Secret reconstruction cost estimation                           │  │
│  │  - Symbol locality scoring, DERP penalty                           │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  Repair Controller                                                 │  │
│  │  - Background symbol coverage evaluation                           │  │
│  │  - Automatic repair toward ObjectPlacementPolicy targets           │  │
│  │  - Rebalancing after device churn or offline periods               │  │
│  │  - Power-aware deferral (battery threshold)                        │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  Egress Proxy                                                      │  │
│  │  - Connector network access via capability-gated IPC               │  │
│  │  - CIDR deny defaults (localhost, private, tailnet ranges)         │  │
│  │  - SNI enforcement, SPKI pinning                                   │  │
│  │  - Secretless credential injection (SecretFetchHook)               │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  Audit Chain                                                       │  │
│  │  - Hash-linked audit events per zone with monotonic seq            │  │
│  │  - Hybrid Logical Clock attributes                                 │  │
│  │  - Quorum-signed audit heads for tamper evidence                   │  │
│  │  - Operation receipts for idempotency                              │  │
│  │  - OpenTelemetry OTLP parity exporter (traces, metrics, logs)      │  │
│  └────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
```

### Transport Priority

```
Priority 1: Tailscale Direct (same LAN)
Priority 2: Tailscale Mesh (NAT traversal)
Priority 3: Tailscale DERP Relay         (policy-controlled per zone)
Priority 4: Tailscale Funnel (public)    (low-trust zones only by default)
```

Zones configure transport policy via `ZoneTransportPolicy` to control DERP/Funnel availability.

### Device Enrollment

New devices join the mesh through owner-signed enrollment:

1. Device joins the Tailscale tailnet.
2. Owner issues a `DeviceEnrollment` object (signed).
3. Owner issues a `NodeKeyAttestation` binding the node to signing/encryption/issuance keys; sensitive zones may require a `PostureAttestation` (TPM, Secure Enclave, Android Keystore).
4. Device receives enrollment via mesh gossip.
5. Other nodes accept the new device as peer.

Device removal triggers revocation + zone key rotation + secret resharing.

### Multi-Host Authority (HRW Leases)

Connectors declaring `singleton_writer = true` use **execution leases** to guarantee only one node writes state at a time. Leases are coordinated via **rendezvous hashing (HRW)** to deterministically select a coordinator from online nodes, with **quorum signatures** for distributed issuance.

| Property | Behavior |
|----------|----------|
| **Holder selection** | HRW score over `(node_id, connector_id, epoch)` — deterministic, no election round |
| **Quorum** | Lease issuance requires N-of-M owner-attested signers; duplicate / unknown / quorum-deficient signers rejected at construction and on gossip ingress |
| **Fencing** | Binary launch / flush / invoke fencing prevents split-writer windows during reseat |
| **Durability** | Leases gossip as durable mesh objects; stale-lease detection, malformed-lease status invalidation, sequence-drift flagging |
| **Failover** | Multi-node failover replay harness with redaction-safe artifacts provides the closeout proof |

This prevents double-polling and cursor conflicts while surviving coordinator failures.

---

## Connector Binary Structure

Every FCP connector is a single executable with embedded metadata:

```
┌──────────────────────────────────────────────────────────────┐
│                          FCP BINARY                          │
├──────────────────────────────────────────────────────────────┤
│  ┌────────────────────────────────────────────────────────┐  │
│  │  MANIFEST SECTION                                      │  │
│  │  ┌─────────────────┐  ┌─────────────────┐              │  │
│  │  │  Metadata       │  │  Capabilities   │              │  │
│  │  │  - Name         │  │  - Required     │              │  │
│  │  │  - Version      │  │  - Optional     │              │  │
│  │  │  - Author       │  │  - Forbidden    │              │  │
│  │  └─────────────────┘  └─────────────────┘              │  │
│  │  ┌─────────────────┐  ┌─────────────────┐              │  │
│  │  │  Zone Policy    │  │  Sandbox Config │              │  │
│  │  │  - Home zone    │  │  - Memory limit │              │  │
│  │  │  - Allowed      │  │  - CPU limit    │              │  │
│  │  │  - Forbidden    │  │  - FS access    │              │  │
│  │  │  - Tailscale tag│  │  - deny_exec    │              │  │
│  │  └─────────────────┘  └─────────────────┘              │  │
│  │  ┌─────────────────────────────────────────────────┐   │  │
│  │  │  [provides.operations.*]                         │   │  │
│  │  │  Typed input/output schemas per operation        │   │  │
│  │  │  Network constraints per operation               │   │  │
│  │  │  Risk / safety / idempotency classification      │   │  │
│  │  │  AI hints for agent-readable operation docs      │   │  │
│  │  └─────────────────────────────────────────────────┘   │  │
│  └────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  CODE SECTION                                          │  │
│  │  - FCP protocol implementation                         │  │
│  │  - Capability negotiation                              │  │
│  │  - External API client                                 │  │
│  │  - State management                                    │  │
│  └────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  SIGNATURE SECTION                                     │  │
│  │  - Ed25519 signature over manifest + code              │  │
│  │  - Reproducible build attestation                      │  │
│  │  - Registry provenance chain                           │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

### Sandbox Enforcement

Connectors support two sandbox models:

- **Native (ELF / Mach-O / PE):** OS-level sandboxes — seccomp + Landlock (Linux), seatbelt (macOS), AppContainer (Windows, Tier 2).
- **WASI (WebAssembly):** WASM-based isolation with capability-gated hostcalls. Recommended for high-risk connectors (financial, credential-handling) due to memory isolation and cross-platform consistency.

| Constraint | Purpose |
|------------|---------|
| Memory limit | Prevent resource exhaustion |
| CPU limit | Prevent runaway computation |
| Wall-clock timeout | Bound operation duration |
| FS readonly paths | Limit filesystem access |
| FS writable paths | Explicit state directory |
| `deny_exec` | Prevent child process spawning |
| `deny_ptrace` | Prevent debugging/tracing |
| `NetworkConstraints` | Explicit host/port/TLS requirements |

### Connector State

Connectors with polling cursors, dedup caches, or other long-lived state externalize their canonical state into the mesh:

```
ConnectorStateRoot {
  connector_id     → Which connector
  zone_id          → Which zone
  head             → Latest ConnectorStateObject
}

ConnectorStateObject {
  prev             → Hash link to previous state
  seq              → Monotonic sequence
  state_cbor       → Canonical connector-specific state
  signature        → Node signature
}
```

Local `$CONNECTOR_STATE` is a cache only. The authoritative state lives as mesh objects, enabling:

- **Safe failover:** another node can resume from last committed state.
- **Resumable polling:** cursors survive node restarts and migrations.
- **Deterministic migration:** state is explicit, not implicit in process memory.

**Periodic snapshots:** connectors emit `ConnectorStateSnapshot` objects at configurable intervals, enabling compaction of the state chain while preserving fork detection for `singleton_writer` connectors.

### Agent API Caching

`fcp-host` exposes cache metadata on agent-facing discovery surfaces so clients can avoid refetching unchanged metadata:

- `GET /rpc/discover`
- `GET /rpc/introspect/{connector_id}`

Responses carry `ETag`, `Last-Modified`, `Cache-Control`, and `Vary`. Clients can revalidate with `If-None-Match` / `If-Modified-Since` headers or the JSON-RPC `_cache` object. When the cached view is still valid, the host returns the normal JSON body with `meta.status = 304` and refreshed cache metadata, keeping the agent API JSON-RPC-friendly.

---

## Security Model

### Threat Model

FCP defends against:

| Threat | Mitigation |
|--------|------------|
| Compromised device | Threshold owner key (FROST), threshold secrets (Shamir), revocation, zone key rotation |
| Malicious connector binary | Ed25519 signature verification, OS sandboxing, supply chain attestations (in-toto / SLSA) |
| Compromised external service | Zone isolation, capability limits, manifest-declared network constraints |
| SSRF / localhost attacks | Egress proxy with CIDR deny defaults (localhost, private, tailnet ranges) |
| Prompt injection via messages | Protocol-level filtering, taint tracking with proof-carrying reductions, MCP-bridge description scanning |
| Privilege escalation | Static capability allocation, no runtime grants, unified `ApprovalToken` for elevation/declassification |
| Replay attacks | Session MACs with monotonic seq, epoch binding, receipts |
| DoS / resource exhaustion | Admission control with `PeerBudget`, anti-amplification rules, per-peer rate limiting |
| Key compromise | Revocation objects with monotonic seq for O(1) freshness, key rotation with `zone_key_id` |
| Supply chain attacks | in-toto attestations, SLSA provenance, reproducible builds, transparency log, mesh mirroring |
| Quantum-capable adversary | Hybrid HPKE-X25519 + X-Wing KEM for zone keys; ML-DSA-65 for post-quantum signatures |
| Side-channel timing | Constant-time comparison on PQ secret types (`subtle::ConstantTimeEq`); HMAC verify via `mac.verify_slice()` |
| Length-bypass on transparent byte envelopes | Custom length-invariant `Deserialize` with proptest fuzz |

### Threshold Secrets

Secrets use **Shamir's Secret Sharing** (not RaptorQ symbols, which can leak structure):

```
Secret: API_KEY
Scheme: Shamir over GF(2^8), k=3, n=5

Distribution:
  Desktop: share_1 (wrapped for Desktop's public key)
  Laptop:  share_2 (wrapped for Laptop's public key)
  Phone:   share_3 (wrapped for Phone's public key)
  Tablet:  share_4 (wrapped for Tablet's public key)
  Server:  share_5 (wrapped for Server's public key)

To use:
  1. Obtain SecretAccessToken (signed by approver)
  2. Collect any 3 wrapped shares
  3. Unwrap and reconstruct using Shamir
  4. Use in memory only
  5. Zeroize immediately after use
  6. Log audit event

No single device ever has the complete secret.
A node cannot decrypt other nodes' shares.
```

### Operation Receipts

Operations with side effects produce signed receipts:

```
OperationReceipt {
  request_object_id    → What was requested
  idempotency_key      → For deduplication
  outcome_object_ids   → What was produced
  executed_at          → When
  executed_by          → Which node
  signature            → Node's signing key
}
```

On retry with the same idempotency key, the mesh returns the prior receipt instead of re-executing.

**OperationIntent pre-commit:** for Strict or Risky operations, callers first write an `OperationIntent` object containing the idempotency key, then invoke. Executors check that the intent exists, preventing accidental re-execution during retries. This provides exactly-once semantics for operations with external side effects.

### Revocation

First-class revocation objects can invalidate:

| Scope | Effect |
|-------|--------|
| Capability | Token becomes invalid |
| IssuerKey | Node can no longer mint tokens |
| NodeAttestation | Device removed from mesh |
| ZoneKey | Forces key rotation |
| ConnectorBinary | Supply chain incident response |

Revocations are owner-signed and enforced before every operation. Revocation lookup is wired into all 14 stages of the host enforcement pipeline.

**Freshness policy:**
- **Strict** — requires fresh revocation check or abort (default for Risky/Dangerous operations).
- **Warn** — log warning but proceed if cached revocation list is within `max_age`.
- **BestEffort** — use stale cache if offline, log degraded state.

### The 14-Stage Enforcement Pipeline

Every `invoke` request flows through a deterministic 14-stage pipeline in `crates/fcp-host/src/enforcement.rs`. Each stage either passes the request to the next stage or produces a structured denial. The conformance test `crates/fcp-conformance/tests/no_permissive_empty_zone_branch.rs` enforces the contract that no stage is skipped on the basis of an empty input.

| # | Stage | Failure Mode |
|---|-------|--------------|
| 1 | **Capability token COSE verify** | Reject malformed or wrong-key signatures before parsing claims |
| 2 | **CWT temporal bounds** | Reject expired (`exp`) or not-yet-valid (`nbf`) tokens |
| 3 | **Typestate binding check** | `UnboundVerified` → `BoundVerified` promotion against the live `InstanceId` |
| 4 | **Revocation lookup** | Exact-membership `is_revoked()` against the registry; HLC + HierVV freshness gate |
| 5 | **Zone binding** | Token's `zone_id` must match the connector instance's `allowed_zones`; empty `allowed_zones` is a hard refusal |
| 6 | **Capability constraints** | Predicate matrix: schema, value-range, host-allowlist, redaction policy |
| 7 | **Provenance & taint flow** | Merge rule (`MIN(integrity)`, `MAX(confidentiality)`); approval/sanitizer receipts as needed |
| 8 | **HRW lease check** | For `singleton_writer` connectors, verify the local node holds the current quorum-signed lease |
| 9 | **Rate-limit gate** | Per-pool token bucket / sliding-window / leaky-bucket |
| 10 | **Admission budget** | `PeerBudget` + anti-amplification (response ≤ N × request) |
| 11 | **Credential pool lease** | Lease a credential from the pool; honor strategy, priority, exhaustion-cooldown |
| 12 | **Audit + HLC** | Append a hash-linked audit event with HLC timestamp and HierVV; emit OTLP span |
| 13 | **Sandbox setup** | Apply network constraints, FS allowlist, memory/CPU limits, `deny_exec`, `deny_ptrace` |
| 14 | **Dispatch to connector subprocess** | Send the invoke envelope over the supervised JSON-RPC channel |

A returned `OperationReceipt` walks back up the pipeline, releasing the credential lease, recording the receipt for idempotency, and closing the OTLP span.

The table above is the conceptual pipeline. The fourteen checks implemented in `crates/fcp-host/src/enforcement.rs` are named `canonical_decode`, `zone_membership`, `capability_verify`, `revocation_cascade`, `deployment_tier`, `holder_proof`, `checkpoint_freshness`, `revocation_freshness`, `taint_approval`, `policy_ceiling`, `capability_constraints`, `connector_manifest`, `budget`, and `rate_limit` (registered in order via `fcp_prelude::EnforcementCheckOrder` and pinned by `host_enforcement_pipeline_outcome_conformance.rs`). The remaining conceptual stages live in the surrounding modules: COSE signature verification, CWT temporal bounds, and the typestate ladder execute inside `fcp-core`'s `CapabilityVerifier`; the HRW lease check runs in the host's lease enforcement path (`crates/fcp-host/src/bin/fcp-host.rs`); credential-pool leasing is `crates/fcp-host/src/credentials.rs`; the audit+HLC append is `invoke_audit.rs`; sandbox setup is `fcp-sandbox`; and dispatch is the supervisor. The count (14) and the short-circuit structured-denial semantics are enforced identically by both views.

### Admission Control

Nodes enforce per-peer resource budgets:

| Mechanism | Purpose |
|-----------|---------|
| **PeerBudget** | Per-peer limits on bytes/sec, frames/sec, pending requests |
| **Anti-amplification** | Response size ≤ N × request size until peer authenticated |
| **Rate limiting** | Token bucket, sliding-window, leaky-bucket enforcement; burst applies to token buckets |
| **Backpressure** | Reject new requests when budget exhausted |

### Audit Chain (HLC + HierVV + OTLP)

Every zone maintains a hash-linked audit chain with monotonic sequence numbers, Hybrid Logical Clock attributes, and a Hierarchical Version Vector frontier for revocation freshness:

```
AuditEvent_1 → AuditEvent_2 → AuditEvent_3 → ... → AuditHead
  seq=1          seq=2          seq=3              head_seq=N
  HLC=(t,c)      HLC=(t,c)      HLC=(t,c)
     ↑              ↑              ↑                   ↑
  signed         signed         signed         quorum-signed

ZoneCheckpoint {
  rev_head, rev_seq      → Revocation chain state
  audit_head, audit_seq  → Audit chain state
  hier_vv                → Hierarchical version vector
}
```

- Events are hash-linked (tamper-evident) with monotonic seq for O(1) freshness checks.
- `AuditHead` checkpoints are quorum-signed (n-f nodes).
- HLC clock rollbacks alert; HierVV size histograms surface frontier health.
- `ZoneCheckpoint` enables fast sync without chain traversal.
- Required events: secret access, risky operations, approvals, zone transitions, revocations.
- W3C-compatible `trace_id` / `span_id` flow through `InvokeRequest`, `AuditEvent`, and the OTLP parity exporter.

The OTLP exporter re-emits audit events as OpenTelemetry traces, metrics, and logs with pinned HLC attributes, host backpressure proof, retry harness, and an `fwc telemetry otlp-readiness` operator probe.

---

## Post-Quantum Cryptography

Production-grade PQ infrastructure lives in `fcp-crypto` (X-Wing KEM, ML-DSA-65 signatures, V4 zone-key envelopes and their constant-time/length-invariant/zeroize machinery); the lattice-trapdoor delegation research surface lives separately in `fcp-crypto-pq`:

| Primitive | Algorithm | Use |
|-----------|-----------|-----|
| **KEM** | X-Wing (RustCrypto draft-06, `crates/fcp-crypto/src/xwing.rs`) | Hybrid HPKE-X25519 + X-Wing wrap of zone keys in `ZoneKeyManifest V4` |
| **Signature** | ML-DSA-65 (FIPS 204, `crates/fcp-crypto/src/ml_dsa.rs`) | Post-quantum signing path alongside Ed25519 |
| **AEAD profile** | `Fcp4Aad` (`crates/fcp-crypto/src/xwing.rs`) | Wire format for `XWingSealedBox` |
| **Lattice delegation** | Trapdoor delegation chain (`crates/fcp-crypto-pq/`) | Lean structural soundness theorem; throughput bench vs Ed25519 and ML-DSA-65 |

Properties:
- IETF KAT regression harness for X-Wing.
- Internal regression KAT pinned for ML-DSA-65 (vendoring the published NIST FIPS 204 vectors is tracked in `kyopb.1.1.3.1`); randomized signing via `getrandom`.
- `ZoneKeyManifest V4` supports mixed V3 + V4 wrap lists, per-recipient KEM discriminator, and a safe `migrated_to_v4` promotion path.
- Hybrid verifier dispatches through both HPKE-X25519 and X-Wing.
- Constant-time `PartialEq` on all PQ secret types via `subtle::ConstantTimeEq`.
- Length-invariant `Deserialize` on all transparent PQ byte envelopes with proptest fuzz coverage.
- Mixed V3/V4 mesh migration harness proves both readers see the same effective zone key during cutover.

---

## Connectors

The workspace ships 177 connector crates — 176 production connectors plus one adversarial conformance test crate (`connectors/_adversarial/`). All 176 production crates ship a `manifest.toml` and tests. The connector surface is broad but not perfectly uniform: 156 currently implement the formal `ConnectorErrorMapping` trait, 158 currently follow the full `src/client.rs` + `src/connector.rs` + `src/types.rs` layout, and 176 currently publish explicit `OperationInfo` structs. A workspace conformance guard fails CI if a mature connector lacks a `tests/` directory.

### Tier 1: Critical Infrastructure

| Connector | Archetype | Why |
|-----------|-----------|-----|
| `fcp.github` | Request-Response + Webhook | Code review, issue management, CI/CD |
| `fcp.linear` | Request-Response + Webhook | Human ↔ agent task handoff; bi-directional Beads sync |
| `fcp.stripe` | Request-Response + Webhook | Financial operations; invoicing, subscriptions |
| `fcp.gmail` | Polling + Request-Response | Email automation, inbox management |
| `fcp.slack` | Bidirectional | Team communication |
| `fcp.twitter` | Request-Response + Streaming | Real-time information layer |
| `fcp.browser` | Browser Automation (Real CDP) | Universal adapter for any web service |
| `fcp.telegram` | Bidirectional + Webhook | Real-time messaging, bot automation |
| `fcp.discord` | Bidirectional + Webhook | Community management, server automation |
| `fcp.youtube` | Request-Response | Video transcripts, channel analytics |

### Connector Categories (representative)

| Category | Connectors |
|----------|------------|
| **AI / LLM (cloud)** | Anthropic, anthropic-vertex, aws-bedrock, OpenAI, Google AI (Gemini), Mistral, xAI Grok, DeepSeek, Together, NVIDIA NIM, MoonShot Kimi, Qwen, Fireworks, llm-router, microsoft-foundry, HuggingFace |
| **AI / LLM (local)** | Ollama, LM Studio, Whisper |
| **Embeddings** | Voyage AI |
| **Media generation** | Fal AI, Runway (Gen-3/Gen-4 video), ComfyUI |
| **Speech** | ElevenLabs, Deepgram, Azure Speech |
| **Specialty AI** | Inworld (character / voice agents) |
| **Search** | DuckDuckGo, Brave Search, Perplexity Search, SearXNG, Tavily, Exa, Firecrawl, Wolfram |
| **Google Services** | Gmail, Calendar, Drive, Docs, Sheets, Chat, Places, YouTube, People, Workspace Events, Admin Reports, BigQuery, Google AI, Google Meet |
| **Messaging & Collaboration** | Slack, Discord, Telegram, Twitter/X, Matrix, Mattermost, Microsoft Teams, Outlook, Signal, WhatsApp, BlueBubbles, iMessage, Synology Chat, IRC, Nostr, Feishu, LINE, DingTalk, WeCom, QQ, Zalo, Tlon (Urbit), Nextcloud Talk |
| **Voice-call** | Twilio, Telnyx, Plivo (all sharing `fcp-voice-call` substrate) |
| **Dev Tools** | GitHub, GitLab, Bitbucket, Linear, Jira, ClickUp, Todoist, Trello, Asana, Confluence, CircleCI |
| **Databases** | PostgreSQL, MySQL/MariaDB, SQLite, Redis, MongoDB, Elasticsearch, DuckDB, Snowflake, Qdrant, Pinecone, VectorDB |
| **Cloud & Infra** | S3, AWS, Azure, GCP, Kubernetes, Terraform, Pulumi, Vercel, Netlify, Cloudflare, DockerHub, Firebase, Supabase |
| **Observability** | Datadog, Grafana, Sentry, Mixpanel, Amplitude, PostHog, Segment, Metabase |
| **Productivity** | Notion, Airtable, Figma, DocuSign, Pandadoc, Evernote, Logseq, Roam, Coda, Apple Notes, Apple Reminders, Obsidian, Email Generic |
| **Communication** | SendGrid, Mailchimp, HubSpot, Intercom, Zendesk |
| **Finance** | Stripe, PayPal, Plaid, Square, Shopify |
| **Security** | 1Password, Bitwarden |
| **Automation** | Zapier, Make, n8n, Retool, Cron, Webhook Receiver |
| **Content** | Reddit, LinkedIn, Spotify, Anna's Archive, Arxiv, Semantic Scholar, Mastodon, Twitch, Hacker News |
| **Home & Local** | Sonos, Hue, Home Assistant |
| **Other** | MCP Bridge, Salesforce, Box, Dropbox, Microsoft 365 |

The authoritative inventory is the `connectors/` directory or manifest-backed `fwc list --offline`, not a handwritten static table. A few connectors are explicitly non-live today (`zalouser` ships as `status = "quarantined"`; `tlon` and `huggingface` declare `status = "proven"` in their manifests, although `huggingface` still reports a code-level `surface_status` of incubating in its connector introspection). Inventory presence does not mean end-to-end proof.

### Google Workspace Platform

The Google service connectors share a discovery-pinned substrate (`fcp-google-discovery`):

- `GoogleAuthSelection` — unified config parsing for `access_token`, `credential_id`, or OAuth refresh.
- `GoogleMaterializedAuth` — materialized auth with `BearerToken` and `CredentialReference` variants.
- `GoogleRestExecutor` — shared HTTP executor with retry loops and structured error extraction.
- Migration acceptance tests validate substrate integration across Gmail, Calendar, and YouTube.

### Voice-Call Multi-Provider Parity

The `fcp-voice-call` crate provides shared `CallAuthToken`, `SessionStore`, and replay-cache primitives. Twilio (HMAC), Telnyx (Ed25519 webhooks), and Plivo (HMAC-SHA256 V2/V3 webhooks) all flow through the same architectural shape. A multi-provider operator proof script (`scripts/e2e/voice_call_multi_provider_verification.sh`) runs each provider's no-live-credential loopback suite through its production connector boundary and normalizes the JSONL into one redaction-checked multi-provider evidence log.

### OpenAI-Compatible Shared Client

The `fcp-openai-compat` crate centralizes the OpenAI-compatible HTTP facade used by Groq, Cerebras, DeepSeek, Fireworks, GLM (Zhipu), LM Studio, Microsoft Foundry, Moonshot, NVIDIA NIM, Ollama, Qwen, Together, Voyage, and xAI. Each provider routes through the unified `/v1/chat/completions` shape with reasoning-content preservation and trace redaction.

### Browser Real-CDP Control Plane

The `browser` connector ships a Rust-owned CDP control-worker, supervised target/session manager with cookie-ownership boundary, native launcher + proxy worker supervisor, and direct-CDP routing for every operation. Readable-content and document-extraction parity guardrails land alongside. The shape mirrors OpenClaw's supervised target/session semantics.

### Connector SDK & Migration Framework

The `fcp-sdk` crate provides the runtime helpers used across the workspace:

```rust
// Every connector implements this trait for unified error handling
pub trait ConnectorErrorMapping: Display + Debug + Send + Sync {
    fn from_async_error(error: AsyncError) -> Self where Self: Sized;
    fn to_fcp_error(&self) -> FcpError;
    fn is_retryable(&self) -> bool;
    fn retry_after(&self) -> Option<Duration> { None }
}
```

Supporting infrastructure:

| Component | Purpose |
|-----------|---------|
| `ConnectorRuntime` | Lifecycle wrapper with request contexts and graceful shutdown. The migration shim has been retired; this is the production surface. |
| `RetryLoop` | Generic retry executor with exponential backoff and jitter |
| `HttpRetryConfig` | Serializable retry config (max retries, initial/max delay, jitter) |
| `AttemptOutcome<T, E>` | Enum for retry decisions: `Success`, `Retryable`, `Terminal` |

### Streaming Health Model

`fcp-streaming` provides a state machine for long-lived connection health:

```
Connected ──(missed heartbeat)──> Degraded
Connected ──(connection lost)───> Reconnecting
Degraded  ──(heartbeat received)─> Connected
Degraded  ──(zombie timeout)────> Unhealthy
Reconnecting ──(connected)──────> Connected
Reconnecting ──(max retries)────> Unhealthy
```

`StreamHealthTracker` drives transitions and produces `StreamHealthSnapshot` structs with `last_heartbeat_ms_ago`, `last_ack_ms_ago`, `reconnect_count`, `messages_received`, and `uptime_ms`. The tracker maps to `fcp_core::ConnectorHealth` for external reporting.

---

## Provider Auth and Credential Pooling

### Multi-Method Provider Auth (`fcp-provider-auth`)

A shared crate consolidating per-provider auth in one place:

| Method | Purpose |
|--------|---------|
| API key | Direct bearer / header auth |
| AWS SigV4 | Request signing + presigning for AWS-family providers |
| JWT refresh | TTL-aware token refresh actors |
| OAuth device-code | Headless flow for CLI / agents |
| OAuth authorization-code + PKCE | Browser-mediated flow |
| Refresh-token | Long-lived session continuation |
| Setup-token | One-time provisioning (used by Anthropic CLI auth, hardware tokens) |

`AuthProfile` flows through the credential-pool lease layer. `fcp-host` and `fwc` expose profile-admin and OAuth login surfaces.

### Credential Pooling (`fcp-host`)

Multi-credential per-provider pools support:

- **Priority** — preference ordering across credentials.
- **Strategy** — round-robin, LRU, sticky-restick, max-use limits.
- **Exhaustion cooldown** — back off rate-limited credentials and retry alternates.
- **Active-lease tracking** — observable handles for in-flight work.
- **Audit log** — mutation events on credential creation, rotation, retirement.
- **Connector-boundary E2E** — redaction-safe JSONL evidence harness.

Admin API routes expose pool inspection and mutation; SDK extensions let connectors lease credentials without ever holding raw bearer material.

---

## FWC: The Agent-First CLI

`fwc` is the sole supported CLI for the Flywheel connector workspace. It provides 50+ commands across discovery, lifecycle, invocation, intent compilation, and workflow management. Output defaults to TOON, a token-efficient format optimized for AI agent consumption.

### Quick Start

```bash
# Install from source
cargo build -p fwc --bin fwc --release
cp target/release/fwc ~/.local/bin/

# Current provisioning path (transitional): fwc talks to fcp-host via --host
fwc --host http://127.0.0.1:8787 status github
fwc --host http://127.0.0.1:8787 list
fwc --host http://127.0.0.1:8787 invoke github issues.create --file payload.json
fwc --host http://127.0.0.1:8787 simulate github issues.create --file payload.json

# See which truth source backs an answer
fwc --host http://127.0.0.1:8787 mesh explain-availability github

# Offline mode: artifact-backed data without a running host or mesh
fwc list --offline
fwc search "send message" --offline
fwc show github --offline
fwc ops github --offline
fwc schema github issues.create --offline

# History and audit
fwc history --connector github --limit 20
fwc audit tail --zone z:work
```

### Command Families

| Family | Commands | Purpose |
|--------|----------|---------|
| **Discovery** | `list`, `search`, `show`, `ops`, `schema`, `examples`, `zones` | Find connectors and understand their operations |
| **Lifecycle** | `doctor`, `status`, `health`, `install`, `update`, `pin`, `rollout` | Manage connector health and deployment |
| **Execution** | `invoke`, `simulate`, `preflight`, `cancel` | Run operations with safety gates |
| **Workflow** | `plan`, `explain`, `do`, `task` | Intent-first workflow compilation and safe-by-default materialization |
| **Composition** | `pipe`, `pipeline`, `recipe`, `map`, `batch-file` | Chain and parallelize operations |
| **History** | `history`, `replay`, `compare`, `undo`, `approvals` | Audit trail and reversal guidance |
| **Auth** | `auth`, `config`, `profile` | Credential and configuration management |
| **Export** | `export-tools`, `serve-mcp` | Expose connectors as MCP tools |
| **Evidence** | `supply-chain`, `audit`, `manifest`, `net`, `trace`, `policy`, `proof`, `otlp` | Verify security posture |
| **Mesh** | `mesh availability`, `mesh explain-availability`, `mesh repair-hints` | Mesh truth and durability |

### FWC Truth Model

`fwc` enforces a host-first control-plane truth contract:

- The knowledge-state taxonomy lives in `crates/fwc/src/truth.rs` and explicitly distinguishes `mesh-backed`, `host-backed`, `node-local`, `offline`, `degraded`, and `fallback-derived` answers.
- `host-backed` is the authoritative answer today: the node-local control-plane view via `fwc → fcp-host`.
- `mesh-backed` is the target steady-state answer (not yet operational): when live runtime data is joined with mesh placement/durability evidence, the CLI elevates the result beyond node-local.
- Runtime resolution is performed before dispatch and yields `live`, `explicit-offline`, `degraded-offline`, or `refused`.
- Hybrid catalog commands (`list`, `search`, `show`, `ops`, `schema`, `examples`, `suggest`, `template`, `validate`, `export-tools`) require an explicit `--offline` opt-in for artifact-backed behavior when live host truth is unavailable.
- The no-fakes invariant is part of the contract: placeholder runtime data, guessed `simulate` support, and local file-edit side channels are bugs.
- Evidence bundles are replayable: every run produces `trace.jsonl`, `summary.json`, `environment.json`, and `replay.sh` under `crates/fwc/src/test_observability.rs`.

When a `fwc` run fails, the shortest trustworthy debugging loop:

1. Read `summary.json` for availability state, provenance markers, and join keys.
2. Read `trace.jsonl` for the exact phase sequence and correlation trail.
3. Read `environment.json` for the captured working directory, git SHA, redacted environment, and replay envelope.
4. Run `replay.sh` only after the first three files agree on what should be reproduced.

### Intent Compiler

`fwc plan`, `fwc explain`, and `fwc do` are not placeholder UX. The local intent compiler (`crates/fwc/src/intent.rs`) is ~6.3k lines with 267 inline tests and compiles natural-language goals into concrete `fwc` primitives plus workflow-truth metadata, ambiguity reporting, missing-information prompts, and suggested next actions. Resolution is strongest for the current curated connector profile set (~two dozen connectors with explicit aliases and domain keywords); connectors outside that set still participate through generic alias/keyword matching plus the manifest-backed operation index. `fwc do` is safe by default — it materializes the compiled workflow in simulation mode unless you explicitly pass `--approve`.

### Output Formats

`fwc` defaults to TOON, a token-efficient structured format optimized for AI agents:

```bash
fwc list --offline                    # TOON (default, compact)
fwc list --offline --json             # Full JSON
fwc list --offline --format table     # ASCII table
fwc list --offline --format csv       # CSV export
fwc list --offline --format markdown  # Markdown table
```

### Operational Pipelines and Recipes

```bash
# Pipes chain two operations
fwc pipe github.search_issues slack.post_message \
    --map 'title -> text, html_url -> blocks[0].url'

# Pipelines: TOML-defined multi-step workflows with dependency ordering
fwc pipeline list
fwc pipeline validate .fwc/pipelines/notify-on-new-issues.toml
fwc pipeline dry-run .fwc/pipelines/notify-on-new-issues.toml --param owner=octocat
fwc pipeline run .fwc/pipelines/notify-on-new-issues.toml --param owner=octocat

# Recipes: bundled, reusable pipeline templates
fwc recipe list
fwc recipe show github-pr-review-notify
fwc recipe export github-pr-review-notify > .fwc/pipelines/custom.toml

# Batch operations: heterogeneous operations from JSONL with dependency ordering
fwc batch-file operations.jsonl --dry-run
fwc batch-file operations.jsonl
```

### MCP Tool Export

```bash
# Serve all connectors as MCP tools
fwc serve-mcp --host http://127.0.0.1:8787

# Serve specific connectors only
fwc serve-mcp --host http://127.0.0.1:8787 github slack gmail

# Cap the live MCP surface at a risk ceiling (inclusive)
fwc serve-mcp --host http://127.0.0.1:8787 --risk-max medium github

# Offline tool schema export
fwc export-tools --offline --format mcp --json
fwc export-tools --offline --format claude github
fwc export-tools --offline --format openai --risk-max medium --output tools.json
```

`--risk-max` excludes operations above a risk threshold, preventing agents from accidentally invoking dangerous operations. Both `export-tools` and `serve-mcp` honor it with the same inclusive boundary semantics; a live `serve-mcp` server enforces the ceiling on `tools/list` and on `tools/call`, and tools without declared risk metadata are excluded whenever a ceiling is set.

---

## Workspace Crate Reference

42 platform crates under `crates/`. Bands shown below describe responsibility, not strict layering.

### Kernel / Execution Semantics

| Crate | Purpose |
|-------|---------|
| `fcp-kernel` | Long-term home for runtime context, lifecycle, invocation semantics, cancellation/progress, budgets, computation migration |
| `fcp-core` | Shared semantic vocabulary: zones, capabilities, provenance, lifecycle. Currently still carries vocabulary that will migrate to `fcp-kernel` / `fcp-policy` / `fcp-evidence` |
| `fcp-prelude` | Curated re-exports for connectors and host code |
| `fcp-async-core` | Async runtime substrate (wraps Asupersync; quarantines a minimal Tokio compat bridge for wiremock/reqwest) |
| `fcp-async-core-macros` | Proc macros for async-core |

### Policy and Evidence

| Crate | Purpose |
|-------|---------|
| `fcp-policy` | Long-term home for zone, capability, provenance, taint, approval, policy-bundle semantics |
| `fcp-evidence` | Long-term home for receipts, intents, revocation, checkpoints, attestations |
| `fcp-audit` | Hash-linked audit chain primitives + HLC + HierVV + OTLP parity exporter |
| `fcp-auth-schema` | Typed capability-token claim schema (consumed by both `fcp-crypto` builder and `fcp-core` verifier) |
| `fcp-manifest` | Connector manifest parsing and validation |

### Cryptography

| Crate | Purpose |
|-------|---------|
| `fcp-crypto` | Ed25519, X25519, HPKE, COSE/CWT, ChaCha20-Poly1305 AEAD, BLAKE3, Shamir, plus production PQ primitives: X-Wing KEM, ML-DSA-65, V4 zone-key envelopes |
| `fcp-crypto-pq` | Lattice-trapdoor delegation (deterministic fixture route), Lean structural soundness theorem, Ed25519/ML-DSA-65/lattice throughput bench |
| `fcp-crypto-hw` | CPU feature detection (CPUID) and SIMD dispatch for BLAKE3 and ChaCha20-Poly1305 AEAD |
| `fcp-cbor` | Deterministic CBOR (RFC 8949 §4.2 canonical encoding), schema hashing |

### Mesh / Data Plane

| Crate | Purpose |
|-------|---------|
| `fcp-protocol` | FCPC + FCPS framing, sessions, control-plane encoding, responder-picks suite negotiation |
| `fcp-mesh` | MeshNode routing, admission, gossip (IBLT + XOR filters + masked-IBLT anti-entropy), placement, HRW leases |
| `fcp-raptorq` | RaptorQ codec, chunking, symbol envelopes, repair |
| `fcp-store` | Object store, symbol store, repair, GC, offline state, power-aware deferral |
| `fcp-tailscale` | Mesh identity, peer discovery, ACL/tag integration |

### Host / Operator Surfaces

| Crate | Purpose |
|-------|---------|
| `fcp-host` | Node-local supervisor + admin API + credential pooling + drift detection + rollout + OTLP readiness |
| `fwc` | Sole supported Flywheel connectors CLI |

### Connector Authoring and Provider Helpers

| Crate | Purpose |
|-------|---------|
| `fcp-sdk` | Connector authoring SDK (ConnectorRuntime, RetryLoop, ConnectorErrorMapping, SigV4 substrate) |
| `fcp-streaming` | Shared streaming substrate with `StreamHealthTracker` |
| `fcp-oauth` | OAuth flows and token lifecycle support |
| `fcp-graphql` | Typed GraphQL client infrastructure with depth/size/alias guards |
| `fcp-webhook` | Webhook delivery + replay protection + signature verification |
| `fcp-google-discovery` | Shared Google service metadata / provisioning substrate |
| `fcp-openai-compat` | Shared OpenAI-compatible HTTP facade |
| `fcp-provider-auth` | Multi-method per-provider auth (API key + SigV4 + JWT + OAuth device-code + auth-code/PKCE + refresh-token + setup-token) |
| `fcp-voice-call` | Shared CallAuthToken, SessionStore, replay-cache for Twilio/Telnyx/Plivo |
| `fcp-ratelimit` | Token-bucket / sliding-window / leaky-bucket enforcement |
| `fcp-sandbox` | OS/WASI isolation, egress proxy, network constraint enforcement |
| `fcp-registry` | Registry/install/update with TUF + cosign verification |
| `fcp-bootstrap` | Provisioning, first-run ceremony, hardware-token PIN, recovery phrases |
| `fcp-telemetry` | Metrics, trace capture, structured logging, OTLP readiness |

### Verification, Test, and Bench Harnesses

| Crate | Purpose |
|-------|---------|
| `fcp-conformance` | Golden vectors, schema checks, interop tooling |
| `fcp-testkit` | Shared test harnesses, fixtures, prewarm cold-start evidence schema |
| `fcp-e2e` | End-to-end compliance and host-backed scenarios |
| `fcp-bench` | Criterion benches across mesh, audit, raptorq, crypto, host hot paths |
| `fcp-chaos` | Chaos-testing harness |
| `br-tools` | Beads helper utilities for Flywheel connector maintenance |

---

## Performance Targets

| Metric | Target (p50/p99) | How Measured |
|--------|------------------|--------------|
| Cold start (connector activate) | < 100 ms / < 500 ms | Host-backed activation benchmark |
| Local invoke latency (same node) | < 2 ms / < 10 ms | Host-backed local invoke scenario |
| Tailnet invoke latency (LAN) | < 20 ms / < 100 ms | Host-backed invoke benchmark with injected direct-path RTT + `fcp-tailnet-invoke-evidence` |
| Tailnet invoke latency (DERP) | < 150 ms / < 500 ms | Host-backed invoke benchmark with injected DERP RTT + `fcp-tailnet-invoke-evidence` |
| Symbol reconstruction (1 MB) | < 50 ms / < 250 ms | RaptorQ benchmark |
| Secret reconstruction (k-of-n) | < 150 ms / < 750 ms | Secret reconstruction benchmark |
| Memory overhead | < 10 MB per connector | Host-backed RSS process-tree benchmark; current proof: [`docs/perf/memory_overhead_evidence.md`](docs/perf/memory_overhead_evidence.md) |
| CPU overhead | < 1 % idle | Host-backed idle CPU benchmark |

### Performance Optimizations Landed

The most impactful tuning the workspace ships today:

- **`fcp-core`** — `IndexedZoneKeyManifest` O(1) recipient lookups (`d2oa0`).
- **`fcp-store`** — repair queue moved from sorted `Vec` to an O(log n) ordered structure (`BTreeMap<RepairQueueKey, QueuedRepair>`); WAL + cursor benches.
- **`fcp-cbor`** — `canonicalize_map` arena allocator (one arena `Vec<u8>` vs per-entry).
- **`fcp-raptorq`** — repair-tail decode coalesce; per-pivot Gaussian elimination heap allocation reduction; hot-path benches.
- **`fcp-webhook`** — precomputed routing index O(1) lookup.
- **`fcp-streaming`** — SSE parser cursor advance without full rescan.
- **`fcp-oauth`** — single-flight refresh gate using `fcp_async_core::channel::watch` (no Vec scan).
- **`fcp-host`** — concurrent `InvokeAuditChain` per-zone sharding (removes global Mutex serialization).
- **`fcp-bootstrap`** — cert-selection O(log n) index.
- **`fcp-tailscale`** — borrowed peer-tag scan.
- **`fcp-graphql`** — hot-path benches with depth/size guards inlined.
- **`fcp-crypto-pq`** — Ed25519 vs ML-DSA-65 vs lattice delegation throughput bench.

---

## Comparison: FCP vs. Alternatives

| Feature | FCP | LangChain Tools | MCP (Model Context Protocol) | Custom API Gateway |
|---------|-----|-----------------|------------------------------|--------------------|
| **Security model** | Zone-based cryptographic isolation, capability tokens (typestate-enforced) | Trust-the-runtime (no isolation) | Server-declared capabilities (no crypto enforcement) | API key + rate limiting |
| **Connector isolation** | Per-connector sandboxes (seccomp / Landlock / seatbelt / WASI) | Shared process memory | Separate server processes | Separate services |
| **Offline support** | Symbol-based availability with SLO-driven repair | None | None | None |
| **Credential handling** | Secretless via egress proxy injection; multi-method provider auth + credential pooling | In-memory shared context | Server-managed | Vault / env vars |
| **Audit trail** | Hash-linked chain + HLC + HierVV + OTLP parity, quorum-signed heads | Logging only | Logging only | Centralized logs |
| **Multi-device** | Mesh-native with fountain-coded distribution, HRW lease coordination | Single process | Client-server | Load balancer |
| **Revocation** | First-class objects with O(1) freshness, exact-membership lookup, priority gossip | N/A | N/A | API key rotation |
| **Agent UX** | TOON-first CLI with intent compilation | Python SDK | JSON-RPC | REST API |
| **Connector count** | 177 connector crates in the workspace (176 production) | ~50 community tools | Varies by server | Custom per service |
| **Supply chain** | Ed25519 signatures, in-toto / SLSA attestations, TUF + cosign | `pip install` | `npm install` | Docker images |
| **Post-quantum** | X-Wing KEM hybrid HPKE + ML-DSA-65 signatures, `ZoneKeyManifest V4` | None | None | None |

FCP is heavier than MCP or LangChain tools. In exchange for that weight it provides cryptographic isolation, mesh distribution, post-quantum readiness, and auditability. For single-machine prototyping, MCP is simpler. For production agent operations where security is non-negotiable, FCP provides guarantees the alternatives cannot.

---

## Algorithms & Design Principles

### RaptorQ Fountain Codes
RFC 6330. Symbol sizes 1 – 65,535 bytes. Chunked objects via `ChunkedObjectManifest`. BLAKE3 hash verification on reconstructed chunks. Admission control: concurrent decode limit (16), memory limits, duplicate rejection, timeouts. All arithmetic uses `checked_*` / `saturating_*`; no integer overflow panics.

### Deterministic CBOR Serialization
`fcp-cbor` enforces RFC 8949 §4.2:
- Map keys sorted by canonical CBOR bytes (length-first, then lexicographic).
- Minimal integer encoding.
- Duplicate-key detection and rejection.
- Depth limit (128 levels) and size limit (64 MiB) for DoS protection.
- Round-trip verification: `deserialize()` re-encodes and compares bytes.

All capability tokens, zone manifests, and signed objects use this canonical form.

### COSE/CWT Capability Tokens
RFC 9052 + RFC 8392:
- Ed25519 signatures over deterministic CBOR payloads.
- Standard claims: `iss`, `sub`, `exp`, `nbf`, `iat`.
- FCP-specific claims: operation scope, capability constraints, zone binding, freshness class, instance binding.
- Signature verified **before** claims are parsed (defense-in-depth).
- Revocation checked via monotonic sequence numbers (O(1) freshness).
- Typestate enforced across every connector boundary.

### Gossip Protocol
`fcp-mesh`:
- XOR filters for set membership (false-positive-only semantics).
- Invertible Bloom Lookup Tables (IBLTs) for set difference.
- Masked-IBLT anti-entropy fallback (`angoc.17.2`).
- Bounded gossip: `MAX_OBJECT_IDS_PER_REQUEST = 100`.
- Admitted vs. quarantined object classification.
- Per-peer admission budgets with anti-amplification rules.

### Repair Controller
`fcp-store`:
- Coverage evaluation in basis points (bps, 0–10000 = 0–100%).
- Per-object placement policies with coverage, diversity, and concentration targets.
- Deterministic repair prioritization: SLO deficit × object hotness × cost estimate.
- Bounded repair plans: max repairs, max bytes, max decode budget per cycle.
- Power-aware deferral: a `PowerState::Battery { percent }` signal below `battery_defer_threshold_percent` (default 20%) returns `None` from `next_repair()` and increments `RepairStats::power_deferred`. In-flight repairs are not interrupted.

### Rate Limiting Architecture
`fcp-ratelimit` provides three complementary algorithms:

| Algorithm | Use Case | State | Thread Safety |
|-----------|----------|-------|---------------|
| **Token Bucket** | Steady-state with burst tolerance | Atomic u32 + Mutex for refill timestamp | Lock-free consume via CAS loop |
| **Sliding Window** | Precise request counting over a time window | Mutex-guarded VecDeque of timestamps | Single Mutex, cleanup on access |
| **Leaky Bucket** | Smooth output rate with configurable drain | Mutex-guarded f64 level + leak rate | Leak on every access |

Operational FCP rate limits flow through `config_from_core` into `TokenBucket::from_config`, using a phase-preserving refill anchor: `last_refill = now - (elapsed % refill_interval)`. This avoids drift accumulation. Jitter in retry backoff uses `[0.5x, 1.5x)` of the base delay.

### Egress Proxy

```
Connector ──HTTP request──> Egress Proxy
                              │
                              ├─ 1. CIDR deny list (localhost, private, tailnet)
                              ├─ 2. Host allowlist (manifest network_constraints)
                              ├─ 3. Port allowlist (manifest)
                              ├─ 4. TLS requirement enforcement
                              ├─ 5. SNI verification (hostname matches)
                              ├─ 6. Optional SPKI pinning
                              ├─ 7. DNS response limit
                              ├─ 8. Credential injection (secretless mode)
                              │     └─ X-FCP-Credential-Id → bearer token via SecretFetchHook
                              └─ 9. Audit event logged
                              │
                              ▼
                         External API
```

Default CIDR deny ranges: `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10` (tailnet), `169.254.0.0/16` (link-local), `::1/128`, `fc00::/7`.

### Webhook Delivery System

`fcp-webhook` handles inbound webhook reception with three layers:

**Signature verification (timing-safe):**
- HMAC-SHA256 with `mac.verify_slice()` (constant-time via the `hmac` crate).
- HMAC-SHA1 for legacy providers.
- Ed25519 for providers that support it.
- Reject empty / short HMAC signing secrets.
- Secrets redacted in `Debug` output.

**Replay protection:**
- Deterministic event IDs: `SHA256(provider ‖ 0x00 ‖ event_type ‖ 0x00 ‖ body)`.
- Atomic claim via RwLock: `claim_event()` checks and records under one write lock; the older split `check_replay()` / `record_event()` pair is deprecated as TOCTOU-racy.
- TTL-based cleanup (default 24h) with periodic GC.

**Provider-specific parsing:**
- Slack: unwraps `event_callback` envelope to extract inner `event.type`.
- GitHub: extracts `X-GitHub-Delivery` header as event ID; falls back to deterministic ID.
- Generic: configurable header extraction with fallback chain.

### Bootstrap Ceremony

```
Phase 1: Time Validation
    └─ NTP drift check (5-min error threshold, 30-sec warning)

Phase 2: Genesis
    ├─ Generate 256-bit entropy (OsRng)
    ├─ Derive BIP39 recovery phrase (24 words)
    ├─ Derive owner keypair (Ed25519 + optional ML-DSA-65)
    ├─ Create genesis object (canonical CBOR, signed; includes created_at + initial_zones)
    └─ Atomic file write (temp → fsync → rename)

Phase 3: Node Key Generation
    ├─ Node signing key (Ed25519)
    ├─ Node encryption key (X25519, optional X-Wing KEM)
    ├─ Node issuance key (Ed25519)
    └─ Owner signs NodeKeyAttestation

Phase 4: Zone Initialization
    ├─ Generate zone symmetric keys
    ├─ Create ZoneKeyManifest V4 (hybrid HPKE-X25519 + X-Wing per node)
    └─ Initialize audit chain (genesis event, HLC=0)
```

Crash recovery: a lock file tracks the current phase. If the process crashes and restarts, it detects the lock and resumes from the last completed phase. Recovery phrases use `zeroize::ZeroizeOnDrop`; constant-time comparison via `subtle::ConstantTimeEq` prevents timing side channels.

### Post-Compromise Security (PCS) Zones

Sensitive zones can use MLS/TreeKEM-based post-compromise security. The on-the-wire enum is `PcsMode` in `crates/fcp-core/src/pcs.rs`:

| Mode | Behavior | Use Case |
|------|----------|----------|
| `Disabled` | Standard owner-distributed `ZoneKeyManifest` rotation | Default; `z:public` and any zone where forward secrecy is not required |
| `Enabled { epoch, commit_ref }` | TreeKEM-managed group ratcheting; key rotates on commits | `z:work`, `z:private`, `z:owner` when forward secrecy is required |

`PcsGroupState` tracks the current epoch, member set (`Vec<GroupMember>`), and key management mode. Each member carries a `node_id`, `public_key` (X25519), and a `leaf_index` into the TreeKEM binary tree. Benchmarked at ~2.6 μs per epoch advance and ~3.5 μs per removal rekey for groups of 3–10 members. See the **Post-Compromise Security (PCS) Group State** section below for the operational consequences.

---

## Test Infrastructure

The workspace has a very large crate-local and end-to-end test surface (60,000+ tests):

| Category | Where | What It Covers |
|----------|-------|----------------|
| **Unit tests** | `#[cfg(test)]` in every crate | Individual function correctness, edge cases |
| **Integration tests** | `connectors/*/tests/` | Connector lifecycle with wiremock HTTP mocking |
| **Conformance** | `crates/fcp-conformance/tests/` | Protocol golden vectors, capability verification, typestate enforcement, manifest operations conformance, revocation timing |
| **E2E** | `crates/fcp-e2e/tests/` | Host-backed compliance scenarios with structured tracing |
| **Connector proof scripts** | `scripts/e2e/*_verification.sh` | Operator replay bundles and redaction-safe JSONL evidence |
| **Mesh scenarios** | `crates/fcp-conformance/tests/integration_scenarios.rs` | Network partition recovery, gossip convergence, multi-node failover |
| **Benchmarks** | `crates/fcp-bench/`, `crates/fwc/benches/`, `crates/fcp-core/benches/` | Search, schema, pipeline, PCS, repair, HLC, OTLP, lattice |
| **Fuzz** | `fuzz/` | 100+ targets across CBOR / crypto / protocol / webhook / oauth / streaming / mesh / host |
| **Chaos** | `crates/fcp-chaos/`, `scenarios/` | Chaos-engineered failures with deferred chaos plans (results land in the runtime-generated, gitignored `chaos-results/`) |
| **Golden vectors** | embedded `insta` snapshots throughout | Canonical CBOR, manifest hashes, protocol frames, signing transcripts |

Key testing patterns:
- **No real API calls in tests** — all external services mocked via `wiremock`.
- **Deterministic test logging** — structured JSON log output with correlation IDs.
- **RFC test vectors** — Ed25519 (RFC 8032), HKDF (RFC 5869), X25519 (RFC 7748), CBOR (RFC 8949), COSE (RFC 9052), CWT (RFC 8392), RaptorQ (RFC 6330).
- **PQ KAT** — IETF X-Wing test vectors; FIPS 204 ML-DSA-65 test vectors.

### Mock Leakage Cleanup

A workspace-wide pass removed source-level mock injections from 16 connectors (Anthropic, Twitter, Wolfram, PayPal, Slack, Discord, Browser, iMessage, DingTalk, Whisper, Telegram, Teams, Matrix, Gmail, Signal, PostgreSQL). Mocks now live exclusively in `tests/` directories, isolated from production code.

### Connector Test-Directory Ratchet

A conformance guard fails CI if a mature connector lacks a `tests/` directory. Fourteen previously-untested connectors received local conformance plus integration suites: IRC, BlueBubbles, Google Meet, Signal, Mattermost, Twitch, iMessage, Google Chat, Apple Notes, Apple Reminders, Tlon (Urbit), Zalo, Email Generic, Whisper.

### Voice-Call Multi-Provider Operator Proof

`scripts/e2e/voice_call_multi_provider_verification.sh` runs the Twilio, Telnyx, and Plivo no-live-credential loopback suites through their production connector boundaries, then normalizes their provider JSONL into one redaction-checked multi-provider evidence log.

### Deadlock Detection

`parking_lot`'s built-in cycle detector is exposed through an opt-in feature flag on both `fcp-store` and `fcp-mesh`:

```bash
# Run fcp-mesh under the detector
CARGO_TARGET_DIR=/tmp/fcp-audit cargo test -p fcp-mesh --features deadlock-detection

# Or scope to fcp-store
CARGO_TARGET_DIR=/tmp/fcp-audit cargo test -p fcp-store --features deadlock-detection
```

The feature flips `parking_lot`'s `Mutex` and `RwLock` implementations to track lock ownership globally; non-trivial overhead, must not be enabled in release builds.

---

## End-to-End Request Flow

When an AI agent invokes a connector operation:

```
Agent ──"search my Gmail for invoices"──> fwc plan
                                            │
                                            ▼
                                    Intent Compiler
                                    ├─ Resolve connector: gmail
                                    ├─ Resolve operation: gmail.list_messages
                                    ├─ Check capability: gmail.read
                                    └─ Build: fwc invoke gmail list_messages --file payload.json
                                            │
                                            ▼
                                    fwc invoke (CLI)
                                    ├─ Resolve host context
                                    ├─ Preflight: risk check + approval gate
                                    └─ HTTP POST to fcp-host admin API
                                            │
                                            ▼
                                    fcp-host (orchestrator)
                                    ├─  1. Verify capability token (COSE signature)
                                    ├─  2. Check token expiry (CWT nbf/exp)
                                    ├─  3. Verify typestate (Bound vs Unbound)
                                    ├─  4. Check revocation (monotonic seq, O(1))
                                    ├─  5. Enforce zone policy (allowed_zones non-empty)
                                    ├─  6. Issue / verify HRW lease (singleton writers)
                                    ├─  7. Check rate limits (token bucket)
                                    ├─  8. Lease credential from pool
                                    ├─  9. Record audit event (HLC + HierVV)
                                    ├─ 10. Emit OTLP span
                                    └─ 11. Dispatch to connector subprocess
                                            │
                                            ▼
                                    Gmail Connector (sandboxed)
                                    ├─ Validate input against JSON Schema
                                    ├─ Materialize auth via fcp-provider-auth
                                    ├─ HTTP GET via egress proxy
                                    │   └─ Proxy enforces: HTTPS, gmail.googleapis.com, port 443
                                    │       Injects bearer token from SecretFetchHook
                                    ├─ Parse response, map errors via ConnectorErrorMapping
                                    └─ Return result + OperationReceipt
                                            │
                                            ▼
                                    fcp-host
                                    ├─ Record receipt (idempotency key)
                                    ├─ Append audit event with HLC + trace context
                                    ├─ Release lease + credential
                                    └─ Return structured result to fwc
                                            │
                                            ▼
                                    fwc → TOON output → Agent
```

Every step is logged with W3C trace context (`trace_id`, `span_id`) for end-to-end distributed tracing.

---

## Connector Authoring API

Building a new connector requires implementing the FCP connector contract. The `fwc new` scaffold generator creates the complete structure:

```bash
fwc new fcp.myservice --archetype request-response
```

This generates:

```
connectors/myservice/
├── Cargo.toml          # Workspace member with fcp-sdk, fcp-core, fcp-async-core
├── manifest.toml       # Capabilities, zones, rate limits, network constraints, sandbox
├── README.md           # Operator-facing connector README (see docs/connector-readme-template.md)
├── src/
│   ├── main.rs         # JSON-RPC stdin/stdout protocol loop
│   ├── lib.rs          # Module declarations
│   ├── connector.rs    # FCP lifecycle: configure, handshake, health, doctor, invoke
│   ├── client.rs       # HTTP client with retry loops and auth handling
│   ├── error.rs        # Error types + ConnectorErrorMapping impl
│   ├── types.rs        # API request/response structs (serde)
│   └── limits.rs       # Named constants for rate limits and validation bounds
└── tests/
    ├── conformance.rs  # Manifest operations conformance
    └── integration.rs  # Wiremock-based lifecycle and operation tests
```

### The Connector Lifecycle

Every connector implements the same protocol loop via `main.rs`:

```rust
let result = match method {
    "configure"  => connector.handle_configure(params).await,
    "handshake"  => connector.handle_handshake(params).await,
    "health"     => connector.handle_health().await,
    "doctor"     => connector.handle_doctor().await,
    "self_check" => connector.handle_self_check().await,
    "introspect" => connector.handle_introspect().await,
    "invoke"     => connector.handle_invoke(params).await,
    "simulate"   => connector.handle_simulate(params).await,
    "shutdown"   => connector.handle_shutdown(params).await,
    _ => Err(FcpError::InvalidRequest { .. }),
};
```

### Manifest Declaration

```toml
[connector]
id = "fcp.myservice"
name = "MyService Connector"
version = "0.1.0"
archetypes = ["operational"]
format = "native"

[zones]
home = "z:work"
allowed_sources = ["z:owner", "z:private", "z:work"]
allowed_targets = ["z:work"]
forbidden = ["z:public"]

[capabilities]
required = ["network.dns", "network.egress", "network.tls.sni"]
forbidden = ["system.exec", "network.listen"]

[sandbox]
profile = "strict"
memory_mb = 128
cpu_percent = 25
wall_clock_timeout_ms = 120000
deny_exec = true
deny_ptrace = true

[provides.operations."myservice.search"]
description = "Search items"
capability = "myservice.read"
risk_level = "low"
safety_tier = "safe"
idempotency = "strict"
revocation_freshness = "warn"

[provides.operations."myservice.search".input_schema]
required = ["query"]
type = "object"

[provides.operations."myservice.search".input_schema.properties.query]
type = "string"
description = "Search query string"

[provides.operations."myservice.search".output_schema]
type = "object"

[provides.operations."myservice.search".network_constraints]
host_allow = ["api.myservice.com"]
port_allow = [443]
require_sni = true
deny_localhost = true
deny_private_ranges = true
deny_tailnet_ranges = true

[[rate_limits.pools]]
id = "myservice.read"
requests = 100
window_ms = 60000
burst = 10
scope = "instance"
```

Every connector must declare `[provides.operations.*]` for each operation it implements; the conformance scanner catches drift between `const OP_*` literals and manifest declarations.

### Error Mapping Contract

```rust
#[derive(Error, Debug)]
pub enum MyServiceError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("API error ({status_code}): {message}")]
    Api { status_code: u16, message: String },
    #[error("Rate limited")]
    RateLimited { retry_after_ms: u64 },
}

impl ConnectorErrorMapping for MyServiceError {
    fn from_async_error(error: AsyncError) -> Self {
        match error {
            AsyncError::Timeout { timeout_ms } => Self::Api {
                status_code: 408,
                message: format!("deadline exceeded after {timeout_ms}ms"),
            },
            AsyncError::Cancelled => Self::Api {
                status_code: 0,
                message: "request cancelled".into(),
            },
            other => Self::Api { status_code: 0, message: other.to_string() },
        }
    }
    fn to_fcp_error(&self) -> FcpError { /* map each variant */ }
    fn is_retryable(&self) -> bool { /* 429, 5xx = true */ }
    fn retry_after(&self) -> Option<Duration> { /* from RateLimited */ }
}
```

---

## Registry Architecture

Registries are **sources, not dependencies**:

| Type | Description |
|------|-------------|
| **Remote Registry** | Public (registry.flywheel.dev) or private HTTP registry |
| **Self-Hosted Registry** | Enterprise internal registry |
| **Mesh Mirror** | Connectors as pinned objects in `z:owner` (recommended) |

Connector binaries are content-addressed objects distributed via the symbol layer. Your mesh can install/update connectors fully offline from mirrored objects.

### Supply Chain Verification

Before execution, FCP verifies:

1. Manifest signature (registry or trusted publisher quorum) over the manifest signing view and binary hash.
2. Binary checksum matches the signed binary hash.
3. Platform / arch match.
4. Requested capabilities ⊆ zone ceilings.
5. **If policy requires:** transparency log entry present.
6. **If policy requires:** in-toto / SLSA attestations valid.
7. **If policy requires:** SLSA provenance meets minimum level.
8. **If policy requires:** attestation from trusted builder.

Owner policy can enforce:
- `require_transparency_log = true`
- `require_attestation_types = ["in-toto"]`
- `min_slsa_level = 2`
- `trusted_builders = ["github-actions", "internal-ci"]`

**Optional enhanced security:** Registries can configure a `RegistryTrustPolicy` (`crates/fcp-registry/src/lib.rs:285`) that adds TUF root pinning (prevents freeze/rollback and mix-and-match attacks) and Sigstore/cosign verification (supply-chain provenance beyond publisher keys).

---

## Installation

### Prerequisites

- **Rust nightly (2024 edition)** — see [`rust-toolchain.toml`](rust-toolchain.toml).
- **Cargo**.
- **Tailscale** — for mesh features.
- **crates.io dependencies** — external runtime crates such as [`asupersync`](https://crates.io/crates/asupersync) (native async runtime) and [`tru`](https://crates.io/crates/tru) (the TOON serializer, imported under the `toon` alias in `fwc`) are pinned to exact versions and fetched from crates.io. A fresh clone builds with no sibling checkouts and no special directory layout.

  To hack on one of those crates locally, add a temporary [`[patch.crates-io]`](https://doc.rust-lang.org/cargo/reference/overriding-dependencies.html) section to the workspace `Cargo.toml` pointing at your checkout (do not commit it):

  ```toml
  [patch.crates-io]
  tru = { path = "../toon_rust" }
  ```

### Building

In shared multi-agent sessions, offload CPU-heavy Cargo work through `rch` so local machines do not turn into compilation bottlenecks. `rch` fails open to local execution if the worker fleet is unavailable.

```bash
# Build the default workspace members (core platform crates)
rch exec -- cargo build --release

# Build the full workspace, including connector crates
rch exec -- cargo build --workspace --release

# Build specific connector
rch exec -- cargo build --release -p fcp-telegram

# Run tests for the default workspace members
rch exec -- cargo test

# Run tests for the full workspace
rch exec -- cargo test --workspace

# Run clippy for the full workspace
rch exec -- cargo clippy --workspace --all-targets -- -D warnings

# Narrow crate-local compiler smoke check for fcp-core
(cd .rch/probes/fcp-core && rch exec -- cargo check)

# Narrow crate-local compiler smoke check for fcp-host
(cd .rch/probes/fcp-host && rch exec -- cargo check)

# ASUPERSYNC Tokio guardrail (local + CI parity)
bash scripts/ci/asupersync_tokio_guard.sh
```

### Operational Model Versions

| Version | Name | Status | Description |
|---------|------|--------|-------------|
| **V1** | Host-First | **Current, Proven** | `fwc → fcp-host → connector subprocesses`. Single-active-host deployment. Host-backed and node-local answers. |
| **V2** | Mesh-Native | **Target, NOT YET OPERATIONAL** | Personal device mesh, symbol-first distribution, mesh-backed answers, automatic failover. Zero production evidence. |

V2 has no committed timeline. See [`docs/OPERATIONAL_MODEL_VERSIONS.md`](docs/OPERATIONAL_MODEL_VERSIONS.md) for the full version definitions, per-command version requirements, and transition milestones.

---

## Minimum Production Bring-Up

This is the current honest deployment shape: a single active `fcp-host` with staged standby peers. Connector admin/lifecycle state is still persisted locally. The mesh infrastructure for automatic failover and state convergence is built and tested but not yet the default.

```bash
# Build the operator binaries
rch exec -- cargo build -p fcp-host -p fwc --release

# Start fcp-host with explicit operator-state paths
export FCP_HOST_BIND=0.0.0.0:8787
export FCP_HOST_CONNECTORS_FILE=/srv/fcp/connectors.json
export FCP_HOST_LIFECYCLE_STATE_FILE=/srv/fcp/lifecycle-state.json

./target/release/fcp-host

# Verify the deployment from an operator shell
fwc --host http://127.0.0.1:8787 list
fwc --host http://127.0.0.1:8787 mesh explain-availability github
fwc --host http://127.0.0.1:8787 status github
fwc --host http://127.0.0.1:8787 doctor --zone z:work --all
fwc config doctor github --host http://127.0.0.1:8787
```

Healthy interpretation:

- `list`, `status`, `doctor`, `config doctor`, and rollout/config mutations are authoritative only when they come from the live host.
- `mesh explain-availability` can legitimately elevate a connector from host-backed/node-local to mesh-backed truth.
- If `mesh explain-availability` does not report mesh-backed readiness, do not describe the deployment as fully mesh-backed.

### Rollout and Rollback Loop

```bash
fwc rollout set github --canary 10 --host http://127.0.0.1:8787
fwc rollout status github --host http://127.0.0.1:8787
fwc status github --host http://127.0.0.1:8787
fwc doctor --zone z:work --all --host http://127.0.0.1:8787
fwc rollout rollback github --to 1.2.2 --host http://127.0.0.1:8787
```

After every rollout or rollback, re-check `rollout status`, `status`, `doctor`, and `mesh explain-availability`. If the active node degrades, promote the staged standby peer deliberately rather than assuming automatic lease handoff or automatic state convergence.

### Provisioning and Secret Flow

- Treat `FCP_HOST_CONNECTORS_FILE` as the live connector inventory source that `fcp-host` mutates.
- Treat `FCP_HOST_LIFECYCLE_STATE_FILE` as the local admin-state snapshot that must move with the active host during a controlled failover.
- Stage the same connector binaries and manifests on the standby peer before claiming failover readiness.
- Use `fwc config export <connector> --host ... --file baseline.json` before any risky config change.
- Use `fwc config import <connector> --host ... --file candidate.json` for live config mutation, then immediately run `fwc config doctor`.
- If `fwc config export` reports a sanitized non-replayable snapshot, move the affected secrets into credential references or rebuild a complete config document explicitly — do not assume the sanitized export is a rollback file.

Proof anchors for deployment claims:

- [`docs/FWC_Host_First_Truthfulness_Playbook.md`](docs/FWC_Host_First_Truthfulness_Playbook.md) — operator truth model, replay contract, deployment/failover checklist.
- [`docs/FCP3_Acceptance_Contracts.md`](docs/FCP3_Acceptance_Contracts.md) — phase-5/phase-6 proof obligations behind mesh-backed and host-backed claims.
- [`docs/testing/core_platform_evidence_index.md`](docs/testing/core_platform_evidence_index.md) — rerun commands that verify the platform crates backing the operator story.

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `FWC_FORMAT` | Default output format (`toon`, `json`, `table`, `csv`, `markdown`) | `toon` |
| `FWC_HOST` | Default `fcp-host` endpoint URL (`fwc` consults this first) | None (requires `--host` or context) |
| `FCP_HOST_ENDPOINT` | Alternate name for the `fcp-host` endpoint URL (`fwc` consults this second) | None |
| `FCP_HOST_BIND` | `fcp-host` listen address (also used by `fwc` as a third fallback for endpoint resolution) | `127.0.0.1:8787` |
| `FCP_HOST_CONNECTORS_FILE` | Live connector inventory file mutated by `fcp-host` | None |
| `FCP_HOST_LIFECYCLE_STATE_FILE` | Local admin-state snapshot for `fcp-host` | None |
| `FCP_CONFIG_DIR` | FCP configuration directory; also resolves `HOME` / `USERPROFILE` as fallbacks | `~/.fcp` |
| `FCP_CONNECTOR_STATE` | Connector state directory | `$FCP_CONFIG_DIR/state` |
| `RUST_LOG` | Standard Rust logging filter | `info` |
| `SOURCE_DATE_EPOCH` | Reproducible-build timestamp source (consumed at compile time via `option_env!`) | None |

---

## Limitations

Honest about what FCP does not do yet:

- **Production deployment is still single-active-host** — the honest operating model is one active `fcp-host` with staged standby peers. Connector admin state remains node-local and automatic multi-node failover is not yet a production guarantee.
- **Mesh-native cutover is incomplete** — gossip, IBLT, XOR filters, masked-IBLT anti-entropy, and the LiveTruthResolver are built and tested, but mesh-backed truth is not the default highest-confidence source in production yet.
- **No GUI** — `fwc` is CLI-only. The `serve-mcp` command exposes connectors as MCP tools for AI agent consumption, but there is no web dashboard.
- **Connector maturity varies** — all 176 production connectors compile and pass tests, but depth of operation coverage ranges from comprehensive (GitHub, Gmail) to minimal. A few connectors are explicitly non-live (`zalouser` ships as `status = "quarantined"`; `tlon` and `huggingface` declare `status = "proven"` in their manifests, although `huggingface` still reports a code-level `surface_status` of incubating in its connector introspection).
- **Windows sandbox is Tier 2** — `fcp-sandbox` implements seccomp + Landlock on Linux and basic WASI isolation; macOS uses seatbelt. Windows sandbox support is not yet hardened.
- **No automatic connector updates** — `fwc install` and `fwc update` exist, but automatic background updates with rollback are not yet implemented.
- **Multi-node connector-state replication is designed, not operational** — `ConnectorStateRoot` and externalized state objects are specified, but the production host stores state locally.

---

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| `fwc list` returns `missing-host-endpoint` | No `fcp-host` running | Use `fwc list --offline` for workspace manifest data |
| Connector returns `NotConfigured` | `configure` not called before `invoke` | Call `fwc config schema <connector>` to see required params, then configure |
| `cargo build` OOMs on macOS | Too many parallel codegen units | Set `CARGO_TARGET_DIR=/tmp/fcp-build` to avoid Cargo lock contention; or use `rch exec -- cargo build` to offload to remote workers |
| `rch exec -- cargo ...` ends with rsync overflow on `.beads/recovery_*` | Remote Cargo command may already have succeeded; artifact retrieval is traversing a worker-side `.beads` recovery tree | Read remote-command status lines first. If `rch` reports a remote `exit=0`, treat the compile/test itself as successful and the failure as tooling state. |
| `rch exec -- cargo ...` fails remotely because a worker lacks the repo-pinned nightly | Worker runtime drifted from `rust-toolchain.toml` | Preserve remote stderr, inspect `rch status --json`, probe with `rch workers capabilities --refresh --command 'cargo +<toolchain> check --lib'` |

| `cargo test -p fcp-host --bin fcp-host` fails ~15 subprocess/prewarm/telegram tests with `expected compiled fcp-test-connector alongside the current test executable` | Filtered `--bin` test runs do not build the sibling `fcp-test-connector` fixture bin (full-package `cargo test -p fcp-host` does); rch-relocated test-exe layouts additionally needed the ancestor-walk fixture locator (br-lfl91) | Prefer the full-package run (`cargo test -p fcp-host`); or build the fixture first (`cargo build -p fcp-host --bins`); or point at it explicitly with `FCP_TEST_CONNECTOR_BIN=/path/to/fcp-test-connector` |
| Clippy fails with `fcp-async-core` errors | Pre-existing lints in async-core test code | Connector code is clean; run clippy per crate: `cargo clippy -p fcp-<crate>` |
| OAuth token refresh fails | Token expired between materialize and use | For `credential_id` auth, the egress proxy + credential pool handles refresh. For `access_token`, re-run configure with a fresh token |
| SSE stream stops without error | Connection idle timeout | The Anthropic SSE parser has a 16 MiB buffer limit and proper CRLF handling. Check network/proxy timeout settings |
| `Unsigned manifest` rejection | V4 zone-key migration not promoted | Owner-key migration is exposed via `fwc bootstrap migrate-owner-key --from v3 --to v4`; zone-key promotion still has to happen at the host/manifest layer rather than via a top-level fwc subcommand |
| HRW lease conflict | Stale lease or sequence drift | `fwc mesh lease ladder --connector <id>` to inspect the current HRW ladder; lease release is a host-side operation, not exposed as a top-level fwc subcommand |

---

## FAQ

**Q: Why 177 separate connector crates instead of a plugin system?**
Each connector is a standalone binary with its own manifest, capabilities, and sandbox policy. This eliminates shared-memory vulnerabilities, enables per-connector resource limits, and makes supply-chain verification tractable — you sign one binary, not a runtime + plugin combination.

**Q: Why RaptorQ instead of regular file transfer?**
Fountain codes eliminate retransmit coordination. Any K' symbols reconstruct the original; no packet is special. This enables multipath aggregation (symbols from any device contribute equally), natural offline resilience (partial availability = partial reconstruction), and DoS resistance (attackers can't target "important" packets).

**Q: Why Tailscale as the transport layer?**
Tailscale provides unforgeable WireGuard keys (identity), NAT traversal (connectivity), and ACLs (authorization) in one layer. FCP maps zones to Tailscale tags, giving cryptographic network isolation without managing a separate PKI.

**Q: Can I use FCP without the mesh?**
Yes. The host-first stack (`fwc` + `fcp-host`) works standalone on a single machine. The mesh layer adds multi-device distribution, offline resilience, and symbol-based data availability, but none of that is required for basic connector operation.

**Q: Why TOON output by default instead of JSON?**
TOON (Token-Optimized Output Notation) is 2-5× more token-efficient than JSON for AI agent consumption. Every `fwc` command also supports `--json` for full-fidelity structured output, plus `--format table|csv|tsv|markdown` for human consumption.

**Q: How do I add a new connector?**
Use the scaffold generator: `fwc new fcp.myservice --archetype request-response`. This creates a complete connector crate with manifest, error types, client stub, `ConnectorErrorMapping`, limits constants, and test harness.

**Q: What happens if a connector tries to access a host outside its manifest?**
The egress proxy denies the request. Network constraints are declared per-operation in the manifest (`allowed_hosts`, `allowed_ports`, `require_tls`). The sandbox enforces CIDR deny defaults (localhost, private ranges, tailnet) and SNI verification. The denial is logged as an audit event.

**Q: Is FCP post-quantum-secure today?**
The infrastructure is there: `fcp-crypto` ships X-Wing KEM (hybrid HPKE + post-quantum) with IETF KAT vectors and ML-DSA-65 signatures with an internal regression KAT. `ZoneKeyManifest V4` supports mixed V3 + V4 wrap lists. Whether a given deployment is operationally PQ-secure depends on whether you have promoted your manifests to V4 and rotated zone keys. The default is hybrid: classical X25519 alongside X-Wing.

**Q: How does `fwc do` avoid disasters?**
`fwc do` materializes the compiled workflow in simulation mode by default. Side-effecting execution requires an explicit `--approve` flag. Operations with `risk_level = "high"` or `risk_level = "dangerous"` additionally require an `ApprovalToken` and may require a quorum signature.

**Q: How does FCP handle prompt injection from external messages?**
Three layers: (1) the taint system tracks `EXTERNAL_INPUT` and `PROMPT_SURFACE` taints through provenance, (2) `mcp-bridge` runs prompt-injection description scanning on incoming tool descriptions, and (3) the merge rule (`MIN(integrity)`, `MAX(confidentiality)`) prevents low-integrity inputs from elevating trust.

**Q: What is the difference between V1 and V2?**
V1 is the current operational reality: `fwc → fcp-host → connector subprocesses`, a single active host with optional staged standby peers. V2 is the target steady state: every device a peer in a personal mesh, symbol-distributed objects, mesh-backed truth as the default. V1 is proven; V2's infrastructure is built and tested but not yet operational by default.

---

## Platform Support

| Platform | Architecture | Status |
|----------|--------------|--------|
| Linux | x86_64, aarch64 | Tier 1 |
| macOS | x86_64, aarch64 | Tier 1 |
| Windows | x86_64 | Tier 2 |
| FreeBSD | x86_64 | Tier 3 |

---

## Related Flywheel Components

FCP integrates with the broader Agent Flywheel ecosystem:

| Component | Purpose | Interaction |
|-----------|---------|-------------|
| **Tailscale** | Mesh networking, identity | Transport and ACL layer |
| **MCP Agent Mail** | Inter-agent messaging | Coordinate connector operations |
| **Beads (br/bv)** | Issue tracking | Track connector development |
| **CASS** | Memory/context system | Store connector interaction history |
| **UBS** | Bug scanning | Validate connector code |
| **dcg** | Command guard | Protect during development |

---

## Specification Refinement with APR

The FCP specification is refined iteratively using [APR (Automated Plan Reviser Pro)](https://github.com/Dicklesworthstone/automated_plan_reviser_pro), which automates multi-round reviews with GPT Pro 5.2 Extended Reasoning. The workflow is configured in `.apr/workflows/fcp.yaml`:

```yaml
documents:
  readme: README.md
  spec: FCP_Specification_V3.md
  implementation: docs/fcp_model_connectors_rust.md
```

```bash
# First round (requires manual ChatGPT login)
apr run 1 --login --wait

# Subsequent rounds
apr run 2
apr run 3 --include-impl

# Check status
apr status
apr show 5
apr diff 4 5
apr stats
```

| File | Purpose |
|------|---------|
| `FCP_Specification_V3.md` | Main protocol and conformance specification |
| `FCP_Specification_V2.md` | Historical / interoperability reference only |
| `docs/fcp_model_connectors_rust.md` | Legacy Rust connector guide used for migration deltas, not canonical FCP3 truth |
| `docs/GOOGLE_Connector_Platform_Reference.md` | Developer/operator guide for the shared Google connector platform |
| `.apr/workflows/fcp.yaml` | APR workflow configuration |
| `.apr/rounds/fcp/round_N.md` | GPT Pro output for each round |

---

## Acknowledgments

Built with:

- [Rust](https://www.rust-lang.org/) (nightly, 2024 edition) — the entire platform.
- [ed25519-dalek](https://github.com/dalek-cryptography/ed25519-dalek) + [x25519-dalek](https://github.com/dalek-cryptography/x25519-dalek) — classical signatures and key exchange.
- [RustCrypto X-Wing](https://github.com/RustCrypto/KEMs) + ML-DSA-65 implementations — post-quantum primitives.
- [chacha20poly1305](https://github.com/RustCrypto/AEADs) — AEAD symmetric encryption.
- [blake3](https://github.com/BLAKE3-team/BLAKE3) — fast cryptographic hashing.
- [coset](https://github.com/google/coset) — COSE token construction and verification.
- [ciborium](https://github.com/enarx/ciborium) — CBOR serialization.
- An in-tree RaptorQ codec in `crates/fcp-raptorq/` (RFC 6330) — fountain code encoding, decoding, and repair.
- [reqwest](https://github.com/seanmonstar/reqwest) — HTTP client for connector API calls.
- [wiremock](https://github.com/LukeMathWalker/wiremock-rs) — HTTP mocking across the workspace test suite.
- [parking_lot](https://github.com/Amanieu/parking_lot) — Mutex/RwLock with built-in cycle detector.
- [insta](https://github.com/mitsuhiko/insta) — snapshot testing for golden vectors.
- [clap](https://github.com/clap-rs/clap) — CLI argument parsing for `fwc`.
- [serde](https://github.com/serde-rs/serde) + [serde_json](https://github.com/serde-rs/json) — serialization throughout.
- [tracing](https://github.com/tokio-rs/tracing) — structured logging and observability.
- [opentelemetry](https://github.com/open-telemetry/opentelemetry-rust) — OTLP audit parity exporter.
- [subtle](https://github.com/dalek-cryptography/subtle) + [zeroize](https://github.com/RustCrypto/utils) — constant-time comparison and secure zeroing.
- [Tailscale](https://tailscale.com/) — mesh networking, identity, and ACL enforcement.
- [Asupersync](https://github.com/Dicklesworthstone/asupersync) — native async runtime.
- [TOON Rust](https://github.com/Dicklesworthstone/toon_rust) — token-optimized output notation.

Developed using multi-agent coding swarms: Claude Code (Opus 4.6 / 4.7), Codex (GPT-5.2), and Gemini coordinating via [MCP Agent Mail](https://github.com/Dicklesworthstone/agent_mail_mcp), [Beads](https://github.com/Dicklesworthstone/beads_rust) issue tracking, and [NTM](https://github.com/Dicklesworthstone/named_tmux_manager) session orchestration. Specification refined through 12+ rounds of [APR](https://github.com/Dicklesworthstone/automated_plan_reviser_pro) with GPT Pro 5.2.

---

## About Contributions

> *About Contributions:* Please don't take this the wrong way, but I do not accept outside contributions for any of my projects. I simply don't have the mental bandwidth to review anything, and it's my name on the thing, so I'm responsible for any problems it causes; thus, the risk-reward is highly asymmetric from my perspective. I'd also have to worry about other "stakeholders," which seems unwise for tools I mostly make for myself for free. Feel free to submit issues, and even PRs if you want to illustrate a proposed fix, but know I won't merge them directly. Instead, I'll have Claude or Codex review submissions via `gh` and independently decide whether and how to address them. Bug reports in particular are welcome. Sorry if this offends, but I want to avoid wasted time and hurt feelings. I understand this isn't in sync with the prevailing open-source ethos that seeks community contributions, but it's the only way I can move at this velocity and keep my sanity.

---

## Algorithm Deep Dives

The high-level "Algorithms & Design Principles" section above lists the major primitives. This section explains the math and the rationale.

### RaptorQ Fountain Codes (RFC 6330)

A traditional erasure code like Reed–Solomon picks a fixed `(k, n)` and produces `n` symbols where any `k` reconstruct the original. RaptorQ is a *fountain* code: from the same source object, it can produce an effectively unbounded stream of distinct symbols where **any K' symbols reconstruct**, with K' ≈ K + small overhead (a couple of symbols on average; pathological cases capped by an admission budget).

Why fountain semantics matter for a mesh:

- **No retransmit coordination.** With Reed–Solomon, if you lose symbol 7 and 12, peers have to agree to send *those specific symbols* back. With RaptorQ, any peer just sends *more* symbols; the receiver stops when it has enough.
- **Multipath aggregation is free.** Three peers can each send arbitrary symbols over independent paths; whichever K' arrive first finish the reconstruction. Bandwidth aggregates without a coordinator.
- **DoS resistance.** Since no symbol is "important," an attacker who selectively drops symbols achieves nothing; the receiver collects substitutes from any other source.
- **Graded offline resilience.** If you have K' − 5 symbols, you don't have "almost the object"; you have a deterministic delta-to-reconstruction. The repair controller scores objects by deficit and prioritizes accordingly.

`fcp-raptorq` carries the RFC 6330 codec with safety hardening on top:
- Symbol sizes are configurable from 1 to 65,535 bytes per object.
- Large payloads chunk into `ChunkedObjectManifest` entries so partial retrieval and targeted repair are possible without reconstructing the full object first.
- BLAKE3 hash verification runs on reconstructed chunks; end-to-end payload hashing rejects false-positive decodes (a hardening landed in March 2026 after an `l` initialization bug allowed a corner case).
- A dense Gaussian-elimination fallback decoder (rewritten with overdetermined GF(256) solve and post-hoc verification) catches sparse-decoder failures.
- Admission control: concurrent-decode limit of 16, memory limits, duplicate-symbol rejection, decode timeouts.
- All arithmetic uses `checked_*` / `saturating_*` operations; no integer-overflow panics under hostile input.

### Rendezvous Hashing (HRW) for Lease Election

Highest Random Weight hashing assigns a key (e.g. a connector instance + epoch) to a node by computing `hash(key, node_id)` for every node and picking the maximum. Properties:

- **Deterministic without coordination.** Every node computes the same answer given the same membership; no election round.
- **Minimal disruption on membership change.** Adding or removing one node only reassigns the keys that hashed highest to that node: `O(K/N)` keys move on average, instead of the `O(K)` that flat hashing causes.
- **No "primary."** Any node can compute the holder for any key, which is what lets a peer ingressing a gossip message verify whether the originator is actually the legitimate holder.

FCP uses HRW for:
- **Singleton-writer lease election** (`crates/fcp-mesh/src/authority.rs`, `coordinator.rs`, `planner.rs`). The lease object names the connector + epoch; HRW picks the holder; the holder requests a quorum of signers; the signed lease gossips as a durable mesh object. Stale-lease detection, malformed-lease status invalidation, sequence-drift flagging, duplicate-signer rejection, and unknown-signer rejection are all enforced at construction and on ingress.
- **Symbol placement scoring.** The repair controller uses HRW-like scoring with a DERP penalty to decide which peer to fetch a symbol from.

### Hybrid Logical Clocks (HLC)

`crates/fcp-audit/src/hlc.rs` ships a Hybrid Logical Clock following the Kulkarni-Demirbas update rules. A `HybridLogicalTimestamp` is `(physical_ms: u64, logical: u32, node_id: String)`. The physical component is wall-clock time in milliseconds; the logical counter ticks when physical time does not advance; the node_id breaks ties between events with identical `(physical_ms, logical)`. The clock advances by `max(local_physical, received_hlc_physical, prior_local) + counter_bump`. Properties:

- **Causal consistency.** If event A happened before event B in the same node, A's HLC < B's HLC. If A's effect arrived at another node before that node emitted B, A's HLC < B's HLC there too.
- **Bounded drift from wall clock.** The physical component tracks NTP; the logical counter only ticks when wall-clock time is non-monotonic (clock skew, leap-second compensation, NTP jump).
- **Cheap.** No vector to maintain, just a `(u64, u32, node_id)` triple. The `Ord` impl orders by `physical_ms`, then `logical`, then `node_id`, giving a total order across the mesh.

FCP uses HLC for:
- **Audit causality.** Every audit event carries an HLC; clock rollback (a real bug surfaced in `angoc.17.3`) is alerted via `audit.hlc.rollback`. The OTLP exporter pins HLC attributes on every emitted span.
- **Revocation freshness.** Combined with HierVV (below) so a peer can ask "is your revocation view at least this fresh?" without reconstructing a full ordering.

### Hierarchical Version Vectors (HierVV)

A traditional vector clock has size `O(N)` for `N` peers: fine for 3 nodes, ugly for 30, hostile for 300. HierVV (`crates/fcp-mesh/src/revocation/hier_vv.rs`) groups peers into a hierarchy (e.g. zone → device-class → device), maintains compressed summaries at each level, and only descends to per-peer detail on demand.

- **Compact representation.** Histograms of HierVV frontier size feed `audit.hier_vv.size` so frontier health is observable.
- **Cheap comparison.** Two HierVV frontiers can be compared at the top level first; descending only happens when the top-level comparison is ambiguous.
- **Bounded under churn.** Devices that disenroll drop out of the frontier; their last-known position is retained for revocation horizon checks but doesn't bloat the active vector.

FCP uses HierVV for the revocation frontier: a peer's "I have processed all revocations up to this HierVV" claim is what makes the masked-IBLT anti-entropy round cheap.

### Masked IBLT Anti-Entropy

Invertible Bloom Lookup Tables let two parties compute their symmetric difference of sets in roughly the size of the difference, not the size of the sets. A peer sends its IBLT; the other side subtracts and inverts; what remains is exactly the missing object IDs. The *masked* variant (`angoc.17.2`) layers a hash mask over the IBLT cells, providing fallback when straight inversion fails because the difference is larger than the IBLT was sized for: the mask lets the other side identify which cells were uninvertible and request a wider IBLT for those alone, instead of restarting the round at the larger size.

### XOR Filters for Set Membership

XOR filters are a recent (2019) compact-set-membership data structure that improves on Bloom filters on three axes: smaller (~9.84 bits per element for 3-wise XOR filters versus ~10 for Bloom), false-positive-only semantics (never false negatives), and constant-time queries. FCP uses XOR filters in gossip for "do I claim to hold this object" probes. They are not used in the revocation path, where exact membership is required (`crates/fcp-core/src/revocation.rs` uses a `HashMap<ObjectId, RevocationObject>` for exact lookup).

### Shamir Secret Sharing Over GF(2⁸)

Shamir's scheme picks a random polynomial of degree `k-1` whose constant term is the secret, evaluates it at `n` distinct points, and hands out `(x, P(x))` pairs. Any `k` shares determine the polynomial (and thus the secret); `k-1` shares give zero information (information-theoretic security, not just computational).

FCP implements Shamir over GF(2⁸) (`crates/fcp-core/src/secret.rs`):
- Per-byte sharing means secrets of arbitrary length share efficiently.
- The byte field's small size keeps polynomial evaluation cheap.
- Shares are wrapped to each receiving node's encryption key (HPKE) so an attacker who compromises one node still has to break HPKE to read the share, *then* still doesn't have enough shares to reconstruct.

The reconstruction flow is deliberately heavy: obtain a `SecretAccessToken` from an approver, collect any `k` wrapped shares from peers, unwrap with the local node encryption key, reconstruct in memory, use, then `zeroize::ZeroizeOnDrop`. No node ever holds the complete secret on disk.

### FROST Threshold Signing

FROST (Flexible Round-Optimized Schnorr Threshold) lets `t-of-n` signers produce a single Ed25519-compatible signature that any verifier can check with the aggregate public key alone; no knowledge of the threshold scheme is required on the verifier side. This is what backs the "threshold owner key" recommendation: the owner key produces standard Ed25519 signatures, but the private key never exists on any single device. Compromise of `t-1` devices yields nothing; loss of `n-t` devices is still recoverable.

`fcp-bootstrap` ships a FROST ceremony with explicit refusal taxonomies (`BootstrapError` variants), hardware-token PIN support, recovery-phrase derivation, and 11 evidence-bearing scenario tests packaged as `fcp-verification-bundle/v1`.

### Hybrid Post-Quantum Zone Keys (X-Wing + HPKE-X25519)

X-Wing is a recent (RFC-draft) KEM that combines X25519 ECDH with the ML-KEM-768 lattice KEM into a single hybrid. The encapsulator runs both KEMs in parallel; the decapsulator runs both and XORs the results through HKDF; if a "harvest now, decrypt later" attacker breaks X25519 in 2040 but not ML-KEM-768, the resulting shared secret is still unrecoverable.

`ZoneKeyManifest V4` carries a wrap list with both `HpkeX25519` and `XWingKem` entries per recipient. The hybrid verifier dispatches based on the wrap discriminator. Mixed V3 + V4 wrap lists are supported during migration; `migrated_to_v4` is a one-way phantom-type promotion enforced by the compiler.

### ML-DSA-65 (FIPS 204) Signatures

ML-DSA-65 (formerly CRYSTALS-Dilithium-3) is NIST's standard post-quantum signature scheme. Public keys are ~1.9 KB; signatures are ~3.3 KB. The randomized signing path uses `getrandom`; an internal regression KAT is pinned (vendoring the published NIST FIPS 204 vectors is tracked in `kyopb.1.1.3.1`). Where Ed25519 would have shipped one signature, hybrid deployments ship `Ed25519 ‖ ML-DSA-65` and verify both, so the post-quantum signature still holds even if the classical primitive falls.

The PQ envelope types in `fcp-crypto` ship:
- Constant-time `PartialEq` on every secret-bearing PQ type via `subtle::ConstantTimeEq`.
- Length-invariant `Deserialize` on every transparent byte envelope (proptest fuzz asserts wrong-length sequences reject; closes a P1 caught during the swarm session).
- `zeroize::ZeroizeOnDrop` on private-key material.

`fcp-crypto-pq` (lattice delegation) additionally ships:
- Constant-time `PartialEq` on its secret-bearing types, behaviorally pinned by tests.
- A Lean structural soundness theorem for the lattice-trapdoor delegation chain; the SIS hardness reduction is an explicitly unmechanized assumption boundary (`lean/Fcp/Invariants/LatticeDelegation.lean`).
- A Criterion throughput bench comparing Ed25519, ML-DSA-65, and lattice delegation.

### Token Bucket with Phase-Preserving Refill

Naive token-bucket implementations track `last_refill_timestamp` as wall-clock time. Over thousands of intervals, accumulated rounding drifts the bucket out of phase with the wall clock, eventually producing burst behavior the operator didn't ask for.

`fcp-ratelimit` uses a phase-preserving refill anchor: `last_refill = now - (elapsed % refill_interval)`. The bucket's refill cadence stays locked to the wall clock indefinitely. The convenience constructors `TokenBucket::new` / `with_burst` remain available for simpler whole-window buckets in tests.

Jitter in retry backoff uses `[0.5×, 1.5×)` of the base delay via `random_float().mul_add(1.0, 0.5)`, preventing thundering herds when many connectors retry simultaneously.

### Repair Controller Scoring Function

`fcp-store`'s repair controller scores each candidate repair as:

```
score = SLO_deficit_bps × object_hotness × inverse_cost_estimate × power_state_factor
```

Where:
- **SLO_deficit_bps** is the gap between current coverage and the per-object placement-policy target, in basis points (0–10000 = 0–100%).
- **object_hotness** is a recency-weighted access counter; cold objects get repaired during idle cycles, hot objects get prioritized.
- **inverse_cost_estimate** prefers repairs the local node can satisfy from already-cached neighbors over repairs that need DERP-relayed fetches.
- **power_state_factor** is 0 when the device reports battery below the deferral threshold (default 20%, matching `fcp_mesh::device::DeviceProfile::is_low_battery`), and 1 otherwise. In-flight repairs are not interrupted by deferral; only newly dequeued ones are gated.

Bounded repair plans cap the number of repairs, total bytes, and decode budget per cycle so the controller never starves the rest of the node.

### Deterministic CBOR Canonical Encoding (RFC 8949 §4.2)

For signatures to be reproducible across implementations, the encoder must be deterministic: the same input must produce the same output bytes regardless of map iteration order, integer width, or floating-point representation. `fcp-cbor` enforces RFC 8949 §4.2:

- Map keys sorted by canonical CBOR bytes (length-first, then lexicographic).
- Minimal integer encoding (`0` is encoded as one byte, not five).
- Duplicate-key detection and rejection.
- Depth limit (128 levels) and size limit (64 MiB) to prevent DoS via deeply nested or massive inputs.
- Round-trip verification: `deserialize()` re-encodes the parsed value and compares bytes; mismatches reject.

A `canonicalize_map` arena allocator (perf optimization `m7aoz`) consolidates per-entry allocations into a single arena `Vec<u8>`, which matters because canonical sort touches every map on the signature path.

---

## Connector Archetype Patterns

When implementing a new connector, identify which archetype(s) apply. Most connectors fit one cleanly; a few (chat platforms, GitHub) span multiple.

| Archetype | Pattern | Lifecycle Bias | Examples |
|-----------|---------|----------------|----------|
| **Request-Response** | Agent → Service → Agent | Synchronous, stateless | REST APIs, GraphQL, gRPC |
| **Streaming** | Service → Agent (continuous) | Long-lived, backpressure-aware | WebSocket, SSE, log tailing |
| **Bidirectional** | Agent ↔ Service | Long-lived, ordered, ack-based | Chat protocols, collaborative apps |
| **Polling** | Agent → Service (periodic) | Stateful cursor, singleton writer | Email IMAP, RSS feeds |
| **Webhook** | Service → Agent (push) | Push with replay protection | GitHub hooks, Stripe events |
| **Queue / Pub-Sub** | Agent ↔ Broker | At-least-once with idempotency | Redis Streams, NATS, Kafka |
| **File / Blob** | Agent → Storage | Idempotent on content hash | S3, GCS, local filesystem |
| **Database** | Agent → DB (query) | Connection pooling, SQL injection guards | PostgreSQL, vector DBs |
| **CLI / Process** | Agent → spawn → Process | Sandboxed subprocess, `deny_exec` exemption | git, kubectl, terraform |
| **Browser** | Agent → CDP → Browser | Supervised target/session manager | Real-CDP automation, scraping |

Voice-call connectors (Twilio, Telnyx, Plivo) are composite: their manifests declare `["operational", "streaming", "bidirectional"]` plus webhook ingress for inbound call events. The shared `fcp-voice-call` crate carries the call-lifecycle types (`CallAuthToken`, `SessionStore`, replay cache) that are common across providers; the per-archetype machinery comes from the individual archetype implementations.

Two enums classify connectors along orthogonal axes. The table above describes interaction *patterns* (the `ConnectorRoute` taxonomy in `crates/fcp-core/src/connector.rs`, ten variants kebab-case). The manifest schema accepts a separate, narrower `ConnectorArchetype` vocabulary in `crates/fcp-manifest/src/lib.rs`: `Operational`, `Streaming`, `Bidirectional`, `Storage`, `Knowledge`. Real manifests declare combinations from this latter set (for example `["operational", "streaming", "knowledge"]` for GitHub and Gmail; `["operational", "streaming", "bidirectional"]` for the voice-call providers). Each archetype maps to a different protocol loop pattern in `main.rs`, a different sandbox profile, and a different test-fixture style in `fcp-testkit`. The `fwc new --archetype <name>` scaffold picks the right defaults.

---

## TOON: Token-Optimized Output Notation

`fwc` defaults to TOON instead of JSON for human + agent output. TOON is the same data model as JSON (objects, arrays, strings, numbers, booleans, null) with a more compact surface syntax: no quotes on keys, no comma separators between siblings, indentation-as-structure, and array shorthand.

```
# JSON
{
  "connector": "github",
  "operations": [
    {"id": "issues.create", "risk": "low"},
    {"id": "issues.list",   "risk": "low"}
  ],
  "zones": ["z:work", "z:owner"]
}

# TOON (equivalent — ~40% fewer tokens for typical fwc payloads)
connector: github
operations[2]{id,risk}:
  issues.create,low
  issues.list,low
zones[2]:
  z:work
  z:owner
```

Token-efficiency is a first-class concern when an LLM consumes every command output: TOON typically saves 30–60% of tokens versus JSON on `fwc list`, `fwc show`, and `fwc ops` payloads, which adds up when an agent runs hundreds of discovery commands per session.

Every command supports `--json` for full-fidelity structured output and `--format table|csv|tsv|markdown` for human consumption. The TOON serializer is the [`tru`](https://crates.io/crates/tru) crate, developed in the [`toon_rust`](https://github.com/Dicklesworthstone/toon_rust) repository.

---

## Truth Hierarchy In Practice

The taxonomy in `crates/fwc/src/truth.rs` distinguishes six knowledge states:

| State | Meaning | Example |
|-------|---------|---------|
| **`mesh-backed`** | Live runtime data joined with mesh placement/durability evidence — the highest-confidence answer (target steady state; not the default in production today) | `fwc mesh availability github` reports "3 of 5 nodes hold ≥ K' symbols of the github connector binary; placement policy satisfied" |
| **`host-backed`** | Node-local control-plane view from `fwc → fcp-host` — the current authoritative answer | `fwc status github` queries the live `fcp-host` admin API |
| **`node-local`** | Local-only state, no cross-node corroboration | `fwc context current` (operator config, not connector runtime state) |
| **`offline`** | Artifact-backed data without a live host or mesh; carries stale-data caveats | `fwc list --offline` reads the workspace manifest TOML files |
| **`degraded`** | The live truth source was reachable but returned an incomplete or self-flagged-stale view | Host reports "drift detected — connector inventory file diverged from supervisor view" |
| **`fallback-derived`** | An answer reconstructed from a lower-confidence source after a higher-confidence source failed; explicit provenance markers attach | Mesh unreachable; host responded; answer is host-backed not mesh-backed, marked accordingly |

A command's classification matrix lives in `crates/fwc/src/catalog.rs` and marks each command as `live_host`, `offline_artifact`, `hybrid`, or `passthrough`. Hybrid commands (`list`, `search`, `show`, `ops`, `schema`, `examples`, `suggest`, `template`, `validate`, `export-tools`) require an explicit `--offline` opt-in for artifact-backed behavior when live host truth is unavailable.

---

## Operator Replay Bundles

Every operator-facing `fwc` run produces a replay bundle under `crates/fwc/src/test_observability.rs`:

| File | Purpose |
|------|---------|
| **`trace.jsonl`** | Phase-by-phase trace events with W3C `trace_id` / `span_id` correlation, structured log lines, and capability decisions |
| **`summary.json`** | Availability state, provenance markers (which truth source, which catalog), join keys, exit code, top-level outcome |
| **`environment.json`** | Captured working directory, git SHA, redacted environment variables, FWC version, host endpoint, replay envelope |
| **`replay.sh`** | Shell script that re-runs the same command against the same host with the same arguments |

When a run fails, the shortest trustworthy debugging loop is:

1. Read `summary.json` for availability state, provenance markers, and join keys.
2. Read `trace.jsonl` for the exact phase sequence and correlation trail.
3. Read `environment.json` for the captured working directory, git SHA, redacted environment, and replay envelope.
4. Run `replay.sh` only after the first three files agree on what should be reproduced.

Connector verifier scripts (`scripts/e2e/<connector>_verification.sh`) emit `*.rch_remote_proof.jsonl` records under their `proof/` directory. Only `accepted_remote_proof` counts as green closeout evidence. `remote_command_failed` is a real remote Cargo failure and belongs in the Beads / final-review record as code or test failure evidence, not green closeout. Other states (`refused_local_fallback`, `infra_blocked`, `failed_closed`, `not_proof`, missing or malformed `rch` summaries) keep the bead open and cite as blocker evidence.

---

## Approval Workflows

Operations with `risk_level = "high"` or `risk_level = "dangerous"` require an explicit `ApprovalToken` before invoke. The unified approval model handles both *elevation* (data moving up the integrity lattice) and *declassification* (data moving down the confidentiality lattice).

The operator-facing surface is `fwc approvals`, which inspects approval artifacts persisted by the host. Filter by status, connector, or artifact ID to investigate what is pending, allowed, denied, or expired:

```bash
# List approvals in the local approvals directory
fwc approvals

# Filter to one connector
fwc approvals --connector github

# Filter by status
fwc approvals --status allowed
fwc approvals --status denied
fwc approvals --expired

# Inspect one artifact by id
fwc approvals <artifact-id>
```

ApprovalToken issuance and signing happen inside the host's approval state machine; the artifacts surface via `fwc approvals` after issuance. Tokens carry the approver's signature, constraints (expires-in, max-uses, target-instance-id), and a reference to the originating operation intent. The host re-checks the token at every invoke; expired or exhausted tokens fail closed.

`SanitizerReceipt` objects are a related primitive: a sanitizer capability (URL scanner, malware scanner, schema validator) produces a receipt proving the sanitization happened. The receipt clears specific taints from the data's provenance, letting it pass downstream gates that would otherwise refuse `EXTERNAL_INPUT`-tainted bytes.

---

## Lean Formal Proofs

The `lean/` directory and `lakefile.lean` ship a Lean 4 proof workspace. The current verified content:

- **`lean/Fcp/Zone/Lattice.lean`** — zone-flow soundness on a confidentiality lattice. The file proves: `no_silent_downgrade_lemma` (an allowed flow never sends data to a more restrictive target), `zone_flow_soundness`, `zone_isolation_invariant` (a passing zone check implies no secret leaked along the operation's trace), `zone_lattice_sound` (no leak reachable from an allowed flow), `no_self_loop_leak`, and `transitive_capability_implies_witness` (composing two direct capabilities yields a transitive-capability witness). The lattice is single-level (confidentiality only, modeled as `Nat`) rather than the full (integrity, confidentiality) product lattice; multi-label and explicit-declassification proofs live outside this file.
- **Lattice-trapdoor delegation chain soundness** — the post-quantum lattice delegation primitive in `fcp-crypto-pq` has a gated witness proving the soundness theorem. The underlying lattice-arithmetic implementation stubs remain unactionable as a long-tail research item (`kyopb.1.3.1.1`, ~320h scope).

Lean proof outputs feed `docs/formal/zone_lattice.md` and `docs/formal/readme-proof-obligations.json`. The proof workspace is built via Lake; the toolchain is pinned in `lean-toolchain`.

---

## Mesh Object Lifecycle

Every durable object in FCP follows the same lifecycle. Understanding it clarifies why the system is offline-tolerant and how repair / GC interact.

```
┌────────────────────────────────────────────────────────────────┐
│                  OBJECT LIFECYCLE                              │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  1. Create        ──> ObjectHeader signed by emitter           │
│                       provenance, retention, refs              │
│                                                                │
│  2. Encode        ──> RaptorQ over canonical CBOR              │
│                       N symbols at SymbolSize                  │
│                                                                │
│  3. Distribute    ──> Gossip XOR-filter "I claim to have"      │
│                       IBLT reconcile differences               │
│                       Peers request specific symbols           │
│                                                                │
│  4. Verify        ──> BLAKE3 hash on reconstructed chunks      │
│                       AEAD tag per symbol                      │
│                       Signature on ObjectHeader                │
│                                                                │
│  5. Place         ──> ObjectPlacementPolicy enforces           │
│                       coverage_bps, diversity, concentration   │
│                                                                │
│  6. Repair        ──> Background controller scores deficits    │
│                       Bounded plan: max repairs / bytes / time │
│                       Power-aware deferral                     │
│                                                                │
│  7. Reference     ──> Other objects reference by ObjectId      │
│                       Reachability graph grows                 │
│                                                                │
│  8. Quarantine    ──> Unreferenced objects move to bounded     │
│                       quarantine store (TTL-bounded)           │
│                                                                │
│  9. GC            ──> Reachability traversal from roots;       │
│                       unreachable in quarantine ≥ TTL → free   │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

Object retention is policy-driven: `retain_until` timestamps, reference counts, and zone-level placement policies all feed the GC controller. The compatibility ledger's latest-pointer cursor survives V1 → V2 schema upgrades and, when a stale V1 pointer is silently upgraded to the on-disk high-water-mark V2 ledger, emits a structured `tracing::warn!` with a `reason` field that distinguishes legitimate first-reopen upgrades from tamper-suggestive ones (the `28nms` discipline; see `crates/fcp-store/src/compatibility_ledger.rs`).

---

## Multi-Agent Development Methodology

This project is largely built and maintained by coordinated swarms of AI coding agents — Claude Code (Opus 4.x), Codex (GPT-5.2), and Gemini — running in parallel under human direction. The methodology is documented and reproducible:

- **[MCP Agent Mail](https://github.com/Dicklesworthstone/agent_mail_mcp)** — agent-to-agent messaging, advisory file reservations, contact handshakes, threaded inboxes. Prevents two agents from editing the same file simultaneously; surfaces who-said-what across a session.
- **[Beads](https://github.com/Dicklesworthstone/beads_rust)** (`br`) and **[bv](https://github.com/Dicklesworthstone/bv)** — dependency-aware issue database with deterministic graph metrics (PageRank, betweenness, critical path, cycles). Agents claim work via `br ready` → `br update --status=in_progress`; commits include the bead ID for traceability; `bv --robot-triage` recommends what to pick up next.
- **[NTM](https://github.com/Dicklesworthstone/named_tmux_manager)** — multi-pane tmux orchestration for parallel agent sessions with cross-pane marching orders, inbox monitoring, and stuck-pane detection.
- **[RCH](https://github.com/Dicklesworthstone/rch)** — remote compilation helper: offloads `cargo build`, `cargo test`, and `cargo clippy` to a fleet of remote workers so a single workstation doesn't become the bottleneck when 6 agents are building simultaneously.
- **[CASS](https://github.com/Dicklesworthstone/cass)** — cross-agent session search; mines prior conversations across Claude Code, Codex, Cursor, Gemini, ChatGPT for working prompts and solved problems.
- **[UBS](https://github.com/Dicklesworthstone/ubs)** — Ultimate Bug Scanner, a multi-language lint that runs in `--ci` mode before commits.
- **[APR (Automated Plan Reviser Pro)](https://github.com/Dicklesworthstone/automated_plan_reviser_pro)** — 12+ rounds of GPT Pro 5.2 Extended Reasoning over the FCP V3 specification, with each round narrowing from architectural flaws → interface refinements → nuanced optimizations.

A representative swarm session (2026-05-02) ran 4 Codex agents and 2 Claude Code agents in parallel for ~6 hours, closing ~167 beads (net of the ~2,935 baseline), filing 18 P1/P2 security findings (all fixed same-day), and shipping 31 new connector beads. Session memo at [`docs/audit/swarm-session-summary-2026-05-02.md`](docs/audit/swarm-session-summary-2026-05-02.md).

The development model also imposes discipline most human-only projects don't bother with:

- **Per-agent build quarantine** — each agent uses `CARGO_TARGET_DIR=/tmp/fcp-<lane>` or `/Volumes/USB_NVME/fcp-<lane>` to avoid Cargo lock contention.
- **Forward-only ratchets** — once a property holds (typestate enforcement, mock-leakage cleanup, manifest operations conformance, test-directory presence), a conformance test in `fcp-conformance` prevents regression.
- **REVIEW MODE final phase** — even when "all beads drained," a final review-mode sweep catches bugs in commits that shipped within the same session. Catch rate on the May 2 session: 5/5 P1 findings caught and fixed same-day.
- **Quarterly debiasing** — every quarter, an agent or human produces a claims-vs-reality report comparing README feature status labels against current code evidence. The inaugural report is [`docs/quarterly/2026-Q2-claims-vs-reality.md`](docs/quarterly/2026-Q2-claims-vs-reality.md).

`AGENTS.md` at the repo root documents the rules for AI coding agents working in this codebase: build commands, branch hygiene, file-deletion prohibitions, irreversible-action protocols, and tool-specific recipes (RCH, UBS, Beads, Agent Mail).

---

## The Adversarial Test Connector

`connectors/_adversarial/` is a deliberately hostile connector binary used as a conformance fixture. It probes:

- **Hostile response shapes** — ten `AdversarialScenario` variants exercising malformed and hostile provider responses through the connector protocol surface.
- **Boundary declarations** — an impossible egress target (`adversarial.invalid` with 1 ms timeouts), forbidden capabilities (`network.*`, `system.exec`), and a strict sandbox profile (16 MiB / 5% CPU / 1 s wall clock, `deny_exec`, `deny_ptrace`), proving the sandbox and network guardrails hold at the manifest boundary.
- **Production-mode refusal** — the fixture fails closed when invoked outside the conformance harness.

The host MUST refuse to start, isolate, or interact with this connector at the appropriate boundary for each probe. Conformance tests under `crates/fcp-conformance/tests/` use the adversarial connector as the "what should fail" half of their assertions.

It plays the same role as a `:memory:` SQLite database in a database project: not a production artifact, but a fixture that proves the production code's invariants under hostile conditions.

---

## Why Mesh-Native? (Philosophy)

The host-first path is operational today and it works. So why converge on a mesh-native steady state at all?

**Trust commingling.** A "single host" model puts every connector on the same machine. If a message from a public Discord channel can reach a private Gmail action, the boundary between them is "the host decided it was OK." In a mesh-native model, the public-zone connector binary literally cannot decrypt the private-zone keyring; the cryptographic boundary exists at rest, not just at the policy layer.

**Sovereignty.** A single host is a single point of failure, a single point of subpoena, and a single thing a vendor can lock you out of. A mesh of your own devices is none of those things. The data lives where you live; the compute happens where you compute; the keys exist as threshold shares across your hardware.

**Offline resilience.** A single-host model treats "the host is down" as a hard outage. A mesh model treats it as "we lost one of N peers; placement policy is degraded; repair controller is scheduling work." This is the same shift cloud distributed systems made in 2008–2012, applied to personal infrastructure.

**Auditability across boundaries.** A single host produces one audit chain. A mesh produces an audit chain *per zone, per node*, with quorum-signed heads that detect divergence. Tampering with one device's audit log is detectable from any other device that has corresponded with it.

**Symbol-based data.** A single host has files. A mesh has symbol-encoded objects whose availability is graded by coverage_bps. The difference matters when a device goes offline mid-operation, a partition heals, or a peer joins late.

None of these are theoretical. The mesh infrastructure is built and tested in `fcp-mesh`, `fcp-store`, `fcp-raptorq`, `fcp-tailscale`, and `fcp-protocol`. What remains is production evidence: proof that mesh-backed truth is actually safer to elevate as the default than host-backed truth, measured across real-world partition patterns and device-churn rates. The cutover gates in [`docs/FCP3_Transition_Scorecard.md`](docs/FCP3_Transition_Scorecard.md) define what "ready" means.

---

## Sandbox Profiles

`fcp-sandbox` supports profile-based sandbox configuration. A connector's manifest selects a `SandboxProfile`; the host applies the corresponding OS-level enforcement. The enum lives in `crates/fcp-manifest/src/lib.rs`:

| Profile | Posture | Typical Use |
|---------|---------|-------------|
| `Strict` | No FS write outside `$CONNECTOR_STATE`; no exec; no ptrace; manifest-declared egress only; SNI enforced | Standard request-response REST connectors |
| `StrictPlus` | Strict baseline plus mandatory SPKI pinning, stricter timeouts, no shared state across instances | Financial, credential-handling, AI-API connectors |
| `Moderate` | Allows controlled child processes (e.g. `git`, `kubectl`) with their own sandbox profiles; FS write restricted to staging dir | CLI/process archetype connectors that need to spawn provider binaries |
| `Permissive` | Used only by `connectors/_adversarial/` and explicit incubation crates | Never in production |

Per-OS enforcement:

- **Linux**: seccomp filters + Landlock LSM for FS, `unshare` namespacing, capability dropping. Egress proxy enforces network constraints; raw sockets blocked unless manifest declares.
- **macOS**: seatbelt profiles generated from manifest, codesign verification, sandbox-exec wrapping.
- **Windows (Tier 2)**: AppContainer + integrity-level lowering. Not yet hardened to Tier 1.
- **WASI**: capability-gated hostcalls via `wasmtime` and `wasmtime-wasi`; deterministic clocks; network socket gating; environment isolation. Recommended profile for high-risk connectors due to memory isolation and cross-platform consistency.

---

## OpenTelemetry OTLP Integration

The audit chain emits OpenTelemetry parity exports via the `fcp-telemetry` OTLP exporter. The wire schema lives at `crates/fwc/schemas/audit_otlp_span.schema.json` and a golden span fixture lives at `crates/fwc/tests/fixtures/audit_otlp_parity/golden_accepted_span.json`. The contract test `crates/fcp-conformance/tests/audit_otlp_hlc_contract.rs` pins the required HLC attribute shape so a future refactor cannot silently drop or rename them.

The four HLC attributes are required on every emitted span:

| Attribute | Type | Meaning |
|-----------|------|---------|
| `fcp.audit.entry.hlc` | string | Combined `"<physical_ms>.<logical>"` form, e.g. `"1747363200000.7"` |
| `fcp.audit.entry.hlc.l` | integer | Physical component in milliseconds (must equal `start_time_unix_nano`) |
| `fcp.audit.entry.hlc.c` | integer | Logical counter |
| `fcp.audit.entry.hlc.node_id` | string | Stable node identifier that produced the entry |

Additional invariants enforced by the contract test:

- `start_time_unix_nano` on the span must equal `fcp.audit.entry.hlc.l`.
- The combined `fcp.audit.entry.hlc` string must equal `"{l}.{c}"`.
- All four attributes must be listed in the schema's `required` array and present in the `properties` object.

The exporter has backpressure proof, timeout proof, and retry harness coverage. The `fwc telemetry otlp-readiness` command verifies endpoint reachability before relying on the export path. The full attribute taxonomy beyond HLC (zone, connector, operation, capability, principal, idempotency key, audit seq, hier_vv frontier) is defined alongside the HLC attributes in `audit_otlp_span.schema.json`; consult that schema directly for the authoritative list.

---

## Anti-Amplification and Backpressure

The mesh layer enforces two related properties that together prevent a hostile or buggy peer from consuming an unbounded share of a node's resources.

### Anti-Amplification

A node enforces an upper bound on the ratio of response symbols to request symbols, so a peer cannot trick the node into amplifying a small request into a much larger reply (the classic DDoS-reflection attack pattern). The default amplification factor is `DEFAULT_AMPLIFICATION_FACTOR = 10` in `crates/fcp-mesh/src/admission.rs`: responses can be at most 10× the request size. The ratio is configurable per-peer via `AdmissionPolicy::max_amplification_factor`.

A peer that sends a 100-symbol request can therefore receive at most 1000 symbols in response. A reply that would exceed the cap surfaces an `AdmissionError::AmplificationViolation` with the request and response symbol counts attached. The cap applies at the admission layer, before the control-plane logic composes a large reply, so a bug in higher-level code that would otherwise return a 50 MB blob to a 100-byte ping is refused before it reaches the wire. The same admission controller also rejects with neighboring variants from the same enum: `ByteBudgetExceeded`, `SymbolBudgetExceeded`, `AuthFailureBudgetExceeded`, `DecodeCapacityExceeded`, `DecodeCpuBudgetExceeded`, `AuthenticationRequired`, `ObjectQuarantined`, or `QuarantineQuotaExceeded`, depending on which guard the request trips first.

### Per-Peer Resource Budget

The `PeerBudget` struct in `crates/fcp-mesh/src/admission.rs` defines per-peer per-minute resource limits. Defaults reflect production-scale workloads:

| Field | Default | Purpose |
|-------|---------|---------|
| `max_bytes_per_min: u64` | 64 MiB (`67 108 864`) | Inbound bandwidth ceiling from this peer |
| `max_symbols_per_min: u32` | 200 000 | Symbol-rate ceiling (separate from bytes so chatty small-symbol peers can't evade the byte budget) |
| `max_failed_auth_per_min: u32` | 100 | Failed-auth threshold before the peer is temporarily blocked |
| `max_inflight_decodes: u32` | 32 | Concurrent RaptorQ decodes attributed to this peer |
| `max_decode_cpu_ms_per_min: u64` | 5 000 | Decode-CPU budget (so a peer cannot force expensive decodes ad-infinitum) |

Budgets are renewed via token buckets (the same `fcp-ratelimit` primitives connectors use) so transient bursts are absorbed without sustained overuse being possible. The conformance test `host_enforcement_pipeline_outcome_conformance.rs` exercises the rejection paths.

### Backpressure Propagation

When a receiver's per-peer budget is exhausted, admission rejects further requests; the sender's invoke surface returns the corresponding error rather than blocking indefinitely. Streaming connectors propagate backpressure end-to-end: if the external provider's SSE stream slows down, the connector's `StreamHealthTracker` transitions to `Degraded`, the host surfaces the degraded state on subsequent `health` and `status` queries, and the caller's I/O stalls naturally without dropping bytes.

The mesh layer also re-prioritizes traffic under partial congestion: priority gossip for revocation push and audit-head checkpoints uses its own admission lane (`priority_gossip_interval_ms` in `GossipConfig`, default 100 ms; `max_revocation_push_peers` default 32), so a node under denial-of-service from one peer can still gossip its revocations and audit heads to all other peers.

---

## Cancellation Propagation

Cancellation in FCP is a first-class control signal that flows end-to-end. The contract: when a caller cancels, every downstream operation should stop within a bounded time, no orphaned external side effects should occur, and any partial work should be either rolled back or recorded as a half-completed receipt for forensic purposes.

The flow:

```
Caller (fwc)                  fcp-host                   Connector              External API
   │                             │                          │                       │
   ├── invoke ──────────────►    │                          │                       │
   │   ctx: CancellationToken    │                          │                       │
   │                             ├── dispatch ──────────►   │                       │
   │                             │   ctx: nested token       │                       │
   │                             │                          ├── HTTP ─────────────► │
   │                             │                          │                       │
   ├── Ctrl-C  ────────────►     │                          │                       │
   │   ── cancel ───────────►    │                          │                       │
   │                             │── deadline reaper ─────► │                       │
   │                             │   force-terminates on    │                       │
   │                             │   expiry (forced=true)   │                       │
   │                             │                          │                       │
   │                             │                          ├── dies mid-request    │
   │   invoke fails (killed) ──► │                          │                       │
   │                             ├── record receipt with    │                       │
   │                             │   outcome=cancelled,     │                       │
   │                             │   external_effect=       │                       │
   │                             │   { sent: yes, ack: no } │                       │
   │◄── Cancelled ───────────────┤                          │                       │
```

Three properties of the cancellation machinery are worth pointing at:

- **Bounded propagation latency.** The host's `cancellation.rs` module (`crates/fcp-host/src/cancellation.rs`) tracks cancellation per operation owner, records outcomes (`Cancelled`, `Pending`, `TooLate`) with 24-hour checkpoints, and emits audit events for every transition. Every subprocess-backed invoke also registers a cancellation deadline: 1 s for bounded one-shot archetypes (`request_response`, `webhook`), 10 s for long-lived archetypes (`streaming`, `bidirectional`, `polling`, and `unknown`), overridable per connector through `cancellation_deadline_ms` in the managed connector inventory. A host reaper sweeps every 200 ms; an operation that ignores its cancellation past the deadline gets its connector subprocess force-terminated (SIGTERM with a 500 ms grace, then SIGKILL) and the cancellation audit event records `outcome = cancelled` with `forced = true`. Failed force-terminates are re-armed and retried by the next sweep, and the tracking entry is released only by the regular invoke-completion path, so a forced cancel never releases a Strict-idempotency `OperationIntent` (`flywheel_connectors-861lx`). A connector subprocess additionally self-terminates on parent-pid drop.
- **Idempotency on retry.** A cancelled operation produces a receipt with `outcome = cancelled` and `external_effect` flags (`sent: yes/no`, `ack: yes/no/unknown`). Retries can decide whether to re-issue based on the recorded external effect rather than guessing. For `Strict` idempotency operations, the cancelled `OperationIntent` blocks naive retries until explicitly released by the caller.
- **No orphaned external side effects on host crash.** If `fcp-host` itself crashes mid-invoke, the connector subprocess detects parent-pid drop (or supervisor heartbeat loss) and self-terminates. The receipt for the cancelled operation lands in the audit chain only if the connector successfully wrote it to its local state cache before exit; otherwise it remains a half-completed gap that the post-restart consistency check surfaces explicitly.

---

## The `simulate` Path: Preflight Without Side Effects

Every operation that supports it (declared in the manifest via `supports_simulate = true`) can be invoked as a preflight rather than as an actual execution. `fwc simulate <connector> <op> --file payload.json` returns the same shape as `invoke` plus a `simulation_evidence` block describing what the actual invoke would do, **without making any external calls or producing external side effects**.

The simulate path does, in order:

1. **Capability verification.** Full 14-stage enforcement pipeline (same as invoke). A simulate against an operation you don't have capability for fails the same way an invoke would.
2. **Input schema validation.** JSON schema check against the operation's declared input type.
3. **Connector-side dry run.** `connector.handle_simulate()` runs operation-specific preflight: shape-check the request URL, validate that referenced resources exist (via lookup, never via mutation), confirm rate-limit budget is available, project the expected response shape.
4. **Cost / risk projection.** Return estimated bytes-out, expected duration, and any side effects that would occur if invoked.
5. **Preflight evidence return.** Emit a simulation-mode response carrying the same trace-context attributes a real invoke would emit, plus the projected outcome and any side-effect summary. This is useful in pipelines where you want to dry-run a whole pipeline without committing.

Three invariants are enforced on `handle_simulate`: it must not make any external HTTP request that changes state, must not write to `$CONNECTOR_STATE`, and must not consume rate-limit tokens. Conformance tests enforce these properties and the `_adversarial` connector exercises violations.

The split between `simulate` and `invoke` means agents can compose multi-step pipelines (`fwc pipeline dry-run`) that verify the whole graph before any external effect occurs. If step 3 of a 5-step pipeline would fail authorization, the dry-run surfaces that *before* step 1's side effect lands.

---

## Operation Risk, Safety, and Idempotency Taxonomies

Every operation declared in a connector's manifest is classified along three independent axes. The CLI, host, and approval workflows all key off these classifications.

### `RiskLevel`: Probabilistic Impact

Defined in `crates/fcp-core/src/capability.rs`. Four values, ordered:

| Level | Meaning | Example |
|-------|---------|---------|
| `Low` | Routine read or low-impact write | `github.issues.list`, `gmail.messages.search` |
| `Medium` | Standard write or read of sensitive data | `github.issues.create`, `gmail.messages.send` |
| `High` | Significant external effect or potential data loss | `stripe.refunds.create`, `kubernetes.pods.delete` |
| `Critical` | Catastrophic if mis-invoked | `kubernetes.cluster.delete`, `cloudflare.dns.delete-zone` |

`fwc --risk-max <level>` filters discovery and tool export to operations at or below the named risk. Default risk ceiling for agent-issued tokens is `Medium`; higher requires explicit operator action.

### `SafetyTier`: Authorization Bar

A separate axis from risk: how must an agent prove it's authorized? Five values:

| Tier | Approval Required | Example |
|------|-------------------|---------|
| `Safe` | None; read-only or benign | `github.issues.list` |
| `Risky` | Policy check; may have side effects | `github.issues.create` |
| `Dangerous` | Interactive approval via the host approval flow | `stripe.charges.refund` |
| `Critical` | Quorum / elevation via threshold-signed approval | `host.connector.uninstall` |
| `Forbidden` | Never allowed under any circumstance; manifest can declare specific operations forbidden to a zone | Anything in the connector's `forbidden` set for the bound zone |

`SafetyTier` is distinct from `RiskTier` in `quorum.rs`. `SafetyTier` answers "can this agent do this?"; `RiskTier` answers "how many signatures are needed?". The two compose during approval-bundle construction.

### `IdempotencyClass`: Deduplication Guarantee

Three values:

| Class | Guarantee | When to Use |
|-------|-----------|-------------|
| `None` | No deduplication; caller responsible | True one-shot reads |
| `BestEffort` | Receipt-based dedup if same `idempotency_key` arrives within retention window | Most writes |
| `Strict` | `OperationIntent` pre-commit required; exactly-once semantics with replay-safe receipts | Financial, billing, irreversible writes |

For `Strict` operations, the caller writes an `OperationIntent` object before invoke. The intent names the `idempotency_key`. Executors check that the intent exists, then proceed. If a retry arrives with the same intent, the executor returns the existing receipt instead of re-invoking.

### `RetryDirective`: What to Do When a Call Fails

Returned by classification layers (`ConnectorErrorMapping::retry_after`, host enforcement). Four values:

| Directive | Meaning |
|-----------|---------|
| `Immediate` | Retry without waiting (e.g. transient network reset) |
| `Backoff` | Retry using the caller's configured backoff policy |
| `RetryAfter(Duration)` | Retry after the named delay (e.g. provider-supplied `Retry-After` header) |
| `Terminal` | Do not retry; surface error to caller |

`RetryDirective::parse_retry_after` handles the RFC 7231 decimal-seconds form of `Retry-After` (the private helper `parse_retry_after_duration` does the actual parse). Connectors mapping rate-limit responses (HTTP 429, provider-specific 5xx with `Retry-After`) populate this directive so the centralized `RetryLoop` in `fcp-sdk` honors the provider's advice.

---

## Operation Intent + Receipt: Exactly-Once Semantics

For operations with external side effects that genuinely cannot tolerate duplication (refund a charge, send a wire, delete an immutable record), best-effort idempotency is not enough. FCP's `Strict` idempotency class uses a pre-commit protocol that survives:

- The caller crashing mid-flight.
- The host crashing mid-flight.
- The connector subprocess crashing mid-flight.
- Network partition that causes the caller to retry against a different node.
- A duplicate retry arriving long after the original completed.

The protocol:

```
                Caller            Host            Connector       External API
                  │                │                │                 │
1. Pre-commit:    │                │                │                 │
                  ├── OperationIntent ──►            │                 │
                  │  { idempotency_key, op, args }   │                 │
                  │                │                │                 │
                  │                ├─── Sign + store ────►            │
                  │                │  (durable mesh object)           │
                  │                │                │                 │
2. Invoke:        │                │                │                 │
                  ├── invoke ─────►│                │                 │
                  │                ├─── Look up intent ────           │
                  │                │   ├── Exists?                    │
                  │                │   ├── No receipt yet? → proceed  │
                  │                │   └── Receipt exists? → return it│
                  │                │                │                 │
                  │                ├─── dispatch ──►│                 │
                  │                │                ├── effect ──────►│
                  │                │                │                 │
                  │                │◄─── result ────┤                 │
                  │                ├─── Sign + store OperationReceipt │
                  │                │   bound to the intent's UUID     │
                  │                │                │                 │
                  │◄── result ─────┤                │                 │
                  │                │                │                 │
3. Retry (any reason):             │                │                 │
                  ├── invoke (same idempotency_key) ─►                │
                  │                ├── Look up intent → receipt exists│
                  │                │── Return cached receipt; no      │
                  │                │   external effect                │
                  │◄── result ─────┤                │                 │
```

The `OperationIntent` and `OperationReceipt` are both durable mesh objects, so this protocol works across nodes during failover: if Node A wrote the intent but crashed before the receipt was signed, Node B (after HRW lease handoff) can re-read the intent, observe that no receipt exists, and complete the operation. Concurrent execution across nodes is prevented by the HRW lease itself — only the current quorum-signed lease holder is allowed to dispatch invokes for a given connector instance. A duplicate retry arriving at a non-holder is forwarded to the holder rather than executed locally.

Stripe's idempotency keys solve the same problem for external HTTP APIs; FCP's intent + receipt model generalizes the pattern into a content-addressed, signed, multi-writer-aware object model.

---

## Capability Token Anatomy

A capability token is a COSE_Sign1 envelope (RFC 9052) carrying CWT claims (RFC 8392) in deterministic CBOR. The wire format below is the operational schema; the typed claim layout lives in `fcp-auth-schema::AuthClaims` (the single source of truth consumed by both the `fcp-crypto` builder and the `fcp-core` verifier). Schema changes are deployment-gated by `schema_version`, which gets bumped only via the explicit versioning ADR process.

```
COSE_Sign1 = [
  protected: bstr .cbor {
    1 (alg):  -8,                  ; EdDSA (Ed25519); hybrid PQ deployments
                                   ; carry a sibling ML-DSA-65 signature in
                                   ; the unprotected header
    4 (kid):  bstr,                ; Issuance key ID (separately revocable)
  },
  unprotected: { ... },            ; KID-only headers; never carries claims
  payload:     bstr .cbor AuthClaims,
  signature:   bstr,               ; Ed25519 over Sig_structure
]
```

`AuthClaims` is the typed Rust struct (`crates/fcp-auth-schema/src/claims.rs`). Each field maps to a CBOR integer label in `crate::labels::{cwt_claims, fcp2_claims}`. Canonical CBOR emits only non-`None` and non-empty fields:

| Field | Type | Role |
|-------|------|------|
| `schema_version` | `u16` | Always emitted; gates deployment compatibility |
| `issuer` | `Option<String>` | CWT `iss` — in FCP this carries the zone id |
| `subject` | `Option<String>` | CWT `sub` |
| `audience` | `Option<String>` | CWT `aud` |
| `expiration` | `Option<DateTime<Utc>>` | CWT `exp` |
| `not_before` | `Option<DateTime<Utc>>` | CWT `nbf` |
| `issued_at` | `Option<DateTime<Utc>>` | CWT `iat` |
| `token_id` | `Option<Vec<u8>>` | CWT `cti` — token UUID for revocation lookup |
| `capability_id` | `Option<String>` | e.g. `"gmail.read"` |
| `zone_id` | `Option<String>` | Cryptographic zone binding |
| `principal_id` | `Option<String>` | Principal on whose behalf the token is exercised |
| `issuing_node` | `Option<String>` | Node that minted the token (separately revocable from signing key) |
| `holder_node` | `Option<String>` | Node currently holding / exercising the token |
| `audience_binary` | `Option<Vec<u8>>` | Binary audience / object id |
| `grant_object_ids` | `Vec<Vec<u8>>` | ObjectIds proving the grant chain |
| `checkpoint_id` | `Option<Vec<u8>>` | Checkpoint anchor for replay safety |
| `checkpoint_seq` | `Option<u64>` | Checkpoint sequence number |
| `instance_id` | `Option<String>` | Connector-instance binding target; `None` for `UnboundVerified`, `Some` for `BoundVerified` |
| `delegation_depth` | `Option<u64>` | Hop count for delegated tokens |
| `parent_token` | `Option<Vec<u8>>` | Parent token id for delegation chains |
| `grants` | `Vec<ciborium::Value>` | Granted capabilities (opaque CBOR here to break the `fcp-core` dep cycle; verifier decodes into `CapabilityGrant`) |
| `constraints` | `Option<ciborium::Value>` | Resource / call constraints (opaque CBOR; verifier decodes into `CapabilityConstraints`) |

The signature is verified *before* claims are parsed. The verifier calls `AuthClaims::check_schema_version` early so an unsupported `schema_version` produces a clear error rather than a confusing field-level decode failure downstream. The legacy `OPERATIONS` claim is rejected by the verifier after epic `8n0rm.6`. Revocation is checked via `token_id` for one-shot tokens, the `kid` for issuance-key revocation, the `issuing_node` for node-attestation revocation, and the `zone_id` for zone-key rotation.

The two opaque-CBOR fields (`grants`, `constraints`) exist that way deliberately: `fcp-auth-schema` is a leaf crate so the verifier doesn't depend on it transitively, and re-decoding into the typed `CapabilityGrant` / `CapabilityConstraints` is owned by `fcp-core`. This also lets a peer with an older schema decode the surface envelope even if it can't interpret the inner grant shape.

### Capability Constraints Predicate Matrix

Constraints live in `CapabilityConstraints` (`crates/fcp-core/src/capability.rs`) and are evaluated by an implementation of the `CapabilityConstraintEvaluator<Request>` trait. The matrix is exercised by `crates/fcp-core/tests/capability_verifier_predicate_matrix.rs`. The struct intentionally has a small, fixed shape rather than a free-form predicate map — easier to verify, easier to audit, no surprise extensions.

| Field | Type | Evaluation |
|-------|------|------------|
| `resource_allow` | `Vec<String>` | Resource URI pattern allowlist; the request's resource URI must match one entry |
| `resource_deny` | `Vec<String>` | Resource URI pattern denylist; the request's resource URI must NOT match any entry |
| `max_calls` | `Option<u32>` | Cap on total invocations against this token |
| `max_bytes` | `Option<u64>` | Cap on total bytes transferred under this token |
| `idempotency_key` | `Option<String>` | If set, operation must carry exactly this idempotency key |
| `credential_allow` | `Vec<CredentialId>` | **NORMATIVE** — connectors can only use credentials in this list; the egress proxy checks `CredentialId` membership before injecting credential material |

A capability token is `ConstraintsEnforced` only when the verifier has evaluated every non-empty field against the live invoke context and all returned `Allow`. The typestate transition `BoundVerified → ConstraintsEnforced` is compiler-enforced; the executor's signature requires the latter type.

**Default-deny default.** An empty `CapabilityConstraints` (all fields empty/`None`) is interpreted as **deny all** rather than "no restrictions." This is the C3.4 default-deny rule: a token that forgot to declare any resource pattern grants access to nothing. `CapabilityConstraints::is_empty()` exists precisely so callers can detect this case explicitly.

---

## Connector Lifecycle and Health

A connector instance carries two orthogonal observable values: a **lifecycle state** (where it is in the activation/run/teardown flow) and a **health state** (whether the runtime is healthy, degraded, or unavailable). The two compose: a connector can be `Running` + `Degraded`, or `Activated` + `Unavailable`, etc.

### Lifecycle State (`ConnectorLifecycleState`)

The canonical enum lives at `crates/fcp-core/src/connector.rs`. Five variants:

| State | Meaning |
|-------|---------|
| `Loaded` | Connector binary and metadata are loaded but not yet active |
| `Activated` | Connector has completed activation and is ready to run |
| `Running` | Connector is actively running |
| `Suspended` | Connector is suspended and may be resumed |
| `Terminated` | Connector has terminated and cannot resume |

The typical transition sequence is `Loaded → Activated → Running`, with `Suspended` reachable from `Running` (and back), and `Terminated` reachable from any state as a terminal sink. Activation runs the JSON-RPC `configure` + `handshake` handlers; once `handshake` returns, the host assigns the `instance_id` that enables the `UnboundVerified → BoundVerified` typestate promotion for capability tokens scoped to this instance.

### Health State (`ConnectorHealth`)

A separate enum in `crates/fcp-core/src/connector_descriptors.rs` carries the runtime health overlay:

| Health | Meaning |
|--------|---------|
| `Healthy` | Connector reports healthy runtime state |
| `Degraded { reason }` | Live but with a stated degradation (e.g. retry budget nearly exhausted) |
| `Unavailable { reason, .. }` | Cannot serve invokes right now (e.g. host offline, dependency down) |

These map to `DescriptorStatus::{ Ready, Degraded, Unavailable }` for the agent-facing discovery surface. `fwc status <connector>` surfaces both lifecycle state and health, plus the last 5 transitions.

### JSON-RPC Method Surface

Connectors implement a closed set of JSON-RPC methods. The supervisor invokes these during state transitions; agents invoke `invoke` / `simulate` / `introspect` while the connector is `Running`:

| Method | Caller | Purpose |
|--------|--------|---------|
| `configure` | Host (during `Loaded → Activated`) | Supply secrets / credential refs / runtime config |
| `handshake` | Host (during `Loaded → Activated`) | Assign `instance_id`; negotiate capabilities |
| `health` | Host (continuous) | Return current `ConnectorHealth` |
| `doctor` | Operator / host | Run diagnostics; return remediation hints |
| `self_check` | Host (pre-invoke gates) | Verify the connector can serve the next operation |
| `introspect` | Agent / fwc | Return manifest + live operation metadata |
| `invoke` | Agent / fwc (via host) | Execute an operation; return result + receipt |
| `simulate` | Agent / fwc (via host) | Dry-run an operation; return preflight evidence |
| `shutdown` | Host (during `Running → Terminated`) | Graceful drain |

The supervisor enforces exponential backoff (guarded against NaN and zero-initial edge cases per commit `d381c424`) when re-running `configure` after a crash. State transitions are recorded as audit events.

---

## Provider Auth Flow Walkthroughs

`fcp-provider-auth` consolidates seven auth methods. Two of them are subtle enough to warrant a walkthrough.

### OAuth Device-Code Flow (Headless Agents)

Used by AI agents that don't have an interactive browser. The flow is RFC 8628 OAuth Device Authorization Grant.

```
                                              fcp-host       Provider
                                              │              │
1. fwc auth login <provider> --oauth-device   │              │
   --client-id ...                            │              │
                                              ├─── POST /device/code ──►│
                                              │                         │
                                              │◄─── { device_code,      │
                                              │      user_code,         │
                                              │      verification_uri,  │
                                              │      interval, expires_in } ─│
2. fwc prints: "Visit                         │
   https://provider.com/device                │
   and enter code ABCD-1234"                  │
                                              │
3. User visits URL in any browser             │
   on any device and approves                 │
                                              │
4. fwc auth login-poll <profile>              │
                                              ├─── POST /token ──►      │
                                              │    grant_type=...       │
                                              │    device_code=...      │
                                              │                         │
                                              │◄─── { access_token,     │
                                              │      refresh_token,     │
                                              │      expires_in } ──────│
                                              │
5. Host stores credentials in pool,           │
   returns AuthProfile id to fwc              │
                                              │
6. fwc uses AuthProfile in subsequent invokes │
```

### OAuth Authorization-Code with PKCE (Interactive)

Used by interactive operators. PKCE (RFC 7636) protects against authorization-code interception even without a client secret. The fwc surface is `fwc auth login <provider> --oauth-auth-code ...` to start the flow and `fwc auth login-complete <profile>` to finish it after the redirect arrives.

```
1. fwc auth login <provider> --oauth-auth-code --client-id ... ...
   ├── Generate code_verifier (43-128 random chars)
   ├── Compute code_challenge = BASE64URL(SHA256(code_verifier))
   └── Open browser to authorize URL with code_challenge

2. User authorizes in browser
   └── Provider redirects to localhost:RANDOM with ?code=AUTH_CODE

3. fwc auth login-complete captures the redirect
   via the ephemeral localhost listener

4. fwc → fcp-host:
   ├── POST /token with grant_type=authorization_code
   │   ├── code=AUTH_CODE
   │   └── code_verifier=ORIGINAL_VERIFIER
   └── Provider verifies SHA256(code_verifier) == code_challenge

5. Host receives tokens, stores in credential pool
```

The credential pool's strategy determines what happens when this AuthProfile is leased: round-robin if multiple equivalent profiles exist, sticky-restick if the previous lease holder has a hot connection, max-use to retire heavily-used credentials before they trigger provider rate limits.

---

## Pipeline and Recipe DSL

`fwc` ships a TOML-based pipeline DSL for multi-step operation composition with dependency ordering. Recipes are pre-bundled, reusable pipelines.

### Pipeline TOML

The on-disk schema lives in `crates/fwc/src/pipeline*.rs`. The example below uses real operation IDs from the GitHub and Slack connector manifests (`github.search_issues`, `github.create_issue`, `slack.post_message`) so the snippet runs against the actual connectors; test fixtures under `crates/fwc/testdata/pipelines/` exercise the same schema with synthetic operation IDs that exist only for the in-tree harness.

```toml
[pipeline]
name = "notify-on-new-issues"
description = "Watch a GitHub repo and post new issues to Slack"
version = "0.1.0"

[[steps]]
id = "list_existing"
operation = "github.search_issues"
input = { owner = "{{params.owner}}", repo = "{{params.repo}}", state = "open" }

[[steps]]
id = "create_issue"
operation = "github.create_issue"
depends_on = ["list_existing"]
input = { owner = "{{params.owner}}", repo = "{{params.repo}}", title = "{{params.title}}", body = "{{params.body}}" }

[[steps]]
id = "notify"
operation = "slack.post_message"
depends_on = ["create_issue"]
input = { channel = "{{params.channel}}", text = "Created issue {{steps.create_issue.output.number}} for {{params.repo}}" }

[params.owner]
type = "string"
required = true

[params.repo]
type = "string"
required = true

[params.title]
type = "string"
required = true
```

Notes on the actual schema:

- `[pipeline]` carries `name`, `description`, `version`.
- Each `[[steps]]` table carries an `id`, a dotted `operation` (`<connector>.<operation>`), an `input` table, and an optional `depends_on` array naming sibling step IDs. Per-step `continue_on_error` is supported.
- Parameters are declared as `[params.<name>]` tables with `type` and `required` fields.
- Template substitution uses double-brace `{{...}}` syntax. Step outputs are referenced as `{{steps.<id>.output.<json_path>}}`; parameters are referenced as `{{params.<name>}}`.

Pipelines are validated with `fwc pipeline validate <file>`, dry-run with `fwc pipeline dry-run`, and executed with `fwc pipeline run`.

### Recipes

A recipe is just a pipeline packaged with metadata and named parameters:

```bash
fwc recipe list
fwc recipe show github-pr-review-notify
fwc recipe dry-run github-pr-review-notify --param owner=octocat --param repo=hello-world
fwc recipe export github-pr-review-notify > .fwc/pipelines/custom.toml
```

The export lets operators copy a recipe to a local pipeline file and customize it.

### Pipes (Single-Step Adapters)

For one-shot adapters, `fwc pipe` chains two operations without a TOML file:

```bash
fwc pipe github.search_issues slack.post_message \
    --map 'title -> text, html_url -> blocks[0].url'
```

Pipes are the imperative shorthand; pipelines and recipes are the declarative form.

### Batch Files (Heterogeneous Operations)

`fwc batch-file` executes a JSONL file of arbitrary operations with optional dependency ordering:

```jsonl
{"id":"a","connector":"github","operation":"issues.create","inputs":{...}}
{"id":"b","connector":"slack", "operation":"messages.send","needs":["a"],"inputs":{...}}
```

```bash
fwc batch-file operations.jsonl --dry-run
fwc batch-file operations.jsonl
```

---

## CRDT-Backed Multi-Writer Connector State

Connectors declaring `singleton_writer = false` can take advantage of CRDTs (Conflict-free Replicated Data Types) for state that legitimately admits concurrent writes. The supported types live in `crates/fcp-core/src/crdt.rs`:

| CRDT | Building Block | Use Case | Convergence Property |
|------|---------------|----------|----------------------|
| `GCounter` | Per-actor `u64` counters keyed by `CrdtActorId` | Monotonic counters (events seen, bytes sent) | Merge = per-actor `max` |
| `PnCounter` | Pair of `GCounter`s (positive, negative) | Increment/decrement counters (quota balance) | Difference of the two G-Counters |
| `OrSet<T>` | Add-tagged elements with `OrSetTag` for observed-remove semantics | Sets that admit concurrent add + remove | Adds and tombstones merge by tag; presence iff some add tag is not tombstoned |
| `LwwMap<K, V>` | Map of `LwwEntry<V>` (value + HLC timestamp) | Sparse config, preferences, label sets | Per-key last-write-wins with HLC tie-breaking |

`CrdtActorId` is the per-writer identifier (typically derived from the node identity) that prevents two writers from clobbering each other's contribution to the same `GCounter`. `LwwEntry` is the value-level building block of `LwwMap` — every entry carries the HLC of the write that produced it, and merge picks the entry with the higher HLC.

CRDT state externalizes as `ConnectorStateObject` chains with the merge function declared in the manifest. The host applies merges deterministically on every read; operators see the merged view through `fwc status <connector> --state`.

Singleton-writer connectors (declared via `singleton_writer = true`) bypass CRDTs and use HRW leases instead — appropriate for cursors and dedup caches where divergent writes would be a bug, not a feature.

---

## Computation Migration and Failover

Connectors with long-running operations (an LLM streaming response, a batch upload, a real-time WebSocket session) can be migrated across nodes without restarting from scratch. The state is modeled by `MigratableComputation` and `MigratableComputationState` (`crates/fcp-core/src/connector_state.rs`); the kernel-side migration logic lives in `crates/fcp-kernel/src/computation_migration.rs`.

`MigratableComputationState` transitions through three phases: `Running → Suspended → Transferring`. The migration is **application-level**, not OS-level — there's no kernel-process checkpoint involved. The connector itself declares what its serializable state is (cursor positions, partial response buffer, dedup caches), the host serializes that state into a signed checkpoint object, and the target node deserializes and resumes from the same logical point.

```
NODE A (current holder)                NODE B (target holder)
│                                      │
├─ Operation in progress               │
│  ├─ Active capability lease          │
│  ├─ Open WebSocket / HTTP stream     │
│  └─ Partial response buffer          │
│                                      │
├─ Migrate trigger                     │
│  (lease expiring; planned drain;     │
│   higher placement score; failure)   │
│                                      │
├─ Phase 1: Suspend                    │
│  ├─ MigratableComputationState       │
│  │  → Suspended                      │
│  ├─ Stop accepting new bytes         │
│  └─ Drain in-flight to a quiescent   │
│     application-layer checkpoint     │
│                                      │
├─ Phase 2: Application checkpoint     │
│  ├─ Connector emits serialized       │
│  │  state (cursor, partial buffer,   │
│  │  protocol-level seq numbers)      │
│  ├─ Host wraps as ConnectorState     │
│  │  Object signed by Node A          │
│  └─ State transitions to             │
│     Transferring { ... }             │
│                                      │
├─ Phase 3: Symbol-encode + place      │──── RaptorQ symbols ────►│
│  └─ Distribute via mesh; placement   │                          │
│     policy targets B + ≥ K' coverage │                          │
│                                      │                          │
├─ Phase 4: Lease transfer             │◄─── HRW lease handoff ──►│
│  └─ Quorum-signed lease re-issued    │                          │
│     to B                             │                          │
│                                      │                          │
│                                      │  Phase 5: Resume         │
│                                      │  ├─ Reconstruct from     │
│                                      │  │  K' symbols           │
│                                      │  ├─ Verify Node A's      │
│                                      │  │  signature on the     │
│                                      │  │  checkpoint object    │
│                                      │  ├─ Pass state to        │
│                                      │  │  connector.resume()   │
│                                      │  ├─ Re-open external     │
│                                      │  │  stream from saved    │
│                                      │  │  byte offset N        │
│                                      │  └─ Continue invoke      │
│                                      │
└─ Retire instance on A                │  ContinueResponse to     │
  (Terminated)                         │  the caller from B       │
```

The closeout proofs (`crates/fcp-e2e/tests/computation_migration_reference.rs` and `crates/fcp-e2e/tests/computation_migration_unplanned_e2e.rs`) verify byte-equivalent completion for planned handoff and unplanned source loss: the final response delivered by Node B matches what Node A would have produced if migration had not occurred. Because the checkpoint is application-level, the migration is *cross-platform*: a `Running` operation on Linux can resume on macOS as long as both have the same connector binary and manifest hash. There is no OS-process snapshot to keep architecturally compatible.

Automatic optimal-device execution (let the planner decide which node should hold a long-running operation) is still hardening, but the planned and unplanned checkpoint-resume migration primitives are proven.

---

## Per-Zone Audit Chains

Audit is *per zone*, not per host. Every zone has its own hash-linked chain with its own monotonic sequence numbers, its own HLC frontier, and its own quorum-signed heads. This matters when:

- A device participates in multiple zones (e.g. `z:work` and `z:private`). The two chains are cryptographically independent.
- A device leaves a zone (revocation, decommission). The remaining members continue their chain; the removed device's audit view is a frozen historical snapshot, not a live tail.
- A zone is split or merged. Chain heads carry the original zone identity; provenance during a zone restructure is auditable.

The `ZoneCheckpoint` object summarizes a zone's audit + policy + revocation state for fast sync. The struct is declared in `crates/fcp-core/src/audit.rs`:

| Field | Type | Role |
|-------|------|------|
| `header` | `ObjectHeader` | Provenance + retention + refs |
| `zone_id` | `ZoneId` | Which zone this checkpoint summarizes |
| `rev_head` | `ObjectId` | Hash of the latest revocation head (NORMATIVE) |
| `rev_seq` | `u64` | Revocation chain sequence number |
| `audit_head` | `ObjectId` | Hash of the latest audit head (NORMATIVE) |
| `audit_seq` | `u64` | Audit chain sequence number |
| `zone_definition_head` | `ObjectId` | Hash of the active zone-definition object |
| `zone_policy_head` | `ObjectId` | Hash of the active policy bundle |
| `active_zone_key_manifest` | `ObjectId` | Currently active `ZoneKeyManifest` (V3 or V4) |
| `checkpoint_seq` | `u64` | Monotonic per-zone checkpoint sequence (NORMATIVE) |
| `as_of_epoch` | `EpochId` | Logical epoch under which the snapshot was taken |
| `quorum_signatures` | `SignatureSet` | Quorum signatures (Byzantine-resilient n/f model) |
| `revocation_freshness_sla_secs` | `u64` | Max age (seconds) of the revocation frontier before the zone enters DEGRADED state. Operations with `RevocationFreshnessClass::Critical` MUST abort when this SLA is breached. |

The checkpoint also acts as the **single GC root** for the zone: reachability garbage collection starts from the checkpoint's tracked heads and walks the object graph; anything unreachable becomes a quarantine GC candidate. This is why having one quorum-signed authoritative checkpoint per zone matters — the system's "what is live data" question reduces to "what does the latest checkpoint reach."

A peer asking "are you caught up with this zone?" sends its own checkpoint; the other peer responds with the delta. The masked-IBLT anti-entropy round only needs to run on the actual divergence, not the full chain.

---

## Why Deterministic CBOR Instead of Protobuf or JSON?

A signature is over a byte string. If two implementations encode the same logical object to different bytes (different map ordering, different integer width, different floating-point representation), the signature is only valid for one of them. JSON's "anything goes" specification, protobuf's lax encoding rules, and msgpack's optional fields all fail this test in subtle ways. RFC 8949 §4.2 specifies exactly how to encode each value, and `fcp-cbor` enforces it: same logical input, identical bytes, every time, every platform.

CBOR is also self-describing. Protobuf requires a schema to decode anything; the wire format is just tags and lengths. With CBOR, an unknown blob can be decoded into a generic value tree, inspected, and re-encoded without ever having seen the schema. A peer that receives an object signed by a newer version of FCP can still verify the signature, even if it does not recognize every claim.

CBOR is also roughly 2× more compact than JSON for typical FCP payloads (smaller for binary-heavy ones), comparable to protobuf, and trivially round-trips to JSON for debugging via `ciborium`'s `Value` type. Signed objects on the wire are binary; the same objects in a developer log are human-readable.

The same logic motivates the choice of *canonical CBOR* over generic CBOR: every layer above signing (host, registry, audit, mesh) re-serializes objects on retrieval, and canonical encoding guarantees those re-serializations match the originals byte-for-byte.

---

## The Zone Lattice in Detail

The five-zone hierarchy (`z:owner > z:private > z:work > z:community > z:public`) is a lattice ordered by *trust*. Two labels — *integrity* and *confidentiality* — flow in opposite directions through this lattice. The mathematics governs every cross-zone operation.

**Integrity flows downward.** Data signed by `z:owner` can be trusted by `z:work`; data signed by `z:public` cannot be trusted by `z:work` without proof. The integrity label tracks the *lowest-trust source* a piece of data has ever passed through — once `EXTERNAL_INPUT` taints a value, the value cannot be elevated to `z:owner` without an explicit `ApprovalToken` proving a sanitizer cleared the relevant taints.

**Confidentiality flows upward.** Data in `z:private` (your personal Gmail) must not appear in `z:public` (a Discord channel) without explicit declassification. The confidentiality label tracks the *highest-sensitivity source* a piece of data has ever combined with — derived values inherit the maximum confidentiality of their inputs.

**Merge rule.** When combining data from sources A and B:

```
merged.integrity      = min(A.integrity, B.integrity)
merged.confidentiality = max(A.confidentiality, B.confidentiality)
```

This is sound: the merge cannot pretend either input was more trusted than it was, and cannot pretend either input was less sensitive than it was. A worked example:

```
Input A:  Gmail inbox     integrity=80 (z:private)  confidentiality=80
Input B:  Discord message integrity=20 (z:public)   confidentiality=20

Merged:                   integrity=20               confidentiality=80
```

The merged value cannot be written to `z:public` (confidentiality 80 > 20) and cannot be used in a `z:private` action that requires integrity ≥ 80 (integrity is now 20 because of the Discord input). To use it as if it were trustworthy, an ApprovalToken from a sanitizer capability (URL scanner, schema validator) must clear the relevant taint reductions.

The Lean proof at `lean/Fcp/Zone/Lattice.lean` verifies the underlying single-level zone-flow soundness (no allowed flow downgrades a secret, no leak is reachable from a passing zone check). The full (integrity, confidentiality) merge rule and the proof-carrying `ApprovalToken` label adjustments are implemented in `fcp-core`'s provenance machinery; they are not separately mechanized in the current Lean file.

---

## Test Methodology

The 60,000+ tests across the workspace fall into seven distinct methodologies, each catching a different class of bug.

### 1. Unit Tests (`#[cfg(test)]` in every crate)
Standard Rust unit tests covering individual function correctness, edge cases (empty input, max values, boundary conditions), and error paths. Every component crate contains them inline.

### 2. Integration Tests (`crate/tests/*.rs`)
Larger tests that exercise multiple modules together but stay within one crate's boundary. Connector integration tests use `wiremock` to mock HTTP services; they cover lifecycle, every operation's happy path, and error mapping.

### 3. Conformance Tests (`crates/fcp-conformance/tests/`)
Cross-crate tests that pin behavioral contracts. Golden vectors for canonical CBOR, manifest hashes, protocol frames, and signing transcripts. Forward-only ratchets (typestate enforcement, mock-leakage absence, manifest-operations conformance) that *prevent regression* — the test fails if any new code violates the property.

### 4. End-to-End Scenarios (`crates/fcp-e2e/tests/`)
Host-backed scenarios with real `fcp-host`, real connector subprocesses (or test-doubles built into `fcp-testkit`), real `fwc` invocations, real audit chains. Examples: `capability_enforcement_concurrent_e2e.rs`, `revocation_cascade_e2e.rs`, `offline_repair_e2e.rs`, `secretless_github_e2e.rs`, `computation_migration_reference.rs`.

### 5. Fuzz Targets (`fuzz/`)
Coverage-guided fuzzing via `cargo fuzz`. 100+ targets across CBOR parsing, crypto primitives, protocol framing, webhook signature paths, OAuth state machines, streaming buffer handling, mesh gossip ingress, host enforcement, RaptorQ symbol injection, IBLT decode. Every target runs to a coverage plateau plus a soak period; corpus files are checked into the repo.

### 6. Metamorphic Tests
For systems with the oracle problem (where the "correct output" is unknown but input-output relationships are predictable). Examples in `fcp-crypto`: HPKE cross-ciphertext swap (swapping two ciphertexts must produce two corrupt decryptions, not one good + one bad), Ed25519 context-sign (signing the same message with different contexts must produce different signatures). In `fcp-raptorq`: random-loss invariants, duplicate-symbol invariants. In `fcp-protocol`: encode → decode → re-encode must produce byte-equal output (round-trip stability).

### 7. Chaos Engineering (`crates/fcp-chaos/`, `scenarios/`)
Deliberately-injected faults: network partitions, clock skew, message drop, message reorder, byzantine peer behavior, slow-loris attacks, disk-full conditions, OOM, supervisor restart loops. Deferred chaos plans are recorded under `chaos-results/`, which is generated at runtime and intentionally not committed (`.gitignore`); results feed back into hardening for fail-closed sites and admission control tuning.

The conformance + ratchet + chaos combination produces a property the project relies on: **once a security property holds, it stays holding**. The 2026-05-02 swarm session's 5/5 REVIEW MODE catch rate on same-day P1 findings is a direct consequence — the ratchet conformance tests catch regressions that human review would miss in a 168-bead session.

---

## Connector Provisioning Automation

A core design rule: if something CAN be automated, it SHOULD be. Operators should not have to:
- Manually create Telegram bots via BotFather.
- Manually configure OAuth redirect URLs.
- Manually copy-paste API keys between systems.
- Manually set up webhook endpoints.

The provisioning automation surfaces vary by provider but share a common shape:

| Step | What FCP Does | Operator-Visible |
|------|---------------|------------------|
| **Discover** | Inspect the manifest's `[provisioning]` section to find what is needed | `fwc show <connector>` and `fwc ops <connector>` surface the declared requirements |
| **OAuth dance** | Run device-code or PKCE flow; capture tokens; store in pool | Browser opens once; tokens live in credential pool, never in env vars |
| **Webhook endpoint** | Allocate a public endpoint via tailnet funnel or registered domain; register signing key | `webhook_url` and `signing_secret` recorded in connector config |
| **Bot creation** | For Telegram/Discord etc., invoke the provider's bot-creation API | Bot token in credential pool |
| **Self-test** | Call `connector.handle_doctor()` to verify the setup end-to-end | Doctor output shows green checkmarks; first invoke is gated until doctor passes |

The shape is intentionally repetitive across providers so the operator's mental model stays simple. Manual prompts only appear for information that truly requires human input (e.g. "which Google account?", "which Slack workspace?").

---

## Single Source of Truth Per Domain

Every concept has exactly one home crate. When the rule is violated, the violation gets tracked as tech debt and migrated. The current ownership map:

| Domain | Owner Crate | Why It Lives There |
|--------|-------------|--------------------|
| Capability-token claim schema | `fcp-auth-schema` | Both the builder (`fcp-crypto`) and the verifier (`fcp-core`) must agree byte-for-byte on the claim layout. A leaf crate that neither depends on the other is the only way to break the dep cycle. |
| Connector manifest format | `fcp-manifest` | Read by `fcp-host`, `fcp-registry`, `fcp-conformance`, and every connector test. Single owner keeps `manifest.toml` semantics consistent across consumers. |
| Deterministic CBOR | `fcp-cbor` | Every signed object passes through it. Canonical encoding must produce the same bytes from any caller. |
| Zone / capability / provenance vocabulary | `fcp-policy` (long-term home), currently `fcp-core` | The "what is a zone? what is a capability? what is provenance?" set of types. Migrated from `fcp-core` to `fcp-policy` via re-export-first migration. |
| Execution semantics / lifecycle | `fcp-kernel` (long-term home), currently `fcp-core` | Runtime context, lifecycle, invocation, cancellation, budgets, computation migration. |
| Receipt / intent / revocation / checkpoint / attestation | `fcp-evidence` (long-term home), currently `fcp-core` + `fcp-audit` | Anything that exists to prove something happened. |
| Mesh framing + transport | `fcp-protocol` + `fcp-mesh` | FCPC/FCPS encoding and the gossip/admission/lease layer. |
| Object durability | `fcp-store` + `fcp-raptorq` | Symbol storage, repair, GC, fountain coding. |
| Identity and ACLs | `fcp-tailscale` | Mesh identity, peer discovery, ACL/tag mapping. |
| Hardware-crypto adapters | `fcp-bootstrap` | PKCS#11 adapter (cryptoki), hardware-token PIN, recovery phrases; keeps `fcp-crypto` free of OS-specific deps. |
| Post-quantum primitives | `fcp-crypto` | X-Wing KEM and ML-DSA-65 live alongside the classical suite, sharing the envelope/constant-time/zeroize machinery. Lattice-trapdoor delegation is isolated in `fcp-crypto-pq` as a research surface pending `kyopb.1.3.1.1`. |
| Provider-specific auth | `fcp-provider-auth` | API key + SigV4 + OAuth flows + token refresh, consumed by every connector that needs more than a bare bearer token. |
| OpenAI-compatible client | `fcp-openai-compat` | Shared by every provider that speaks OpenAI's `/v1/chat/completions` shape. |
| Voice-call primitives | `fcp-voice-call` | `CallAuthToken`, `SessionStore`, replay cache shared across Twilio/Telnyx/Plivo. |
| Connector SDK ergonomics | `fcp-sdk` | `ConnectorRuntime`, `RetryLoop`, `ConnectorErrorMapping`, archetype-specific helpers. |

The rule extends to operational data too: every external state has exactly one trusted source. Live connector inventory lives at `FCP_HOST_CONNECTORS_FILE`; live admin state lives at `FCP_HOST_LIFECYCLE_STATE_FILE`; live capability tokens live in the credential pool registry, not in env vars; live audit truth lives in the per-zone hash-linked chain, not in scattered log files. When two places appear to carry the same truth, one is the cache and the other is the authority; the truthful-runtime-resolution layer in `fwc/src/truth.rs` makes which is which an explicit, observable property.

---

## The FCP CDDL Schema

CBOR Data Definition Language (CDDL, RFC 8610) is the schema language for canonical CBOR. The repository ships [`FCP_CDDL_V2.cddl`](FCP_CDDL_V2.cddl) at the root — a wire-level schema describing every object that travels on FCPC and FCPS streams. CDDL is what protobuf's `.proto` files are for protobuf: a single language-neutral definition that:

- **Validates** any candidate CBOR blob against the expected shape.
- **Documents** the wire format in a form other implementations can read.
- **Generates** test vectors deterministically (CDDL-conforming random byte strings).

The CDDL schema is the authoritative wire-level definition. The Rust structs in `fcp-auth-schema`, `fcp-core`, `fcp-mesh`, and `fcp-audit` exist to *implement* the CDDL contract for one language; an implementation in another language (Go, Python, Swift) would derive its types from the same CDDL and interoperate with this Rust implementation byte-for-byte.

When the CDDL and the Rust structs disagree, the CDDL is the spec and the Rust structs have a bug. Conformance tests in `fcp-conformance` validate both: golden CBOR fixtures must parse under the Rust structs AND validate against the CDDL.

---

## Manifest Validation Pipeline

A connector's `manifest.toml` passes through a multi-stage validation pipeline before the connector is allowed to install or activate. The `ManifestError` enum in `crates/fcp-manifest/src/lib.rs` has nine variants; most field-level violations funnel through `ManifestError::Invalid { field, message }`.

| Stage | Check | Failure Variant |
|-------|-------|-----------------|
| **Parse** | TOML well-formedness | `ManifestError::Toml` (wraps `toml::de::Error`) |
| **Identifier validity** | `connector.id`, capability IDs, operation IDs are valid identifiers | `ManifestError::Id` (wraps `IdValidationError`) |
| **Zone validity** | Every `ZoneId` reference is well-formed (including `z:project:*` patterns via the separate `ZonePatternError`) | `ManifestError::ZoneId` (wraps `ZoneIdError`) |
| **Canonical CBOR** | Embedded serialized blobs are deterministic CBOR | `ManifestError::CanonicalCbor` (wraps `fcp_cbor::SerializationError`) |
| **Field-level invariants** | Required fields present, sandbox profile recognized, network constraints valid, operation declarations match implementations, capability vocabulary, etc. | `ManifestError::Invalid { field, message }` — the field name pinpoints the violation |
| **Performance budget** | `[performance_budget]` fields (memory, CPU, wall-clock) are in range | `ManifestError::InvalidPerformanceBudget { field, message }` |
| **Interface hash** | Reproducible-build hash matches the embedded value | `ManifestError::InterfaceHashMismatch { expected, found }` |
| **Rate limit** | Per-operation rate-limit declarations are well-formed | `ManifestError::RateLimit`, `ManifestError::RateLimitDeclaration` |

Beyond the manifest crate itself, two cross-crate validation passes also run:

- **Const-literal drift** — a `fcp-conformance` test ensures runtime `const OP_*` literals exported by the connector binary match the manifest's operation IDs (introduced under epic `4kw5f.8`). A connector that adds an operation in code but forgets to declare it in the manifest fails this check.
- **Capability ⊆ zone ceiling** — `fcp-host` and `fcp-policy` verify that the connector's required capabilities are within the zones declared as allowed sources before activation.

The `fwc manifest fix --check` command runs the manifest crate's validator in non-mutating mode; `fwc install` runs the validator implicitly before staging the binary.

---

## Network Constraint Inheritance

A connector declares network constraints at two levels:

```toml
[network]                         # Connector-level baseline
require_sni = true                # SNI verification on every TLS handshake
deny_localhost = true
deny_private_ranges = true

[[provides]]
id = "github.issues.create"
[provides.network_constraints]    # Per-operation overrides
host_allow = ["api.github.com"]
port_allow = [443]
require_sni = true

[[provides]]
id = "github.gists.create"
[provides.network_constraints]
host_allow = ["api.github.com", "gist.github.com"]
port_allow = [443]
require_sni = true
```

The `NetworkConstraints` struct (`crates/fcp-manifest/src/lib.rs`) carries an explicit allow-set per operation: `host_allow`, `port_allow`, `ip_allow`, `cidr_deny`, plus `deny_localhost` / `deny_private_ranges` / `deny_tailnet_ranges` (all default `true`), `require_sni`, `spki_pins`, `deny_ip_literals`, `require_host_canonicalization`, `dns_max_ips` (default 16), `max_redirects` (default 5), `connect_timeout_ms` (default 10 000), `total_timeout_ms` (default 60 000), and `max_response_bytes` (default 10 MiB).

The egress proxy resolves the effective constraint set for a given invoke by merging connector-level + operation-level + zone-level constraints. The merge rule is **most-restrictive wins**:

- Hosts: intersection of all declared `host_allow` sets.
- Ports: intersection of all declared `port_allow` sets.
- SNI: `require_sni = true` at any layer enforces SNI verification.
- CIDR deny: union of all `cidr_deny` declarations; any layer can extend the denylist.

A zone-level `cidr_deny` for `0.0.0.0/8` therefore cannot be relaxed by a connector, only made stricter. Zones are the upper bound on what connectors can reach; connectors can only narrow that bound, never widen it.

---

## PostureAttestation

Sensitive zones can require hardware-backed key residency. `PostureAttestation` is an owner-signed object naming the hardware modality and binding it to a `NodeKeyAttestation`. Supported modalities:

| Modality | Platform | What's Attested |
|----------|----------|-----------------|
| **TPM 2.0** | Linux, Windows | Node signing/encryption/issuance keys generated and sealed inside the TPM; private material cannot be exported |
| **Apple Secure Enclave** | macOS, iOS | Keys live in the Secure Enclave; software cannot extract them |
| **Android Keystore** | Android | Keys are bound to an Android KeyMint (the platform HAL) hardware-backed key alias with attestation chain |
| **PKCS#11 hardware token** | Cross-platform | YubiKey, Nitrokey, SoftHSM2; `fcp-bootstrap` carries the adapter |

A zone's `ZonePolicy` can declare `require_posture = ["tpm2", "secure-enclave"]` to enforce that only nodes with one of the named hardware modalities can decrypt that zone's keys. The host refuses to register a node into such a zone without a valid posture attestation. PKCS#11 PIN handling uses constant-time comparison (`subtle::ConstantTimeEq`) and zeroizes the PIN buffer on drop (`zeroize::ZeroizeOnDrop`) — surfaced as a fix during the Gemini Lane 4 (Bootstrap) audit.

---

## Post-Compromise Security (PCS) Group State

The `PcsGroupState` type (`crates/fcp-core/src/pcs.rs`) tracks a sensitive zone's MLS-style epoch state. The properties that matter:

- **Forward secrecy** — a key exposed at epoch N does not let an attacker read epochs N-1 or earlier.
- **Post-compromise security** — once a compromised device is removed (via revocation + TreeKEM update), the remaining members produce a new epoch key the removed device cannot derive. The group heals.
- **Bounded operational cost** — TreeKEM is `O(log n)` per membership change. Benchmarks: ~2.6 μs per epoch advance, ~3.5 μs per removal rekey, for groups of 3–10 members.

The on-the-wire mode discriminator is `PcsMode`, with two variants: `Disabled` (standard owner-distributed zone-key rotation) and `Enabled { epoch, commit_ref }` (TreeKEM-managed group ratcheting with the current epoch number and an opaque 32-byte reference to the commit that established this epoch). A sibling enum, `KeyManagementMode`, switches `ZoneKeyManifest` integration between `StandardRotation` and `PcsGroupManaged { commit_ref, epoch }`.

Each `GroupMember` carries `node_id`, `public_key` (X25519), and a `leaf_index` (u32) — the index into the binary TreeKEM tree, which is what lets a `O(log n)` group operation update only the path from the affected leaf to the root.

---

## Error Taxonomy

`FcpError` in `crates/fcp-core/src/error.rs` is the canonical error type carried across the protocol boundary. Every `ConnectorErrorMapping::to_fcp_error` lands in one of these variants. The taxonomy is grouped by category via the `#[serde(tag = "category")]` discriminator.

**Protocol-shape errors**
| Variant | Meaning |
|---------|---------|
| `InvalidRequest { code, message }` | Caller-shaped error (malformed input) |
| `MalformedFrame { code, message }` | Wire-level framing violation |
| `MissingField { field }` | Required CBOR/JSON field absent |
| `ChecksumMismatch` | Object hash did not match its content-addressed id |
| `VersionMismatch { expected, actual }` | Schema version drift |

**Authentication / authorization**
| Variant | Meaning |
|---------|---------|
| `Unauthorized { code, message }` | No valid capability token presented |
| `TokenExpired` | CWT `exp` elapsed |
| `TokenNotYetValid` | CWT `nbf` not yet reached |
| `InvalidSignature` | COSE signature verification failed |
| `CapabilityDenied { capability, reason }` | Capability not granted for this principal/zone |
| `OperationNotGranted { operation }` | Capability present but specific operation not in scope |
| `ResourceNotAllowed { resource }` | `resource_allow` / `resource_deny` constraint refused |
| `CapabilityConstraintDenied { ... }` | A `CapabilityConstraints` predicate refused (max_calls, max_bytes, idempotency_key, credential_allow) |
| `ZoneViolation { ... }` | Zone-binding or zone-lattice violation |
| `TaintViolation { ... }` | Provenance/taint merge refused the data flow |
| `ElevationRequired { ... }` | Operation requires an `ApprovalToken` before invoke |

**Rate / budget**
| Variant | Meaning |
|---------|---------|
| `RateLimited { ... }` | Rate-limit pool returned no tokens |
| `ResourceExhausted { resource }` | Per-resource quota exceeded |
| `BudgetExceeded { ... }` | Invoke budget (bytes, time, attempts) consumed |

**Connector / runtime**
| Variant | Meaning |
|---------|---------|
| `ConnectorUnavailable { code, message }` | Connector subprocess not reachable |
| `NotConfigured` | `configure` has not yet been called for this instance |
| `NotHandshaken` | `handshake` has not yet completed |
| `HealthCheckFailed { reason }` | `health` returned a failure |
| `StreamingNotSupported` | Operation called against a connector without streaming archetype |
| `ConfigurationLeakedSecret { ... }` | Raw secret material in configuration; refused before reaching the wire |

**Resource / dependency**
| Variant | Meaning |
|---------|---------|
| `ResourceNotFound { resource }` | Target resource id does not exist |
| `Conflict { message }` | Idempotency, lease, or version conflict |
| `External { ... }` | External service returned an error mapped from connector code |
| `UpstreamTimeout { service }` | Upstream call exceeded its timeout |
| `DependencyUnavailable { service }` | A required downstream dependency is unreachable |

**Catch-all**
| Variant | Meaning |
|---------|---------|
| `Internal { message }` | Implementation bug; should never reach production |

The category tags map to error families: `Protocol`, `Auth`, `Capability`, `Zone`, `Connector`, `Resource`, `External`, `Internal`. Connector-specific error types implement `ConnectorErrorMapping::to_fcp_error` to project into this taxonomy. The host's enforcement pipeline surfaces the specific layer that refused via the variant chosen — `CapabilityDenied`, `ZoneViolation`, `TaintViolation`, `ElevationRequired`, `CapabilityConstraintDenied`, etc. — rather than a single `PermissionDenied` with an opaque reason string.

---

## Three Verification Layers

Every operation passes three independent verification layers. A bug in any one of them does not silently allow the operation — the other layers refuse.

### Layer 1: Cryptographic Signature

The capability token is a COSE_Sign1 envelope signed by the issuing node's *issuance key*. Verifying the signature:

- Confirms the token was minted by a node whose `NodeKeyAttestation` is current.
- Confirms the token has not been tampered with since minting.
- Confirms the kid identifies a non-revoked issuance key.

If signature verification fails, none of the claims are even parsed. `Unverified → UnboundVerified` is the typestate transition that records signature verification success.

### Layer 2: Type-Level Binding

After signature verification, the token is `UnboundVerified`. To actually invoke against a connector instance, the host promotes the token to `BoundVerified` by:

- Checking `instance_id` in the claims (`None` for `UnboundVerified`; must be filled in by `promote_with_instance` for `BoundVerified`).
- Confirming the bound `instance_id` matches the live connector subprocess's `InstanceId`.

A `CapabilityToken<UnboundVerified>` does not compile against an executor that requires `CapabilityToken<BoundVerified>`. The Rust type system enforces the binding before the runtime even runs. `crates/fcp-core/tests/typestate_compile_fail.rs` is a `trybuild` test that verifies the wrong-typestate program fails to compile.

### Layer 3: Semantic / Constraint Enforcement

After binding, the token is still only `BoundVerified`. To actually execute, the host promotes to `ConstraintsEnforced` by:

- Evaluating every non-empty field of `CapabilityConstraints` against the live invoke context.
- Checking revocation freshness against the zone's `revocation_freshness_sla_secs`.
- Verifying provenance/taint flow under the merge rule.
- Confirming the `RevocationFreshnessClass` is satisfied.

Only `CapabilityToken<ConstraintsEnforced>` can be passed to the connector's operation handler. The three transitions are forward-only and compiler-checked: there is no way to "downgrade" a token or skip a layer in safe code.

A misconfiguration in the signature layer (wrong key, wrong algorithm) cannot leak into semantic enforcement; a bug in semantic enforcement cannot bypass the type-level binding; a flaw in the type system (hypothetically) cannot make a forged signature verifiable.

---

## Why FCPC and FCPS Are Split

FCPC (control-plane framing) and FCPS (symbol framing) are separate protocols on the wire — same session, different shapes. The split is deliberate.

**FCPC is reliable, ordered, and backpressured.** Invokes, responses, receipts, approvals, and audit events all flow over FCPC as a sequence of length-prefixed AEAD-encrypted control messages, each carrying its own causal metadata. FCPC uses the session's negotiated `k_ctx` symmetric key, so every message is authenticated without per-message signatures. Backpressure flows naturally: if the receiver is slow, the sender stalls; there is no symbol-loss-style "send more" semantics. This is the right shape for request/response RPC.

**FCPS is high-throughput, lossy-tolerant, and stateless per frame.** Symbol delivery for bulk objects flows over FCPS as a stream of independent symbol frames with a fixed 114-byte header and AEAD-tagged payload. Frames are independent: lose any one, the receiver collects more. There is no reorder buffer, no retransmit coordination. This is the right shape for content distribution and repair.

Co-locating these two over one transport (Tailscale, optionally MASQUE/QUIC) lets the same authenticated session carry both an invoke (FCPC) and the symbol response (FCPS) without re-authenticating. A connector that streams a large response splits: the control message ("here comes 2 MB of payload as object id X") goes over FCPC; the actual symbols flow over FCPS. The receiver reassembles when it has K' symbols and returns the FCPC response.

The same split shows up in HTTP/3 (data vs. control), in TLS (handshake vs. record), and in QUIC (long header vs. short header). The tension is universal: control needs reliability, bulk needs throughput.

---

## Reproducible Builds and Connector Binary Signing

A connector binary must be reproducibly buildable for supply-chain attestations to be meaningful. "Reproducible" means: given the same source tree, the same toolchain version, the same build flags, and the same environment, two independent builds produce byte-identical binaries. Three sources of non-reproducibility typically break this:

- **Timestamps embedded in the binary** — eliminated by `SOURCE_DATE_EPOCH` and rustc's `-Z embed-source` discipline.
- **Path prefixes baked in by `panic!` location metadata** — eliminated via `--remap-path-prefix` in `[profile.release]`.
- **Non-deterministic codegen ordering** — eliminated by `codegen-units = 1` in `[profile.release]` (already set in this workspace's `Cargo.toml`).

The release profile (`Cargo.toml` workspace `[profile.release]`) optimizes for both binary size and reproducibility:

```toml
[profile.release]
opt-level = "z"     # Optimize for size
lto = true          # Link-time optimization
codegen-units = 1   # Single codegen unit (also enables reproducibility)
panic = "abort"     # Smaller binary, no unwinding overhead
strip = true        # Remove debug symbols
```

Once a binary is reproducibly built, it gets signed via Ed25519 with the publisher's signing key. The signature covers both the connector binary AND the embedded manifest section, so a manifest tamper detaches the signature even if the binary bytes are unchanged.

For supply-chain hardening beyond a single publisher signature, `fcp-registry` supports:

- **TUF root pinning** — owner-signed root metadata prevents freeze attacks (registry serving stale-but-signed-by-valid-key versions) and mix-and-match attacks (registry serving valid-but-mismatched signed components).
- **Sigstore / cosign verification** — adds a transparency-log-anchored secondary signature so a compromised publisher key alone is not sufficient to ship a malicious binary undetected.
- **in-toto attestations** — proves the binary was built from the claimed source tree by the claimed builder, with a chain of signed step attestations.
- **SLSA provenance** — declares the build environment level (SLSA 1 through 4); owner policy can refuse to install binaries below a minimum SLSA level.

The host's enforcement pipeline checks every applicable attestation before allowing a binary to activate. Owner policy declares which attestations are required:

```
require_transparency_log = true
require_attestation_types = ["in-toto"]
min_slsa_level = 2
trusted_builders = ["github-actions", "internal-ci"]
```

A binary failing any required check is refused at install time, not at first invoke. The failure is recorded as an `installation_refused` audit event so post-hoc investigation can determine why a previously-rolled-out version stopped being accepted.

---

## Replay-Protection Windows and TTL Math

Webhook ingestion, capability tokens, and operation receipts all need replay protection — proof that the same signed payload isn't being re-played by an attacker after a successful first acceptance. FCP uses three different replay-protection mechanisms tuned to the threat model of each surface.

### Webhook Replay Cache

Inbound webhooks (`fcp-webhook`) use a deterministic-id + TTL cache. The webhook event id is computed as:

```
event_id = SHA256(provider ‖ 0x00 ‖ event_type ‖ 0x00 ‖ body)
```

The deterministic id means the same payload always produces the same id, regardless of provider-supplied headers (which can be missing or spoofed). The cache stores `(event_id, accepted_at)` pairs; lookup at ingress checks both presence (replay refused) and age (entries older than the webhook config's `idempotency_ttl`, default 86 400 seconds = 24 hours, are eligible for GC).

The TTL is bounded by two competing pressures: too short, and a legitimate retry from a slow upstream gets refused as a duplicate; too long, and the cache grows without bound. 24 hours covers virtually every real-world webhook retry window (Stripe maxes at ~3 days; GitHub at hours; Slack within minutes) while keeping the cache small enough to fit in memory for reasonable workloads. The atomic `claim_event` operation acquires a write lock, checks, and records in one critical section, eliminating the TOCTOU race that the deprecated split `check_replay()` + `record_event()` pair had.

### Capability Token Replay

Capability tokens carry a `token_id` (CWT `cti`) for one-shot revocation tracking and a CWT `exp` for time-bound expiry. The replay-protection model differs from webhooks: tokens are long-enough lived that a per-token cache would bloat, so replay protection is bounded by the `exp` window plus the revocation freshness SLA.

- An expired token is refused before any further check (cheap, no cache lookup).
- A non-expired one-shot token (`max_calls = 1` in `CapabilityConstraints`) is checked against the per-token revocation registry; the first invoke records the token as used; the second is refused.
- A non-expired N-shot token (`max_calls = N`) carries its used-count in a per-token mesh object that all peers can read; concurrent invokes coordinate via the HRW lease holder.

The replay window for a one-shot token is bounded by `exp - iat`, which for FCP's defaults is single-digit minutes for high-risk operations and hours for low-risk ones. Token revocation freshness must keep up; `RevocationFreshnessClass::Critical` operations refuse to proceed if the revocation view is older than `revocation_freshness_sla_secs` (default 300 seconds).

### Operation Receipt Idempotency

Operation receipts use the idempotency_key field as the cache key. The host stores `(idempotency_key, signed_receipt)` for retention configured per-zone (default 7 days). A retry with the same idempotency key returns the cached receipt without re-executing.

Storage cost is `O(retention × write_rate × receipt_size)`. For a workspace doing 1000 ops/hour with 7-day retention and 2 KB receipts, that comes out to roughly 336 MB per zone, which is comfortably in memory or trivial on disk. For workspaces doing millions of ops/hour, retention typically drops to 24 hours and storage moves to a dedicated symbol-store namespace.

---

## Observability Integration

FCP integrates with standard observability stacks via three surfaces. The intent: an operator using Prometheus + Grafana + Loki + Jaeger should not have to write a single line of FCP-specific glue code to see what's happening.

### Metrics: Prometheus / OpenMetrics

`fcp-telemetry` (`crates/fcp-telemetry/src/export.rs`) embeds the `metrics_exporter_prometheus` crate and exposes a `/metrics` scrape endpoint on a configurable port. The exporter is initialized via `PrometheusBuilder::new()` at host startup. Metric families cover invokes (counter + duration histogram), bytes in/out, audit events, revocation freshness, lease holders, credential pool occupancy, repair-controller SLO deficit, and rate-limit pool occupancy. The authoritative list of metric names lives in `fcp-telemetry`'s registration code; the schema is what gets emitted at `/metrics`, not a separately-documented contract.

### Tracing: OpenTelemetry OTLP

Every invoke produces a span tree rooted at the `fwc` invocation, with child spans for the host enforcement stages, the connector subprocess invoke, the egress proxy HTTPS call, and the audit append. The OTLP exporter ships traces, metrics, and logs to any OTLP-compatible collector (Jaeger, Tempo, Honeycomb, Datadog, New Relic). Audit OTLP HLC attributes are pinned (see the **OpenTelemetry OTLP Integration** section above).

### Structured Logs: Loki / Vector

`fcp-host` and connector subprocesses emit `tracing` events as line-delimited JSON via `tracing-subscriber`'s `json` formatter. Default fields per event:

- `timestamp` (RFC 3339)
- `level` (`INFO` / `WARN` / `ERROR` / `DEBUG`)
- `target` (Rust module path)
- `trace_id` / `span_id` (W3C trace context)
- `connector_id` / `operation_id` / `zone_id` (when applicable)
- `audit_seq` (when an audit event is emitted)
- `message` (human-readable)
- structured fields specific to the event (`bytes_in`, `latency_ms`, `outcome`, etc.)

Secrets are redacted in `Debug` output via hand-written `Debug` impls on credential-bearing types — for example, every secret-carrying field on `fcp-oauth`'s OAuth state machines renders as `"[REDACTED]"` via `.field("...", &"[REDACTED]")` in the custom `fmt::Debug` impl. This catches the common case where a `tracing::error!` or `println!("{:?}", credentials)` would otherwise leak the secret into a log file. Unit tests in `fcp-oauth` assert that the rendered debug string actually contains `[REDACTED]` so future refactors cannot regress the property.

---

## Connection Pooling and Connector HTTP Architecture

Every connector that speaks HTTP shares a baseline architecture provided by `fcp-sdk`. The shape is small enough to memorize and consistent enough that the next connector you write inherits the right defaults.

```
┌─────────────────────────────────────────────────────────────────┐
│                  CONNECTOR HTTP STACK                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Application code: typed operation handlers               │   │
│  │ (issues.create, messages.send, search_messages, …)       │   │
│  └────────────────────────────┬─────────────────────────────┘   │
│                               │                                 │
│                               ▼                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Client (per connector, in client.rs)                     │   │
│  │  - Bearer token resolution via SecretFetchHook           │   │
│  │  - URL canonicalization                                  │   │
│  │  - Per-operation request shaping                         │   │
│  └────────────────────────────┬─────────────────────────────┘   │
│                               │                                 │
│                               ▼                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ RetryLoop (fcp-sdk)                                      │   │
│  │  - HttpRetryConfig: max_retries, initial_delay,          │   │
│  │    max_delay, jitter                                     │   │
│  │  - AttemptOutcome: Success / Retryable / Terminal         │   │
│  │  - RetryDirective honoring (Immediate / Backoff /        │   │
│  │    RetryAfter / Terminal)                                │   │
│  └────────────────────────────┬─────────────────────────────┘   │
│                               │                                 │
│                               ▼                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ reqwest::Client (single instance, reused)                │   │
│  │  - Connection pool: HTTP/2 multiplexing, keep-alive      │   │
│  │  - TLS via rustls; SPKI pins enforced if declared        │   │
│  │  - Connect / total timeouts from manifest                │   │
│  └────────────────────────────┬─────────────────────────────┘   │
│                               │                                 │
│                               ▼                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Egress Proxy (host-managed)                              │   │
│  │  - SNI verification, SPKI pinning                        │   │
│  │  - CIDR deny, host allowlist                             │   │
│  │  - Credential injection (X-FCP-Credential-Id → bearer)   │   │
│  │  - Audit event on every request                          │   │
│  └────────────────────────────┬─────────────────────────────┘   │
│                               │                                 │
│                               ▼                                 │
│                          External API                           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

The single-`reqwest::Client`-per-connector pattern is critical: every operation reuses the same connection pool, so HTTP/2 multiplexing works for providers that support it and TCP/TLS handshake cost amortizes across requests. The connection pool's default sizing (controlled by `reqwest`'s defaults) is fine for most connectors; high-fanout connectors override it explicitly.

The `RetryLoop` is centralized because every connector had its own retry implementation early on — and every one had a subtly different bug (off-by-one max retries, retry on non-retryable errors, exponential backoff overflow). One implementation, exercised by 100+ connectors, gets debugged once.

---

## The Sealed-Trait Pattern

`FcpConnector` is sealed: third-party crates outside this workspace cannot implement the trait themselves. The seal is enforced via a private marker type in the trait bound:

```rust
mod private {
    pub trait Sealed {}
}

pub trait FcpConnector: private::Sealed {
    // ... lifecycle methods ...
}
```

A connector crate declares its struct implements `FcpConnector` only by going through `fcp-sdk`'s controlled-implementation pathway, which provides the `Sealed` impl. External code that tries `impl FcpConnector for MyType {}` outside the workspace fails to compile because `MyType: private::Sealed` is unsatisfied.

The seal pays for itself three ways:

- **Lifecycle invariants are mechanical.** A connector that skips `handshake` cannot exist because the seal forces it through the macro that wires the full lifecycle.
- **Future extensions are non-breaking.** Adding a new required method to `FcpConnector` would normally break every downstream implementor. With a sealed trait, only the in-workspace implementors break, and those are under the workspace owners' control.
- **Capability surface is auditable.** Every connector that talks to the host is in the workspace. There is no "I installed a random crate that claims to be a connector" pathway.

The same pattern is used for `ConnectorErrorMapping` (every connector error type goes through a controlled mapping), `SecretFetchHook` (only `fcp-host` can produce one), and `CapabilityToken<S>` where `S: TypeStateMarker` (only the typestate marker types defined in `fcp-core` qualify).

---

## Atomic File Operations: `fsync` + `rename` Discipline

The bootstrap ceremony, audit chain, and connector state cache all write to disk. The discipline is the same across all three: never write into a file in place. The pattern:

```rust
let tmp = path.with_extension("tmp");
let mut file = File::create(&tmp)?;
file.write_all(&bytes)?;
file.sync_all()?;   // fsync the file contents
drop(file);
fs::rename(&tmp, &path)?;  // atomic on POSIX-compliant filesystems
// On Linux ext4, also fsync the parent directory:
let parent = path.parent().unwrap();
File::open(parent)?.sync_all()?;
```

The four properties:

- **Crash safety.** If the process crashes after `write_all` but before `rename`, the original `path` is untouched. Recovery finds the orphaned `.tmp` and discards it.
- **fsync before rename.** The bytes have to be durable on disk before the rename advertises them as the new live version. Reordering would let `rename` make a partially-written file visible after a power loss.
- **fsync the parent directory.** On ext4 (and other journaling filesystems), the directory entry change from `rename` is itself journaled separately. Without the parent fsync, a crash can re-expose the old name pointing at the old inode.
- **No partial reads.** A reader looking up `path` either sees the old fully-coherent file or the new fully-coherent file; never a half-written intermediate.

This discipline costs about a millisecond per write (two fsyncs) but eliminates an entire class of bugs that surface as "file exists but is empty" or "file has the right size but the wrong checksum" after a crash. The bootstrap ceremony's genesis write (`crates/fcp-bootstrap/src/`) does this; the connector state cache does this; the audit chain's per-zone heads do this.

---

## The Three-Per-Node Key Model

Every node has *three* per-device keys, not one. The split is deliberate and operationally significant.

| Key | Algorithm | What It Does | Why It's Separate |
|-----|-----------|--------------|-------------------|
| **Node Signing Key** | Ed25519 | Signs FCPS frames, gossip messages, receipts, audit-chain entries | This key sees the most use; it's hot. Compromise of this key means an attacker can sign forged frames as if they were this node. |
| **Node Encryption Key** | X25519 (+ optional X-Wing KEM for hybrid PQ) | Receives HPKE-sealed zone keys and Shamir secret shares | This key holds the keys to the kingdom. Compromise lets the attacker decrypt every zone-key wrap intended for this node, but not impersonate the node's signature surface. |
| **Node Issuance Key** | Ed25519 | Mints capability tokens for principals authorized through this node | Separately revocable so an operator can disable token minting (e.g. on suspicious behavior) without making the node unable to receive zone-key updates or sign frames. |

Why three separate keys instead of one master key?

- **Separately revocable.** If a node's issuance key is compromised, revoking it stops new tokens from being minted; the node can still receive zone-key updates (encryption key) and sign frames (signing key) until it's fully decommissioned. With one master key, any compromise forces full decommission.
- **Forward secrecy on different surfaces.** The signing key sees thousands of operations per minute; if rotated frequently, frames signed before rotation are still verifiable (key id rotation), but a future signing-key compromise doesn't retroactively forge old frames. Encryption-key rotation triggers zone-key reseal but doesn't invalidate already-decrypted data. Issuance-key rotation is independent of both.
- **Hardware-residency optimization.** The encryption key (which never has to compute over arbitrary user inputs, only HPKE-seal/unseal fixed-shape payloads) is the cheapest to put in a hardware element. Keeping it separate from the signing key (which signs arbitrary bytes and is harder to constrain in hardware) lets each be hardware-backed independently.

The owner key is a fourth class on top of the per-node keys: it signs the `NodeKeyAttestation` that binds all three node keys to the Tailscale node ID. The owner key itself uses FROST threshold signing so no single device ever holds the complete private key; losing or compromising any one device does not compromise the owner authority.

---

## Tailscale Integration: Identity, Transport, ACL

Tailscale is the transport in FCP, but it is also the identity layer and the ACL layer. The integration goes deeper than "use WireGuard to encrypt traffic between nodes."

### Identity From WireGuard Keys

Every device in a tailnet has a stable WireGuard public key. The Tailscale coordination server (or a self-hosted Headscale) signs the binding `(public_key → node_id → tailnet_member)`. This binding is unforgeable: there is no way for a peer to claim to be a different node without compromising the WireGuard private key on the legitimate device.

FCP layers its own identity on top: every node has a `NodeKeyAttestation` signed by the owner key, binding the Tailscale node id to the per-node signing/encryption/issuance keys. The composition is what gives the mesh strong identity:

- Tailscale guarantees "this packet came from the device with `node_id = X`."
- The owner-signed attestation guarantees "the device with `node_id = X` has these three FCP keys."
- The FCP keys sign frames, encrypt zone payloads, mint capability tokens.

Compromising any one layer doesn't break the others. Compromising the WireGuard key still requires forging FCP signatures to act as the node. Compromising an FCP key still requires routing through the legitimate WireGuard tunnel. Compromising both still requires owner-signed attestation, which uses FROST threshold signing.

### Zone-to-Tag Mapping

Tailscale ACLs operate over *tags* (`tag:fcp-owner`, `tag:fcp-private`, etc.). FCP's zones map directly to these tags:

```jsonc
// Tailscale ACL policy (example)
{
  "tagOwners": {
    "tag:fcp-owner":     ["autogroup:admin"],
    "tag:fcp-private":   ["autogroup:admin"],
    "tag:fcp-work":      ["autogroup:admin"],
    "tag:fcp-community": ["autogroup:admin"],
    "tag:fcp-public":    ["autogroup:admin"],
  },
  "acls": [
    // z:owner peers can talk to anyone in the tailnet
    { "action": "accept", "src": ["tag:fcp-owner"], "dst": ["*:*"] },

    // z:private peers can talk to z:owner and z:private only
    { "action": "accept",
      "src": ["tag:fcp-private"],
      "dst": ["tag:fcp-owner:*", "tag:fcp-private:*"] },

    // z:work peers can talk down to z:work and below
    { "action": "accept",
      "src": ["tag:fcp-work"],
      "dst": ["tag:fcp-work:*", "tag:fcp-community:*", "tag:fcp-public:*"] },

    // z:public can only talk to z:public peers (no upward connectivity)
    { "action": "accept", "src": ["tag:fcp-public"], "dst": ["tag:fcp-public:*"] }
  ]
}
```

The mapping has two consequences:

1. **Network-layer isolation matches cryptographic-layer isolation.** A `z:public` peer cannot even *reach* a `z:private` peer on the network, regardless of what FCP-layer policy says. Defense-in-depth: a bug in FCP authorization is contained by the Tailscale ACL refusing the connection.
2. **Tailscale tag changes propagate to FCP zone changes.** Re-tagging a device in the tailnet (e.g. promoting a previously-public device to community access) only takes effect once the device's `NodeKeyAttestation` is re-signed with the new zone membership. The two have to agree before access is granted.

### Transport Priority

The `fcp-tailscale` crate consumes the Tailscale LocalAPI (`/localapi/v0/status`) to determine the best path to each peer. Path selection and priority live in `fcp-mesh/src/transport.rs`; the priority order:

```
Priority 1: Tailscale Direct (peers on the same LAN, NAT-free)
Priority 2: Tailscale Mesh   (NAT traversal via STUN-like coordination)
Priority 3: Tailscale DERP   (encrypted relay through Tailscale's DERP servers)
Priority 4: Tailscale Funnel (public TLS endpoint, for low-trust zones only)
```

Zones configure transport policy via `ZoneTransportPolicy` (`crates/fcp-core/src/policy.rs`) to control DERP/Funnel availability. By default, `z:owner` and `z:private` traffic refuses to use Funnel (so personal data never flows through public-internet endpoints), while `z:public` may use any path.

### Why Not Build a Mesh Layer From Scratch

Doing so would mean re-implementing NAT traversal, key rotation, ACL enforcement at the network layer, relay infrastructure for peers behind symmetric NATs, and cross-platform interface management. Tailscale ships all of this on every major OS, with a 10+ year operational track record. Adopting it lets FCP focus on the protocol semantics layer (zones, capabilities, audit, post-quantum crypto) instead of re-solving WireGuard NAT traversal for the n+1th time.

---

## The Asupersync Native Async Runtime

FCP3 production paths run on Asupersync, a native async runtime developed in a sibling repository (`asupersync/`). The migration off Tokio happened across early-to-mid 2026 as part of the FCP3 re-foundation.

### Why Move Off Tokio?

Tokio is excellent but it's a generic runtime built for a wide range of use cases. FCP's workload is specific: high-fanout signed-frame ingest, deterministic CBOR serialization, long-running streaming connectors with backpressure, and a need for cross-platform behavior that doesn't drift between Linux epoll, macOS kqueue, and Windows IOCP. Asupersync optimizes for that profile:

- **Native Cx and region-based execution.** Asupersync's concurrency primitive is a `Cx` (context) bound to a *region*, a logical scope with deterministic finalization order. This eliminates the "task lifetime is the runtime's lifetime, period" coupling that complicates Tokio teardown semantics.
- **Predictable polling.** A region's polling order is deterministic given the input event sequence, which means test runs reproduce deterministically. Tokio's work-stealing scheduler is faster on average but harder to make reproducible.
- **Smaller surface to audit.** A custom runtime is auditable end-to-end; Tokio (~150K lines of code in 2026) is not realistically auditable by the FCP maintainers.

### `fcp-async-core` Quarantine Layer

The `fcp-async-core` crate wraps Asupersync and provides a thin quarantine bridge for the small set of dependencies that still require Tokio (chiefly `wiremock` for HTTP mocking in tests and a small `reqwest` compatibility surface). Production paths do not touch the Tokio compat layer; only test infrastructure does. The CI guard `scripts/ci/asupersync_tokio_guard.sh` enforces that no new production code imports Tokio directly.

`fcp-async-core` also exposes:

- `fcp_async_core::runtime` — `tokio::test`-compatible `#[fcp_async_core::runtime::test]` macro for ergonomic async tests.
- `fcp_async_core::io` — `AsyncRead` / `AsyncWrite` traits, bridge for stdin/stdout (used by JSON-RPC connector stdio).
- WebSocket client substrate (replaces `tokio-tungstenite` in streaming connectors).
- Lines + stdin/stdout bridges (replaces `tokio::io::BufReader::lines()` for MCP server work).

### The Quarantined Tokio Surface

What's left of Tokio in the workspace is intentionally tracked in `docs/FCP3_Retirement_Kill_List.md` with explicit removal triggers:

- The Tokio compat bridge in `fcp-async-core` is removed when `wiremock` ships an asupersync-native counterpart or when test infrastructure migrates to a different HTTP mock.
- The `fwc/src/serve_mcp.rs` Tokio seam is **retired**: the file now uses `fcp_async_core::io::{AsyncBufRead, AsyncWrite, …}` and contains zero Tokio imports.

The forward-only ratchet ensures these surfaces shrink over time. The asupersync-tokio guard test fails if new Tokio imports appear in production paths.

---

## IBLT Mathematics

Invertible Bloom Lookup Tables are the workhorse of FCP's gossip protocol. The math is worth understanding because the parameter choices determine whether reconciliation converges in one round or many.

### Construction

An IBLT is an array of `m` cells, each cell holding three fields:

- `count` (signed int): how many entries hashed into this cell, +1 for "I have it," -1 for "you have it."
- `key_xor`: XOR of the keys (object IDs) of all entries in this cell.
- `value_xor`: XOR of the values associated with those entries (optional; not always carried).

Each entry hashes into `k` cells (typically `k = 3` or `k = 4`) chosen by `k` independent hash functions. To insert, you increment the count and XOR the key into each of the `k` chosen cells. To delete, you decrement and XOR (XOR is self-inverse, so XORing twice cancels).

### The Difference Operation

Given peer A's IBLT and peer B's IBLT for the same set domain, you can subtract them cell-wise:

```
diff_cell[i].count    = A.cell[i].count    - B.cell[i].count
diff_cell[i].key_xor  = A.cell[i].key_xor  ^ B.cell[i].key_xor
```

Cells where exactly one party has an entry now have `count = ±1` and `key_xor` equal to the missing key. Peel them out: each peeled entry identifies a key one party has and the other does not. After peeling, more cells become single-entry, so you peel again. The process iterates until either all cells are empty (full reconciliation succeeded) or no further peeling is possible (failure: the IBLT was too small for the difference size).

### Sizing

The classical result: an IBLT of size `m = c · d` (where `d` is the size of the symmetric difference and `c ≈ 1.5` for `k = 4` hashes) reconciles fully with high probability. For an FCP gossip round where the typical difference is ~100 object IDs, `m ≈ 600` cells. Each cell is ~50 bytes (depending on key/value width), so a ~30 KB IBLT per gossip message reconciles a 100-id difference in one round.

The pathological case: if the actual difference exceeds the IBLT's capacity, peeling stalls partway through. The masked-IBLT anti-entropy fallback (`angoc.17.2`) detects which cells remain unsolved and requests a wider IBLT just for those cells, avoiding a full restart at the larger size.

### Why Not Just Bloom Filters?

A Bloom filter can answer "do you have this object?" but cannot answer "what objects do you have that I don't?". You'd have to send your entire object inventory and let the other side check each one against the Bloom filter, which is `O(N)` work in the inventory size. IBLT is `O(d)` in the *difference* size, which for large near-converged sets is dramatically smaller.

### Why XOR Filters Then?

XOR filters (`crates/fcp-mesh/src/gossip.rs`, separate use case) are still useful for the simpler "do you have this object?" probe; they're more compact than Bloom filters for static sets and give false-positive-only semantics. The two structures coexist: XOR filters for "advertise what I have," IBLT for "reconcile what we differ on."

---

## How This Repository Relates to `FCP_Specification_V3.md`

The repository ships three artifacts that together define FCP:

| Artifact | Role |
|----------|------|
| `FCP_Specification_V3.md` | **The specification.** Architectural target, security invariants, conformance obligations, wire-level shapes. This is the "what the protocol IS" document. |
| `FCP_CDDL_V2.cddl` | **The wire schema.** CBOR Data Definition Language describing every signed object that travels on FCPC or FCPS streams. |
| `crates/fcp-*` and `connectors/*` | **The reference implementation.** Rust code that implements the V3 spec; the conformance harness in `fcp-conformance` validates the implementation against the spec. |

When the three disagree, the canonical resolution order:

1. The V3 spec is the spec. If the implementation diverges from it, that's a bug in the implementation.
2. The CDDL is the wire schema. If the Rust structs serialize to bytes the CDDL rejects, the Rust structs are wrong (or the CDDL needs updating via ADR).
3. The implementation is the live behavior. If the spec says X but the implementation does Y and is correct under audit, the spec needs an ADR amendment.

The V3 spec went through 12+ rounds of APR (Automated Plan Reviser Pro) review with GPT-Pro 5.2 Extended Reasoning, with each round narrowing focus from architectural flaws → interface refinements → nuanced optimizations. The current spec converged in early 2026 and is the basis for the current implementation.

`FCP_Specification_V2.md` is retained only for historical interoperability context. New work targets V3. The transition scorecard at [`docs/FCP3_Transition_Scorecard.md`](docs/FCP3_Transition_Scorecard.md) tracks remaining V2-era surfaces that need to retire before the V3 cutover is complete.

---

## Performance Optimization Techniques (Catalog)

A non-exhaustive list of the concrete optimization patterns the workspace uses, with examples:

| Technique | Where Applied | Effect |
|-----------|---------------|--------|
| **O(1) indexed lookups** | `IndexedZoneKeyManifest` (`d2oa0`) — replaced linear search with HashMap | Recipient-key lookup in zone manifests went from O(n) to O(1) |
| **Ordered priority queue** | `fcp-store` repair queue (`u97n8`) — sorted `Vec` → `BTreeMap` keyed by `RepairQueueKey` | Repair-deficit ordering went from O(n) to O(log n) per insert |
| **Arena allocators** | `canonicalize_map` in `fcp-cbor` (`m7aoz`) — single arena `Vec<u8>` vs per-entry allocations | Map canonicalization allocation overhead amortized |
| **Pre-computed routing index** | `fcp-webhook` route dispatch (`7j7fa`) — HashMap of provider → handler | Per-request route lookup went from O(n) linear scan to O(1) |
| **Cursor-advance parsing** | `fcp-streaming` SSE parser (`gqpn5`) — advance read pointer instead of full rescan | Frame parsing avoids re-walking already-consumed bytes |
| **Single-flight coordination** | `fcp-oauth` token refresh (`p36a0`) — `fcp_async_core::channel::watch` gate for concurrent refreshes | N concurrent refresh requests collapse to 1 upstream call |
| **Per-zone sharding** | `fcp-host` `InvokeAuditChain` (`uwlj5`) — sharded by zone instead of global Mutex | Concurrent invokes in different zones no longer serialize on a single audit mutex |
| **Sorted-index cert selection** | `fcp-bootstrap` (`vkq68`) — O(log n) binary search vs linear scan | Cert selection during handshake went from O(n) to O(log n) |
| **Borrowed scan vs owned clone** | `fcp-tailscale` peer-tag scan (`qfsse`) — borrow peer-tag list instead of clone | Per-handshake heap allocation removed |
| **Repair coalesce** | `fcp-raptorq` repair-tail decode (`qmepq`) — batch repair-tail symbols into one decode | Tail-decode overhead amortized |
| **Coalesce signed-head broadcasts** | Audit-head gossip — emit one signed head per epoch, not per event | Signature operations on the audit path dropped from per-event to per-epoch |
| **Constant-time crypto comparison** | PQ secret types (`1zlht`) — `subtle::ConstantTimeEq` replaces `PartialEq` | Byte-by-byte timing side-channel closed |
| **Phase-preserving token bucket refill** | `fcp-ratelimit` (`sh6le`) — `last_refill = now - (elapsed % interval)` | Rate-limit drift accumulation eliminated |
| **Length-invariant deserialize** | PQ transparent byte envelopes (`kfr9j`) — custom `Deserialize` with length check | Length-bypass attack on transparent serde structs closed |
| **Per-pivot Gaussian elimination heap reduction** | `fcp-raptorq` dense fallback decoder | Heap allocations per decode pivot reduced |

Each of these landed with a Criterion bench under `fcp-bench` so regressions surface as numerical drift rather than as "feels slower." The benchmarks live as a forward-only ratchet: once a hot path is bench-covered, future changes cannot silently regress it.

---

## Disk and Build Hygiene

The workspace's multi-agent build pattern creates disk-pressure scenarios that wouldn't arise in a single-developer setup. Documenting the discipline that keeps things from melting:

### Per-Agent Build Quarantine

Cargo's default `target/` directory is workspace-relative. With 6 agents running concurrent `cargo build` / `cargo check` / `cargo test` in the same workspace, lock contention on `target/` becomes the bottleneck (and worse, partial-build poisoning becomes possible).

The pattern: every agent uses an isolated `CARGO_TARGET_DIR`:

```bash
# Per-agent, per-lane quarantine
export CARGO_TARGET_DIR=/tmp/fcp-<agent-name>
# or on macOS with a fast external NVMe:
export CARGO_TARGET_DIR=/Volumes/USB_NVME/fcp-<agent-name>
```

The 2026-05-02 swarm session caught a `target/debug` directory bloated to 248 GB across competing builds. Cleanup recovered ~252 GB. Subsequent sessions honor the `CARGO_TARGET_DIR` redirect by default.

### RCH Probe Directories

`.rch/probes/fcp-core/` and `.rch/probes/fcp-host/` are tracked probe packages that pin their `target-dir` under `/tmp`, outside the synced project tree. This keeps `rch` from spending most of the run syncing probe-local `target/` artifacts back into the repo after the remote check has already finished. Probe-local `target/` directories also stay excluded from git and `rch` sync rules so stale worker artifacts cannot leak back into the workspace.

Each probe root carries its own `.rchignore` because `rch`'s retrieval filtering is evaluated relative to the probe root, not the repository root.

### `.git/` Exclusion in `rch` Sync

The repository excludes `.git/` in both `.rchignore` and `.rch/config.toml`. Allowing local refs or `packed-refs` to sync without the corresponding object database can corrupt the worker clone and surface later as `RCH-E326` / `fatal: bad object HEAD`. The exclusion is a maintenance discipline, not an oversight.

### Stale Worker State Recovery

If `rch` fails during dependency planning with `RCH-E326`, or a worker clone reports `fatal: bad object HEAD`, the diagnosis is: worker-side canonical clone synced git refs or shallow metadata without the matching object database. Repair without rewriting the worktree:

```bash
git fetch --force --update-shallow --deepen=64 \
  origin +refs/heads/main:refs/remotes/origin/main
```

If `rch` reports `Remote command finished: exit=0` and only then fails during artifact retrieval, the compile/test itself succeeded — the failure is tooling state, not a Cargo failure.

---

## Agent-Friendly CLI Conventions

`fwc` is designed for AI agents first, humans second. The conventions:

### Every Command Has a Robot Mode

Bare invocations (`fwc list`) produce TOON-formatted human-readable output. Robot-mode invocations (`fwc list --json`, `fwc list --format ndjson`) produce structured machine-parseable output with stable field names. Robot output is part of the CLI's stable contract: a future version will not silently rename fields, drop fields, or change types.

### Exit Codes Are Stable

| Exit | Meaning |
|------|---------|
| 0 | Success |
| 1 | Operation failed (generic internal error) |
| 2 | Invalid arguments / usage error (parse) |
| 3 | Unknown command |
| 4 | Ambiguous correction (the command resolved to more than one candidate; guidance is printed) |
| 5 | Validation failure (schema mismatch, manifest invalid) |
| 6 | Policy denied (capability denied / authentication or policy refusal) |
| 7 | Connector/service error (the operation failed inside the connector or upstream service, e.g. rate limited) |
| 8 | Transport error / refused (the host endpoint was missing, unreachable, or unhealthy, and truthful-runtime resolution declined to fabricate an answer) |

An 8 is distinct from a 1: it signals "the command's truth source was unreachable and I refused to make something up" — which an agent should retry (with `--offline` or by waiting for the host to come back) rather than treating as a general failure.

### Stdout vs Stderr Discipline

Stdout is data-only. Every diagnostic (progress, warnings, retry notices, lint output) goes to stderr. This lets agents pipe `fwc invoke ... | jq .` without parsing failures, and lets `fwc list --json | tee` capture clean machine data.

### `--offline` Is an Opt-In

Hybrid catalog commands (`list`, `search`, `show`, `ops`, `schema`, `examples`, `suggest`, `template`, `validate`, `export-tools`) require an explicit `--offline` flag to fall back to artifact-backed data when the host is unreachable. Without `--offline`, they refuse rather than silently substituting stale data. This is the truthfulness invariant in action: agents that explicitly opt into offline mode know they're working from artifact data; agents that don't opt in get a refusal they can interpret correctly.

### Bare TUI Commands Are Discouraged in Agent Sessions

Some commands (`bv` without `--robot-*`, `cass` without `--robot`, bare `br`) launch interactive TUIs that block the session waiting for keystrokes. Agents must use the `--robot-*` flag variants. `fwc` itself has no TUI mode — every command is non-interactive by design.

### Help Output Is Machine-Parseable

`fwc <command> --help` produces structured help with a stable shape: usage line, description, arguments list (with `<name>` / `[name]` conventions), options list, and examples. The help format is consistent across all 50+ `fwc` commands so an agent that learned to parse one help screen can parse them all.

---

## Glossary

| Term | Definition |
|------|------------|
| **AAD** | Additional Authenticated Data — bytes covered by the AEAD authentication tag but not encrypted |
| **AEAD** | Authenticated Encryption with Associated Data (ChaCha20-Poly1305 in FCP) |
| **ApprovalToken** | A signed token authorizing elevation or declassification across the zone lattice |
| **Audit Head** | The latest event in a zone's hash-linked audit chain; quorum-signed |
| **Capability Token** | A COSE/CWT token granting permission to invoke a specific operation in a specific zone, with constraints |
| **CDP** | Chrome DevTools Protocol — used by the browser connector for real-browser automation |
| **Coverage bps** | Object placement coverage in basis points (0–10000 = 0–100%) |
| **CWT** | CBOR Web Token (RFC 8392) — the FCP capability-token format |
| **DERP** | Designated Encrypted Relay for Packets — Tailscale's fallback when direct connections fail |
| **ESI** | Encoding Symbol Identifier — per-symbol index in a RaptorQ stream |
| **FCPC** | Flywheel Connector Protocol Control plane framing — reliable, ordered, AEAD-encrypted |
| **FCPS** | Flywheel Connector Protocol Symbol framing — high-throughput, per-frame MAC |
| **FROST** | Flexible Round-Optimized Schnorr Threshold — threshold signing scheme producing Ed25519-compatible signatures |
| **HierVV** | Hierarchical Version Vector — compact causality summary across grouped peers |
| **HLC** | Hybrid Logical Clock — `(physical, logical)` pair tracking both wall-clock time and causal order |
| **HRW** | Highest Random Weight hashing — deterministic peer-selection function |
| **IBLT** | Invertible Bloom Lookup Table — set-difference data structure |
| **InstanceId** | Unique identifier for a running connector subprocess (binds capability tokens) |
| **KEM** | Key Encapsulation Mechanism (X-Wing is a hybrid KEM combining X25519 and ML-KEM-768) |
| **KID** | Key ID; identifier for a specific key within a multi-key keyring (used for rotation) |
| **MeshNode** | A device participating in the FCP mesh |
| **ML-DSA-65** | NIST FIPS 204 post-quantum signature scheme (formerly CRYSTALS-Dilithium-3) |
| **OperationIntent** | A pre-commit object naming the idempotency key before invoke; required for Strict/Risky operations |
| **PCS** | Post-Compromise Security — MLS/TreeKEM-based key healing after a device is removed |
| **Provenance** | Per-data tracking of origin zone, current zone, integrity/confidentiality labels, taint flags |
| **RaptorQ** | Fountain code (RFC 6330) used for all symbol-encoded objects |
| **Receipt** | Signed proof of operation execution; used for idempotency and audit |
| **Revocation** | First-class object invalidating tokens, keys, or devices |
| **SLO** | Service Level Objective — target coverage / availability for an object placement policy |
| **SPKI** | Subject Public Key Info — used for certificate pinning in the egress proxy |
| **Symbol** | A RaptorQ-encoded fragment of an object |
| **Tailscale** | The mesh networking, identity, and ACL substrate |
| **Taint** | Compositional flags on provenance (`PUBLIC_INPUT`, `EXTERNAL_INPUT`, `PROMPT_SURFACE`, etc.) |
| **TOON** | Token-Optimized Output Notation — `fwc`'s default output format |
| **TreeKEM** | The MLS group-key agreement protocol; used for PCS zones |
| **TUF** | The Update Framework — supply-chain root pinning |
| **WASI** | WebAssembly System Interface — used for cross-platform sandboxed connectors |
| **X-Wing** | Hybrid X25519 + ML-KEM-768 KEM (RustCrypto draft-06) |
| **Zone** | A cryptographic namespace with its own symmetric encryption key |
| **ZoneKeyManifest** | Owner-signed object distributing zone symmetric keys via HPKE; V4 supports hybrid PQ wrap |

---

## License

MIT License (with OpenAI/Anthropic Rider). See [LICENSE](LICENSE).
