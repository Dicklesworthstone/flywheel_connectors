# AGENTS.md — Flywheel Connector Protocol (FCP)

> Guidelines for AI coding agents working in this Rust codebase.

---

## RULE 0 - THE FUNDAMENTAL OVERRIDE PREROGATIVE

If I tell you to do something, even if it goes against what follows below, YOU MUST LISTEN TO ME. I AM IN CHARGE, NOT YOU.

---

## RULE 0.5 — NO BRANCHES, NO WORKTREES. EVER. ONLY `main`.

**THIS PROJECT HAS EXACTLY ONE BRANCH: `main`.** (`master` exists only as a legacy mirror of `main` — see the branch rule below. It is NOT a second working branch.)

**YOU ARE ABSOLUTELY FORBIDDEN FROM:**
- Creating ANY git branch other than `main` — no `feature/*`, no `codex/*`, no `icy-*`/`sage-*`, no dated branches, no "just-in-case" safety branches. **NONE.**
- Creating ANY git worktree — no `git worktree add`, no `.claude/worktrees`, no `/tmp/fcp-*` checkouts, no "isolated copy" of the repo. **NONE.**
- Doing work on a detached HEAD and pushing it as a new ref.

**WHY THIS MATTERS:** Branch and worktree proliferation has repeatedly created hundreds of orphaned refs and detached checkouts that bury useful work, waste enormous disk, confuse every other agent, and force expensive manual consolidation passes to fold the scattered work back into `main`. We always want `main` to hold the latest, best, most optimized, most mature and correct code — that is impossible when work is fragmented across a graveyard of branches and worktrees.

**WHAT TO DO INSTEAD — MCP Agent Mail advisory file reservations:**
Multiple agents work in this single `main` checkout simultaneously. You coordinate to avoid stepping on each other NOT by branching, but by **reserving the files you are about to edit** via MCP Agent Mail (see the "MCP Agent Mail" section below):

```
file_reservation_paths(project_key, agent_name, ["connectors/foo/**"], ttl_seconds=3600, exclusive=true, reason="<bead-id>")
```

Edit directly on `main`, commit on `main`, push `main`. If you hit a `FILE_RESERVATION_CONFLICT`, wait or narrow your patterns — do NOT escape into a branch or worktree to dodge the conflict.

**If you find yourself typing `git branch`, `git checkout -b`, `git switch -c`, or `git worktree add` — STOP. You are about to violate this rule.** The only acceptable answer to "where should this work go?" is: **on `main`, after reserving the files.**

If you encounter pre-existing stray branches or worktrees, do not silently delete them (they may hold unmerged work) — surface them so their content can be folded into `main` first, then cleaned up.

---

## AGENT MAIL (am) PROCESS PROTECTION — DO NOT TOUCH

**NEVER run any of these commands:**
- `am service restart` / `am service stop`
- `am doctor fix` / `am doctor repair` / `am doctor reconstruct`
- `kill` targeting any `am`, `am serve-http`, or `mcp-agent-mail` process

The `am serve-http` process is a **shared singleton** that all agents depend on. Restarting or killing it disrupts every other agent. Multiple agents running `am service restart` create a **restart cascade** that makes the service permanently unavailable.

**If `am` commands fail or the API is unreachable:** retry once after a few seconds, then proceed with your work WITHOUT agent-mail. Do NOT attempt to diagnose, repair, or restart the service.

---

## RULE NUMBER 1: NO FILE DELETION

**YOU ARE NEVER ALLOWED TO DELETE A FILE WITHOUT EXPRESS PERMISSION.** Even a new file that you yourself created, such as a test code file. You have a horrible track record of deleting critically important files or otherwise throwing away tons of expensive work. As a result, you have permanently lost any and all rights to determine that a file or folder should be deleted.

**YOU MUST ALWAYS ASK AND RECEIVE CLEAR, WRITTEN PERMISSION BEFORE EVER DELETING A FILE OR FOLDER OF ANY KIND.**

---

## Irreversible Git & Filesystem Actions — DO NOT EVER BREAK GLASS

1. **Absolutely forbidden commands:** `git reset --hard`, `git clean -fd`, `rm -rf`, or any command that can delete or overwrite code/data must never be run unless the user explicitly provides the exact command and states, in the same message, that they understand and want the irreversible consequences.
2. **No guessing:** If there is any uncertainty about what a command might delete or overwrite, stop immediately and ask the user for specific approval. "I think it's safe" is never acceptable.
3. **Safer alternatives first:** When cleanup or rollbacks are needed, request permission to use non-destructive options (`git status`, `git diff`, `git stash`, copying to backups) before ever considering a destructive command.
4. **Mandatory explicit plan:** Even after explicit user authorization, restate the command verbatim, list exactly what will be affected, and wait for a confirmation that your understanding is correct. Only then may you execute it—if anything remains ambiguous, refuse and escalate.
5. **Document the confirmation:** When running any approved destructive command, record (in the session notes / final response) the exact user text that authorized it, the command actually run, and the execution time. If that record is absent, the operation did not happen.

---

## Git Branch: ONLY Use `main`, NEVER `master`

**The default branch is `main`. The `master` branch exists only for legacy URL compatibility.**

> **SEE RULE 0.5 ABOVE: NO branches and NO worktrees are permitted in this repo — only `main`.** Coordinate via MCP Agent Mail file reservations, never by branching or creating a worktree. This section governs the `main`/`master` mirror relationship only; it does NOT authorize creating any other branch.

- **All work happens on `main`** — commits and PRs land on `main`; there are no feature branches
- **Never reference `master` in code or docs** — if you see `master` anywhere, it's a bug that needs fixing
- **The `master` branch must stay synchronized with `main`** — after pushing to `main`, also push to `master`:
  ```bash
  git push origin main:master
  ```

**If you see `master` referenced anywhere:**
1. Update it to `main`
2. Ensure `master` is synchronized: `git push origin main:master`

---

## Toolchain: Rust & Cargo

We only use **Cargo** in this project, NEVER any other package manager.

- **Edition:** Rust 2024 (nightly required — see `rust-toolchain.toml`)
- **Dependency versions:** Explicit versions for stability
- **Configuration:** Cargo.toml workspace with `workspace = true` pattern
- **Unsafe code:** Denied at workspace level (`unsafe_code = "deny"`); individual crates that legitimately need unsafe (e.g., `fcp-sandbox`) may override

### Key Dependencies

| Crate | Purpose |
|-------|---------|
| `asupersync` | Async runtime (FCP3 native; replaces tokio) |
| `fcp-async-core` | Runtime abstraction layer (wraps asupersync, quarantines tokio compat) |
| `async-trait` | Async trait support for connector interfaces |
| `futures-util` | Async stream combinators |
| `serde` + `serde_json` | JSON serialization for FCP protocol messages |
| `ciborium` | CBOR serialization for binary protocol |
| `ed25519-dalek` + `x25519-dalek` | Cryptographic signatures and key exchange |
| `blake3` | Fast cryptographic hashing |
| `chacha20poly1305` | AEAD symmetric encryption |
| `hpke` | Hybrid Public Key Encryption |
| `coset` | COSE (CBOR Object Signing and Encryption) |
| `reqwest` | HTTP client for request-response connectors |
| `asupersync` (websocket) | WebSocket support for streaming connectors (native, replaces tokio-tungstenite) |
| `wasmtime` + `wasmtime-wasi` | WASI sandbox runtime for connector isolation |
| `raptorq` | Fountain codes for reliable data transfer |
| `tough` + `sigstore` | Supply-chain hardening (TUF + Sigstore verification) |
| `uuid` | Unique identifiers for sessions, correlations |
| `chrono` | Timestamps for capabilities and events |
| `bytes` | Efficient byte handling for binary protocol |
| `clap` | CLI argument parsing |
| `thiserror` | Ergonomic error type derivation |
| `tracing` | Structured logging and observability |

### Release Profile

The release build optimizes for binary size:

```toml
[profile.release]
opt-level = "z"     # Optimize for size (lean binary for distribution)
lto = true          # Link-time optimization
codegen-units = 1   # Single codegen unit for better optimization
panic = "abort"     # Smaller binary, no unwinding overhead
strip = true        # Remove debug symbols
```

---

## Code Editing Discipline

### No Script-Based Changes

**NEVER** run a script that processes/changes code files in this repo. Brittle regex-based transformations create far more problems than they solve.

- **Always make code changes manually**, even when there are many instances
- For many simple changes: use parallel subagents
- For subtle/complex changes: do them methodically yourself

### No File Proliferation

If you want to change something or add a feature, **revise existing code files in place**.

**NEVER** create variations like:
- `connectorV2.rs`
- `connector_improved.rs`
- `connector_enhanced.rs`

New files are reserved for **genuinely new functionality** that makes zero sense to include in any existing file. The bar for creating new files is **incredibly high**.

---

## Backwards Compatibility

We do not care about backwards compatibility—we're in early development with no users. We want to do things the **RIGHT** way with **NO TECH DEBT**.

- Never create "compatibility shims"
- Never create wrapper functions for deprecated APIs
- Just fix the code directly

---

## Compiler Checks (CRITICAL)

**After any substantive code changes, you MUST verify no errors were introduced. In shared sessions, offload the Cargo work through `rch`:**

```bash
# Check for compiler errors and warnings (workspace-wide)
rch exec -- cargo check --workspace --all-targets

# Check for clippy lints (pedantic + nursery are enabled)
rch exec -- cargo clippy --workspace --all-targets -- -D warnings

# Verify formatting
rch exec -- cargo fmt --check
```

For a narrow `fcp-core` compiler smoke check, use the tracked probe package:

```bash
(cd .rch/probes/fcp-core && rch exec -- cargo check)
```

For a narrow `fcp-host` library smoke check, use:

```bash
(cd .rch/probes/fcp-host && rch exec -- cargo check)
```

This keeps `rch` from syncing the full connector workspace when you only need the
`fcp-core` or `fcp-host` library closure. These probe packages also pin their
`target-dir` under `/tmp` so `rch` does not spend minutes syncing probe-local
build artifacts back into the repo, and probe-local `target/` trees remain
excluded from git and `rch` sync rules so stale worker artifacts do not leak
back into the workspace. Each probe root also carries its own `.rchignore`
because `rch` applies retrieval-side filtering relative to the current project
root, not the repository root. It is a targeted optimization, not a
substitute for workspace-wide verification after broad or cross-crate changes.

Do not point one probe at a different crate with `cargo check --manifest-path ...`.
`rch` plans sync roots from the current probe directory, so that pattern can compile
stale remote code for the target crate.

If you see errors, **carefully understand and resolve each issue**. Read sufficient context to fix them the RIGHT way.

---

## Testing

### Testing Policy

Every component crate includes inline `#[cfg(test)]` unit tests alongside the implementation. Tests must cover:
- Happy path
- Edge cases (empty input, max values, boundary conditions)
- Error conditions

Cross-component integration coverage is distributed across crate-local `tests/`
directories (for example `crates/fcp-conformance/tests`,
`crates/fcp-e2e/tests`, and `crates/fcp-host/tests`) plus per-connector
integration tests. Do not assume a single monolithic root `tests/` directory is
the primary integration surface.

### Unit Tests

```bash
# Run all tests across the workspace
rch exec -- cargo test --workspace

# Run with output
rch exec -- cargo test --workspace -- --nocapture

# Run tests for a specific crate
rch exec -- cargo test -p fcp-core
rch exec -- cargo test -p fcp-protocol
rch exec -- cargo test -p fcp-crypto
rch exec -- cargo test -p fcp-sandbox
rch exec -- cargo test -p fcp-manifest
rch exec -- cargo test -p fcp-sdk
rch exec -- cargo test -p fcp-conformance

# Run specific connector tests
rch exec -- cargo test -p fcp-telegram
rch exec -- cargo test -p fcp-discord

# Run tests with all features enabled
rch exec -- cargo test --workspace --all-features
```

### Test Categories

| Crate | Focus Areas |
|-------|-------------|
| `fcp-core` | Zone model, capability types, principal identity, error types |
| `fcp-protocol` | FCP message framing, serialization round-trips, version negotiation |
| `fcp-crypto` | Ed25519 signing, X25519 key exchange, HPKE encryption, COSE token construction |
| `fcp-cbor` | CBOR encoding/decoding, deterministic serialization |
| `fcp-manifest` | Manifest parsing, validation, capability declaration |
| `fcp-sandbox` | WASI isolation, filesystem filtering, network policy enforcement |
| `fcp-ratelimit` | Token bucket, sliding window, burst allowance |
| `fcp-oauth` | OAuth2 flows, token refresh, redirect handling |
| `fcp-registry` | Connector discovery, version resolution, signature verification |
| `fcp-sdk` | SDK ergonomics, connector lifecycle, trait contracts |
| `fcp-conformance` | Cross-crate protocol conformance, interop validation |
| `fcp-host` | Gateway orchestration, zone routing, capability enforcement |
| `fcp-mesh` | Multi-node connector mesh, routing, discovery |
| `fcp-store` | Persistent state, key-value storage, migration |
| `fcp-audit` | Audit log generation, tamper detection |
| `fcp-streaming` | Event stream framing, backpressure, reconnection |
| `fcp-webhook` | Webhook delivery, retry, signature verification |
| `fcp-graphql` | GraphQL schema, resolver contracts |
| `fcp-tailscale` | Tailscale integration, ACL mapping |
| `fcp-telemetry` | Metrics export, span propagation |
| `fcp-raptorq` | Fountain code encoding/decoding, loss recovery |
| `fcp-bootstrap` | First-run setup, credential provisioning |
| `fcp-e2e` | End-to-end integration scenarios |
| `fcp-testkit` | Shared test helpers, mock connectors, fixtures |
| `connectors/*` | Per-connector unit + integration tests |
| `fuzz/` | Fuzz targets for protocol parsing and CBOR handling |
| `crates/*/tests` | Cross-crate integration, host-backed scenarios, test vectors |

### Mock External Services

Use mock servers for external APIs in tests:
- Never make real API calls in unit tests
- Use `wiremock` or similar for HTTP mocking
- Test error conditions and rate limits

---

## Third-Party Library Usage

If you aren't 100% sure how to use a third-party library, **SEARCH ONLINE** to find the latest documentation and current best practices.

---

## FCP (Flywheel Connector Protocol) — This Project

**This is the project you're working on.** FCP is a secure, modular, high-performance framework for integrating external services into the Agent Flywheel ecosystem. It enables AI coding agents to safely interact with messaging platforms, cloud services, productivity tools, and other external systems while maintaining strict security boundaries.

### What It Does

Provides a zone-based, capability-gated connector architecture where self-contained binaries implement the FCP interface to bridge AI agents with external services (messaging, cloud, databases, browsers) through a central Gateway with cryptographic verification and WASI sandboxing.

### Architecture

```
Gateway -> Zone Check -> Capability Check -> Connector -> External Service
                                                |
                                    Sandbox (isolated filesystem, filtered network)
```

### Workspace Structure

This is a schematic map, not an exhaustive directory dump. The current tree has
42 crate directories (42 active Cargo workspace members) and 177 connector
crates.

```
flywheel_connectors/
|-- Cargo.toml                         # Workspace root
|-- crates/
|   |-- fcp-async-core/                # Runtime substrate and async primitives
|   |-- fcp-async-core-macros/         # Async-core proc macros
|   |-- fcp-core/                      # Zone model, capabilities, provenance, lifecycle
|   |-- fcp-protocol/                  # FCPC/FCPS framing and sessions
|   |-- fcp-crypto/                    # Ed25519, X25519, HPKE, COSE, Blake3
|   |-- fcp-cbor/                      # Deterministic CBOR serialization
|   |-- fcp-manifest/                  # Connector manifest parsing and validation
|   |-- fcp-sandbox/                   # WASI/runtime isolation and guardrails
|   |-- fcp-store/                     # Object store, symbol store, repair, GC
|   |-- fcp-raptorq/                   # Fountain-code codec and chunking
|   |-- fcp-tailscale/                 # Mesh identity and ACL/tag integration
|   |-- fcp-mesh/                      # Mesh routing, admission, placement, leases
|   |-- fcp-host/                      # Host/orchestrator and admin API
|   |-- fcp-sdk/                       # Connector authoring/runtime helpers
|   |-- fcp-streaming/                 # Shared streaming substrate
|   |-- fcp-oauth/                     # OAuth flows and token lifecycle
|   |-- fcp-graphql/                   # Typed GraphQL client helpers
|   |-- fcp-google-discovery/          # Google discovery/provisioning substrate
|   |-- fcp-registry/                  # Registry/install/update verification
|   |-- fcp-telemetry/                 # Metrics and structured tracing
|   |-- fcp-webhook/                   # Webhook delivery/runtime helpers
|   |-- fcp-audit/                     # Audit receipts and logging
|   |-- fcp-bootstrap/                 # First-run setup and provisioning
|   |-- fcp-conformance/               # Protocol conformance tooling/tests
|   |-- fcp-testkit/                   # Shared fixtures and mocks
|   |-- fcp-e2e/                       # End-to-end harness
|   +-- fwc/                           # Canonical Flywheel connectors CLI
|-- connectors/                        # 177 connector crates at varying maturity
|   |-- anthropic/
|   |-- discord/
|   |-- github/
|   |-- gmail/
|   |-- slack/
|   |-- stripe/
|   |-- telegram/
|   |-- kubernetes/
|   +-- ...
|-- crates/fcp-conformance/tests/      # Cross-crate conformance coverage
|-- crates/fcp-e2e/tests/              # Host-backed end-to-end scenarios
|-- crates/fcp-host/tests/             # Host/admin integration tests
+-- fuzz/                              # Fuzz testing targets
```

### Core Concepts

| Concept | Description |
|---------|-------------|
| **Connector** | A self-contained binary implementing the FCP interface |
| **Zone** | A security boundary defining trust level and capabilities |
| **Capability** | A specific permission granted to a connector |
| **Manifest** | Embedded metadata describing connector properties |
| **Gateway** | The Flywheel component orchestrating connectors |
| **Principal** | An identity (user, agent, or service) making requests |

### Key Principles

1. **Secure by Default**: Connectors start with zero capabilities; everything must be explicitly declared
2. **Mechanical Enforcement**: Security via type system and binary boundaries, NOT prompts.
   - *Worked example — capability-token typestate:* `CapabilityToken<UnboundVerified>` and `CapabilityToken<BoundVerified>` are distinct types. An operation executor that requires full instance-binding declares `fn execute(_: CapabilityToken<BoundVerified>, ...)`. An `UnboundVerified` token (produced by the gateway, which does not yet know the connector's real `InstanceId`) does NOT compile against that signature. The connector runtime must call `promote_with_instance` to obtain the bound variant. Enforced mechanically by the compiler + `trybuild` tests in `crates/fcp-core/tests/typestate_compile_fail.rs`. Design docs: `docs/architecture/adr/jkcka-typestate-split.md` and `docs/architecture/adr/jkcka-call-sites.md`.
   - *Worked example — responder-picks suite negotiation:* `negotiate_suite` in `fcp_protocol::session` returns the responder's first-preferred suite that the initiator also offers, with a `MINIMUM_SUITE` floor. See `docs/protocol/session-handshake.md`.
   - *Worked example — typed auth-claim schema:* Capability-token claim layout lives in `fcp-auth-schema::AuthClaims` (single source of truth consumed by both `fcp-crypto` builder and `fcp-core` verifier). Schema changes are deployment-gated by `schema_version`; see `docs/architecture/adr/8n0rm-claim-schema-versioning.md`.
3. **Zone-First Isolation**: Every request/event is attached to a Zone; cross-zone access requires explicit policy
4. **Capability-Based Auth**: Cryptographically scoped tokens for every operation

### Connector Archetypes

When implementing connectors, identify which archetype(s) apply:

| Archetype | Pattern | Examples |
|-----------|---------|----------|
| **Request-Response** | Agent -> Service -> Agent | REST APIs, GraphQL, gRPC |
| **Streaming** | Service -> Agent (continuous) | WebSocket, SSE, log tailing |
| **Bidirectional** | Agent <-> Service | Chat protocols, collaborative apps |
| **Polling** | Agent -> Service (periodic) | Email IMAP, RSS feeds |
| **Webhook** | Service -> Agent (push) | GitHub hooks, Stripe events |
| **Queue/Pub-Sub** | Agent <-> Broker | Redis, NATS, Kafka |
| **File/Blob** | Agent -> Storage | S3, GCS, local filesystem |
| **Database** | Agent -> DB (query) | PostgreSQL, vector DBs |
| **CLI/Process** | Agent -> spawn -> Process | git, kubectl, terraform |
| **Browser** | Agent -> CDP -> Browser | Automation, scraping |

### Standard Zone Hierarchy

```
z:owner          -> Full owner access (personal private data)
z:private        -> Personal email, calendar, files
z:work           -> Work services, internal systems
z:project:<name> -> Per-project isolation
z:community      -> Semi-trusted communities (Discord servers)
z:public         -> Public/untrusted inputs
```

### Zone Rules

1. **Single-zone binding**: A connector instance MUST bind to exactly one zone
2. **Default deny**: If a capability isn't granted to a zone, it's impossible to invoke
3. **No cross-connector calling**: All composition goes through the Gateway

### Performance Targets

Connectors must be "unbelievably fast and reliable". Canonical targets live in
[README.md](README.md#performance-targets); reproduced here for quick reference:

| Metric | Target (p50/p99) | How Measured |
|--------|------------------|--------------|
| Cold start (connector activate) | < 100ms / < 500ms | Host-backed connector activation benchmark harness |
| Local invoke latency (same node) | < 2ms / < 10ms | Host-backed local invoke scenario |
| Tailnet invoke latency (LAN) | < 20ms / < 100ms | Mesh invoke benchmark on direct path |
| Tailnet invoke latency (DERP) | < 150ms / < 500ms | Mesh invoke benchmark on DERP path |
| Memory overhead | < 10MB per connector | Sandbox limits |
| CPU overhead | < 1% idle | Event-driven architecture |

Achieve this through:
- Zero-copy parsing where possible
- Connection pooling for HTTP clients
- Lazy initialization of expensive resources
- Static dispatch over dynamic dispatch

### Key Design Decisions

- **Self-contained binaries** — one binary + one manifest file per connector, no interpreted runtimes
- **WASI sandboxing** via wasmtime for filesystem and network isolation
- **Ed25519 + X25519 + HPKE** for signing, key exchange, and hybrid encryption
- **CBOR wire format** with deterministic serialization for protocol messages
- **Supply-chain hardening** via TUF (tough) and Sigstore for connector verification
- **Fountain codes** (RaptorQ) for reliable data transfer over lossy channels
- **Zone-first security model** — every operation scoped to exactly one zone
- **Capability tokens** — cryptographically scoped, time-bounded permissions
- **Structured tracing** throughout — every connector operation emits spans with latency and context
- **Responder-picks suite negotiation** — session crypto-suite selection is controlled by the responder's preference order, with a `MINIMUM_SUITE` floor. See `docs/protocol/session-handshake.md` before adding or deprecating suites.

---

## FCP Development Philosophy

### Porting Existing Code to Rust

Many connectors will be Rust reimplementations of existing libraries written in Swift, TypeScript, Python, Go, etc. The approach:

1. **Clone to /tmp for analysis** - Never clone external repos into this project; use `/tmp/fcp-analysis/` for studying source code
2. **Study the original thoroughly** - Understand all edge cases, error handling, and protocol details
3. **Reimplement from scratch** - Don't transliterate; write idiomatic Rust
4. **Improve on the original** - Better error handling, more robustness, stricter types
5. **Cross-platform from day one** - Must work on Linux, macOS, and Windows

```bash
# Example: analyzing a library for porting
mkdir -p /tmp/fcp-analysis
git clone https://github.com/example/bird /tmp/fcp-analysis/bird
# Study the code, then implement fresh in this repo
```

Examples of libraries to port:
- **gog** (Google services) -> `fcp-google`
- **bird** (messaging platforms) -> `fcp-telegram`, `fcp-discord`, etc.
- **whisperX** (voice recognition) -> `fcp-whisper`
- **qmd** (markdown processing) -> `fcp-markdown`

### Automate Everything

**If something CAN be automated, it SHOULD be automated.** Users should not have to:
- Manually create Telegram bots via BotFather
- Manually configure OAuth redirect URLs
- Manually copy-paste API keys between systems
- Manually set up webhook endpoints

The connector should handle all setup automatically where possible, with clear prompts only for information that truly requires human input (like "which Google account?").

### No Interpreted Runtimes

FCP connectors MUST be self-contained binaries. The following are **explicitly forbidden**:

- Python projects requiring `pip install` or virtual environments
- Node.js projects requiring `npm install`
- Ruby gems, Java JARs, or any runtime dependencies
- Docker containers as the primary distribution mechanism

**Why?**
- Interpreted runtimes add startup latency
- Dependency resolution is fragile and non-reproducible
- Security scanning is harder with dynamic dependencies
- Cross-platform distribution becomes a nightmare

A valid FCP connector is: **one binary + one manifest file**.

### Security-First Implementation

When implementing connectors:

1. **Secrets never touch disk** - Keep credentials in memory only
2. **Validate all external input** - Assume everything from external services is hostile
3. **Timeout everything** - No unbounded waits on external services
4. **Log carefully** - Never log tokens, passwords, or PII
5. **Fail closed on auth errors** - When in doubt, deny access

### Connector README Convention

Every connector should have an operator-facing `connectors/<name>/README.md`
that follows `docs/connector-readme-template.md`. Treat it as the stable
contract for the connector's current runtime surface, not as marketing copy.

Required README content:
- Status, canonical bead ID, verification script or command, and upstream docs
- Purpose and explicit scope boundary
- Current operation inventory with capabilities, risk, safety, and idempotency
- Auth, zone, sandbox, and network invariants
- Known non-goals, limits, quirks, and remediation guidance
- Redaction-safe verification commands and evidence expectations

Do not invent unsupported operations or generic provider boilerplate. Source the
README from `manifest.toml`, connector introspection/operation metadata,
provider docs, tests, and the actual request paths in the connector code. If a
connector is incubating or intentionally has no live provider surface, say that
plainly instead of filling the template with optimistic placeholders.

---

## MCP Agent Mail — Multi-Agent Coordination

A mail-like layer that lets coding agents coordinate asynchronously via MCP tools and resources. Provides identities, inbox/outbox, searchable threads, and advisory file reservations with human-auditable artifacts in Git.

### Why It's Useful

- **Prevents conflicts:** Explicit file reservations (leases) for files/globs
- **Token-efficient:** Messages stored in per-project archive, not in context
- **Quick reads:** `resource://inbox/...`, `resource://thread/...`

### Same Repository Workflow

1. **Register identity:**
   ```
   ensure_project(project_key=<abs-path>)
   register_agent(project_key, program, model)
   ```

2. **Reserve files before editing:**
   ```
   file_reservation_paths(project_key, agent_name, ["src/**"], ttl_seconds=3600, exclusive=true)
   ```

3. **Communicate with threads:**
   ```
   send_message(..., thread_id="FEAT-123")
   fetch_inbox(project_key, agent_name)
   acknowledge_message(project_key, agent_name, message_id)
   ```

4. **Quick reads:**
   ```
   resource://inbox/{Agent}?project=<abs-path>&limit=20
   resource://thread/{id}?project=<abs-path>&include_bodies=true
   ```

### Macros vs Granular Tools

- **Prefer macros for speed:** `macro_start_session`, `macro_prepare_thread`, `macro_file_reservation_cycle`, `macro_contact_handshake`
- **Use granular tools for control:** `register_agent`, `file_reservation_paths`, `send_message`, `fetch_inbox`, `acknowledge_message`

### Common Pitfalls

- `"from_agent not registered"`: Always `register_agent` in the correct `project_key` first
- `"FILE_RESERVATION_CONFLICT"`: Adjust patterns, wait for expiry, or use non-exclusive reservation
- **Auth errors:** If JWT+JWKS enabled, include bearer token with matching `kid`

---

## Beads (br) — Dependency-Aware Issue Tracking

Beads provides a lightweight, dependency-aware issue database and CLI (`br` - beads_rust) for selecting "ready work," setting priorities, and tracking status. It complements MCP Agent Mail's messaging and file reservations.

**Important:** `br` is non-invasive—it NEVER runs git commands automatically. You must manually commit changes after `br sync --flush-only`.

### Conventions

- **Single source of truth:** Beads for task status/priority/dependencies; Agent Mail for conversation and audit
- **Shared identifiers:** Use Beads issue ID (e.g., `br-123`) as Mail `thread_id` and prefix subjects with `[br-123]`
- **Reservations:** When starting a task, call `file_reservation_paths()` with the issue ID in `reason`

### Typical Agent Flow

1. **Pick ready work (Beads):**
   ```bash
   br ready --json  # Choose highest priority, no blockers
   ```

2. **Reserve edit surface (Mail):**
   ```
   file_reservation_paths(project_key, agent_name, ["src/**"], ttl_seconds=3600, exclusive=true, reason="br-123")
   ```

3. **Announce start (Mail):**
   ```
   send_message(..., thread_id="br-123", subject="[br-123] Start: <title>", ack_required=true)
   ```

4. **Work and update:** Reply in-thread with progress

5. **Complete and release:**
   ```bash
   br close 123 --reason "Completed"
   br sync --flush-only  # Export to JSONL (no git operations)
   ```
   ```
   release_file_reservations(project_key, agent_name, paths=["src/**"])
   ```
   Final Mail reply: `[br-123] Completed` with summary

### Mapping Cheat Sheet

| Concept | Value |
|---------|-------|
| Mail `thread_id` | `br-###` |
| Mail subject | `[br-###] ...` |
| File reservation `reason` | `br-###` |
| Commit messages | Include `br-###` for traceability |

---

## bv — Graph-Aware Triage Engine

bv is a graph-aware triage engine for Beads projects (`.beads/beads.jsonl`). It computes PageRank, betweenness, critical path, cycles, HITS, eigenvector, and k-core metrics deterministically.

**Scope boundary:** bv handles *what to work on* (triage, priority, planning). For agent-to-agent coordination (messaging, work claiming, file reservations), use MCP Agent Mail.

**CRITICAL: Use ONLY `--robot-*` flags. Bare `bv` launches an interactive TUI that blocks your session.**

### The Workflow: Start With Triage

**`bv --robot-triage` is your single entry point.** It returns:
- `quick_ref`: at-a-glance counts + top 3 picks
- `recommendations`: ranked actionable items with scores, reasons, unblock info
- `quick_wins`: low-effort high-impact items
- `blockers_to_clear`: items that unblock the most downstream work
- `project_health`: status/type/priority distributions, graph metrics
- `commands`: copy-paste shell commands for next steps

```bash
bv --robot-triage        # THE MEGA-COMMAND: start here
bv --robot-next          # Minimal: just the single top pick + claim command
```

### Command Reference

**Planning:**
| Command | Returns |
|---------|---------|
| `--robot-plan` | Parallel execution tracks with `unblocks` lists |
| `--robot-priority` | Priority misalignment detection with confidence |

**Graph Analysis:**
| Command | Returns |
|---------|---------|
| `--robot-insights` | Full metrics: PageRank, betweenness, HITS, eigenvector, critical path, cycles, k-core, articulation points, slack |
| `--robot-label-health` | Per-label health: `health_level`, `velocity_score`, `staleness`, `blocked_count` |
| `--robot-label-flow` | Cross-label dependency: `flow_matrix`, `dependencies`, `bottleneck_labels` |
| `--robot-label-attention [--attention-limit=N]` | Attention-ranked labels |

**History & Change Tracking:**
| Command | Returns |
|---------|---------|
| `--robot-history` | Bead-to-commit correlations |
| `--robot-diff --diff-since <ref>` | Changes since ref: new/closed/modified issues, cycles |

**Other:**
| Command | Returns |
|---------|---------|
| `--robot-burndown <sprint>` | Sprint burndown, scope changes, at-risk items |
| `--robot-forecast <id\|all>` | ETA predictions with dependency-aware scheduling |
| `--robot-alerts` | Stale issues, blocking cascades, priority mismatches |
| `--robot-suggest` | Hygiene: duplicates, missing deps, label suggestions |
| `--robot-graph [--graph-format=json\|dot\|mermaid]` | Dependency graph export |
| `--export-graph <file.html>` | Interactive HTML visualization |

### Scoping & Filtering

```bash
bv --robot-plan --label backend              # Scope to label's subgraph
bv --robot-insights --as-of HEAD~30          # Historical point-in-time
bv --recipe actionable --robot-plan          # Pre-filter: ready to work
bv --recipe high-impact --robot-triage       # Pre-filter: top PageRank
bv --robot-triage --robot-triage-by-track    # Group by parallel work streams
bv --robot-triage --robot-triage-by-label    # Group by domain
```

### Understanding Robot Output

**All robot JSON includes:**
- `data_hash` — Fingerprint of source beads.jsonl
- `status` — Per-metric state: `computed|approx|timeout|skipped` + elapsed ms
- `as_of` / `as_of_commit` — Present when using `--as-of`

**Two-phase analysis:**
- **Phase 1 (instant):** degree, topo sort, density
- **Phase 2 (async, 500ms timeout):** PageRank, betweenness, HITS, eigenvector, cycles

### jq Quick Reference

```bash
bv --robot-triage | jq '.quick_ref'                        # At-a-glance summary
bv --robot-triage | jq '.recommendations[0]'               # Top recommendation
bv --robot-plan | jq '.plan.summary.highest_impact'        # Best unblock target
bv --robot-insights | jq '.status'                         # Check metric readiness
bv --robot-insights | jq '.Cycles'                         # Circular deps (must fix!)
```

---

## UBS — Ultimate Bug Scanner

**Golden Rule:** `ubs <changed-files>` before every commit. Exit 0 = safe. Exit >0 = fix & re-run.

### Commands

```bash
ubs file.rs file2.rs                    # Specific files (< 1s) — USE THIS
ubs $(git diff --name-only --cached)    # Staged files — before commit
ubs --only=rust,toml src/               # Language filter (3-5x faster)
ubs --ci --fail-on-warning .            # CI mode — before PR
ubs .                                   # Whole project (ignores target/, Cargo.lock)
```

### Output Format

```
Warning  Category (N errors)
    file.rs:42:5 - Issue description
    Suggested fix
Exit code: 1
```

Parse: `file:line:col` -> location | Suggested fix -> how to fix | Exit 0/1 -> pass/fail

### Fix Workflow

1. Read finding -> category + fix suggestion
2. Navigate `file:line:col` -> view context
3. Verify real issue (not false positive)
4. Fix root cause (not symptom)
5. Re-run `ubs <file>` -> exit 0
6. Commit

### Bug Severity

- **Critical (always fix):** Memory safety, use-after-free, data races, SQL injection
- **Important (production):** Unwrap panics, resource leaks, overflow checks
- **Contextual (judgment):** TODO/FIXME, println! debugging

---

## RCH — Remote Compilation Helper

RCH offloads `cargo build`, `cargo test`, `cargo clippy`, and other compilation commands to a fleet of 8 remote Contabo VPS workers instead of building locally. This prevents compilation storms from overwhelming csd when many agents run simultaneously.

**RCH is installed at `~/.local/bin/rch` and is hooked into Claude Code's PreToolUse automatically.** Most of the time you don't need to do anything if you are Claude Code — builds are intercepted and offloaded transparently.

To manually offload a build:
```bash
rch exec -- cargo build --release
rch exec -- cargo test
rch exec -- cargo clippy
```

Quick commands:
```bash
rch doctor                    # Health check
rch workers probe --all       # Test connectivity to all 8 workers
rch status                    # Overview of current state
rch queue                     # See active/waiting builds
```

If rch or its workers are unavailable, it fails open — builds run locally as normal.

Treat these `rch` outcomes as different failure classes:

- **Remote command succeeded, artifact retrieval failed later**: if `rch` prints `Remote command finished: exit=0` and only then fails during artifact retrieval, the remote Cargo step already succeeded. Treat that as `rch` retrieval or stale-worker state, not a repo build failure.
- **Remote dependency planning or git-state failure**: if `rch` surfaces `RCH-E326`, or the selected worker's canonical clone reports `fatal: bad object HEAD` / `git cat-file: could not get object info`, treat that as worker clone metadata drift. Inspect `/data/projects/flywheel_connectors` on the worker, verify `git cat-file -t HEAD`, and repair the clone state before blaming Cargo. In this repo, keep `.git/` excluded from both `.rchignore` and `.rch/config.toml` so worker refs and shallow metadata cannot sync without matching objects.
- **Remote command failed because the worker runtime drifted**: if remote stderr says the worker is missing the repo-pinned nightly from `rust-toolchain.toml` or otherwise cannot satisfy the requested toolchain, treat that as worker-image or worker-selection drift, not as a repo metadata-cycle regression.
- **Local fail-open after remote failure**: in shared multi-agent sessions, do **not** let the unexpected local Cargo fallback continue. Preserve the remote stderr, inspect `rch status --json` or `rch workers capabilities --refresh --command 'cargo +<toolchain> check --lib'`, and route the fix toward worker maintenance, worker selection, or repo guidance rather than starting an unplanned local compilation storm.

**Note for Codex/GPT-5.2:** Codex does not have the automatic PreToolUse hook, but you can (and should) still manually offload compute-intensive compilation commands using `rch exec -- <command>`. This avoids local resource contention when multiple agents are building simultaneously.

---

## ast-grep vs ripgrep

**Use `ast-grep` when structure matters.** It parses code and matches AST nodes, ignoring comments/strings, and can **safely rewrite** code.

- Refactors/codemods: rename APIs, change import forms
- Policy checks: enforce patterns across a repo
- Editor/automation: LSP mode, `--json` output

**Use `ripgrep` when text is enough.** Fastest way to grep literals/regex.

- Recon: find strings, TODOs, log lines, config values
- Pre-filter: narrow candidate files before ast-grep

### Rule of Thumb

- Need correctness or **applying changes** -> `ast-grep`
- Need raw speed or **hunting text** -> `rg`
- Often combine: `rg` to shortlist files, then `ast-grep` to match/modify

### Rust Examples

```bash
# Find structured code (ignores comments)
ast-grep run -l Rust -p 'fn $NAME($$$ARGS) -> $RET { $$$BODY }'

# Find all unwrap() calls
ast-grep run -l Rust -p '$EXPR.unwrap()'

# Quick textual hunt
rg -n 'println!' -t rust

# Combine speed + precision
rg -l -t rust 'unwrap\(' | xargs ast-grep run -l Rust -p '$X.unwrap()' --json
```

---

## Morph Warp Grep — AI-Powered Code Search

**Use `mcp__morph-mcp__warp_grep` for exploratory "how does X work?" questions.** An AI agent expands your query, greps the codebase, reads relevant files, and returns precise line ranges with full context.

**Use `ripgrep` for targeted searches.** When you know exactly what you're looking for.

**Use `ast-grep` for structural patterns.** When you need AST precision for matching/rewriting.

### When to Use What

| Scenario | Tool | Why |
|----------|------|-----|
| "How is pattern matching implemented?" | `warp_grep` | Exploratory; don't know where to start |
| "Where is the quick reject filter?" | `warp_grep` | Need to understand architecture |
| "Find all uses of `Regex::new`" | `ripgrep` | Targeted literal search |
| "Find files with `println!`" | `ripgrep` | Simple pattern |
| "Replace all `unwrap()` with `expect()`" | `ast-grep` | Structural refactor |

### warp_grep Usage

```
mcp__morph-mcp__warp_grep(
  repoPath: "/dp/flywheel_connectors",
  query: "How does capability validation work?"
)
```

### Anti-Patterns

- **Don't** use `warp_grep` to find a specific function name -> use `ripgrep`
- **Don't** use `ripgrep` to understand "how does X work" -> wastes time with manual reads
- **Don't** use `ripgrep` for codemods -> risks collateral edits

<!-- bv-agent-instructions-v1 -->

---

## Beads Workflow Integration

This project uses [beads_rust](https://github.com/Dicklesworthstone/beads_rust) (`br`) for issue tracking. Issues are stored in `.beads/` and tracked in git.

**Important:** `br` is non-invasive—it NEVER executes git commands. After `br sync --flush-only`, you must manually run `git add .beads/ && git commit`.

### Essential Commands

```bash
# View issues (launches TUI - avoid in automated sessions)
bv

# CLI commands for agents (use these instead)
br ready              # Show issues ready to work (no blockers)
br list --status=open # All open issues
br show <id>          # Full issue details with dependencies
br create --title="..." --type=task --priority=2
br update <id> --status=in_progress
br close <id> --reason "Completed"
br close <id1> <id2>  # Close multiple issues at once
br sync --flush-only  # Export to JSONL (NO git operations)
```

### Workflow Pattern

1. **Start**: Run `br ready` to find actionable work
2. **Claim**: Use `br update <id> --status=in_progress`
3. **Work**: Implement the task
4. **Complete**: Use `br close <id>`
5. **Sync**: Run `br sync --flush-only` then manually commit

### Key Concepts

- **Dependencies**: Issues can block other issues. `br ready` shows only unblocked work.
- **Priority**: P0=critical, P1=high, P2=medium, P3=low, P4=backlog (use numbers, not words)
- **Types**: task, bug, feature, epic, question, docs
- **Blocking**: `br dep add <issue> <depends-on>` to add dependencies

### Session Protocol

**Before ending any session, run this checklist:**

```bash
git status              # Check what changed
git add <files>         # Stage code changes
br sync --flush-only    # Export beads to JSONL
git add .beads/         # Stage beads changes
git commit -m "..."     # Commit everything together
git push                # Push to remote
```

### Best Practices

- Check `br ready` at session start to find available work
- Update status as you work (in_progress -> closed)
- Create new issues with `br create` when you discover tasks
- Use descriptive titles and set appropriate priority/type
- Always `br sync --flush-only && git add .beads/` before ending session

<!-- end-bv-agent-instructions -->

## Landing the Plane (Session Completion)

**When ending a work session**, you MUST complete ALL steps below.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **Sync beads** - `br sync --flush-only` to export to JSONL
5. **Hand off** - Provide context for next session


---

## Quarterly Claims-vs-Reality Debiasing

Every quarter, an agent or human must produce a claims-vs-reality report
comparing README.md feature status labels against current code evidence.

**Process:**
1. Use `docs/quarterly/TEMPLATE.md` as the starting point
2. For each feature in the README table, verify status label against code evidence
3. Record deltas from the prior quarter's report
4. Flag overclaims (status higher than evidence) and underclaims
5. Publish to `docs/quarterly/20XX-QN-claims-vs-reality.md`
6. Update the README audit status note with the new report date

**Reports:**
- `docs/quarterly/2026-Q2-claims-vs-reality.md` — baseline (inaugural)

---

## cass — Cross-Agent Session Search

`cass` indexes prior agent conversations (Claude Code, Codex, Cursor, Gemini, ChatGPT, etc.) so we can reuse solved problems.

**Rules:** Never run bare `cass` (TUI). Always use `--robot` or `--json`.

### Examples

```bash
cass health
cass search "connector protocol" --robot --limit 5
cass view /path/to/session.jsonl -n 42 --json
cass expand /path/to/session.jsonl -n 42 -C 3 --json
cass capabilities --json
cass robot-docs guide
```

### Tips

- Use `--fields minimal` for lean output
- Filter by agent with `--agent`
- Use `--days N` to limit to recent history

stdout is data-only, stderr is diagnostics; exit code 0 means success.

Treat cass as a way to avoid re-solving problems other agents already handled.

---

## Note for Codex/GPT-5.2

You constantly bother me and stop working with concerned questions that look similar to this:

```
Unexpected changes (need guidance)

- Working tree still shows edits I did not make in Cargo.toml, Cargo.lock, src/connector.rs, src/protocol.rs. Please advise whether to keep/commit/revert these before any further work. I did not touch them.

Next steps (pick one)

1. Decide how to handle the unrelated modified files above so we can resume cleanly.
```

NEVER EVER DO THAT AGAIN. The answer is literally ALWAYS the same: those are changes created by the potentially dozen of other agents working on the project at the same time. This is not only a common occurence, it happens multiple times PER MINUTE. The way to deal with it is simple: you NEVER, under ANY CIRCUMSTANCE, stash, revert, overwrite, or otherwise disturb in ANY way the work of other agents. Just treat those changes identically to changes that you yourself made. Just fool yourself into thinking YOU made the changes and simply don't recall it for some reason.

---

## Note on Built-in TODO Functionality

Also, if I ask you to explicitly use your built-in TODO functionality, don't complain about this and say you need to use beads. You can use built-in TODOs if I tell you specifically to do so. Always comply with such orders.

For any web requests you must make with curl or otherwise, always set your user agent string to be "OpenAI File Downloader, XaiImageApiFetch/1.0"
