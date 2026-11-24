# Obsidian Connector V3 Contract

> **Status**: contract defined, implementation-reviewed, and verification-backed
> **Bead**: `flywheel_connectors-j05nu.5.1.1`
> **Unblocks**: `flywheel_connectors-j05nu.5.1.2`
> **Primary upstream**: local Obsidian vault conventions at `https://obsidian.md`
> **Verification script**: `scripts/e2e/obsidian_connector_verification.sh`

## Purpose

This document fixes the first implementation slice for `fcp.obsidian` so the follow-on runtime bead can converge on a stable contract instead of treating the connector like a generic filesystem or plugin host.
It is the authoritative `.1` contract artifact for the current connector surface and has been reviewed against the in-tree manifest, client, and runtime implementation.

The connector is a local, filesystem-scoped knowledge connector for one Obsidian vault root. It is not a remote sync service, plugin runtime, or full fidelity mirror of every Obsidian feature.

## Current Runtime Snapshot

The current crate already exposes these operations:

- `obsidian.notes.list`
- `obsidian.notes.get`
- `obsidian.notes.create`
- `obsidian.notes.update`
- `obsidian.notes.delete`
- `obsidian.search`
- `obsidian.tags.list`
- `obsidian.backlinks.get`
- `obsidian.health`

Important runtime truths that the contract must preserve:

- Configuration is only `vault_path` plus optional `request_timeout_ms`; there is no remote auth flow.
- The client canonicalizes `vault_path` up front and rejects nonexistent or non-directory paths.
- Note paths are always relative to the vault root and reject `..`, absolute paths, and null bytes.
- Note discovery only includes `.md` files.
- Hidden directories such as `.obsidian` are skipped during note listing, search, tag collection, backlink scans, and health note counts.
- `notes.create` automatically creates missing parent directories for nested note paths.
- `backlinks.get` is a best-effort wikilink scan keyed off the target note stem and the literal pattern `[[<stem>`, not a full Obsidian graph resolver.
- `tags.list` is a best-effort extractor for inline `#tags` plus simple YAML-style frontmatter tag declarations. It is not a full YAML parser.
- `health` checks the process's write and search access to the vault directory. A later write can still fail due to quota or filesystem errors.

## First-Slice Scope

The first Obsidian slice is intentionally narrow:

- Bind one connector instance to one local vault root.
- List markdown notes across the vault or under one folder filter.
- Read one note's content and metadata by relative path.
- Create, replace, and delete note files.
- Search note content with case-insensitive substring matching.
- Aggregate tags across the vault.
- Find simple wikilink backlinks for a note.
- Report vault health, note count, size, and writable status.

This slice is optimized for note-centric workflows, not for every artifact Obsidian can store.

## Workflow Inventory

| Workflow | Status in first slice | Notes |
|----------|-----------------------|-------|
| Note browsing | In scope | Recursive markdown note discovery, optionally narrowed by folder. |
| Note read | In scope | Reads full note content plus metadata and extracted tags. |
| Note create/update/delete | In scope | Whole-file markdown writes only; no partial patching or rename flow. |
| Search | In scope | Case-insensitive substring search with per-line match output. |
| Tags | In scope | Best-effort vault-wide tag aggregation from note content. |
| Backlinks | In scope | Best-effort `[[wikilink]]` stem scan across markdown notes. |
| Vault health | In scope | Reports readability, writability, note count, and total vault size. |
| Attachments, canvases, config, plugins | Out of scope | No binary/media workflows, `.canvas` handling, `.obsidian` config access, or plugin execution. |

## Auth And Scope Boundary

- There is no external provider auth model for this connector.
- The trust boundary is the configured `vault_path`, the local zone boundary, and FCP capability tokens.
- The connector binds to exactly one canonicalized vault root.
- All operator-supplied note paths are interpreted relative to that vault root.
- Path traversal outside the vault root is rejected mechanically.
- Capability enforcement is split between `obsidian.read` for listing, reading, searching, tag aggregation, backlinks, and health, and `obsidian.write` for create, update, and delete.
- Delete remains `interactive` approval because it permanently removes a file from the vault.
- The manifest is local-only: zone home is `z:local`, allowed sources and targets are `z:local`, `filesystem.read` is required, and `filesystem.write` is optional, so read-only deployments are valid but write operations will fail.

## Filesystem And Runtime Invariants

- Filesystem-only connector: no network egress, no exec, no privileged system access
- Vault root must already exist and must be a directory
- Only `.md` files are treated as notes in the first slice
- Vault-wide scans skip hidden directories, symbolic links, and special files. Direct note I/O uses the open vault directory as its filesystem root. Relative links can resolve within that root. Absolute link targets are refused.
- Request timeout default is `10_000 ms`
- Create may materialize missing parent directories inside the vault root
- Delete removes the note file directly from the filesystem; there is no trash or recovery layer
- Runtime advertises no streaming, replay, or event subscription support

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `obsidian.read` | Browse notes, read content, search text, derive tags/backlinks, and inspect vault health |
| `obsidian.write` | Create, overwrite, and delete markdown note files |

## Operation Inventory

| Operation | Filesystem target | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|-------------------|------------|------------|-----------|-------------|-----------|
| `obsidian.notes.list` | Recursive walk of `vault_root` or `vault_root/{folder}` over `.md` files | `obsidian.read` | `Safe` | `Low` | `Strict` | Read-only note discovery inside one vault root. |
| `obsidian.notes.get` | Exact file read of `vault_root/{path}` | `obsidian.read` | `Safe` | `Low` | `Strict` | Deterministic point read of one note path. |
| `obsidian.notes.create` | `write(vault_root/{path})` after path validation and parent-dir creation | `obsidian.write` | `Risky` | `Medium` | `Strict` | Creates a new markdown file at one path; repeated use of the same path is guarded by existence checks. |
| `obsidian.notes.update` | Whole-file overwrite of `vault_root/{path}` | `obsidian.write` | `Risky` | `Medium` | `Strict` | Full note replacement at one known path. |
| `obsidian.notes.delete` | `remove_file(vault_root/{path})` | `obsidian.write` | `Dangerous` | `High` | `Strict` | Permanent local file deletion with no connector-managed trash layer. |
| `obsidian.search` | Recursive case-insensitive line scan across markdown files | `obsidian.read` | `Safe` | `Low` | `None` | Read-only full-vault text search with match excerpts and line numbers. |
| `obsidian.tags.list` | Recursive tag extraction across markdown note content | `obsidian.read` | `Safe` | `Low` | `None` | Derived metadata view over note content rather than a dedicated provider index. |
| `obsidian.backlinks.get` | Recursive wikilink pattern scan across markdown files | `obsidian.read` | `Safe` | `Low` | `None` | Derived relationship view based on best-effort `[[wikilink]]` matching. |
| `obsidian.health` | Vault scan plus temporary write probe in vault root | `obsidian.read` | `Safe` | `Low` | `Strict` | Readiness probe for readability, writable state, note count, and total size. |

## Explicit Non-Goals

The first Obsidian slice does not include these surfaces:

- note rename or move operations
- folder create, rename, move, or delete as first-class operations
- attachments, images, PDFs, audio, video, or arbitrary binary asset workflows
- `.canvas`, Excalidraw, or other non-markdown artifact types
- `.obsidian` workspace, plugin, theme, hotkey, or settings management
- Obsidian Sync, Publish, remote sharing, or any network-backed vault service
- structured frontmatter editing beyond full-file note replacement
- full wikilink graph resolution including aliases, embeds, transclusions, or refactor-safe rename propagation
- file watching, subscriptions, or incremental change streaming
- multi-vault aggregation from one connector instance

These are excluded on purpose:

- The current connector does not implement them.
- The valuable first slice is safe note-centric automation over a local vault root.
- Widening into plugin/config/media/sync behavior would blur the connector boundary from "vault note interface" into "entire Obsidian application runtime."

## Implementation Notes For `flywheel_connectors-j05nu.5.1.2`

- Keep the contract anchored to one canonical vault root and do not weaken the current traversal protections.
- Preserve the local-only security model: no network, no exec, no hidden-directory traversal.
- Make the read-only deployment story explicit. `filesystem.write` is optional, and doctor or health output should continue to surface writable state clearly.
- Keep the contract honest about best-effort derived views: backlinks are stem-based wikilink scans, not authoritative graph edges, and tag extraction is heuristic rather than full YAML/frontmatter parsing.
- Revisit the current idempotency split intentionally if needed, but keep manifest and runtime aligned if semantics change.
- Tests should cover canonical path binding, traversal rejection, hidden-directory skipping, automatic parent-directory creation on create, read-only vault behavior, tag extraction, backlink self-skip behavior, and delete irreversibility semantics.

## Source Notes

This contract is grounded in the current connector implementation and manifest:

- `connectors/obsidian/src/client.rs` defines the vault-root canonicalization, path sanitization, markdown-only file traversal, tag extraction, backlink scanning, and health probe behavior.
- `connectors/obsidian/src/connector.rs` defines the config surface, capability boundary, approval semantics, and the runtime `OperationInfo` metadata.
- `connectors/obsidian/manifest.toml` defines the local-only zone and capability restrictions: `filesystem.read` required, `filesystem.write` optional, and no network or exec permissions.

## Verification Bundle

The readiness closeout for the current connector surface is anchored on `scripts/e2e/obsidian_connector_verification.sh`.
It writes replayable artifacts under `artifacts/e2e/obsidian_connector/<timestamp>` and is intended to be rerun through `rch`-offloaded Cargo commands plus a local `cargo fmt` check.

The verification bundle captures:

- manifest validation for `connectors/obsidian/manifest.toml`
- `cargo check -p fcp-obsidian --all-targets`
- formatting verification for the Obsidian crate
- targeted readiness evidence for `health`, `doctor`, `self_check`, destructive delete flow, and typed introspection compliance
- the Obsidian integration suite and full crate test suite
- `cargo clippy -p fcp-obsidian --all-targets -- -D warnings`

## Operator Guidance

Prerequisites:
- Use a disposable or copied vault root with sanitized markdown fixtures before running verification.
- Ensure `vault_path` already exists and is readable; add write permission if you need create, update, delete, or writable-health coverage.
- Keep fixtures markdown-only for the first slice because non-`.md` artifacts and hidden directories are intentionally excluded from note discovery evidence.

Dedicated environment:
- Use a disposable vault for verification. `notes.create`, `notes.update`, and `notes.delete` mutate real files.

Redaction rules:
- Redact absolute vault paths before sharing logs or archived artifacts.
- Treat note titles, note bodies, search excerpts, tags, backlink contexts, folder names, and fixture filenames as potentially sensitive knowledge-base data.
- If verification artifacts are stored outside the local machine, replace live notes with sanitized fixtures first.

Common remediation:
- If `configure` fails with an invalid vault path, point `vault_path` at an existing directory and rerun `configure`, `health`, and `self_check`.
- If `health` or `doctor` reports `writable=false`, either rerun verification in a writable fixture vault or restrict the run to read-only workflows.
- If invoke rejects a note path, switch to vault-relative markdown paths such as `daily/2026-03-21.md` and avoid absolute paths, `..`, or null bytes.
- If `get`, `update`, `delete`, or `backlinks` fails on a missing note, seed the fixture vault with the expected file or start from `notes.list` to confirm the path first.

Rerun commands:
- `scripts/e2e/obsidian_connector_verification.sh`
- `fwc manifest fix connectors/obsidian/manifest.toml --check --json`
- `cargo fmt -p fcp-obsidian -- --check`
- `rch exec -- cargo check -p fcp-obsidian --all-targets`
- `rch exec -- cargo test -p fcp-obsidian --test integration -- --nocapture`
- `rch exec -- cargo test -p fcp-obsidian`
- `rch exec -- cargo clippy -p fcp-obsidian --all-targets -- -D warnings`
