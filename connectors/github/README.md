# GitHub Connector V3 Contract

> **Status**: PROVEN
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: `scripts/e2e/github_connector_verification.sh`
> **GitHub REST upstream**: https://docs.github.com/en/rest
> **Issues upstream**: https://docs.github.com/en/rest/issues/issues
> **Pull requests upstream**: https://docs.github.com/en/rest/pulls/pulls
> **Repositories upstream**: https://docs.github.com/en/rest/repos/repos
> **Contents upstream**: https://docs.github.com/en/rest/repos/contents
> **Search upstream**: https://docs.github.com/en/rest/search/search
> **Actions workflows upstream**: https://docs.github.com/en/rest/actions/workflows
> **Webhooks upstream**: https://docs.github.com/en/webhooks/using-webhooks

## Purpose

This document fixes the operator-facing contract for `fcp.github`. The connector exposes the GitHub REST API surface implemented in this crate: issues, pull requests, repositories, repository contents, search, Actions workflow dispatch, and pre-verified webhook payload processing.

The connector is intentionally a bounded GitHub bridge. It is not a full GitHub App installation manager, repository mirror, release publisher, package registry client, Codespaces client, secret scanner, dependency graph client, or webhook HTTP listener.

## Current Runtime Snapshot

The current crate exposes these operations:

- `github.create_issue`
- `github.get_issue`
- `github.search_issues`
- `github.create_pull_request`
- `github.get_pull_request`
- `github.merge_pull_request`
- `github.get_repo`
- `github.search_repos`
- `github.list_workflows`
- `github.trigger_workflow`
- `github.get_file_content`
- `github.search_code`
- `github.process_webhook`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-github`.
- Runtime `BaseConnector` ID is `github`.
- Manifest connector ID is `fcp.github`.
- Configuration requires a host credential reference through `credential_id`; raw `token` fields are rejected as leaked secret material.
- `credential_id` mode sends `X-FCP-Credential-ID` and expects host egress policy to inject real secret material.
- Default base URL is `https://api.github.com`.
- `credential_id` mode accepts HTTPS custom base URLs for egress-proxy routing, plus loopback hosts for tests.
- All base URLs reject userinfo, query strings, and fragments.
- Runtime request timeout is 30 seconds.
- HTTP requests include `Accept: application/vnd.github+json` and `X-GitHub-Api-Version: 2022-11-28`.
- The client uses the shared retry loop with `max_retries = 3`, `initial_delay_ms = 1000`, and `max_delay_ms = 60000`.
- The client retries connect/timeout errors and retryable API errors; 429 and secondary-rate-limit 403 responses map to `RateLimited`.
- Owner and repository names are validated locally before URL construction.
- File paths are percent-encoded by path segment before content lookup.
- Runtime handshake installs a `CapabilityVerifier`.
- Runtime handshake returns a SHA-256 hash of the bundled `manifest.toml`.
- `invoke` requires `operation`, `input`, and `capability_token`; it validates input, computes resource URIs, and verifies a bound capability token before provider execution.
- `simulate` validates operation inventory, input shape, configured state, handshaken state, resource URI construction, and bound capability token before returning an allowed result.
- `github.process_webhook` never calls GitHub. It accepts only host-forwarded structured payloads with `signature_validated = true`, requires repository context, and deduplicates the latest 1024 delivery IDs in process memory.
- `health()` is local state only; `self_check()` degrades for `credential_id` because real connectivity depends on the egress proxy.
- `handle_shutdown()` shuts down the client runtime, records local shutdown state, and clears base configured/handshaken flags.

## Drift Visible In This Checkout

This README documents the runtime truth and keeps current drift visible:

- Manifest optional capabilities include `github.search`, but runtime capability verification uses `github.read` for all search operations.
- `rate_limits.operation_pools` maps search operations to `github.search`; manifest operation metadata and runtime introspection map them to `github.read`.
- `rate_limits.operation_pools` maps `github.process_webhook` to `github.read`; manifest operation metadata and runtime verification use `github.process_webhook`.
- Manifest `github.process_webhook` input schema requires only `payload`, while runtime and introspection also require `signature_validated`.
- Manifest approval modes are `policy` or `interactive` for mutating operations, but runtime introspection currently sets `requires_approval = None` for all GitHub operations.
- Source contains `invoke_begin_oauth` and `invoke_complete_oauth` helpers, but neither operation is advertised by introspection or reachable through `handle_invoke`.
- Manifest description mentions releases, but there are no release operations in this runtime slice.
- Manifest event caps say streaming is enabled, but the runtime exposes no event stream catalog; the only event-shaped output is returned by `github.process_webhook`.
- `connectors/github/tests/local_non_mock.rs` exercises the production connector invoke path against a deterministic loopback GitHub API fixture for read, write, and workflow-dispatch operations.

A follow-up parity bead should reconcile search/rate-limit capability mapping, align webhook schemas, surface approval modes in introspection, either publish or remove the OAuth helper paths, and decide whether the loopback acceptance fixture should grow into GitHub fixture replay.

## First-Slice Scope

The current GitHub README slice documents the existing runtime surface:

- host credential-reference configuration with fail-closed raw-secret rejection
- REST host policy, GitHub API version header, timeout, retry, and rate-limit behavior
- issue, pull request, repository, repository content, search, Actions workflow dispatch, and forwarded webhook operations
- bound capability-token verification during both `invoke` and `simulate`
- provider error mapping, redaction posture, doctor behavior, health behavior, and shutdown behavior
- deterministic WireMock tests and direct proof commands

## Auth And Scope Boundary

- Authentication mechanism: host credential reference through `credential_id`.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zone: `z:public`.
- Runtime capability surface:
  - `github.read` gates reads, repository metadata, repository contents, and search.
  - `github.write` gates issue creation and pull request creation.
  - `github.admin` gates pull request merge and workflow dispatch.
  - `github.process_webhook` gates forwarded webhook payload processing.
- Manifest-only capability note: `github.search` exists as an optional/rate-limit capability, but runtime verification currently uses `github.read` for search operations.
- The connector does not persist repository metadata, issue payloads, pull request payloads, webhook payloads, tokens, credential IDs, provider responses, or provider error bodies beyond process memory.
- GitHub payloads can include private source paths, issue text, pull request content, workflow names, user identities, webhook data, and repository topology. Treat live output as work-zone operational data.

## Network And Runtime Invariants

- Production host: `api.github.com`.
- Production port: `443`.
- TLS and SNI are required by the manifest for provider operations.
- Manifest network policy denies localhost, private ranges, tailnet ranges, and IP literals for live provider operations.
- `github.process_webhook` declares `none.invalid` and `port 0` in the manifest because it performs no provider egress.
- Credential-reference runtime host policy allows custom HTTPS base URLs for egress-proxy routing.
- Localhost overrides are test/debug-only.
- Runtime request timeout: `30 seconds`.
- Manifest connect timeout is `10000 ms` for provider operations and `1000 ms` for `github.process_webhook`.
- Manifest total timeout is `30000 ms` for most provider operations, `60000 ms` for search operations, and `15000 ms` for `github.process_webhook`.
- Manifest maximum response bytes range from `1048576` to `10485760`.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `120000 ms` wall-clock timeout, no exec, and no ptrace.
- The connector does not open inbound sockets.
- Webhook handling is a local typed transform over payloads already verified and forwarded by `fcp-host`.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `github.read` | Read issues, pull requests, repository metadata, workflow lists, contents, and search results. |
| `github.write` | Create issues and pull requests. |
| `github.admin` | Merge pull requests and trigger Actions workflow dispatch events. |
| `github.process_webhook` | Process pre-verified webhook payloads forwarded by `fcp-host`. |
| `github.search` | Manifest/rate-limit capability in this checkout; runtime verification uses `github.read`. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `github.create_issue` | `POST /repos/{owner}/{repo}/issues` | `github.write` | `Risky` | `Medium` | `None` | Creates a new issue in a repository. |
| `github.get_issue` | `GET /repos/{owner}/{repo}/issues/{issue_number}` | `github.read` | `Safe` | `Low` | `Strict` | Reads one issue by repository-local issue number. |
| `github.search_issues` | `GET /search/issues?q={query}` | `github.read` | `Safe` | `Low` | `Strict` | Searches issues and pull requests using GitHub search syntax. |
| `github.create_pull_request` | `POST /repos/{owner}/{repo}/pulls` | `github.write` | `Risky` | `Medium` | `None` | Opens a new pull request from `head` to `base`. |
| `github.get_pull_request` | `GET /repos/{owner}/{repo}/pulls/{pull_number}` | `github.read` | `Safe` | `Low` | `Strict` | Reads one pull request by repository-local pull number. |
| `github.merge_pull_request` | `PUT /repos/{owner}/{repo}/pulls/{pull_number}/merge` | `github.admin` | `Risky` | `High` | `None` | Merges a pull request using optional merge settings. |
| `github.get_repo` | `GET /repos/{owner}/{repo}` | `github.read` | `Safe` | `Low` | `Strict` | Reads repository metadata. |
| `github.search_repos` | `GET /search/repositories?q={query}` | `github.read` | `Safe` | `Low` | `Strict` | Searches repositories using GitHub search syntax. |
| `github.list_workflows` | `GET /repos/{owner}/{repo}/actions/workflows` | `github.read` | `Safe` | `Low` | `Strict` | Lists GitHub Actions workflow definitions. |
| `github.trigger_workflow` | `POST /repos/{owner}/{repo}/actions/workflows/{workflow_id}/dispatches` | `github.admin` | `Risky` | `High` | `None` | Triggers a workflow dispatch for a requested ref. |
| `github.get_file_content` | `GET /repos/{owner}/{repo}/contents/{path}` | `github.read` | `Safe` | `Low` | `Strict` | Reads file or directory content metadata from a repository path. |
| `github.search_code` | `GET /search/code?q={query}` | `github.read` | `Safe` | `Low` | `Strict` | Searches code using GitHub search syntax. |
| `github.process_webhook` | local only, no provider egress | `github.process_webhook` | `Safe` | `Low` | `Strict` | Converts a host-verified webhook payload into a typed event object. |

## Pagination, Repository Refs, And Workflow Inputs

`github.search_issues`, `github.search_repos`, `github.search_code`, and
`github.list_workflows` return one provider page per invocation. All four accept
`page` (a positive integer, default `1`) and `per_page` (an integer from `1` to
`100`, default `100`). For example, the input for a second issue-search page is:

```json
{"query": "repo:octocat/hello-world is:issue", "page": 2, "per_page": 100}
```

The response preserves the provider's `total_count` and item collection and adds
`pagination` with `page`, `per_page`, `returned`, `next_page`,
`accessible_total_count`, `result_limit`, and `result_limit_exceeded`. Continue
with `next_page`, keeping the query and page size unchanged; `null` means there
is no next page within the accessible result window. Pagination reflects the
provider's reported count, so concurrent repository changes can alter subsequent
pages.

GitHub search exposes at most the first `1000` matches for a query. Search
responses report `result_limit: 1000`, cap `accessible_total_count` at `1000`, and
set `result_limit_exceeded` when more matches exist. Narrow the query to retrieve
additional matches. The provider's `incomplete_results` flag is also returned;
`false` is required before treating a search as complete. Requests whose page
starts beyond the search window fail locally. Workflow inventories have no
search-result cap and report `result_limit: null`.

`github.get_file_content` accepts an optional nonempty `ref` containing a branch,
tag, or commit SHA. Omit it to use the repository's default branch. An empty
`path` lists the repository root:

```json
{"owner": "octocat", "repo": "hello-world", "path": "", "ref": "main"}
```

The response's `content` is an object for a single file and an array for a
directory, including an empty array for an empty directory. File contents retain
GitHub's encoding metadata; symlink targets and submodule URLs are preserved when
provided, and `html_url` may be `null` for external submodules. GitHub limits a
directory response to `1000` entries; the Contents API does not paginate those
entries.

`github.trigger_workflow` accepts a workflow ID or YAML filename, the required
`ref`, and an optional `inputs` object with at most `25` properties. Input values
are forwarded without coercion and must satisfy the workflow's declared inputs:

```json
{"owner": "octocat", "repo": "hello-world", "workflow_id": "deploy.yml", "ref": "main", "inputs": {"environment": "staging", "dry_run": true}}
```

Successful dispatch responses, including GitHub's empty `204 No Content`, return
`{"triggered": true}`. Dispatch is non-idempotent: the connector does not replay
an ambiguous provider failure or a transport failure after submission. Inspect
the repository's workflow runs before deciding whether to dispatch again.

## Resource URIs

Runtime capability-token verification binds operations to these resource URI shapes:

| Operation | Resource URI |
|-----------|--------------|
| `github.create_issue` | `github://{owner}/{repo}/issues` |
| `github.get_issue` | `github://{owner}/{repo}/issues/{issue_number}` |
| `github.create_pull_request` | `github://{owner}/{repo}/pulls` |
| `github.get_pull_request` | `github://{owner}/{repo}/pulls/{pull_number}` |
| `github.merge_pull_request` | `github://{owner}/{repo}/pulls/{pull_number}` |
| `github.get_repo` | `github://{owner}/{repo}` |
| `github.list_workflows` | `github://{owner}/{repo}/actions/workflows` |
| `github.trigger_workflow` | `github://{owner}/{repo}/actions/workflows/{workflow_id}` |
| `github.get_file_content` | `github://{owner}/{repo}/contents/{path}` |
| `github.process_webhook` | `github://{repository_full_name}/webhooks/deliveries/{delivery_id}` |
| `github.search_issues` | no resource URI beyond capability and operation binding |
| `github.search_repos` | no resource URI beyond capability and operation binding |
| `github.search_code` | no resource URI beyond capability and operation binding |

## Explicit Non-Goals

The current implementation does not include:

- GitHub App installation setup, private key handling, token exchange, or app webhook registration
- releases, packages, deployments, environments, branch protections, repository administration, secrets, variables, security advisories, dependency graph, code scanning, or discussions
- issue edit/close/comment, pull request review/comment/update, workflow run listing, workflow cancellation, logs, artifacts, or status checks
- repository clone, git object writes, commit creation, content writes, or tree/blob mutation
- live webhook HTTP listening or signature verification inside the connector
- durable webhook replay, persistent deduplication, webhook subscription management, or event fanout

These are excluded on purpose:

- Repository administration and Actions mutation need narrower approval and audit contracts.
- Webhook signature verification belongs at the host ingress boundary before connector invocation.
- Search and content reads can expose sensitive source paths and code snippets, so the runtime keeps them behind capability-token verification.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- local configuration, client, shutdown, and request metric state
- auth mode without secret disclosure
- base URL class and credential-injection warning state
- degraded self-check for `credential_id` mode because real connectivity depends on the egress proxy
- operation metadata with capability, risk, safety tier, idempotency, schemas, and hints
- bound capability-token verification during `invoke`
- simulation denial for unknown operation, invalid input, unconfigured connector, missing handshake, resource URI construction failure, and bound capability-token mismatch
- typed provider/FCP error mapping

The deterministic integration evidence is anchored on connector-local tests covering:

- lifecycle, configuration, base URL policy, loopback allowance, introspection, simulation, doctor, self-check, and shutdown behavior
- issue, pull request, repository, workflow, content, search, and webhook paths through deterministic HTTP fixtures or local payload fixtures
- invoke rejection for unknown operation, missing token, wrong token, missing handshake, missing configuration, and invalid input
- provider 401, 404, 409, 422, 429, 500 classes and FCP error mapping
- webhook signature gate, repository context requirement, delivery-ID deduplication, and no-egress manifest constraints

## Source Notes

- `connectors/github/src/connector.rs` defines configuration parsing, base URL policy, lifecycle handlers, introspection, simulation, capability-token verification, resource URI binding, webhook payload handling, and invoke dispatch.
- `connectors/github/src/client.rs` defines GitHub REST paths, auth headers, retry dispatch, timeout, request metrics, path encoding, owner/repo validation, and provider error mapping.
- `connectors/github/src/types.rs` defines issue, pull request, repository, content, workflow, search, and webhook shapes.
- `connectors/github/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/github/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, event caps, and rate-limit pools.
- `connectors/github/tests/integration.rs`, `connectors/github/tests/conformance_contract.rs`, and `connectors/github/tests/local_non_mock.rs` cover deterministic runtime behavior, contract assertions, and local loopback acceptance.

## Verification Bundle

The tracked verifier is `scripts/e2e/github_connector_verification.sh`. The closeout surface is the verifier, crate-local test suite, and fail-closed `fwc proof run` evidence for Cargo-backed `rch` proof commands.

The verification surface captures:

- runtime operation inventory and policy metadata
- deterministic WireMock coverage for GitHub API paths
- auth, endpoint policy, provider error, webhook, lifecycle, simulation, and introspection tests
- formatting as a source-state check, plus check, test, and clippy proof through `fwc proof run` / `rch`
- UBS on changed files before commit

The verifier writes proof-governor artifacts under `${OUT_ROOT}/proof`. Only `accepted_remote_proof` rows in `*.rch_remote_proof.jsonl` are green closeout evidence for Cargo-backed steps. `refused_local_fallback`, `infra_blocked`, `remote_command_failed`, `failed_closed`, `not_proof`, or a missing proof row keep the batch bead open. The wrapper normalizes stale proof-runner output for `[RCH] remote required; refusing local fallback` to `refused_local_fallback` so local-fallback refusal is not mistaken for a GitHub connector code failure.

Run the tracked verifier first:

```bash
scripts/e2e/github_connector_verification.sh
```

## Operator Guidance

**Prerequisites**:

- Use a GitHub test organization or repository for live mutation proof.
- Configure the connector with `credential_id` only; raw token fields are treated as leaked secret material.
- Use loopback WireMock fixtures for routine proof.
- Give live tokens only the scopes needed for the operation family under test.

**Dedicated environment**:

- Keep test issues, pull requests, workflow dispatches, and webhook payloads separate from production repositories.
- Avoid running merge or workflow-dispatch proof against production branches.
- Treat webhook replay fixtures as sensitive because payloads can include repository, sender, and source-path details.

**Redaction rules**:

- Redact bearer tokens, credential IDs where needed, repository names when private, owner names, issue and pull request body text, branch names when sensitive, workflow names, file paths, source snippets, webhook delivery IDs, webhook payloads, provider error bodies, and endpoint URLs that reveal private topology.
- Verification output should use operation IDs, endpoint shapes, auth mode, host class, result counts, status/error classes, retry decisions, and payload-shape summaries.

**Common remediation**:

- If configuration fails, provide a valid `credential_id` and remove any raw token material from config.
- If credential-reference self-check degrades, materialize host credentials through the egress proxy before invoking provider operations.
- If provider returns 403 with no rate-limit budget remaining, treat it as rate-limited and honor retry guidance.
- If `github.process_webhook` fails, verify `signature_validated = true`, repository context, and a fresh delivery ID before inspecting payload shape.
- If search operations are denied unexpectedly, inspect both the runtime `github.read` capability and the manifest/rate-limit `github.search` drift.

**Rerun commands**:

- `scripts/e2e/github_connector_verification.sh`
- `PROOF_GOVERNOR=1 scripts/e2e/github_connector_verification.sh`
- `FWC_BIN=/path/to/current/target/debug/fwc PROOF_GOVERNOR=1 scripts/e2e/github_connector_verification.sh` when the installed `fwc` binary does not yet include `proof run`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-github-readme cargo check -p fcp-github --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-github-readme cargo test -p fcp-github --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-github-readme cargo clippy -p fcp-github --all-targets --no-deps -- -D warnings`
- `ubs connectors/github/README.md`
