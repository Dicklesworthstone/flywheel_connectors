# Google Workspace Events Connector V3 Contract

> **Status**: PROVEN runtime contract documented; capability and approval drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: `scripts/e2e/google_workspace_events_connector_verification.sh`
> **Workspace Events upstream**: https://developers.google.com/workspace/events
> **Subscriptions create upstream**: https://developers.google.com/workspace/events/reference/rest/v1/subscriptions/create
> **Pub/Sub pull upstream**: https://cloud.google.com/pubsub/docs/reference/rest/v1/projects.subscriptions/pull
> **Pub/Sub subscriptions upstream**: https://cloud.google.com/pubsub/docs/reference/rest/v1/projects.subscriptions

## Purpose

This document fixes the operator-facing contract for `fcp.workspace-events`. The connector exposes the Google Workspace Events API and Google Cloud Pub/Sub delivery surface implemented in this crate: provisioning scope description, subscription lifecycle management, Pub/Sub pull, and Pub/Sub acknowledgement.

The connector is intentionally a Workspace event subscription and delivery bridge. It is not a Google Chat app, Drive client, Meet client, Admin SDK client, Pub/Sub topic manager, IAM provisioner, webhook listener, durable event store, or generic CloudEvents router.

## Current Runtime Snapshot

The current crate exposes these operations:

- `workspace_events.describe_provisioning`
- `workspace_events.list_subscriptions`
- `workspace_events.get_subscription`
- `workspace_events.create_subscription`
- `workspace_events.reactivate_subscription`
- `workspace_events.delete_subscription`
- `workspace_events.pull_events`
- `workspace_events.ack_events`

Important runtime truths the contract preserves:

- Configuration requires exactly one Google auth source accepted by `GoogleAuthSelection`.
- Supported auth material includes direct access-token style auth and host credential references handled by the shared Google discovery auth layer.
- Required scopes are resolved from the embedded `workspace_events` provisioning bundle.
- Callers may provide explicit `required_scopes`, or provide `scope_triggers`, but not both.
- Default Workspace Events base URL is `https://workspaceevents.googleapis.com/v1`.
- Default Pub/Sub base URL is `https://pubsub.googleapis.com/v1`.
- Public base URLs must use HTTPS, target the expected Google host, and contain no userinfo, query string, or fragment.
- `localhost`, `127.0.0.1`, `::1`, and `[::1]` are accepted for deterministic loopback tests.
- `describe_provisioning` is local and can run before provider configuration.
- Subscription control-plane operations call Workspace Events REST endpoints.
- Delivery operations call Pub/Sub REST endpoints and decode Pub/Sub message data as base64, preserving malformed payload metadata with a structured decode error.
- The client timeout is `30 seconds`.
- The client uses the shared retry loop configuration with `max_retries = 2`.
- Handshake installs a `CapabilityVerifier`, but invoke does not currently use it.
- Handshake advertises event caps with `streaming = true`, `replay = false`, `min_buffer_events = 50`, and `requires_ack = true`.
- Event delivery is modeled as explicit Pub/Sub `pull_events` and `ack_events` operations, not as a connector-owned inbound listener.

## Drift Visible In This Checkout

This README documents the runtime truth and keeps current drift visible:

- Manifest connector ID is `fcp.workspace-events`, while runtime `BaseConnector` ID is `google-workspace-events`.
- Runtime handshake returns a SHA-256 hash of the bundled `manifest.toml`.
- Handshake grants every requested capability instead of filtering to the manifest/runtime capability set.
- Runtime `handle_invoke` does not parse or verify capability tokens for any operation.
- Runtime `handle_invoke` does not enforce approval tokens, even though the manifest marks create/reactivate/delete operations as requiring policy or interactive approval.
- Runtime `handle_simulate` returns a permissive dry-run shape for any operation string and does not validate configuration, input schema, capability, approval, or provider readiness.
- Manifest and runtime advertise streaming-style event caps, but the current JSON-RPC loop exposes no `subscribe` method; event delivery is Pub/Sub pull/ack through `invoke`.
- `handle_shutdown` clears the client but does not reset verifier, session ID, configured flag, or handshaken flag.
- There is no dedicated tracked verification shell script for this connector.

A follow-up parity bead should enforce bound capability tokens and approval tokens in invoke, filter handshake grants, align connector IDs, make simulation policy-aware, and decide whether event caps should describe Pub/Sub pull/ack or a future subscribe API.

## First-Slice Scope

The current Google Workspace Events README slice documents the existing runtime surface:

- shared Google auth selection and scope-trigger resolution
- Workspace Events subscription list/get/create/reactivate/delete
- Pub/Sub pull and ack delivery operations
- local provisioning-bundle description
- base URL validation and loopback test allowance
- local health, doctor, self-check, introspection, simulation, invoke, and shutdown behavior
- provider error mapping for auth failures, 404 resources, 429 retry-after, 5xx, malformed JSON, and invalid Pub/Sub payloads
- deterministic WireMock/Pub/Sub tests and direct proof commands

## Auth And Scope Boundary

- Authentication mechanisms: Google bearer token, host credential reference, or other shared Google auth material accepted by `GoogleAuthSelection`.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zone: `z:public`.
- Runtime capability surface:
  - `workspace_events.provisioning.read` gates provisioning-bundle inspection.
  - `workspace_events.subscriptions.read` gates subscription listing and lookup.
  - `workspace_events.subscriptions.write` gates subscription create, reactivate, and delete.
  - `workspace_events.delivery.read` gates Pub/Sub message pulls.
  - `workspace_events.delivery.ack` gates Pub/Sub acknowledgement.
- Current invoke path does not enforce these capabilities. Host policy must not treat connector invoke as capability-verified until the follow-up fix lands.
- The connector does not persist access tokens, credential IDs, subscription payloads, event payloads, Pub/Sub message data, ack IDs, provider payloads, or provider error bodies beyond process memory.
- Workspace event payloads can include private Chat, Drive, Meet, and other Workspace resource metadata. Treat pulled events and decoded message data as private or work-zone data.

## Network And Runtime Invariants

- Production Workspace Events host: `workspaceevents.googleapis.com`.
- Production Pub/Sub host: `pubsub.googleapis.com`.
- Production port: `443`.
- TLS and SNI are required by the manifest for live traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, IP literals, and redirects for live provider operations.
- Runtime loopback base URLs are test-only.
- Runtime request timeout: `30 seconds`.
- Manifest response caps are `524_288`, `2_097_152`, or `4_194_304` bytes depending on operation.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `120_000 ms` wall-clock timeout, no exec, and no ptrace.
- The connector does not open inbound sockets; Pub/Sub delivery is consumed by explicit pull calls.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `workspace_events.provisioning.read` | Inspect embedded Workspace Events provisioning bundles and effective OAuth scopes. |
| `workspace_events.subscriptions.read` | List and inspect Workspace Events subscriptions. |
| `workspace_events.subscriptions.write` | Create, reactivate, or delete Workspace Events subscriptions. |
| `workspace_events.delivery.read` | Pull Pub/Sub-delivered Workspace Events messages. |
| `workspace_events.delivery.ack` | Acknowledge Pub/Sub messages after successful downstream processing. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `workspace_events.describe_provisioning` | local provisioning bundle | `workspace_events.provisioning.read` | `Safe` | `Low` | `Strict` | Computes effective Google OAuth scopes without provider I/O. |
| `workspace_events.list_subscriptions` | `GET /v1/subscriptions` | `workspace_events.subscriptions.read` | `Safe` | `Low` | `Strict` | Lists Workspace Events subscriptions visible to the credential. |
| `workspace_events.get_subscription` | `GET /v1/{subscription_name}` | `workspace_events.subscriptions.read` | `Safe` | `Low` | `Strict` | Reads one Workspace Events subscription resource. |
| `workspace_events.create_subscription` | `POST /v1/subscriptions` | `workspace_events.subscriptions.write` | `Risky` | `Medium` | `None` | Creates upstream event delivery and can start Pub/Sub fanout. |
| `workspace_events.reactivate_subscription` | `POST /v1/{subscription_name}:reactivate` | `workspace_events.subscriptions.write` | `Risky` | `Medium` | `None` | Resumes delivery for a suspended subscription. |
| `workspace_events.delete_subscription` | `DELETE /v1/{subscription_name}` | `workspace_events.subscriptions.write` | `Risky` | `High` | `None` | Stops Workspace Events delivery for a subscription. |
| `workspace_events.pull_events` | `POST /v1/{pubsub_subscription}:pull` | `workspace_events.delivery.read` | `Safe` | `Low` | `Strict` | Pulls the next Pub/Sub delivery batch and decodes message payloads. |
| `workspace_events.ack_events` | `POST /v1/{pubsub_subscription}:acknowledge` | `workspace_events.delivery.ack` | `Safe` | `Low` | `BestEffort` | Acknowledges messages after downstream processing succeeds. |

## Explicit Non-Goals

The current implementation does not include:

- Google Cloud project creation, API enablement, OAuth consent setup, Pub/Sub topic creation, Pub/Sub subscription creation, or IAM binding
- Google Chat app registration, Drive event policy, Meet event policy, or product-specific admin setup
- connector-owned HTTP push receivers, webhook validation, or direct CloudEvents listener sockets
- durable event queues, replay stores, de-duplication ledgers, or exactly-once processing
- Pub/Sub seek, modifyAckDeadline, nack, dead-letter policy management, topic management, or schema management
- automatic subscription renewal, lifecycle alert routing, or suspended-subscription remediation
- connector-local credential vaulting

These are excluded on purpose:

- Workspace Events spans multiple Google Workspace products with product-specific OAuth scopes and tenant policy.
- Pub/Sub delivery is an at-least-once stream; ack timing must remain explicit so agents do not lose messages after downstream failure.
- Provisioning and IAM changes require a separate Google Cloud bootstrap contract.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configured state, client state, request counters, and required scope set
- operation metadata with capability, risk, safety tier, idempotency, schemas, and AI hints
- event caps that declare ack-required Pub/Sub delivery posture
- local self-check for configured state
- provisioning-bundle scope resolution
- current simulation behavior, which is permissive
- current invoke capability and approval enforcement gaps

The deterministic integration evidence is anchored on connector-local tests covering:

- manifest/runtime schema parity for all eight operations
- provisioning-bundle scope resolution
- subscription list/create/reactivate/delete request paths
- Pub/Sub pull and acknowledge request paths
- empty batches, duplicate delivery, decoded JSON payloads, and malformed base64 payload reporting
- 401, 429 with `Retry-After`, missing resources, and FCP error mapping
- ack ID and `max_messages` validation
- event caps and operation inventory checks

## Source Notes

- `connectors/google-workspace-events/src/connector.rs` defines configuration parsing, scope resolution, lifecycle handlers, operation metadata, simulation, and invoke dispatch.
- `connectors/google-workspace-events/src/client.rs` defines Workspace Events and Pub/Sub REST paths, shared Google auth headers, retry dispatch, timeout, request metrics, and provider error handling.
- `connectors/google-workspace-events/src/types.rs` defines Workspace subscription, long-running operation, Pub/Sub message, and pull response shapes.
- `connectors/google-workspace-events/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/google-workspace-events/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, event caps, and rate-limit pools.
- `connectors/google-workspace-events/tests/pubsub_delivery.rs` covers deterministic schema, subscription, Pub/Sub delivery, acknowledgement, and error behavior.

## Verification Bundle

The tracked verification bundle is `scripts/e2e/google_workspace_events_connector_verification.sh`. It runs the graduation gauntlet, manifest check, crate-local compilation, formatting, Pub/Sub delivery suite, `local_non_mock` loopback acceptance suite, JSONL redaction/evidence checks, and clippy through `rch`.

The verification surface captures:

- runtime operation inventory and metadata
- deterministic WireMock coverage for Workspace Events and Pub/Sub REST paths
- scope-resolution, event-cap, schema, delivery, ack, and error behavior
- formatting, check, test, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use a Google Cloud project with Google Workspace Events API and Pub/Sub API enabled.
- Prepare a Pub/Sub topic that Workspace Events can publish to and a Pub/Sub subscription that the connector can pull from.
- Grant the correct product-specific OAuth scopes for the chosen target resource and event types.
- Prefer loopback fixtures for routine proof.

**Dedicated environment**:

- Use test Chat spaces, Drive files, Meet spaces, and Pub/Sub topics for live validation.
- Use `validate_only` before deleting live subscriptions when possible.
- Pull small batches first and ack only after downstream processing is complete.

**Redaction rules**:

- Redact access tokens, credential IDs where needed, `Authorization` headers, subscription names when tenant-revealing, Pub/Sub topic/subscription names, ack IDs, event payloads, provider error bodies, and endpoint URLs when they reveal tenant topology.
- Verification output should use operation IDs, host class, event type, counts, status/error classes, retry decisions, and payload-shape summaries instead of raw Workspace content.

**Common remediation**:

- If configuration fails, provide exactly one Google auth source and choose either `required_scopes` or `scope_triggers`, not both.
- If `create_subscription` fails, verify Pub/Sub topic existence and publisher IAM before retrying.
- If `pull_events` returns no messages, verify that the Workspace Events subscription target, event types, and Pub/Sub delivery path are all active.
- If decoded events contain `decode_error`, preserve the envelope metadata and inspect the Pub/Sub producer payload before acking.
- If 401/403 errors appear, refresh credentials and confirm the product-specific scopes for the event type.
- If invoke succeeds without a capability token, remember that this is current drift; rely on host policy until connector-local enforcement lands.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-google-workspace-events-readme cargo check -p fcp-google-workspace-events --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-google-workspace-events-readme cargo test -p fcp-google-workspace-events --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-google-workspace-events-readme cargo clippy -p fcp-google-workspace-events --all-targets --no-deps -- -D warnings`
- `ubs connectors/google-workspace-events/README.md`
