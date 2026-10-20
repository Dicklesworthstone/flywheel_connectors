# Kubernetes Connector V3 Contract

> **Status**: PROVEN runtime contract documented; manifest/runtime drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: `scripts/e2e/kubernetes_connector_verification.sh`
> **Kubernetes API upstream**: https://kubernetes.io/docs/reference/

## Purpose

This document fixes the operator-facing contract for `fcp.kubernetes`. The connector exposes the Kubernetes API surface implemented in this crate: pods, pod logs, deployments, services, ConfigMaps, Secrets, events, pod exec, and rollout helpers.

The connector is intentionally a bounded cluster operations bridge. It is not a kubeconfig manager, cluster provisioning tool, Helm client, CRD controller, admission webhook, operator framework, metrics server client, full watch/event streaming substrate, or general-purpose `kubectl` replacement.

## Current Runtime Snapshot

The current crate exposes these operations:

- `kubernetes.list_pods`
- `kubernetes.get_pod`
- `kubernetes.create_pod`
- `kubernetes.delete_pod`
- `kubernetes.get_pod_logs`
- `kubernetes.stream_pod_logs`
- `kubernetes.list_deployments`
- `kubernetes.get_deployment`
- `kubernetes.apply_deployment`
- `kubernetes.scale_deployment`
- `kubernetes.delete_deployment`
- `kubernetes.rollout_restart`
- `kubernetes.get_service`
- `kubernetes.list_services`
- `kubernetes.get_configmap`
- `kubernetes.update_configmap`
- `kubernetes.get_secret`
- `kubernetes.watch_events`
- `kubernetes.exec`
- `kubernetes.configmap.list`
- `kubernetes.configmap.get`
- `kubernetes.configmap.create`
- `kubernetes.configmap.update`
- `kubernetes.configmap.delete`
- `kubernetes.secret.list`
- `kubernetes.secret.get`
- `kubernetes.secret.create`
- `kubernetes.secret.delete`
- `kubernetes.rollout.status`
- `kubernetes.rollout.history`
- `kubernetes.rollout.rollback`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-kubernetes`.
- Manifest connector ID is `fcp.kubernetes`.
- Runtime `BaseConnector` ID is `kubernetes`; introspection and handshake report `fcp.kubernetes`.
- Manifest interface hash is `blake3-256:fcp.interface.v2:e90faeeadc7a5377ce77653b8e437e77916f71689d67e66186acddafcbff7a5c`.
- Configuration requires exactly one auth source: direct `bearer_token` or `credential_id`.
- Direct auth sends `Authorization: Bearer <token>`.
- `credential_id` mode sends `X-FCP-Credential-Id` and expects host egress policy to inject real secret material.
- Default base URL is `https://kubernetes.default.svc`.
- URL policy rejects malformed URLs, userinfo, query strings, fragments, non-HTTP(S) schemes, and non-loopback HTTP.
- URL policy accepts the default in-cluster service host, `.svc`, `.svc.cluster.local`, loopback hosts, and custom HTTPS hosts.
- URL policy is reported as configure status and readiness detail; the client is still created for `configured_with_warnings` cases.
- Runtime request timeout is 30 seconds.
- The client uses the shared retry loop with `max_retries = 3`.
- Runtime `invoke` uses `operation_id`, not `operation`.
- Runtime `simulate` uses `operation_id`, validates operation inventory and policy gates, and does not require configured/handshaken/client state.
- Runtime does not install a `CapabilityVerifier` and does not verify `capability_token`.
- Runtime does not verify approval tokens even when introspection reports approval modes.
- Writes and deletes are disabled by default.
- Pod exec is disabled by default.
- Enabling write operations or pod exec requires `allowed_namespaces`.
- Default exec target label requirement is `fcp.flywheel.ai/exec-approved=true`.
- `health()` is local state only; `self_check()` does not call Kubernetes for direct bearer-token auth.
- `handle_shutdown()` shuts down the client runtime and clears config/client/base flags, but leaves `session_id` in memory.

## Drift Visible In This Checkout

This README documents the runtime truth and keeps current drift visible:

- Runtime `BaseConnector` ID is `kubernetes`, while manifest and reported connector ID are `fcp.kubernetes`.
- Handshake is simplified and does not parse a full `HandshakeRequest`; it only reads optional `session_id`.
- Handshake does not return manifest hash, nonce binding, requested capability grants, or a capability verifier.
- `invoke` and `simulate` do not verify capability tokens.
- Introspection exposes approval metadata for high-risk operations, but runtime does not validate approval tokens.
- Manifest event caps say streaming is enabled with durable watch cursor state, but runtime exposes no event catalog and no durable cursor persistence.
- `kubernetes.watch_events` performs a one-shot event list and returns an array.
- `kubernetes.stream_pod_logs` performs a log request with `follow=true` and returns a string payload, not a connector event stream.
- `handle_health` reports `handshaken` from `session_id.is_some()`, while base readiness can be set by a handshake without a `session_id`.
- `handle_shutdown` leaves a stale `session_id`.
- `base_url_policy` can produce `configured_with_warnings` but does not hard-stop client creation.
- `kubernetes.get_secret` redacts data by default unless `unmask=true`, while `kubernetes.secret.get` returns the full secret object including `data`.
- The manifest state hint mentions watch cursors and checkpoints, but the current runtime does not persist watch cursors.
- The tracked verifier script is deliberately fail-closed: missing `rch` workers or remote prerequisites are reported as infra-blocked, not as a green connector proof.

A follow-up parity bead should align connector IDs, implement full handshake and token verification, reconcile approval metadata with runtime approval-token checks, split one-shot reads from true streams, persist watch cursors if event caps remain advertised, and add a tracked verification bundle.

## First-Slice Scope

The current Kubernetes README slice documents the existing runtime surface:

- direct bearer-token and host credential-reference configuration
- Kubernetes API base URL policy, timeout, retry, and provider error mapping
- pod, log, deployment, service, ConfigMap, Secret, event, exec, and rollout operations
- runtime policy flags for writes and exec
- namespace scope enforcement
- pod/deployment spec validation and exec target validation
- deterministic WireMock tests and direct proof commands

## Auth And Scope Boundary

- Authentication mechanisms: Kubernetes bearer token or host credential reference.
- Home zone: `z:infra`.
- Allowed source zones: `z:owner`, `z:private`, `z:work`, and `z:infra`.
- Allowed target zones: `z:infra` and `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Runtime capability surface from introspection:
  - `kubernetes.read` gates read-only pod, log, deployment, service, ConfigMap, event, and rollout reads.
  - `kubernetes.write` gates scaling, rollout restart, ConfigMap updates, and rollout rollback.
  - `kubernetes.admin` gates pod create/delete, deployment apply/delete, exec, and ConfigMap create/delete.
  - `kubernetes.secrets` gates full secret read/create/delete operations.
- Runtime policy flags, not capability tokens, currently enforce write and exec availability.
- The connector does not persist bearer tokens, credential secret material, raw provider responses, secret values, pod logs, exec output, event lists, or rollout data outside process memory.
- Kubernetes payloads can include infrastructure topology, pod specs, image names, logs, events, ConfigMaps, Secrets, and exec output. Treat live output as infra-zone operational data.

## Network And Runtime Invariants

- Default production host shape: `kubernetes.default.svc`.
- Common Kubernetes API ports: `443` and `6443`.
- TLS and SNI are required by the manifest for provider operations.
- Manifest network policy denies localhost, private ranges, and tailnet ranges; local loopback coverage is limited to deterministic test fixtures outside production egress.
- Runtime base URL policy accepts in-cluster service hosts and custom HTTPS API endpoints.
- Runtime base URL policy accepts loopback hosts for deterministic tests.
- Runtime base URL policy rejects non-loopback HTTP.
- Runtime request timeout: `30 seconds`.
- Runtime retry policy: three attempts using the shared retry loop.
- Manifest connect timeout is `10000 ms`.
- Manifest total timeout is usually `60000 ms` for mutating operations.
- Manifest maximum response bytes range from `1048576` to `10485760`.
- Sandbox profile is `strict`, with `1024 MB` memory, `75%` CPU, no exec, and no inbound listener capability.
- The connector itself does not open inbound sockets.

## Policy Flags

| Configuration field | Default | Runtime effect |
|---------------------|---------|----------------|
| `allow_write_operations` | `false` | Gates write, deploy, delete, and secret mutation categories. |
| `allow_pod_exec` | `false` | Gates `kubernetes.exec`. |
| `allowed_namespaces` | unset | Required before enabling writes or exec; when set, every input `namespace` must be listed. |
| `allow_exec_into_system_namespaces` | `false` | Blocks exec in `kube-system`, `kube-public`, and `kube-node-lease` unless enabled. |
| `allow_untrusted_exec_targets` | `false` | Requires approved target labels unless enabled. |
| `exec_required_pod_labels` | `fcp.flywheel.ai/exec-approved=true` | Labels required on exec target pods. |
| `allow_shell_exec` | `false` | Blocks shell trampolines such as `sh`, `bash`, `python`, `node`, `powershell`, and `env <shell>`. |

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `kubernetes.read` | Read pods, logs, deployments, services, ConfigMaps, event lists, and rollout metadata. |
| `kubernetes.write` | Scale or restart deployments, update ConfigMaps, and roll back deployments. |
| `kubernetes.admin` | Create/delete pods, apply/delete deployments, create/delete ConfigMaps, and run pod exec. |
| `kubernetes.secrets` | Read, create, and delete Kubernetes Secrets. |
| `network.tls.mtls` | Manifest optional capability; no distinct runtime configuration path is exposed in this README slice. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `kubernetes.list_pods` | `GET /api/v1/namespaces/{namespace}/pods` | `kubernetes.read` | `Safe` | `Low` | `Strict` | Lists pods, with optional label and field selectors. |
| `kubernetes.get_pod` | `GET /api/v1/namespaces/{namespace}/pods/{name}` | `kubernetes.read` | `Safe` | `Low` | `Strict` | Reads one pod object. |
| `kubernetes.create_pod` | `POST /api/v1/namespaces/{namespace}/pods` | `kubernetes.admin` | `Dangerous` | `High` | `None` | Creates a standalone pod after spec validation. |
| `kubernetes.delete_pod` | `DELETE /api/v1/namespaces/{namespace}/pods/{name}` | `kubernetes.admin` | `Dangerous` | `High` | `BestEffort` | Deletes a pod and may trigger rescheduling. |
| `kubernetes.get_pod_logs` | `GET /api/v1/namespaces/{namespace}/pods/{name}/log` | `kubernetes.read` | `Safe` | `Low` | `Strict` | Reads pod logs as a string. |
| `kubernetes.stream_pod_logs` | `GET /api/v1/namespaces/{namespace}/pods/{name}/log?follow=true` | `kubernetes.read` | `Safe` | `Low` | `Strict` | Requests followed logs but returns a string payload. |
| `kubernetes.list_deployments` | `GET /apis/apps/v1/namespaces/{namespace}/deployments` | `kubernetes.read` | `Safe` | `Low` | `Strict` | Lists deployments. |
| `kubernetes.get_deployment` | `GET /apis/apps/v1/namespaces/{namespace}/deployments/{name}` | `kubernetes.read` | `Safe` | `Low` | `Strict` | Reads one deployment. |
| `kubernetes.apply_deployment` | `POST` or `PUT /apis/apps/v1/namespaces/{namespace}/deployments` | `kubernetes.admin` | `Dangerous` | `High` | `BestEffort` | Creates or updates a deployment after pod-template validation. |
| `kubernetes.scale_deployment` | `PATCH /apis/apps/v1/namespaces/{namespace}/deployments/{name}/scale` | `kubernetes.write` | `Risky` | `High` | `BestEffort` | Changes replica count. |
| `kubernetes.delete_deployment` | `DELETE /apis/apps/v1/namespaces/{namespace}/deployments/{name}` | `kubernetes.admin` | `Dangerous` | `High` | `BestEffort` | Deletes a deployment. |
| `kubernetes.rollout_restart` | `PATCH /apis/apps/v1/namespaces/{namespace}/deployments/{name}` | `kubernetes.write` | `Risky` | `High` | `None` | Patches restart annotation using an epoch timestamp. |
| `kubernetes.get_service` | `GET /api/v1/namespaces/{namespace}/services/{name}` | `kubernetes.read` | `Safe` | `Low` | `Strict` | Reads one Service. |
| `kubernetes.list_services` | `GET /api/v1/namespaces/{namespace}/services` | `kubernetes.read` | `Safe` | `Low` | `Strict` | Lists Services. |
| `kubernetes.get_configmap` | `GET /api/v1/namespaces/{namespace}/configmaps/{name}` | `kubernetes.read` | `Safe` | `Low` | `Strict` | Legacy ConfigMap read operation. |
| `kubernetes.update_configmap` | `PUT /api/v1/namespaces/{namespace}/configmaps/{name}` | `kubernetes.write` | `Risky` | `Medium` | `BestEffort` | Legacy ConfigMap update operation; approval metadata is `Policy`. |
| `kubernetes.get_secret` | `GET /api/v1/namespaces/{namespace}/secrets/{name}` | `kubernetes.secrets` | `Dangerous` | `High` | `Strict` | Legacy Secret read; redacts `data` unless `unmask=true`. |
| `kubernetes.watch_events` | `GET /api/v1/namespaces/{namespace}/events` | `kubernetes.read` | `Safe` | `Low` | `Strict` | One-shot event list, not a durable watch stream. |
| `kubernetes.exec` | `GET /api/v1/namespaces/{namespace}/pods/{name}/exec` | `kubernetes.admin` | `Dangerous` | `High` | `None` | Runs a command in a container after exec guard validation. |
| `kubernetes.configmap.list` | `GET /api/v1/namespaces/{namespace}/configmaps` | `kubernetes.read` | `Safe` | `Low` | `Strict` | Lists ConfigMaps. |
| `kubernetes.configmap.get` | `GET /api/v1/namespaces/{namespace}/configmaps/{name}` | `kubernetes.read` | `Safe` | `Low` | `Strict` | Reads one ConfigMap. |
| `kubernetes.configmap.create` | `POST /api/v1/namespaces/{namespace}/configmaps` | `kubernetes.admin` | `Dangerous` | `High` | `None` | Creates a ConfigMap. |
| `kubernetes.configmap.update` | `PUT /api/v1/namespaces/{namespace}/configmaps/{name}` | `kubernetes.write` | `Dangerous` | `Medium` | `BestEffort` | Updates a ConfigMap. |
| `kubernetes.configmap.delete` | `DELETE /api/v1/namespaces/{namespace}/configmaps/{name}` | `kubernetes.admin` | `Dangerous` | `High` | `BestEffort` | Deletes a ConfigMap. |
| `kubernetes.secret.list` | `GET /api/v1/namespaces/{namespace}/secrets` | `kubernetes.read` | `Safe` | `Low` | `Strict` | Lists Secrets and strips `data` from returned items. |
| `kubernetes.secret.get` | `GET /api/v1/namespaces/{namespace}/secrets/{name}` | `kubernetes.secrets` | `Dangerous` | `High` | `Strict` | Reads a full Secret object including `data`. |
| `kubernetes.secret.create` | `POST /api/v1/namespaces/{namespace}/secrets` | `kubernetes.secrets` | `Dangerous` | `High` | `None` | Creates a Secret. |
| `kubernetes.secret.delete` | `DELETE /api/v1/namespaces/{namespace}/secrets/{name}` | `kubernetes.secrets` | `Dangerous` | `High` | `BestEffort` | Deletes a Secret. |
| `kubernetes.rollout.status` | deployment and ReplicaSet reads | `kubernetes.read` | `Safe` | `Low` | `Strict` | Computes rollout completion from replica status. |
| `kubernetes.rollout.history` | ReplicaSet list for deployment selector | `kubernetes.read` | `Safe` | `Low` | `Strict` | Lists rollout revisions and first container image. |
| `kubernetes.rollout.rollback` | `PATCH /apis/apps/v1/namespaces/{namespace}/deployments/{name}` | `kubernetes.write` | `Dangerous` | `High` | `BestEffort` | Patches deployment template to a provided previous revision. |

## Approval Metadata

Runtime introspection returns approval metadata:

| Approval mode | Operations |
|---------------|------------|
| `Interactive` | `kubernetes.delete_pod`, `kubernetes.create_pod`, `kubernetes.apply_deployment`, `kubernetes.delete_deployment`, `kubernetes.get_secret`, `kubernetes.rollout_restart`, `kubernetes.scale_deployment`, `kubernetes.exec`, `kubernetes.configmap.create`, `kubernetes.configmap.update`, `kubernetes.configmap.delete`, `kubernetes.secret.get`, `kubernetes.secret.create`, `kubernetes.secret.delete`, `kubernetes.rollout.rollback` |
| `Policy` | `kubernetes.update_configmap` |
| `None` | `kubernetes.list_services`, `kubernetes.get_configmap`, `kubernetes.get_deployment`, `kubernetes.get_pod`, `kubernetes.get_pod_logs`, `kubernetes.get_service`, `kubernetes.list_deployments`, `kubernetes.list_pods`, `kubernetes.stream_pod_logs`, `kubernetes.watch_events`, `kubernetes.configmap.list`, `kubernetes.configmap.get`, `kubernetes.secret.list`, `kubernetes.rollout.status`, `kubernetes.rollout.history` |

This metadata is advisory in the current runtime. `invoke` enforces configuration policy gates and input validation, but does not validate an approval token.

## Resource URIs

Runtime capability-token verification is absent for Kubernetes in this checkout, so there are no effective resource URI bindings. The practical authorization binding is configuration plus policy flags plus namespace guards.

Follow-up work should add resource URI shapes such as:

| Operation family | Candidate resource URI shape |
|------------------|------------------------------|
| Pods and logs | `kubernetes://{cluster}/namespaces/{namespace}/pods/{name}` |
| Deployments and rollouts | `kubernetes://{cluster}/namespaces/{namespace}/deployments/{name}` |
| Services | `kubernetes://{cluster}/namespaces/{namespace}/services/{name}` |
| ConfigMaps | `kubernetes://{cluster}/namespaces/{namespace}/configmaps/{name}` |
| Secrets | `kubernetes://{cluster}/namespaces/{namespace}/secrets/{name}` |
| Events | `kubernetes://{cluster}/namespaces/{namespace}/events` |
| Exec | `kubernetes://{cluster}/namespaces/{namespace}/pods/{name}/exec` |

## Runtime Guardrails

The current runtime implements several concrete guardrails:

- Namespace scope applies to any input with a `namespace` field when `allowed_namespaces` is configured.
- Write, deploy, delete, and secret mutation categories require `allow_write_operations=true`.
- Pod exec requires `allow_pod_exec=true`.
- Pod and deployment specs reject `hostNetwork`, `hostPID`, `hostIPC`, `shareProcessNamespace`, `serviceAccountName`, `serviceAccount`, `nodeName`, `automountServiceAccountToken=true`, hostPath volumes, projected service account tokens, privileged containers, `allowPrivilegeEscalation`, added Linux capabilities, and host ports.
- Container specs must include non-empty `name` and `image`.
- Exec rejects system namespaces unless explicitly enabled.
- Exec rejects shell trampolines unless explicitly enabled.
- Exec validates the target pod and rejects host networking, host PID/IPC, hostPath volumes, privileged containers, `allowPrivilegeEscalation`, and ambiguous multi-container targets.
- Exec requires approved pod labels unless `allow_untrusted_exec_targets=true`.
- Path segments reject empty values, slash and backslash, `..`, `%2f`, and `%5c`.
- Query selectors are percent-encoded before request construction.

## Explicit Non-Goals

The current implementation does not include:

- kubeconfig parsing, context switching, cluster discovery, certificate authority provisioning, or token refresh
- Helm, Kustomize, server-side apply field ownership, CRDs, custom resources, Jobs, CronJobs, StatefulSets, DaemonSets, Ingresses, PVCs, RBAC, Namespaces, Nodes, or admission resources
- true watch streams, durable resourceVersion replay, informer caches, bookmarks, backoff cursors, or event fanout
- metrics, traces, audit log collection, Prometheus API access, or Kubernetes Events streaming as connector events
- `kubectl cp`, port forwarding, attach, debug containers, ephemeral containers, or local process execution
- transparent Secret redaction across every Secret operation; `kubernetes.secret.get` returns full secret data

These are excluded on purpose:

- Cluster administration needs narrower capability and approval contracts.
- True watch support needs durable cursor state and stream backpressure before it is safe to advertise as a full event surface.
- Exec remains a high-risk maintenance operation and must stay behind explicit policy flags and target validation.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- local configuration, client, shutdown, base URL, auth mode, namespace policy, write policy, and exec policy state
- degraded self-check for unconfigured and credential-reference modes
- direct-auth self-check based on local readiness only, not a live Kubernetes API probe
- operation metadata with capability, risk, safety tier, idempotency, schemas, hints, and approval metadata
- simulation denial for unknown operations or policy-denied operations
- typed provider/FCP error mapping

The deterministic integration evidence is anchored on connector-local tests covering:

- lifecycle, configuration, URL policy, introspection, simulation, doctor, self-check, counters, and shutdown behavior
- read operations for pods, logs, deployments, services, ConfigMaps, Secrets, events, and rollouts through deterministic HTTP fixtures
- write and delete operation policy denials by default
- namespace scope denial
- ConfigMap and Secret create/update/delete paths when write policy is enabled
- Secret list data stripping and legacy Secret get redaction
- exec success and rejection cases for missing inputs, shell trampolines, system namespaces, unapproved target pods, hostPath targets, and privileged pods
- provider 401, 403, 404, 429, and API error mapping

## Source Notes

- `connectors/kubernetes/src/connector.rs` defines configuration parsing, URL policy, lifecycle handlers, introspection, simulation, runtime policy gates, spec validation, exec validation, and invoke dispatch.
- `connectors/kubernetes/src/client.rs` defines Kubernetes API paths, auth headers, retry dispatch, timeout, selector encoding, path validation, and provider error mapping.
- `connectors/kubernetes/src/types.rs` defines Kubernetes pod, deployment, service, ConfigMap, Secret, event, rollout, and exec data shapes.
- `connectors/kubernetes/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/kubernetes/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, event caps, and rate-limit intent.
- `connectors/kubernetes/tests/integration.rs` contains the runtime contract proof surface.
- `scripts/e2e/kubernetes_connector_verification.sh` bundles the redaction-safe gauntlet, docs, Cargo, integration, and loopback local non-mock proof lane for reruns.

## Verification Bundle

The closeout surface is the verifier, crate-local test suite, and fail-closed
`fwc proof run` evidence for Cargo-backed `rch` proof commands. The verifier
writes proof-governor artifacts under `${OUT_ROOT}/proof`. Only
`accepted_remote_proof` rows in `*.rch_remote_proof.jsonl` are green closeout
evidence for Cargo-backed steps. `refused_local_fallback`, `infra_blocked`,
`remote_command_failed`, `failed_closed`, `not_proof`, or a missing proof row
keep the batch bead open. `format_check` is a source-state check, not accepted
remote Cargo proof.

Run these after changing this connector contract:

```bash
scripts/e2e/kubernetes_connector_verification.sh
PROOF_GOVERNOR=1 scripts/e2e/kubernetes_connector_verification.sh
FWC_BIN=/path/to/current/target/debug/fwc PROOF_GOVERNOR=1 scripts/e2e/kubernetes_connector_verification.sh
git diff --check -- connectors/kubernetes/README.md
ubs connectors/kubernetes/README.md
LC_ALL=C rg -n '[^ -~]' connectors/kubernetes/README.md
rg -n '\bmaster\b' connectors/kubernetes/README.md
```

For source or behavior changes, also run the connector proof lane through `rch`:

```bash
rch exec -- cargo test -p fcp-kubernetes
rch exec -- cargo check -p fcp-kubernetes --all-targets
rch exec -- cargo clippy -p fcp-kubernetes --all-targets -- -D warnings
rch exec -- cargo fmt --check
```

## Operator Guidance

Rerun commands are listed in the verification bundle above. Use the tracked verifier for the full redaction-safe proof lane, and use the individual `rch` commands only when narrowing a specific failing step.

- Prefer `credential_id` for production so host policy owns secret injection.
- Use direct `bearer_token` only in local deterministic tests or explicitly scoped environments.
- Set `allowed_namespaces` before enabling writes or exec.
- Treat `kubernetes.exec`, deployment mutation, Secret reads, Secret mutation, pod create/delete, and ConfigMap mutation as high-review operations.
- Use `kubernetes.get_secret` when redaction-by-default is required; do not use `kubernetes.secret.get` unless full Secret data is intentionally needed.
- Do not rely on capability-token or approval-token enforcement until runtime verification is implemented.
- Do not interpret `watch_events` or `stream_pod_logs` as durable connector event streams in this checkout.
