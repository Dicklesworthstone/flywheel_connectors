# S3 Connector

> **Status**: native FCP runtime with AWS SigV4 and S3 REST response handling
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Amazon S3 API reference**: https://docs.aws.amazon.com/AmazonS3/latest/API/Type_API_Reference.html
> **PutObject API**: https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html
> **GetObject API**: https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html
> **Presigned URL guide**: https://docs.aws.amazon.com/AmazonS3/latest/userguide/ShareObjectPreSignedURL.html

## Purpose

`fcp-s3` exposes ten bounded operations for general-purpose S3 buckets: bucket list/create/delete, object put/get/head/list/copy/delete, and signed download URLs. Runtime and manifest identify the connector as `fcp.s3`. The manifest declares a native, stateless process.

Normal HTTP requests use AWS Signature Version 4, including the exact payload digest, region, endpoint authority, and temporary-session token when configured. Object data travels as bytes; metadata comes from HTTP headers; bucket listings, object listings, copy results, and provider errors use S3 XML shapes. This is an FCP 2.0 JSONL executable, not an FCP3 transport cutover.

## Configuration

Send `configure` with direct credentials:

```json
{
  "access_key_id": "AKIAEXAMPLE",
  "secret_access_key": "configured-secret",
  "region": "us-east-1",
  "session_token": "optional-temporary-session-token"
}
```

Omit `session_token` for long-lived credentials. The connector does not discover credentials from profiles, assume roles, or refresh an expired session. `credential_id` is rejected because this native executable has no host SigV4 signing transport. It never converts an unsupported signing mode into an unsigned sharing URL.

The region defaults to `us-east-1`, whose default endpoint is `https://s3.amazonaws.com`. Other regions use `https://s3.<region>.amazonaws.com`; `cn-` regions use the `.amazonaws.com.cn` suffix. Set `base_url` to an HTTPS origin for an alternate S3-compatible endpoint. A non-default port is included in signing. Only the root path is accepted; credentials, query strings and fragments in an endpoint are rejected. Plain HTTP is accepted only for loopback development fixtures.

The embedded network policy allows AWS hosts over port 443 and denies private/loopback addresses. An alternate endpoint requires the corresponding host policy; endpoint syntax validation does not grant egress. Configure or handshake failure revokes earlier session authority. A failed replacement configuration also discards the previous credentials.

## Native Protocol And Authority

After configuration, handshake with `protocol_version` `2.0` or `2.0.0`, a host public key, a nonce, an allowed target zone (`z:private` or `z:work`), and requested capability IDs (`s3.read`, `s3.write`, `s3.delete`). The returned `connector_id`, fresh actual `instance_id`, `session_id`, granted capabilities and bundled-manifest SHA-256 identify the negotiated session. Bind signed tokens to the returned instance; a requested instance ID is not reused. An empty capability request grants nothing. Changing the session zone requires reconfiguration.

Invocations use the canonical request envelope, inside the JSON-RPC `params` object:

```json
{
  "type": "invoke",
  "id": "read-report",
  "connector_id": "fcp.s3",
  "zone_id": "z:work",
  "operation": "s3.get_object",
  "input": { "bucket": "reports", "key": "2026/report.txt" },
  "capability_token": "<host-issued serialized token>",
  "deadline_ms": 10000
}
```

Successful replies contain one canonical `response` envelope with the same ID, a `result`, and the actual `resource_uris`. Schema and domain validation happen before admission. Signed capability checks bind the host key, instance, zone, operation, negotiated capability and these input-derived resources:

| Operation target | Authorized resource |
|---|---|
| Object operations and presigning | `s3://bucket/percent-encoded-key` |
| Bucket operations and object-list pages | `s3://bucket` |
| Account bucket listing | `s3://` |
| Object copy | Both source and destination object URIs |

Object-key slashes are preserved. Glob metacharacters and URI delimiters in keys are encoded as data. Keys must be 1–1024 UTF-8 bytes; literal `.` or `..` path segments are rejected because URL normalization could target another object. General-purpose bucket names must pass the supported DNS validation.

Admission consumes signed call allowances and reserves the compact JSON request plus a bounded response against signed byte allowances. Simulation checks authority without spending a call. Timeouts, cancellation and provider errors do not refund a potentially executed invocation. Byte limits are FCP message accounting, not S3 billing measurements.

This executable relies on its private host-to-connector control channel. The host must verify approval signatures, holder proofs, revocation, leases, provenance and policy before dispatch. Manifest approval requirements remain policy approval for put/copy and elevation approval for delete/create-bucket/delete-bucket/presign. Canonical `approval_tokens` are host evidence; unsigned local metadata never substitutes for signed capability authority. Local simulation does not prove those host checks or live AWS availability.

## Data, Pagination And Execution Bounds

`s3.put_object` accepts `body` with optional `body_encoding` (`utf8`, the default, or standard `base64`) and `content_type`. Uploads and downloads are limited to 2 MiB of actual object data. Oversized objects fail instead of returning a successful truncated value. `s3.get_object` returns `body`, `body_encoding` and `content_type`; invalid UTF-8 bytes are represented in base64. `s3.head_object` reads metadata headers without downloading a response body.

`s3.list_objects` uses ListObjectsV2. Optional inputs are `prefix`, `max_keys` (1–1000), and the opaque `continuation_token`. A truncated page returns `next_continuation_token` in its result and `next_cursor` in its response envelope. Each subsequent page is a new authorized invocation. List/copy XML is bounded at 2 MiB, and provider error bodies at 64 KiB.

Presigned GET URLs use the configured credentials and endpoint, including temporary-session credentials. `expires_in` defaults to 3600 seconds and must be 1–604800; invalid lifetimes are rejected, not clamped. A temporary credential can expire before the requested URL lifetime. Presigning creates a bearer URL and therefore remains a dangerous operation requiring host approval.

The JSONL reader bounds each request at 16 MiB. Invocation deadlines cover dispatch, response validation and accounting, with a maximum of 30 seconds. Timing out drops pending I/O and reports that the provider outcome may be unknown. Redirects and automatic HTTP retries are disabled. The explicit retry path is limited to safe read operations and eligible failures within the remaining budget. Mutations are never automatically replayed after an uncertain result. Their declared idempotency is `best_effort`, accounting for versioned-object effects; this is not an idempotency-result cache.

Successful shutdown flushes its reply and exits even while stdin remains open. EOF, I/O errors, malformed shutdown, failed configuration and failed handshake all revoke local authority. `health` and `doctor` distinguish configuration from negotiated readiness; `self_check` performs a signed list-buckets request. These checks do not establish that every object or bucket permission is available.

## Operation Inventory

| Operation | Runtime request shape | Capability | SafetyTier | RiskLevel | Idempotency | Required input |
|-----------|-----------------------|------------|------------|-----------|-------------|----------------|
| `s3.put_object` | `PUT /{bucket}/{key}` | `s3.write` | `Risky` | `Medium` | `BestEffort` | `bucket`, `key`, `body` |
| `s3.get_object` | `GET /{bucket}/{key}` | `s3.read` | `Safe` | `Low` | `Strict` | `bucket`, `key` |
| `s3.delete_object` | `DELETE /{bucket}/{key}` | `s3.delete` | `Dangerous` | `High` | `BestEffort` | `bucket`, `key` |
| `s3.create_bucket` | `PUT /{bucket}` | `s3.write` | `Dangerous` | `High` | `BestEffort` | `bucket` |
| `s3.delete_bucket` | `DELETE /{bucket}` | `s3.delete` | `Dangerous` | `High` | `BestEffort` | `bucket` |
| `s3.head_object` | `HEAD /{bucket}/{key}` | `s3.read` | `Safe` | `Low` | `Strict` | `bucket`, `key` |
| `s3.list_objects` | `GET /{bucket}?list-type=2` | `s3.read` | `Safe` | `Low` | `Strict` | `bucket`; optional `prefix`, `max_keys`, `continuation_token` |
| `s3.list_buckets` | `GET /` | `s3.read` | `Safe` | `Low` | `Strict` | none |
| `s3.copy_object` | `PUT /{dest_bucket}/{dest_key}` | `s3.write` | `Risky` | `Medium` | `BestEffort` | `source_bucket`, `source_key`, `dest_bucket`, `dest_key` |
| `s3.generate_presigned_url` | local signing only | `s3.read` | `Dangerous` | `High` | `None` | `bucket`, `key`; optional `expires_in` |

## Explicit Non-Goals

The current implementation does not include:

- AWS STS, IAM role assumption, MFA, profile discovery, or credential refresh
- multipart upload, resumable upload, checksum selection, server-side encryption options, object tags, ACLs, object lock, legal holds, or retention policies
- bucket policy, CORS, website hosting, lifecycle, replication, inventory, notification, versioning, requester-pays, or access-point management
- delimiter/common-prefix handling, S3 Select, Glacier restore, batch operations, directory buckets, access-point or object-lambda routing
- inbound event notifications, SQS/SNS/EventBridge integration, durable cursors, or replay
- durable local object cache, large-object streaming, or provider-wide rate-limit enforcement

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- local configuration, client, auth mode, base URL, and request/error counter state
- direct-key live list-buckets self-check behavior
- fail-closed rejection of unsupported credential-reference signing
- typed introspection with operations, schemas, capability IDs, risk levels, safety tiers, idempotency, and approval metadata
- simulation allow/deny with the same local signed operation/resource authority checks used by invoke
- provider/FCP error mapping for auth failures, missing resources, rate limits, malformed XML, oversized responses, and transport errors

The deterministic integration evidence is anchored on connector-local tests covering:

- lifecycle, configuration, health, handshake, introspection, simulation, shutdown, and missing-input behavior
- client-level put/get/head/delete/list/copy/list-buckets and presigning behavior through deterministic REST fixtures
- connector-level invoke dispatch with bound capability tokens
- wrong-capability rejection, unknown-operation rejection, and missing required input rejection
- signed authority rejection even when unsigned approval metadata is supplied
- direct-key presigning and refusal to emit unsigned URLs
- provider 401/403, 404, 429, and retryable server-error classes
- auth redaction, XML response handling, exact resource scopes, pagination and binary data

## Source Notes

- `connectors/s3/src/connector.rs` defines configuration parsing, lifecycle handlers, signed admission, operation catalog, simulation, introspection, and invoke dispatch.
- `connectors/s3/src/client.rs` defines URL validation, SigV4 signing, bounded REST requests, retry behavior, presigning, and provider error mapping.
- `connectors/s3/src/types.rs` defines runtime response and API error shapes.
- `connectors/s3/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/s3/manifest.toml` defines the manifest operation catalog, network constraints, sandbox boundary, zone policy, and rate-limit intent.
- `connectors/s3/tests/integration.rs` and `tests/local_non_mock.rs` exercise the native and REST contracts.

## Verification Bundle

Run the connector proof lane through `rch` when the remote builder is available:

```bash
rch exec -- cargo test -p fcp-s3
rch exec -- cargo check -p fcp-s3 --all-targets
rch exec -- cargo clippy -p fcp-s3 --all-targets -- -D warnings
rch exec -- cargo fmt --check
```

The deterministic fixtures exercise production request construction and response decoding without AWS credentials. They do not constitute a live AWS account acceptance run. Use the intended account, region, bucket policy and native host approval path for deployment validation.
