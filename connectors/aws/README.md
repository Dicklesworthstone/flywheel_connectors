# AWS Connector V3 Contract

> **Status**: native AWS protocols, bounded inventory pagination, and host-managed SigV4 transport implemented; live S3 object lifecycle proof documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: `scripts/e2e/aws_connector_verification.sh`
> **Primary upstream**: https://docs.aws.amazon.com/AmazonS3/latest/API/Type_API_Reference.html
> **EC2 upstream**: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html
> **Lambda upstream**: https://docs.aws.amazon.com/lambda/latest/api/API_Invoke.html
> **STS upstream**: https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html
> **Signing upstream**: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv.html

## Purpose

This document fixes the operator-facing contract for `fcp.aws`. The connector exposes the AWS surface implemented in this crate: S3 bucket/object operations, EC2 instance read and lifecycle operations, Lambda list/invoke, STS identity, and credential health.

The connector is intentionally a work-zone AWS operations bridge. It is not a general AWS SDK, CloudFormation orchestrator, IAM policy editor, credential broker, inventory warehouse, event listener, or production-safe live mutation harness.

## Current Runtime Snapshot

The current runtime exposes these operations:

- `aws.s3.list_buckets`
- `aws.s3.list_objects`
- `aws.s3.get_object`
- `aws.s3.put_object`
- `aws.s3.delete_object`
- `aws.ec2.describe_instances`
- `aws.ec2.start_instance`
- `aws.ec2.stop_instance`
- `aws.ec2.terminate_instance`
- `aws.lambda.list_functions`
- `aws.lambda.invoke`
- `aws.sts.get_caller_identity`
- `aws.health`

Important runtime truths the contract preserves:

- Configuration requires `region` and either static AWS credentials or service-specific host credential references.
- `session_token` is optional and is forwarded as `X-Amz-Security-Token` when present.
- Credential values are trimmed on configuration and redacted in debug output.
- Default service endpoints are region-derived for all four services:
  - `https://s3.{region}.amazonaws.com`
  - `https://ec2.{region}.amazonaws.com`
  - `https://lambda.{region}.amazonaws.com`
  - `https://sts.{region}.amazonaws.com`
- `s3_base_url`, `ec2_base_url`, `lambda_base_url`, and `sts_base_url` overrides are accepted for staging, LocalStack, signing proxies, and deterministic tests.
- Endpoint overrides must be valid URLs, must not include userinfo/query/fragment, and must use HTTPS unless they target loopback verification hosts.
- Runtime request timeout defaults to `30_000 ms`.
- Direct mode signs requests locally with SigV4. Host mode sends the original admitted capability and a service-specific credential reference to the host, which injects the signature without exposing AWS secrets to the connector.
- The connector uses the shared HTTP retry loop for provider dispatch.
- Reads and EC2 lifecycle operations retain bounded retries for transient errors. S3 put/delete and Lambda invoke retry only failures known to occur before dispatch or explicit HTTP 429 throttles. Uncertain transport failures and server errors are terminal and carry no retry hint.
- 401 and 403 map to unauthorized; 404 maps to not found; other non-success non-500 statuses map to terminal API errors.
- Handshake grants requested capabilities and installs a bound `CapabilityVerifier`.
- `invoke` and `simulate` both verify bound capability tokens against the requested operation.
- `self_check` intentionally abstains against default STS to avoid probing production AWS credentials during routine readiness checks.
- Direct-mode `self_check` runs only when `sts_base_url` points at a custom verification endpoint. Host-mode checks require a signed `aws.health` invocation and an STS binding.
- `health` is local readiness plus provisioning detail; it does not call AWS directly.
- `introspect` exposes no streaming support.

## Authentication Configuration

Direct mode remains available:

```json
{
  "region": "us-west-2",
  "access_key_id": "<AWS access key>",
  "secret_access_key": "<AWS secret key>",
  "session_token": "<optional temporary session token>"
}
```

For host-managed signing, bind AWS profiles through the host credential service and configure the resulting references. Each host SigV4 profile pins a service and signing region, so each service needs a distinct binding:

```json
{
  "region": "us-west-2",
  "credential_ids": {
    "s3": "11111111-1111-4111-8111-111111111111",
    "ec2": "22222222-2222-4222-8222-222222222222",
    "lambda": "33333333-3333-4333-8333-333333333333",
    "sts": "44444444-4444-4444-8444-444444444444"
  }
}
```

The UUIDs above are examples. Use the actual references returned by host binding, with signing services `s3`, `ec2`, `lambda`, and `sts`, and a signing region matching the provider endpoint. With default endpoints, that is the configured connector region. The host profile's zone and allowed hosts must also match the invocation. The original signed capability must permit each credential reference and provider resource used by the operation.

A connector using one service may instead provide `credential_id` and `credential_service`, for example a reference plus `"credential_service": "s3"`. A partial service map is valid; operations for missing services fail before network access. `aws.health` requires the `sts` reference. Configuration rejects empty maps, unknown service names, malformed references, duplicate references across services, mixed map/shorthand forms, and mixed static/host credentials.

The host launcher supplies `FCP_HOST_EGRESS_PROXY_URL`. Host credentials without this runtime endpoint are rejected during configuration. Each admitted invocation gets an immutable transport context containing its original capability, operation, zone, request ID, and correlation ID. Proxy admission or attribution failures remain terminal; the connector never falls back to direct AWS access. Host replies must confirm credential injection. Unsigned lifecycle health checks do not send credentialed traffic.

Default DNS construction uses `amazonaws.com`, covering commercial and GovCloud regional endpoints. China and isolated partitions require explicit endpoint overrides and matching manifest/network policy; this connector does not discover partition endpoints. AWS recommends [regional STS endpoints](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_region-endpoints.html); their region now matches the configured SigV4 scope by default.

## Native Protocols And Complete Inventories

S3 bucket and object lists, EC2 instance lists and lifecycle responses, and STS identity use their native XML envelopes. Lambda function lists decode the provider's `Functions` envelope. Lambda invocation returns the function's JSON payload unchanged and takes status, function error, and executed version from HTTP metadata. A function cannot forge the outer invocation result by returning fields with the same names.

Native decoding checks required identities and envelope structure. EC2 mutations must return exactly the requested instance under the expected action response. XML parsing rejects malformed documents, unexpected roots, DTDs, and excessive nesting. Parse errors do not echo provider bodies.

S3 object keys are treated as literal UTF-8 data: percent signs, query/fragment punctuation, backslashes, Unicode, and repeated slashes retain their exact identity for reads, writes, and deletes. Listing requests use `encoding-type=url`; returned keys are decoded exactly once, while continuation tokens remain opaque. Prefixes are encoded as query data. Keys exceeding 1,024 UTF-8 bytes and standalone `.` or `..` path segments are rejected before dispatch because the HTTP URL parser cannot preserve those segments. Dots inside a name, such as `..backup`, remain supported.

Bucket, object, instance, and Lambda function inventories follow provider continuation tokens under one request deadline. Opaque tokens are URL-encoded and retain the original authority on every page. S3 bucket lists explicitly request pages of up to 1,000 buckets; EC2 lists request up to 1,000 results. The client returns the complete aggregated inventory or an error, with limits of 100 pages, 100,000 entries, and 10 MiB of aggregate provider response bytes. Repeated or invalid tokens, missing S3 truncation markers, and limit exhaustion fail instead of silently returning a partial inventory.

S3 object reads preserve body and HTTP metadata and reject non-success responses. S3 put/delete take native ETag, version, and delete-marker metadata from response headers. On versioned buckets, [repeated uploads](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html) or [deletions](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObject.html) can create additional versions or delete markers, so these operations advertise `BestEffort` idempotency. Ambiguous outcomes require checking the provider state before deliberately issuing another mutation.

Regression coverage includes native provider envelopes, pagination, direct SigV4 compatibility, all thirteen operations through a loopback host proxy, original capability forwarding, per-service reference selection, missing-proxy refusal, denied or misattributed host responses, and mutation replay prevention.

## First-Slice Scope

The first AWS README slice documents the existing runtime surface:

- S3 bucket listing through `GET /`
- S3 object listing through `GET /{bucket}?list-type=2`
- S3 object download through `GET /{bucket}/{key}`
- S3 object upload through `PUT /{bucket}/{key}`
- S3 object deletion through `DELETE /{bucket}/{key}`
- EC2 instance listing through `Action=DescribeInstances&Version=2016-11-15`
- EC2 start, stop, and terminate through AWS Query API action calls
- Lambda function listing through `GET /2015-03-31/functions`
- Lambda invocation through `POST /2015-03-31/functions/{function_name}/invocations`
- STS identity through `Action=GetCallerIdentity&Version=2011-06-15`
- SigV4 static-key, session-token, and host-managed credential-reference signing
- endpoint override, lifecycle, doctor, self-check, introspection, simulation, and shutdown surfaces

## Auth And Scope Boundary

- Authentication mechanisms: static AWS access key and secret access key with optional session token, or host-managed per-service SigV4 credential references.
- Home zone: `z:work`.
- Allowed source zones: `z:work` and `z:private`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Capability surface:
  - `aws.s3.read` gates S3 bucket listing, object listing, and object download.
  - `aws.s3.write` gates S3 object upload and deletion.
  - `aws.ec2.read` gates EC2 instance listing.
  - `aws.ec2.write` gates EC2 start, stop, and terminate.
  - `aws.lambda.read` gates Lambda function listing.
  - `aws.lambda.write` gates Lambda invocation.
  - `aws.iam.read` gates STS identity and AWS health.
- The connector does not persist credentials, account IDs, ARNs, bucket names, object bodies, instance IDs, Lambda names, or provider responses beyond process memory.
- The manifest required capability list covers network primitives; operation entries and runtime introspection carry the operation-specific `aws.*` capability IDs.

## Tier B Live Sandbox Verification

The connector's gated sandbox proof is `rch exec -- cargo test -p fcp-aws --test live_verification -- --nocapture`. It is skipped unless `FCP_LIVE_SANDBOX=1` and the AWS sandbox environment is complete.

Required live inputs:

- `AWS_SANDBOX_ACCESS_KEY_ID`
- `AWS_SANDBOX_SECRET_ACCESS_KEY`
- `AWS_SANDBOX_REGION`
- `AWS_SANDBOX_ACCOUNT_ID`
- `AWS_SANDBOX_BUCKET`
- `FCP_SANDBOX_RUN_NAMESPACE`

`AWS_SANDBOX_REGION` must match the sandbox bucket region. `AWS_SANDBOX_SESSION_TOKEN` is optional for temporary credentials.

Use a dedicated AWS sandbox account and a dedicated S3 bucket. The credentials must be scoped to put, list, get, and delete only synthetic objects under the verification prefix. The proof performs an invalid-signature list request as the auth-denial path, then performs a reversible `put_object` -> `list_objects` -> `delete_object` -> post-delete `get_object` lifecycle.

The live test emits `AWS_LIVE_SANDBOX_JSONL` evidence with the command, git revision when provided through `FCP_LIVE_GIT_REVISION`, sandbox class, call ceiling, cleanup result, hashed account/bucket/object identifiers, and skip/failure reason. It never logs access keys, session tokens, account IDs, bucket names, object keys, object bodies, provider resource IDs, or raw provider error bodies.

## Network And Runtime Invariants

- Production hosts are under `*.amazonaws.com`, with `s3.amazonaws.com`, `ec2.amazonaws.com`, `lambda.amazonaws.com`, and `sts.amazonaws.com` called out by operation constraints.
- Production port: `443`.
- TLS and SNI are required for live provider traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, and IP literals for live operations.
- Runtime loopback endpoint overrides are test-only.
- Runtime request timeout: `30_000 ms`.
- Manifest `aws.s3.get_object` total timeout is `120_000 ms`; other operations use `30_000 ms`.
- Maximum response bytes are `104_857_600` for S3 get object; `10_485_760` for inventory lists and Lambda invoke; and `1_048_576` for S3/EC2 mutations, STS identity, and AWS health. Inventory aggregation additionally caps total bytes across all pages.
- Sandbox profile is `strict`, with `128 MB` memory, `25%` CPU, `30_000 ms` wall-clock timeout, no exec, and no ptrace.
- The connector does not open listeners and does not implement FCP subscriptions.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `aws.s3.read` | List buckets, list objects, and download object bodies. |
| `aws.s3.write` | Upload and delete S3 objects. |
| `aws.ec2.read` | List EC2 instances visible to the credentials. |
| `aws.ec2.write` | Start, stop, and terminate EC2 instances. |
| `aws.lambda.read` | List Lambda functions. |
| `aws.lambda.write` | Invoke Lambda functions. |
| `aws.iam.read` | Read STS caller identity and credential-health status. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `aws.s3.list_buckets` | `GET /` | `aws.s3.read` | `Safe` | `Low` | `None` | Reads bucket inventory for the current account. |
| `aws.s3.list_objects` | `GET /{bucket}?list-type=2` | `aws.s3.read` | `Safe` | `Low` | `None` | Reads object keys and metadata in one bucket. |
| `aws.s3.get_object` | `GET /{bucket}/{key}` | `aws.s3.read` | `Safe` | `Low` | `None` | Downloads one object body and response metadata. |
| `aws.s3.put_object` | `PUT /{bucket}/{key}` | `aws.s3.write` | `Risky` | `Medium` | `BestEffort` | Creates or overwrites object content; retries can create additional object versions. |
| `aws.s3.delete_object` | `DELETE /{bucket}/{key}` | `aws.s3.write` | `Dangerous` | `High` | `BestEffort` | Deletes object content; retries can create additional delete markers. |
| `aws.ec2.describe_instances` | `Action=DescribeInstances` | `aws.ec2.read` | `Safe` | `Low` | `None` | Reads instance inventory. |
| `aws.ec2.start_instance` | `Action=StartInstances` | `aws.ec2.write` | `Risky` | `Medium` | `Strict` | Starts a stopped instance and can incur compute cost. |
| `aws.ec2.stop_instance` | `Action=StopInstances` | `aws.ec2.write` | `Risky` | `Medium` | `Strict` | Stops a running instance and can interrupt workloads. |
| `aws.ec2.terminate_instance` | `Action=TerminateInstances` | `aws.ec2.write` | `Dangerous` | `Critical` | `Strict` | Terminates an instance and can permanently destroy attached state. |
| `aws.lambda.list_functions` | `GET /2015-03-31/functions` | `aws.lambda.read` | `Safe` | `Low` | `None` | Reads Lambda function inventory. |
| `aws.lambda.invoke` | `POST /2015-03-31/functions/{function_name}/invocations` | `aws.lambda.write` | `Risky` | `Medium` | `BestEffort` | Executes provider code with caller-supplied payload. |
| `aws.sts.get_caller_identity` | `Action=GetCallerIdentity` | `aws.iam.read` | `Safe` | `Low` | `None` | Reads identity for the configured credentials. |
| `aws.health` | STS identity probe | `aws.iam.read` | `Safe` | `Low` | `Strict` | Confirms AWS authentication through an admitted STS call. |

## Explicit Non-Goals

The current implementation does not include:

- IAM role assumption, profile discovery, SSO, IMDS, or automatic credential refresh
- AWS SDK integration or response coverage for operations outside the thirteen-operation catalog
- CloudFormation, CloudWatch, EventBridge, SNS, SQS, DynamoDB, IAM, KMS, RDS, ECS, EKS, or broader AWS APIs
- S3 multipart upload, range reads, object version selection, bucket creation/deletion, or ACL/policy management
- EC2 reboot, run instances, volume/snapshot mutation, security group mutation, or termination-protection controls
- Lambda function creation, update, deletion, logs, aliases, layers, event sources, or async result tracking
- durable inventory storage, local cache, or account-wide scanner state
- public-zone invocation or inbound callback listeners
- connector-local credential vaulting

These are excluded on purpose:

- The useful first slice is bounded S3/EC2/Lambda/STS operations with clear capability gates.
- S3 delete, EC2 stop, EC2 terminate, Lambda invoke, and S3 put can mutate production state and need dedicated staging resources for proof.
- Full AWS service coverage belongs in separate beads with service-specific auth, parser, and safety contracts.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration, handshake state, runtime readiness, request counters, and error counters
- auth mode as static keys, static keys with session token, or host-managed SigV4
- endpoint override status for S3, EC2, Lambda, and STS
- SigV4 active status
- custom STS self-check target status
- manifest hash, verification script, artifact root, rerun commands, and operator guidance
- operation metadata, schemas, capability IDs, risk levels, safety tiers, idempotency, and approval modes
- simulation denial for missing readiness, missing handshake, unknown operations, or invalid bound capability tokens

The deterministic integration evidence is anchored on WireMock and connector-local tests covering:

- lifecycle health, doctor, self-check, introspection, and shutdown
- SigV4 header construction and redaction
- custom endpoint overrides
- S3 delete, EC2 terminate, Lambda list, and STS identity dispatch
- risky and dangerous operation metadata
- bound capability-token verification
- input-required validation paths
- default endpoint health behavior and custom STS readiness
- retryable and terminal provider error mapping

## Source Notes

- `connectors/aws/src/connector.rs` defines configuration parsing, lifecycle handlers, capability mapping, doctor/self-check details, simulation, operation dispatch, and introspection metadata.
- `connectors/aws/src/client.rs` defines endpoint selection, local/host SigV4 transport, bounded HTTP retry dispatch, inventory pagination, request builders, and provider error classification.
- `connectors/aws/src/protocol.rs` decodes native AWS response envelopes into normalized connector outputs.
- `connectors/aws/src/types.rs` defines credentials and normalized S3, EC2, Lambda, STS, and health response types.
- `connectors/aws/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, and operation AI hints.
- `connectors/aws/tests/integration.rs` covers deterministic WireMock operation behavior, SigV4 headers, lifecycle diagnostics, capability verification, and metadata evidence.

## Verification Bundle

The tracked verification bundle is `scripts/e2e/aws_connector_verification.sh`.

The verification surface captures:

- runtime operation contract tests
- deterministic WireMock AWS API coverage
- auth redaction, endpoint override, lifecycle, doctor, self-check, risky mutation, dangerous operation, and introspection tests
- formatting, check, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use disposable AWS credentials scoped to the exact read and mutation operations under test.
- Use a staging AWS account, LocalStack stack, or signing proxy for routine proof.
- Configure `sts_base_url` to a custom verification endpoint when expecting `self_check` to run.
- Keep S3 buckets, EC2 instances, and Lambda functions synthetic for live verification.

**Dedicated environment**:

- Use staging-only buckets, objects, instances, Lambda functions, and STS endpoints.
- Never run S3 delete or EC2 terminate against production resources during verification.
- Do not use operator personal credentials for automated mutation tests.
- Treat account IDs, ARNs, bucket names, instance IDs, function names, object keys, and non-public endpoint override URLs as sensitive.

**Redaction rules**:

- Redact `access_key_id`, `secret_access_key`, `session_token`, `Authorization`, `X-Amz-Security-Token`, and full signed URL/query material.
- Redact object bodies, object keys when sensitive, account IDs, ARNs, instance IDs, function names, provider payloads, and provider error bodies.
- Verification output should use operation names, endpoint classes, status/error classes, result counts, and redacted identity/account markers.

**Common remediation**:

- If configuration fails, check `region`, the selected auth mode, service-specific reference bindings, the host launch proxy endpoint, and endpoint override URL policy.
- If `doctor` reports missing endpoint overrides, decide whether the run is a live AWS run or a deterministic stub run.
- If direct-mode `self_check` degrades with `self_check_unsupported_on_default_sts`, set `sts_base_url` to a verification endpoint. In host mode, use an admitted `aws.health` invocation with an STS credential reference.
- If AWS reports `SignatureDoesNotMatch`, check system clock skew, region, service name, host, path, query, and payload hash.
- If `invoke` returns a capability error, ensure the bound token capability and operation list match the requested operation.
- If an AWS success response fails decoding, verify that the endpoint returns the native AWS envelope for the operation. Normalized JSON fixtures are not a substitute for native XML or Lambda envelopes.
- If a mutation reports an uncertain outcome, inspect the object's version/delete markers or function result before issuing another request; the connector deliberately does not suggest automatic replay.

**Rerun commands**:

- `scripts/e2e/aws_connector_verification.sh`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-aws-e2e cargo check -p fcp-aws --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-aws-e2e cargo test -p fcp-aws --test integration -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-aws-e2e cargo clippy -p fcp-aws --all-targets --no-deps -- -D warnings`
- `ubs connectors/aws/README.md`
