# Generic webhook HTTP ingress

`fcp-host` can receive provider callbacks at `POST /webhooks/{*path}` and
forward them to the `webhook.events.ingest` operation of the webhook receiver.
The host supplies the FCP authority and applies its normal invocation checks.
The receiver independently verifies the provider signature before retaining
the event in its bounded in-memory store.

This is an opt-in host adapter, tracked by `flywheel_connectors-whing1`.
The connector still opens no socket. It does not persist endpoints, secrets,
events, or replay identities across restart or reconfiguration. There is no
live-provider verification claim for this adapter.

## Deployment admission and singleton ownership

`webhook.events.ingest` remains a `Risky` operation. The host's deployment gate
refuses it in `Evaluation` mode even when its provider signature and capability
are valid. Configure [signed deployment evidence](deployment_evidence.md) for
the intake zone using a trusted integration that actually observes current
peer health, lease-coordinator reachability, and zone revocation freshness.
Missing, invalid, or stale evidence does not reuse an earlier active result.

The checked-in receiver manifest also declares `singleton_writer`. A
manifest-backed inventory therefore requires one explicit allowed zone, at
least two eligible HRW nodes, and the selected holder for the connector and
zone. The existing host settings are `FCP_HOST_HRW_LEASE_LOCAL_NODE`,
`FCP_HOST_HRW_LEASE_NODES` (comma-separated node IDs), and, when a sequence floor
is configured, `FCP_HOST_HRW_LEASE_CURRENT_SEQ`. The local node must be in the
eligible set. Choose real deployment membership and current lease state;
listing nodes is not evidence that those nodes are healthy.

For a registered singleton receiver, the host HTTP adapter supplies the current
sequence from host-owned routing configuration before ordinary invocation
enforcement. Provider headers and payloads cannot supply that sequence. This
does not elect a holder, mint a lease, or skip ownership, stale-sequence,
durable-lease, capability, policy, or approval checks. Deploy the callback
binding with the receiver's actual ownership and session; endpoint creation
requires its own capability and signed execution approval.

## Configure the host binding

Set `FCP_HOST_WEBHOOK_INGRESS_CONFIG_FILE` to a JSON configuration file before
starting the host with its existing connector inventory and authority settings.
For example, `/etc/fcp/webhook-ingress.json` can contain:

```json
{
  "connector_id": "fcp.webhook-receiver",
  "zone_id": "z:work",
  "public_base_url": "https://hooks.example.test/webhooks",
  "capability_token_file": "/etc/fcp/webhook-ingress.capability.b64",
  "max_body_bytes": 1048576,
  "timeout_ms": 15000,
  "max_in_flight": 8
}
```

Enable that binding in the host environment:

```bash
export FCP_HOST_WEBHOOK_INGRESS_CONFIG_FILE=/etc/fcp/webhook-ingress.json
```

Replace the example hostname and paths with the actual deployment values.
The configuration file is limited to 64 KiB. Unknown fields, malformed JSON,
invalid URLs, and unsupported limits reject startup before connector runtimes
are created. If the environment variable is absent, the host mounts no generic
webhook route.

The binding selects one receiver and one explicit zone for every path under
`/webhooks/`. HTTP callers cannot select another connector, zone, operation,
capability, or approval. The adapter always invokes `webhook.events.ingest`.
It does not provide per-endpoint zone routing.

### Capability file and renewal

`capability_token_file` is required and must be an absolute path. Inline
capability material is not supported by the startup configuration. For each
admitted HTTP attempt, the host reads the current regular file, limited to
32 KiB of UTF-8 base64 text. Its content must be the base64-encoded COSE
capability itself, without a JSON wrapper or raw binary encoding.

The capability file may be absent when the host starts. This allows the
operator to start the receiver, prepare its actual session, issue authority
for the returned instance, and publish the token without another restart.
A missing, unreadable, malformed, expired, revoked, or mismatched token
returns `503`; the adapter does not retain an older token as fallback.

Provision the capability through the deployment's authorization integration for:

- The configured execution zone and receiver.
- Capability `webhook.events.write`.
- Operation `webhook.events.ingest`.
- Resource constraints covering the registered endpoint URLs that may receive
  deliveries.
- The current instance and other constraints required by normal host and
  receiver admission.

The adapter does not create holder proofs. Use a capability without a
`holder_node` requirement, while retaining the required receiver instance
binding and least-privilege operation/resource constraints.

Normal expiry, revocation, principal, resource, zone, policy, and instance
checks still apply. Parsing the configured token does not establish authority.
Provider request headers never supply this capability or replace its scope.

### Prepare authority for the current process

The native-session preparation API is:

| Item | Value |
| --- | --- |
| Method and route | `POST /rpc/admin/connectors/fcp.webhook-receiver/session` |
| Admin authentication | Existing host admin bearer credential and `X-FCP-Zone: z:owner` |
| JSON body | `{"zone_id":"z:work"}` for the example binding |
| Response fields | `connector_id`, `zone_id`, `instance_id`, `protocol_version` |

Use the registered connector ID in the route. This protected call negotiates
the on-demand native process and reads its authenticated health; it returns
the actual instance ID rather than a caller-chosen value. It requires the
connector's configured allowed zones and host capability verification key.
Warm-pool and WASI session preparation are not supported by this endpoint.

The current `fwc session` command records local agent session metadata; it
does not call this endpoint. `fwc capabilities` reports usage and suggestions;
it has no capability-issuance subcommand. Use the protected HTTP preparation
API and the deployment's existing issuer integration. The repository exposes
`HostAdminStateStore::issue_capability_token` and `CapabilityIssuanceRequest`
for issuance and durable recording, but this adapter adds no public or admin
token-minting route.

For an issuer using that library API, the request for one GitHub intake
endpoint has this shape; replace the instance placeholder with the preparation
response and select the deployment's authorized principal:

```json
{
  "connector_id": "fcp.webhook-receiver",
  "capability_id": "webhook.events.write",
  "zone_id": "z:work",
  "instance_id": "<instance_id returned by session preparation>",
  "principal_id": "user:webhook-ingress",
  "operations": ["webhook.events.ingest"],
  "resource_allow": ["https://hooks.example.test/webhooks/github"],
  "ttl_secs": 3600,
  "max_delegation_depth": 0
}
```

Write the issuance response's `token_cbor_b64` string into a restricted-access
temporary file beside the configured capability file, then atomically replace
the configured file. Subsequent admitted callbacks read the new token without
a host restart. Do not expose the raw issuance response in public logs.

The connector, zone, public base, limits, and capability-file path are fixed
at startup. Changes to those settings require a host restart. After process
replacement, reconfiguration, or any change that invalidates the receiver's
instance, prepare the current session and replace the capability file with
newly issued authority. A returned instance is a snapshot, not a lease;
concurrent process replacement can invalidate it before issuance completes.

## Configure and approve receiver endpoints

The receiver's `configure` input must use the same public base as the host:

```json
{
  "public_base_url": "https://hooks.example.test/webhooks"
}
```

Include the deployment's independent `approval_public_key` in that same
configuration when endpoint management is needed. Its format is an array of
32 unsigned bytes containing the trusted Ed25519 approval public key, as
described in the [receiver contract](../../connectors/webhook-receiver/README.md#auth-and-scope-boundary).
The host does not populate this connector setting automatically.

After configuration and the normal private-channel handshake, create each
endpoint through a capability-authorized invocation carrying its signed
execution approval. For example, the input to `webhook.endpoints.create` for
a GitHub endpoint is:

```json
{
  "path": "/github",
  "provider": "github"
}
```

The receiver generates a signing secret when one is omitted and returns it
only in the authorized creation response. Where the provider supplies the
verification secret, pass that actual value in `signing_secret` instead.
Keep secret material out of logs and public callback responses.

| Receiver endpoint path | Provider-facing callback URL | Host request target |
| --- | --- | --- |
| `/github` | `https://hooks.example.test/webhooks/github` | `/webhooks/github` |
| `/billing/stripe` | `https://hooks.example.test/webhooks/billing/stripe` | `/webhooks/billing/stripe` |
| `/twilio` | `https://hooks.example.test/webhooks/twilio` | `/webhooks/twilio` |

The host removes only the `/webhooks` prefix for receiver endpoint lookup.
It constructs the externally signed URL from the configured public base plus
the original raw suffix and query. It never derives that URL from `Host`,
`Forwarded`, or `X-Forwarded-*`.

The public base must be an origin followed by exactly `/webhooks`, without
a trailing slash, userinfo, query, or fragment. Public deployments require
HTTPS. HTTP is accepted only for `localhost` or a literal loopback address
for local operation and tests.

## Proxy and source-address behavior

Use a TLS-terminating reverse proxy to expose only the host's `/webhooks/`
callback route. Host administration and unrelated RPC routes are separate
operator surfaces and should not be included in this public mapping.

Preserve the original path spelling, percent escapes, query order, content
type, signature headers, and body bytes. Do not remove the `/webhooks` prefix
at the proxy, reserialize JSON, rewrite form fields, or normalize a Twilio
signature URL. The host rejects ambiguous path forms, malformed escapes,
dot segments, encoded path separators, and duplicate header names.

The source address comes only from the actual accepted TCP connection.
There is no trusted-proxy or forwarded-client-IP mode in this adapter.
Consequently:

- A direct TCP callback uses the provider connection's peer address.
- A reverse-proxied callback uses the proxy's address for receiver source
  allowlists and rate-limit keys. Apply provider-origin IP filtering at the
  proxy when it is required; do not depend on forwarded headers for it.
- All callbacks for an endpoint arriving through one proxy can share its
  receiver rate-limit key.
- A request without a TCP peer address, including Unix-socket transport,
  supplies no source IP. Endpoints requiring a source allowlist reject it.

Provider headers and body fields also cannot replace the FCP principal,
zone, operation, deadline, or approval. The invocation envelope represents
the operator's fixed intake command in the configured zone. Its provenance
retains the public-input taint, with a public-origin payload-receipt step
and the fixed intake command recorded in the provenance chain. The adapter
does not elevate the payload or create approval evidence. Normal host policy
still applies to the command, and the public-input taint prevents this
request from authorizing dangerous operations.

## Resource limits

| Setting or bound | Default | Maximum or rule |
| --- | --- | --- |
| `max_body_bytes` | 1 MiB | 16 MiB; must be positive |
| `timeout_ms` | 15,000 ms | 120,000 ms; must be positive |
| `max_in_flight` | 8 | 64; must be positive |
| Reserved concurrent body capacity | 8 MiB with defaults | `max_body_bytes * max_in_flight` must not exceed 64 MiB |
| Header entries | Fixed | 100, including fields suppressed before dispatch |
| Aggregate header-name/value bytes | Fixed | 32 KiB |
| Raw path and query | Fixed | 8 KiB |

For example, a 16 MiB body limit permits at most four concurrent deliveries.
The joint capacity limit bounds retained raw request bodies; parsed JSON,
FCP serialization, connector state, and allocator overhead are additional.
The receiver's own body, rate, replay, and retention limits remain active.

The adapter admits a delivery before reading its body and rejects excess
concurrency immediately, without a waiter queue. It validates the request
head before collection and bounds streaming or chunked bodies even when
`Content-Length` is absent. Oversized declared bodies are rejected before
collection. Bodies must be UTF-8 for the receiver's raw-body contract.

Capability-file loading, body collection, and invocation share one deadline.
The invocation receives only the remaining budget. Capability and deployment
evidence files use synchronous bounded regular-file reads on trusted local
storage. Elapsed read time counts against that budget, but the deadline cannot
preempt blocked storage. A timeout does not prove that an already admitted
operation had no effect; inspect recent events with an authorized FCP read
when a delivery outcome is uncertain.

## Authentication, acknowledgment, and replay

The adapter supports the receiver's existing provider verification profiles:
generic HMAC, GitHub, Stripe, Slack, and Twilio. JSON and Twilio form bodies
are forwarded unchanged. Twilio JSON keeps the exact query containing its
`bodySHA256`; Twilio form verification uses the receiver's canonical field
rules. See the [signature contract](../../connectors/webhook-receiver/README.md#signature-and-event-id-behavior).

Every HTTP attempt receives fresh host-generated invocation, idempotency,
and delivery identities. Provider delivery-ID headers cannot occupy the
host's idempotency cache or select the receiver's public-ID replay identity.
After signature verification, the receiver's separate authenticated-content
digest rejects previously accepted payloads even when the HTTP attempt has
a new host identity.

Public replies contain only `accepted`, `status_code`, and `reason_code`.
An accepted delivery returns:

```json
{
  "accepted": true,
  "status_code": 202,
  "reason_code": "accepted"
}
```

| HTTP status | Meaning |
| --- | --- |
| `202` | The receiver verified and retained this delivery in its current in-memory store. |
| `400`, `414`, `431` | Malformed or ambiguous request, excessive request target, or excessive headers. |
| `401` | Provider signature validation failed. |
| `403` | The receiver's source policy denied the delivery. |
| `404` | The receiver endpoint is unknown; an entirely disabled host route also returns HTTP 404. |
| `405`, `415` | Unsupported method or content type. |
| `409` | The receiver rejected an already accepted delivery as a duplicate. |
| `413` | The body exceeds an active host or receiver limit. |
| `429` | Host concurrent admission or receiver rate capacity is exhausted. |
| `502`, `503` | Receiver response failure or unavailable host/receiver authority. Public replies omit internal diagnostics. |
| `504` | The adapter's request budget expired. |
| `507` | Receiver replay capacity is exhausted; operator recovery is required. |

A duplicate remains `409`, not a fresh-success acknowledgment. Confirm how
the provider handles that status and use authenticated recent-event reads
for investigation. A `202` does not imply durable queueing, external consumer
processing, or persistence across restart.

This first adapter returns a minimal acknowledgment, not provider-specific
response content. Slack URL-verification challenges and Twilio flows that
require TwiML responses are not implemented. Signature support alone does
not establish that every subscription or interactive callback workflow is
ready for live use.

## Readiness and verification

The receiver's `health`, `doctor`, and `self_check` continue to report no
connector-owned listener and no verified gateway binding. These diagnostics
cannot attest the host route, TLS proxy, public DNS, or provider registration.
Enabling the host adapter does not silently change those claims.

Focused verification commands are:

```bash
rch exec -- cargo test -p fcp-host --lib webhook_ingress::
rch exec -- cargo test -p fcp-host --bin fcp-host webhook_runtime_
rch exec -- cargo test -p fcp-host --bin fcp-host webhook_ingress_admission_
rch exec -- cargo test -p fcp-host --test webhook_receiver_ingress
rch exec -- cargo test -p fcp-webhook-receiver
```

The shared-module tests cover binding validation, signed-byte preservation,
authority separation, limits, and response redaction. The runtime tests
cover streaming body bounds, deadlines, concurrent admission, and failures
before dispatch. The integration suite uses the real receiver with signed
FCP capabilities, separate signed endpoint approvals, provider HMACs, and
a real loopback HTTP connection. Its loopback harness exercises shared
translation and receiver verification; it does not replace full host policy
and subprocess integration coverage.

A separate host-admission regression drives the real receiver through the
normal invocation route using a native RPC bridge and a host-first inventory
without `manifest_path`. It exercises the capability, policy, and deployment
boundaries. That fixture does not establish deployment of the checked-in
singleton manifest, HRW ownership, durable lease state, or manifest network
enforcement. Those operational requirements still apply to a manifest-backed
receiver.

These commands describe added verification coverage, not recorded passing
results. Record their actual outputs and any dependency or environment
blockers separately. Live callback proof, durable receiver state, provider
subscription provisioning, and provider-specific response handling remain
separate work.
