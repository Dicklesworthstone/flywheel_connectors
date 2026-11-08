# Generic webhook HTTP ingress

`fcp-host` can receive provider callbacks at `POST /webhooks/{*path}` and
forward them to the `webhook.events.ingest` operation of the webhook receiver.
The host supplies the FCP authority and applies its normal invocation checks.
The receiver independently verifies the provider signature before committing
an ordinary event to its bounded encrypted local store or answering a Slack
URL-verification challenge. Production event acceptance requires configured
durable storage; the host returns HTTP `202` only after the receiver's committed
invoke result.

This is an opt-in host adapter, tracked by `flywheel_connectors-whing1`.
The connector still opens no socket. Its explicit local storage preserves
endpoints, secrets, events, replay identities, and polling cursors across
reopening. Canonical mesh replication and state handoff remain incomplete.
There is no live-provider verification claim for this adapter.

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

### Manifest authority and runtime lifecycle

The host freezes the validated manifest's state model in the published
registry generation. The managed connector ID must exactly match the
manifest's `connector.id`; a configured state-model hint that conflicts with
the manifest is rejected. The receiver's declared `singleton_writer` model
therefore selects the existing HRW ownership and request-fencing checks even
when no legacy configuration hint names that model.

Runtime admission follows that state evidence:

- Native warm pools require a validated manifest whose effective model is
  `stateless`, including the manifest schema default when the state section
  is omitted.
  Singleton-writer, CRDT, and unknown-state registrations cannot start
  independent warm-pool replicas.
- Explicitly stateful WASI registrations are refused.
- Legacy on-demand registrations whose state remains unknown retain their
  existing supported path. Unknown state does not establish statelessness
  or authorize a warm pool.

Normal explicit inventory preview/apply compares manifest content, so an edit
at the same path is detected. Active policy changes only through publication
of a validated generation. Unreadable or invalid manifest evidence, and
attempts to downgrade or remove established stateful policy, fail closed
while retaining the published generation.

Hot replacement of an executable native process, warm pool, or WASI runtime
is refused before spawning a replacement when either the current or proposed
state model is singleton-writer or CRDT. This includes same-model configuration
and manifest edits: the active runtime remains intact until verified quiescence
and canonical state handoff are supported. An inert
`UnavailableNativeProxyOnly` registration has no live connector state and may
accept otherwise valid same-model metadata or manifest updates. Explicit
connector removal and shutdown have separate lifecycle semantics.

These checks do not issue a signed canonical writer lease. The configured HRW
sequence remains request-fencing input checked by normal admission. The
receiver's encrypted local journal now preserves endpoint secrets, retained
events, replay identities, and cursors across reopening, but canonical mesh
persistence and state transfer remain incomplete.

## Configure receiver persistence

Configure the receiver's own storage before enabling production event intake.
This is separate from the host HTTP binding below:

```json
{
  "public_base_url": "https://hooks.example.test/webhooks",
  "storage": {
    "directory": "/var/lib/fcp/webhook-receiver-work",
    "key_file": "/run/secrets/fcp-webhook-state.key",
    "zone": "z:work",
    "initialize": false
  }
}
```

Use a private state directory and a separate protected key file containing
32 random raw bytes or 64 hexadecimal characters. Set `initialize` to `true`
only when creating a new empty store, and use the default `false` for every
recovery. Initialization refuses existing state; recovery refuses missing,
corrupt, truncated, or incorrectly scoped state without resetting it.

The stored zone and exact public base URL must match later configuration and
handshake. The host-provided `zone_dir` is a cache and is not used for this
durable store. Endpoint creation/rotation/deletion and ordinary event ingest
synchronize their records before success. A failed or uncertain storage write
fences data access until validated recovery, so it cannot generate a successful
provider acknowledgment.

The default connector configuration refuses ordinary event ingest without
durable storage. Development fixtures may explicitly opt into
`allow_ephemeral_ingest: true`; their accepted events, replay protection, and
cursors disappear on reset. Signed Slack URL-verification challenges remain
available without event persistence because they do not create delivery state.
See [Durable Storage Configuration](../../connectors/webhook-receiver/README.md#durable-storage-configuration)
for lifecycle, recovery, and local-storage limits.

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

Capabilities with a `holder_node` requirement are supported through an
explicit operator-owned signing key, as described below. Bearer capabilities
remain supported when no holder key is configured. Both forms retain the
required receiver instance binding and least-privilege operation/resource
constraints.

Normal expiry, revocation, principal, resource, zone, policy, and instance
checks still apply. Parsing the configured token does not establish authority.
Provider request headers never supply this capability or replace its scope.

### Holder-bound capabilities

For a capability that names a `holder_node`, add this optional field to the
host binding configuration:

```json
"holder_key_file": "/etc/fcp/webhook-ingress.holder.key"
```

The path must be absolute. The file contains the holder's Ed25519 secret key as
exactly 32 raw bytes or 64 hexadecimal digits, with optional surrounding
whitespace for hexadecimal text. It must be a regular file no larger than
128 bytes. Provision the actual node key whose public key appears in the
owner-authenticated mesh membership for the token's holder; the adapter does
not generate or enroll an identity. Keep this file readable only by the
operator and host process. Inline signing material is not a configuration
option.

Each admitted callback reloads both the capability and configured key. A
holder-bound token needs a nonempty token JTI and a usable key. A key configured
for a bearer token, a missing or malformed key, or an incomplete holder
signing context returns `503` before the provider body is read. The files may
be absent at startup so the operator can provision authority for the prepared
receiver instance. A failed refresh never reuses a previous token or signer.
Temporary file buffers and parsed signing keys are cleared when dropped.

The adapter signs the canonical FCP holder proof over the fresh host-generated
request ID, the fixed `webhook.events.ingest` operation, and the current
capability's JTI. Token claims select this signing context only: the ordinary
host path verifies the capability and resolves the holder's public key from
current owner-authenticated mesh membership, with another holder check before
dispatch. A wrong or retired node key cannot gain authority by producing a
well-formed signature. Provider headers and bodies cannot choose the holder,
signing key, JTI, or proof.

Publish replacement capability and key files by atomic replacement of each
file. Coordinate node-key changes with the deployment's signed membership
update; a mismatched token/key/membership combination is refused rather than
falling back. Capability renewal with the same holder still produces proofs
bound to the new token JTI. This signing authority does not mint a lease or
replace the existing singleton-writer ownership and configured-fence checks.

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

The connector, zone, public base, limits, and capability/key-file paths are
fixed at startup. Changes to those settings require a host restart. After process
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

Capability/key-file loading, body collection, and invocation share one
deadline. The invocation receives only the remaining budget. Capability,
holder-key, and deployment evidence files use synchronous bounded regular-file
reads on trusted local storage. Elapsed read time counts against that budget, but the deadline cannot
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
digest recognizes previously accepted ordinary event payloads even when the HTTP
attempt has a new host identity. It confirms prior acceptance without creating
another event or reserving the retry's delivery identity. Slack URL verification has the control-exchange
behavior described below.

Ordinary event replies contain only `accepted`, `status_code`, and `reason_code`.
An accepted event delivery returns:

```json
{
  "accepted": true,
  "status_code": 202,
  "reason_code": "accepted"
}
```

| HTTP status | Meaning |
| --- | --- |
| `200` | Previously accepted authenticated content was confirmed with `reason_code: "already_accepted"`, or authenticated Slack URL verification completed with only `challenge`. |
| `202` | The receiver verified and committed this delivery to its configured encrypted local store. Explicit development mode may use volatile storage instead. |
| `400`, `414`, `431` | Malformed or ambiguous request, excessive request target, or excessive headers. |
| `401` | Provider signature validation failed. |
| `403` | The receiver's source policy denied the delivery. |
| `404` | The receiver endpoint is unknown; an entirely disabled host route also returns HTTP 404. |
| `405`, `415` | Unsupported method or content type. |
| `409` | New authenticated content conflicts with an already accepted public delivery ID. |
| `413` | The body exceeds an active host or receiver limit. |
| `429` | Host concurrent admission or receiver rate capacity is exhausted. |
| `502`, `503` | Receiver response failure or unavailable host/receiver authority. Public replies omit internal diagnostics. |
| `504` | The adapter's request budget expired. |
| `507` | Receiver replay capacity is exhausted; operator recovery is required. |

A valid retry after a lost acknowledgment returns
`{"accepted":true,"status_code":200,"reason_code":"already_accepted"}`.
Every retry still passes current authority, source, freshness, signature, body,
and rate checks. The receiver checks that its live durable writer still owns the
committed journal before confirming acceptance; missing, replaced, or fenced
storage fails closed. Retained authenticated identities survive event-body
eviction and durable reopening. This acknowledgment adds no event or journal
record and does not imply that an external consumer has processed the delivery.
Ordinary `202` responses confirm local durable acceptance when storage is configured.

### Slack Events API URL verification

Configure the receiver endpoint with provider `slack` and its actual signing
secret. A Slack `url_verification` request passes the same FCP capability,
resource, zone, instance, deployment, source, body, and rate checks as ordinary
intake. The receiver verifies the fresh `v0` signature over the original raw
body before interpreting its challenge; the deprecated payload token is never
an authentication fallback.

A successful verification returns HTTP `200` with JSON containing exactly:

```json
{"challenge": "the-authenticated-challenge"}
```

The challenge must be a nonempty string of at most `4096` UTF-8 bytes and
contain no control characters. Its exact value, including ordinary whitespace,
is preserved. The host returns only this bounded field from a successful,
request-bound canonical receiver response. Other payload fields, tokens,
event metadata, capability data, and receiver diagnostics are not reflected.

URL verification is a control exchange. It creates no retained business event
and reserves no event replay identity, so fresh signed registration retries
can succeed. Ordinary Slack event deliveries keep their existing `202`
acknowledgment; a fresh signed retry of accepted content earns `200`, and new
authenticated content conflicting with a retained public ID returns `409`.
Provider headers alone cannot select
this reply: a generic or GitHub endpoint receives no Slack verification behavior
from a challenge-shaped payload.

See Slack's [URL-verification contract](https://docs.slack.dev/reference/events/url_verification/).
Twilio flows that require TwiML and arbitrary provider-specific response
formats remain unsupported. This exchange does not provide automatic
subscription provisioning or every interactive callback workflow.

## Consuming accepted events

Use the authenticated FCP operation `webhook.events.poll` to consume deliveries
for a specific endpoint. The public HTTP ingress route does not expose event
reads. Begin with `{"endpoint_id":"ep_abc123","start":"earliest"}` to read
retained history or `start: "latest"` to subscribe from the current frontier.
Continue with the returned `next_cursor` and the same endpoint, omitting
`start`. Each page still requires a valid instance-bound `webhook.events.read`
capability authorizing `webhook.events.poll` and the endpoint URL.

Pages are ordered by arrival sequence and bounded by event count and stored
event bytes. Save the returned cursor only after successfully processing the
page. A `410` with `webhook_replay_gap` means unread event bodies were evicted;
`webhook_cursor_expired` means the receiver lifetime changed. Neither outcome
silently skips missing deliveries. Recover explicitly before selecting a new
start position. A `413` means the first unread event exceeds the requested
byte budget; retry the same cursor with a larger budget within the `16 MiB`
maximum. See the [complete replay contract](../../connectors/webhook-receiver/README.md#cursor-based-event-consumption).

Polling preserves redaction and does not delete events or change ingress
deduplication. The configured encrypted store preserves retained event bodies,
replay identities, and cursors across receiver restart. Explicit development
mode with `allow_ephemeral_ingest: true` has no restart guarantee.

## Readiness and verification

The receiver's `health`, `doctor`, and `self_check` continue to report no
connector-owned listener and no verified gateway binding. These diagnostics
cannot attest the host route, TLS proxy, public DNS, or provider registration.
Enabling the host adapter does not silently change those claims.

Focused verification commands are:

```bash
rch exec -- cargo test -p fcp-host --lib webhook_ingress::
rch exec -- cargo test -p fcp-host --bin fcp-host webhook_runtime_
rch exec -- cargo test -p fcp-host --bin fcp-host webhook_holder_
rch exec -- cargo test -p fcp-host --bin fcp-host webhook_ingress_admission_
rch exec -- cargo test -p fcp-host --test webhook_receiver_ingress
rch exec -- cargo test -p fcp-webhook-receiver
```

The shared-module tests cover binding validation, signed-byte preservation,
authority separation, holder-proof binding and rotation, limits, and response
redaction. The runtime tests cover streaming body bounds, deadlines, concurrent
admission, bounded signing-key parsing, token/key replacement, and failures
before dispatch. The integration suite uses the real receiver with signed
FCP capabilities, separate signed endpoint approvals, provider HMACs, and
a real loopback HTTP connection. Its loopback harness exercises shared
translation and receiver verification; it does not replace full host policy
and subprocess integration coverage.

A separate host-admission regression drives the real receiver through the
normal invocation route using a native RPC bridge and a host-first inventory
without `manifest_path`. It exercises the capability, policy, and deployment
boundaries, including holder proofs checked against owner-signed mesh
membership and rejection of wrong keys or proofs reused across requests or
tokens. That fixture does not establish deployment of the checked-in
singleton manifest, HRW ownership, durable lease state, or manifest network
enforcement. Those operational requirements still apply to a manifest-backed
receiver.

These commands describe added verification coverage, not recorded passing
results. Record their actual outputs and any dependency or environment
blockers separately. Live callback proof, durable receiver state, provider
subscription provisioning, and response formats beyond the Slack verification
exchange remain separate work.
