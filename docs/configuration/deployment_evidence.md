# Signed deployment evidence for live admission

The host can use fresh, authenticated observations from a trusted health
attester when deciding whether an operation's deployment tier is available.
This supplies the existing deployment classifier with evidence for one
configured zone. It does not grant a capability, issue an execution approval,
elect a connector owner, or create a lease.

Without valid evidence, live admission remains in `Evaluation` mode.
`Risky`, `Dangerous`, and `Critical` operations continue to be refused there.
`Safe` operations remain subject to their other checks. The webhook receiver's
`webhook.events.ingest` remains `Risky`; enabling its HTTP route alone does
not satisfy this deployment gate.

The attester is an explicit trust boundary. Its signing key must belong to
an integration that actually observes current peer health, lease-coordinator
reachability, and revocation freshness for the selected zone. A configured
peer list, a desired deployment size, or possession of a signing key does not
establish those facts. This feature authenticates external health evidence;
it does not implement automatic mesh discovery or health probing.

## Configure the verifier

Set `FCP_HOST_DEPLOYMENT_EVIDENCE_CONFIG_FILE` to a JSON configuration file
before starting the host. For example:

```json
{
  "subject": "host:hooks-1",
  "zone_id": "z:work",
  "attester_public_key_hex": "<64 hexadecimal characters for the trusted Ed25519 public key>",
  "evidence_file": "/run/fcp/deployment-evidence.json"
}
```

Replace the key placeholder with the actual public key, and choose the subject,
zone, and file path for this host. The attester's private signing key stays
with the health integration. The host receives only its pinned public key.
Startup rejects an attester key equal to the configured capability or approval
verification key. Health attestation must have an independent signing authority.

```bash
export FCP_HOST_DEPLOYMENT_EVIDENCE_CONFIG_FILE=/etc/fcp/deployment-evidence.json
```

The subject is a 1-256 byte label using ASCII letters, digits, or `._:/-`.
It identifies this deployment and does not
replace the host's mesh identity or the connector's instance identity.
The configured zone applies only to invocations in that zone; other zones
remain in `Evaluation` mode. Static settings and the trusted key are fixed
for the running process. Changing them requires a host restart and new
evidence for that process.

Both configuration and evidence files are limited to 64 KiB and must be
regular files. `evidence_file` must be absolute. Use trusted local storage
and a publisher-controlled directory. Unknown configuration fields, malformed
configuration, invalid keys, and invalid binding settings reject startup.
They do not silently disable a partially configured verifier.

The evidence file may be absent at startup so the attester can first obtain
the running process's challenge. Missing evidence keeps the deployment gate
closed for higher-tier operations. If the configuration environment variable
is absent, the host remains in `Evaluation` for this admission boundary.

## Obtain the running process challenge

Read the protected host endpoint:

| Item | Value |
| --- | --- |
| Method and route | `GET /rpc/admin/deployment/challenge` |
| Authentication | Existing host admin bearer credential and `X-FCP-Zone: z:owner` |
| Purpose | Bind evidence to the configured subject, zone, and this host process |

The challenge contains:

| Field | Meaning |
| --- | --- |
| `schema_version` | Protocol version `1` |
| `subject` | Configured deployment subject |
| `zone_id` | Configured execution zone |
| `challenge` | Fresh 32-byte process nonce from the operating system |
| `attesting_kid` | Identity of the pinned attester key |
| `max_lifetime_ms` | Maximum evidence lifetime, `30000` ms |
| `max_future_skew_ms` | Maximum allowed future issuance skew, `5000` ms |

The nonce is regenerated on every host process start. Evidence for a previous
process, another subject, or another zone cannot activate this process.
Keep this administrative route out of a public webhook reverse-proxy mapping.
When evidence verification is not configured, the protected endpoint returns
`503` instead of inventing a challenge or signing identity.

## Sign observations and publish them

The signing integration must deserialize the current challenge, make its own
fresh observations, and sign them with the pinned attester's private key.
The existing `MeshQuorumSignals` fields have these meanings:

| Field | Required observation |
| --- | --- |
| `healthy_peer_count` | Healthy mesh peers, excluding this host itself |
| `lease_coordinator_reachable` | Whether the configured lease coordinator can currently be reached; `None` is for deployments that do not use one |
| `revocation_snapshot_fresh` | Whether revocation state for this zone satisfies the deployment's freshness requirements |

The verifier pins the existing `FCP_V2_MIN_HEALTHY_MESH_PEERS` setting at startup,
using the same parser as boot policy. The default is one healthy peer; the
configured threshold must be positive. This is an environment setting, not an
additional JSON field. Changing it requires a host restart. Only authenticated,
fresh observations are classified against that threshold: a threshold of three
still refuses a signed observation of two healthy peers.

The classifier also refuses stale revocation state and a configured but
unreachable lease coordinator. An authenticated unhealthy observation remains
`Evaluation`; a valid signature does not turn unhealthy observations into an
active deployment.

Use the library signing helper so the inner quorum signature and the outer
domain-separated envelope have the correct encoding:

```rust
use fcp_host::SignedDeploymentEvidence;

let evidence = SignedDeploymentEvidence::sign(
    &challenge,
    observed_signals,
    next_generation,
    observed_at_ms,
    expires_at_ms,
    &health_signing_key,
)?;
let encoded = serde_json::to_vec(&evidence)?;
```

Here `observed_signals` comes from the health integration's actual measurements,
not a hardcoded healthy fixture. `observed_at_ms` and `expires_at_ms` are Unix
timestamps in milliseconds. Choose a short validity period that does not
exceed the challenge's 30-second ceiling, and renew before expiry. This is a
library integration point; no `fwc` signing or issuance command is added.

The signed envelope binds `schema_version`, `subject`, `zone_id`, `challenge`,
`generation`, `issued_at_ms`, `expires_at_ms`, and the signed quorum observation.
Publish the serialized envelope to a temporary file beside `evidence_file`,
then atomically replace the configured file. A partial or missing file cannot
be used as a reason to retain older authority.

Generations start at `1` and increase for each newly issued snapshot. The host
retains a process-local generation floor. Reusing a generation is allowed only
for the identical signed content while it remains valid; changing observations
or extending expiry requires a higher generation. A later authenticated
unhealthy snapshot also advances that floor, preventing replay of an older
healthy snapshot. A restart gets a new challenge, so the previous process's
evidence remains unusable even though its in-memory floor is gone.

An authenticated higher generation advances the floor even when its time
interval is expired or too far in the future. Two different authenticated
snapshots at the same generation invalidate that generation until a newer one
arrives. Correct publishing mistakes with a higher generation rather than
rewriting the same generation. Forged or differently bound snapshots cannot
advance the generation floor. A process-monotonic clock floor prevents a
backward or stalled wall clock from extending previously observed validity.

## Admission and failure behavior

The host reads and verifies the bounded evidence file at live admission and
again before final dispatch. It checks the pinned key, both signatures, subject,
zone, process nonce, generation, and issuance/expiry bounds. It does not cache
an older healthy result as fallback when the current file is missing, unreadable,
malformed, forged, stale, or rolled back.

The regular-file reads are synchronous and intended for trusted local storage.
Their elapsed time counts against the invocation budget, but a deadline cannot
preempt a blocked filesystem read. Byte bounds and Unix nonblocking-open flags
do not establish a hard storage-latency bound.

Evidence expiration or an unhealthy replacement before dispatch can therefore
refuse a request that passed an earlier check. This is admission control; it
does not promise to reverse an operation that has already started or to monitor
that operation continuously after dispatch.

The following checks remain independent and mandatory where applicable:

- Signed capability, principal, operation, resource, zone, and current instance.
- Current capability revocations and normal zone policy.
- Execution approvals, holder proofs, and other operation-specific evidence.
- Singleton-writer ownership, lease sequence fences, and durable lease checks.
- Network constraints, runtime admission, and the original invocation deadline.

A health attester's single signature is not a substitute for an operation's
quorum signatures or a quorum-issued connector lease. Configuring this feature
does not establish durable connector storage.

Boot truth-precedence selection still starts from `Evaluation` observations
and uses the existing boot-policy settings. Evidence for the post-start process
challenge affects per-invocation admission only. It cannot satisfy an earlier
`refuse-boot` decision or automatically transition the running process to V2
truth precedence. See the [single-host runbook](../runbooks/v2_mesh_native_single_host.md)
for boot behavior and [mesh invocation routing](../runbooks/mesh_invoke_routing.md)
for authenticated routing and executor checks.

For generic HTTP webhook intake, deployment or authority refusal becomes the
adapter's redacted `503` response. Use authenticated operator diagnostics to
investigate the actual cause; public callbacks receive no attester, capability,
or policy details. See the [webhook ingress guide](webhook_receiver_ingress.md)
for the complete route and receiver setup.

## Verification scope

Focused verification commands are:

```bash
rch exec -- cargo test -p fcp-host --lib deployment_evidence::
rch exec -- cargo test -p fcp-host --bin fcp-host deployment_evidence_runtime_
```

The implementation adds signature, freshness, process/zone binding, generation,
and live-admission regressions. Added tests do not establish that an external
observer reports correct health or that a production mesh has been deployed.
Record actual command output when running the relevant library and host tests;
the documentation itself is not a passing result or live deployment proof.
