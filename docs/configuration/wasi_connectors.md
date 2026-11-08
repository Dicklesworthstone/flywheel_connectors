# Running FCP connectors as WASI components

The host runs stateless WASI components through the versioned
[`fcp:connector@1.0.0` component contract](../../crates/fcp-sandbox/wit/connector.wit).
The guest receives the complete FCP invocation and returns its own typed result.
A component that exports only `run()` is not an FCP connector and cannot return
a successful invocation merely by exiting successfully.

## Component contract

The component exports `fcp-dispatch(method: string, request: list<u8>) -> list<u8>`.
Each body is one canonical CBOR value, without a JSON-RPC wrapper, schema prefix,
length prefix, or stdout transport. It uses the existing FCP message types:

| Method | Request | Response |
| --- | --- | --- |
| `configure` | Connector configuration object | Configuration result |
| `handshake` | `HandshakeRequest` | `HandshakeResponse` |
| `health` | Empty map | `HealthSnapshot` |
| `invoke` | Complete `InvokeRequest` | `InvokeResponse` |

The handshake must echo the nonce and grant the requested operation capability.
Ready health must include `details.configured = true`,
`details.handshaken = true`, and the guest's actual `details.instance_id`.
The guest owns this identity; the host does not derive it from a caller's token
or pass a requested identity for the guest to adopt.

An invocation response must have `type = "response"` and the original request
ID. Status `ok` requires a result and no error; status `error` requires an error
and no result. A business error is a normal `InvokeResponse`, not a trap or an
extra error envelope. The complete original capability, holder proof, approval
tokens, input, deadline, and idempotency information remain in the request body.

Requests and responses have a 16 MiB transport ceiling. Preparation responses
have a 64 KiB limit; invocation responses also respect the host's operation
response budget. The recipient rejects malformed or noncanonical CBOR,
duplicate map keys, trailing data, and mismatched response identities. Guest
memory, execution fuel, and per-call wall time remain bounded by the admitted
sandbox policy.

The [host component fixture](../../crates/fcp-host/src/bin/fcp-host/wasi_connector/component.wat)
implements this dispatch contract with actual guest state and input-dependent
results. Its adjacent tests supply canonical response fragments and exercise
the normal host prepare and invoke handlers.

## Configure a compute-only component

The managed inventory is a JSON array. For example:

```json
[
  {
    "id": "fcp.compute",
    "binary": "/opt/fcp/compute/connector.wasm",
    "manifest_path": "/opt/fcp/compute/manifest.toml",
    "allowed_zones": ["z:work"],
    "allowed_operations": ["compute.echo"],
    "runtime_network_enforcement": "wasi_sandbox",
    "operation_network_constraints": {
      "compute.echo": {
        "host_allow": [],
        "port_allow": [],
        "require_sni": true,
        "max_response_bytes": 65536
      }
    }
  }
]
```

Two empty allow-lists explicitly deny all egress. Missing per-operation policy
and a policy with only one empty list are refused. Normal strict locality and
canonicalization defaults still apply. Raw WASI sockets remain disabled.

Supply a validated manifest with the same connector ID, the exact operation
and capability, and `connector.state.model = "stateless"`. Its admitted operation
schemas and security attributes drive discovery and policy admission. Its
sandbox resource and filesystem limits configure the guest. Protect and deploy
the component and manifest together; apply a new inventory generation after
changing the manifest. Configure `FCP_HOST_CONNECTORS_FILE`, the trusted
`FCP_HOST_CAPABILITY_PUBLIC_KEY` or `_FILE`, the execution zone policy through
`FCP_HOST_ZONE_POLICIES_FILE`, and `FCP_HOST_ADMIN_BEARER_TOKEN` as for native
connectors. The HTTP host needs the issuer's public verification key only.

## Prepare the instance before issuing its token

Call the protected admin endpoint for the exact operation and zone:

```http
POST /rpc/admin/connectors/fcp.compute/session
Authorization: Bearer <configured-admin-token>
Content-Type: application/json

{"zone_id":"z:work","operation_id":"compute.echo"}
```

The host creates one guest, configures it, handshakes it, and reads its ready
health under the same session lock. A successful response has this shape and
`Cache-Control: no-store`:

```json
{
  "connector_id": "fcp.compute",
  "zone_id": "z:work",
  "operation_id": "compute.echo",
  "instance_id": "<actual-instance-reported-by-the-guest>",
  "protocol_version": "2.0"
}
```

Have the trusted issuer create a capability for this exact instance, zone,
operation, and manifest capability. Use `CapabilityTokenBuilder::target_instance`
or `CapabilityIssuanceRequest.instance_id` with the returned ID. Send the signed
token unchanged in the ordinary `/rpc/invoke` request. Preparation does not
issue a token or bypass normal policy, approval, holder, revocation, quota,
inventory, or deployment checks. The gateway performs its normal unbound
admission, and the selected guest boundary verifies the signed instance binding
before entering guest code.

The host retains a separate session for each `(zone, operation)` pair. Repeating
preparation for a healthy pair returns the same instance; it does not silently
rehandshake it. A different operation or zone requires its own preparation and
instance authority. The sandbox environment and filesystem/network context stay
fixed for that pair. `FCP_REQUEST_ID` is removed from the retained environment;
each actual request ID arrives in its FCP message.

## Failure and resource behavior

Calls to one session are serialized. After waiting for its lock, the host
rechecks current invocation authority immediately before execution. A refusal
before guest execution is recorded as a definite host failure. A trap, timeout,
cancelled execution, malformed response, or wrong response ID retires that guest.
An already selected invocation with no definite response remains
`outcome_unknown`; session retirement is not proof that the operation had no
effects. Inspect the retained invocation record before deciding to repeat work.

Recovery is explicit: prepare the operation again, obtain its new actual
instance ID, and issue new instance-bound authority. The host neither creates a
replacement during invoke nor retries an old request. The old signed token
cannot authorize the replacement. A valid business error preserves the session.
Cancellation while only waiting for the session leaves the current owner alone;
cancellation after guest entry retires only the affected session.

Each connector has at most eight resident operation/zone slots. Empty retired
slots with no owner or waiter can be reclaimed. Healthy sessions are not evicted
to make room; applying a replacement inventory configuration or restarting the
host releases its resident guests. Preparation itself has the existing bounded
admin RPC deadline.

This path currently supports stateless request/response components. Stateful
WASI connectors remain refused until canonical state recovery is integrated.
Guest simulation and native event-consumer routes are not exposed for WASI;
use host preflight for admission inspection. Configured network constraints do
not create guest HTTP imports: mediated provider HTTP calls still need a linked
component host interface. Native connector binaries and existing provider SDK
connectors require a component implementation of this ABI before they can use
this runtime.
