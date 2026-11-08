# FCP Environment Variables

This page documents operator-facing environment variables whose values affect
host startup, truth precedence, and mesh-native cutover behavior.

## Truth Precedence And V2 Mesh-Native Boot

Env-var precedence for the V2 single-host guard is:

1. `FCP_V2_DEFAULT_GRADUATED`
2. `FCP_TRUTH_PRECEDENCE_DEFAULT`
3. `FCP_V2_INSUFFICIENT_PEERS_BEHAVIOR`
4. documented defaults

### `FCP_TRUTH_PRECEDENCE_DEFAULT`

Accepted values:

- `v1`, `v1-host-first`, `v1_host_first`, `host-first`, `host_first`
- `v2`, `v2-mesh-native`, `v2_mesh_native`, `mesh-native`, `mesh_native`

Unset defaults to V1 for fcp-host boot selection until
`FCP_V2_DEFAULT_GRADUATED=true` is explicitly set. `v2` opts into V2
mesh-native truth precedence, subject to the insufficient-peer behavior below.

### `FCP_V2_INSUFFICIENT_PEERS_BEHAVIOR`

Accepted values:

- `degrade-to-v1` (default)
- `refuse-boot`
- `explicit-opt-in`

`degrade-to-v1` is the safest first-install behavior when the host cannot see
enough healthy mesh peers. It is not a compatibility shim. `refuse-boot` exits
with code 78 when V2 is requested without enough healthy peers. `explicit-opt-in`
allows insufficient-peer V2 only when `FCP_TRUTH_PRECEDENCE_DEFAULT=v2` is also
set.

### `FCP_V2_DEFAULT_GRADUATED`

Accepted values:

- true: `1`, `true`, `yes`, `on`
- false: `0`, `false`, `no`, `off`

When true, fcp-host requests V2 even if `FCP_TRUTH_PRECEDENCE_DEFAULT=v1` is
present. This flag is reserved for the future graduated default after cutover
gates are green.

### `FCP_V2_MIN_HEALTHY_MESH_PEERS`

Accepted value: integer `>= 1`.

Default: `1`.

The count is exclusive of self. Zero peers means the host cannot distinguish an
active mesh from an isolated single host.

### `FCP_TRUTH_PRECEDENCE_ACCEPT_DEGRADED_SINGLE_HOST`

Legacy evaluation variable from the earlier V2 cutover prototype. New fcp-host
boot behavior is controlled by `FCP_V2_INSUFFICIENT_PEERS_BEHAVIOR` and
`FCP_TRUTH_PRECEDENCE_DEFAULT=v2`.

## Canonical Connector-State Store Authentication

Unlike the process-wide startup settings above, these values belong to a
connector's managed inventory `env` map. They authenticate read-only canonical
store access for state explanation, durable lease evidence, and the
flush-before-yield barrier.

| Store | Host-prefixed key | Connector-prefixed alias |
|-------|-------------------|--------------------------|
| Canonical objects | `FCP_HOST_CONNECTOR_STATE_OBJECT_MAC_KEY` | `FCP_CONNECTOR_STATE_OBJECT_MAC_KEY` |
| Canonical symbols | `FCP_HOST_CONNECTOR_STATE_SYMBOL_MAC_KEY` | `FCP_CONNECTOR_STATE_SYMBOL_MAC_KEY` |

Each value must encode exactly 32 bytes as 64 hexadecimal digits. Optional
`hex:` and `0x` prefixes and surrounding whitespace are accepted. If both
aliases for a store are present, they must decode to the same key. Empty,
malformed, and conflicting values fail static inventory validation.

Use the key already configured on the corresponding store's writer. These
keys are separate from `FCP_HOST_CONNECTOR_STATE_OBJECT_ID_KEY` /
`FCP_CONNECTOR_STATE_OBJECT_ID_KEY`; no key is implicitly derived or reused.
A configured MAC refuses unkeyed V1 envelopes. Omitting the MAC permits
existing unkeyed stores but cannot read authenticated V2 envelopes. Failed
authentication never falls back to an unkeyed read, and inspection never
rewrites or migrates the store.

See [authenticated canonical state inspection](../runbooks/connector_state_externalization.md#inspect-authenticated-canonical-stores)
for inventory examples, storage paths, and failure behavior.
