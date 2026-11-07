# V2 Mesh-Native Single-Host Runbook

Use this runbook when fcp-host is configured for V2 mesh-native truth precedence
but the host sees too few healthy mesh peers.

## Recommended Production Setting

After mesh cutover gates are green and the operator has confirmed peer setup,
use:

```bash
FCP_TRUTH_PRECEDENCE_DEFAULT=v2
FCP_V2_INSUFFICIENT_PEERS_BEHAVIOR=refuse-boot
FCP_V2_MIN_HEALTHY_MESH_PEERS=1
```

With zero healthy peers, fcp-host emits
`fcp.host.boot_refused_truth_precedence` and exits with code 78.

To supply authenticated health observations before this decision, configure the
Unix-only [deployment evidence startup exchange](../configuration/deployment_evidence.md#supply-evidence-before-boot-policy-optional).
Set the paired `startup_challenge_file` and `startup_timeout_ms` fields, prepare
the private host-owned directory, and arrange for an independent observer to
read the current process challenge and sign actual health before the listener
starts. Use a new challenge filename on every launch. A configured peer list
alone does not establish healthy peers, and without the startup exchange the
host begins the boot decision with `Evaluation` observations.

The startup wait is bounded by the configured polling timeout. If valid
mesh-active evidence does not arrive, the ordinary insufficient-peer policy
applies. Successful boot still requires fresh evidence at later operation
admission and dispatch; it does not retain permanent deployment authority.

## First-Install Safe Default

Unset `FCP_V2_INSUFFICIENT_PEERS_BEHAVIOR` defaults to `degrade-to-v1`.

```bash
FCP_TRUTH_PRECEDENCE_DEFAULT=v2
```

With zero healthy peers, fcp-host runs effective V1 and emits
`fcp.host.boot_truth_precedence` with
`degraded_from="v2-insufficient-peers"`.

## Intentional Single-Host V2

Use only for test or explicitly accepted single-host V2 deployments:

```bash
FCP_TRUTH_PRECEDENCE_DEFAULT=v2
FCP_V2_INSUFFICIENT_PEERS_BEHAVIOR=explicit-opt-in
```

If `FCP_TRUTH_PRECEDENCE_DEFAULT=v2` is missing, fcp-host exits with code 78.

This opt-in selects truth precedence only. It does not bypass the separate
deployment-evidence, capability, approval, or lease requirements for live
operations.

## Rollback

Run V1 host-first:

```bash
FCP_TRUTH_PRECEDENCE_DEFAULT=v1
unset FCP_V2_DEFAULT_GRADUATED
```

If your supervisor manages environment files, apply the same two changes there
and restart through the supervisor's normal non-destructive service path.

## Recovery

For `refuse-boot` with missing or insufficient startup observations:

1. Check mesh peer health and heartbeat freshness.
2. Verify peer gossip signatures resolve to known `NodeKeyAttestation` records.
3. Confirm `FCP_V2_MIN_HEALTHY_MESH_PEERS` is not set above the intended peer
   count.
4. Check that both startup fields are configured and that the observer reads
   this launch's descriptor before the timeout. It must publish fresh evidence
   for the descriptor's subject, zone, nonce, and pinned signing identity; a
   previous process's signed file cannot satisfy the new launch.
5. Restart fcp-host through the normal service path after peer health recovers,
   with a new challenge filename and the observer ready for that path.

For `degrade-to-v1`, monitor for
`fcp.host.boot_truth_precedence` events with
`degraded_from="v2-insufficient-peers"` and switch to `refuse-boot` once mesh
setup is confirmed.

## Common Failures

`FCP_V2_INSUFFICIENT_PEERS_BEHAVIOR=refus-boot`

Cause: typo. Fix the value to `refuse-boot`. fcp-host exits with code 78.

`FCP_V2_MIN_HEALTHY_MESH_PEERS=0`

Cause: invalid threshold. Use an integer `>= 1`.

`FCP_V2_DEFAULT_GRADUATED=true` plus zero peers and `refuse-boot`

Cause: the graduated flag has highest precedence and requests V2. Either restore
mesh health or unset `FCP_V2_DEFAULT_GRADUATED`.

`cannot create startup challenge; use a new nonexisting file per launch`

Cause: the configured challenge destination already exists or cannot be safely
created. Choose a new filename in the private `0700` host-owned directory and
update the observer's launch configuration. The host deliberately does not
overwrite or remove a previous launch's descriptor. Symlink ancestors, shared
writable directories, and unsafe ownership also reject publication; follow the
path requirements in the deployment evidence guide.

## Redacted Log Examples

```json
{"event_type":"fcp.host.boot_truth_precedence","bead_id":"flywheel_connectors-hr0rr.2.6","actor":"host","redaction_scope":"public","correlation_id":"boot","precedence_default":"v2_requested","effective_model":"V1-host-first","behavior_chosen":"degrade-to-v1","mesh_peer_count":0,"min_healthy_peers":1,"degraded_from":"v2-insufficient-peers"}
```

```json
{"event_type":"fcp.host.boot_refused_truth_precedence","bead_id":"flywheel_connectors-hr0rr.2.6","actor":"host","redaction_scope":"public","correlation_id":"boot","precedence_default":"v2_requested","behavior_chosen":"refuse-boot","mesh_peer_count":0,"min_healthy_peers":1,"exit_code":78}
```
