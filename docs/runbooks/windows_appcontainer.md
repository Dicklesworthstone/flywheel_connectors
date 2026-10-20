# Windows AppContainer, Firewall & `ProfileLevel` Hardening Runbook

**Beads:** `flywheel_connectors-r4qcg.2`, `flywheel_connectors-r4qcg.3`, `flywheel_connectors-r4qcg.4`
**Audience:** Operators and agents validating the Windows sandbox path.

Windows remains `ProcessLimit` unless a connector process is launched through
the AppContainer process-launch path **and** all four required Windows layers
(`AppContainer` profile + `STARTUPINFOEXW` child launch, Job Object limits,
low-integrity primary child token via `CreateProcessAsUserW`, and default-deny
Windows Firewall egress policy enforcement) are active and verified for the run.

## Verify AppContainer, Firewall & `ProfileLevel` Readiness

1. Run the Windows workflow from GitHub Actions or against a Windows `rch`
   worker (such as `wsurf`):

```bash
WINDOWS_APPCONTAINER_RCH_WORKER=wsurf \
WINDOWS_APPCONTAINER_CARGO_TARGET=x86_64-pc-windows-msvc \
WINDOWS_APPCONTAINER_CARGO_TEST_FILTER=windows \
FCP_SANDBOX_WINDOWS_APPCONTAINER_E2E=1 \
FCP_SANDBOX_WINDOWS_FIREWALL_E2E=1 \
FCP_SANDBOX_WINDOWS_HARDENING_E2E=1 \
bash scripts/e2e/windows_appcontainer_process_launch_verification.sh
```

2. Confirm the artifact path. The local script default is
   `artifacts/e2e/windows-appcontainer/<run-id>/`; the GitHub Actions lane may
   place the process-launch bundle under:

```text
artifacts/e2e/windows_appcontainer/<run-id>/
```

3. Inspect `windows_appcontainer_process_launch.jsonl` and `summary.json`.
4. Treat the lane as a skip unless `windows_appcontainer_process_launch.jsonl`
   contains the live `windows_appcontainer_process_launch_e2e`,
   `windows_firewall_policy_enforcement_e2e`, and
   `windows_profile_level_hardening_e2e` records:

```json
{
  "schema_version": "1.0.0",
  "record_type": "windows_appcontainer_process_launch_e2e",
  "bead_id": "flywheel_connectors-r4qcg.2",
  "launch_mechanism": "startup_info_ex_security_capabilities",
  "integrity_level": "low",
  "integrity_enforcement": "low_primary_integrity",
  "sid_present": true,
  "job_object_attached": true,
  "allowed_process_startup": true,
  "denied_user_profile_write": true,
  "denied_user_profile_write_error_mapping": "user_profile_write_denied",
  "redaction_scope": "public",
  "test_status": "passed",
  "fallback_decision": "not_needed",
  "action_result": "launched"
}
```

```json
{
  "schema_version": "1.0.0",
  "record_type": "windows_firewall_policy_enforcement_e2e",
  "bead_id": "flywheel_connectors-r4qcg.3",
  "lifecycle_action": "applied",
  "allow_rule_count": 1,
  "stale_rules_cleaned": true,
  "idempotent_reapply_verified": true,
  "allowed_loopback_connect": true,
  "forbidden_egress_denied": true,
  "cleanup_verified": true,
  "action_result": "enforced_and_cleaned"
}
```

```json
{
  "schema_version": "1.0.0",
  "record_type": "windows_profile_level_hardening_e2e",
  "bead_id": "flywheel_connectors-r4qcg.4",
  "appcontainer_status": "active_verified",
  "job_object_status": "active_verified",
  "integrity_status": "active_verified",
  "firewall_status": "active_verified",
  "allowed_state_write": true,
  "denied_high_integrity_write": true,
  "denied_process_escape": true,
  "firewall_enforced": true,
  "profile_level_verified": true,
  "reported_filter_strength": "profile_level",
  "wasi_fallback_recommended": false,
  "downgrade_on_layer_failure_verified": true,
  "cleanup_verified": true,
  "final_readiness_layer": "profile_level"
}
```

Profile creation by itself is not enough to claim `ProfileLevel`.
When the script runs through `rch`, passing evidence must include a remote
summary in `rch_summary` and `worker_execution_class:"remote"`. The GitHub
Windows lane sets `RCH_BIN=direct`, so its successful live-launch record uses
`cargo_runner:"direct"`, `worker_execution_class:"not_applicable"`, and
`rch_summary:null`. A missing worker fleet is recorded as
`skip_reason:"rch_remote_prerequisite_unavailable"` with `test_status:"skipped"`;
it is useful evidence about the proof lane but not AppContainer readiness.

## Rollback

Rollback means returning to the conservative Windows posture: Job Object limits
only, no live AppContainer process-launch claim.

```powershell
Remove-Item Env:FCP_SANDBOX_WINDOWS_APPCONTAINER -ErrorAction SilentlyContinue
Remove-Item Env:FCP_SANDBOX_WINDOWS_APPCONTAINER_E2E -ErrorAction SilentlyContinue
cargo test -p fcp-sandbox --target x86_64-pc-windows-msvc --features windows-appcontainer windows_appcontainer -- --nocapture
```

The expected result after rollback is a structured skip or
`SkippedInactive` evidence. The final readiness layer must remain
`process_limit`.

## Recovery

When AppContainer launch fails in production or CI:

1. Preserve the JSONL artifact and command output.
2. Check whether `FCP_SANDBOX_WINDOWS_APPCONTAINER=1` was set for the process.
3. Check whether the profile SID was resolved.
4. Confirm the record shows `integrity_level:"low"` and
   `integrity_enforcement:"low_primary_integrity"` for a real launch.
5. Confirm Job Object attachment happened after process creation and before the
   child was resumed.
6. Confirm capability names match
   `docs/architecture/windows_appcontainer_capability_map.md`.

Do not promote Windows readiness to `ProfileLevel` after a failed launch.

## Common Failures

| Error | Cause | Fix |
|---|---|---|
| `windows_appcontainer_not_active_createprocessasuser_path_unwired` | Operator did not opt in to the AppContainer launch path. | Set `FCP_SANDBOX_WINDOWS_APPCONTAINER=1` only for the Windows validation lane. |
| `CreateAppContainerProfile failed` | Windows rejected profile creation or the profile API is unavailable. | Keep the failure artifact and check OS edition, account policy, and profile name validity. |
| `CreateProcessWithTokenW AppContainer launch failed` | Low-integrity child identity creation or launch failed after profile setup. | Treat as fail-closed; preserve the artifact and rerun on a worker with the required Windows process privileges. |
| `DeriveCapabilitySidsFromName(...) failed` | Capability name is invalid for Windows. | Update the capability map and policy compiler together, or deny the FCP capability. |
| `AssignProcessToJobObject(child) failed` | Child process launched but could not receive resource limits. | Treat as fail-closed; do not claim AppContainer enforcement for that run. |
| `rch_remote_prerequisite_unavailable` | The script required remote `rch` execution, but no admissible worker was available. | Keep the structured skip artifact and rerun after the worker fleet recovers or on the Windows Actions lane. |

## Redacted Log Examples

Successful launch:

```json
{"schema_version":"1.0.0","record_type":"windows_appcontainer_process_launch_e2e","bead_id":"flywheel_connectors-r4qcg.2","actor":"host","redaction_scope":"public","correlation_id":"windows-appcontainer-ci","timestamp":"2026-05-10T12:00:00.000Z","cargo_runner":"direct","profile_name_hash":"8d7c...","sid_present":true,"launch_mechanism":"startup_info_ex_security_capabilities","integrity_level":"low","integrity_enforcement":"low_primary_integrity","job_object_attached":true,"allowed_process_startup":true,"denied_user_profile_write":true,"denied_user_profile_write_error_mapping":"user_profile_write_denied","test_status":"passed","worker_execution_class":"not_applicable","fallback_decision":"not_needed","rch_summary":null,"action_result":"launched","final_readiness_layer":"process_limit"}
```

Skipped lane:

```json
{"schema_version":"1.0.0","record_type":"windows_appcontainer_process_launch_e2e","bead_id":"flywheel_connectors-r4qcg.2","actor":"host","redaction_scope":"public","correlation_id":"windows-appcontainer-ci","timestamp":"2026-05-10T12:00:00.000Z","test_status":"skipped","integrity_level":"none","integrity_enforcement":"none","allowed_process_startup":false,"denied_user_profile_write":false,"denied_user_profile_write_error_mapping":null,"worker_execution_class":"local_fallback_refused","fallback_decision":"rch_local_fallback_refused","skip_reason":"rch_remote_prerequisite_unavailable","action_result":"structured_skip","final_readiness_layer":"process_limit"}
```

Denied capability:

```json
{"schema_version":"1.0.0","event_type":"fcp.host.windows.appcontainer.capability_denied","bead_id":"flywheel_connectors-r4qcg.2","actor":"host","redaction_scope":"public","correlation_id":"windows-appcontainer-ci","timestamp":"2026-05-10T12:00:00.000Z","capability_decision":"denied","error_class":"capability_unsupported"}
```

## Manual Profile Cleanup

Use manual cleanup only after confirming the profile name belongs to this FCP
installation and no connector process is using it. Prefer the host crash-recovery
cleanup path when available.

```powershell
# Example only. Replace with the exact fcp-* profile name after confirming scope.
$profileName = "fcp-example-0000000000000000"
$signature = @"
using System;
using System.Runtime.InteropServices;

public static class AppContainerCleanup {
    [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
    public static extern int DeleteAppContainerProfile(string appContainerName);
}
"@
Add-Type -TypeDefinition $signature
$hr = [AppContainerCleanup]::DeleteAppContainerProfile($profileName)
if ($hr -ne 0) {
    throw ("DeleteAppContainerProfile failed: HRESULT 0x{0:x8}" -f $hr)
}
```

If manual cleanup is required, record the profile name hash, reason, operator,
and timestamp in the bead or incident record. Never run broad profile cleanup.

### Manual Firewall Rule Cleanup

Connector firewall rules are prefixed with `fcp-fw-<connector_id_hash>-` and are
normally cleaned up automatically by `WindowsFirewallPolicyGuard::cleanup()` or
`WindowsSandbox::cleanup_firewall_policy()`. To inspect or delete an orphaned
connector rule manually from an elevated command prompt:

```powershell
# Inspect rules for a specific connector hash:
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /f "Name=fcp-fw-<connector_id_hash>-" /d

# Delete a specific rule by exact name:
netsh advfirewall firewall delete rule name="fcp-fw-<connector_id_hash>-tcp-443-<addr_hash>" dir=out
```

## Differences From Linux And macOS

| Platform | Primary sandbox proof | Readiness layer |
|---|---|---|
| Linux | seccomp/Landlock/user namespace depending on profile | `syscall_level` when active |
| macOS | SBPL profile via sandbox APIs | `profile_level` |
| Windows | Job Object limits + AppContainer launch + Low-Integrity primary child token + Windows Firewall egress policy | `profile_level` when all 4 layers are verified via `evaluate_windows_sandbox_readiness` (`process_limit` + `wasi_fallback_recommended: true` if any layer is missing or degraded) |

Windows `evaluate_windows_sandbox_readiness` promotes `reported_filter_strength`
to `profile_level` **only** when `appcontainer_status`, `job_object_status`,
`integrity_status`, and `firewall_status` are all `active_verified`. Any skipped
or degraded layer keeps `reported_filter_strength` at `process_limit` with
`wasi_fallback_recommended: true`.
