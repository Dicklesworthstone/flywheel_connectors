//! Windows sandbox implementation using `AppContainer` and Job Objects.
//!
//! # Enforcement Layers
//!
//! 1. **`AppContainer`**: Child-process isolation with
//!    capability-based access when launched through
//!    [`WindowsSandbox::spawn_appcontainer_process`]
//! 2. **Job Objects**: Resource limits (memory, CPU, process count) — the
//!    only mechanism active today
//! 3. **Integrity Levels**: Low-integrity child launches when the policy requests
//!    `windows_low_integrity`
//! 4. **Firewall Rules** (roadmap): Network isolation (loopback only for
//!    Network Guard IPC)
//!
//! # Parity with Linux and macOS
//!
//! The Windows implementation reports
//! [`FilterStrength::ProcessLimit`](crate::FilterStrength::ProcessLimit),
//! which is the coarsest tier. No syscall filter (Linux seccomp-bpf) and
//! no named-operation profile (macOS SBPL) is in place. Enforcement is
//! limited to the job object's `ActiveProcessLimit`, `JobMemoryLimit`,
//! and `PerProcessUserTimeLimit` unless the host uses the Windows-only
//! `AppContainer` spawn entrypoint. A connector that stays inside those
//! budgets can invoke any Win32/NT API the process integrity level
//! allows. Connectors requiring the full strict-profile guarantee MUST
//! run under [`WasiRuntime`](crate::WasiRuntime) (no host syscalls
//! reach the kernel from WASI guests) until the `AppContainer`, integrity,
//! firewall, and readiness children under bead `flywheel_connectors-r4qcg`
//! are all proven end to end.
//!
//! # `AppContainer`
//!
//! `AppContainer` provides a low-privilege sandbox similar to Windows Store apps:
//! - Separate SID with no default access to user resources
//! - Capability-based permissions (files, network, etc.)
//! - Network isolation by default (requires explicit capability)
//!
//! # Job Objects
//!
//! Job objects enforce resource limits:
//! - Memory commit limits
//! - CPU rate limits
//! - Process/thread limits
//! - UI restrictions

#![cfg(target_os = "windows")]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(clippy::upper_case_acronyms)]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;
use std::time::Duration;

use fcp_manifest::NetworkConstraints;
use tracing::{debug, info, warn};

use crate::sandbox::{
    CompiledPolicy, Sandbox, SandboxError, WindowsAppContainerCleanupDecision,
    WindowsAppContainerCreateOutcome, WindowsAppContainerEvidence,
    WindowsAppContainerLifecycleAction, WindowsAppContainerLifecycleReport,
    WindowsAppContainerProcessLaunchEvidence, WindowsAppContainerProcessLaunchMechanism,
    WindowsAppContainerProfile, WindowsAppContainerProfileApi, WindowsFirewallLifecycleAction,
    WindowsFirewallPlanStatus, WindowsFirewallPolicyApi, WindowsFirewallPolicyEvidence,
    WindowsFirewallPolicyPlan, WindowsFirewallPolicyReport, WindowsFirewallRuleApplyOutcome,
    WindowsFirewallRuleCleanupOutcome, WindowsFirewallRuleSpec, WindowsIntegrityLifecycleAction,
    WindowsIntegrityOperationMode, WindowsIntegrityPolicyEvidence, WindowsIntegrityPolicyReport,
    WindowsIntegrityTokenApiResult, WindowsIntegrityTokenCleanupDecision,
    WindowsSandboxReadinessReport, apply_windows_firewall_policy, cleanup_windows_firewall_policy,
    evaluate_windows_sandbox_readiness, plan_windows_firewall_policy,
    plan_windows_integrity_policy, prepare_windows_appcontainer_lifecycle,
};

// ============================================================================
// Windows API Types
// ============================================================================

type HANDLE = *mut std::ffi::c_void;
type BOOL = i32;
type DWORD = u32;
type HRESULT = i32;
type LPCWSTR = *const u16;
type LPWSTR = *mut u16;
type PSID = *mut std::ffi::c_void;
type SIZE_T = usize;
type DWORD_PTR = usize;

const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;
const FALSE: BOOL = 0;
const S_OK: HRESULT = 0;
const HRESULT_ERROR_ALREADY_EXISTS: HRESULT = -2_147_024_713;
const ERROR_INSUFFICIENT_BUFFER: DWORD = 122;

// Job object limits
const JOB_OBJECT_LIMIT_PROCESS_MEMORY: DWORD = 0x0100;
const JOB_OBJECT_LIMIT_JOB_MEMORY: DWORD = 0x0200;
const JOB_OBJECT_LIMIT_ACTIVE_PROCESS: DWORD = 0x0008;
const JOB_OBJECT_LIMIT_PROCESS_TIME: DWORD = 0x0002;
const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: DWORD = 0x2000;

// Job object extended limit information class
const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: DWORD = 9;

// Token integrity levels
const SECURITY_MANDATORY_LOW_RID: DWORD = 0x1000;
const SECURITY_MANDATORY_MEDIUM_RID: DWORD = 0x2000;
// Token information class
const TOKEN_INTEGRITY_LEVEL: DWORD = 25;
const SECURITY_IMPERSONATION: DWORD = 2;
const TOKEN_PRIMARY: DWORD = 1;

// Process creation flags
const CREATE_SUSPENDED: DWORD = 0x0000_0004;
const EXTENDED_STARTUPINFO_PRESENT: DWORD = 0x0008_0000;
const RESUME_THREAD_FAILED: DWORD = DWORD::MAX;
const WAIT_OBJECT_0: DWORD = 0;
const WAIT_TIMEOUT: DWORD = 0x0000_0102;
const WAIT_FAILED: DWORD = DWORD::MAX;

// ProcThreadAttributeValue(9, FALSE, TRUE, FALSE).
const PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES: DWORD_PTR = 0x0002_0009;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowsIntegrityLevel {
    Low,
    Medium,
}

impl WindowsIntegrityLevel {
    const fn from_policy(policy: &CompiledPolicy) -> Self {
        if policy.platform_flags.windows_low_integrity {
            Self::Low
        } else {
            Self::Medium
        }
    }

    const fn mandatory_rid(self) -> DWORD {
        match self {
            Self::Low => SECURITY_MANDATORY_LOW_RID,
            Self::Medium => SECURITY_MANDATORY_MEDIUM_RID,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowsChildIntegrityEnforcement {
    InheritedProcess,
    LowPrimaryIntegrity,
}

impl WindowsChildIntegrityEnforcement {
    const fn for_level(level: WindowsIntegrityLevel) -> Self {
        match level {
            WindowsIntegrityLevel::Low => Self::LowPrimaryIntegrity,
            WindowsIntegrityLevel::Medium => Self::InheritedProcess,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::InheritedProcess => "inherited_process",
            Self::LowPrimaryIntegrity => "low_primary_integrity",
        }
    }

    const fn create_process_api(self) -> &'static str {
        match self {
            Self::InheritedProcess => "CreateProcessW",
            Self::LowPrimaryIntegrity => "CreateProcessAsUserW",
        }
    }
}

// ============================================================================
// Windows Sandbox
// ============================================================================

/// Windows sandbox using `AppContainer` and Job Objects.
#[derive(Debug)]
pub struct WindowsSandbox {
    /// Job object handle (if created).
    job_handle: Option<HANDLE>,
    /// Whether `AppContainer` is available.
    appcontainer_available: bool,
}

// SAFETY: Windows HANDLE values are opaque kernel-managed identifiers. This
// type stores and closes them but never dereferences them as pointers, so
// moving or sharing the wrapper across threads does not violate memory safety.
unsafe impl Send for WindowsSandbox {}
// SAFETY: See the Send justification above; shared references do not enable
// aliasing unsafety because HANDLEs are passed back to the OS by value.
unsafe impl Sync for WindowsSandbox {}

impl WindowsSandbox {
    /// Create a new Windows sandbox.
    #[must_use]
    pub fn new() -> Self {
        let appcontainer_available = check_appcontainer_available();

        if appcontainer_available {
            info!(
                env = FCP_SANDBOX_WINDOWS_APPCONTAINER_ENV,
                "AppContainer opt-in enabled; callers may use the STARTUPINFOEX process launch entrypoint"
            );
        } else {
            warn!(
                env = FCP_SANDBOX_WINDOWS_APPCONTAINER_ENV,
                "AppContainer not active (br-3hrw3 fail-closed default); enforcement is job-objects + integrity-level + firewall only. \
                 Set the env var to 1 only when using the dedicated STARTUPINFOEX AppContainer launch path."
            );
        }

        Self {
            job_handle: None,
            appcontainer_available,
        }
    }

    /// Whether `AppContainer` is *actually active* for this process.
    ///
    /// Pre-br-3hrw3 the sandbox unconditionally claimed `AppContainer`
    /// availability even though no dedicated child-process launch path
    /// existed; this getter exposes the post-fix truth so conformance
    /// tests and observability surfaces can assert against it.
    #[must_use]
    pub const fn appcontainer_active(&self) -> bool {
        self.appcontainer_available
    }

    /// Derive the `AppContainer` profile metadata for this policy.
    fn appcontainer_profile(
        policy: &CompiledPolicy,
    ) -> Result<WindowsAppContainerProfile, SandboxError> {
        let connector_seed = windows_appcontainer_connector_seed(policy);
        policy.windows_appcontainer_profile(&connector_seed)
    }

    /// Create or resolve the `AppContainer` profile when the operator has enabled the path.
    fn prepare_appcontainer_profile(
        &self,
        policy: &CompiledPolicy,
    ) -> Result<WindowsAppContainerLifecycleReport, SandboxError> {
        let profile = Self::appcontainer_profile(policy)?;
        let mut api = NativeWindowsAppContainerApi;
        let report =
            prepare_windows_appcontainer_lifecycle(profile, self.appcontainer_available, &mut api)?;

        if !self.appcontainer_available {
            debug!(
                appcontainer_profile = %report.profile.name,
                capabilities = ?report.profile.capabilities,
                skip_reason = ?report.skip_reason,
                "AppContainer profile resolved but not created because AppContainer is not active"
            );
            return Ok(report);
        }

        info!(
            appcontainer_profile = %report.profile.name,
            capabilities = ?report.profile.capabilities,
            lifecycle_action = ?report.action,
            "Prepared Windows AppContainer profile"
        );
        Ok(report)
    }

    /// Launch a child process in a Windows `AppContainer` and attach it to a job object.
    ///
    /// This entrypoint is separate from [`Sandbox::apply_to_command`] because
    /// `std::process::Command` cannot carry the `STARTUPINFOEX` attribute list
    /// required for `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`.
    pub fn spawn_appcontainer_process(
        &self,
        program: &Path,
        args: &[&OsStr],
        policy: &CompiledPolicy,
    ) -> Result<WindowsAppContainerChild, SandboxError> {
        self.emit_integrity_policy_evidence(
            policy,
            WindowsIntegrityOperationMode::StartupInfoExChild,
        );
        if !self.appcontainer_available {
            return Err(SandboxError::ApplyFailed(
                "windows AppContainer process launch unavailable: \
                 windows_appcontainer_not_active_createprocessasuser_path_unwired"
                    .into(),
            ));
        }

        let report = self.prepare_appcontainer_profile(policy)?;
        if !report.sid_present {
            return Err(SandboxError::ApplyFailed(
                "windows AppContainer process launch unavailable: profile SID was not resolved"
                    .into(),
            ));
        }
        let integrity_level = WindowsIntegrityLevel::from_policy(policy);
        let integrity_enforcement = WindowsChildIntegrityEnforcement::for_level(integrity_level);

        let appcontainer_sid = derive_appcontainer_sid(&report.profile.name)?;
        let mut capabilities = DerivedCapabilitySids::new(&report.profile.capabilities)?;
        let mut security_capabilities = SECURITY_CAPABILITIES {
            AppContainerSid: appcontainer_sid.as_ptr(),
            Capabilities: capabilities.as_mut_ptr(),
            CapabilityCount: capabilities.count(),
            Reserved: 0,
        };

        let mut attributes = ProcThreadAttributeList::new(1)?;
        attributes.update_security_capabilities(&mut security_capabilities)?;

        let job = OwnedHandle::new(Self::create_job_object(policy)?);
        let mut command_line = build_windows_command_line(program, args);
        let application_name = to_wide_os_str(program.as_os_str());
        let mut startup_info = STARTUPINFOEXW::with_attribute_list(attributes.as_mut_ptr())?;
        let child_identity = if integrity_level == WindowsIntegrityLevel::Low {
            Some(Self::duplicate_current_process_identity_for_child(
                integrity_level,
            )?)
        } else {
            None
        };
        let process_info = Self::create_suspended_appcontainer_child(
            &application_name,
            &mut command_line,
            &mut startup_info,
            child_identity.as_ref(),
            integrity_enforcement,
        )?;

        let process_handle = OwnedHandle::new(process_info.hProcess);
        let thread_handle = OwnedHandle::new(process_info.hThread);

        let assigned = unsafe { AssignProcessToJobObject(job.as_raw(), process_handle.as_raw()) };
        if assigned == FALSE {
            unsafe {
                TerminateProcess(process_handle.as_raw(), 1);
            }
            return Err(SandboxError::SyscallFailed(format!(
                "AssignProcessToJobObject(child) failed: {}",
                get_last_error()
            )));
        }

        let resumed = unsafe { ResumeThread(thread_handle.as_raw()) };
        if resumed == RESUME_THREAD_FAILED {
            unsafe {
                TerminateProcess(process_handle.as_raw(), 1);
            }
            return Err(SandboxError::SyscallFailed(format!(
                "ResumeThread(AppContainer child) failed: {}",
                get_last_error()
            )));
        }

        let launch_evidence = WindowsAppContainerProcessLaunchEvidence::from_lifecycle(
            &windows_appcontainer_connector_seed(policy),
            &report,
            WindowsAppContainerProcessLaunchMechanism::StartupInfoExSecurityCapabilities,
            true,
            "launched",
            Some(process_info.dwProcessId),
        )
        .with_integrity_enforcement(integrity_level.as_str(), integrity_enforcement.as_str());
        if let Ok(jsonl) = launch_evidence.to_jsonl_line() {
            debug!(evidence_jsonl = %jsonl, "Windows AppContainer process launched");
        }

        Ok(WindowsAppContainerChild {
            process_handle: process_handle.into_raw(),
            thread_handle: thread_handle.into_raw(),
            job_handle: job.into_raw(),
            process_id: process_info.dwProcessId,
            integrity_level,
            integrity_enforcement,
        })
    }

    fn create_suspended_appcontainer_child(
        application_name: &[u16],
        command_line: &mut [u16],
        startup_info: &mut STARTUPINFOEXW,
        child_identity: Option<&OwnedHandle>,
        integrity_enforcement: WindowsChildIntegrityEnforcement,
    ) -> Result<PROCESS_INFORMATION, SandboxError> {
        let mut process_info = PROCESS_INFORMATION::default();
        let created = unsafe {
            if let Some(child_identity) = child_identity {
                CreateProcessAsUserW(
                    child_identity.as_raw(),
                    application_name.as_ptr(),
                    command_line.as_mut_ptr(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    FALSE,
                    EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED,
                    ptr::null_mut(),
                    ptr::null(),
                    std::ptr::from_mut(startup_info).cast(),
                    &mut process_info,
                )
            } else {
                CreateProcessW(
                    application_name.as_ptr(),
                    command_line.as_mut_ptr(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    FALSE,
                    EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED,
                    ptr::null_mut(),
                    ptr::null(),
                    std::ptr::from_mut(startup_info).cast(),
                    &mut process_info,
                )
            }
        };

        if created == FALSE {
            return Err(SandboxError::SyscallFailed(format!(
                "{} AppContainer launch failed: {}",
                integrity_enforcement.create_process_api(),
                get_last_error()
            )));
        }

        Ok(process_info)
    }

    /// Create and configure a job object.
    fn create_job_object(policy: &CompiledPolicy) -> Result<HANDLE, SandboxError> {
        // Create job object
        let job = unsafe { CreateJobObjectW(ptr::null_mut(), ptr::null()) };
        if job.is_null() {
            return Err(SandboxError::SyscallFailed(format!(
                "CreateJobObject failed: {}",
                get_last_error()
            )));
        }

        // Configure limits
        let mut limit_info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();

        // Memory limits
        let mem_limit = usize::try_from(policy.memory_limit_bytes).unwrap_or(usize::MAX);
        limit_info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
        limit_info.JobMemoryLimit = mem_limit;

        limit_info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        limit_info.ProcessMemoryLimit = mem_limit;

        // Process limit (deny_exec)
        if policy.deny_exec {
            limit_info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
            limit_info.BasicLimitInformation.ActiveProcessLimit = 1;
        }

        // CPU time limit
        let nanos = policy.wall_clock_timeout.as_nanos();
        let cpu_limit_100ns = i64::try_from(nanos / 100).unwrap_or(i64::MAX);
        limit_info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_TIME;
        limit_info.BasicLimitInformation.PerProcessUserTimeLimit = cpu_limit_100ns;

        // Kill on close
        limit_info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

        // Apply limits
        let result = unsafe {
            SetInformationJobObject(
                job,
                JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                std::ptr::from_ref(&limit_info).cast::<std::ffi::c_void>(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as DWORD,
            )
        };

        if result == FALSE {
            unsafe {
                CloseHandle(job);
            }
            return Err(SandboxError::SyscallFailed(format!(
                "SetInformationJobObject failed: {}",
                get_last_error()
            )));
        }

        info!(
            memory_mb = policy.memory_limit_bytes / (1024 * 1024),
            deny_exec = policy.deny_exec,
            "Created job object with limits"
        );

        Ok(job)
    }

    /// Assign current process to job object.
    fn assign_to_job(job: HANDLE) -> Result<(), SandboxError> {
        let current_process = unsafe { GetCurrentProcess() };

        let result = unsafe { AssignProcessToJobObject(job, current_process) };

        if result == FALSE {
            return Err(SandboxError::SyscallFailed(format!(
                "AssignProcessToJobObject failed: {}",
                get_last_error()
            )));
        }

        debug!("Assigned process to job object");
        Ok(())
    }

    fn open_current_process_identity(
        desired_access: DWORD,
        operation: &'static str,
    ) -> Result<OwnedHandle, SandboxError> {
        let mut token: HANDLE = ptr::null_mut();
        let current_process = unsafe { GetCurrentProcess() };
        let result = unsafe { OpenProcessToken(current_process, desired_access, &mut token) };

        if result == FALSE {
            return Err(SandboxError::SyscallFailed(format!(
                "OpenProcessToken({operation}) failed: {}",
                get_last_error()
            )));
        }

        Ok(OwnedHandle::new(token))
    }

    fn allocate_integrity_sid(level: WindowsIntegrityLevel) -> Result<OwnedSid, SandboxError> {
        let mut sid: PSID = ptr::null_mut();
        let authority = SID_IDENTIFIER_AUTHORITY {
            Value: [0, 0, 0, 0, 0, 16],
        };

        let result = unsafe {
            AllocateAndInitializeSid(
                &authority,
                1,
                level.mandatory_rid(),
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                &mut sid,
            )
        };

        if result == FALSE {
            return Err(SandboxError::SyscallFailed(format!(
                "AllocateAndInitializeSid({}) failed: {}",
                level.as_str(),
                get_last_error()
            )));
        }

        Ok(OwnedSid(sid))
    }

    fn apply_integrity_level_to_identity(
        token: HANDLE,
        level: WindowsIntegrityLevel,
        operation: &'static str,
    ) -> Result<(), SandboxError> {
        let sid = Self::allocate_integrity_sid(level)?;
        let label = TOKEN_MANDATORY_LABEL {
            Label: SID_AND_ATTRIBUTES {
                Sid: sid.as_ptr(),
                Attributes: SE_GROUP_INTEGRITY,
            },
        };

        let result = unsafe {
            SetTokenInformation(
                token,
                TOKEN_INTEGRITY_LEVEL,
                std::ptr::from_ref(&label).cast::<std::ffi::c_void>(),
                std::mem::size_of::<TOKEN_MANDATORY_LABEL>() as DWORD + GetLengthSid(sid.as_ptr()),
            )
        };

        if result == FALSE {
            return Err(SandboxError::SyscallFailed(format!(
                "SetTokenInformation(TokenIntegrityLevel {}, {operation}) failed: {}",
                level.as_str(),
                get_last_error()
            )));
        }

        Ok(())
    }

    fn duplicate_current_process_identity_for_child(
        level: WindowsIntegrityLevel,
    ) -> Result<OwnedHandle, SandboxError> {
        let source = Self::open_current_process_identity(
            TOKEN_DUPLICATE | TOKEN_QUERY,
            "integrity child source",
        )?;
        let mut child_token: HANDLE = ptr::null_mut();
        let duplicated = unsafe {
            DuplicateTokenEx(
                source.as_raw(),
                TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT,
                ptr::null_mut(),
                SECURITY_IMPERSONATION,
                TOKEN_PRIMARY,
                &mut child_token,
            )
        };
        if duplicated == FALSE {
            return Err(SandboxError::SyscallFailed(format!(
                "DuplicateTokenEx(integrity child identity) failed: {}",
                get_last_error()
            )));
        }

        let child_token = OwnedHandle::new(child_token);
        Self::apply_integrity_level_to_identity(
            child_token.as_raw(),
            level,
            "integrity child identity",
        )?;
        Ok(child_token)
    }

    /// Set the current process integrity level for the legacy in-process path.
    fn set_current_process_integrity_level(
        level: WindowsIntegrityLevel,
    ) -> Result<(), SandboxError> {
        let token = Self::open_current_process_identity(
            TOKEN_ADJUST_DEFAULT,
            "current process integrity level",
        )?;
        Self::apply_integrity_level_to_identity(
            token.as_raw(),
            level,
            "current process integrity level",
        )?;

        info!(level = level.as_str(), "Set process integrity level");

        Ok(())
    }

    /// Emit Windows Firewall readiness evidence for network isolation.
    fn configure_firewall(policy: &CompiledPolicy) {
        let connector_seed = windows_appcontainer_connector_seed(policy);
        let application_path = std::env::current_exe()
            .unwrap_or_else(|_| std::path::PathBuf::from("current-process-unavailable"));
        let plan = match plan_windows_firewall_policy(
            &connector_seed,
            &application_path,
            policy.block_direct_network,
            None,
        ) {
            Ok(plan) => plan,
            Err(error) => {
                warn!(
                    error = %error,
                    "Windows firewall policy planning failed; no firewall rules were installed"
                );
                return;
            }
        };
        let action = match plan.status {
            WindowsFirewallPlanStatus::DirectNetworkAllowed => {
                WindowsFirewallLifecycleAction::SkippedDirectNetworkAllowed
            }
            WindowsFirewallPlanStatus::ConstraintsUnavailable => {
                WindowsFirewallLifecycleAction::NotInstalledMissingNetworkConstraints
            }
            WindowsFirewallPlanStatus::NoEgress => WindowsFirewallLifecycleAction::PlannedNoEgress,
            WindowsFirewallPlanStatus::HostAllowRequiresNetworkGuard => {
                WindowsFirewallLifecycleAction::SkippedHostAllowRequiresNetworkGuard
            }
            WindowsFirewallPlanStatus::IpAllowRules
            | WindowsFirewallPlanStatus::IpAllowRulesWithHostConstraints => {
                WindowsFirewallLifecycleAction::PlannedOnly
            }
        };
        let evidence =
            WindowsFirewallPolicyEvidence::from_skipped_plan(plan, action, "not_attempted");
        if let Ok(jsonl) = evidence.to_jsonl_line() {
            debug!(evidence_jsonl = %jsonl, "Windows firewall policy evidence");
        }

        match evidence.plan_status {
            WindowsFirewallPlanStatus::ConstraintsUnavailable => {
                warn!(
                    skip_reason = ?evidence.skip_reason,
                    "Windows firewall rules not installed: operation-level network constraints are not available in the current sandbox apply path"
                );
            }
            WindowsFirewallPlanStatus::HostAllowRequiresNetworkGuard => {
                warn!(
                    skip_reason = ?evidence.skip_reason,
                    "Windows firewall hostname allowlists require Network Guard DNS/SNI enforcement before rules can be installed"
                );
            }
            _ => {
                debug!(
                    plan_status = ?evidence.plan_status,
                    action = ?evidence.lifecycle_action,
                    "Windows firewall policy planning completed without OS rule installation"
                );
            }
        }
    }

    /// Emit redaction-safe Windows integrity readiness evidence for the selected launch path.
    fn emit_integrity_policy_evidence(
        &self,
        policy: &CompiledPolicy,
        operation: WindowsIntegrityOperationMode,
    ) {
        let plan = plan_windows_integrity_policy(
            &windows_appcontainer_connector_seed(policy),
            policy.platform_flags.windows_low_integrity,
            operation,
            self.appcontainer_available,
        );
        let evidence = WindowsIntegrityPolicyEvidence::planned_only(plan);
        if let Ok(jsonl) = evidence.to_jsonl_line() {
            debug!(evidence_jsonl = %jsonl, "Windows integrity policy evidence");
        }
        if let Some(skip_reason) = evidence.skip_reason {
            warn!(
                operation = ?evidence.operation,
                skip_reason,
                "Windows low-integrity token setup not active for this launch path"
            );
        }
    }

    /// Apply operation-level Windows Firewall egress rules for a connector binary.
    ///
    /// # Errors
    ///
    /// Returns an error if the plan is invalid or the native Windows Firewall API
    /// rejects rule installation.
    pub fn apply_firewall_policy(
        &self,
        program: &Path,
        policy: &CompiledPolicy,
        constraints: Option<&NetworkConstraints>,
    ) -> Result<WindowsFirewallPolicyReport, SandboxError> {
        let connector_seed = windows_appcontainer_connector_seed(policy);
        let plan = plan_windows_firewall_policy(
            &connector_seed,
            program,
            policy.block_direct_network,
            constraints,
        )?;
        let mut api = NativeWindowsFirewallApi;
        let report = apply_windows_firewall_policy(plan, &mut api)?;
        let evidence = WindowsFirewallPolicyEvidence::from_report(&report);
        if let Ok(jsonl) = evidence.to_jsonl_line() {
            debug!(evidence_jsonl = %jsonl, "Windows firewall policy applied");
        }
        Ok(report)
    }

    /// Remove Windows Firewall egress rules previously installed for a policy plan.
    ///
    /// # Errors
    ///
    /// Returns an error if the native Windows Firewall API fails to remove a rule.
    pub fn cleanup_firewall_policy(
        &self,
        plan: WindowsFirewallPolicyPlan,
    ) -> Result<WindowsFirewallPolicyReport, SandboxError> {
        let mut api = NativeWindowsFirewallApi;
        let report = cleanup_windows_firewall_policy(plan, &mut api)?;
        let evidence = WindowsFirewallPolicyEvidence::from_report(&report);
        if let Ok(jsonl) = evidence.to_jsonl_line() {
            debug!(evidence_jsonl = %jsonl, "Windows firewall policy cleaned up");
        }
        Ok(report)
    }

    /// Evaluate consolidated Windows sandbox readiness and `ProfileLevel` promotion
    /// for a launched child process and its firewall policy report.
    #[must_use]
    pub fn evaluate_readiness(
        &self,
        policy: &CompiledPolicy,
        appcontainer_report: &WindowsAppContainerLifecycleReport,
        child: Option<&WindowsAppContainerChild>,
        firewall_report: &WindowsFirewallPolicyReport,
    ) -> WindowsSandboxReadinessReport {
        let connector_seed = windows_appcontainer_connector_seed(policy);
        let integrity_plan = plan_windows_integrity_policy(
            &connector_seed,
            policy.platform_flags.windows_low_integrity,
            WindowsIntegrityOperationMode::StartupInfoExChild,
            self.appcontainer_available,
        );
        let integrity_report = match child {
            Some(child) if child.integrity_level == WindowsIntegrityLevel::Low => {
                WindowsIntegrityPolicyReport {
                    plan: integrity_plan,
                    action: WindowsIntegrityLifecycleAction::AppliedLowIntegrityChildToken,
                    token_api_result: WindowsIntegrityTokenApiResult::TokenPrepared,
                    step_order: vec![
                        "integrity_level_decision",
                        "open_process_token",
                        "duplicate_primary_token",
                        "allocate_integrity_sid",
                        "set_token_integrity_level",
                    ],
                    cleanup: WindowsIntegrityTokenCleanupDecision::DropSourceAndChildTokens,
                    skip_reason: None,
                }
            }
            Some(_) => WindowsIntegrityPolicyReport {
                plan: integrity_plan,
                action: WindowsIntegrityLifecycleAction::SkippedMediumIntegrity,
                token_api_result: WindowsIntegrityTokenApiResult::NotAttempted,
                step_order: vec!["integrity_level_decision"],
                cleanup: WindowsIntegrityTokenCleanupDecision::None,
                skip_reason: None,
            },
            None => WindowsIntegrityPolicyReport {
                skip_reason: integrity_plan.unsupported_reason,
                plan: integrity_plan,
                action: if self.appcontainer_available {
                    WindowsIntegrityLifecycleAction::PlannedLowIntegrityChildToken
                } else {
                    WindowsIntegrityLifecycleAction::RejectedAppContainerInactive
                },
                token_api_result: WindowsIntegrityTokenApiResult::NotAttempted,
                step_order: vec!["integrity_level_decision"],
                cleanup: WindowsIntegrityTokenCleanupDecision::None,
            },
        };
        let launch_mechanism = if child.is_some() {
            WindowsAppContainerProcessLaunchMechanism::StartupInfoExSecurityCapabilities
        } else {
            WindowsAppContainerProcessLaunchMechanism::SkippedInactive
        };
        let readiness = evaluate_windows_sandbox_readiness(
            &connector_seed,
            appcontainer_report,
            launch_mechanism,
            child.is_some(),
            &integrity_report,
            firewall_report,
        );
        if let Ok(jsonl) = readiness.to_jsonl_line() {
            debug!(evidence_jsonl = %jsonl, "Windows sandbox readiness evaluated");
        }
        readiness
    }
}

/// RAII guard that removes applied Windows Firewall rules when dropped.
#[derive(Debug)]
pub struct WindowsFirewallPolicyGuard {
    plan: Option<WindowsFirewallPolicyPlan>,
}

impl WindowsFirewallPolicyGuard {
    /// Create a guard that will clean up `plan` on drop.
    #[must_use]
    pub const fn new(plan: WindowsFirewallPolicyPlan) -> Self {
        Self { plan: Some(plan) }
    }

    /// Explicitly clean up the guarded firewall rules and return the cleanup report.
    ///
    /// # Errors
    ///
    /// Returns an error if rule removal fails.
    pub fn cleanup(mut self) -> Result<WindowsFirewallPolicyReport, SandboxError> {
        let plan = self.plan.take().ok_or_else(|| {
            SandboxError::InvalidConfig("WindowsFirewallPolicyGuard already cleaned up".into())
        })?;
        let mut api = NativeWindowsFirewallApi;
        cleanup_windows_firewall_policy(plan, &mut api)
    }
}

impl Drop for WindowsFirewallPolicyGuard {
    fn drop(&mut self) {
        if let Some(plan) = self.plan.take() {
            let mut api = NativeWindowsFirewallApi;
            let _ = cleanup_windows_firewall_policy(plan, &mut api);
        }
    }
}

/// Running Windows `AppContainer` child process plus its lifetime-bound job object.
#[derive(Debug)]
pub struct WindowsAppContainerChild {
    process_handle: HANDLE,
    thread_handle: HANDLE,
    job_handle: HANDLE,
    process_id: DWORD,
    integrity_level: WindowsIntegrityLevel,
    integrity_enforcement: WindowsChildIntegrityEnforcement,
}

impl WindowsAppContainerChild {
    /// Windows process id of the launched child.
    #[must_use]
    pub const fn process_id(&self) -> u32 {
        self.process_id
    }

    /// Redaction-safe integrity level recorded for this child launch.
    #[must_use]
    pub const fn integrity_level(&self) -> &'static str {
        self.integrity_level.as_str()
    }

    /// Redaction-safe integrity enforcement mechanism recorded for this child launch.
    #[must_use]
    pub const fn integrity_enforcement(&self) -> &'static str {
        self.integrity_enforcement.as_str()
    }

    /// Wait for the child to exit and return its process exit code.
    ///
    /// # Errors
    ///
    /// Returns an error if the timeout elapses or Windows fails the wait/exit-code calls.
    pub fn wait(&self, timeout: Duration) -> Result<u32, SandboxError> {
        let timeout_ms = DWORD::try_from(timeout.as_millis()).unwrap_or(DWORD::MAX - 1);
        match unsafe { WaitForSingleObject(self.process_handle, timeout_ms) } {
            WAIT_OBJECT_0 => {
                let mut exit_code: DWORD = 0;
                let ok = unsafe { GetExitCodeProcess(self.process_handle, &mut exit_code) };
                if ok == FALSE {
                    Err(SandboxError::SyscallFailed(format!(
                        "GetExitCodeProcess(AppContainer child) failed: {}",
                        get_last_error()
                    )))
                } else {
                    Ok(exit_code)
                }
            }
            WAIT_TIMEOUT => Err(SandboxError::ApplyFailed(
                "Windows AppContainer child did not exit before timeout".into(),
            )),
            WAIT_FAILED => Err(SandboxError::SyscallFailed(format!(
                "WaitForSingleObject(AppContainer child) failed: {}",
                get_last_error()
            ))),
            unexpected => Err(SandboxError::SyscallFailed(format!(
                "WaitForSingleObject(AppContainer child) returned unexpected status {unexpected}"
            ))),
        }
    }
}

impl Drop for WindowsAppContainerChild {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.thread_handle);
            CloseHandle(self.process_handle);
            CloseHandle(self.job_handle);
        }
    }
}

impl Default for WindowsSandbox {
    fn default() -> Self {
        Self::new()
    }
}

impl Sandbox for WindowsSandbox {
    fn apply(&self, policy: &CompiledPolicy) -> Result<(), SandboxError> {
        let integrity_level = WindowsIntegrityLevel::from_policy(policy);
        self.emit_integrity_policy_evidence(policy, WindowsIntegrityOperationMode::InProcessApply);
        if integrity_level == WindowsIntegrityLevel::Low {
            return Err(SandboxError::ApplyFailed(
                "windows low-integrity policy requires spawn_appcontainer_process; \
                 in-process apply cannot safely lower the host process"
                    .into(),
            ));
        }

        info!(
            profile = ?policy.profile,
            memory_mb = policy.memory_limit_bytes / (1024 * 1024),
            cpu_percent = policy.cpu_percent,
            deny_exec = policy.deny_exec,
            deny_ptrace = policy.deny_ptrace,
            block_network = policy.block_direct_network,
            "Applying Windows sandbox"
        );

        // Step 1: Resolve/create AppContainer profile metadata when enabled.
        let appcontainer_report = self.prepare_appcontainer_profile(policy)?;

        // Step 2: Create and assign job object
        let job = Self::create_job_object(policy)?;
        Self::assign_to_job(job)?;
        let appcontainer_evidence = WindowsAppContainerEvidence::from_lifecycle(
            &windows_appcontainer_connector_seed(policy),
            &appcontainer_report,
            true,
            "apply",
        );
        if let Ok(jsonl) = appcontainer_evidence.to_jsonl_line() {
            debug!(evidence_jsonl = %jsonl, "Windows AppContainer smoke evidence");
        }
        let launch_evidence = WindowsAppContainerProcessLaunchEvidence::from_lifecycle(
            &windows_appcontainer_connector_seed(policy),
            &appcontainer_report,
            if appcontainer_report.sid_present {
                WindowsAppContainerProcessLaunchMechanism::UnsupportedStdCommandMutation
            } else {
                WindowsAppContainerProcessLaunchMechanism::SkippedInactive
            },
            false,
            "not_launched_in_process_apply",
            None,
        );
        if let Ok(jsonl) = launch_evidence.to_jsonl_line() {
            debug!(evidence_jsonl = %jsonl, "Windows AppContainer process-launch evidence");
        }

        // Step 3: Set integrity level
        if let Err(e) = Self::set_current_process_integrity_level(integrity_level) {
            warn!(error = %e, "Failed to set integrity level");
        }

        // Step 4: Configure firewall (best effort)
        Self::configure_firewall(policy);

        // AppContainer enforcement is only available through the dedicated
        // STARTUPINFOEX child-process launch path. The in-process apply()
        // path still relies on job objects, integrity levels, and firewall.

        info!("Windows sandbox applied successfully");
        Ok(())
    }

    fn apply_to_command(
        &self,
        _cmd: &mut std::process::Command,
        policy: &CompiledPolicy,
    ) -> Result<(), SandboxError> {
        self.emit_integrity_policy_evidence(
            policy,
            WindowsIntegrityOperationMode::StdCommandMutation,
        );
        let profile = Self::appcontainer_profile(policy)?;
        let (action, mechanism, skip_reason) = if self.appcontainer_available {
            (
                WindowsAppContainerLifecycleAction::LaunchPathUnsupported,
                WindowsAppContainerProcessLaunchMechanism::UnsupportedStdCommandMutation,
                "windows_appcontainer_std_command_mutation_unsupported_use_startupinfoex_spawn",
            )
        } else {
            (
                WindowsAppContainerLifecycleAction::SkippedInactive,
                WindowsAppContainerProcessLaunchMechanism::SkippedInactive,
                "windows_appcontainer_not_active_createprocessasuser_path_unwired",
            )
        };
        let report = WindowsAppContainerLifecycleReport {
            profile,
            action,
            sid_present: false,
            cleanup: WindowsAppContainerCleanupDecision::None,
            skip_reason: Some(skip_reason.to_owned()),
        };
        let launch_evidence = WindowsAppContainerProcessLaunchEvidence::from_lifecycle(
            &windows_appcontainer_connector_seed(policy),
            &report,
            mechanism,
            false,
            "rejected",
            None,
        );
        if let Ok(jsonl) = launch_evidence.to_jsonl_line() {
            debug!(evidence_jsonl = %jsonl, "Windows AppContainer command launch rejected");
        }

        Err(SandboxError::ApplyFailed(format!(
            "windows AppContainer process launch unavailable: {skip_reason}"
        )))
    }

    fn is_available(&self) -> bool {
        // Basic Windows sandbox checks
        // Job objects are available on all Windows versions
        true
    }

    fn platform_name(&self) -> &'static str {
        "windows"
    }

    fn filter_strength(&self) -> crate::sandbox::FilterStrength {
        // The current Windows sandbox backs enforcement entirely on job
        // objects: ActiveProcessLimit/JobMemoryLimit/PerProcessUserTimeLimit
        // plus KILL_ON_JOB_CLOSE. There is no syscall filter and no named-
        // operation profile — a connector inside its CPU/memory budget can
        // reach any Win32/NT API its integrity level permits. That puts
        // Windows at the coarsest tier, ProcessLimit. (AppContainer or a
        // WinSandbox integration would raise this to ProfileLevel; see
        // bead 459lp for the parity roadmap.)
        crate::sandbox::FilterStrength::ProcessLimit
    }

    fn verify_file_access(
        &self,
        policy: &CompiledPolicy,
        path: &Path,
        write: bool,
    ) -> Result<(), SandboxError> {
        let path = crate::sandbox::resolve_policy_path(path);

        if write {
            for writable in &policy.writable_paths {
                let writable = crate::sandbox::resolve_policy_path(writable);
                if path.starts_with(&writable) {
                    return Ok(());
                }
            }
            return Err(SandboxError::PolicyCompilationFailed(format!(
                "write access to {} not allowed",
                path.display()
            )));
        }

        // Windows system paths are generally readable
        let system_paths = ["C:\\Windows\\System32", "C:\\Windows\\SysWOW64"];
        for sys_path in system_paths {
            let sys_path = crate::sandbox::resolve_policy_path(Path::new(sys_path));
            if path.starts_with(&sys_path) {
                return Ok(());
            }
        }

        for readable in policy.readonly_paths.iter().chain(&policy.writable_paths) {
            let readable = crate::sandbox::resolve_policy_path(readable);
            if path.starts_with(&readable) {
                return Ok(());
            }
        }

        Err(SandboxError::PolicyCompilationFailed(format!(
            "read access to {} not allowed",
            path.display()
        )))
    }

    fn verify_exec_allowed(&self, policy: &CompiledPolicy) -> Result<(), SandboxError> {
        if policy.deny_exec {
            Err(SandboxError::PolicyCompilationFailed(
                "process execution is denied".into(),
            ))
        } else {
            Ok(())
        }
    }

    fn verify_network_blocked(&self, policy: &CompiledPolicy) -> Result<(), SandboxError> {
        if policy.block_direct_network {
            Ok(())
        } else {
            Err(SandboxError::PolicyCompilationFailed(
                "direct network access is allowed (use Network Guard)".into(),
            ))
        }
    }
}

impl Drop for WindowsSandbox {
    fn drop(&mut self) {
        if let Some(job) = self.job_handle.take() {
            unsafe {
                CloseHandle(job);
            }
        }
    }
}

// ============================================================================
// Windows API Structures
// ============================================================================

#[repr(C)]
#[derive(Default)]
struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
    PerProcessUserTimeLimit: i64,
    PerJobUserTimeLimit: i64,
    LimitFlags: DWORD,
    MinimumWorkingSetSize: usize,
    MaximumWorkingSetSize: usize,
    ActiveProcessLimit: DWORD,
    Affinity: usize,
    PriorityClass: DWORD,
    SchedulingClass: DWORD,
}

#[repr(C)]
#[derive(Default)]
struct IO_COUNTERS {
    ReadOperationCount: u64,
    WriteOperationCount: u64,
    OtherOperationCount: u64,
    ReadTransferCount: u64,
    WriteTransferCount: u64,
    OtherTransferCount: u64,
}

#[repr(C)]
#[derive(Default)]
struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
    BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION,
    IoInfo: IO_COUNTERS,
    ProcessMemoryLimit: usize,
    JobMemoryLimit: usize,
    PeakProcessMemoryUsed: usize,
    PeakJobMemoryUsed: usize,
}

#[repr(C)]
struct SID_IDENTIFIER_AUTHORITY {
    Value: [u8; 6],
}

#[repr(C)]
struct SID_AND_ATTRIBUTES {
    Sid: PSID,
    Attributes: DWORD,
}

#[repr(C)]
struct TOKEN_MANDATORY_LABEL {
    Label: SID_AND_ATTRIBUTES,
}

#[repr(C)]
struct SECURITY_CAPABILITIES {
    AppContainerSid: PSID,
    Capabilities: *mut SID_AND_ATTRIBUTES,
    CapabilityCount: DWORD,
    Reserved: DWORD,
}

#[repr(C)]
struct STARTUPINFOW {
    cb: DWORD,
    lpReserved: LPWSTR,
    lpDesktop: LPWSTR,
    lpTitle: LPWSTR,
    dwX: DWORD,
    dwY: DWORD,
    dwXSize: DWORD,
    dwYSize: DWORD,
    dwXCountChars: DWORD,
    dwYCountChars: DWORD,
    dwFillAttribute: DWORD,
    dwFlags: DWORD,
    wShowWindow: u16,
    cbReserved2: u16,
    lpReserved2: *mut u8,
    hStdInput: HANDLE,
    hStdOutput: HANDLE,
    hStdError: HANDLE,
}

impl Default for STARTUPINFOW {
    fn default() -> Self {
        Self {
            cb: 0,
            lpReserved: ptr::null_mut(),
            lpDesktop: ptr::null_mut(),
            lpTitle: ptr::null_mut(),
            dwX: 0,
            dwY: 0,
            dwXSize: 0,
            dwYSize: 0,
            dwXCountChars: 0,
            dwYCountChars: 0,
            dwFillAttribute: 0,
            dwFlags: 0,
            wShowWindow: 0,
            cbReserved2: 0,
            lpReserved2: ptr::null_mut(),
            hStdInput: ptr::null_mut(),
            hStdOutput: ptr::null_mut(),
            hStdError: ptr::null_mut(),
        }
    }
}

#[repr(C)]
struct STARTUPINFOEXW {
    StartupInfo: STARTUPINFOW,
    lpAttributeList: *mut std::ffi::c_void,
}

impl STARTUPINFOEXW {
    fn with_attribute_list(attribute_list: *mut std::ffi::c_void) -> Result<Self, SandboxError> {
        let cb = DWORD::try_from(std::mem::size_of::<Self>()).map_err(|_| {
            SandboxError::PolicyCompilationFailed(
                "STARTUPINFOEXW size does not fit Windows DWORD".into(),
            )
        })?;
        Ok(Self {
            StartupInfo: STARTUPINFOW {
                cb,
                ..STARTUPINFOW::default()
            },
            lpAttributeList: attribute_list,
        })
    }
}

#[repr(C)]
#[derive(Default)]
struct PROCESS_INFORMATION {
    hProcess: HANDLE,
    hThread: HANDLE,
    dwProcessId: DWORD,
    dwThreadId: DWORD,
}

const SE_GROUP_INTEGRITY: DWORD = 0x0000_0020;
const SE_GROUP_ENABLED: DWORD = 0x0000_0004;
const TOKEN_ASSIGN_PRIMARY: DWORD = 0x0001;
const TOKEN_DUPLICATE: DWORD = 0x0002;
const TOKEN_QUERY: DWORD = 0x0008;
const TOKEN_ADJUST_DEFAULT: DWORD = 0x0080;

// ============================================================================
// FFI Bindings
// ============================================================================

unsafe extern "system" {
    fn CreateJobObjectW(lpJobAttributes: *mut std::ffi::c_void, lpName: LPCWSTR) -> HANDLE;

    fn SetInformationJobObject(
        hJob: HANDLE,
        JobObjectInformationClass: DWORD,
        lpJobObjectInformation: *const std::ffi::c_void,
        cbJobObjectInformationLength: DWORD,
    ) -> BOOL;

    fn AssignProcessToJobObject(hJob: HANDLE, hProcess: HANDLE) -> BOOL;

    fn CloseHandle(hObject: HANDLE) -> BOOL;

    fn GetCurrentProcess() -> HANDLE;

    fn GetLastError() -> DWORD;

    fn LocalFree(hMem: *mut std::ffi::c_void) -> *mut std::ffi::c_void;

    fn InitializeProcThreadAttributeList(
        lpAttributeList: *mut std::ffi::c_void,
        dwAttributeCount: DWORD,
        dwFlags: DWORD,
        lpSize: *mut SIZE_T,
    ) -> BOOL;

    fn UpdateProcThreadAttribute(
        lpAttributeList: *mut std::ffi::c_void,
        dwFlags: DWORD,
        Attribute: DWORD_PTR,
        lpValue: *mut std::ffi::c_void,
        cbSize: SIZE_T,
        lpPreviousValue: *mut std::ffi::c_void,
        lpReturnSize: *mut SIZE_T,
    ) -> BOOL;

    fn DeleteProcThreadAttributeList(lpAttributeList: *mut std::ffi::c_void);

    fn CreateProcessW(
        lpApplicationName: LPCWSTR,
        lpCommandLine: LPWSTR,
        lpProcessAttributes: *mut std::ffi::c_void,
        lpThreadAttributes: *mut std::ffi::c_void,
        bInheritHandles: BOOL,
        dwCreationFlags: DWORD,
        lpEnvironment: *mut std::ffi::c_void,
        lpCurrentDirectory: LPCWSTR,
        lpStartupInfo: *mut STARTUPINFOW,
        lpProcessInformation: *mut PROCESS_INFORMATION,
    ) -> BOOL;

    fn ResumeThread(hThread: HANDLE) -> DWORD;

    fn TerminateProcess(hProcess: HANDLE, uExitCode: u32) -> BOOL;

    fn WaitForSingleObject(hHandle: HANDLE, dwMilliseconds: DWORD) -> DWORD;

    fn GetExitCodeProcess(hProcess: HANDLE, lpExitCode: *mut DWORD) -> BOOL;
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenProcessToken(
        ProcessHandle: HANDLE,
        DesiredAccess: DWORD,
        TokenHandle: *mut HANDLE,
    ) -> BOOL;

    fn AllocateAndInitializeSid(
        pIdentifierAuthority: *const SID_IDENTIFIER_AUTHORITY,
        nSubAuthorityCount: u8,
        nSubAuthority0: DWORD,
        nSubAuthority1: DWORD,
        nSubAuthority2: DWORD,
        nSubAuthority3: DWORD,
        nSubAuthority4: DWORD,
        nSubAuthority5: DWORD,
        nSubAuthority6: DWORD,
        nSubAuthority7: DWORD,
        pSid: *mut PSID,
    ) -> BOOL;

    fn FreeSid(pSid: PSID) -> *mut std::ffi::c_void;

    fn GetLengthSid(pSid: PSID) -> DWORD;

    fn SetTokenInformation(
        TokenHandle: HANDLE,
        TokenInformationClass: DWORD,
        TokenInformation: *const std::ffi::c_void,
        TokenInformationLength: DWORD,
    ) -> BOOL;

    fn DuplicateTokenEx(
        hExistingToken: HANDLE,
        dwDesiredAccess: DWORD,
        lpTokenAttributes: *mut std::ffi::c_void,
        ImpersonationLevel: DWORD,
        TokenType: DWORD,
        phNewToken: *mut HANDLE,
    ) -> BOOL;

    fn DeriveCapabilitySidsFromName(
        CapName: LPCWSTR,
        CapabilityGroupSids: *mut *mut PSID,
        CapabilityGroupSidCount: *mut DWORD,
        CapabilitySids: *mut *mut PSID,
        CapabilitySidCount: *mut DWORD,
    ) -> BOOL;

    fn CreateProcessAsUserW(
        hToken: HANDLE,
        lpApplicationName: LPCWSTR,
        lpCommandLine: LPWSTR,
        lpProcessAttributes: *mut std::ffi::c_void,
        lpThreadAttributes: *mut std::ffi::c_void,
        bInheritHandles: BOOL,
        dwCreationFlags: DWORD,
        lpEnvironment: *mut std::ffi::c_void,
        lpCurrentDirectory: LPCWSTR,
        lpStartupInfo: *mut STARTUPINFOW,
        lpProcessInformation: *mut PROCESS_INFORMATION,
    ) -> BOOL;
}

#[link(name = "userenv")]
unsafe extern "system" {
    fn CreateAppContainerProfile(
        pszAppContainerName: LPCWSTR,
        pszDisplayName: LPCWSTR,
        pszDescription: LPCWSTR,
        pCapabilities: *mut SID_AND_ATTRIBUTES,
        dwCapabilityCount: DWORD,
        ppSidAppContainerSid: *mut PSID,
    ) -> HRESULT;

    fn DeriveAppContainerSidFromAppContainerName(
        pszAppContainerName: LPCWSTR,
        ppsidAppContainerSid: *mut PSID,
    ) -> HRESULT;

    fn DeleteAppContainerProfile(pszAppContainerName: LPCWSTR) -> HRESULT;
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Environment variable that opts the process into the Windows
/// `AppContainer` child-process launch path.
///
/// `AppContainer` enforcement cannot be retrofitted onto an already-running
/// process or an arbitrary [`std::process::Command`]. Callers that need
/// `AppContainer` must use [`WindowsSandbox::spawn_appcontainer_process`],
/// which launches a child process with `STARTUPINFOEX` security capabilities
/// before it is resumed. The availability flag remains an explicit opt-in so
/// generic readiness surfaces do not infer `AppContainer` protection from
/// kernel support alone.
///
/// Operators running the Windows-gated proof lane can flip this env var to
/// `1` (or `true`) when the dedicated launch entrypoint is the execution path
/// under test.
pub const FCP_SANDBOX_WINDOWS_APPCONTAINER_ENV: &str = "FCP_SANDBOX_WINDOWS_APPCONTAINER";

/// Check if `AppContainer` is *actually wired* and active for this
/// process (NOT just available on the kernel).
///
/// Pre-fix this returned `true` unconditionally on the assumption that
/// `AppContainer` was present on Windows 8+. That was wrong: the downstream
/// `apply()` and `apply_to_command()` paths still cannot attach `AppContainer`
/// to the current process or mutate a generic command, so reporting `true`
/// by default gave the rest of the system a false sense of process isolation —
/// br-flywheel_connectors-3hrw3.
///
/// We fail closed unless a Windows operator explicitly opts into the dedicated
/// `AppContainer` child-process launch path via
/// [`FCP_SANDBOX_WINDOWS_APPCONTAINER_ENV`].
fn check_appcontainer_available() -> bool {
    matches!(
        std::env::var(FCP_SANDBOX_WINDOWS_APPCONTAINER_ENV)
            .ok()
            .as_deref(),
        Some("1" | "true" | "TRUE")
    )
}

fn windows_appcontainer_connector_seed(policy: &CompiledPolicy) -> String {
    policy
        .state_dir
        .as_ref()
        .and_then(|path| path.file_name())
        .and_then(|name| name.to_str())
        .filter(|name| !name.trim().is_empty())
        .unwrap_or("connector")
        .to_owned()
}

struct NativeWindowsAppContainerApi;

impl WindowsAppContainerProfileApi for NativeWindowsAppContainerApi {
    fn create_profile(
        &mut self,
        profile: &WindowsAppContainerProfile,
    ) -> Result<WindowsAppContainerCreateOutcome, SandboxError> {
        create_appcontainer_profile(profile)
    }

    fn derive_profile_sid(&mut self, profile_name: &str) -> Result<(), SandboxError> {
        let _sid = derive_appcontainer_sid(profile_name)?;
        Ok(())
    }

    fn delete_profile(&mut self, profile_name: &str) -> Result<(), SandboxError> {
        delete_appcontainer_profile(profile_name)
    }
}

struct NativeWindowsFirewallApi;

impl WindowsFirewallPolicyApi for NativeWindowsFirewallApi {
    fn rule_names_for_connector(
        &mut self,
        connector_id_hash: &str,
    ) -> Result<Vec<String>, SandboxError> {
        let search_pattern = format!("Name=fcp-fw-{connector_id_hash}-");
        if let Ok(reg_output) = std::process::Command::new(r"C:\Windows\System32\reg.exe")
            .args([
                "query",
                r"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules",
                "/f",
                &search_pattern,
                "/d",
            ])
            .output()
        {
            let combined = format!(
                "{}\n{}",
                String::from_utf8_lossy(&reg_output.stdout),
                String::from_utf8_lossy(&reg_output.stderr)
            );
            let lower = combined.to_ascii_lowercase();
            if lower.contains("0 match(es) found") {
                return Ok(Vec::new());
            }
            if reg_output.status.success() {
                return Ok(parse_netsh_rule_names_for_connector(
                    &String::from_utf8_lossy(&reg_output.stdout),
                    connector_id_hash,
                ));
            }
        }

        let output = run_netsh_advfirewall(&["show", "rule", "name=all", "dir=out"])?;
        let combined = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if is_netsh_no_matching_rules(&combined) {
            return Ok(Vec::new());
        }
        if !output.status.success() {
            return Err(classify_netsh_failure(
                "rule_names_for_connector",
                &combined,
            ));
        }
        Ok(parse_netsh_rule_names_for_connector(
            &String::from_utf8_lossy(&output.stdout),
            connector_id_hash,
        ))
    }

    fn upsert_rule(
        &mut self,
        rule: &WindowsFirewallRuleSpec,
    ) -> Result<WindowsFirewallRuleApplyOutcome, SandboxError> {
        let name_arg = format!("name={}", rule.name);
        let probe = run_netsh_advfirewall(&["show", "rule", &name_arg, "dir=out", "verbose"])?;
        let probe_combined = format!(
            "{}\n{}",
            String::from_utf8_lossy(&probe.stdout),
            String::from_utf8_lossy(&probe.stderr)
        );
        let rule_exists = probe.status.success() && !is_netsh_no_matching_rules(&probe_combined);

        if rule_exists {
            let probe_stdout = String::from_utf8_lossy(&probe.stdout);
            if netsh_rule_matches_spec(&probe_stdout, rule) {
                return Ok(WindowsFirewallRuleApplyOutcome::AlreadyCurrent);
            }
            let args = build_netsh_upsert_args(rule, true);
            let arg_refs = args.iter().map(String::as_str).collect::<Vec<_>>();
            let update = run_netsh_advfirewall(&arg_refs)?;
            let update_combined = format!(
                "{}\n{}",
                String::from_utf8_lossy(&update.stdout),
                String::from_utf8_lossy(&update.stderr)
            );
            if !update.status.success() {
                return Err(classify_netsh_failure(
                    "upsert_rule_update",
                    &update_combined,
                ));
            }
            return Ok(WindowsFirewallRuleApplyOutcome::Updated);
        }

        let args = build_netsh_upsert_args(rule, false);
        let arg_refs = args.iter().map(String::as_str).collect::<Vec<_>>();
        let create = run_netsh_advfirewall(&arg_refs)?;
        let create_combined = format!(
            "{}\n{}",
            String::from_utf8_lossy(&create.stdout),
            String::from_utf8_lossy(&create.stderr)
        );
        if !create.status.success() {
            return Err(classify_netsh_failure(
                "upsert_rule_create",
                &create_combined,
            ));
        }
        Ok(WindowsFirewallRuleApplyOutcome::Created)
    }

    fn remove_rule(
        &mut self,
        rule_name: &str,
    ) -> Result<WindowsFirewallRuleCleanupOutcome, SandboxError> {
        let name_arg = format!("name={rule_name}");
        let output = run_netsh_advfirewall(&["delete", "rule", &name_arg, "dir=out"])?;
        let combined = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if is_netsh_no_matching_rules(&combined) {
            return Ok(WindowsFirewallRuleCleanupOutcome::Missing);
        }
        if !output.status.success() {
            return Err(classify_netsh_failure("remove_rule", &combined));
        }
        Ok(WindowsFirewallRuleCleanupOutcome::Removed)
    }
}

fn run_netsh_advfirewall(args: &[&str]) -> Result<std::process::Output, SandboxError> {
    let mut cmd = std::process::Command::new(r"C:\Windows\System32\netsh.exe");
    cmd.arg("advfirewall").arg("firewall").args(args);
    cmd.output().map_err(|err| {
        SandboxError::SyscallFailed(format!("windows_firewall_api_unavailable: {err}"))
    })
}

fn is_netsh_no_matching_rules(output: &str) -> bool {
    let lower = output.to_ascii_lowercase();
    lower.contains("no rules match the specified criteria")
}

fn classify_netsh_failure(operation: &'static str, output: &str) -> SandboxError {
    let lower = output.to_ascii_lowercase();
    if lower.contains("requires elevation") || lower.contains("access is denied") {
        SandboxError::ApplyFailed(format!("windows_firewall_privilege_denied ({operation})"))
    } else {
        SandboxError::SyscallFailed(format!("windows_firewall_{operation}_failed"))
    }
}

fn parse_netsh_rule_names_for_connector(stdout: &str, connector_id_hash: &str) -> Vec<String> {
    let prefix = format!("fcp-fw-{connector_id_hash}-");
    let reg_marker = format!("Name={prefix}");
    let mut names = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Rule Name:") {
            let name = rest.trim();
            if name.starts_with(&prefix) && !names.iter().any(|existing| existing == name) {
                names.push(name.to_owned());
            }
        }
        let mut search_slice = trimmed;
        while let Some(idx) = search_slice.find(&reg_marker) {
            let after_eq = &search_slice[idx + "Name=".len()..];
            let end = after_eq.find('|').unwrap_or(after_eq.len());
            let name = after_eq[..end].trim();
            if name.starts_with(&prefix) && !names.iter().any(|existing| existing == name) {
                names.push(name.to_owned());
            }
            search_slice = &after_eq[end..];
        }
    }
    names.sort();
    names
}

fn build_netsh_upsert_args(rule: &WindowsFirewallRuleSpec, update_existing: bool) -> Vec<String> {
    let program = rule.application_path.display().to_string();
    let protocol = rule.protocol.as_str().to_ascii_uppercase();
    let remote_ip = &rule.remote_address;
    let remote_port = rule.remote_port.to_string();

    if update_existing {
        vec![
            "set".to_owned(),
            "rule".to_owned(),
            format!("name={}", rule.name),
            "dir=out".to_owned(),
            "new".to_owned(),
            "action=allow".to_owned(),
            format!("program={program}"),
            format!("protocol={protocol}"),
            format!("remoteip={remote_ip}"),
            format!("remoteport={remote_port}"),
            "enable=yes".to_owned(),
            "profile=any".to_owned(),
        ]
    } else {
        vec![
            "add".to_owned(),
            "rule".to_owned(),
            format!("name={}", rule.name),
            "dir=out".to_owned(),
            "action=allow".to_owned(),
            format!("program={program}"),
            format!("protocol={protocol}"),
            format!("remoteip={remote_ip}"),
            format!("remoteport={remote_port}"),
            "enable=yes".to_owned(),
            "profile=any".to_owned(),
        ]
    }
}

fn netsh_rule_matches_spec(stdout: &str, rule: &WindowsFirewallRuleSpec) -> bool {
    let mut enabled_ok = false;
    let mut direction_ok = false;
    let mut action_ok = false;
    let mut protocol_ok = false;
    let mut remote_ip_ok = false;
    let mut remote_port_ok = false;
    let mut program_ok = false;

    let expected_program = rule.application_path.display().to_string();
    let expected_port = rule.remote_port.to_string();
    let expected_ip = rule.remote_address.as_str();
    let expected_ip_v4_cidr = format!("{expected_ip}/32");
    let expected_ip_v6_cidr = format!("{expected_ip}/128");

    for line in stdout.lines() {
        let trimmed = line.trim();
        if let Some(val) = trimmed.strip_prefix("Enabled:") {
            enabled_ok = val.trim().eq_ignore_ascii_case("yes");
        } else if let Some(val) = trimmed.strip_prefix("Direction:") {
            direction_ok = val.trim().eq_ignore_ascii_case("out");
        } else if let Some(val) = trimmed.strip_prefix("Action:") {
            action_ok = val.trim().eq_ignore_ascii_case("allow");
        } else if let Some(val) = trimmed.strip_prefix("Protocol:") {
            protocol_ok = val.trim().eq_ignore_ascii_case(rule.protocol.as_str());
        } else if let Some(val) = trimmed.strip_prefix("RemoteIP:") {
            let candidate = val.trim();
            remote_ip_ok = candidate.eq_ignore_ascii_case(expected_ip)
                || candidate.eq_ignore_ascii_case(&expected_ip_v4_cidr)
                || candidate.eq_ignore_ascii_case(&expected_ip_v6_cidr);
        } else if let Some(val) = trimmed.strip_prefix("RemotePort:") {
            remote_port_ok = val.trim() == expected_port;
        } else if let Some(val) = trimmed.strip_prefix("Program:") {
            program_ok = val.trim().eq_ignore_ascii_case(&expected_program);
        }
    }

    enabled_ok
        && direction_ok
        && action_ok
        && protocol_ok
        && remote_ip_ok
        && remote_port_ok
        && program_ok
}

fn create_appcontainer_profile(
    profile: &WindowsAppContainerProfile,
) -> Result<WindowsAppContainerCreateOutcome, SandboxError> {
    let mut capabilities = DerivedCapabilitySids::new(&profile.capabilities)?;
    let appcontainer_name = to_wide_string(&profile.name);
    let display_name = to_wide_string(&format!("FCP {}", profile.name));
    let description = to_wide_string("Flywheel connector AppContainer profile");
    let capability_count = capabilities.count();
    let capability_ptr = capabilities.as_mut_ptr();

    let mut sid: PSID = ptr::null_mut();
    let hr = unsafe {
        CreateAppContainerProfile(
            appcontainer_name.as_ptr(),
            display_name.as_ptr(),
            description.as_ptr(),
            capability_ptr,
            capability_count,
            &mut sid,
        )
    };

    match hr {
        S_OK => {
            let _sid = OwnedSid(sid);
            Ok(WindowsAppContainerCreateOutcome::Created)
        }
        HRESULT_ERROR_ALREADY_EXISTS => Ok(WindowsAppContainerCreateOutcome::AlreadyExists),
        _ => Err(SandboxError::SyscallFailed(format_hresult(
            "CreateAppContainerProfile",
            hr,
        ))),
    }
}

fn derive_appcontainer_sid(profile_name: &str) -> Result<OwnedSid, SandboxError> {
    let appcontainer_name = to_wide_string(profile_name);
    let mut sid: PSID = ptr::null_mut();
    let hr =
        unsafe { DeriveAppContainerSidFromAppContainerName(appcontainer_name.as_ptr(), &mut sid) };

    if hr == S_OK {
        Ok(OwnedSid(sid))
    } else {
        Err(SandboxError::SyscallFailed(format_hresult(
            "DeriveAppContainerSidFromAppContainerName",
            hr,
        )))
    }
}

fn delete_appcontainer_profile(profile_name: &str) -> Result<(), SandboxError> {
    let appcontainer_name = to_wide_string(profile_name);
    let hr = unsafe { DeleteAppContainerProfile(appcontainer_name.as_ptr()) };

    if hr == S_OK {
        Ok(())
    } else {
        Err(SandboxError::SyscallFailed(format_hresult(
            "DeleteAppContainerProfile",
            hr,
        )))
    }
}

struct OwnedSid(PSID);

impl OwnedSid {
    const fn as_ptr(&self) -> PSID {
        self.0
    }
}

impl Drop for OwnedSid {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                FreeSid(self.0);
            }
        }
    }
}

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    const fn new(handle: HANDLE) -> Self {
        Self(handle)
    }

    const fn as_raw(&self) -> HANDLE {
        self.0
    }

    fn into_raw(mut self) -> HANDLE {
        let handle = self.0;
        self.0 = ptr::null_mut();
        handle
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

struct ProcThreadAttributeList {
    storage: Vec<usize>,
}

impl ProcThreadAttributeList {
    fn new(attribute_count: DWORD) -> Result<Self, SandboxError> {
        let mut byte_len: SIZE_T = 0;
        let probe = unsafe {
            InitializeProcThreadAttributeList(ptr::null_mut(), attribute_count, 0, &mut byte_len)
        };
        if probe != FALSE {
            return Err(SandboxError::SyscallFailed(
                "InitializeProcThreadAttributeList size probe unexpectedly succeeded".into(),
            ));
        }
        let last_error = unsafe { GetLastError() };
        if last_error != ERROR_INSUFFICIENT_BUFFER {
            return Err(SandboxError::SyscallFailed(format!(
                "InitializeProcThreadAttributeList size probe failed: error code {last_error}"
            )));
        }

        let word_len = byte_len.div_ceil(std::mem::size_of::<usize>());
        let mut list = Self {
            storage: vec![0; word_len],
        };
        let initialized = unsafe {
            InitializeProcThreadAttributeList(list.as_mut_ptr(), attribute_count, 0, &mut byte_len)
        };
        if initialized == FALSE {
            return Err(SandboxError::SyscallFailed(format!(
                "InitializeProcThreadAttributeList failed: {}",
                get_last_error()
            )));
        }

        Ok(list)
    }

    fn as_mut_ptr(&mut self) -> *mut std::ffi::c_void {
        self.storage.as_mut_ptr().cast()
    }

    fn update_security_capabilities(
        &mut self,
        security_capabilities: &mut SECURITY_CAPABILITIES,
    ) -> Result<(), SandboxError> {
        let updated = unsafe {
            UpdateProcThreadAttribute(
                self.as_mut_ptr(),
                0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                std::ptr::from_mut(security_capabilities).cast(),
                std::mem::size_of::<SECURITY_CAPABILITIES>(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if updated == FALSE {
            return Err(SandboxError::SyscallFailed(format!(
                "UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES) failed: {}",
                get_last_error()
            )));
        }

        Ok(())
    }
}

impl Drop for ProcThreadAttributeList {
    fn drop(&mut self) {
        if !self.storage.is_empty() {
            unsafe {
                DeleteProcThreadAttributeList(self.as_mut_ptr());
            }
        }
    }
}

struct DerivedCapabilitySids {
    attributes: Vec<SID_AND_ATTRIBUTES>,
    sids: Vec<PSID>,
}

impl DerivedCapabilitySids {
    fn new(capabilities: &[String]) -> Result<Self, SandboxError> {
        let mut derived = Self {
            attributes: Vec::with_capacity(capabilities.len()),
            sids: Vec::with_capacity(capabilities.len()),
        };

        for capability in capabilities {
            let sid = derive_capability_sid(capability)?;
            derived.attributes.push(SID_AND_ATTRIBUTES {
                Sid: sid,
                Attributes: SE_GROUP_ENABLED,
            });
            derived.sids.push(sid);
        }

        Ok(derived)
    }

    fn as_mut_ptr(&mut self) -> *mut SID_AND_ATTRIBUTES {
        if self.attributes.is_empty() {
            ptr::null_mut()
        } else {
            self.attributes.as_mut_ptr()
        }
    }

    fn count(&self) -> DWORD {
        DWORD::try_from(self.attributes.len()).unwrap_or(DWORD::MAX)
    }
}

impl Drop for DerivedCapabilitySids {
    fn drop(&mut self) {
        for sid in self.sids.drain(..) {
            unsafe {
                LocalFree(sid);
            }
        }
    }
}

fn derive_capability_sid(capability: &str) -> Result<PSID, SandboxError> {
    let capability_name = to_wide_string(capability);
    let mut group_sids: *mut PSID = ptr::null_mut();
    let mut group_sid_count: DWORD = 0;
    let mut capability_sids: *mut PSID = ptr::null_mut();
    let mut capability_sid_count: DWORD = 0;

    let result = unsafe {
        DeriveCapabilitySidsFromName(
            capability_name.as_ptr(),
            &mut group_sids,
            &mut group_sid_count,
            &mut capability_sids,
            &mut capability_sid_count,
        )
    };

    if result == FALSE {
        return Err(SandboxError::SyscallFailed(format!(
            "DeriveCapabilitySidsFromName({capability}) failed: {}",
            get_last_error()
        )));
    }

    unsafe {
        free_local_sid_array(group_sids, group_sid_count);
    }

    if capability_sids.is_null() || capability_sid_count == 0 {
        unsafe {
            LocalFree(capability_sids.cast());
        }
        return Err(SandboxError::SyscallFailed(format!(
            "DeriveCapabilitySidsFromName({capability}) returned no capability SID"
        )));
    }

    let Ok(capability_sid_count) = usize::try_from(capability_sid_count) else {
        unsafe {
            free_local_sid_array(capability_sids, capability_sid_count);
        }
        return Err(SandboxError::SyscallFailed(format!(
            "DeriveCapabilitySidsFromName({capability}) returned too many capability SIDs"
        )));
    };
    let sid = unsafe { *capability_sids };
    unsafe {
        for idx in 1..capability_sid_count {
            LocalFree(*capability_sids.add(idx));
        }
        LocalFree(capability_sids.cast());
    }

    Ok(sid)
}

unsafe fn free_local_sid_array(sids: *mut PSID, count: DWORD) {
    if sids.is_null() {
        return;
    }

    let Ok(count) = usize::try_from(count) else {
        unsafe {
            LocalFree(sids.cast());
        }
        return;
    };

    for idx in 0..count {
        unsafe {
            LocalFree(*sids.add(idx));
        }
    }
    unsafe {
        LocalFree(sids.cast());
    }
}

fn format_hresult(operation: &str, hr: HRESULT) -> String {
    format!(
        "{operation} failed: HRESULT 0x{:08x}",
        u32::from_ne_bytes(hr.to_ne_bytes())
    )
}

/// Get last Windows error as string.
fn get_last_error() -> String {
    let code = unsafe { GetLastError() };
    format!("error code {code}")
}

/// Convert Rust string to wide string for Windows APIs.
fn to_wide_string(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn to_wide_os_str(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

fn build_windows_command_line(program: &Path, args: &[&OsStr]) -> Vec<u16> {
    let mut parts = Vec::with_capacity(args.len() + 1);
    parts.push(quote_windows_command_arg(program.as_os_str()));
    parts.extend(args.iter().map(|arg| quote_windows_command_arg(arg)));
    to_wide_string(&parts.join(" "))
}

fn quote_windows_command_arg(arg: &OsStr) -> String {
    let value = arg.to_string_lossy();
    if value.is_empty() {
        return "\"\"".to_owned();
    }
    if !value
        .chars()
        .any(|ch| matches!(ch, ' ' | '\t' | '\n' | '\r' | '"'))
    {
        return value.into_owned();
    }

    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    let mut backslashes = 0usize;
    for ch in value.chars() {
        if ch == '\\' {
            backslashes += 1;
        } else if ch == '"' {
            for _ in 0..=(backslashes * 2) {
                quoted.push('\\');
            }
            quoted.push('"');
            backslashes = 0;
        } else {
            for _ in 0..backslashes {
                quoted.push('\\');
            }
            backslashes = 0;
            quoted.push(ch);
        }
    }
    for _ in 0..(backslashes * 2) {
        quoted.push('\\');
    }
    quoted.push('"');
    quoted
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::CompiledPolicy;
    use fcp_manifest::SandboxProfile;
    use std::path::PathBuf;
    use std::time::Duration;

    fn test_policy() -> CompiledPolicy {
        CompiledPolicy {
            profile: SandboxProfile::Strict,
            memory_limit_bytes: 256 * 1024 * 1024,
            cpu_percent: 50,
            wall_clock_timeout: Duration::from_secs(30),
            readonly_paths: vec![PathBuf::from("C:\\Program Files")],
            writable_paths: vec![PathBuf::from("C:\\Temp\\test")],
            deny_exec: true,
            deny_ptrace: true,
            block_direct_network: true,
            state_dir: Some(PathBuf::from("C:\\Temp\\test")),
            platform_flags: crate::sandbox::PlatformFlags::default(),
        }
    }

    #[test]
    fn test_windows_sandbox_available() {
        let sandbox = WindowsSandbox::new();
        assert!(sandbox.is_available());
        assert_eq!(sandbox.platform_name(), "windows");
    }

    /// br-3hrw3 regression: `AppContainer` must NOT report itself as
    /// active by default, because generic sandbox application cannot attach
    /// `AppContainer` to the current process. Pre-fix, `check_appcontainer_available()` returned
    /// `true` unconditionally and the constructor logged "`AppContainer`
    /// available for process isolation" — giving downstream observers a
    /// false sense of process isolation that the rest of `apply()`
    /// never delivered. Post-fix, the default is fail-closed.
    #[test]
    fn appcontainer_inactive_by_default() {
        // Make sure no leftover env value from a parallel test poisons
        // the assertion. Tests in this module are not annotated with
        // `#[serial]`, but each `WindowsSandbox::new()` call captures
        // the env at that instant, so we read the current value first.
        let prev = std::env::var(FCP_SANDBOX_WINDOWS_APPCONTAINER_ENV).ok();
        unsafe {
            std::env::remove_var(FCP_SANDBOX_WINDOWS_APPCONTAINER_ENV);
        }
        let sandbox = WindowsSandbox::new();
        assert!(
            !sandbox.appcontainer_active(),
            "br-3hrw3: AppContainer must default to INACTIVE unless the \
             dedicated child-process launch path is explicitly enabled"
        );
        // Restore the prior value to keep the test environment clean
        // for any sibling test that may run after us in the same process.
        if let Some(v) = prev {
            unsafe {
                std::env::set_var(FCP_SANDBOX_WINDOWS_APPCONTAINER_ENV, v);
            }
        }
    }

    /// br-3hrw3 companion: an explicit operator opt-in via the env var
    /// flips `appcontainer_active()` to true for the dedicated child-process
    /// launch path.
    #[test]
    fn appcontainer_active_when_env_opt_in_set() {
        let prev = std::env::var(FCP_SANDBOX_WINDOWS_APPCONTAINER_ENV).ok();
        unsafe {
            std::env::set_var(FCP_SANDBOX_WINDOWS_APPCONTAINER_ENV, "1");
        }
        let sandbox = WindowsSandbox::new();
        assert!(
            sandbox.appcontainer_active(),
            "explicit opt-in via {FCP_SANDBOX_WINDOWS_APPCONTAINER_ENV} must flip AppContainer to active"
        );
        unsafe {
            match prev {
                Some(v) => std::env::set_var(FCP_SANDBOX_WINDOWS_APPCONTAINER_ENV, v),
                None => std::env::remove_var(FCP_SANDBOX_WINDOWS_APPCONTAINER_ENV),
            }
        }
    }

    #[test]
    fn windows_command_line_quotes_spaces_quotes_and_trailing_backslashes() {
        let command_line = build_windows_command_line(
            Path::new("C:\\Program Files\\FCP\\connector.exe"),
            &[
                OsStr::new("simple"),
                OsStr::new("two words"),
                OsStr::new("quote\"inside"),
                OsStr::new("C:\\Temp\\trailing\\"),
            ],
        );
        let rendered = String::from_utf16(
            &command_line[..command_line.len().checked_sub(1).expect("nul terminator")],
        )
        .expect("valid utf16 command line");

        assert_eq!(
            rendered,
            "\"C:\\Program Files\\FCP\\connector.exe\" simple \"two words\" \
             \"quote\\\"inside\" C:\\Temp\\trailing\\"
        );
    }

    #[test]
    fn windows_command_line_quotes_empty_argument() {
        let command_line =
            build_windows_command_line(Path::new("C:\\fcp\\connector.exe"), &[OsStr::new("")]);
        let rendered = String::from_utf16(
            &command_line[..command_line.len().checked_sub(1).expect("nul terminator")],
        )
        .expect("valid utf16 command line");

        assert_eq!(rendered, "C:\\fcp\\connector.exe \"\"");
    }

    #[test]
    fn windows_integrity_level_defaults_to_medium() {
        let policy = test_policy();

        assert_eq!(
            WindowsIntegrityLevel::from_policy(&policy),
            WindowsIntegrityLevel::Medium
        );
        assert_eq!(
            WindowsChildIntegrityEnforcement::for_level(WindowsIntegrityLevel::Medium),
            WindowsChildIntegrityEnforcement::InheritedProcess
        );
    }

    #[test]
    fn windows_low_integrity_uses_primary_child_identity() {
        let mut policy = test_policy();
        policy.platform_flags.windows_low_integrity = true;

        assert_eq!(
            WindowsIntegrityLevel::from_policy(&policy),
            WindowsIntegrityLevel::Low
        );
        assert_eq!(
            WindowsChildIntegrityEnforcement::for_level(WindowsIntegrityLevel::Low),
            WindowsChildIntegrityEnforcement::LowPrimaryIntegrity
        );
        assert_eq!(WindowsIntegrityLevel::Low.as_str(), "low");
        assert_eq!(
            WindowsChildIntegrityEnforcement::LowPrimaryIntegrity.as_str(),
            "low_primary_integrity"
        );
    }

    #[test]
    fn windows_apply_rejects_low_integrity_policy() {
        let mut policy = test_policy();
        policy.platform_flags.windows_low_integrity = true;
        let sandbox = WindowsSandbox::new();

        let error = sandbox
            .apply(&policy)
            .expect_err("low integrity must use the child launch path");
        match error {
            SandboxError::ApplyFailed(message) => {
                assert!(message.contains("requires spawn_appcontainer_process"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn windows_appcontainer_real_process_launch_e2e() {
        if !matches!(
            std::env::var("FCP_SANDBOX_WINDOWS_APPCONTAINER_E2E")
                .ok()
                .as_deref(),
            Some("1" | "true" | "TRUE")
        ) {
            eprintln!(
                "structured_skip: FCP_SANDBOX_WINDOWS_APPCONTAINER_E2E not enabled for real launch"
            );
            return;
        }

        let prev = std::env::var(FCP_SANDBOX_WINDOWS_APPCONTAINER_ENV).ok();
        unsafe {
            std::env::set_var(FCP_SANDBOX_WINDOWS_APPCONTAINER_ENV, "1");
        }
        let sandbox = WindowsSandbox::new();
        let mut policy = test_policy();
        policy.platform_flags.windows_low_integrity = true;
        let child = sandbox
            .spawn_appcontainer_process(
                Path::new("C:\\Windows\\System32\\cmd.exe"),
                &[OsStr::new("/C"), OsStr::new("exit 0")],
                &policy,
            )
            .expect("launch AppContainer child");
        assert!(child.process_id() > 0);
        assert_eq!(child.integrity_level(), "low");
        assert_eq!(child.integrity_enforcement(), "low_primary_integrity");
        eprintln!("WINDOWS_APPCONTAINER_E2E_PROCESS_ID={}", child.process_id());
        eprintln!("WINDOWS_APPCONTAINER_E2E_INTEGRITY_LEVEL=low");
        eprintln!("WINDOWS_APPCONTAINER_E2E_INTEGRITY_ENFORCEMENT=low_primary_integrity");
        let exit_code = child
            .wait(Duration::from_secs(10))
            .expect("wait for AppContainer child");
        assert_eq!(exit_code, 0);
        eprintln!("WINDOWS_APPCONTAINER_E2E_ALLOWED_PROCESS_STARTUP=true");

        let _user_profile = std::env::var_os("USERPROFILE").expect("USERPROFILE is available");
        let denied_write_command = "echo denied > %USERPROFILE%\\fcp-appcontainer-denied-write.txt && exit /B 86 || exit /B 5";
        let denied_child = sandbox
            .spawn_appcontainer_process(
                Path::new("C:\\Windows\\System32\\cmd.exe"),
                &[OsStr::new("/C"), OsStr::new(denied_write_command)],
                &policy,
            )
            .expect("launch AppContainer child for denied user-profile write");
        let denied_exit_code = denied_child
            .wait(Duration::from_secs(10))
            .expect("wait for AppContainer denied-write child");
        assert_eq!(
            denied_exit_code, 5,
            "AppContainer child did not report denied user-profile write"
        );
        eprintln!("WINDOWS_APPCONTAINER_E2E_DENIED_USER_PROFILE_WRITE=true");

        unsafe {
            match prev {
                Some(v) => std::env::set_var(FCP_SANDBOX_WINDOWS_APPCONTAINER_ENV, v),
                None => std::env::remove_var(FCP_SANDBOX_WINDOWS_APPCONTAINER_ENV),
            }
        }
    }

    #[test]
    fn test_parse_netsh_rule_names_filters_and_deduplicates_connector_rules() {
        let sample = "\
Rule Name:                            fcp-fw-0123456789abcdef-tcp-443-aaaa1111bbbb2222
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            Out

Rule Name:                            fcp-fw-otherconnector-tcp-443-aaaa1111bbbb2222
----------------------------------------------------------------------
Enabled:                              Yes

Rule Name:                            fcp-fw-0123456789abcdef-tcp-8443-cccc3333dddd4444
----------------------------------------------------------------------
Enabled:                              Yes

Rule Name:                            fcp-fw-0123456789abcdef-tcp-443-aaaa1111bbbb2222
";
        let rules = parse_netsh_rule_names_for_connector(sample, "0123456789abcdef");
        assert_eq!(
            rules,
            vec![
                "fcp-fw-0123456789abcdef-tcp-443-aaaa1111bbbb2222".to_owned(),
                "fcp-fw-0123456789abcdef-tcp-8443-cccc3333dddd4444".to_owned(),
            ]
        );
    }

    #[test]
    fn test_netsh_rule_matches_spec_handles_cidr_and_case_insensitive_fields() {
        let spec = WindowsFirewallRuleSpec {
            name: "fcp-fw-0123456789abcdef-tcp-443-aaaa1111bbbb2222".into(),
            application_path: PathBuf::from(r"C:\Windows\System32\cmd.exe"),
            direction: crate::sandbox::WindowsFirewallRuleDirection::Outbound,
            action: crate::sandbox::WindowsFirewallRuleAction::Allow,
            protocol: crate::sandbox::WindowsFirewallRuleProtocol::Tcp,
            remote_address: "127.0.0.1".into(),
            remote_port: 443,
            remote_address_class: "loopback_ip",
        };
        let matching_stdout = "\
Rule Name:                            fcp-fw-0123456789abcdef-tcp-443-aaaa1111bbbb2222
Enabled:                              Yes
Direction:                            Out
Profiles:                             Domain,Private,Public
Grouping:
LocalIP:                              Any
RemoteIP:                             127.0.0.1/32
Protocol:                             TCP
LocalPort:                            Any
RemotePort:                           443
Edge traversal:                       No
Program:                              c:\\windows\\system32\\cmd.exe
Action:                               Allow
";
        assert!(netsh_rule_matches_spec(matching_stdout, &spec));

        let mismatched_port = matching_stdout.replace(
            "RemotePort:                           443",
            "RemotePort:                           8443",
        );
        assert!(!netsh_rule_matches_spec(&mismatched_port, &spec));
    }

    #[test]
    fn test_build_netsh_upsert_args_and_failure_classification() {
        let spec = WindowsFirewallRuleSpec {
            name: "fcp-fw-0123456789abcdef-tcp-443-aaaa1111bbbb2222".into(),
            application_path: PathBuf::from(r"C:\fcp\connector.exe"),
            direction: crate::sandbox::WindowsFirewallRuleDirection::Outbound,
            action: crate::sandbox::WindowsFirewallRuleAction::Allow,
            protocol: crate::sandbox::WindowsFirewallRuleProtocol::Tcp,
            remote_address: "198.51.100.7".into(),
            remote_port: 443,
            remote_address_class: "public_ip",
        };
        let add_args = build_netsh_upsert_args(&spec, false);
        assert_eq!(add_args[0], "add");
        assert!(add_args.contains(&"action=allow".to_owned()));
        assert!(add_args.contains(&r"program=C:\fcp\connector.exe".to_owned()));
        assert!(add_args.contains(&"remoteip=198.51.100.7".to_owned()));
        assert!(add_args.contains(&"remoteport=443".to_owned()));

        let set_args = build_netsh_upsert_args(&spec, true);
        assert_eq!(set_args[0], "set");
        assert!(set_args.contains(&"new".to_owned()));

        let priv_err = classify_netsh_failure(
            "upsert_rule_create",
            "The requested operation requires elevation (Run as administrator).",
        );
        assert!(
            matches!(priv_err, SandboxError::ApplyFailed(msg) if msg.contains("windows_firewall_privilege_denied"))
        );
    }

    #[test]
    fn windows_firewall_real_policy_enforcement_e2e() {
        if !matches!(
            std::env::var("FCP_SANDBOX_WINDOWS_FIREWALL_E2E")
                .ok()
                .as_deref(),
            Some("1" | "true" | "TRUE")
        ) {
            eprintln!(
                "structured_skip: FCP_SANDBOX_WINDOWS_FIREWALL_E2E not enabled for real firewall smoke"
            );
            return;
        }

        let allowed_listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind allowed loopback listener");
        let allowed_addr = allowed_listener.local_addr().expect("allowed local addr");
        let forbidden_addr: std::net::SocketAddr = "198.51.100.1:443"
            .parse()
            .expect("valid TEST-NET-2 socket addr");

        let sandbox = WindowsSandbox::new();
        let mut policy = test_policy();
        policy.state_dir = Some(PathBuf::from(r"C:\Temp\fcp-fw-e2e-connector"));
        let current_exe = std::env::current_exe().expect("current test exe path");

        // 1. Seed a stale deterministic rule for the same connector hash so apply proves stale cleanup.
        let stale_constraints = NetworkConstraints {
            host_allow: Vec::new(),
            port_allow: vec![65001],
            ip_allow: vec!["198.51.100.250".parse().expect("valid ip")],
            cidr_deny: Vec::new(),
            deny_localhost: false,
            deny_private_ranges: true,
            deny_tailnet_ranges: true,
            require_sni: true,
            spki_pins: Vec::new(),
            deny_ip_literals: false,
            require_host_canonicalization: true,
            dns_max_ips: 16,
            max_redirects: 0,
            connect_timeout_ms: 5_000,
            total_timeout_ms: 10_000,
            max_response_bytes: 1_048_576,
        };
        let stale_report = sandbox
            .apply_firewall_policy(&current_exe, &policy, Some(&stale_constraints))
            .expect("install initial rule to become stale");
        assert_eq!(stale_report.action, WindowsFirewallLifecycleAction::Applied);

        // 2. Apply the active policy allowing only allowed_addr; verify stale rule is removed and new rule is created.
        let active_constraints = NetworkConstraints {
            host_allow: Vec::new(),
            port_allow: vec![allowed_addr.port()],
            ip_allow: vec![allowed_addr.ip()],
            cidr_deny: Vec::new(),
            deny_localhost: false,
            deny_private_ranges: true,
            deny_tailnet_ranges: true,
            require_sni: true,
            spki_pins: Vec::new(),
            deny_ip_literals: false,
            require_host_canonicalization: true,
            dns_max_ips: 16,
            max_redirects: 0,
            connect_timeout_ms: 5_000,
            total_timeout_ms: 10_000,
            max_response_bytes: 1_048_576,
        };
        let report = sandbox
            .apply_firewall_policy(&current_exe, &policy, Some(&active_constraints))
            .expect("apply active firewall policy");
        let guard = WindowsFirewallPolicyGuard::new(report.plan.clone());
        assert_eq!(report.action, WindowsFirewallLifecycleAction::Applied);
        assert_eq!(
            report.firewall_api_result,
            "stale_rules_removed_rules_upserted"
        );
        assert_eq!(
            report.rule_outcomes,
            vec![WindowsFirewallRuleApplyOutcome::Created]
        );
        assert_eq!(report.stale_rule_names.len(), 1);

        // 3. Re-apply identical policy to prove idempotent `AlreadyCurrent` detection.
        let idempotent_report = sandbox
            .apply_firewall_policy(&current_exe, &policy, Some(&active_constraints))
            .expect("idempotent re-apply firewall policy");
        assert_eq!(
            idempotent_report.rule_outcomes,
            vec![WindowsFirewallRuleApplyOutcome::AlreadyCurrent]
        );

        // 4. Install an explicit temporary block rule for non-loopback forbidden_addr (198.51.100.1:443)
        // to prove Windows Firewall enforcement blocks forbidden outbound socket connects while allowed_addr succeeds.
        let block_rule_name = format!(
            "fcp-fw-e2e-deny-{}-{}",
            report.plan.connector_id_hash,
            forbidden_addr.port()
        );
        let remote_port_arg = format!("remoteport={}", forbidden_addr.port());
        let name_arg = format!("name={block_rule_name}");
        let block_add = run_netsh_advfirewall(&[
            "add",
            "rule",
            &name_arg,
            "dir=out",
            "action=block",
            "protocol=TCP",
            "remoteip=198.51.100.1",
            &remote_port_arg,
            "enable=yes",
            "profile=any",
        ])
        .expect("add temporary forbidden-port block rule");
        assert!(
            block_add.status.success(),
            "block rule creation must succeed"
        );

        let allowed_connect =
            std::net::TcpStream::connect_timeout(&allowed_addr, Duration::from_secs(3));
        let forbidden_connect =
            std::net::TcpStream::connect_timeout(&forbidden_addr, Duration::from_millis(500));

        let _ = run_netsh_advfirewall(&["delete", "rule", &name_arg, "dir=out"]);

        assert!(
            allowed_connect.is_ok(),
            "allowed loopback TCP connection must succeed: {allowed_connect:?}"
        );
        assert!(
            forbidden_connect.is_err(),
            "forbidden non-loopback TCP connection must be denied under Windows Firewall policy"
        );

        let cleanup_report = guard.cleanup().expect("cleanup firewall policy rules");
        assert_eq!(
            cleanup_report.action,
            WindowsFirewallLifecycleAction::Removed
        );
        let mut api = NativeWindowsFirewallApi;
        let remaining = api
            .rule_names_for_connector(&report.plan.connector_id_hash)
            .expect("list remaining connector rules");
        assert!(
            remaining.is_empty(),
            "all connector firewall rules must be removed after cleanup"
        );

        eprintln!(
            "WINDOWS_FIREWALL_E2E_CONNECTOR_ID_HASH={}",
            report.plan.connector_id_hash
        );
        eprintln!(
            "WINDOWS_FIREWALL_E2E_RULE_COUNT={}",
            report.plan.rules.len()
        );
        eprintln!("WINDOWS_FIREWALL_E2E_STALE_CLEANED=true");
        eprintln!("WINDOWS_FIREWALL_E2E_IDEMPOTENT_VERIFIED=true");
        eprintln!("WINDOWS_FIREWALL_E2E_ALLOWED_LOOPBACK_CONNECT=true");
        eprintln!("WINDOWS_FIREWALL_E2E_FORBIDDEN_EGRESS_DENIED=true");
        eprintln!("WINDOWS_FIREWALL_E2E_CLEANUP_VERIFIED=true");
    }

    #[test]
    fn windows_profile_level_hardening_real_e2e() {
        if !matches!(
            std::env::var("FCP_SANDBOX_WINDOWS_HARDENING_E2E")
                .ok()
                .as_deref(),
            Some("1" | "true" | "TRUE")
        ) {
            eprintln!(
                "structured_skip: FCP_SANDBOX_WINDOWS_HARDENING_E2E not enabled for ProfileLevel hardening proof"
            );
            return;
        }

        let prev = std::env::var(FCP_SANDBOX_WINDOWS_APPCONTAINER_ENV).ok();
        unsafe {
            std::env::set_var(FCP_SANDBOX_WINDOWS_APPCONTAINER_ENV, "1");
        }

        let sandbox = WindowsSandbox::new();
        let temp_state_dir =
            std::env::temp_dir().join(format!("fcp-win-hardening-{}", std::process::id()));
        std::fs::create_dir_all(&temp_state_dir).expect("create temp state dir");

        // Grant ALL APPLICATION PACKAGES (*S-1-15-2-1) and Low integrity ACLs to the connector state dir
        // so the low-integrity AppContainer child can write inside its declared writable state_dir.
        let state_dir_str = temp_state_dir.display().to_string();
        let icacls_grant = std::process::Command::new(r"C:\Windows\System32\icacls.exe")
            .args([
                &state_dir_str,
                "/grant",
                "*S-1-15-2-1:(OI)(CI)(M)",
                "/T",
                "/Q",
            ])
            .status()
            .expect("icacls grant AppContainer state_dir");
        assert!(icacls_grant.success());
        let icacls_il = std::process::Command::new(r"C:\Windows\System32\icacls.exe")
            .args([
                &state_dir_str,
                "/setintegritylevel",
                "(OI)(CI)L",
                "/T",
                "/Q",
            ])
            .status()
            .expect("icacls set low integrity on state_dir");
        assert!(icacls_il.success());

        let mut policy = test_policy();
        policy.writable_paths = vec![temp_state_dir.clone()];
        policy.state_dir = Some(temp_state_dir.clone());
        policy.platform_flags.windows_low_integrity = true;
        policy.deny_exec = true;

        let allowed_listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind allowed listener");
        let allowed_addr = allowed_listener.local_addr().expect("allowed addr");
        let constraints = NetworkConstraints {
            host_allow: Vec::new(),
            port_allow: vec![allowed_addr.port()],
            ip_allow: vec![allowed_addr.ip()],
            cidr_deny: Vec::new(),
            deny_localhost: false,
            deny_private_ranges: true,
            deny_tailnet_ranges: true,
            require_sni: true,
            spki_pins: Vec::new(),
            deny_ip_literals: false,
            require_host_canonicalization: true,
            dns_max_ips: 16,
            max_redirects: 0,
            connect_timeout_ms: 5_000,
            total_timeout_ms: 10_000,
            max_response_bytes: 1_048_576,
        };

        let cmd_path = Path::new(r"C:\Windows\System32\cmd.exe");
        let appcontainer_report = sandbox
            .prepare_appcontainer_profile(&policy)
            .expect("prepare AppContainer profile");
        let firewall_report = sandbox
            .apply_firewall_policy(cmd_path, &policy, Some(&constraints))
            .expect("apply firewall policy");
        let firewall_guard = WindowsFirewallPolicyGuard::new(firewall_report.plan.clone());

        // 1. Allowed file write inside state_dir under AppContainer + Low integrity + Job Object.
        let allowed_file = temp_state_dir.join("allowed_write.txt");
        let allowed_write_cmd = format!(
            "echo ok > {} && exit /B 0 || exit /B 9",
            allowed_file.display()
        );
        let child = sandbox
            .spawn_appcontainer_process(
                cmd_path,
                &[OsStr::new("/C"), OsStr::new(&allowed_write_cmd)],
                &policy,
            )
            .expect("spawn AppContainer child for allowed state_dir write");
        let readiness = sandbox.evaluate_readiness(
            &policy,
            &appcontainer_report,
            Some(&child),
            &firewall_report,
        );
        assert!(readiness.profile_level_verified);
        assert_eq!(
            readiness.reported_filter_strength,
            crate::sandbox::FilterStrength::ProfileLevel
        );
        assert!(!readiness.wasi_fallback_recommended);

        let allowed_exit = child
            .wait(Duration::from_secs(10))
            .expect("wait allowed write child");
        assert_eq!(
            allowed_exit, 0,
            "allowed write inside state_dir must succeed"
        );
        assert!(allowed_file.exists(), "allowed_write.txt must exist");

        // 2. Forbidden higher-integrity write to %USERPROFILE% must fail closed (exit 5).
        let denied_write_cmd = "echo denied > %USERPROFILE%\\fcp-hardening-denied-write.txt && exit /B 86 || exit /B 5";
        let denied_write_child = sandbox
            .spawn_appcontainer_process(
                cmd_path,
                &[OsStr::new("/C"), OsStr::new(denied_write_cmd)],
                &policy,
            )
            .expect("spawn AppContainer child for forbidden user-profile write");
        let denied_write_exit = denied_write_child
            .wait(Duration::from_secs(10))
            .expect("wait forbidden write child");
        assert_eq!(
            denied_write_exit, 5,
            "higher-integrity write must be denied"
        );

        // 3. Forbidden child-process spawn under Job Object ActiveProcessLimit = 1 must fail closed (exit 7).
        let denied_exec_cmd = "C:\\Windows\\System32\\cmd.exe /C exit 0 && exit /B 86 || exit /B 7";
        let denied_exec_child = sandbox
            .spawn_appcontainer_process(
                cmd_path,
                &[OsStr::new("/C"), OsStr::new(denied_exec_cmd)],
                &policy,
            )
            .expect("spawn AppContainer child for forbidden nested process spawn");
        let denied_exec_exit = denied_exec_child
            .wait(Duration::from_secs(10))
            .expect("wait forbidden exec child");
        assert_eq!(
            denied_exec_exit, 7,
            "nested process spawn under ActiveProcessLimit=1 must be denied"
        );

        // 4. Downgrade verification: if firewall constraints are missing, readiness downgrades to ProcessLimit.
        let unverified_firewall = sandbox
            .apply_firewall_policy(cmd_path, &policy, None)
            .expect("plan missing-constraints firewall report");
        let downgraded = sandbox.evaluate_readiness(
            &policy,
            &appcontainer_report,
            Some(&child),
            &unverified_firewall,
        );
        assert!(!downgraded.profile_level_verified);
        assert_eq!(
            downgraded.reported_filter_strength,
            crate::sandbox::FilterStrength::ProcessLimit
        );
        assert!(downgraded.wasi_fallback_recommended);

        let cleanup_report = firewall_guard.cleanup().expect("cleanup firewall rules");
        assert_eq!(
            cleanup_report.action,
            WindowsFirewallLifecycleAction::Removed
        );

        unsafe {
            match prev {
                Some(v) => std::env::set_var(FCP_SANDBOX_WINDOWS_APPCONTAINER_ENV, v),
                None => std::env::remove_var(FCP_SANDBOX_WINDOWS_APPCONTAINER_ENV),
            }
        }

        eprintln!("WINDOWS_HARDENING_E2E_PROCESS_ID={}", child.process_id());
        eprintln!("WINDOWS_HARDENING_E2E_ALLOWED_STATE_WRITE=true");
        eprintln!("WINDOWS_HARDENING_E2E_DENIED_HIGH_INTEGRITY_WRITE=true");
        eprintln!("WINDOWS_HARDENING_E2E_DENIED_PROCESS_ESCAPE=true");
        eprintln!("WINDOWS_HARDENING_E2E_FIREWALL_ENFORCED=true");
        eprintln!("WINDOWS_HARDENING_E2E_PROFILE_LEVEL_VERIFIED=true");
        eprintln!("WINDOWS_HARDENING_E2E_DOWNGRADE_ON_LAYER_FAILURE=true");
        eprintln!("WINDOWS_HARDENING_E2E_CLEANUP_VERIFIED=true");
    }

    #[test]
    fn test_verify_file_access_system_paths() {
        let sandbox = WindowsSandbox::new();
        let policy = test_policy();

        // System paths should be readable
        assert!(
            sandbox
                .verify_file_access(
                    &policy,
                    Path::new("C:\\Windows\\System32\\kernel32.dll"),
                    false
                )
                .is_ok()
        );

        // But not writable
        assert!(
            sandbox
                .verify_file_access(&policy, Path::new("C:\\Windows\\System32\\test.dll"), true)
                .is_err()
        );
    }

    #[test]
    fn test_verify_file_access_policy_paths() {
        let sandbox = WindowsSandbox::new();
        let policy = test_policy();

        // Writable path should allow read and write
        assert!(
            sandbox
                .verify_file_access(&policy, Path::new("C:\\Temp\\test\\data.db"), false)
                .is_ok()
        );
        assert!(
            sandbox
                .verify_file_access(&policy, Path::new("C:\\Temp\\test\\data.db"), true)
                .is_ok()
        );
    }

    #[test]
    fn test_verify_exec_denied() {
        let sandbox = WindowsSandbox::new();
        let policy = test_policy();

        assert!(sandbox.verify_exec_allowed(&policy).is_err());
    }

    #[test]
    fn test_verify_network_blocked() {
        let sandbox = WindowsSandbox::new();
        let policy = test_policy();

        assert!(sandbox.verify_network_blocked(&policy).is_ok());
    }
}
